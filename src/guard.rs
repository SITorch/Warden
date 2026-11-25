//! guard.rs — the userspace half of the enforcing layer.
//!
//! The kernel's BPF-LSM programs decide "deny or allow" against a map keyed by
//! the one file identity that survives renames, hardlinks, and bind mounts: the
//! resolved (device, inode number). They never see a path — a path check
//! in-kernel is both expensive (a string walk) and bypassable (symlink, hardlink,
//! `..`, bind mount). This module is what turns the operator's path-based policy
//! (`[[enforce.guarded_files]]` in warden.toml) into that inode-keyed map: it
//! stat()s each configured path, resolves it to (dev, ino), and builds the desired
//! kernel map contents. `loader.rs` reconciles the result into the live map.
//!
//! Because the map is keyed on the resolved inode, a guarded file rewritten in
//! place gets a NEW inode — so protection would silently follow the old, now-
//! unlinked inode. That is why `resolve` is re-run on every refresh tick and on
//! SIGHUP (see main.rs): each pass re-stats the paths, so the policy tracks the
//! file's CURRENT inode within one tick of it changing.

use std::collections::{BTreeMap, HashSet};
use std::os::linux::fs::MetadataExt;
use std::sync::{Mutex, MutexGuard, OnceLock};

use crate::config::GuardedFile;

/// Wire-identical to `struct warden_inode_key` in warden.h: the (dev, ino) the
/// kernel matches an accessed inode against. `#[repr(C)]` + `aya::Pod` let aya
/// copy it into the map byte-for-byte.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InodeKey {
    pub dev: u64,
    pub ino: u64,
}

// SAFETY: InodeKey is repr(C), fixed-size, all-integer, no padding (two u64s =
// 16 bytes), and every bit pattern is a valid value — the aya::Pod contract.
unsafe impl aya::Pod for InodeKey {}

/// Wire-identical to `struct warden_guard_policy` in warden.h: the per-inode
/// policy the kernel enforces. `authorized_uid` is the sole uid allowed the denied
/// intents; `deny_intents` is a WARDEN_INTENT_* mask; `flags` carries WARDEN_GUARD_*
/// bits. `_pad` keeps the value 8-byte-sized and matches the C struct's trailing pad.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardPolicy {
    pub authorized_uid: u32,
    pub deny_intents: u32,
    pub flags: u32,
    pub _pad: u32,
}

// SAFETY: repr(C), fixed-size (four u32s = 16 bytes), all-integer, no invalid bit
// patterns — the aya::Pod contract, same as InodeKey.
unsafe impl aya::Pod for GuardPolicy {}

/// Paths already warned about, so the refresh tick does not repeat the same
/// warning every 10 seconds. `resolve` runs on every tick (the inode a path
/// points at can change), and a missing path or an empty deny mask would
/// otherwise log forever — 12 warnings a minute that bury the findings the
/// journal exists for. A path leaves its set the moment its condition clears,
/// so a file that disappears again after being fixed is reported again.
static WARNED_MISSING: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static WARNED_EMPTY_DENY: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn warned(
    state: &'static OnceLock<Mutex<HashSet<String>>>,
) -> MutexGuard<'static, HashSet<String>> {
    // A poisoned lock still holds a usable set; recovering beats dropping the
    // dedupe state and flooding the journal after a panic elsewhere.
    state
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Convert a userspace `st_dev` (as `stat(2)` / `MetadataExt::st_dev` report it)
/// into the kernel-internal `dev_t` that a BPF program reads directly from
/// `super_block->s_dev`. These are DIFFERENT encodings, and getting this wrong is
/// the difference between "the guard matches the file" and "the guard silently
/// matches nothing":
///
///   * glibc's `st_dev` packs major/minor as
///     `minor&0xff | major<<8 | (minor&~0xff)<<12 | (major&~0xfff)<<32`
///     (the split-field "gnu_dev" layout).
///   * the kernel stores `s_dev` as the raw kernel `dev_t`: major<<20 | minor
///     (MINORBITS = 20). This is what CO-RE's `BPF_CORE_READ(inode, i_sb, s_dev)`
///     returns — the raw field, NOT the `new_encode_dev` form applied only at the
///     stat(2) copy-out boundary.
///
/// So we decode the true major/minor out of the glibc value and re-encode them the
/// kernel's way. Round-trips for both real block devices (major 8, minor 2 →
/// 0x800002) and anonymous/pseudo-fs devs (major 0, large minor).
pub fn to_kernel_dev(st_dev: u64) -> u64 {
    // Decode the glibc gnu_dev layout → true major/minor.
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfffu64);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xffu64);
    // Re-encode the kernel way: 12-bit major above a 20-bit minor.
    ((major & 0xfff) << 20) | (minor & 0xf_ffff)
}

/// Resolve the operator's path-based guard list into the inode-keyed policy the
/// kernel map wants. Each path is stat()ed to (dev, ino); a path that cannot be
/// resolved (missing, permission, a dangling symlink) is SKIPPED with a warning —
/// the strictest-safe behaviour is to guard nothing for that entry rather than
/// guess an inode. When two entries resolve to the SAME inode (e.g. a path and a
/// hardlink to it) the later entry wins, which a warning notes.
///
/// Returned map is ordered (BTreeMap) purely for deterministic reconciliation and
/// testable output. The (dev, ino) tuple is the key; `loader.rs` turns it into an
/// `InodeKey` when it writes the kernel map.
pub fn resolve(files: &[GuardedFile]) -> BTreeMap<(u64, u64), GuardPolicy> {
    let mut out: BTreeMap<(u64, u64), GuardPolicy> = BTreeMap::new();
    for g in files {
        let meta = match std::fs::metadata(&g.path) {
            Ok(m) => {
                // Resolved again: if it was missing on an earlier tick, a later
                // disappearance is a new event worth a new warning.
                warned(&WARNED_MISSING).remove(&g.path);
                m
            }
            Err(e) => {
                if warned(&WARNED_MISSING).insert(g.path.clone()) {
                    log::warn!(
                        "enforce: guarded file {:?} could not be resolved ({e}); not guarding it",
                        g.path
                    );
                }
                continue;
            }
        };
        let dev = to_kernel_dev(meta.st_dev());
        let ino = meta.st_ino();
        let policy = GuardPolicy {
            authorized_uid: g.authorized_uid,
            deny_intents: g.deny_mask(),
            flags: g.flags(),
            _pad: 0,
        };
        // A guarded file that denies NOTHING (empty/unknown deny list) can never
        // block and only adds hot-path lookups; warn but still install it so its
        // shadow records surface (an operator may be probing what an access looks
        // like before choosing a deny mask).
        if policy.deny_intents == 0 {
            if warned(&WARNED_EMPTY_DENY).insert(g.path.clone()) {
                log::warn!(
                    "enforce: guarded file {:?} has an empty deny mask — it will emit \
                     access records but never deny; set `deny = [\"read\",\"write\"]`",
                    g.path
                );
            }
        } else {
            warned(&WARNED_EMPTY_DENY).remove(&g.path);
        }
        if out.insert((dev, ino), policy).is_some() {
            log::warn!(
                "enforce: guarded file {:?} resolves to an inode already guarded \
                 (dev={dev}, ino={ino}); the later entry's policy wins",
                g.path
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{WARDEN_GUARD_ALLOW_ROOT, WARDEN_INTENT_READ, WARDEN_INTENT_WRITE};

    #[test]
    fn abi_struct_sizes_match_the_c_contract() {
        // warden_inode_key = two u64 = 16; warden_guard_policy = four u32 = 16.
        // If these drift the kernel reads garbage keys/policies.
        assert_eq!(std::mem::size_of::<InodeKey>(), 16);
        assert_eq!(std::mem::size_of::<GuardPolicy>(), 16);
    }

    #[test]
    fn kernel_dev_encoding_round_trips_a_real_block_device() {
        // major 8, minor 2 (/dev/sda2). glibc st_dev = major<<8 | minor = 0x802.
        // Kernel s_dev = major<<20 | minor = 0x800002. The converter must map the
        // former to the latter — the whole reason the guard matches at all.
        let glibc_st_dev = (8u64 << 8) | 2;
        assert_eq!(to_kernel_dev(glibc_st_dev), (8u64 << 20) | 2);
    }

    #[test]
    fn kernel_dev_encoding_handles_a_large_minor_anon_dev() {
        // A pseudo-fs anonymous dev: major 0, minor 300 (> 8 bits). glibc splits
        // the minor across two fields; the kernel keeps it contiguous in the low
        // 20 bits. Both must survive the round-trip or overlayfs/tmpfs-backed
        // guarded files would never match.
        let major = 0u64;
        let minor = 300u64;
        let glibc_st_dev = (minor & 0xff) | (major << 8) | ((minor & !0xffu64) << 12);
        assert_eq!(to_kernel_dev(glibc_st_dev), (major << 20) | minor);
    }

    #[test]
    fn resolve_skips_a_missing_path_and_guards_nothing_for_it() {
        // A guarded file that doesn't exist must not fabricate an inode (which
        // could accidentally match a real file); it's dropped entirely.
        let files = vec![GuardedFile {
            path: "/nonexistent/warden/definitely-not-here.key".to_string(),
            authorized_uid: 991,
            deny: vec!["read".into(), "write".into()],
            allow_root: false,
        }];
        assert!(resolve(&files).is_empty());
    }

    #[test]
    fn resolve_maps_a_real_file_to_its_inode_and_policy() {
        // Guard this test's own source-adjacent temp file: stat it ourselves, then
        // assert resolve() produced the same (dev, ino) key and the policy we asked
        // for. This pins the end-to-end path→inode→policy translation.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("warden-guard-test-{}", std::process::id()));
        std::fs::write(&path, b"secret").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let want_key = (to_kernel_dev(meta.st_dev()), meta.st_ino());

        let files = vec![GuardedFile {
            path: path.to_string_lossy().into_owned(),
            authorized_uid: 991,
            deny: vec!["read".into(), "write".into()],
            allow_root: true,
        }];
        let resolved = resolve(&files);
        std::fs::remove_file(&path).ok();

        assert_eq!(resolved.len(), 1);
        let pol = resolved
            .get(&want_key)
            .expect("resolved to the stat'd inode");
        assert_eq!(pol.authorized_uid, 991);
        assert_eq!(pol.deny_intents, WARDEN_INTENT_READ | WARDEN_INTENT_WRITE);
        assert_eq!(pol.flags, WARDEN_GUARD_ALLOW_ROOT);
    }
}
