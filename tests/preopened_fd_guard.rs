//! W-R2 / BUG-08: access through a descriptor opened BEFORE the guard was armed.
//!
//! The audit's finding was that the five original `lsm/*` programs gate
//! *acquisition* — open, mmap, unlink, rename, setattr. A process that already
//! held a writable fd when the guard was armed kept writing through it: the open
//! had happened before there was a policy to check, and `write(2)` never passed
//! through `file_open` again. The design notes said so plainly ("a file already
//! open is not revoked"), but "documented" is not "fixed".
//!
//! `bpf/warden.bpf.c` now ships `lsm/file_permission`, the per-I/O MAC hook the
//! kernel calls from `vfs_read`/`vfs_write` on every operation regardless of the
//! fd's age. This file proves both halves of that change:
//!
//!   1. `the_permission_hook_and_its_loader_row_ship` — an unprivileged,
//!      structural test that the hook and the loader row exist together. (The
//!      embedded object's section set is frozen by `tests/capability_matrix.rs`,
//!      which now expects `lsm/file_permission`.)
//!   2. `a_preopened_fd_loses_write_access_when_the_guard_is_armed` — the
//!      mandatory runtime test: open the file FIRST, arm the guard SECOND, then
//!      write / read / truncate / chmod through the old descriptor and require
//!      `EPERM` for each. It needs root, `CAP_BPF`, `bpf` in the boot `lsm=`
//!      list, and a rebuilt `bpf/warden.bpf.o`.
//!
//! PRQ-01 test-semantics fix: the runtime test is now `#[ignore]`d. In an
//! ordinary `cargo test` run it is reported as `ignored` — never as `ok` — so
//! an unprivileged developer workstation cannot inflate the passing-test count
//! with a qualification that did not execute. It is invoked explicitly (with
//! `--ignored`) by `scripts/test-privileged.sh`, which checks the preconditions
//! and emits an unambiguous `SKIP` (exit 77) when they are absent. When the
//! test itself is invoked but a precondition is unmet, it FAILS loudly rather
//! than returning success. Never treat a SKIP as a PASS.
//!
//! A memory mapping established before arming is NOT covered: page faults do not
//! pass through `file_permission`, and there is no per-store LSM hook for an
//! established mapping. That residual gap is stated in README and DESIGN.

use aya::include_bytes_aligned;
use aya::maps::Array;
use aya::programs::Lsm;
use aya::{Btf, Ebpf};
use std::os::unix::fs::MetadataExt;

/// The exact bytes the `warden` binary embeds. Same macro and same path as
/// `src/loader.rs`; `bpf/warden.bpf.o` is prebuilt, so editing only the C source
/// changes nothing at runtime. Rebuild with `make bpf`.
fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

/// Wire-identical to `struct warden_inode_key` in `bpf/warden.h` (two u64s).
#[repr(C)]
#[derive(Clone, Copy)]
struct InodeKey {
    dev: u64,
    ino: u64,
}
// SAFETY: repr(C), all-integer, 16 bytes, no padding, every bit pattern valid.
unsafe impl aya::Pod for InodeKey {}

/// Wire-identical to `struct warden_guard_policy` in `bpf/warden.h`.
#[repr(C)]
#[derive(Clone, Copy)]
struct GuardPolicy {
    authorized_uid: u32,
    deny_intents: u32,
    flags: u32,
    _pad: u32,
}
// SAFETY: repr(C), four u32s, no invalid bit patterns.
unsafe impl aya::Pod for GuardPolicy {}

/// Mirror of `src/guard.rs::to_kernel_dev`, repeated here because the crate is a
/// binary and integration tests cannot import its internals. The two encodings
/// differ: glibc's `st_dev` is not the kernel's raw `s_dev`. A mismatch here is
/// the failure mode where the guard matches nothing and every denial silently
/// becomes a no-op.
fn to_kernel_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfffu64);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xffu64);
    ((major & 0xfff) << 20) | (minor & 0xf_ffff)
}

/// WARDEN_INTENT_READ | WARDEN_INTENT_WRITE from `bpf/warden.h`.
const DENY_READ_WRITE: u32 = 0x1 | 0x2;
/// CFG_ACCESS_EMIT and CFG_ENFORCE_ARM from `bpf/warden.h`.
const CFG_ACCESS_EMIT: u32 = 8;
const CFG_ENFORCE_ARM: u32 = 9;

/// Read errno immediately and require the operation to have failed with EPERM.
/// `rc` must be the raw return of the libc call, evaluated in the argument so no
/// other libc call can run between the failure and the errno read.
fn assert_denied(rc: libc::c_long, op: &str) {
    let err = std::io::Error::last_os_error();
    assert_eq!(
        rc, -1,
        "{op} through the pre-opened fd SUCCEEDED after arming: {err:?}"
    );
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EPERM),
        "{op} was refused, but with {err:?} rather than EPERM"
    );
}

/// Structural half. Always runs, in CI too.
#[test]
fn the_permission_hook_and_its_loader_row_ship() {
    let c_source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.c"));
    assert!(
        c_source.contains(r#"SEC("lsm/file_permission")"#),
        "bpf/warden.bpf.c has no lsm/file_permission program. Without it, an fd \
         opened before arming keeps reading and writing the guarded file (W-R2)."
    );

    let header = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.h"));
    assert!(
        header.contains("WARDEN_ACCESS_PERMISSION = 6"),
        "the ABI lost WARDEN_ACCESS_PERMISSION=6; src/events.rs decodes the hook \
         from this enum, so the guard would emit an event userspace cannot name"
    );

    let loader = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader.rs"));
    assert!(
        loader.contains(r#"("warden_guard_file_permission", "file_permission")"#),
        "the loader's LSM_PROGRAMS table does not attach \
         warden_guard_file_permission. A program that ships in the object but is \
         never attached protects nothing."
    );
}

/// The kernel's raw `s_dev` the BPF side reads equals what stat(2) reports only
/// after re-encoding. Pin the decoder the runtime test depends on.
#[test]
fn the_dev_encoding_matches_the_loader() {
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/preopened_fd_guard.rs");
    let meta = std::fs::metadata(source).expect("stat this test source");
    let key = InodeKey {
        dev: to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    };
    assert_ne!(key.ino, 0);
    // For a regular file on a normal fs the kernel dev is nonzero; zero means the
    // decode lost the device and the guard would look up a key that never matches.
    assert_ne!(key.dev, 0, "the device number decoded to zero");
}

/// Regression guard: the privileged runtime test must stay out of the default
/// suite. If someone removes its `#[ignore]`, this test fails so a CI summary
/// cannot silently count an unexecuted kernel qualification as `ok`.
#[test]
fn the_privileged_runtime_test_is_excluded_from_the_default_suite() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/preopened_fd_guard.rs"
    ));
    let marker = "fn a_preopened_fd_loses_write_access_when_the_guard_is_armed()";
    // rfind: this test's own source mentions `marker` as a string literal;
    // the last occurrence is the real function definition.
    let pos = source
        .rfind(marker)
        .expect("the runtime test function must still exist (do not delete it)");
    let before = &source[..pos];
    let last_test = before.rfind("#[test]");
    let last_ignore = before.rfind("#[ignore");
    assert!(
        matches!((last_test, last_ignore), (Some(t), Some(i)) if i > t),
        "the runtime test lost its #[ignore] annotation (it must follow #[test]). \
         It must not run in the default `cargo test` suite, where its SKIP would \
         be reported as `ok`."
    );
}

/// The mandatory runtime test. Requires root + CAP_BPF + `bpf` in the boot
/// `lsm=` list + a rebuilt object. `#[ignore]` keeps it out of the default
/// suite; `scripts/test-privileged.sh` invokes it explicitly with `--ignored`.
/// Any unmet precondition when it IS invoked is a hard failure, never a skip.
#[test]
#[ignore = "privileged BPF-LSM qualification: run via scripts/test-privileged.sh in a disposable VM"]
fn a_preopened_fd_loses_write_access_when_the_guard_is_armed() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "privileged runtime test invoked without root: qualification FAIL, not SKIP"
    );

    // ── 1. Create the file and OPEN IT BEFORE ANY GUARD EXISTS. ─────────────
    let path = std::env::temp_dir().join(format!("warden-preopened-fd-{}.tmp", std::process::id()));
    std::fs::write(&path, b"pre-guard contents").expect("write the probe file");
    let meta = std::fs::metadata(&path).expect("stat the probe file");

    let c_path =
        std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path has no NUL");
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
    assert!(fd >= 0, "open the probe file before arming");

    // ── 2. Load and attach the two hooks under test. ────────────────────────
    let mut ebpf = Ebpf::load(embedded_object()).unwrap_or_else(|e| {
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_file(&path);
        panic!(
            "privileged runtime test could not load the eBPF object ({e}); needs \
             CAP_BPF and a rebuilt bpf/warden.bpf.o (`make bpf`). Qualification FAIL."
        );
    });

    let btf = Btf::from_sys_fs().unwrap_or_else(|e| {
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_file(&path);
        panic!("privileged runtime test: kernel BTF unavailable ({e}); BPF-LSM cannot attach. Qualification FAIL.");
    });

    for (prog_name, hook) in [
        ("warden_guard_file_permission", "file_permission"),
        ("warden_guard_inode_setattr", "inode_setattr"),
    ] {
        let prog: &mut Lsm = ebpf
            .program_mut(prog_name)
            .unwrap_or_else(|| panic!("program {prog_name} missing from the object"))
            .try_into()
            .expect("the program is an LSM program");
        prog.load(hook, &btf).unwrap_or_else(|e| {
            panic!(
                "could not load {prog_name} onto lsm/{hook} ({e}). The kernel must \
                 have `bpf` in its boot lsm= list (CONFIG_BPF_LSM). This is a real \
                 failure of the deployment precondition, not a skip."
            )
        });
        prog.attach()
            .unwrap_or_else(|e| panic!("could not attach {prog_name} to lsm/{hook}: {e}"));
    }

    // ── 3. Install the policy and ARM denial. ──────────────────────────────
    let mut guarded: aya::maps::HashMap<_, InodeKey, GuardPolicy> = aya::maps::HashMap::try_from(
        ebpf.take_map("guarded_inodes")
            .expect("guarded_inodes map missing from the object"),
    )
    .expect("guarded_inodes is a hash map");
    guarded
        .insert(
            InodeKey {
                dev: to_kernel_dev(meta.dev()),
                ino: meta.ino(),
            },
            GuardPolicy {
                // A uid that is not ours, so the test actor is unauthorised.
                authorized_uid: 424_242,
                deny_intents: DENY_READ_WRITE,
                flags: 0,
                _pad: 0,
            },
            0,
        )
        .expect("install the guard policy");

    let mut cfg: Array<_, u32> = Array::try_from(
        ebpf.take_map("runtime_cfg")
            .expect("runtime_cfg map missing from the object"),
    )
    .expect("runtime_cfg is an array");
    cfg.set(CFG_ACCESS_EMIT, 1, 0)
        .expect("enable access events");
    cfg.set(CFG_ENFORCE_ARM, 1, 0).expect("arm denial");

    // ── 4. Use ONLY the pre-existing fd. Record the real result. ────────────
    let mut buf = [0u8; 4];
    let read_rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    assert_denied(read_rc as libc::c_long, "read(2)");

    let write_rc = unsafe { libc::write(fd, b"x".as_ptr() as *const libc::c_void, 1) };
    assert_denied(write_rc as libc::c_long, "write(2)");

    let trunc_rc = unsafe { libc::ftruncate(fd, 0) };
    assert_denied(trunc_rc as libc::c_long, "ftruncate(2)");

    let chmod_rc = unsafe { libc::fchmod(fd, 0o600) };
    assert_denied(chmod_rc as libc::c_long, "fchmod(2)");

    // ── 5. Clean up: detach by dropping the programs, then remove the file. ──
    unsafe { libc::close(fd) };
    drop(ebpf);
    let _ = std::fs::remove_file(&path);
}
