//! loader.rs — the aya glue. Loads the CO-RE eBPF object compiled from
//! `bpf/warden.bpf.c`, attaches the sensor programs, and hands back typed
//! handles to the maps the event loop needs (ring buffer + protected-pids +
//! runtime config + the W-02 ring-buffer drop counter).
//!
//! The compiled object is embedded in the binary at build time (see the
//! `include_bytes_aligned!` below), so the shipped `warden` is one Rust
//! executable with no external .o to lose or tamper with at runtime. It is not
//! fully static: the optional mTLS transport links the host's libssl/libcrypto.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray, RingBuf};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, FExit, KProbe, Lsm, TracePoint};
use aya::{include_bytes_aligned, Btf, Ebpf, EbpfLoader};

use crate::egress::{
    apply_egress_reload_with_stats as apply_egress_reload_facts, EgressDeny, EgressHook,
    EgressHooks, EgressKey, EgressReloadReport, EgressReloadTransition, EgressRule, EgressRuntime,
    EgressStats, CFG_EGRESS_ARM, EGRESS_POLICY_MAX,
};
use crate::guard::{GuardPolicy, InodeKey};
use crate::net_vol::{
    self, CgroupVolume, VolumeHooks, VolumeInvocations, VolumeRecord, VolumeTotals,
};

/// The CO-RE object, baked in at compile time. Rebuilt by the Makefile's
/// `clang -target bpf` step before every `cargo build`.
static WARDEN_OBJ: &[u8] =
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"));

/// Length of the embedded object — surfaced by `--check` as a wiring smoke test
/// that doesn't require kernel privileges.
pub fn obj_len() -> usize {
    WARDEN_OBJ.len()
}

/// FNV-1a/64 over the embedded object, printed by `--doctor` and `--version`.
///
/// Length alone cannot tell two builds of the same file apart, and §۵۱ of the
/// report shows why that matters here: a comment-only edit to `bpf/warden.bpf.c`
/// changes the object's bytes (DWARF line info) while leaving its size exactly as it
/// was — 1 211 600 for a long run of builds, 1 216 656 from the W2K-29 exe-inode stamp
/// onward. A digest is the cheapest way for an operator to answer "WHICH object
/// is in this binary" without loading anything. Not a security hash — it
/// distinguishes builds, it does not authenticate them.
pub fn obj_fingerprint() -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in WARDEN_OBJ {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

/// Decode the handful of escapes mountinfo uses in path fields. A mount point
/// with a space is unusual but legal; treating the escaped spelling as a
/// different path would make the root comparison silently weaker.
fn unescape_mountinfo_path(field: &str) -> String {
    field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// All cgroup2 mount points visible in this process's mount namespace. The
/// mount point — not the textual `/sys/fs/cgroup` default — is the effective
/// root in a cgroup or mount namespace; comparing the opened target's identity
/// against it is what rejects namespace-local roots and bind-mounted aliases.
fn cgroup2_mount_points() -> anyhow::Result<Vec<PathBuf>> {
    let text = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| anyhow::anyhow!("cannot read /proc/self/mountinfo: {e}"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        if sep + 1 >= fields.len() || fields[sep + 1] != "cgroup2" {
            continue;
        }
        if fields.len() < 5 {
            continue;
        }
        out.push(PathBuf::from(unescape_mountinfo_path(fields[4])));
    }
    Ok(out)
}

fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    let path_parts: Vec<_> = path.components().collect();
    let prefix_parts: Vec<_> = prefix.components().collect();
    path_parts.len() >= prefix_parts.len()
        && path_parts
            .iter()
            .zip(prefix_parts.iter())
            .all(|(p, q)| p == q)
}

/// Open a directory one component at a time with `O_NOFOLLOW` on every link.
/// This refuses both a final symlink and an intermediate symlink alias before
/// any BPF attach happens, and returns an fd that is the object we validated.
fn open_directory_nofollow(path: &Path) -> anyhow::Result<File> {
    if !path.is_absolute() {
        anyhow::bail!("cgroup path must be absolute");
    }
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let root = unsafe { libc::open(c"/".as_ptr(), flags) };
    if root < 0 {
        return Err(anyhow::anyhow!(
            "cannot open / while resolving cgroup path {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root) };
    for component in path.components().skip(1) {
        let name = match component {
            Component::Normal(part) => part,
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                anyhow::bail!(
                    "cgroup path {} contains a traversal or non-normal component",
                    path.display()
                )
            }
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("cgroup path component contains a NUL byte"))?;
        let next = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if next < 0 {
            return Err(anyhow::anyhow!(
                "cannot open cgroup path {} at {:?}: {}",
                path.display(),
                name,
                std::io::Error::last_os_error()
            ));
        }
        current = unsafe { OwnedFd::from_raw_fd(next) };
    }
    Ok(unsafe { File::from_raw_fd(current.into_raw_fd()) })
}

fn ensure_cgroup2_fs(file: &File, path: &Path) -> anyhow::Result<()> {
    if !file
        .metadata()
        .map_err(|e| anyhow::anyhow!("cannot stat {}: {e}", path.display()))?
        .is_dir()
    {
        anyhow::bail!("cgroup path {} is not a directory", path.display());
    }
    let mut info: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut info) } != 0 {
        return Err(anyhow::anyhow!(
            "cannot fstatfs {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    if info.f_type as u64 != CGROUP2_SUPER_MAGIC {
        anyhow::bail!(
            "cgroup path {} is not on cgroup2 (f_type=0x{:x}); a normal directory is not a cgroup",
            path.display(),
            info.f_type as u64
        );
    }
    Ok(())
}

fn file_identity(file: &File) -> anyhow::Result<(u64, u64)> {
    let meta = file
        .metadata()
        .map_err(|e| anyhow::anyhow!("cannot stat validated cgroup fd: {e}"))?;
    Ok((meta.dev(), meta.ino()))
}

/// Validate a cgroup v2 destination and return the SAME opened fd that was
/// checked. Config validation calls this to fail early; the loader calls it
/// again and attaches from the returned fd, so a path swapped after validation
/// cannot redirect the hooks.
pub fn open_validated_cgroup(path: &Path) -> anyhow::Result<File> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        anyhow::bail!("egress.cgroup_path must be an absolute path");
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::CurDir | Component::Prefix(_)
        ) {
            anyhow::bail!(
                "egress.cgroup_path {} contains a traversal or alias component; name the \
                 isolated cgroup directly",
                path.display()
            );
        }
    }
    let file = open_directory_nofollow(path)?;
    ensure_cgroup2_fs(&file, path)?;

    let mounts = cgroup2_mount_points()?;
    let matching: Vec<&PathBuf> = mounts
        .iter()
        .filter(|mount| path_has_prefix(path, mount))
        .collect();
    if matching.is_empty() {
        anyhow::bail!(
            "egress.cgroup_path {} is not under any cgroup2 mount visible in this mount namespace",
            path.display()
        );
    }
    if matching.len() > 1 {
        anyhow::bail!(
            "egress.cgroup_path {} is ambiguous: {} cgroup2 mounts could own it; refusing to \
             guess which root it aliases",
            path.display(),
            matching.len()
        );
    }
    let root_path = matching[0];
    let root_file = open_directory_nofollow(root_path)?;
    ensure_cgroup2_fs(&root_file, root_path)?;
    if file_identity(&file)? == file_identity(&root_file)? {
        anyhow::bail!(
            "egress.cgroup_path {} is the cgroup root (or an alias of it): attaching there \
             would affect every process in this cgroup namespace. Name an isolated child cgroup.",
            path.display()
        );
    }
    Ok(file)
}

/// Counter slots in the kernel's per-sensor maps — must match
/// `WARDEN_KIND_SLOTS` in `bpf/warden.h`, and is asserted against the shipped
/// object by `tests/ringbuf_drop_counter.rs`. Indexed by `Kind as u32`.
pub const KIND_SLOTS: usize = 16;

/// Per-sensor kernel counters (W2K-14), summed across CPUs, indexed by
/// `enum warden_event_kind`. Slot 0 is never written, so it reads zero.
#[derive(Debug, Clone, Copy, Default)]
pub struct SensorCounters {
    /// Records the sensor tried to emit while the ring was full.
    pub drops: [u64; KIND_SLOTS],
    /// Records the sensor actually handed to the ring.
    pub submitted: [u64; KIND_SLOTS],
}

impl SensorCounters {
    /// The sensor that lost the most, for a one-line attribution in the journal.
    /// `None` when nothing was lost.
    pub fn worst_drop(&self) -> Option<(crate::events::Kind, u64)> {
        crate::events::Kind::ALL
            .iter()
            .map(|k| (*k, self.drops[*k as usize]))
            .filter(|(_, n)| *n > 0)
            .max_by_key(|(_, n)| *n)
    }
}

/// Sum one PERCPU_ARRAY slot across every CPU's copy. A slot the kernel never
/// wrote reads zero, which is the right answer for slot 0 — the only index no
/// event kind uses.
fn per_cpu_total(map: &PerCpuArray<MapData, u64>, slot: u32) -> anyhow::Result<u64> {
    Ok(map.get(&slot, 0)?.iter().copied().sum::<u64>())
}

/// Everything the event loop needs after load+attach: the ring buffer to poll,
/// and the two maps it writes policy into. `_ebpf` is retained only to keep the
/// program links alive — dropping it detaches every sensor and restores the
/// kernel to its normal behaviour, so Warden leaves no trace when it exits.
pub struct Loaded {
    pub events: RingBuf<MapData>,
    protected_pids: HashMap<MapData, u32, u8>,
    runtime_cfg: Array<MapData, u32>,
    /// W-02: one counter per CPU per event kind (index = `enum warden_event_kind`,
    /// slot 0 unused), bumped by the kernel every time `bpf_ringbuf_reserve`
    /// failed. Nothing here is ever written by userspace — it is the only surviving
    /// record that a flood happened at all, so it is retained for the life of the
    /// process and read by `dropped()` / `sensor_counters()`.
    ringbuf_drops: PerCpuArray<MapData, u64>,
    /// W2K-14: the mirror of `ringbuf_drops` for records that were handed to the
    /// ring. Without it, "0 drops, 0 events" is ambiguous between a quiet host and
    /// a sensor that never fired; with it, each sensor has its own denominator.
    ringbuf_events: PerCpuArray<MapData, u64>,
    /// N-05: the per-cgroup byte/operation totals the six fexit programs add to.
    /// A hard requirement like the two counters above — the object is embedded in
    /// this binary, so a missing map here means the kernel side and the reader have
    /// diverged, and continuing would print a `0 cgroup(s) tracked` line that reads
    /// as an idle host instead of the broken pairing it is.
    net_volume: HashMap<MapData, u64, VolumeRecord>,
    /// N-05: `[0]` refused, `[1]` landed bumps, `[2..8)` per-hook fexit
    /// invocations. The denominator for the totals: without it, an empty map is
    /// ambiguous between "nothing moved", "gate off" and "no hook ever fired".
    net_volume_stats: PerCpuArray<MapData, u64>,
    /// Which of the six volume hooks actually attached. `net_volume_totals`
    /// carries it into every read so a one-sided total cannot be presented as a
    /// measurement, and `main.rs` prints it on the coverage line at startup.
    pub volume_hooks: VolumeHooks,
    /// The (dev, ino) → policy map the BPF-LSM guard programs consult. `None` when
    /// the object carries the map but the LSM programs could NOT attach (no "bpf"
    /// LSM active on this kernel — see `attach`): with nothing enforcing, writing
    /// guard policy would be a lie, so we drop the handle and `sync_guarded_inodes`
    /// becomes a no-op that says so.
    guarded_inodes: Option<HashMap<MapData, InodeKey, GuardPolicy>>,
    /// Whether the six BPF-LSM enforcing programs actually attached. False on a
    /// kernel without the "bpf" LSM in its active list; the sensor half still runs.
    pub lsm_attached: bool,
    /// Phase 7 egress: the verified hook/arm/policy state. Every fact inside is
    /// set from the kernel's attach result or a map read-back, never from config
    /// alone, so `policy.rs` can tell "attached" from "wanted".
    pub egress_runtime: EgressRuntime,
    /// The exact-destination policy map the four cgroup programs consult. Held
    /// even when egress is disabled (the map exists in the embedded object) so
    /// the reader can always report its true generation and readiness.
    egress_policy: HashMap<MapData, EgressKey, EgressRule>,
    /// The four kernel counters that distinguish "no rule matched" from "a rule
    /// matched in shadow" from "an armed rule really denied".
    egress_stats: Array<MapData, u64>,
    /// W2K-13: the capacity the kernel actually built for `events`, read back from
    /// the created map. The drop-rate warning quotes this, because a warning that
    /// says "N events dropped" against a capacity nobody measured is advice with
    /// a missing half. `None` only when `BPF_OBJ_GET_INFO_BY_FD` would not answer;
    /// the counters keep counting either way.
    pub ring_capacity_bytes: Option<u32>,
    _ebpf: Ebpf,
}

/// runtime_cfg slot indices — must match `enum warden_cfg_slot` in warden.h.
/// The kernel reads these to decide whether a sensor emits; userspace writes
/// them here. Numbered, never reused.
const CFG_EXEC_EMIT: u32 = 0;
const CFG_CONNECT_EMIT: u32 = 1;
const CFG_MODULE_EMIT: u32 = 2;
const CFG_FILE_EMIT: u32 = 3;
const CFG_SERVICE_EMIT: u32 = 4;
const CFG_LISTEN_EMIT: u32 = 5;
const CFG_BPF_EMIT: u32 = 6;
const CFG_MOUNT_EMIT: u32 = 7;
const CFG_ACCESS_EMIT: u32 = 8;
const CFG_ENFORCE_ARM: u32 = 9;
const CFG_CONNECT_RESULT_EMIT: u32 = 10;
const CFG_FLOW_EMIT: u32 = 11;
const CFG_NET_VOLUME_EMIT: u32 = 12;

/// Cgroups the kernel's volume map can track — must match `WARDEN_NET_VOLUME_MAX`
/// in `bpf/warden.h`, and is asserted against the shipped object by
/// `tests/net_volume_abi.rs`. Quoted by the coverage line, because "at most N
/// cgroups, and here is how many were refused" is the difference between a
/// partial view and a smaller truth.
pub const NET_VOLUME_MAX: usize = 512;

/// The eight health slots of `net_volume_stats`, matching
/// `enum warden_net_volume_stat` in `bpf/warden.h`. Slots 2..8 are lifetime
/// fexit invocations in `VolumeHook::ALL` order.
const NET_VOLUME_STAT_FULL: u32 = 0;
const NET_VOLUME_STAT_BUMP: u32 = 1;
const NET_VOLUME_STAT_TCP_OUT: u32 = 2;
const NET_VOLUME_STAT_TCP_IN: u32 = 3;
const NET_VOLUME_STAT_UDP_OUT: u32 = 4;
const NET_VOLUME_STAT_UDP_IN: u32 = 5;
const NET_VOLUME_STAT_UDP6_OUT: u32 = 6;
const NET_VOLUME_STAT_UDP6_IN: u32 = 7;

/// The six BPF-LSM enforcing programs, in `bpf/warden.bpf.c`, paired with the
/// LSM hook each attaches to. `Lsm::load` takes the bare hook name (no `bpf_lsm_`
/// prefix) and resolves it through BTF. Kept as a table so the attach loop reads
/// as data, and so a future seventh hook is one row rather than another block.
const LSM_PROGRAMS: &[(&str, &str)] = &[
    ("warden_guard_file_open", "file_open"),
    ("warden_guard_mmap_file", "mmap_file"),
    ("warden_guard_inode_unlink", "inode_unlink"),
    ("warden_guard_inode_rename", "inode_rename"),
    ("warden_guard_inode_setattr", "inode_setattr"),
    ("warden_guard_file_permission", "file_permission"),
];

/// The two host facts that decide whether `perf_event_open(2)` will accept a
/// tracepoint or kprobe at all — a gate that has nothing to do with BPF.
///
/// `paranoid > 1` makes the kernel require **CAP_SYS_ADMIN** for those two event
/// types, and `CAP_PERFMON` does not satisfy it. Measured on the lab VM (Debian
/// 13, 6.12.107+deb13-amd64, `perf_event_paranoid = 3`): a process holding
/// CAP_BPF+CAP_PERFMON+CAP_SYS_PTRACE+CAP_KILL — the set the unit shipped until
/// this measurement existed — gets `EACCES` on the very first attach, so Warden
/// exits before any sensor, any BPF-LSM program, or any protection is live.
/// Mainline's default for the knob is 2, so `> 1` is the ordinary case rather
/// than a hardened one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfGate {
    /// `/proc/sys/kernel/perf_event_paranoid`, or `None` if it could not be read.
    paranoid: Option<i64>,
    /// Whether CAP_SYS_ADMIN is in THIS process's effective set, or `None` if
    /// `/proc/self/status` could not be read.
    sys_admin: Option<bool>,
}

/// CAP_SYS_ADMIN's bit position in the `CapEff` mask (linux/capability.h).
const CAP_SYS_ADMIN_BIT: u32 = 21;

impl PerfGate {
    /// Read the two facts. Nothing here is privileged: both files are
    /// world-readable, and no syscall that needs a capability is attempted — so
    /// `warden --doctor` can answer this question as any user, which is the point.
    pub fn read() -> Self {
        let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok());
        let sys_admin = std::fs::read_to_string("/proc/self/status")
            .ok()
            .map(|body| {
                body.lines()
                    .find_map(|l| l.strip_prefix("CapEff:"))
                    .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                    .map(|mask| (mask >> CAP_SYS_ADMIN_BIT) & 1 == 1)
                    .unwrap_or(false)
            });
        PerfGate {
            paranoid,
            sys_admin,
        }
    }

    /// Would this process be refused a tracepoint/kprobe perf event?
    ///
    /// An unknown fact answers `false`. The preflight exists to replace an
    /// anonymous `EACCES` with a named cause, and a preflight that guessed would
    /// refuse a start that was going to work — the same false-negative rule
    /// `doctor::State::Unreadable` exists for.
    pub fn refuses_tracepoints(&self) -> bool {
        matches!(self.paranoid, Some(p) if p > 1) && self.sys_admin == Some(false)
    }

    /// The two facts, for `--doctor` to print. Exposed as accessors rather than
    /// public fields so the "unknown" case cannot be flattened into a number.
    pub fn paranoid(&self) -> Option<i64> {
        self.paranoid
    }

    pub fn holds_sys_admin(&self) -> Option<bool> {
        self.sys_admin
    }

    /// A gate built from the two facts, for tests and for callers that already
    /// read them (a unit test cannot change the host's `/proc`).
    #[cfg(test)]
    pub fn from_parts(paranoid: Option<i64>, sys_admin: Option<bool>) -> Self {
        PerfGate {
            paranoid,
            sys_admin,
        }
    }

    /// The sentence an operator needs: what was seen, and both remedies.
    pub fn explain(&self) -> String {
        let paranoid = self
            .paranoid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "unreadable".to_string());
        format!(
            "kernel.perf_event_paranoid is {paranoid} and this process does not hold \
             CAP_SYS_ADMIN. While the knob is above 1 the kernel gates perf_event_open() for \
             tracepoints and kprobes on CAP_SYS_ADMIN specifically — CAP_BPF and CAP_PERFMON do \
             not satisfy it — so Warden's exec tracepoint and every security_* kprobe would fail \
             with EACCES and the agent would run with no sensors at all. Either grant \
             CAP_SYS_ADMIN in the unit's AmbientCapabilities (what systemd/warden.service does \
             now; the syscall filter keeps mount/reboot/kexec/ptrace-injection refused \
             regardless), or set kernel.perf_event_paranoid = 1 host-wide, which is the weaker \
             choice because it opens kernel tracing to every unprivileged process on the host."
        )
    }
}

impl Loaded {
    /// Load the object, load+attach the sensor programs, and take ownership of
    /// the maps. Requires CAP_BPF+CAP_PERFMON for the BPF side, and — because
    /// the sensors are perf events, not only BPF programs — CAP_SYS_ADMIN unless
    /// `kernel.perf_event_paranoid` is 1 or lower: see [`PerfGate`], which is
    /// checked before anything is loaded so the refusal names itself instead of
    /// surfacing as `Permission denied (os error 13)` after the object is in the
    /// kernel. (`CAP_SYS_PTRACE` is used by the responder, not here.)
    ///
    /// `ring_bytes` is the capacity policy asked for (`[runtime].ring_size_kib`);
    /// it is applied at map *creation*, which is the only moment a ring's size is
    /// still a decision. Passing the default re-states the 256 KiB baked into
    /// `bpf/warden.bpf.c` and changes nothing, so an operator who never edits the
    /// new key runs exactly the ring Warden has always run.
    pub fn attach(ring_bytes: u32, egress: Option<(&Path, bool)>) -> anyhow::Result<Self> {
        let gate = PerfGate::read();
        if gate.refuses_tracepoints() {
            return Err(anyhow::anyhow!(gate.explain()));
        }

        let mut ebpf = EbpfLoader::new()
            .set_max_entries("events", ring_bytes)
            .load(WARDEN_OBJ)?;

        // 1. exec tripwire — tracepoint sched:sched_process_exec.
        {
            let prog: &mut TracePoint = ebpf
                .program_mut("warden_on_exec")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_exec missing from object"))?
                .try_into()?;
            prog.load()?;
            prog.attach("sched", "sched_process_exec")?;
        }

        // 2. takedown tripwire — kprobe on security_task_kill.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_task_kill")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_task_kill missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_task_kill", 0)?;
        }

        // 3. inspect/inject tripwire — kprobe on security_ptrace_access_check.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_ptrace")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_ptrace missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_ptrace_access_check", 0)?;
        }

        // 4. egress tripwire — kprobe on security_socket_connect (C2 dial-out).
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_connect")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_connect missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_socket_connect", 0)?;
        }

        // 4b. the dial's VERDICT — a kprobe/kretprobe pair on __inet_stream_connect
        // (N-02). The pair is deliberate: the destination only exists on the way in
        // and the verdict only exists on the way out, and the two records of one dial
        // have to agree on the endpoint byte-for-byte or userspace cannot pair them.
        //
        // This is the first Warden attach target that is NOT an LSM/security_* hook:
        // `security_*` names are the stable API surface, while an internal function
        // name is a weaker contract. It was therefore measured before being shipped
        // (see docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md §§16/42): the symbol is
        // present and non-blacklisted on the deployment kernel, the pair attaches and
        // fires there, and both signatures agree on the two kernels surveyed. The cost
        // of getting this wrong is N-14's: a target that cannot be resolved fails the
        // load, and the loader is fail-closed, so the agent would not start at all.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_connect_start")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_connect_start missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("__inet_stream_connect", 0)?;
        }
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_connect_result")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_connect_result missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("__inet_stream_connect", 0)?;
        }

        // 4c. the inbound ACCEPT — a kprobe/kretprobe pair on `inet_accept` (N-03
        // accept half, N-04, N-12). Like 4b this is an internal function, not an
        // `security_*` hook, and it is here because the stable hook cannot answer the
        // question: `security_socket_accept` runs before the protocol family installs
        // the child socket, so 2021/2021 entry and 2184/2184 return probes on the
        // deployment kernel saw `newsock->sk == NULL` and had no peer to report.
        // `inet_accept`'s return is where the child holds its 4-tuple while `current`
        // is still the accepting task. Measured before shipping (docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md and
        // docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md §45/§46): symbol present and kprobe-attachable,
        // signature vlen=3 on both surveyed kernels, 6301 calls fired cleanly, zero
        // stash misses, peak 3 entries outstanding.
        //
        // N-14's caveat applies with full force here and is the reason this stage was
        // measured rather than reasoned about: a kprobe target that does not resolve
        // fails the load, the loader is fail-closed, and the agent would not start.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_accept_start")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_accept_start missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("inet_accept", 0)?;
        }
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_flow")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_flow missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("inet_accept", 0)?;
        }

        // ── network volume counters (N-05, roadmap stage 16b) ────────────────
        //
        // Three fexit programs that write a map instead of a ring record, so the
        // answer to "how many bytes did this cgroup move" does not depend on the
        // ring having survived the traffic that prompted the question. They are
        // attached here — at load time, gated per-event inside the kernel by
        // CFG_NET_VOLUME_EMIT — because a counter map only accumulates while the
        // agent runs, and a sensor that attached lazily on first read would report
        // zero for every interval before it.
        //
        // The degradation contract is N-14's, and it is the reason this block
        // looks different from the twelve above it: a fexit target that does not
        // resolve, or is not ftrace-able, fails `FExit::load`. Propagating that
        // would mean the whole guardian refusing to start because an *observational*
        // byte counter was unavailable on this kernel — the exact asymmetry the
        // report names as unacceptable for an 8-bit field, one notch larger. So
        // each of the six is attempted on its own, the outcome is recorded per
        // hook, and `main.rs` prints which halves are missing on every run. A host
        // where `tcp_cleanup_rbuf` was inlined gets egress totals and a loud note
        // saying the ingress half is absent, which is a different claim from a
        // host where nothing attached.
        // M15: check the kernel's own FUNC prototypes BEFORE asking aya to load
        // an fexit against them. An argument-count drift is not an attach failure
        // to be discovered in a generic warning: it is a deliberate skip with a
        // named cause, and the coverage line must carry that cause. UNKNOWN (an
        // unreadable BTF) does NOT block an attempt — only a measured mismatch
        // does, so a transient file-read problem cannot manufacture a gap.
        let mut volume_hooks = net_vol::VolumeHooks::default();
        let abi = crate::btf_compat::check_all(crate::btf_compat::BTF_PATH);
        for status in &abi {
            if status.status.blocks_attach() {
                volume_hooks.reject_abi(status.hook, status.reason());
                log::warn!(
                    "net_volume: BTF ABI preflight skipped fexit/{}: {}. The hook is not \
                     compatible with this kernel's prototype; its totals will be reported as \
                     absent with this reason, not as zero traffic.",
                    status.hook.func(),
                    status.reason()
                );
            }
        }
        if abi
            .iter()
            .all(|s| s.status == crate::btf_compat::Compatibility::Compatible)
        {
            log::info!(
                "net_volume: BTF ABI preflight matched all six fexit prototypes on this kernel"
            );
        }
        match Btf::from_sys_fs() {
            Ok(btf) => {
                for hook in net_vol::VolumeHook::ALL {
                    if let Some(reason) = volume_hooks.abi_reason(hook) {
                        log::warn!(
                            "net_volume: fexit/{} was not loaded because BTF ABI preflight \
                             rejected it: {reason}",
                            hook.func()
                        );
                        continue;
                    }
                    match Self::attach_one_fexit(&mut ebpf, hook, &btf) {
                        Ok(()) => volume_hooks.attach(hook),
                        Err(e) => log::warn!(
                            "net_volume: {} could not attach to fexit/{} ({e}); {} will stay \
                             empty on this kernel. Warden continues — the counter is \
                             observational, and a missing half is reported by the coverage \
                             line rather than being silently read as zero traffic. To check \
                             whether the target is attachable at all, look for it in \
                             /sys/kernel/tracing/available_filter_functions.",
                            hook.prog_name(),
                            hook.func(),
                            hook.measures()
                        ),
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "net_volume: kernel BTF unavailable ({e}); the fexit volume counters cannot \
                     load, so no byte or operation totals will be kept this run. Every other \
                     sensor is unaffected."
                );
            }
        }

        // 5. privilege-escalation tripwire — kprobe on commit_creds (privesc).
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_commit_creds")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_commit_creds missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("commit_creds", 0)?;
        }

        // 6. rootkit tripwire — tracepoint module:module_load (LKM implant).
        {
            let prog: &mut TracePoint = ebpf
                .program_mut("warden_on_module_load")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_module_load missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("module", "module_load")?;
        }

        // 7. ransomware / tamper tripwires — kprobes on the two destructive-file
        // LSM chokepoints. Both feed one WARDEN_FILE kind, distinguished by op.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_inode_rename")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_inode_rename missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_inode_rename", 0)?;
        }
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_inode_unlink")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_inode_unlink missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_inode_unlink", 0)?;
        }

        // 8. persistence tripwire — kprobe on security_inode_create. A file
        // dropped into a boot/login-survival directory (systemd unit, cron,
        // autostart, authorized_keys, …); the kernel captures the path ladder and
        // userspace holds the persistence-dir allowlist.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_inode_create")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_inode_create missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_inode_create", 0)?;
        }

        // 9. bind-shell / backdoor tripwire — kprobe on security_socket_listen. A
        // socket entering LISTEN is the inbound dual of egress: the box is now
        // waiting for the attacker to dial in. Userspace holds the port allowlist.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_listen")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_listen missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_socket_listen", 0)?;
        }

        // 10. eBPF-rootkit tripwire — kprobe on security_bpf. Emits only on
        // BPF_PROG_LOAD (map ops are far too hot and uninteresting). Warden loads
        // its own programs before this probe attaches, so it never trips itself.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_bpf")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_bpf missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_bpf", 0)?;
        }

        // 11. container-escape tripwire — kprobe on security_sb_mount. A mount
        // (especially a bind mount of the host root/device tree) is how a
        // contained attacker breaks containment; userspace holds the source
        // allowlist.
        {
            let prog: &mut KProbe = ebpf
                .program_mut("warden_on_sb_mount")
                .ok_or_else(|| anyhow::anyhow!("program warden_on_sb_mount missing"))?
                .try_into()?;
            prog.load()?;
            prog.attach("security_sb_mount", 0)?;
        }

        // 12. the ENFORCING half — 6 BPF-LSM programs that can return -EPERM to
        // actually DENY a touch of a guarded inode (the other 12 only observe).
        // These attach ONLY when the "bpf" LSM is in the kernel's active list
        // (CONFIG_BPF_LSM=y AND `bpf` present in `lsm=` at boot). On a kernel
        // without it, `Btf::from_sys_fs` or `Lsm::attach` fails — and that must NOT
        // take the whole guardian down: the 11 sensors above are fully functional
        // and valuable on their own. So we treat an LSM failure as "enforcement
        // unavailable on this host", log it loudly ONCE, and continue detection-only.
        // `lsm_attached` records which world we're in; main.rs surfaces it and
        // `sync_guarded_inodes` refuses to pretend it's guarding when it isn't.
        let lsm_attached = match Btf::from_sys_fs() {
            Ok(btf) => {
                let mut all_ok = true;
                for (prog_name, hook) in LSM_PROGRAMS {
                    match Self::attach_one_lsm(&mut ebpf, prog_name, hook, &btf) {
                        Ok(()) => {}
                        Err(e) => {
                            // First failure is the whole story (they share a cause:
                            // the bpf LSM isn't active). Warn once, stop trying.
                            log::warn!(
                                "enforce: BPF-LSM program {prog_name} could not attach to \
                                 lsm/{hook} ({e}); enforcement is UNAVAILABLE on this kernel. \
                                 Warden continues in detection-only mode. To enable in-kernel \
                                 denial, add `bpf` to the boot LSM list (e.g. \
                                 lsm=landlock,lockdown,yama,integrity,apparmor,bpf) and reboot."
                            );
                            all_ok = false;
                            break;
                        }
                    }
                }
                all_ok
            }
            Err(e) => {
                log::warn!(
                    "enforce: kernel BTF unavailable ({e}); BPF-LSM enforcement cannot load. \
                     Warden continues in detection-only mode."
                );
                false
            }
        };
        // 13. Phase 7 cgroup egress (OPTIONAL, OFF BY DEFAULT). Unlike every
        // sensor above, these four programs are only loaded and attached when
        // the operator explicitly named an isolated cgroup. `None` means the
        // object still carries the programs and maps, but nothing is attached,
        // nothing is armed, and no rule can deny traffic. A config knob alone
        // cannot manufacture a deny primitive: the hook facts below come from
        // `bpf_link_create` succeeding, not from what was requested.
        let (egress_hooks, egress_enabled, egress_armed) = match egress {
            Some((cgroup_path, arm)) => {
                // Validate and attach from the SAME fd: checking one path and
                // reopening another is the TOCTOU window this helper closes.
                let cgroup = open_validated_cgroup(cgroup_path)?;
                let mut hooks = EgressHooks::default();
                for hook in EgressHook::ALL {
                    match Self::attach_one_cgroup(&mut ebpf, hook, &cgroup) {
                        Ok(()) => hooks.mark(hook),
                        Err(e) => log::warn!(
                            "egress: {} could not attach to {} ({e}); this protocol's denies \
                             will NOT be enforced. Warden continues — a partial attach is \
                             reported as DEGRADED by the policy claim, never as full coverage.",
                            hook.program_name(),
                            hook.section()
                        ),
                    }
                }
                (hooks, true, arm)
            }
            None => (EgressHooks::default(), false, false),
        };

        // borrow; `ebpf` itself is retained to hold the program links alive.
        let events_map = ebpf
            .take_map("events")
            .ok_or_else(|| anyhow::anyhow!("map events missing"))?;
        // W2K-13: ask the kernel what it built rather than quoting what was
        // requested. A ring buffer is allocated as a power-of-two number of pages,
        // so the two can differ for any size the config did not validate — and the
        // drop counters below are measured against this number, not the config.
        let ring_capacity_bytes = match &events_map {
            // The `RingBuf` variant is what `RingBuf::try_from` below requires, so
            // this arm is the only one a working Warden can reach; anything else
            // says "unknown", not "zero", because the warning that quotes this
            // number is the same warning that must never round a loss down to 0.
            Map::RingBuf(data) => match data.info() {
                Ok(info) => Some(info.max_entries()),
                Err(e) => {
                    log::debug!(
                        "loader: could not read back the events map capacity ({e}); the \
                         drop-rate warning will quote the requested size instead"
                    );
                    None
                }
            },
            _ => None,
        };
        let events = RingBuf::try_from(events_map)?;
        let protected_pids = HashMap::try_from(
            ebpf.take_map("protected_pids")
                .ok_or_else(|| anyhow::anyhow!("map protected_pids missing"))?,
        )?;
        let runtime_cfg = Array::try_from(
            ebpf.take_map("runtime_cfg")
                .ok_or_else(|| anyhow::anyhow!("map runtime_cfg missing"))?,
        )?;
        // W-02: the drop counter. A hard error rather than an `Option`, unlike
        // `guarded_inodes`: that map is legitimately inert when no LSM attached,
        // whereas this one has no harmless missing state. The object is embedded
        // in this same binary, so an absent map means `bpf/warden.bpf.o` and this
        // source have diverged — and continuing with an uncounted ring would
        // reinstate exactly the invisible loss the audit reported. Refusing to
        // start is the loud failure; a warn-and-continue would be the quiet one.
        let ringbuf_drops = PerCpuArray::try_from(
            ebpf.take_map("ringbuf_drops")
                .ok_or_else(|| anyhow::anyhow!("map ringbuf_drops missing"))?,
        )?;
        // W2K-14: same contract as the drop counter — a missing map here means the
        // object and this source have diverged, and continuing would restore the
        // ambiguity this counter exists to remove (no per-sensor denominator).
        let ringbuf_events = PerCpuArray::try_from(
            ebpf.take_map("ringbuf_events")
                .ok_or_else(|| anyhow::anyhow!("map ringbuf_events missing"))?,
        )?;

        // N-05: the volume totals and their health slots. Required maps, on the
        // same reasoning as the two ring counters above: a missing one is an
        // object/source divergence, not a harmless absence, and reading a map that
        // does not exist would print a confident "0 cgroup(s) tracked".
        let net_volume = HashMap::try_from(
            ebpf.take_map("net_volume")
                .ok_or_else(|| anyhow::anyhow!("map net_volume missing"))?,
        )?;
        let net_volume_stats = PerCpuArray::try_from(
            ebpf.take_map("net_volume_stats")
                .ok_or_else(|| anyhow::anyhow!("map net_volume_stats missing"))?,
        )?;

        // Phase 7: the two egress maps. Hard requirements like the two ring
        // counters above — the object is embedded in this binary, so an absent
        // map means the BPF source and this reader diverged. Taking them even
        // when egress is disabled is intentional: `--doctor` can then say the
        // policy map is at generation 0 and ready rather than guessing.
        let egress_policy = HashMap::try_from(
            ebpf.take_map("egress_policy")
                .ok_or_else(|| anyhow::anyhow!("map egress_policy missing"))?,
        )?;
        let egress_stats = Array::try_from(
            ebpf.take_map("egress_stats")
                .ok_or_else(|| anyhow::anyhow!("map egress_stats missing"))?,
        )?;
        let mut egress_runtime = EgressRuntime::new(egress_enabled, egress_armed);
        egress_runtime.hooks = egress_hooks;

        // The guard map exists in the object whether or not the LSM programs
        // attached (it's a plain hash map). Only keep a handle to it when the
        // programs that READ it are live — otherwise policy written here enforces
        // nothing, and holding the handle would invite exactly that illusion.
        let guarded_inodes = if lsm_attached {
            match ebpf.take_map("guarded_inodes") {
                Some(m) => Some(HashMap::try_from(m)?),
                None => {
                    log::warn!(
                        "enforce: LSM programs attached but map guarded_inodes is missing; \
                         no files can be guarded this run"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            events,
            protected_pids,
            runtime_cfg,
            ringbuf_drops,
            ringbuf_events,
            net_volume,
            net_volume_stats,
            volume_hooks,
            guarded_inodes,
            lsm_attached,
            egress_runtime,
            egress_policy,
            egress_stats,
            ring_capacity_bytes,
            _ebpf: ebpf,
        })
    }

    /// Load and attach one of the four cgroup socket-address programs to the
    /// named cgroup. `CgroupAttachMode::Single` means one program per attach
    /// point (no overriding an existing link), and the returned link is kept
    /// alive by the program data inside `ebpf` so detachment follows Warden's
    /// lifetime — the same "leave no trace on exit" contract as the sensors.
    fn attach_one_cgroup(
        ebpf: &mut Ebpf,
        hook: EgressHook,
        cgroup: &std::fs::File,
    ) -> anyhow::Result<()> {
        let prog: &mut CgroupSockAddr = ebpf
            .program_mut(hook.program_name())
            .ok_or_else(|| anyhow::anyhow!("program {} missing from object", hook.program_name()))?
            .try_into()?;
        prog.load()?;
        prog.attach(cgroup.as_fd(), CgroupAttachMode::Single)?;
        Ok(())
    }

    /// Load one BPF-LSM program and attach it to its hook. Split out so the attach
    /// loop stays readable and every LSM program is loaded identically: `Lsm::load`
    /// sets expected_attach_type = BPF_LSM_MAC and resolves `bpf_lsm_<hook>` through
    /// the kernel BTF, then `attach` installs it into the LSM callback chain.
    fn attach_one_lsm(
        ebpf: &mut Ebpf,
        prog_name: &str,
        hook: &str,
        btf: &Btf,
    ) -> anyhow::Result<()> {
        let prog: &mut Lsm = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("program {prog_name} missing from object"))?
            .try_into()?;
        prog.load(hook, btf)?;
        prog.attach()?;
        Ok(())
    }

    /// Load and attach one of the six volume `fexit` programs to its kernel
    /// function. Split out for the same reason as `attach_one_lsm`: every program
    /// of a kind is loaded identically, so the only thing that varies per hook is
    /// which function it names.
    ///
    /// `FExit::load` resolves the function through the running kernel's BTF and
    /// `attach` installs a trampoline at its ftrace location — which is why the
    /// failure this returns is a fact about the kernel, not about the object: a
    /// function that was inlined into its callers has no location to attach to.
    fn attach_one_fexit(
        ebpf: &mut Ebpf,
        hook: net_vol::VolumeHook,
        btf: &Btf,
    ) -> anyhow::Result<()> {
        let prog: &mut FExit = ebpf
            .program_mut(hook.prog_name())
            .ok_or_else(|| anyhow::anyhow!("program {} missing from object", hook.prog_name()))?
            .try_into()?;
        prog.load(hook.func(), btf)?;
        prog.attach()?;
        Ok(())
    }

    /// Flip the volume counter's gate: 1 = the six fexit programs add to the map,
    /// 0 = they return immediately. Separate from every `set_*_emit` above because
    /// it mutes a counter rather than a record — nothing here ever reaches the ring,
    /// so this is the only knob an operator has once the totals are being kept.
    pub fn set_net_volume_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_NET_VOLUME_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the Phase 7 egress arm gate. `true` lets a matched DENY rule return
    /// -EPERM; `false` (the default and every unseeded value) keeps SHADOW. This
    /// is the second independent switch — attaching the hooks without this is
    /// an audit position, not enforcement.
    pub fn set_egress_arm(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_EGRESS_ARM, if on { 1u32 } else { 0u32 }, 0)?;
        self.egress_runtime.armed = on;
        Ok(())
    }

    /// Read the arm slot back from the kernel. The kernel is the authority on
    /// whether denial is active; a config field that says `arm=true` while the
    /// write failed must not be reported as armed.
    pub fn egress_armed(&self) -> anyhow::Result<bool> {
        Ok(self.runtime_cfg.get(&CFG_EGRESS_ARM, 0)? == 1)
    }

    /// The verified egress state (hooks, arm, policy generation/readiness).
    pub fn egress_runtime(&self) -> &EgressRuntime {
        &self.egress_runtime
    }

    /// Install an exact deny policy with transactional rollback. No-op that
    /// reports zero when egress is disabled — a disabled build must never write
    /// rules into a map that no program reads.
    pub fn sync_egress_policy(&mut self, denies: &[EgressDeny]) -> anyhow::Result<usize> {
        if !self.egress_runtime.enabled {
            return Ok(0);
        }
        if denies.len() > EGRESS_POLICY_MAX {
            anyhow::bail!(
                "{} egress deny rule(s) exceed the kernel map capacity of {EGRESS_POLICY_MAX}",
                denies.len()
            );
        }
        let written = self.egress_runtime.policy_mut().sync_with_stats(
            &mut self.egress_policy,
            denies,
            &mut self.egress_stats,
        )?;
        Ok(written)
    }

    /// Apply one classified SIGHUP reload against the real kernel maps. The
    /// arm slot and policy map are passed as the verified traits from
    /// `egress.rs`; tests exercise the same state machine with injectable
    /// doubles, but production always uses these aya map handles.
    pub fn apply_egress_reload(
        &mut self,
        transition: EgressReloadTransition,
        desired_arm: bool,
        denies: &[EgressDeny],
    ) -> anyhow::Result<EgressReloadReport> {
        apply_egress_reload_facts(
            &mut self.egress_runtime,
            &mut self.runtime_cfg,
            &mut self.egress_policy,
            transition,
            desired_arm,
            denies,
            &mut self.egress_stats,
        )
    }

    /// Sample the kernel's egress counters. Monotonic since load; difference two
    /// samples for a rate. A read failure is an error, not a zero — zero loss is
    /// the reassuring answer and must never come from a failed read.
    pub fn egress_stats(&self) -> anyhow::Result<EgressStats> {
        EgressStats::read(&self.egress_stats)
    }

    /// Read every cgroup's absolute totals, resolved to paths where the caller's
    /// walk found them.
    ///
    /// The path map is a parameter, not looked up here, for two reasons: the walk
    /// of `/sys/fs/cgroup` is policy-bounded (`cgroup_walk_max`) and the loader has
    /// no business knowing policy, and making the caller do it puts the cost of the
    /// tick in one visible place instead of hiding a filesystem walk inside a map
    /// read.
    ///
    /// `paths` missing an id is not an error and not a zero: the row is returned
    /// with `cgroup: None`, which the report prints as "cgroup gone or beyond the
    /// walk bound". A counter for a tenant we could not name is still a counter.
    pub fn net_volume_totals(&self, paths: &BTreeMap<u64, String>) -> anyhow::Result<VolumeTotals> {
        let mut rows: Vec<CgroupVolume> = Vec::new();
        // A row we could not read is a coverage hole, so it is counted rather
        // than skipped in silence — the same discipline that made the drop
        // counters a hard requirement instead of an `Option`.
        let mut unreadable = 0u64;
        for entry in self.net_volume.iter() {
            match entry {
                Ok((cgroup_id, totals)) => rows.push(CgroupVolume {
                    cgroup_id,
                    cgroup: paths.get(&cgroup_id).cloned(),
                    totals,
                }),
                Err(_) => unreadable += 1,
            }
        }
        if unreadable > 0 {
            log::warn!(
                "net_volume: {unreadable} map entry(s) could not be read; the totals below are \
                 missing that many cgroups and are NOT a complete view of this host"
            );
        }
        rows.sort_by_key(|r| r.cgroup_id);
        Ok(VolumeTotals {
            rows,
            refused: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_FULL)?,
            bumps: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_BUMP)?,
            invocations: VolumeInvocations {
                tcp_sendmsg: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_TCP_OUT)?,
                tcp_cleanup_rbuf: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_TCP_IN)?,
                udp_sendmsg: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_UDP_OUT)?,
                udp_recvmsg: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_UDP_IN)?,
                udpv6_sendmsg: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_UDP6_OUT)?,
                udpv6_recvmsg: per_cpu_total(&self.net_volume_stats, NET_VOLUME_STAT_UDP6_IN)?,
            },
            hooks: self.volume_hooks.clone(),
        })
    }

    /// Total events the kernel dropped because the ring buffer was full, summed
    /// across every CPU, since load. W-02.
    ///
    /// Monotonic — it only ever grows — so a caller that wants "how much was lost
    /// just now" must difference two samples. A bare reading says nothing about
    /// the present, and reporting the lifetime total as though it were the current
    /// rate would make one burst an hour ago look like a flood happening now.
    ///
    /// A failed read is returned as an error rather than flattened to zero.
    /// "Nothing was dropped" and "the counter could not be read" are different
    /// facts, and conflating them is the fail-open direction: zero loss is the
    /// reassuring answer, so it is the one an unreadable counter must never be
    /// allowed to give. This is the same trap the balance path had.
    pub fn dropped(&self) -> anyhow::Result<u64> {
        Ok(self.sensor_counters()?.drops.iter().sum::<u64>())
    }

    /// W2K-14: per-sensor loss and throughput, each summed across CPUs.
    ///
    /// The kernel indexes both maps by `enum warden_event_kind`, so the arrays
    /// here are indexable the same way and slot 0 is always zero. A failed read is
    /// returned as an error rather than a partial picture, for the reason
    /// [`Loaded::dropped`] gives: a counter that reads zero because it could not be
    /// read is the invisible-loss bug wearing a different hat.
    pub fn sensor_counters(&self) -> anyhow::Result<SensorCounters> {
        let mut out = SensorCounters::default();
        for slot in 0..KIND_SLOTS as u32 {
            out.drops[slot as usize] = per_cpu_total(&self.ringbuf_drops, slot)?;
            out.submitted[slot as usize] = per_cpu_total(&self.ringbuf_events, slot)?;
        }
        Ok(out)
    }

    /// Flip the exec sensor's emit gate: 1 = emit exec events, 0 = mute the exec
    /// sensor (the allowlist-learning window) without detaching the program.
    pub fn set_exec_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_EXEC_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the connect sensor's emit gate, same semantics as `set_exec_emit`.
    /// Muting egress detection during a noisy deploy without a full reload.
    pub fn set_connect_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_CONNECT_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the connect-OUTCOME sensor's emit gate, same semantics as the others.
    /// This one is a separate gate from `set_connect_emit` on purpose: the dial
    /// (where) and the verdict (what happened) are different evidence, and a
    /// mute-everything-on-egress window would otherwise be written as two calls
    /// that can drift apart. Muting stops the entry probe from stashing, and the
    /// return probe drains any stash regardless, so no stale entry survives a flip.
    pub fn set_connect_result_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_CONNECT_RESULT_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the accepted-FLOW sensor's emit gate, same semantics as the others.
    /// This is the sensor most likely to need muting: the deployment host measured
    /// ≈3.9 accepts per second in a quiet window, and a load balancer or a busy
    /// listener can multiply that, so an operator running an allowlist-learning
    /// pass — or simply trying to read the journal during a deploy — has a knob
    /// that costs one map write. The stash contract is the dial's: muting stops the
    /// entry probe storing, and the return probe drains whatever is there, so a
    /// flip mid-flight cannot leave a stale socket pointer for a recycled tid.
    pub fn set_flow_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_FLOW_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the module-load sensor's emit gate, same semantics as the others.
    /// Muting during a maintenance window that legitimately loads modules,
    /// without detaching the tracepoint.
    pub fn set_module_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_MODULE_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the file rename/unlink sensor's emit gate, same semantics as the
    /// others. Muting during a bulk migration or restore that legitimately churns
    /// files, without detaching the two kprobes.
    pub fn set_file_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_FILE_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the persistence-create sensor's emit gate, same semantics as the
    /// others. Muting during a provisioning/package run that legitimately writes
    /// units and cron entries, without detaching the kprobe.
    pub fn set_service_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_SERVICE_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the listen-socket sensor's emit gate, same semantics as the others.
    /// Muting during a deploy that legitimately opens new listeners, without
    /// detaching the kprobe.
    pub fn set_listen_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_LISTEN_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the bpf-prog-load sensor's emit gate, same semantics as the others.
    /// Muting during a window that legitimately loads tracing programs, without
    /// detaching the kprobe.
    pub fn set_bpf_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_BPF_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the mount sensor's emit gate, same semantics as the others. Muting
    /// during a maintenance window that legitimately mounts volumes, without
    /// detaching the kprobe.
    pub fn set_mount_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_MOUNT_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the guarded-inode ACCESS sensor's emit gate. This mutes the RECORDS the
    /// 6 LSM programs emit, NOT whether they deny — muting during an allowlist-
    /// learning window still lets `set_enforce_arm(true)` block, it just stops the
    /// shadow/deny event stream. Independent of `set_enforce_arm` on purpose.
    pub fn set_access_emit(&mut self, on: bool) -> anyhow::Result<()> {
        self.runtime_cfg
            .set(CFG_ACCESS_EMIT, if on { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Flip the ENFORCE arm gate — the one switch that turns a would-deny into an
    /// actual -EPERM. 0 = SHADOW (log the would-deny, allow the operation through);
    /// 1 = ARMED (return -EPERM, deny in-kernel). The kernel side fails CLOSED to
    /// shadow, so an unset slot never denies; arming is always this deliberate flip.
    ///
    /// PRQ-01: arming with no attached BPF-LSM program used to warn but still write
    /// the slot and return `Ok(())`, so startup/reload telemetry could report
    /// `arm=true` when nothing would deny — a misleading success. We now FAIL
    /// CLOSED: an arm request that cannot be honored is an error, and the arm slot
    /// is left at shadow. Disarming is always allowed so recovery stays possible.
    pub fn set_enforce_arm(&mut self, armed: bool) -> anyhow::Result<()> {
        if armed && !self.enforce_arm_effective() {
            anyhow::bail!(
                "enforce: arm=true requested but file enforcement is not effective \
                 (no BPF-LSM program attached or guarded-inode map unavailable); \
                 refusing to write the arm slot because nothing would deny. \
                 Check the active `bpf` LSM and kernel CAP_BPF, then restart WARDEN."
            );
        }
        self.runtime_cfg
            .set(CFG_ENFORCE_ARM, if armed { 1u32 } else { 0u32 }, 0)?;
        Ok(())
    }

    /// Effective file-enforcement posture: true only when a BPF-LSM program is
    /// attached AND this process still holds the live guarded-inode map handle.
    /// Telemetry and logs must derive "arm=true" claims from this, not from raw
    /// configuration, so a missing sensor cannot be reported as enforcement.
    pub fn enforce_arm_effective(&self) -> bool {
        self.lsm_attached && self.guarded_inodes.is_some()
    }

    /// Reconcile the kernel's guarded-inode map with `want` (the resolved output of
    /// `guard::resolve`): insert/overwrite every desired (dev, ino) → policy, and
    /// drop keys no longer wanted. Overwriting unconditionally means a policy edit
    /// (a changed deny mask or authorized_uid for the same inode) takes effect on
    /// the next tick, and a file rewritten in place — new inode — is added under
    /// its new key while the stale old key is reaped here. Returns the live guarded
    /// count after reconciliation.
    ///
    /// A no-op returning 0 when enforcement is unavailable (no LSM attached): with
    /// nothing reading the map, writing it would misrepresent the box as guarded.
    pub fn sync_guarded_inodes(
        &mut self,
        want: &BTreeMap<(u64, u64), GuardPolicy>,
    ) -> anyhow::Result<usize> {
        let map = match self.guarded_inodes.as_mut() {
            Some(m) => m,
            None => return Ok(0),
        };

        // What the kernel currently holds. A key we can't decode is unexpected;
        // skip it rather than abort the whole reconcile.
        let have: BTreeSet<(u64, u64)> = map
            .keys()
            .filter_map(|k| k.ok())
            .map(|k| (k.dev, k.ino))
            .collect();

        // Drop stale — a guarded file that was removed from policy, or whose inode
        // changed (its old inode lingers here until we reap it). PRQ-01: removals
        // are no longer silently ignored; a stale policy that fails to be removed
        // must be surfaced rather than reported as a clean desired-state count.
        let mut removal_errors = Vec::new();
        for (dev, ino) in have.difference(&want.keys().copied().collect()) {
            if let Err(e) = map.remove(&InodeKey {
                dev: *dev,
                ino: *ino,
            }) {
                removal_errors.push(format!("({dev}, {ino}): {e}"));
            }
        }
        if !removal_errors.is_empty() {
            anyhow::bail!(
                "guarded-inode reconcile failed to remove {} stale key(s): {}",
                removal_errors.len(),
                removal_errors.join("; ")
            );
        }

        // Insert/overwrite every wanted entry. Overwrite is intentional: it makes a
        // policy change to an already-guarded inode land without a remove/re-add.
        for ((dev, ino), policy) in want {
            map.insert(
                InodeKey {
                    dev: *dev,
                    ino: *ino,
                },
                *policy,
                0,
            )?;
        }
        // PRQ-01: report what the kernel actually holds, not `want.len()`, so a
        // failed insert/remove can never be described as a successful reconcile.
        let live = map.keys().filter_map(|k| k.ok()).count();
        Ok(live)
    }

    /// Reconcile the kernel's protected-pid set with `want`: push pids that are
    /// newly protected, drop pids that no longer are. Returns how many were
    /// newly inserted this call. The kernel map is the live source of truth the
    /// signal/ptrace probes consult, so this is what actually arms protection.
    pub fn sync_protected(&mut self, want: &BTreeSet<u32>) -> anyhow::Result<usize> {
        // Current keys in the kernel map.
        let have: BTreeSet<u32> = self.protected_pids.keys().filter_map(|k| k.ok()).collect();

        // Remove stale.
        for pid in have.difference(want) {
            // A pid that already exited leaves a stale key; remove is best-effort.
            let _ = self.protected_pids.remove(pid);
        }

        // Add new.
        let mut added = 0usize;
        for pid in want.difference(&have) {
            self.protected_pids.insert(*pid, 1u8, 0)?;
            added += 1;
        }
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Kind;

    #[test]
    fn the_perf_gate_refuses_only_when_both_facts_agree() {
        // The rule the kernel applies (kernel/events/core.c: the tracepoint/kprobe
        // case requires CAP_SYS_ADMIN while perf_event_paranoid > 1), measured on
        // Debian 13 / 6.12.107+deb13: paranoid=3 with CAP_BPF+CAP_PERFMON+
        // CAP_SYS_PTRACE+CAP_KILL → EACCES on the first attach; add CAP_SYS_ADMIN
        // → all 14 sensors and the 6 enforcing programs attach.
        for p in [2, 3, 4] {
            assert!(
                PerfGate::from_parts(Some(p), Some(false)).refuses_tracepoints(),
                "paranoid={p} without CAP_SYS_ADMIN is the refusal this preflight exists to name"
            );
        }
        assert!(
            PerfGate::from_parts(Some(4), Some(false)).refuses_tracepoints(),
            "the gate is `> 1`, not `== 3`: Ubuntu ships a patched 4 and it refuses too"
        );

        // Each way the answer can legitimately change…
        assert!(!PerfGate::from_parts(Some(1), Some(false)).refuses_tracepoints());
        assert!(!PerfGate::from_parts(Some(-1), Some(false)).refuses_tracepoints());
        assert!(!PerfGate::from_parts(Some(3), Some(true)).refuses_tracepoints());

        // …and each way it cannot be known. A preflight that guessed here would
        // refuse a start that was going to work, which is the false-negative class
        // doctor.rs's `State::Unreadable` exists to prevent.
        assert!(
            !PerfGate::from_parts(None, Some(false)).refuses_tracepoints(),
            "an unreadable knob is not a refusal"
        );
        assert!(
            !PerfGate::from_parts(Some(3), None).refuses_tracepoints(),
            "unreadable capabilities are not a refusal"
        );
    }

    #[test]
    fn the_gate_reads_this_host_and_refuses_exactly_when_the_kernel_would() {
        let g = PerfGate::read();
        // Both files are world-readable, so a None here is the parser's fault, not
        // the host's — which is the one way this test can be a real assertion.
        let paranoid = g
            .paranoid()
            .expect("kernel.perf_event_paranoid is readable and parses as an integer");
        assert!(
            (-1..=5).contains(&paranoid),
            "paranoid={paranoid} is not a value any kernel documents — the wrong file was read"
        );
        let admin = g
            .holds_sys_admin()
            .expect("/proc/self/status carries CapEff");
        assert_eq!(
            g.refuses_tracepoints(),
            paranoid > 1 && !admin,
            "the preflight and the kernel's rule must not be two different answers"
        );
    }

    #[test]
    fn the_refusal_sentence_names_the_knob_the_capability_and_both_remedies() {
        // An operator reads this once, in a journal line, while the host is
        // unprotected. It has to carry the whole answer.
        let s = PerfGate::from_parts(Some(3), Some(false)).explain();
        for needle in [
            "kernel.perf_event_paranoid is 3",
            "CAP_SYS_ADMIN",
            "CAP_PERFMON",
            "AmbientCapabilities",
            "kernel.perf_event_paranoid = 1",
        ] {
            assert!(s.contains(needle), "the sentence omits {needle}: {s}");
        }
    }

    #[test]
    fn the_worst_dropping_sensor_is_named() {
        // W2K-14 exists so the flood warning can answer "which sensor?" — the
        // largest per-kind loss is what the journal line prints.
        let mut c = SensorCounters::default();
        assert_eq!(c.worst_drop(), None, "nothing lost is not attributable");
        c.drops[Kind::Connect as usize] = 3;
        c.drops[Kind::File as usize] = 11;
        let (kind, n) = c.worst_drop().expect("a non-zero loss is attributable");
        assert_eq!(kind, Kind::File);
        assert_eq!(n, 11);
    }

    #[test]
    fn the_unused_slot_is_never_reported_as_a_sensor() {
        // Slot 0 is not an event kind. If it were ever mistaken for one, a kernel
        // that lost nothing would appear to have lost events on a sensor that does
        // not exist.
        let mut c = SensorCounters::default();
        c.drops[0] = 5;
        assert_eq!(c.worst_drop(), None);
    }

    #[test]
    fn every_decodable_kind_has_a_counter_slot() {
        // The kernel indexes both maps by `Kind as u32` and refuses to bump a slot
        // outside the bound, so a kind that outran KIND_SLOTS would stop being
        // counted while still being decoded normally in userspace — invisible loss
        // of the exact kind W-02 was added to make visible.
        for kind in Kind::ALL {
            let slot = kind as usize;
            assert!(
                slot > 0 && slot < KIND_SLOTS,
                "kind {kind:?} ({slot}) has no counter slot (KIND_SLOTS = {KIND_SLOTS})"
            );
            assert_eq!(
                Kind::from_u32(slot as u32),
                Some(kind),
                "the wire number for {kind:?} drifted from its discriminant"
            );
        }
    }
}
