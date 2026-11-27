//! net_vol.rs — the per-cgroup network volume totals (N-05, roadmap stages 16b and 16f).
//!
//! The kernel half is six `fexit` programs that add two numbers to a bounded
//! hash map (`net_volume` in `bpf/warden.bpf.c`) and never touch the ring. This
//! module is everything else: the Rust mirror of the record the kernel writes,
//! the translation of a cgroup id into a path an operator can read, the
//! between-ticks delta the journal prints, and the coverage sentence that says
//! what the totals cannot see.
//!
//! WHY THIS EXISTS AT ALL. docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md §۳۹ measured the problem: the
//! events ring is lossy and defaults to 256 KiB — about 760 records in flight at
//! 344 bytes each — while a record about a connection carries roughly twelve
//! bytes of network fact. An operator asking "how much did this container move"
//! cannot be answered from a ring that drops under load, because the records that
//! would have summed to the answer are precisely the ones lost first. A counter
//! map is the opposite shape: cost lands on the kernel side as a handful of
//! atomic adds, and userspace reads one total per interval.
//!
//! WHY CGROUPS AND NOT FLOWS OR PIDS. Nothing in this hook set sees a connection
//! close, so a flow-keyed or pid-keyed counter would keep the dead tenant's total
//! and hand it to whoever inherited the reused identity. `bpf_get_current_cgroup_id()`
//! returns a kernfs node id, allocated from a monotone 64-bit generator and never
//! reused, so the failure mode is a stale total that says so (`last_ns`) rather
//! than a total attributed to the wrong workload. The full argument, including
//! what an event-time identity would take, is on `struct warden_net_volume` in
//! `bpf/warden.h`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::NetVolume;

/// The value the kernel adds to per cgroup. `#[repr(C)]` + `aya::Pod` make it a
/// valid map value; the field order and the 40-byte size are ABI, mirrored in
/// `bpf/warden.h`, and asserted against the shipped object by
/// `tests/net_volume_abi.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct VolumeRecord {
    /// Bytes the kernel accepted into a send queue.
    pub bytes_out: u64,
    /// Send-side calls that returned, whether or not they moved bytes.
    pub ops_out: u64,
    /// Bytes copied to a reader's userspace.
    pub bytes_in: u64,
    /// Receive-side completions, counted either way.
    pub ops_in: u64,
    /// `bpf_ktime_get_ns()` at the most recent bump.
    pub last_ns: u64,
}

// SAFETY: repr(C), five u64 fields and no padding (40 bytes, 8-byte aligned),
// and every bit pattern is a legal value — the aya::Pod contract, same as
// `guard::InodeKey`. A struct with padding would be undefined here because the
// kernel's bytes would not be the bytes Rust reads.
unsafe impl aya::Pod for VolumeRecord {}

/// One fexit program of the volume sensor, named by what it hooks and by what it
/// can therefore say. The distinction matters to the reader: six programs share
/// one map, so a host where one of them failed to attach has totals that are
/// silently one-sided, and "silently" is exactly what this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VolumeHook {
    /// `fexit/tcp_sendmsg` — stream egress.
    TcpSendMsg,
    /// `fexit/tcp_cleanup_rbuf` — stream ingress.
    TcpCleanupRbuf,
    /// `fexit/udp_sendmsg` — IPv4 datagram egress.
    UdpSendMsg,
    /// `fexit/udp_recvmsg` — IPv4 datagram ingress. §23 measured both halves.
    UdpRecvMsg,
    /// `fexit/udpv6_sendmsg` — IPv6 datagram egress. Implemented in this build;
    /// attachment and a landed bump are NOT established without a privileged run.
    Udp6SendMsg,
    /// `fexit/udpv6_recvmsg` — IPv6 datagram ingress, same caveat as its egress
    /// twin.
    Udp6RecvMsg,
}

impl VolumeHook {
    /// Every hook the sensor is built with, in attach order.
    pub const ALL: [VolumeHook; 6] = [
        VolumeHook::TcpSendMsg,
        VolumeHook::TcpCleanupRbuf,
        VolumeHook::UdpSendMsg,
        VolumeHook::UdpRecvMsg,
        VolumeHook::Udp6SendMsg,
        VolumeHook::Udp6RecvMsg,
    ];

    /// The program name inside the object.
    pub fn prog_name(self) -> &'static str {
        match self {
            VolumeHook::TcpSendMsg => "warden_vol_tcp_out",
            VolumeHook::TcpCleanupRbuf => "warden_vol_tcp_in",
            VolumeHook::UdpSendMsg => "warden_vol_udp_out",
            VolumeHook::UdpRecvMsg => "warden_vol_udp_in",
            VolumeHook::Udp6SendMsg => "warden_vol_udp6_out",
            VolumeHook::Udp6RecvMsg => "warden_vol_udp6_in",
        }
    }

    /// The kernel function it is attached to — the name an operator checks
    /// against `/sys/kernel/tracing/available_filter_functions`.
    pub fn func(self) -> &'static str {
        match self {
            VolumeHook::TcpSendMsg => "tcp_sendmsg",
            VolumeHook::TcpCleanupRbuf => "tcp_cleanup_rbuf",
            VolumeHook::UdpSendMsg => "udp_sendmsg",
            VolumeHook::UdpRecvMsg => "udp_recvmsg",
            VolumeHook::Udp6SendMsg => "udpv6_sendmsg",
            VolumeHook::Udp6RecvMsg => "udpv6_recvmsg",
        }
    }

    /// Which half of the totals this program feeds.
    pub fn measures(self) -> &'static str {
        match self {
            VolumeHook::TcpSendMsg => "stream egress bytes/ops",
            VolumeHook::TcpCleanupRbuf => "stream ingress bytes/ops",
            VolumeHook::UdpSendMsg => "IPv4 datagram egress bytes/ops",
            VolumeHook::UdpRecvMsg => "IPv4 datagram ingress bytes/ops",
            VolumeHook::Udp6SendMsg => "IPv6 datagram egress bytes/ops",
            VolumeHook::Udp6RecvMsg => "IPv6 datagram ingress bytes/ops",
        }
    }
}

/// The two IPv6 datagram functions this build now attaches.
///
/// §23 of `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` measured that an IPv6 datagram is sent and
/// read through these, not through `udp_sendmsg`/`udp_recvmsg`, and §24 confirmed
/// they are in the kernel's ftrace attach list. They stay as a named constant so
/// the doctor, the coverage line and the tests can be checked against the same
/// two names. Presence in the kernel is still not proof of a landed bump: only a
/// privileged run that sees an `[::1]` datagram in `net_volume` can say that.
pub const V6_DATAGRAM_FUNCS: [&str; 2] = ["udpv6_sendmsg", "udpv6_recvmsg"];

/// Which of the six programs actually attached, and which were rejected by the
/// BTF ABI preflight before an attach was even attempted. A set rather than a
/// bool: `fexit/tcp_sendmsg` can attach where `fexit/tcp_cleanup_rbuf` cannot,
/// and totals with one direction missing must be reported as one-direction
/// rather than as a measurement. The reasons map exists because "absent" and
/// "incompatible with this kernel's prototype" are different states: the first
/// is an attach result, the second is a decision the loader made deliberately.
#[derive(Debug, Clone, Default)]
pub struct VolumeHooks {
    attached: BTreeSet<VolumeHook>,
    abi_rejected: BTreeMap<VolumeHook, String>,
}

impl VolumeHooks {
    pub fn attach(&mut self, hook: VolumeHook) {
        self.attached.insert(hook);
        self.abi_rejected.remove(&hook);
    }

    /// Record a preflight rejection. The hook is deliberately NOT inserted into
    /// `attached`: an ABI mismatch is a skipped attach, not an attached probe
    /// whose totals will arrive later.
    pub fn reject_abi(&mut self, hook: VolumeHook, reason: impl Into<String>) {
        self.attached.remove(&hook);
        self.abi_rejected.insert(hook, reason.into());
    }

    pub fn abi_reason(&self, hook: VolumeHook) -> Option<&str> {
        self.abi_rejected.get(&hook).map(String::as_str)
    }

    pub fn is_live(&self, hook: VolumeHook) -> bool {
        self.attached.contains(&hook)
    }

    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    pub fn all_attached(&self) -> bool {
        self.attached.len() == VolumeHook::ALL.len()
    }

    /// The hooks that did not attach, in declaration order. Empty is the good
    /// case; non-empty is the coverage gap the reader must name.
    pub fn missing(&self) -> Vec<VolumeHook> {
        VolumeHook::ALL
            .iter()
            .copied()
            .filter(|h| !self.attached.contains(h))
            .collect()
    }

    /// What the missing hooks would have contributed, as one phrase for a log
    /// line. `None` when nothing is missing. An ABI rejection names its reason
    /// so an operator can tell a kernel-prototype change from an attach failure.
    pub fn missing_claim(&self) -> Option<String> {
        let missing = self.missing();
        if missing.is_empty() {
            return None;
        }
        Some(
            missing
                .iter()
                .map(|h| match self.abi_reason(*h) {
                    Some(reason) => format!(
                        "{} ({}) — BTF ABI preflight rejected the attach: {reason}",
                        h.func(),
                        h.measures()
                    ),
                    None => format!("{} ({})", h.func(), h.measures()),
                })
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

/// Lifetime fexit invocations, one per program, read from `net_volume_stats`
/// slots 2..8. These are incremented before the emit gate and map-full check,
/// so a disabled sensor still reports that its probes ran.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VolumeInvocations {
    pub tcp_sendmsg: u64,
    pub tcp_cleanup_rbuf: u64,
    pub udp_sendmsg: u64,
    pub udp_recvmsg: u64,
    pub udpv6_sendmsg: u64,
    pub udpv6_recvmsg: u64,
}

impl VolumeInvocations {
    pub fn for_hook(&self, hook: VolumeHook) -> u64 {
        match hook {
            VolumeHook::TcpSendMsg => self.tcp_sendmsg,
            VolumeHook::TcpCleanupRbuf => self.tcp_cleanup_rbuf,
            VolumeHook::UdpSendMsg => self.udp_sendmsg,
            VolumeHook::UdpRecvMsg => self.udp_recvmsg,
            VolumeHook::Udp6SendMsg => self.udpv6_sendmsg,
            VolumeHook::Udp6RecvMsg => self.udpv6_recvmsg,
        }
    }

    pub fn total(&self) -> u64 {
        VolumeHook::ALL.iter().map(|h| self.for_hook(*h)).sum()
    }
}

/// One cgroup's totals, with the path resolved as far as the host allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupVolume {
    pub cgroup_id: u64,
    /// The cgroup path under the resolved root, or `None` when the cgroup is
    /// gone (its directory is unlinked the moment it is removed) or when the
    /// walk hit its entry bound before reaching it.
    pub cgroup: Option<String>,
    pub totals: VolumeRecord,
}

/// Everything one read of the volume maps yields.
#[derive(Debug, Clone)]
pub struct VolumeTotals {
    pub rows: Vec<CgroupVolume>,
    /// Bumps refused because the map held no slot for a new cgroup, summed over
    /// CPUs. Non-zero means `rows` is a partial view, not a smaller truth.
    pub refused: u64,
    /// Bumps that landed, summed over CPUs. Zero alongside zero rows means the
    /// hooks never fired; it does not mean the host was quiet.
    pub bumps: u64,
    /// Lifetime fexit invocations by program. Non-zero with zero bumps proves
    /// the probes ran while the emit gate was off or the map was full; zero
    /// with no attached hooks is the dead-sensor shape.
    pub invocations: VolumeInvocations,
    pub hooks: VolumeHooks,
}

/// The change between two reads of the same cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeDelta {
    pub bytes_out: u64,
    pub ops_out: u64,
    pub bytes_in: u64,
    pub ops_in: u64,
}

impl VolumeDelta {
    pub fn bytes_total(&self) -> u64 {
        self.bytes_out.saturating_add(self.bytes_in)
    }
}

/// Turn two `VolumeRecord`s into a per-interval delta.
///
/// Saturating, never wrapping. The kernel's totals are monotone for one boot of
/// one agent, but a reader cannot assume it is comparing against the same agent:
/// after a restart the map is brand new and every "previous" value belongs to a
/// process that is gone. A subtraction that wrapped would report an enormous
/// volume out of nothing, which is the worst possible failure for a counter whose
/// entire purpose is to be the trustworthy half of the network picture. A
/// clamped zero is the honest answer to "I do not know what came before this".
fn delta(prev: &VolumeRecord, now: &VolumeRecord) -> VolumeDelta {
    VolumeDelta {
        bytes_out: now.bytes_out.saturating_sub(prev.bytes_out),
        ops_out: now.ops_out.saturating_sub(prev.ops_out),
        bytes_in: now.bytes_in.saturating_sub(prev.bytes_in),
        ops_in: now.ops_in.saturating_sub(prev.ops_in),
    }
}

/// A running sampler: remembers the last absolute read per cgroup and yields the
/// movement since then.
#[derive(Debug, Default)]
pub struct VolumeSampler {
    prev: HashMap<u64, VolumeRecord>,
    /// Cgroups seen in the previous tick. Reported so an operator can see a
    /// tenant disappear rather than infer it from a line that stopped appearing.
    seen: BTreeSet<u64>,
}

/// One line of a tick report: a cgroup, what it moved since the last tick, and
/// where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeTickRow {
    pub cgroup_id: u64,
    pub cgroup: Option<String>,
    pub delta: VolumeDelta,
    pub totals: VolumeRecord,
}

impl VolumeSampler {
    /// The movement since the previous tick, in descending byte order, with the
    /// `report_min_bytes` floor already applied. Cgroups that went quiet are not
    /// here — they contribute nothing — and that is why `gone` is returned
    /// separately rather than left for the caller to diff.
    pub fn tick(&mut self, totals: &VolumeTotals, floor: u64) -> (Vec<VolumeTickRow>, Vec<u64>) {
        let mut rows: Vec<VolumeTickRow> = Vec::new();
        let mut now: BTreeSet<u64> = BTreeSet::new();

        for row in &totals.rows {
            now.insert(row.cgroup_id);
            let d = match self.prev.get(&row.cgroup_id) {
                // First sighting of this cgroup: the absolute totals cover
                // everything since the map was created, not since the last tick.
                // It is still reported — dropping it would hide an exfiltration
                // that finished inside the very first interval — and `totals`
                // rides along on the row so a reader can tell a lifetime figure
                // from an interval one instead of having to trust the ordering.
                None => VolumeDelta {
                    bytes_out: row.totals.bytes_out,
                    ops_out: row.totals.ops_out,
                    bytes_in: row.totals.bytes_in,
                    ops_in: row.totals.ops_in,
                },
                Some(prev) => delta(prev, &row.totals),
            };
            // The floor is a floor on REPORTING, and zero movement is never
            // worth a row: with `report_min_bytes = 0` an operator asks for
            // everything that moved, not for a line per tracked cgroup per tick.
            if d.bytes_total() > 0 && d.bytes_total() >= floor {
                rows.push(VolumeTickRow {
                    cgroup_id: row.cgroup_id,
                    cgroup: row.cgroup.clone(),
                    delta: d,
                    totals: row.totals,
                });
            }
            self.prev.insert(row.cgroup_id, row.totals);
        }

        let gone: Vec<u64> = self.seen.difference(&now).copied().collect();
        self.seen = now;
        rows.sort_by(|a, b| {
            b.delta
                .bytes_total()
                .cmp(&a.delta.bytes_total())
                .then_with(|| a.cgroup_id.cmp(&b.cgroup_id))
        });
        (rows, gone)
    }
}

/// Resolve cgroup ids to paths by walking the cgroup v2 hierarchy.
///
/// The kernel's id IS the cgroup directory's inode number (`bpf_get_current_cgroup_id()`
/// returns the kernfs node id, and kernfs reports that same value through
/// `getattr`), which is why no parsing of `/proc/<pid>/cgroup` is needed and why
/// a deleted cgroup resolves to `None` instead of to a stale name. Walking the
/// tree is O(cgroups on the host) and is done once per tick, not once per byte.
///
/// `max_entries` bounds the walk so a host with an enormous hierarchy cannot make
/// the sensor's cost depend on how many cgroups somebody left behind: past the
/// bound the walk stops and the unresolved ids simply report as `None`. That is
/// the honest degradation — a name we did not look up is not the same as a
/// counter we did not take.
pub fn cgroup_paths(root: &Path, max_entries: usize) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    let root = canonicalized_root(root);
    walk_cgroup_tree(root.as_path(), "", max_entries, &mut out);
    out
}

/// `realpath` the root if we can. `/sys/fs/cgroup` is a mount point and every
/// cgroup directory under it is reachable by more than one path once bind mounts
/// are involved; the ids, however, are per-inode, so the walk works from
/// whatever single path the operator configured. A root that cannot be resolved
/// is used verbatim — the failure then shows up as an empty map, which the
/// coverage line reports as "no cgroup could be named", rather than as a panic
/// or a wrong path.
fn canonicalized_root(root: &Path) -> PathBuf {
    match root.canonicalize() {
        Ok(p) => p,
        Err(_) => root.to_path_buf(),
    }
}

fn walk_cgroup_tree(dir: &Path, relative: &str, budget: usize, out: &mut BTreeMap<u64, String>) {
    if out.len() >= budget {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    // Sort the names so the map content does not depend on readdir order. Not a
    // correctness requirement — ids are per-directory — but a report that
    // reordered between ticks for no reason reads like a bug.
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let ft = e.file_type().ok()?;
            ft.is_dir()
                .then(|| e.file_name().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();

    for name in names {
        if out.len() >= budget {
            return;
        }
        let path = dir.join(&name);
        let rel = if relative.is_empty() {
            format!("/{name}")
        } else {
            format!("{relative}/{name}")
        };
        if let Ok(meta) = path.metadata() {
            let id = meta.st_ino();
            // A cgroup directory's st_ino IS the id the kernel stamped. Recorded
            // before descending so a parent whose children filled the budget
            // still resolves.
            out.insert(id, rel.clone());
        }
        walk_cgroup_tree(&path, &rel, budget, out);
    }
}

/// The cadence the agent can actually deliver for a requested interval: the volume
/// tick rides the protect refresh loop, so the request is rounded up to that loop's
/// period. `5 → 10`, `10 → 10`, `25 → 30`.
///
/// This exists because of a live measurement, not a reading of the code: with
/// `interval_secs = 5` the deployment host produced ticks at 18:12:11.678,
/// 18:12:21.695, 18:12:31.728 — 10.0 s apart. A report line that printed the
/// requested number would have been describing a cadence the agent cannot run.
pub fn effective_interval_secs(requested: u64) -> u64 {
    let period = crate::config::NET_VOLUME_TICK_GRANULARITY_SECS.max(1);
    requested.max(1).next_multiple_of(period)
}

/// The phrase used in both coverage lines. Naming the requested value alongside
/// the delivered one is deliberate: an operator who wrote `interval_secs = 5` and
/// is told only "every 10s" reasonably suspects the config was ignored.
fn cadence_phrase(requested: u64) -> String {
    let effective = effective_interval_secs(requested);
    if effective == requested {
        format!("{effective}s")
    } else {
        let period = crate::config::NET_VOLUME_TICK_GRANULARITY_SECS;
        format!(
            "{effective}s (interval_secs = {requested} is finer than the agent's {period}s \
             refresh loop, which is what it delivers)"
        )
    }
}

/// The sentence that says what these totals are and what they cannot see. Same
/// contract as `net_snap::coverage_line`: printed at startup, on every reload
/// that changes the policy, and by `--check`, so an operator never has to read
/// the source to learn whether the number they are looking at is a full view.
pub fn coverage_line(policy: &NetVolume, hooks: Option<&VolumeHooks>) -> String {
    if !policy.enabled {
        return format!(
            "warden: network volume (N-05): OFF — no byte or operation totals are kept, so \
             how much any cgroup moved is unanswerable while this is off; the events ring is \
             the only network evidence and it is lossy (set [net_volume].enabled = true; it \
             then samples every {} and reports the {} cgroup(s) per tick that move at least \
             {} bytes)",
            cadence_phrase(policy.interval_secs),
            policy.max_rows_per_tick,
            policy.report_min_bytes
        );
    }
    match hooks {
        None => "warden: network volume (N-05): ON by policy, but the kernel object is not loaded \
                 in this path — the hooks and their totals are unknown here; nothing is being \
                 counted until the agent runs"
            .to_string(),
        Some(hooks) => {
            let mut line = format!(
                "warden: network volume (N-05): ON, {} hook(s) attached ({}), totals kept per \
                 cgroup and reported every {} with a {}-byte floor. These are not wire bytes and \
                 not packets: they are the bytes userspace handed to the kernel at the send/recv \
                 call, capped for UDP receives at the caller's buffer length so MSG_TRUNC cannot \
                 charge the original datagram size; kernel IP/TCP headers and retransmitted \
                 segments are OUTSIDE them while a userspace TLS library's own record framing is \
                 INSIDE them. A receive that only PEEKs counts, because the copy into userspace \
                 really happened. Sockets addressed with AF_INET6 are sent and read through `{}` \
                 and `{}`, which this build now attaches, so that socket path is targeted in both \
                 directions; an IPv4-mapped datagram on such a socket is still IPv6-socket-path \
                 accounting, not an IPv6-wire claim, and a hook named above is only an attachment \
                 claim, not proof that a bump landed. Loopback is included, and the \
                 map holds at most {} cgroups before new ones are refused and counted as refused",
                hooks.attached_count(),
                VolumeHook::ALL
                    .iter()
                    .filter(|h| hooks.is_live(**h))
                    .map(|h| h.func())
                    .collect::<Vec<_>>()
                    .join("+"),
                cadence_phrase(policy.interval_secs),
                policy.report_min_bytes,
                V6_DATAGRAM_FUNCS[0],
                V6_DATAGRAM_FUNCS[1],
                crate::loader::NET_VOLUME_MAX,
            );
            if let Some(missing) = hooks.missing_claim() {
                line.push_str(&format!(
                    ". COVERAGE GAP: {missing} did NOT attach, so the totals are one-sided and \
                     must not be read as a volume"
                ));
            }
            line
        }
    }
}

/// Compact per-hook invocation denominator for a tick line. Kept separate from
/// `bumps` because the two answer different questions: a hook can run on every
/// datagram while the emit gate is off, and a bump can only land when it is on.
fn invocation_phrase(totals: &VolumeTotals) -> String {
    format!(
        "total={}: {}",
        totals.invocations.total(),
        VolumeHook::ALL
            .iter()
            .map(|h| format!("{}={}", h.func(), totals.invocations.for_hook(*h)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// One tick's journal line. Deliberately one line per report rather than one per
/// cgroup: the tick is a status heartbeat, and a report that emits a paragraph
/// every interval is the thing `respond.log_throttle` was built to avoid.
///
/// `rows` is what the caller chose to NAME; `moved_total` is how many actually
/// moved. The two are separate arguments because the caller truncates by policy
/// (`max_rows_per_tick`) and a line that counted only the rows it printed would
/// report "2 cgroup(s) moved" on a tick where 40 did. Naming the bound and the
/// overflow is what keeps a bounded report from reading as a complete one.
pub fn tick_line(
    rows: &[VolumeTickRow],
    moved_total: usize,
    totals: &VolumeTotals,
    gone: &[u64],
) -> String {
    let went_away = if gone.is_empty() {
        String::new()
    } else {
        format!("; {} cgroup(s) stopped being tracked", gone.len())
    };
    if rows.is_empty() {
        // The quiet case still quotes `bumps`: "0 bytes since the last tick"
        // means something different when the hooks have never bumped a counter
        // at all, and the difference between those two sentences is the
        // difference between an idle host and a dead sensor.
        return format!(
            "net_volume: quiet tick — {} cgroup(s) tracked, 0 bytes moved since the last tick; \
             {} lifetime bump(s), {} refused for want of a map slot; hook invocation(s) {}{went_away}",
            totals.rows.len(),
            totals.bumps,
            totals.refused,
            invocation_phrase(totals)
        );
    }
    let named = rows.len();
    let listed: Vec<String> = rows
        .iter()
        .map(|r| {
            let who = r
                .cgroup
                .as_deref()
                .unwrap_or("<cgroup gone or beyond the walk bound>");
            format!(
                "{} out {}B/{} ops, in {}B/{} ops",
                who, r.delta.bytes_out, r.delta.ops_out, r.delta.bytes_in, r.delta.ops_in
            )
        })
        .collect();
    let bound_note = if moved_total > named {
        format!(", {named} of {moved_total} named")
    } else {
        String::new()
    };
    format!(
        "net_volume: {moved_total} cgroup(s) moved since the last tick: {} ({named} cgroup(s) \
         listed, {} tracked in total, {} lifetime bump(s), {} refused for want of a map \
         slot; hook invocation(s) {}){bound_note}{went_away}",
        listed.join("; "),
        totals.rows.len(),
        totals.bumps,
        totals.refused,
        invocation_phrase(totals)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(bytes_out: u64, ops_out: u64, bytes_in: u64, ops_in: u64) -> VolumeRecord {
        VolumeRecord {
            bytes_out,
            ops_out,
            bytes_in,
            ops_in,
            last_ns: 1,
        }
    }

    /// The fields of `NetVolume` themselves, not nested under a `[net_volume]`
    /// table header: `NetVolume` IS that table's contents, so a header here would
    /// deserialize as an unknown key and leave every field at its default — which
    /// is `enabled = false`, and would silently route these tests down the OFF
    /// branch no matter what the test asked for.
    fn policy(text: &str) -> NetVolume {
        toml::from_str(&format!("enabled = true\n{text}\n")).unwrap()
    }

    #[test]
    fn the_kernel_record_mirror_is_exactly_forty_bytes() {
        // The map value and the Rust struct must agree byte for byte, and the C
        // side says 40. A field added without the assert being updated is a map
        // read that silently misparses every row.
        assert_eq!(std::mem::size_of::<VolumeRecord>(), 40);
        assert_eq!(std::mem::align_of::<VolumeRecord>(), 8);
    }

    #[test]
    fn every_hook_names_a_distinct_program_and_function() {
        let names: Vec<&str> = VolumeHook::ALL.iter().map(|h| h.prog_name()).collect();
        let funcs: Vec<&str> = VolumeHook::ALL.iter().map(|h| h.func()).collect();
        assert_eq!(names.len(), 6, "six programs is the shipped contract");
        assert_eq!(funcs.len(), 6);
        for f in V6_DATAGRAM_FUNCS {
            assert!(
                funcs.contains(&f),
                "the named v6 datagram functions must be the attached ones: {funcs:?}"
            );
        }
        assert!(names.iter().all(|n| n.starts_with("warden_vol_")));
        // Two hooks sharing a program name would attach the same fexit twice and
        // double-count one direction while leaving another at zero.
        assert_eq!(
            names.iter().collect::<BTreeSet<_>>().len(),
            names.len(),
            "program names must be unique: {names:?}"
        );
        assert_eq!(
            funcs.iter().collect::<BTreeSet<_>>().len(),
            funcs.len(),
            "hooked functions must be unique: {funcs:?}"
        );
        // Both families have both directions; a missing attach must name the
        // exact family and direction that is unmeasured.
        for family in ["IPv4", "IPv6"] {
            for direction in ["egress", "ingress"] {
                assert_eq!(
                    VolumeHook::ALL
                        .iter()
                        .filter(|h| h.measures().starts_with(family)
                            && h.measures().ends_with(&format!("{direction} bytes/ops")))
                        .count(),
                    1,
                    "exactly one {family} {direction} hook"
                );
            }
        }
    }

    #[test]
    fn a_partial_attach_is_reported_as_the_exact_directions_that_are_missing() {
        let mut hooks = VolumeHooks::default();
        hooks.attach(VolumeHook::TcpSendMsg);
        hooks.attach(VolumeHook::UdpSendMsg);
        hooks.attach(VolumeHook::UdpRecvMsg);
        assert!(!hooks.all_attached());
        assert_eq!(hooks.attached_count(), 3);
        assert_eq!(
            hooks.missing(),
            vec![
                VolumeHook::TcpCleanupRbuf,
                VolumeHook::Udp6SendMsg,
                VolumeHook::Udp6RecvMsg
            ]
        );
        let claim = hooks.missing_claim().unwrap();
        for (func, description) in [
            ("tcp_cleanup_rbuf", "stream ingress"),
            ("udpv6_sendmsg", "IPv6 datagram egress"),
            ("udpv6_recvmsg", "IPv6 datagram ingress"),
        ] {
            assert!(
                claim.contains(func) && claim.contains(description),
                "{claim}"
            );
        }

        let mut full = VolumeHooks::default();
        for h in VolumeHook::ALL {
            full.attach(h);
        }
        assert!(full.all_attached());
        assert!(
            full.missing_claim().is_none(),
            "a complete set says nothing"
        );
    }

    #[test]
    fn the_datagram_ingress_hooks_are_named_when_absent() {
        // Stage ۱۶f exists because this hook's absence used to be a permanent
        // sentence in the coverage line rather than a gap the line could name. A
        // host where it fails to attach must be told which direction is missing.
        assert!(VolumeHook::ALL.contains(&VolumeHook::UdpRecvMsg));
        assert_eq!(VolumeHook::UdpRecvMsg.func(), "udp_recvmsg");
        assert_eq!(VolumeHook::UdpRecvMsg.prog_name(), "warden_vol_udp_in");

        assert!(VolumeHook::ALL.contains(&VolumeHook::Udp6RecvMsg));
        assert_eq!(VolumeHook::Udp6RecvMsg.func(), "udpv6_recvmsg");
        assert_eq!(VolumeHook::Udp6RecvMsg.prog_name(), "warden_vol_udp6_in");

        let mut hooks = VolumeHooks::default();
        for h in VolumeHook::ALL {
            if h != VolumeHook::UdpRecvMsg && h != VolumeHook::Udp6RecvMsg {
                hooks.attach(h);
            }
        }
        let claim = hooks.missing_claim().unwrap();
        assert!(
            claim.contains("udp_recvmsg")
                && claim.contains("udpv6_recvmsg")
                && claim.contains("datagram ingress"),
            "{claim}"
        );
        let line = coverage_line(&policy(""), Some(&hooks));
        assert!(line.contains("COVERAGE GAP"), "{line}");
        assert!(line.contains("udp_recvmsg"), "{line}");
        assert!(line.contains("udpv6_recvmsg"), "{line}");
    }

    #[test]
    fn a_delta_never_wraps_when_the_kernel_counter_goes_backwards() {
        // After an agent restart the map is new and `prev` belongs to a process
        // that no longer exists. The answer is zero, not 18 exabytes.
        let d = delta(&rec(1000, 10, 1000, 10), &rec(10, 1, 0, 0));
        assert_eq!(
            d,
            VolumeDelta {
                bytes_out: 0,
                ops_out: 0,
                bytes_in: 0,
                ops_in: 0
            }
        );
    }

    #[test]
    fn a_delta_reports_only_the_movement_and_counts_ops_independently() {
        let d = delta(&rec(1000, 10, 500, 4), &rec(1500, 13, 500, 4));
        assert_eq!(d.bytes_out, 500);
        assert_eq!(d.ops_out, 3);
        assert_eq!(d.bytes_in, 0, "nothing arrived on ingress");
        assert_eq!(d.ops_in, 0);
        assert_eq!(d.bytes_total(), 500);
    }

    #[test]
    fn the_first_sighting_of_a_cgroup_is_not_silently_relabelled_as_a_tick() {
        // The sampler has no previous value, so what it reports is the whole
        // lifetime total. It must still be reported — dropping it would hide an
        // exfiltration that finished inside the very first interval — and the
        // totals field is what lets the caller tell the two apart.
        let mut s = VolumeSampler::default();
        let totals = VolumeTotals {
            rows: vec![CgroupVolume {
                cgroup_id: 77,
                cgroup: Some("/svc/app.service".into()),
                totals: rec(9_000, 40, 1_000, 9),
            }],
            refused: 0,
            bumps: 49,
            invocations: VolumeInvocations::default(),
            hooks: VolumeHooks::default(),
        };
        let (rows, gone) = s.tick(&totals, 0);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].delta.bytes_out, 9_000);
        assert_eq!(rows[0].totals.bytes_out, 9_000, "lifetime total is kept");
        assert!(gone.is_empty());

        // Second tick, nothing moved: the floor and the zero check both apply.
        let (rows, _) = s.tick(&totals, 0);
        assert!(rows.is_empty(), "a quiet cgroup reports nothing");
    }

    #[test]
    fn the_floor_drops_small_movement_and_keeps_the_largest_first() {
        let mut s = VolumeSampler::default();
        let mk = |id: u64, out: u64| CgroupVolume {
            cgroup_id: id,
            cgroup: Some(format!("/c{id}")),
            totals: rec(out, 1, 0, 0),
        };
        let totals = VolumeTotals {
            rows: vec![mk(1, 10), mk(2, 5_000), mk(3, 900)],
            refused: 0,
            bumps: 3,
            invocations: VolumeInvocations::default(),
            hooks: VolumeHooks::default(),
        };
        let (rows, _) = s.tick(&totals, 1_000);
        assert_eq!(
            rows.iter().map(|r| r.cgroup_id).collect::<Vec<_>>(),
            vec![2],
            "only the cgroup over the floor is reported, and descending order holds"
        );
    }

    #[test]
    fn a_cgroup_that_disappears_is_named_as_gone_instead_of_vanishing_from_the_report() {
        let mut s = VolumeSampler::default();
        let totals = VolumeTotals {
            rows: vec![CgroupVolume {
                cgroup_id: 5,
                cgroup: None,
                totals: rec(1, 1, 1, 1),
            }],
            refused: 0,
            bumps: 2,
            invocations: VolumeInvocations::default(),
            hooks: VolumeHooks::default(),
        };
        s.tick(&totals, 0);
        let gone = s.tick(
            &VolumeTotals {
                rows: vec![],
                refused: 0,
                bumps: 2,
                invocations: VolumeInvocations::default(),
                hooks: VolumeHooks::default(),
            },
            0,
        );
        assert_eq!(gone.1, vec![5], "the id that stopped being reported");
    }

    #[test]
    fn the_tick_sorts_on_both_directions_together_not_on_egress_alone() {
        let row = |id: u64, out: u64, inflow: u64| CgroupVolume {
            cgroup_id: id,
            cgroup: None,
            totals: rec(out, 1, inflow, 1),
        };
        let totals = VolumeTotals {
            rows: vec![row(1, 100, 100), row(2, 0, 500), row(3, 1_000, 0)],
            refused: 0,
            bumps: 6,
            invocations: VolumeInvocations::default(),
            hooks: VolumeHooks::default(),
        };
        let mut s = VolumeSampler::default();
        let (rows, _) = s.tick(&totals, 0);
        assert_eq!(
            rows.iter().map(|r| r.cgroup_id).collect::<Vec<_>>(),
            vec![3, 2, 1],
            "egress alone would put the 100+100 cgroup second, and a flood aimed inward must \
             not lose to one aimed outward"
        );
    }

    #[test]
    fn an_off_policy_says_the_totals_are_unanswerable_and_names_the_knob() {
        let mut p = policy("");
        p.enabled = false;
        let line = coverage_line(&p, None);
        for needle in [
            "network volume (N-05): OFF",
            "unanswerable",
            "[net_volume].enabled = true",
        ] {
            assert!(line.contains(needle), "missing {needle:?} in {line}");
        }
    }

    #[test]
    fn an_on_policy_with_all_hooks_states_the_three_limits_that_change_a_number() {
        let hooks = VolumeHooks::default();
        let mut full = VolumeHooks::default();
        for h in VolumeHook::ALL {
            full.attach(h);
        }
        let p = policy("interval_secs = 30\nreport_min_bytes = 2048\n");
        let line = coverage_line(&p, Some(&full));
        for needle in [
            "tcp_sendmsg+tcp_cleanup_rbuf+udp_sendmsg+udp_recvmsg+udpv6_sendmsg+udpv6_recvmsg",
            "every 30s",
            "2048-byte floor",
            "not wire bytes",
            "6 hook(s) attached",
            "PEEKs counts",
            "that socket path is targeted in both directions",
            "IPv6-socket-path accounting",
            "udpv6_sendmsg",
            "Loopback is included",
        ] {
            assert!(line.contains(needle), "missing {needle:?} in {line}");
        }
        assert!(
            !line.contains("COVERAGE GAP"),
            "a complete attach must not claim a gap: {line}"
        );
        assert!(
            coverage_line(&p, Some(&hooks)).contains("COVERAGE GAP"),
            "zero hooks attached is the largest gap there is"
        );
        assert!(
            coverage_line(&p, None).contains("kernel object is not loaded"),
            "--check must not imply the hooks are live"
        );
    }

    #[test]
    fn a_request_finer_than_the_refresh_loop_is_reported_as_the_cadence_it_gets() {
        // Live measurement, not a reading of the loop: interval_secs = 5 produced
        // ticks 10.0 s apart on the deployment host. The report must state what the
        // agent delivers, and a config file is allowed to ask for less than that.
        assert_eq!(effective_interval_secs(5), 10);
        assert_eq!(effective_interval_secs(1), 10);
        assert_eq!(effective_interval_secs(10), 10);
        assert_eq!(effective_interval_secs(11), 20);
        assert_eq!(effective_interval_secs(25), 30);
        assert_eq!(effective_interval_secs(30), 30);
        assert_eq!(effective_interval_secs(60), 60);

        let fine = cadence_phrase(5);
        assert!(fine.starts_with("10s ("), "{fine}");
        assert!(fine.contains("interval_secs = 5"), "{fine}");
        assert!(fine.contains("10s refresh loop"), "{fine}");
        assert_eq!(cadence_phrase(30), "30s");
    }

    #[test]
    fn both_coverage_lines_print_the_delivered_cadence_not_the_requested_one() {
        let full = {
            let mut h = VolumeHooks::default();
            for hook in VolumeHook::ALL {
                h.attach(hook);
            }
            h
        };
        let p = policy("interval_secs = 5\n");
        let on = coverage_line(&p, Some(&full));
        assert!(on.contains("every 10s (interval_secs = 5"), "{on}");
        let mut off = p.clone();
        off.enabled = false;
        assert!(
            coverage_line(&off, None).contains("every 10s (interval_secs = 5"),
            "the OFF line promises a cadence too, so it must round the same way"
        );
    }

    #[test]
    fn a_hook_that_failed_to_attach_is_written_into_the_line_by_name() {
        let mut hooks = VolumeHooks::default();
        hooks.attach(VolumeHook::TcpSendMsg);
        hooks.attach(VolumeHook::UdpSendMsg);
        let line = coverage_line(&policy(""), Some(&hooks));
        assert!(line.contains("COVERAGE GAP"), "{line}");
        assert!(line.contains("tcp_cleanup_rbuf"), "{line}");
        assert!(line.contains("udp_recvmsg"), "{line}");
        assert!(line.contains("2 hook(s)"), "{line}");
        assert!(
            line.contains("(tcp_sendmsg+udp_sendmsg)"),
            "the attached list names exactly the two live programs, in declare order: {line}"
        );
    }

    #[test]
    fn a_quiet_tick_line_and_a_moving_tick_line_are_both_one_line() {
        let totals = VolumeTotals {
            rows: vec![CgroupVolume {
                cgroup_id: 9,
                cgroup: Some("/docker/abc".into()),
                totals: rec(0, 0, 0, 0),
            }],
            refused: 0,
            bumps: 12,
            invocations: VolumeInvocations::default(),
            hooks: VolumeHooks::default(),
        };
        let quiet = tick_line(&[], 0, &totals, &[]);
        assert!(quiet.contains("quiet tick"), "{quiet}");
        assert!(!quiet.contains('\n'), "the journal gets one line");

        let row = VolumeTickRow {
            cgroup_id: 9,
            cgroup: Some("/docker/abc".into()),
            delta: VolumeDelta {
                bytes_out: 4_000,
                ops_out: 7,
                bytes_in: 100,
                ops_in: 3,
            },
            totals: rec(4_000, 7, 100, 3),
        };
        let moving = tick_line(std::slice::from_ref(&row), 1, &totals, &[]);
        assert!(moving.contains("/docker/abc"), "{moving}");
        assert!(moving.contains("out 4000B/7 ops"), "{moving}");
        assert!(moving.contains("in 100B/3 ops"), "{moving}");
        assert!(moving.contains("1 cgroup(s) moved"), "{moving}");

        let unnamed = VolumeTickRow {
            cgroup_id: 9,
            cgroup: None,
            delta: row.delta,
            totals: row.totals,
        };
        let l = tick_line(&[unnamed], 1, &totals, &[]);
        assert!(
            l.contains("cgroup gone or beyond the walk bound"),
            "an unresolved id must be printed as unresolved: {l}"
        );
    }

    #[test]
    fn a_truncated_report_says_how_many_moved_rather_than_only_how_many_it_named() {
        // The caller caps the rows it passes by policy. If the line counted those
        // rows, a tick where 40 cgroups moved and 8 were named would report "8
        // cgroup(s) moved" — a bounded report presented as a complete one, which
        // is the exact failure mode every other bound in this module documents.
        let totals = VolumeTotals {
            rows: vec![],
            refused: 0,
            bumps: 40,
            invocations: VolumeInvocations::default(),
            hooks: VolumeHooks::default(),
        };
        let row = VolumeTickRow {
            cgroup_id: 1,
            cgroup: Some("/a".into()),
            delta: VolumeDelta {
                bytes_out: 10,
                ops_out: 1,
                bytes_in: 0,
                ops_in: 0,
            },
            totals: rec(10, 1, 0, 0),
        };
        let line = tick_line(&[row], 40, &totals, &[]);
        assert!(line.contains("40 cgroup(s) moved"), "{line}");
        assert!(line.contains("1 of 40 named"), "{line}");
        assert!(line.contains("1 cgroup(s) listed"), "{line}");
    }

    #[test]
    fn the_walk_resolves_a_cgroup_directory_by_its_inode_and_bounds_itself() {
        let root = std::env::temp_dir().join(format!("warden-netvol-{}", std::process::id()));
        let nested = root.join("system.slice").join("app.service");
        std::fs::create_dir_all(&nested).unwrap();
        let map = cgroup_paths(&root, 64);
        let want = std::fs::metadata(&nested).unwrap().st_ino();
        assert_eq!(
            map.get(&want).map(String::as_str),
            Some("/system.slice/app.service"),
            "the id the kernel stamps is the directory's inode"
        );
        assert!(map.contains_key(
            &std::fs::metadata(root.join("system.slice"))
                .unwrap()
                .st_ino()
        ));

        // The bound is a bound on the walk, not a silent skip of the parents.
        let bounded = cgroup_paths(&root, 1);
        assert_eq!(bounded.len(), 1, "max_entries is respected exactly");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_root_that_does_not_exist_resolves_to_nothing_instead_of_failing() {
        let map = cgroup_paths(Path::new("/nonexistent-warden-cgroup-root"), 64);
        assert!(map.is_empty(), "a missing cgroupfs names no cgroups");
    }
}
