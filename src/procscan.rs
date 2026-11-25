//! procscan.rs — resolve the operator's "protect these" policy into concrete
//! processes by walking /proc. PIDs are ephemeral, so this runs at startup and
//! on a timer; the kernel-side `protected_pids` map is the live source of truth
//! the signal/ptrace probes consult.
//!
//! W-R4: what lands in that set is an *identity*, not a pid number. Each
//! protected pid is recorded together with the start time it had when it was
//! resolved (see [`Protected`]), and the responder's refusal to kill is bound to
//! that pair. Without it, "pid 4711 is protected" stays true after 4711 has been
//! recycled, and protection becomes something an unrelated process inherits.
//!
//! The other half of W-R4 is *how a process gets in here at all*. The legacy
//! selectors are a 15-byte comm an attacker can set with `prctl(PR_SET_NAME)`
//! and a cgroup substring; [`Protect::protects`] adds identity tuples that
//! AND over exe/uid/exact-cgroup, which is what the audit prescribes for
//! anything that decides whether a process may be killed.
//!
//! The third thing this module does is answer "am I the only one?" — see
//! [`peer_instances`] and W2K-43. It is a /proc walk for the same reason the
//! protect policy is one: the question is about live processes, and the answer
//! is an identity rather than a pid.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;

use crate::config::{Protect, ProtectTarget};
use crate::detect::{basename, exe_identity};
use crate::events::{cgroup_of, exe_of, starttime_of};

/// Read /proc/<pid>/comm (the 15-char kernel comm), trimmed.
fn comm_of(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
}

/// Read a process's real uid from /proc/<pid>/status.
///
/// The `Uid:` line is four numbers — real, effective, saved, filesystem. We take
/// the *real* one because that is what Warden already means by "uid" everywhere
/// else: the sensors report `bpf_get_current_uid_gid()` as `ProcessInfo.uid`,
/// and the guarded-file layer documents that it attributes by real uid. A second
/// meaning of the word in the protect policy would be a trap for whoever writes
/// the next rule.
fn uid_of(pid: u32) -> Option<u32> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_uid(&raw)
}

/// The parsing half of [`uid_of`], split out so the line format is testable
/// without depending on what happens to be running on the test host.
fn parse_uid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Every numeric entry in /proc is a live tgid.
fn all_pids() -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for e in entries.flatten() {
            if let Ok(name) = e.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    out.push(pid);
                }
            }
        }
    }
    out
}

/// The identity-relevant facts about one live process.
///
/// Split out from the scanning loop so the matching rules can be tested against
/// constructed identities rather than only against whatever is running here. An
/// `Option` field records that /proc would not tell us — `hidepid=` hides whole
/// entries, and `/proc/<pid>/exe` is unreadable for another user's process
/// without `CAP_SYS_PTRACE`. An unreadable fact cannot satisfy a constraint on
/// it, so a target naming that field simply does not match; see
/// [`Resolution::unmatched_targets`], which is how that stays visible instead of
/// becoming a silent loss of protection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcIdentity {
    pub pid: u32,
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub uid: Option<u32>,
    pub cgroup: Option<String>,
}

impl ProcIdentity {
    /// Read every identity fact for `pid`, each one best-effort.
    pub fn read(pid: u32) -> Self {
        Self {
            pid,
            comm: comm_of(pid),
            exe: exe_of(pid),
            uid: uid_of(pid),
            cgroup: cgroup_of(pid),
        }
    }
}

impl ProtectTarget {
    /// Whether this target describes the process behind `id`.
    ///
    /// Every field the operator named must hold — it is an AND, so naming more
    /// fields can only narrow the match. A target that names nothing returns
    /// false: an empty `[[protect.targets]]` entry must not protect the whole
    /// host, which is the failure mode that would make this feature worse than
    /// the one it replaces.
    pub fn matches(&self, id: &ProcIdentity) -> bool {
        let mut constrained = false;

        if let Some(want) = &self.comm {
            constrained = true;
            if id.comm.as_deref() != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.exe {
            constrained = true;
            if id.exe.as_deref() != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = self.uid {
            constrained = true;
            if id.uid != Some(want) {
                return false;
            }
        }
        if let Some(want) = &self.cgroup {
            constrained = true;
            if id.cgroup.as_deref() != Some(want.as_str()) {
                return false;
            }
        }

        constrained
    }
}

impl Protect {
    /// Whether this policy protects the process behind `id`.
    ///
    /// Legacy selectors and `[[protect.targets]]` are ORed, so adding a target
    /// can never take protection away from a process an existing selector
    /// already covered — the property that makes this change safe to ship to a
    /// deployment whose `warden.toml` nobody is going to re-read.
    pub fn protects(&self, id: &ProcIdentity) -> bool {
        if let Some(c) = &id.comm {
            if self.comms.iter().any(|want| want == c) {
                return true;
            }
        }
        if let Some(cg) = &id.cgroup {
            if self
                .cgroup_contains
                .iter()
                .any(|needle| !needle.trim().is_empty() && cg.contains(needle.as_str()))
            {
                return true;
            }
        }
        self.targets.iter().any(|t| t.matches(id))
    }
}

/// The pre-W-R4 matching rule, kept exactly as it was: exact comm, or a cgroup
/// substring.
///
/// Run on its own — never alongside [`Protect::protects`] — when no
/// `[[protect.targets]]` are configured, so a deployment that has not opted into
/// identity matching pays no extra /proc reads on every tick.
///
/// The one change is the emptiness test. `cgroup_contains = [""]` used to match
/// every process on the host, because every string contains the empty string;
/// treating a blank needle as absent is the only reading of it that could have
/// been intended.
fn legacy_match(cfg: &Protect, pid: u32) -> bool {
    if !cfg.comms.is_empty() {
        if let Some(c) = comm_of(pid) {
            if cfg.comms.iter().any(|want| want == &c) {
                return true;
            }
        }
    }
    if let Some(cg) = cgroup_of(pid) {
        if cfg
            .cgroup_contains
            .iter()
            .any(|needle| !needle.trim().is_empty() && cg.contains(needle.as_str()))
        {
            return true;
        }
    }
    false
}

/// The resolved protected set: each pid with the start time it had when it was
/// resolved. `None` for a start time means /proc would not tell us.
///
/// Membership is deliberately not exposed as a bare `contains(pid)`. A pid
/// number on its own is the whole problem W-R4 describes — it is a name the
/// kernel hands out again — so the only question this type answers is
/// [`Protected::immune`], which requires the live start time as well.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    recorded: BTreeMap<u32, Option<u64>>,
}

impl Protected {
    pub fn insert(&mut self, pid: u32, starttime: Option<u64>) {
        self.recorded.insert(pid, starttime);
    }

    pub fn len(&self) -> usize {
        self.recorded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recorded.is_empty()
    }

    /// The pids alone, for the kernel map — which is keyed by tgid and cannot
    /// carry an identity. Everything the *kernel* can enforce stops at this
    /// line; the start-time half lives in [`Protected::immune`], userspace.
    pub fn pids(&self) -> BTreeSet<u32> {
        self.recorded.keys().copied().collect()
    }

    /// Whether `pid` is still the process that was protected when the policy was
    /// resolved, given its live start time.
    ///
    ///  - not in the set            → not protected
    ///  - protected, start unknown  → protected. We cannot show the pid was
    ///    recycled, and the conservative half here is to refuse to kill:
    ///    protection only ever restrains Warden, it grants nothing.
    ///  - protected, times agree    → protected
    ///  - protected, times disagree → **not** protected. The number was reused
    ///    and the process behind it now is not the one the operator guarded.
    pub fn immune(&self, pid: u32, live: Option<u64>) -> bool {
        match self.recorded.get(&pid) {
            None => false,
            Some(None) => true,
            Some(Some(recorded)) => match live {
                Some(live) => live == *recorded,
                None => true,
            },
        }
    }

    /// The start time recorded for `pid`, distinguishing "absent from the set"
    /// from "present but unreadable when the set was resolved".
    ///
    /// [`Protected::immune`] answers "may we act?", and conflating those two
    /// answers is safe there — both refuse a kill. The detection side needs the
    /// difference: `src/detect.rs` may only silence a takedown claim when it can
    /// *prove* the number changed hands, and "this pid is not in the table" is
    /// not proof of anything. Absent ⇒ `None`; present with an unreadable start
    /// time ⇒ `Some(None)`; otherwise `Some(Some(ticks))`.
    pub fn recorded_starttime(&self, pid: u32) -> Option<Option<u64>> {
        self.recorded.get(&pid).copied()
    }
}

/// What one walk of /proc produced.
#[derive(Debug, Clone, Default)]
pub struct Resolution {
    pub protected: Protected,
    /// One line per configured `[[protect.targets]]` entry that matched no live
    /// process.
    ///
    /// A target that matches nothing is almost always a mistake — a typo in
    /// `exe`, a uid that changed with a package update, a unit renamed inside a
    /// container, a `hidepid=` host where `/proc/<pid>/exe` is unreadable — and
    /// its consequence is silent: the process the operator meant to guard is not
    /// guarded, and nothing says so. This is the runtime version of the audit's
    /// "validate each host's policy"; nothing here logs, because this runs every
    /// ten seconds, so the caller decides when the warning is worth repeating.
    pub unmatched_targets: Vec<String>,
}

/// Resolve the protect policy to the concrete processes to guard. Always
/// includes Warden's own pid when `protect_self`, so an attacker can't
/// decapitate the guardian without tripping the takedown sensor.
pub fn resolve_protected(cfg: &Protect) -> Resolution {
    let mut protected = Protected::default();
    let mut matched_target = vec![false; cfg.targets.len()];

    if cfg.protect_self {
        let me = std::process::id();
        protected.insert(me, starttime_of(me));
    }

    // Cheap early-out: nothing to scan for.
    if cfg.comms.is_empty() && cfg.cgroup_contains.is_empty() && cfg.targets.is_empty() {
        return Resolution {
            protected,
            unmatched_targets: Vec::new(),
        };
    }

    // With no targets configured the scan stays on the legacy path and reads
    // only comm and cgroup. Identity facts are read only when some target
    // actually constrains them.
    let by_identity = !cfg.targets.is_empty();

    for pid in all_pids() {
        let hit = if by_identity {
            let id = ProcIdentity::read(pid);
            for (i, t) in cfg.targets.iter().enumerate() {
                if t.matches(&id) {
                    matched_target[i] = true;
                }
            }
            cfg.protects(&id)
        } else {
            legacy_match(cfg, pid)
        };

        if hit {
            protected.insert(pid, starttime_of(pid));
        }
    }

    let mut unmatched_targets = Vec::new();
    for (i, t) in cfg.targets.iter().enumerate() {
        if !matched_target[i] {
            unmatched_targets.push(format!(
                "protect.targets[{i}] ({}) matched no live process",
                t.describe()
            ));
        }
    }

    Resolution {
        protected,
        unmatched_targets,
    }
}

// ── W2K-43: co-resident instances ───────────────────────────────────────────

/// The identity facts the peer rule reads about one process, gathered into a
/// type so [`peer_basis`] is a function of data rather than of /proc.
///
/// `exe_base` is stored already reduced — the kernel's `" (deleted)"` marker
/// stripped and the path cut to its last component — so a name match means the
/// same thing wherever it is computed, and `exe` keeps the raw path because
/// that marker is itself worth showing to the operator: an instance whose
/// binary was replaced underneath it is the upgrade shape this rule exists to
/// catch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessId {
    pub exe_id: Option<(u64, u64)>,
    pub exe: Option<String>,
    pub exe_base: Option<String>,
    pub comm: Option<String>,
}

impl ProcessId {
    /// Read the peer-relevant facts for `pid`, each one best-effort.
    pub fn read(pid: u32) -> Self {
        let exe = exe_of(pid);
        Self {
            exe_id: exe_id(pid),
            comm: comm_of(pid),
            exe_base: exe.as_deref().and_then(exe_base_of),
            exe,
        }
    }
}

/// How sure we are that another live process is a second copy of this binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerBasis {
    /// Both `/proc/<pid>/exe` targets are the same `(dev, ino)`: the same
    /// executable file. A name cannot produce this and a second build does not
    /// satisfy it.
    SameExecutable,
    /// The name matched and the identity did not prove it. That is one of three
    /// shapes: the other exe was unreadable (`hidepid=`, or another user's
    /// process without `CAP_SYS_PTRACE`), the exe is a readable but *different*
    /// file — another build, another install prefix, an upgrade that replaced
    /// the first one's inode — or the process is not Warden at all and merely
    /// carries its name.
    SameNameOnly,
}

impl PeerBasis {
    /// The words the operator sees. `SameNameOnly` is never allowed to read as
    /// proof, because it is the half an attacker could arrange.
    pub fn phrase(&self) -> &'static str {
        match self {
            PeerBasis::SameExecutable => "the same executable file (dev/ino match)",
            PeerBasis::SameNameOnly => "the same name only; identity NOT verified",
        }
    }
}

/// The `(dev, ino)` of the executable `pid` is running.
///
/// `fs::metadata` follows the `/proc/<pid>/exe` symlink, so the pair names the
/// binary itself rather than the symlink. It also keeps working once the file
/// is unlinked — measured on this host, a process whose on-disk binary had
/// been removed still reported the `dev`/`ino` of the inode it was executing,
/// which is why an upgrade-then-start-a-second-instance is provable rather than
/// merely name-matched. `None` means the read was refused or the process is
/// gone, both of which are statements about the reader, not about the target.
pub fn exe_id(pid: u32) -> Option<(u64, u64)> {
    let md = fs::metadata(format!("/proc/{pid}/exe")).ok()?;
    Some((md.dev(), md.ino()))
}

/// Whether `theirs` is a second copy of `ours`, and on what basis.
///
/// Identity beats name. An unreadable `exe_id` on *either* side cannot produce
/// [`PeerBasis::SameExecutable`] — and the `is_some()` guard matters more than
/// it looks: without it, `None == None` would call every process whose exe this
/// reader cannot open a co-resident Warden, which on a `hidepid=` host is
/// everything on the machine.
pub fn peer_basis(ours: &ProcessId, theirs: &ProcessId) -> Option<PeerBasis> {
    if ours.exe_id.is_some() && ours.exe_id == theirs.exe_id {
        return Some(PeerBasis::SameExecutable);
    }
    if names_match(ours, theirs) {
        return Some(PeerBasis::SameNameOnly);
    }
    None
}

/// Either name half matching is enough, because the two halves disagree for
/// exactly the shapes this must still catch: a comm truncated to 15 bytes, and
/// a wrapper script whose comm is `warden` while its exe is `bash`.
fn names_match(ours: &ProcessId, theirs: &ProcessId) -> bool {
    same_name(&ours.comm, &theirs.comm) || same_name(&ours.exe_base, &theirs.exe_base)
}

/// The name half of a peer rule, reduced the way the rule reads it: the
/// kernel's `" (deleted)"` marker off, the path cut to its last component.
///
/// This has to be the *same* reduction on both sides or the upgrade case
/// silently stops matching — a running instance whose package was replaced
/// shows `<old path> (deleted)` while the new one shows the bare path, and they
/// are the same program. `None` for an empty name, because a path of slashes
/// has no basename and an empty name must not match everything.
fn exe_base_of(exe: &str) -> Option<String> {
    let base = basename(exe_identity(exe));
    if base.is_empty() {
        None
    } else {
        Some(base.to_string())
    }
}

/// Equality of two optional names, where a missing or empty half is *not* a
/// name. An empty string is what `basename` of a path of slashes returns, and
/// matching on it would match everything.
fn same_name(ours: &Option<String>, theirs: &Option<String>) -> bool {
    match (ours, theirs) {
        (Some(a), Some(b)) => !a.is_empty() && a == b,
        _ => false,
    }
}

/// One other live process that reads as a copy of this binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInstance {
    pub pid: u32,
    pub exe: Option<String>,
    pub comm: Option<String>,
    pub basis: PeerBasis,
}

/// The modes that ask a question and exit: they load no program, attach no hook
/// and deliver no finding, so they are not the thing W2K-43 counts.
///
/// This is the argument list, not the behaviour — a process could rename itself
/// away from these tokens. It is used only to decide what a *warning* lists, and
/// never to clear a finding or permit a kill.
pub const INSPECTION_FLAGS: &[&str] = &[
    "--check",
    "--doctor",
    "--health",
    "--explain",
    "--version",
    "--socket-snapshot",
    "--event",
];

/// Whether a command line names one of the modes above.
///
/// Split from /proc so the rule is testable against the strings themselves:
/// an argument must equal a flag exactly, not contain it as a substring, or
/// `--config /etc/warden/--doctorish.conf` would describe an agent as an
/// inspector and drop it from a warning that exists to be complete.
pub fn cmdline_is_inspection(args: &[String]) -> bool {
    args.iter().any(|a| {
        INSPECTION_FLAGS
            .iter()
            .any(|flag| a.as_str() == *flag || a.starts_with(&format!("{flag}=")))
    })
}

/// The arguments of `pid` from `/proc/<pid>/cmdline`, NUL-separated as the
/// kernel writes it. Empty for a kernel thread and for a process whose entry
/// this reader cannot open — and an unreadable command line is not evidence
/// that an agent is running, so callers get `None` rather than a guess.
pub fn cmdline_of(pid: u32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if raw.is_empty() {
        return None;
    }
    let args: Vec<String> = raw
        .split(|b| *b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

/// Whether **this** process is one of the sensing instances, read from its own
/// command line rather than asserted by the caller.
///
/// The startup path and `--doctor` are the same binary, and the count in
/// [`peer_notice`] has to be right for both: the daemon's peer list excludes
/// itself, so one peer means two agents; a `--doctor` run is not an agent, so
/// one peer means a healthy host. Deriving it beats a `true`/`false` literal at
/// each call site — a literal is the kind of thing that stays correct until
/// someone adds a mode and never looks at this line again.
pub fn this_process_is_agent() -> bool {
    cmdline_of(std::process::id())
        .map(|args| !cmdline_is_inspection(&args))
        .unwrap_or(false)
}

/// Whether a candidate that matched by identity or name should still be
/// reported, given its command line.
///
/// The basis test answers "is this the same program?"; this answers "is that
/// program *sensing*?". Both have to hold, and the second one is what keeps
/// `--doctor` off the list — an instance that loads no program and delivers no
/// finding cannot amplify anything, so counting it would make every diagnostic
/// beside a healthy daemon read as a collision.
///
/// `None` for the command line means no readable argv: a kernel thread, a
/// zombie, or an entry `hidepid=` withholds. None of those is a second sensor,
/// and the cost of that reading is a peer this reader cannot see — which
/// [`peer_notice`] words as a count of what was found, never as a claim that no
/// others exist.
fn keep_peer(
    ours: &ProcessId,
    theirs: &ProcessId,
    their_args: Option<&[String]>,
) -> Option<PeerBasis> {
    let basis = peer_basis(ours, theirs)?;
    let args = their_args?;
    if cmdline_is_inspection(args) {
        return None;
    }
    Some(basis)
}

/// Every *other* live process on this host that reads as another copy of this
/// executable **and is running as an agent**.
///
/// W2K-43 is why the question is worth asking: with two Wardens resident and
/// `protect_self` on in both, each one's own /proc enrichment reads arrive at
/// the other as signal and ptrace activity at a protected pid, and each answers
/// by reading /proc again. Measured on the lab VM: ~166 records/s, 26.5% of the
/// kernel ring dropped, no attacker involved.
///
/// The command-line filter is what keeps that claim true of `--doctor`: an
/// operator running a read-only diagnostic next to the daemon would otherwise
/// be told the host holds two instances, when one of them reports nothing and
/// amplifies nothing.
///
/// This is the detection half only. Whether a second instance folds into the
/// first, stands down, or is refused at startup is an operator decision — so
/// nothing here touches what either agent protects, kills, or reports, and no
/// config key changes behaviour. The scan runs at startup and from `--doctor`,
/// never on the per-event path: adding a /proc walk to enrichment would widen
/// the very traffic this is meant to see.
pub fn peer_instances() -> Vec<PeerInstance> {
    let me = std::process::id();
    let ours = ProcessId::read(me);
    let mut peers = Vec::new();

    for pid in all_pids() {
        // Ourselves, excluded. Not a cosmetic filter: the identity test compares
        // two `ProcessId`s, and our own pid satisfies it exactly — so without
        // this line every Warden would report itself as its own co-resident.
        if pid == me {
            continue;
        }
        let theirs = ProcessId::read(pid);
        if let Some(basis) = keep_peer(&ours, &theirs, cmdline_of(pid).as_deref()) {
            peers.push(PeerInstance {
                pid,
                exe: theirs.exe,
                comm: theirs.comm,
                basis,
            });
        }
    }

    peers.sort_by_key(|p| p.pid);
    peers
}

/// One peer, spelled out: what it is, where its executable is, and how sure the
/// match is. `--doctor` prints this even when nothing else would be said, so
/// the listing is a function of its own rather than a fragment of the notice.
pub fn peer_listing(peers: &[PeerInstance]) -> String {
    peers
        .iter()
        .map(|p| {
            format!(
                "pid {} [exe={}, comm={}] — {}",
                p.pid,
                p.exe.as_deref().unwrap_or("UNREADABLE"),
                p.comm.as_deref().unwrap_or("UNREADABLE"),
                p.basis.phrase()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The startup warning's own entry point: the scan result plus the observer
/// kind, read from this process's argv in one place.
///
/// The wrapper exists so the *composition* has a test. `peer_notice` takes
/// `observer_is_agent` as data, and `this_process_is_agent` answers a question
/// about /proc, and neither half is the thing that can be got wrong in
/// production — the failure mode is a call site that passes a literal, or that
/// asks the question of the wrong process. This is the one line both halves are
/// joined at, so it is the one line that can be decided by a unit test.
pub fn peer_warning(peers: &[PeerInstance]) -> Option<String> {
    peer_notice(peers, this_process_is_agent())
}

/// The sentence about what [`peer_instances`] found, or `None` when the host
/// holds at most one agent — silence is the normal case, and a boot log should
/// not be padded with a warning that means nothing.
///
/// `observer_is_agent` is what makes the count honest at the two call sites.
/// The scan leaves our own pid out, so the daemon with one peer holds **two**
/// agents and that is the W2K-43 shape; `--doctor` is not an agent, so seeing
/// one peer means a healthy host with a single instance and must not be worded
/// as a collision. Both sites build their line from this one function so the
/// same evidence cannot be described two ways.
pub fn peer_notice(peers: &[PeerInstance], observer_is_agent: bool) -> Option<String> {
    let total = peers.len() + observer_is_agent as usize;
    if total < 2 {
        return None;
    }
    let listing = peer_listing(peers);
    let who = if observer_is_agent {
        format!("this process (pid {}) and {}", std::process::id(), listing)
    } else {
        listing
    };
    Some(format!(
        "{total} Warden instances are live on this host: {who}. Each one enriches its signal \
         and ptrace records from /proc and each writes findings, so the reads of one arrive at \
         the other as activity at a protected pid — measured on the lab VM at ~166 records/s \
         with 26.5% of the kernel ring dropped, with no attacker involved. Detection only: \
         neither instance's protection, kills, or findings were changed by this reading, and \
         folding one in, standing one down, or refusing a second start is the operator's call \
         (W2K-43). Instances run for --check/--doctor/--health/--explain/--version/\
         --socket-snapshot/--event are excluded because they report nothing; a process that is \
         not Warden but carries its name appears as SAME NAME ONLY, never as proof."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(comms: Vec<&str>, cgroup_contains: Vec<&str>, protect_self: bool) -> Protect {
        Protect {
            comms: comms.into_iter().map(String::from).collect(),
            cgroup_contains: cgroup_contains.into_iter().map(String::from).collect(),
            protect_self,
            targets: Vec::new(),
        }
    }

    fn target(
        comm: Option<&str>,
        exe: Option<&str>,
        uid: Option<u32>,
        cgroup: Option<&str>,
    ) -> ProtectTarget {
        ProtectTarget {
            comm: comm.map(String::from),
            exe: exe.map(String::from),
            uid,
            cgroup: cgroup.map(String::from),
        }
    }

    fn identity(comm: &str, exe: &str, uid: u32, cgroup: &str) -> ProcIdentity {
        ProcIdentity {
            pid: 1234,
            comm: Some(comm.into()),
            exe: Some(exe.into()),
            uid: Some(uid),
            cgroup: Some(cgroup.into()),
        }
    }

    #[test]
    fn self_is_always_protected_by_default() {
        let cfg = policy(vec![], vec![], true);
        let set = resolve_protected(&cfg);
        assert!(set.protected.pids().contains(&std::process::id()));
    }

    #[test]
    fn resolves_our_own_comm() {
        // Whatever the test harness comm is, matching it must find at least us.
        let me = comm_of(std::process::id()).expect("own comm readable");
        let cfg = policy(vec![me.as_str()], vec![], false);
        let set = resolve_protected(&cfg);
        assert!(set.protected.pids().contains(&std::process::id()));
    }

    #[test]
    fn empty_policy_without_self_is_empty() {
        let cfg = policy(vec![], vec![], false);
        assert!(resolve_protected(&cfg).protected.is_empty());
    }

    // ── W-R4: the selector ──────────────────────────────────────────────────

    /// An empty cgroup needle used to match every process on the host, because
    /// every path contains "". A blank needle must mean nothing.
    #[test]
    fn a_blank_cgroup_needle_protects_nobody() {
        let cfg = policy(vec![], vec![""], false);
        assert!(
            resolve_protected(&cfg).protected.is_empty(),
            "a blank cgroup_contains needle must not match every process"
        );

        // Whitespace is the same mistake spelled differently.
        let cfg = policy(vec![], vec!["   "], false);
        assert!(resolve_protected(&cfg).protected.is_empty());
    }

    /// The selector the audit asks for, against the spoof it exists to stop: an
    /// impostor wearing the protected comm. Every named field must hold, so the
    /// comm alone is not enough.
    #[test]
    fn a_target_requires_every_field_it_names() {
        let t = target(
            Some("granian"),
            Some("/usr/bin/granian"),
            Some(999),
            Some("/system.slice/granian.service"),
        );

        assert!(t.matches(&identity(
            "granian",
            "/usr/bin/granian",
            999,
            "/system.slice/granian.service"
        )));

        // The spoof: prctl(PR_SET_NAME) gets the comm right and nothing else.
        assert!(
            !t.matches(&identity(
                "granian",
                "/tmp/evil",
                1000,
                "/user.slice/session-3.scope"
            )),
            "a process that only renamed itself must not satisfy an identity target"
        );

        // One field off is enough to fail — this is an AND, not an OR.
        assert!(!t.matches(&identity(
            "granian",
            "/usr/bin/granian",
            0,
            "/system.slice/granian.service"
        )));
        assert!(!t.matches(&identity(
            "granian",
            "/usr/bin/granian",
            999,
            "/other.slice/granian.service"
        )));
        assert!(!t.matches(&identity(
            "other",
            "/usr/bin/granian",
            999,
            "/system.slice/granian.service"
        )));
    }

    /// A target that names nothing matches nothing. The alternative — an empty
    /// `[[protect.targets]]` entry protecting every process on the host — would
    /// be a worse bug than the one this change fixes.
    #[test]
    fn a_target_that_names_nothing_matches_nothing() {
        let t = ProtectTarget::default();
        assert!(!t.matches(&identity("granian", "/usr/bin/granian", 999, "/x")));
        assert!(!t.names_identity());
    }

    /// An unreadable fact cannot satisfy a constraint on it. On a `hidepid=`
    /// host, a target that names `exe` protects nothing — fail-closed toward
    /// *not* protecting, which is why the resolve reports the miss.
    #[test]
    fn an_unreadable_identity_fact_cannot_satisfy_a_target() {
        let t = target(Some("granian"), Some("/usr/bin/granian"), None, None);
        let mut id = identity("granian", "/usr/bin/granian", 999, "/x");
        id.exe = None;
        assert!(!t.matches(&id));
    }

    /// Legacy selectors keep working alongside targets, and are ORed with them,
    /// so adding a target can never take protection away.
    #[test]
    fn legacy_selectors_still_match_next_to_targets() {
        let mut cfg = policy(vec!["legacy"], vec![], false);
        cfg.targets = vec![target(
            Some("granian"),
            Some("/usr/bin/granian"),
            None,
            None,
        )];

        assert!(cfg.protects(&identity("legacy", "/tmp/x", 1, "/x")));
        assert!(cfg.protects(&identity("granian", "/usr/bin/granian", 2, "/x")));
        assert!(!cfg.protects(&identity("granian", "/tmp/evil", 2, "/x")));
    }

    #[test]
    fn a_target_matching_nothing_is_reported_rather_than_silent() {
        let mut cfg = policy(vec![], vec![], false);
        cfg.targets = vec![target(Some("no-such-process-xyz"), None, None, None)];
        let set = resolve_protected(&cfg);
        assert_eq!(set.unmatched_targets.len(), 1);
        assert!(
            set.unmatched_targets[0].contains("no-such-process-xyz"),
            "the report must name the target as the operator wrote it: {:?}",
            set.unmatched_targets
        );

        // A policy with no targets reports nothing.
        assert!(resolve_protected(&policy(vec![], vec![], false))
            .unmatched_targets
            .is_empty());
    }

    // ── W-R4: the recorded identity ─────────────────────────────────────────

    /// The resolve records the start time, and immunity follows it: a pid whose
    /// live start time disagrees is no longer protected, which is what stops a
    /// recycled number from inheriting protection inside the 10s refresh window.
    #[test]
    fn a_protected_pid_is_immune_only_while_its_start_time_matches() {
        let me = std::process::id();
        let live = starttime_of(me).expect("own start time readable");
        let cfg = policy(vec![], vec![], true);
        let set = resolve_protected(&cfg);

        assert!(
            set.protected.immune(me, Some(live)),
            "the process the policy just matched must be protected"
        );
        assert!(
            !set.protected.immune(me, Some(live + 1)),
            "a pid now naming a process that started later must not inherit protection"
        );
        assert!(
            !set.protected.immune(999_999, Some(live)),
            "a pid the policy never matched is not protected"
        );
    }

    /// An unresolvable start time is the conservative case, not a free pass:
    /// with nothing to compare we cannot show the process changed, so it stays
    /// protected.
    #[test]
    fn an_unreadable_start_time_keeps_immunity() {
        let mut p = Protected::default();
        p.insert(4242, None);
        assert!(p.immune(4242, Some(99)));
        assert!(p.immune(4242, None));
        assert!(!p.immune(4243, Some(99)));
        assert!(p.pids().contains(&4242));
    }

    #[test]
    fn uid_parses_the_real_uid_from_status() {
        let status = "Name:\tgranian\nUid:\t999\t1000\t999\t999\nGid:\t999\t999\t999\t999\n";
        assert_eq!(parse_uid(status), Some(999));
        assert_eq!(parse_uid("Name:\tx\n"), None);
        assert_eq!(parse_uid("Uid:\t0\n"), Some(0));
    }

    /// The /proc readers work against a real process — ours. Without this the
    /// matcher tests above could all pass while `ProcIdentity::read` returned
    /// nothing but `None` in production.
    #[test]
    fn reads_our_own_identity() {
        let me = ProcIdentity::read(std::process::id());
        assert_eq!(me.pid, std::process::id());
        assert!(me.comm.is_some(), "own comm must be readable");
        assert!(me.exe.is_some(), "own exe must be readable");
        assert!(me.uid.is_some(), "own uid must be readable");
    }

    /// W2K-10: `immune` collapses "absent" and "unknown start time" into one
    /// answer because both refuse a kill. The detection side reads the three
    /// states separately, so the collapse has to be explicit and tested here —
    /// if `recorded_starttime` ever returns `Some(None)` for an absent pid,
    /// `src/detect.rs` would start believing it had evidence it never had.
    #[test]
    fn the_recorded_start_time_keeps_absent_apart_from_unknown() {
        let mut set = Protected::default();
        set.insert(100, Some(4242));
        set.insert(200, None);
        assert_eq!(set.recorded_starttime(100), Some(Some(4242)));
        assert_eq!(set.recorded_starttime(200), Some(None));
        assert_eq!(set.recorded_starttime(300), None);
        // The two types agree on what they both answer, and disagree only where
        // `immune` deliberately does not distinguish.
        assert!(set.immune(100, Some(4242)));
        assert!(!set.immune(100, Some(1)));
        assert!(set.immune(200, Some(1)));
        assert!(!set.immune(300, Some(1)));
    }

    // ── W2K-43: the peer rule ───────────────────────────────────────────────

    fn pid_id(exe_id: Option<(u64, u64)>, exe: &str, comm: &str) -> ProcessId {
        ProcessId {
            exe_id,
            exe: Some(exe.into()),
            exe_base: exe_base_of(exe),
            comm: Some(comm.into()),
        }
    }

    fn no_exe_id(exe: &str, comm: &str) -> ProcessId {
        pid_id(None, exe, comm)
    }

    /// The reduction both sides of the name rule have to agree on. A running
    /// instance whose package was replaced shows `<path> (deleted)`; the new
    /// one shows the bare path. Different strings, same program — so if only
    /// one side were reduced, the upgrade shape would stop matching exactly
    /// when the operator most needs to know about it.
    #[test]
    fn the_name_half_is_reduced_the_same_way_on_both_sides() {
        assert_eq!(
            exe_base_of("/usr/local/sbin/warden (deleted)").as_deref(),
            Some("warden")
        );
        assert_eq!(
            exe_base_of("/usr/local/sbin/warden").as_deref(),
            Some("warden"),
            "the reduced and unreduced forms of the same install must agree"
        );
        // No basename at all is no name, not an empty one.
        assert_eq!(exe_base_of("/"), None);
        assert_eq!(exe_base_of(""), None);
        // The marker is only stripped as a suffix: a directory genuinely named
        // that keeps its name.
        assert_eq!(
            exe_base_of("/srv/warden (deleted)/bin").as_deref(),
            Some("bin")
        );
    }

    /// The provable case, and it does not need the name to agree: same file,
    /// same process, however the two were launched or renamed.
    #[test]
    fn the_same_inode_is_the_same_executable_however_it_is_named() {
        let ours = pid_id(Some((42, 7)), "/usr/local/sbin/warden", "warden");
        let peer = pid_id(Some((42, 7)), "/home/dev/warden", "warden");
        assert_eq!(peer_basis(&ours, &peer), Some(PeerBasis::SameExecutable));

        // Even with a different comm — comm is a string the process chose, so
        // the identity test must not require its agreement.
        let renamed = pid_id(Some((42, 7)), "/usr/local/sbin/warden", "kworker");
        assert_eq!(peer_basis(&ours, &renamed), Some(PeerBasis::SameExecutable));
    }

    /// Two unknowns are not one match. Without the `is_some()` guard this pair
    /// compares equal and every process whose exe the reader cannot open —
    /// everything, on a `hidepid=` host — becomes a co-resident Warden.
    #[test]
    fn two_unreadable_identities_never_prove_the_same_file() {
        let ours = no_exe_id("/usr/local/sbin/warden", "warden");
        let other_user = no_exe_id("/usr/local/sbin/warden", "warden");
        assert_eq!(
            peer_basis(&ours, &other_user),
            Some(PeerBasis::SameNameOnly),
            "a name match is the fallback, and it must be labelled unverified"
        );

        let unrelated = no_exe_id("/usr/bin/bash", "bash");
        assert_eq!(peer_basis(&ours, &unrelated), None);
    }

    /// One readable identity and one unreadable cannot produce proof either —
    /// and when the names also disagree, nothing is claimed at all.
    #[test]
    fn a_one_sided_identity_read_is_not_a_match() {
        let ours = pid_id(Some((42, 7)), "/usr/local/sbin/warden", "warden");
        let unreadable = no_exe_id("/usr/local/sbin/warden", "warden");
        assert_eq!(
            peer_basis(&ours, &unreadable),
            Some(PeerBasis::SameNameOnly)
        );

        let unreadable_other = no_exe_id("/usr/bin/ssh", "sshd");
        assert_eq!(peer_basis(&ours, &unreadable_other), None);
    }

    /// Either name half carries the match, because the halves disagree for the
    /// two shapes that must still be caught: a 15-byte truncated comm, and a
    /// wrapper script named `warden` whose exe is the shell.
    #[test]
    fn either_name_half_matches_and_neither_is_proof() {
        let ours = pid_id(Some((42, 7)), "/usr/local/sbin/warden", "warden");

        // Same comm, different exe basename.
        let comm_only = pid_id(Some((42, 8)), "/opt/other/warden", "warden");
        assert_eq!(peer_basis(&ours, &comm_only), Some(PeerBasis::SameNameOnly));

        // Same exe basename, different comm — the `prctl` shape, and the
        // truncated-comm shape.
        let base_only = pid_id(Some((42, 8)), "/opt/other/warden", "wrk");
        assert_eq!(peer_basis(&ours, &base_only), Some(PeerBasis::SameNameOnly));

        // A wrapper: comm says warden, exe says bash.
        let wrapper = pid_id(Some((42, 8)), "/usr/bin/bash", "warden");
        assert_eq!(peer_basis(&ours, &wrapper), Some(PeerBasis::SameNameOnly));

        // Neither half, despite a readable identity on both sides.
        let unrelated = pid_id(Some((42, 9)), "/usr/bin/ssh", "ssh");
        assert_eq!(peer_basis(&ours, &unrelated), None);
    }

    /// The upgrade shape: the packaged instance keeps running the inode the
    /// package manager unlinked, the new one execs the new file. The kernel
    /// marks the first one's path `(deleted)`, the inodes differ, and the name
    /// still says what both processes are.
    #[test]
    fn an_upgraded_binary_still_reads_as_the_same_name() {
        let ours = pid_id(Some((42, 99)), "/usr/local/sbin/warden", "warden");
        let stale = pid_id(Some((42, 7)), "/usr/local/sbin/warden (deleted)", "warden");
        assert_eq!(stale.exe_base.as_deref(), Some("warden"));
        assert_eq!(peer_basis(&ours, &stale), Some(PeerBasis::SameNameOnly));
    }

    /// An empty name is not a name. `basename` of a path of slashes is `""`,
    /// and matching on it would match every process that has no readable exe
    /// basename — the same mistake as the `None == None` comparison above.
    #[test]
    fn a_blank_name_matches_nothing() {
        let ours = pid_id(Some((42, 7)), "/usr/local/sbin/warden", "warden");
        let blank = ProcessId {
            exe_id: None,
            exe: Some("/".into()),
            exe_base: Some(String::new()),
            comm: Some(String::new()),
        };
        assert_eq!(peer_basis(&ours, &blank), None);

        // And a blank on our own side must not turn the walk into "everything".
        let blank_ours = ProcessId::default();
        assert_eq!(peer_basis(&blank_ours, &blank), None);
        assert_eq!(peer_basis(&blank_ours, &ours), None);

        // Two processes that each read as blank on both halves. This is the case
        // `same_name`'s emptiness guard exists for — equality alone calls them the
        // same program. It is reachable, not theoretical: `prctl(PR_SET_NAME, "")`
        // leaves an empty comm, and a `hidepid=` or EPERM reader gets `None` exe, so
        // an unreadable stranger would be reported as a second sensor.
        assert_eq!(
            peer_basis(&blank, &blank),
            None,
            "two empty names are not proof of one program"
        );
    }

    /// Our own identity has to be readable for the walk to say anything at all:
    /// `/proc/self/exe` is readable without any privilege, and its inode is the
    /// one every copy of this binary is compared against.
    #[test]
    fn our_own_identity_is_readable_enough_to_compare() {
        let me = std::process::id();
        let ours = ProcessId::read(me);
        assert!(
            ours.exe_id.is_some(),
            "our own (dev,ino) must be readable — the whole SameExecutable basis rests on it"
        );
        assert!(ours.comm.is_some());
        let exe = ours.exe.as_deref().expect("own exe readable");
        assert_eq!(
            ours.exe_base.as_deref(),
            exe_base_of(exe).as_deref(),
            "the stored name is the reduced form of the stored path"
        );
    }

    /// The read has to follow the symlink to the **binary**.
    ///
    /// `/proc/<pid>/exe` is itself a file with its own inode, on procfs, one per
    /// process. Stat it without following and every two processes get a
    /// different pair, `SameExecutable` can never fire, and the whole rule
    /// degrades to name matching while still printing the word "verified" next
    /// door. This is the one property of `exe_id` that no pure test can state,
    /// so it is checked against the file the running binary actually is.
    #[test]
    fn the_identity_is_the_binaries_own_inode_not_the_procfs_symlink() {
        let me = std::process::id();
        let file = std::env::current_exe().expect("own exe path");
        let md = fs::metadata(&file).expect("own exe statable");
        assert_eq!(
            exe_id(me),
            Some((md.dev(), md.ino())),
            "exe_id must report the executable's (dev,ino); the symlink at {} is a \
             different file on a different filesystem",
            file.display()
        );

        // And it is not the symlink's own identity, which is what a
        // `symlink_metadata` implementation would return.
        let link = fs::symlink_metadata(format!("/proc/{me}/exe")).expect("own exe link");
        assert_ne!(
            exe_id(me),
            Some((link.dev(), link.ino())),
            "the /proc/<pid>/exe inode is per-process and would make every comparison fail"
        );
    }

    /// The walk must never name the process doing the walking. This is the one
    /// case that is guaranteed to be on every host, so a missing self-exclusion
    /// would put a false co-resident in the log on every single boot.
    #[test]
    fn the_walk_excludes_the_process_doing_the_walk() {
        let peers = peer_instances();
        let me = std::process::id();
        assert!(
            !peers.iter().any(|p| p.pid == me),
            "peer_instances named its own process: {peers:?}"
        );
    }

    /// `keep_peer` is the walk's whole agent filter, and the live version of it
    /// is `this_process_is_agent()`: this test binary is an agent by argv, so
    /// the walk must not drop itself for being an inspection mode. That is what
    /// makes the self-exclusion above the *only* thing keeping this pid out of
    /// its own peer list — if the filter were inverted, `peer_notice(&[], …)`
    /// would silently never fire on a real second instance.
    #[test]
    fn the_agent_filter_keeps_the_process_it_is_running_in() {
        assert!(
            this_process_is_agent(),
            "the test harness carries none of Warden's inspection flags"
        );
        let ours = ProcessId::read(std::process::id());
        let args = cmdline_of(std::process::id()).expect("own cmdline readable");
        assert_eq!(
            keep_peer(&ours, &ours, Some(&args)),
            Some(PeerBasis::SameExecutable),
            "a same-inode process with an ordinary argv is an agent"
        );
    }

    /// Every peer the walk reports has to be a *different* live pid whose
    /// identity or name genuinely says what the rule claims. Cheap to check and
    /// it catches a scan that compares against the wrong `ProcessId`.
    #[test]
    fn every_reported_peer_is_another_live_process() {
        for p in peer_instances() {
            assert_ne!(p.pid, std::process::id());
            let id = ProcessId::read(p.pid);
            assert_eq!(id.comm, p.comm, "pid {} comm drifted", p.pid);
            assert_eq!(id.exe, p.exe, "pid {} exe drifted", p.pid);
            assert!(
                keep_peer(
                    &ProcessId::read(std::process::id()),
                    &id,
                    cmdline_of(p.pid).as_deref()
                )
                .is_some(),
                "pid {} was reported by the walk but fails the walk's own rule",
                p.pid
            );
            match p.basis {
                PeerBasis::SameExecutable => {
                    assert_eq!(
                        id.exe_id,
                        ProcessId::read(std::process::id()).exe_id,
                        "pid {} was called the same file without matching inodes",
                        p.pid
                    );
                }
                PeerBasis::SameNameOnly => {
                    assert!(
                        names_match(&ProcessId::read(std::process::id()), &id),
                        "pid {} was name-matched with no name in common",
                        p.pid
                    );
                }
            }
        }
    }

    /// Silence when there is nothing to say, and evidence when there is: the
    /// notice has to carry the pid, the basis in the words the tier earns, and
    /// the statement that no decision was taken.
    #[test]
    fn the_notice_says_only_what_the_evidence_supports() {
        assert_eq!(peer_notice(&[], true), None);
        assert_eq!(peer_notice(&[], false), None);

        let proved = PeerInstance {
            pid: 4711,
            exe: Some("/usr/local/sbin/warden".into()),
            comm: Some("warden".into()),
            basis: PeerBasis::SameExecutable,
        };
        let notice = peer_notice(std::slice::from_ref(&proved), true).expect("two agents");
        assert!(
            notice.starts_with("2 Warden instances are live on this host"),
            "{notice}"
        );
        assert!(notice.contains("4711"), "{notice}");
        assert!(notice.contains("dev/ino match"), "{notice}");
        assert!(!notice.contains("NOT verified"), "{notice}");

        let named = PeerInstance {
            pid: 8888,
            exe: None,
            comm: Some("warden".into()),
            basis: PeerBasis::SameNameOnly,
        };
        let notice = peer_notice(&[proved, named], true).expect("three agents is a notice");
        assert!(
            notice.starts_with("3 Warden instances are live on this host"),
            "{notice}"
        );
        assert!(notice.contains("identity NOT verified"), "{notice}");
        assert!(notice.contains("UNREADABLE"), "{notice}");
        // Both halves of a peer's identity have to be labelled when they are
        // missing: a listing that prints `exe=, comm=` reads as an empty field,
        // not as a read that was refused.
        let blind = PeerInstance {
            pid: 7,
            exe: None,
            comm: None,
            basis: PeerBasis::SameNameOnly,
        };
        let notice = peer_notice(std::slice::from_ref(&blind), true).expect("a peer is a notice");
        assert!(
            notice.contains("[exe=UNREADABLE, comm=UNREADABLE]"),
            "{notice}"
        );
        // Detection, never action: the sentence must not read as if the second
        // instance had been dealt with.
        assert!(notice.contains("operator's call"), "{notice}");

        // And the observer has to say whether it is inside the count it
        // prints: an agent names itself, an inspector does not.
        assert!(
            notice.contains(&format!("this process (pid {}) and", std::process::id())),
            "an agent's notice must put itself in the count it reports: {notice}"
        );
        let seen_by_inspector =
            peer_notice(&[agent(4711), named2()], false).expect("two agents seen by an inspector");
        assert!(
            !seen_by_inspector.contains("this process"),
            "an inspector is not one of the instances it counts: {seen_by_inspector}"
        );
    }

    fn named2() -> PeerInstance {
        PeerInstance {
            pid: 9999,
            exe: Some("/usr/local/sbin/warden".into()),
            comm: Some("warden".into()),
            basis: PeerBasis::SameExecutable,
        }
    }

    /// The filter that keeps `--doctor` out of the peer list, stated apart from
    /// /proc: same inode is not enough when the process holding it is only
    /// asking a question.
    #[test]
    fn an_inspection_mode_is_never_a_peer_even_on_the_same_inode() {
        let ours = pid_id(Some((42, 7)), "/usr/local/sbin/warden", "warden");
        let arg = |a: &str| a.to_string();

        // The daemon's own shape: argv[0] and a config path.
        let agent_args = vec![
            arg("warden"),
            arg("--config"),
            arg("/etc/warden/warden.toml"),
        ];
        assert_eq!(
            keep_peer(&ours, &ours, Some(&agent_args)),
            Some(PeerBasis::SameExecutable)
        );

        // The same binary, run as a diagnostic: no pair, no warning.
        for flag in INSPECTION_FLAGS {
            let inspector = vec![arg("/usr/local/sbin/warden"), arg(flag)];
            assert_eq!(
                keep_peer(&ours, &ours, Some(&inspector)),
                None,
                "{flag} runs load nothing and must not be counted as a second sensor"
            );
        }

        // No readable argv at all is not counted either.
        assert_eq!(keep_peer(&ours, &ours, None), None);
        // And a process that is not a copy of us is dropped before argv is
        // ever consulted.
        let stranger = pid_id(Some((42, 8)), "/usr/bin/ssh", "ssh");
        assert_eq!(keep_peer(&ours, &stranger, Some(&agent_args)), None);
    }

    /// The whole reason `observer_is_agent` exists. `--doctor` beside a single
    /// daemon sees one peer — and one agent on the host is the healthy case, so
    /// printing the collision sentence there would train the operator to ignore
    /// the warning that fires when two daemons really do run. The daemon itself
    /// does not exclude a `--doctor` run by accident: the filter is its business.
    #[test]
    fn one_agent_seen_by_an_inspector_is_not_a_collision() {
        let daemon = agent(945);
        assert_eq!(peer_notice(std::slice::from_ref(&daemon), false), None);
        assert!(peer_notice(std::slice::from_ref(&daemon), true).is_some());

        // Two agents seen by an inspector IS the finding, and the count says
        // two, not three: the process asking the question is not one of them.
        let notice = peer_notice(&[daemon, agent(3122)], false).expect("two live agents");
        assert!(
            notice.starts_with("2 Warden instances are live on this host"),
            "{notice}"
        );
    }

    fn agent(pid: u32) -> PeerInstance {
        PeerInstance {
            pid,
            exe: Some("/usr/local/sbin/warden".into()),
            comm: Some("warden".into()),
            basis: PeerBasis::SameExecutable,
        }
    }

    /// The seam the startup warning uses. It joins the scan to the observer's
    /// kind, and this process is an agent by argv, so one synthetic peer has to
    /// read as the pair it is.
    ///
    /// Hardcoding `false` at this one line is the bug this test exists to
    /// catch: the daemon would then need TWO other instances before it warned,
    /// and the measured two-agent lab host would stay quiet — the same silence
    /// as no detection at all, but with a detection next to it in the code.
    #[test]
    fn the_startup_seam_counts_the_process_it_is_running_in() {
        assert!(
            this_process_is_agent(),
            "the walk runs inside an agent here, or the seam below proves nothing"
        );
        assert!(
            peer_warning(std::slice::from_ref(&agent(945))).is_some(),
            "one peer seen by an agent is two instances"
        );
        assert_eq!(peer_warning(&[]), None);
        let two = [agent(945), agent(3122)];
        assert_eq!(
            peer_warning(&two).as_deref(),
            peer_notice(&two, true).as_deref(),
            "the seam must be the notice, with this process counted in it"
        );
    }

    /// The inspector flags, exactly. A substring match would drop an agent whose
    /// config path merely *looks* like a flag, and a missing flag would let a
    /// read-only diagnostic be counted as a second sensor.
    #[test]
    fn the_inspection_modes_are_matched_exactly_and_all_of_them() {
        let arg = |a: &str| a.to_string();

        for flag in INSPECTION_FLAGS {
            assert!(cmdline_is_inspection(&[arg("warden"), arg(flag)]), "{flag}");
            // The `--explain=KIND` spelling the parser also accepts.
            assert!(
                cmdline_is_inspection(&[arg("warden"), arg(&format!("{flag}=x"))]),
                "{flag}=x"
            );
        }

        // Not inspection: an agent, whatever the string contains.
        assert!(!cmdline_is_inspection(&[arg("warden")]));
        assert!(!cmdline_is_inspection(&[
            arg("warden"),
            arg("--config"),
            arg("/etc/warden/warden.toml")
        ]));
        assert!(
            !cmdline_is_inspection(&[
                arg("warden"),
                arg("--config"),
                arg("/warden/--doctorish.conf")
            ]),
            "a flag is an argument, not a substring"
        );
        assert!(!cmdline_is_inspection(&[arg("warden"), arg("--docto")]));

        // An empty command line — a kernel thread, a zombie, or a hidden entry —
        // is not an inspector either, so the caller's `None` handling decides.
        assert!(!cmdline_is_inspection(&[]));
    }

    /// A live command line reads back as the arguments that were used, and the
    /// shapes that have none are not counted as agents. This is the filter's
    /// only contact with /proc, so it is checked against the reading process
    /// itself — the one entry every host is guaranteed to have.
    #[test]
    fn a_live_command_line_reads_back_and_an_absent_one_reads_as_nothing() {
        let me = std::process::id();
        let args = cmdline_of(me).expect("our own cmdline is readable");
        assert!(!args.is_empty(), "an execed process has an argv[0]");
        assert!(
            !cmdline_is_inspection(&args),
            "a test harness is not a warden inspection mode: {args:?}"
        );

        // No such pid, and the kernel-thread shape: no command line at all.
        assert_eq!(cmdline_of(0), None);
    }
}
