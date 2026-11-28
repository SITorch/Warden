//! detect.rs — behavioural detection: raw kernel events → severity-tagged
//! Findings. This is where "an execve happened" becomes "the web worker just
//! spawned an interactive shell — that's a reverse shell."
//!
//! No signatures. Every rule is a statement about *behaviour in context*: who
//! the actor is (app cgroup? app exe?), what they did, against whom.

use crate::c2::{C2Tracker, ConnectSample};
use crate::config::Config;
use crate::events::{
    cap_names, cgroup_of, cmdline_of, exe_of, pidfd_liveness, signal_name, starttime_of, Event,
    ExeIdentity, FileOp, Kind, Liveness, Protocol, ServiceOp, SignalDelivery, TASK_COMM_LEN,
};
use crate::procscan::{ProcIdentity, Protected};
use serde::Serialize;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
/// Severity ladder — mirrors the strings Sentinel's host-ingest expects.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// The Sentinel `endpoint:*` event taxonomy (the reserved kill-chain slots).
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    #[serde(rename = "endpoint:process_creation")]
    ProcessCreation,
    #[serde(rename = "endpoint:self_tamper")]
    SelfTamper,
    #[serde(rename = "endpoint:privilege_change")]
    PrivilegeChange,
    #[serde(rename = "endpoint:network_connect")]
    NetworkConnect,
    /// Phase 4: a bounded, confidence-bearing local beaconing signal. A
    /// behavioural observation, not a verdict and never a kill request.
    #[serde(rename = "endpoint:c2_beaconing")]
    C2Beaconing,
    /// A bounded join of two already-judged kernel observations (e.g. a
    /// suspicious exec followed by an unsanctioned dial). A stronger signal
    /// than either half alone, but observe-only: never a kill request, never a
    /// claim about payload, DNS or TLS metadata this build cannot see.
    #[serde(rename = "endpoint:attack_chain")]
    AttackChain,
    #[serde(rename = "endpoint:module_load")]
    ModuleLoad,
    #[serde(rename = "endpoint:file_tamper")]
    FileTamper,
    #[serde(rename = "endpoint:new_service")]
    NewService,
    #[serde(rename = "endpoint:listen")]
    ListenBackdoor,
    #[serde(rename = "endpoint:bpf_load")]
    BpfLoad,
    #[serde(rename = "endpoint:mount")]
    MountEscape,
    #[serde(rename = "endpoint:access_denied")]
    AccessDenied,
    /// The sensor reporting a degradation of its OWN delivery path (findings
    /// lost, dead-lettered, or isolated). Not an attacker action — this slot is
    /// for the platform's own operational picture, and carries no kill intent.
    #[serde(rename = "endpoint:self_degraded")]
    SelfDegraded,
}

impl FindingType {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingType::ProcessCreation => "endpoint:process_creation",
            FindingType::SelfTamper => "endpoint:self_tamper",
            FindingType::PrivilegeChange => "endpoint:privilege_change",
            FindingType::NetworkConnect => "endpoint:network_connect",
            FindingType::C2Beaconing => "endpoint:c2_beaconing",
            FindingType::AttackChain => "endpoint:attack_chain",
            FindingType::ModuleLoad => "endpoint:module_load",
            FindingType::FileTamper => "endpoint:file_tamper",
            FindingType::NewService => "endpoint:new_service",
            FindingType::ListenBackdoor => "endpoint:listen",
            FindingType::BpfLoad => "endpoint:bpf_load",
            FindingType::MountEscape => "endpoint:mount",
            FindingType::AccessDenied => "endpoint:access_denied",
            FindingType::SelfDegraded => "endpoint:self_degraded",
        }
    }
}

/// Process evidence block — the attribution the network layer can't see.
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// Clock ticks since boot at which this process started (W-R3). Captured
    /// alongside the pid so the responder can prove, immediately before
    /// signalling, that the pid still names *this* process and not a later one
    /// that inherited the number. `None` means /proc could not be read (it may
    /// be mounted with `hidepid=`) — the responder treats that as unverified
    /// identity rather than as a match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starttime: Option<u64>,
}

/// A judged finding, ready to log, act on, and ship to Sentinel.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub event_type: FindingType,
    pub severity: Severity,
    pub summary: String,
    /// The kernel's monotonic event timestamp (`bpf_ktime_get_ns`, in
    /// nanoseconds) from the raw ring-buffer record that produced this
    /// finding. `0` means the finding has no kernel event to anchor to — a
    /// locally synthesised degradation finding, a test, or a record built
    /// before this field existed. It is deliberately NOT a Unix time: the
    /// bridge converts it using a same-instant clock sample and labels both
    /// values on the wire. Never substitute the agent's processing time for
    /// this when judging event chronology.
    #[serde(skip)]
    pub source_ts_ns: u64,
    pub process: ProcessInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pid: Option<u32>,
    /// Whether a local responder should consider acting (kill). The policy
    /// engine in main decides if it actually does, per config + mode.
    ///
    /// `#[serde(skip)]` here is about this struct's own JSON, not about the wire:
    /// the envelope ships the same bool under the name `enforcement_requested`
    /// (`bridge::envelope`), because the far side needs it to read `action`
    /// correctly. One spelling on the wire, deliberately.
    #[serde(skip)]
    pub wants_kill: bool,
    pub detail: serde_json::Value,
}

/// Prune the per-actor burst map once it holds more than this many pids. The
/// walk is amortised and only runs when the map is this large; below it, the
/// per-event cost is one hash lookup, as before.
const BURST_MAP_PRUNE_AT: usize = 4096;

/// How many process identities the `/proc` evidence cache may hold. Same shape as
/// the burst-map bound: the map is sized for a busy host, and the eviction walk
/// only runs once it is actually full.
const ENRICH_CACHE_MAX: usize = 4096;

/// `/proc` evidence for one *process image*, reused across events until the cache
/// window in `[runtime] enrich_cache_ms` expires (W2K-13).
///
/// Deliberately not a whole `ProcessInfo`: `pid`, `ppid`, `uid` and `comm` ride
/// on the event itself, measured by the kernel when the event happened, so
/// caching them would only make a finding report the kernel's own numbers from
/// an earlier moment. What costs four syscalls to get — and is what this caches
/// — is the readlink and the three file reads.
#[derive(Clone)]
struct CachedProc {
    exe: Option<String>,
    cmdline: Option<String>,
    cgroup: Option<String>,
    fetched_at: Instant,
}

impl CachedProc {
    /// A cache hit plus the numbers the event itself carries — which is all of
    /// them, except the three that cost reads.
    fn into_process(self, e: &Event, starttime: u64) -> ProcessInfo {
        ProcessInfo {
            pid: e.actor_pid,
            ppid: e.actor_ppid,
            uid: e.actor_uid,
            comm: e.comm.clone(),
            exe: self.exe,
            cmdline: self.cmdline,
            cgroup: self.cgroup,
            starttime: Some(starttime),
        }
    }
}

impl From<&ProcessInfo> for CachedProc {
    fn from(p: &ProcessInfo) -> Self {
        Self {
            exe: p.exe.clone(),
            cmdline: p.cmdline.clone(),
            cgroup: p.cgroup.clone(),
            fetched_at: Instant::now(),
        }
    }
}

/// What `--explain` hands in place of the three `/proc` reads.
///
/// The shape is deliberately identical to the three fields of `CachedProc` and
/// `ProcessInfo` that cost syscalls, and deliberately does not include `pid`,
/// `ppid`, `uid` or `comm`: those ride on the event and are the kernel's own
/// numbers, so an explaining run keeps taking them from the record it is
/// judging. A hypothetical event has no `/proc` entry to read, and inventing one
/// would let the CLI answer "what would Warden have said" with evidence Warden
/// never had. Nothing here is ever set by the daemon path —
/// [`Detector::new`] leaves it `None` and only [`Detector::for_explain`] fills
/// it, which is what keeps this a question-answering seam rather than a policy
/// one.
#[derive(Debug, Clone)]
pub(crate) struct FabricatedEvidence {
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub cgroup: Option<String>,
}

/// A pid that cannot exist on any Linux host (`PID_MAX_LIMIT` is far below it),
/// used by `--explain` so a hypothetical actor can never collide with
/// [`Detector::self_pid`] — the ptrace READ self-exemption is real in the daemon,
/// and an explaining run must not trip it by accident.
pub(crate) const IMPOSSIBLE_PID: u32 = u32::MAX;

pub struct Detector {
    cfg: Config,
    /// Per-actor sliding window of recent destructive-file-op timestamps (ns),
    /// for the behavioural ransomware (mass-modification) rule. Keyed by actor
    /// pid. Interior-mutable because `judge` takes `&self` — the event loop is
    /// single-threaded, so a plain RefCell is sufficient and lock-free.
    file_bursts: RefCell<HashMap<u32, VecDeque<u64>>>,
    /// W2K-13: fetched `/proc` evidence, keyed by `(pid, start time)`. The start
    /// time is what makes the key an identity rather than a number: the kernel
    /// recycles pids, and a recycled pid necessarily starts later, so a new
    /// occupant misses here instead of inheriting someone else's exe and cgroup.
    proc_evidence: RefCell<HashMap<(u32, u64), CachedProc>>,
    /// Complete `/proc` fetches served by this detector. The counter is what turns
    /// "the cache saves reads" from a claim into something a test can assert.
    enrich_fetches: Cell<u64>,
    /// Events whose evidence came from `proc_evidence` rather than from `/proc`.
    enrich_hits: Cell<u64>,
    /// This process's own pid. The proc scanner reads /proc/<pid> of every
    /// protected process to keep its identity table fresh, and each read raises
    /// `security_ptrace_access_check`; without this the guardian reports *itself*
    /// tens of times a second and fills the bridge spool with its own
    /// supervision (seen live: endpoint:self_tamper at ~50/s). A pid cannot be
    /// spoofed the way a comm can, so this is the precise filter.
    self_pid: u32,
    /// W2K-10: the protected set exactly as it was when the kernel's pid-keyed
    /// map was last written, each pid bound to the start time it had then.
    ///
    /// `protected_pids` in the kernel is keyed by tgid alone — a map cannot carry
    /// an identity — so the kernel's "this target is protected" is only ever as
    /// fresh as the last `PROTECT_REFRESH`. When a protected process dies and its
    /// number is handed to something else, the kernel keeps emitting for the
    /// stale number and the judges below would report a takedown of a process
    /// that is not protected. `src/main.rs` refreshes this alongside the map, so
    /// the two are never more than one tick out of step.
    ///
    /// Empty by default, which is a *deliberate* fail-open: with no recorded
    /// identities there is nothing to compare a live start time against, and no
    /// takedown is ever silenced for lack of evidence.
    protected: RefCell<Protected>,
    /// W2K-20b: `Some` only for an `--explain` run, where the actor is
    /// hypothetical and its `/proc` entry does not exist. `None` is the daemon's
    /// normal state and the only state the production path ever reaches.
    fabricated: Option<FabricatedEvidence>,
    /// Phase 4: bounded per-process beaconing state over CONNECT telemetry.
    /// Interior-mutable like `file_bursts`; the event loop is single-threaded.
    c2: RefCell<C2Tracker>,
    /// Bounded cross-event joins over the judged stream. Anchors are kernel
    /// timestamps plus the identity of an already-suspicious event — no payload,
    /// no `comm`-only trust, and never an enforcement decision.
    correlator: RefCell<crate::correlate::Correlator>,
    /// Phase 1 → Phase 4 quality link. `None` means the live ring-loss ratio
    /// could not be read, which caps C2 confidence rather than inflating it.
    c2_ring_loss: Cell<Option<f64>>,
    /// Phase 7: positive proof that an egress denial primitive is loaded,
    /// attached and backed by a known-good policy map. `None` (the default)
    /// means no proof was ever supplied, so every policy-DENY finding stays an
    /// observe-only finding. The daemon sets this from the *kernel-verified*
    /// runtime state after startup and every SIGHUP; config alone never does.
    egress_preflight: Cell<Option<crate::policy::Preflight>>,
}

impl Finding {
    pub fn severity_str(&self) -> &'static str {
        self.severity.as_str()
    }
    pub fn event_type_str(&self) -> &'static str {
        self.event_type.as_str()
    }
}

/// Last component of a path. Used to compare an executed binary against
/// `shell_comms`, whose entries are names (`bash`), not paths.
pub(crate) fn basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// `/proc/<pid>/exe` for a binary removed from disk reads `<path> (deleted)` —
/// the kernel appends that to the link target. The part in front of it is still
/// the identity worth matching, so name and location rules strip it; only the
/// fileless rule keys on the suffix itself.
pub(crate) fn exe_identity(exe: &str) -> &str {
    exe.strip_suffix(" (deleted)").unwrap_or(exe)
}

/// Is the file the kernel named one of the files these paths name?
///
/// The kernel's half of the comparison is `(s_dev, i_ino)` stamped inside the hook;
/// the configured half is produced here by `stat()`ing each path, in the kernel's own
/// `kdev_t` encoding. Two paths that are hardlinks of one file collapse to one inode,
/// so a match means "this exact file", not "this exact name" — which is the claim an
/// authorization has to rest on, and it is the same identity the guarded-inode map
/// keys use (`crate::guard`).
///
/// Three answers, because the third is not a verdict:
/// * `Some(true)` — the kernel-named file is an authorized one.
/// * `Some(false)` — an authorized path resolved, and none of them is that file.
/// * `None` — nothing was comparable: the list is empty (the shipped default) or no
///   entry resolves from this mount namespace. Returning `Some(false)` here would
///   turn an unconfigured host's silence into a conviction, which is a different
///   posture than the one the operator chose.
fn inode_matches_any_path(id: ExeIdentity, paths: &[String]) -> Option<bool> {
    let mut any_resolved = false;
    for path in paths {
        let Some(candidate) = ExeIdentity::of_path(path) else {
            continue;
        };
        any_resolved = true;
        if candidate == id {
            return Some(true);
        }
    }
    any_resolved.then_some(false)
}

/// Can the name the process chose for itself be the reason a finding is dropped?
///
/// A comm is a string the process picked with `prctl(PR_SET_NAME)`, so every
/// comm-keyed suppressor in this file — `benign_reader_comms`,
/// `expected_privilege_comms`, `allow_loaders` — is a switch an attacker can flip
/// for their own process. This function is what makes a *readable* executable
/// argue back: the name clears the finding when it is the name of the binary we
/// found, and does not when the two contradict each other. It is weaker than a
/// path allowlist, which is why every caller consults the allowlist first, and it
/// needs no configuration, which is why it also runs where the operator has pinned
/// nothing.
///
/// `None` agrees by construction — nothing we read contradicts the name — and that
/// is a statement about the evidence, not a pass: the caller decides what a
/// name-only claim is worth at its own boundary.
///
/// Two tolerances, both from how the kernel reports names and neither from
/// anything an attacker could do:
///  - `/proc/<pid>/comm` is cut at [`TASK_COMM_LEN`] minus one byte, so
///    `systemd-journal` IS `systemd-journald`'s name. A truncated prefix is
///    accepted only at exactly that length, because that is the only length at
///    which truncation can have happened.
///  - A process may re-title a *child* of the same binary with a suffixed name
///    (`runc` reports `runc:[1:CHILD]`), so a comm that is the binary's name plus
///    a separator and a suffix is accepted too.
///
/// The residual, stated plainly: an attacker who puts their payload at a path
/// whose basename equals the name they claim (`/tmp/sudo`) still passes here. That
/// is a file-writing step, not a syscall, and the location rules
/// (`exec_rules.untrusted_exe_prefixes`) and the fileless-exe rules judge it
/// separately. An operator who wants the name to buy nothing at all pins the real
/// paths — `benign_reader_exes`, `expected_privilege_exes`, `allow_loader_exes`.
fn name_agrees_with_exe(comm: &str, exe: Option<&str>) -> bool {
    let Some(exe) = exe else { return true };
    let base = basename(exe_identity(exe)).to_ascii_lowercase();
    let comm = comm.to_ascii_lowercase();
    if comm.is_empty() || base.is_empty() {
        return false;
    }
    if comm == base {
        return true;
    }
    if comm.len() == TASK_COMM_LEN - 1 && base.starts_with(&comm) {
        return true;
    }
    match comm.strip_prefix(&base) {
        // The suffix has to look like a suffix, not like a different word: a
        // separator first (`runc:[1:CHILD]`, `sshd: [accepted]`).
        Some(rest) => matches!(rest.as_bytes().first(), Some(b':' | b'-' | b' ')),
        None => false,
    }
}

/// Can a self-chosen name be the whole reason an implant-capable eBPF load is
/// silent?
///
/// Only when there is no process left to ask. A loader that exited before
/// enrichment leaves no identity for anyone to read — that is the case
/// `allow_loaders` exists for, and the finding calls it the weaker posture it is.
/// A loader still sitting at that pid number is a live process whose binary could
/// not be read and whose name it picked for itself, and that is not a pass: it is
/// the shape this rule was written to catch.
///
/// `Unknown` goes with `Gone`. The two answers that produce it — a kernel without
/// pidfd support, a seccomp filter that refuses `pidfd_open` — mean the probe
/// learned nothing, and "the probe learned nothing" is not evidence that a process
/// is running. Refusing a name because a probe failed would turn a kernel-capability
/// question into a Critical finding, which is the wrong direction for a report-only
/// detector. The gap that leaves is the host's, and the report names it.
fn name_only_clears_a_load(liveness: Liveness) -> bool {
    !matches!(liveness, Liveness::Alive)
}

/// What a signal number does, by the kernel's own default, to a process that has
/// no handler for it.
///
/// The detector used a five-number list — KILL, TERM, STOP, QUIT, ABRT — and
/// called every other number a "takedown attempt" at Medium. Both halves were
/// wrong in opposite directions: SIGHUP, SIGINT, SIGUSR1, SIGUSR2, SIGPIPE,
/// SIGALRM and the whole real-time range *terminate* a target that does not catch
/// them, and were reported below the tier that describes them, while SIGCONT,
/// SIGWINCH, SIGCHLD and SIGURG cannot stop a process at all and were still
/// labelled an attempt on a protected pid.
///
/// Report §۸۷ measured this table instead of quoting one: a throwaway target with
/// its handlers reset to `SIG_DFL`, one signal per process, alive-or-dead read
/// back from `/proc`. The default is deliberately the harsher reading, for the
/// same reason the hook guesses `SI_USER` for an si_code it could not read — a
/// number this table does not know is far more likely to be an unfamiliar member
/// of the terminate-by-default set than a new way to do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalEffect {
    /// Default action is Term or Core: the target stops existing unless it catches
    /// or ignores the signal.
    Terminates,
    /// Default action is Stop: the target keeps its memory and stops running — an
    /// application that is not executing is not signing, and a guardian frozen here
    /// stops beating for the same reason a dead one does.
    Freezes,
    /// Default action is Ign or Cont: this number cannot take the target out of
    /// service by itself.
    Inert,
}

impl SignalEffect {
    fn as_str(self) -> &'static str {
        match self {
            SignalEffect::Terminates => "terminates",
            SignalEffect::Freezes => "freezes",
            SignalEffect::Inert => "inert",
        }
    }

    /// Can this number take a process out of service on its own?
    fn stops_the_target(self) -> bool {
        !matches!(self, SignalEffect::Inert)
    }
}

fn signal_effect(sig: u32) -> SignalEffect {
    let s = sig as i32;
    if matches!(
        s,
        libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
    ) {
        SignalEffect::Freezes
    } else if matches!(
        s,
        libc::SIGCHLD | libc::SIGCONT | libc::SIGURG | libc::SIGWINCH
    ) {
        SignalEffect::Inert
    } else {
        SignalEffect::Terminates
    }
}

/// The one thing `--explain` needs from the table above, exported so the probe
/// wording cannot drift from the tier it describes — a probe that calls SIGHUP
/// "non-lethal" is offering a change that changes nothing.
pub(crate) fn signal_stops_target(sig: u32) -> bool {
    signal_effect(sig).stops_the_target()
}

/// Who the actor is, as far as this host could verify it, in one sentence the
/// finding carries.
///
/// The point is not to decorate the summary. `endpoint:self_tamper` has always said
/// *someone signalled a protected pid*; what an operator needed and could not get is
/// the reason to believe or doubt the identity attached to it. `comm` is a string the
/// process picked, `/proc/<pid>/exe` is a path the kernel read, and pid 1 belongs to
/// exactly one task on a Linux host.
///
/// Callers reach this only after the parent check has been answered, so the sentence
/// says what the hook ruled out rather than re-deriving it.
fn identity_note(proc: &ProcessInfo) -> String {
    // The actor's uid stays in the finding detail for the remote record, but
    // it has no place in a phrase that can be copied into a local log: it is
    // an account identifier, not an operational correlate. PID and executable
    // evidence still say what the kernel could verify.
    let who = match proc.exe.as_deref() {
        Some(path) => format!("{} running {}", proc.comm, exe_identity(path)),
        None => format!(
            "{} whose executable could not be read — identity NOT verified",
            proc.comm
        ),
    };
    // Three different things a small pid number can mean, and the old two-way test
    // conflated the first two: `pid <= 1` called pid 0 init, which is not true of any
    // task, and it is the number `--explain` always shows because its actor is
    // hypothetical. The sentence below is evidence an operator reads as a claim about
    // who sent the signal, so a pid that names no task must not be handed the one
    // privilege that makes a finding look authorized.
    let role = match proc.pid {
        0 => format!("actor pid 0 names no task — this record has no sender identity to check: {who}"),
        1 => format!("actor pid 1 is init, a pid number no other task can hold: {who}"),
        n => format!("actor pid {n} is not the victim's real parent — the hook settled that at send time: {who}"),
    };
    role
}

/// Is `path` `dir` itself or something below it? A bare `starts_with` would call
/// `/tmpish/stage` a child of `/tmp`, so the boundary byte must be a separator.
pub(crate) fn under_dir(path: &str, dir: &str) -> bool {
    let dir = dir.trim_end_matches('/');
    path == dir
        || (path.len() > dir.len()
            && path.starts_with(dir)
            && path.as_bytes().get(dir.len()) == Some(&b'/'))
}

impl Detector {
    pub fn new(cfg: Config) -> Self {
        let c2 = C2Tracker::new(cfg.c2_rules.clone());
        let correlation = cfg.correlation.clone();
        Self {
            cfg,
            file_bursts: RefCell::new(HashMap::new()),
            proc_evidence: RefCell::new(HashMap::new()),
            enrich_fetches: Cell::new(0),
            enrich_hits: Cell::new(0),
            self_pid: std::process::id(),
            protected: RefCell::new(Protected::default()),
            fabricated: None,
            c2: RefCell::new(c2),
            correlator: RefCell::new(crate::correlate::Correlator::new(correlation)),
            c2_ring_loss: Cell::new(None),
            egress_preflight: Cell::new(None),
        }
    }

    /// Phase 7: publish the kernel-verified egress capability to the judge.
    /// `None` degrades every deny annotation to observe-only; `Some` is only
    /// ever built from attach/map facts by `main.rs`, never from config. The
    /// caller passes a plain `Preflight` (Copy) so no map handle is shared with
    /// the single-threaded event loop.
    pub fn set_egress_preflight(&self, preflight: Option<crate::policy::Preflight>) {
        self.egress_preflight.set(preflight);
    }

    /// Phase 1 → Phase 4: hand the latest measured ring-loss ratio to the
    /// beaconing detector. Called from the same tick that logs the counters;
    /// `None` is honest ("not measurable") and caps C2 confidence at Medium.
    pub fn set_ring_loss_ratio(&self, ratio: Option<f64>) {
        self.c2_ring_loss.set(ratio);
    }

    /// A detector that judges a *hypothetical* event: the evidence `--explain`
    /// was given instead of `/proc`, and a self-pid no real process can carry.
    ///
    /// The self-pid is swapped because `judge_ptrace` exempts a READ-mode ptrace
    /// from `self_pid`, and an explaining CLI's own pid is as arbitrary as the
    /// pid the operator typed — a request about "some process reading /proc"
    /// would otherwise be silenced, or a request about Warden reading its own
    /// protected process would not be judged at all. `IMPOSSIBLE_PID` makes the
    /// exemption untriggerable, and `--explain` prints the rule so the reader
    /// knows the exemption exists.
    pub(crate) fn for_explain(cfg: Config, fabricated: FabricatedEvidence) -> Self {
        Self {
            fabricated: Some(fabricated),
            self_pid: IMPOSSIBLE_PID,
            ..Self::new(cfg)
        }
    }

    /// W2K-10 / F09: hand the judges the identity table behind the pid set that
    /// was pushed to the kernel. This includes tripwire-only pids (comm matches)
    /// so PID reuse can still be proven for them; it is NOT the responder's
    /// immunity set and is never passed to `Responder::act`. Called by
    /// `src/main.rs` at startup, on every reconciliation tick, and on SIGHUP
    /// reload — the same three places that write the kernel's pid map.
    pub fn set_protected(&mut self, protected: Protected) {
        *self.protected.borrow_mut() = protected;
    }

    /// Whether `target_pid` still names the protected process the kernel
    /// recorded it for.
    ///
    /// The kernel's `protected_pids` map is pid-keyed, so a signal or ptrace
    /// aimed at a number that has since been reused reaches userspace labelled
    /// "protected" and would be reported as a takedown attempt. A start time
    /// settles the question, and only a *proven* change of hands silences it:
    ///
    ///  - pid absent from the recorded set → keep. Nothing to compare against,
    ///    and the set is the same one the kernel map was written from, so absence
    ///    means the tick hasn't caught up — not that the target is innocent.
    ///  - recorded, but /proc would not give a start time then → keep, same reason.
    ///  - live start time unreadable (process gone, or `hidepid=`) → keep. This is
    ///    the branch that matters: a successful kill makes the victim disappear,
    ///    so "the target is no longer there" is the sound of the attack
    ///    succeeding and must never be read as "nothing happened".
    ///  - start times agree → the same process; keep.
    ///  - start times disagree → the number changed hands. Report only if the
    ///    process sitting on it now matches the protect policy itself, because
    ///    then the takedown claim is still true of a different victim.
    fn target_is_protected(&self, target_pid: u32) -> bool {
        let recorded = match self.protected.borrow().recorded_starttime(target_pid) {
            None => return true,
            Some(None) => return true,
            Some(Some(start)) => start,
        };
        match starttime_of(target_pid) {
            None => true,
            Some(live) if live == recorded => true,
            Some(live) => {
                let reused = self.cfg.protect.protects(&ProcIdentity::read(target_pid));
                if !reused {
                    log::debug!(
                        "detect: pid {target_pid} is still in the kernel's protected map but now \
                         starts at {live}, not the recorded {recorded} — the number was recycled, \
                         not a takedown. Silenced until the next protected-set refresh \
                         (W2K-10).",
                    );
                }
                reused
            }
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The process evidence block an event is judged and reported on.
    ///
    /// This used to cost four `/proc` reads per event — `stat` for the identity
    /// anchor, then `exe`, `cmdline` and `cgroup` — however busy the actor was.
    /// W2K-13 keeps the anchor read and serves the other three from
    /// `proc_evidence` for `[runtime] enrich_cache_ms`, so an actor producing a
    /// storm of file or connect records now costs one read per event instead of
    /// four.
    ///
    /// Three rules keep a cached answer from ever becoming a wrong one:
    ///
    ///  - **The key is `(pid, starttime)`, never the pid alone.** A recycled
    ///    number necessarily starts later, so it misses and re-reads. With no
    ///    anchor at all — `hidepid=`, or the process already gone — nothing is
    ///    cached and the event pays the original four reads, which is the honest
    ///    fallback rather than a performance bug.
    ///  - **An exec always re-reads.** `execve` is the one operation that changes
    ///    `exe` and `cmdline` under an unchanged `(pid, starttime)` — same number,
    ///    same clock, different binary — and the deleted-exe and staged-binary
    ///    rules from W2K-15 are judged on exactly those fields. The exec's fresh
    ///    read is what republishes the entry.
    ///  - **The window bounds the staleness a finding can carry.** `cgroup`
    ///    membership really does move under a live process (`cgclassify`, a unit
    ///    reload), so app-cgroup attribution can be up to the window old: 100 ms
    ///    by default, refused above [`crate::config::MAX_ENRICH_CACHE_MS`].
    ///    `cmdline` is writable by the process itself (`setproctitle`), and no
    ///    rule in this file keys on it — it is evidence inside a finding, never
    ///    the reason for one.
    ///
    /// The residual, and it is a real one: an exec *record* lost to a ring
    /// overrun leaves the previous image cached for one window. That is why the
    /// same audit pairs this cache with the ring size and the per-sensor drop
    /// counters — the counters are how an operator learns the cache is being fed
    /// incomplete execs.
    fn enrich(&self, e: &Event) -> ProcessInfo {
        if let Some(f) = &self.fabricated {
            return ProcessInfo {
                pid: e.actor_pid,
                ppid: e.actor_ppid,
                uid: e.actor_uid,
                comm: e.comm.clone(),
                exe: f.exe.clone(),
                cmdline: f.cmdline.clone(),
                cgroup: f.cgroup.clone(),
                // No start time: there is no process to have started. `None` is
                // the same claim a live agent makes when `/proc` refuses it
                // (`hidepid=`, or the process already exited), and the responder
                // reads it as unverified identity rather than as a match.
                starttime: None,
            };
        }
        let starttime = starttime_of(e.actor_pid);
        let ttl = self.cfg.runtime.enrich_cache_ttl();
        if let (Some(ttl), Some(start)) = (ttl, starttime) {
            if e.kind != Kind::Exec {
                if let Some(hit) = self.cached_proc(e.actor_pid, start, ttl) {
                    self.enrich_hits.set(self.enrich_hits.get() + 1);
                    return hit.into_process(e, start);
                }
            }
            let proc = self.read_actor(e, Some(start));
            self.remember(e.actor_pid, start, &proc);
            return proc;
        }
        self.read_actor(e, starttime)
    }

    /// The three `/proc` reads the cache exists to avoid. One call is one
    /// increment of `enrich_fetches`, which is what the tests measure.
    fn read_actor(&self, e: &Event, starttime: Option<u64>) -> ProcessInfo {
        self.enrich_fetches.set(self.enrich_fetches.get() + 1);
        ProcessInfo {
            pid: e.actor_pid,
            ppid: e.actor_ppid,
            uid: e.actor_uid,
            comm: e.comm.clone(),
            exe: exe_of(e.actor_pid),
            cmdline: cmdline_of(e.actor_pid),
            cgroup: cgroup_of(e.actor_pid),
            starttime,
        }
    }

    /// Cached evidence for this exact process image, if the window has not
    /// passed. An expired entry is left where it is: `remember` overwrites it on
    /// the next read, and the eviction walk in `remember` owns removal, so the
    /// hot path stays a single lookup.
    fn cached_proc(&self, pid: u32, start: u64, ttl: Duration) -> Option<CachedProc> {
        let hit = self.proc_evidence.borrow().get(&(pid, start)).cloned()?;
        (hit.fetched_at.elapsed() <= ttl).then_some(hit)
    }

    fn remember(&self, pid: u32, start: u64, proc: &ProcessInfo) {
        let mut cache = self.proc_evidence.borrow_mut();
        cache.insert((pid, start), CachedProc::from(proc));
        if cache.len() > ENRICH_CACHE_MAX {
            // Full: drop what the window has already aged out, and if even that
            // leaves it full, drop the whole map. A miss costs three reads; an
            // entry kept too long costs a wrongly-attributed finding, and the
            // bound is here because the deployment target is a small VPS.
            let ttl = self.cfg.runtime.enrich_cache_ttl().unwrap_or_default();
            cache.retain(|_, entry| entry.fetched_at.elapsed() <= ttl);
            if cache.len() > ENRICH_CACHE_MAX {
                cache.clear();
            }
        }
    }

    /// A READ-mode ptrace from a process whose job is to read /proc is not
    /// credential recon: known scanner comms, or a container runtime joining a
    /// target's namespaces (every `docker exec` and healthcheck does this).
    ///
    /// Two authorisations, strongest first (W2K-30b). The exe list decides whenever
    /// the path could be read — it is compared against `/proc/<pid>/exe`, a path the
    /// process did not choose. The comm list is matched case-insensitively and now
    /// clears a read only when the executable we read *agrees* with the name:
    /// `prctl(PR_SET_NAME)` lets any process call itself `systemd`, and a bare
    /// comm-match made the list an evasion target rather than a suppression. Where
    /// no exe could be read the name still carries the read, because a `runc` that
    /// joins namespaces and exits before enrichment is the routine shape.
    fn benign_reader(&self, comm: &str, exe: Option<&str>) -> bool {
        if let Some(path) = exe {
            if self
                .cfg
                .ptrace_rules
                .benign_reader_exes
                .iter()
                .any(|allowed| allowed == path)
            {
                return true;
            }
        }
        self.cfg
            .ptrace_rules
            .benign_reader_comms
            .iter()
            .any(|c| c.eq_ignore_ascii_case(comm))
            && name_agrees_with_exe(comm, exe)
    }

    /// Is this actor inside the application's cgroup? Attribution for T1: a
    /// shell spawned *by the app* is an incident; the same shell in an admin's
    /// login session is routine.
    fn actor_in_app_cgroup(&self, proc: &ProcessInfo) -> bool {
        match &proc.cgroup {
            Some(cg) => self
                .cfg
                .app
                .cgroup_contains
                .iter()
                .any(|needle| cg.contains(needle)),
            None => false,
        }
    }

    /// Is there still a process at this pid? Asked of the kernel's pid table, not
    /// of `/proc`.
    ///
    /// The difference matters exactly where W2K-29 lives. A load whose loader has
    /// exited leaves no identity for anyone to read, so honouring its self-chosen
    /// `comm` is the weakest available evidence. A load whose loader is *still
    /// running* is not that case: the process is there, its name was read from
    /// nowhere the kernel controls, and the only thing standing between it and a
    /// silent implant-capable program is that name. `pidfd_open` is the only syscall
    /// that answers this without going through `/proc` (W2K-39 established it on the
    /// kill path), and the branch is rare enough — implant-capable type, allowlisted
    /// comm, unreadable exe — that asking costs nothing in the common path.
    ///
    /// What the answer is worth depends on who asks, so the fall-back is stated
    /// rather than assumed: the shipped unit grants `CAP_SYS_PTRACE`, and for a
    /// process this task may not reach the kernel may refuse the handle. Either way
    /// only a positive `Alive` changes the verdict — every other answer, including
    /// one the probe could not give, lands in [`name_only_clears_a_load`] and keeps
    /// the behaviour this stage replaced. Report §۷۷ measured the arm that matters
    /// on Debian 13 / 6.12.107: uid 1000 with no capabilities, behind
    /// `hidepid=invisible`, got `ALIVE` for three root-owned processes whose
    /// `/proc/<pid>/exe` read `ENOENT` in the same breath — so on that kernel a
    /// hidden live loader is caught, not excused. The refused arm stays unmeasured
    /// because the shipped unit does not install a filter that refuses it.
    ///
    /// `--explain` runs have no process behind the event at all, so there is nothing
    /// to ask: the hypothetical is treated as the exited loader, which is what those
    /// runs did before and what the finding then says in its `authorization` field.
    fn loader_is_live(&self, pid: u32) -> bool {
        if self.fabricated.is_some() {
            return false;
        }
        !name_only_clears_a_load(pidfd_liveness(pid))
    }

    /// Judge one event. Returns None when the event is benign in context (e.g.
    /// a routine non-shell exec, or a shell outside the app cgroup when we have
    /// an app cgroup configured).
    pub fn judge(&self, e: &Event) -> Option<Finding> {
        // Single anchoring point for the kernel's own event time. Every
        // per-kind judge builds a Finding from this Event; stamping here means
        // no judge can forget the timestamp, and a finding synthesised without
        // a kernel event (degradation reports, tests) keeps the explicit 0.
        // `ts_ns` is CLOCK_MONOTONIC from bpf_ktime_get_ns(), never a Unix time.
        let judged = match e.kind {
            Kind::Exec => self.judge_exec(e),
            Kind::Signal => self.judge_signal(e),
            Kind::Ptrace => self.judge_ptrace(e),
            Kind::Connect => self.judge_connect(e),
            // The dial's VERDICT (N-02) deliberately produces no host finding here.
            // `judge_connect` already raises the one High finding per unsanctioned
            // egress at the moment the socket is aimed; raising again when the
            // transport answers would double-count the same dial — the finding-flood
            // failure this detector was explicitly tuned down for. The outcome
            // record's consumer is the platform flow contract (`conn_state`, see
            // `Event::conn_state_hint`), and that path is the owner-gated F-38.1
            // wiring, not this build. Attaching a verdict to the finding it belongs
            // to needs correlation state userspace does not keep yet.
            Kind::ConnectResult => None,
            // The accept record (N-03 accept half) is journal-only in this build, and
            // for a reason that is a policy rather than an oversight: an accepted
            // connection is *expected* traffic on a host whose whole job is serving
            // connections. The deployment host measured ≈3.9 accepts per second in a
            // quiet window — a finding per accept would bury the detector, which is
            // the failure mode this file's history is full of. The value is in the
            // record (who accepted whom, on which port, in which namespace), and the
            // judgement that can use it is "this peer is not one of the listeners'
            // sanctioned peers" — an allowlist the platform owns, not a host rule this
            // agent has. Until that wiring exists, no finding: see the roadmap's F-38
            // flow contract, which is owner-gated.
            Kind::Flow => None,
            Kind::Creds => self.judge_creds(e),
            Kind::Module => self.judge_module(e),
            Kind::File => self.judge_file(e),
            Kind::Service => self.judge_service(e),
            Kind::Listen => self.judge_listen(e),
            Kind::BpfLoad => self.judge_bpf(e),
            Kind::Mount => self.judge_mount(e),
            Kind::Access => self.judge_access(e),
        };
        judged.map(|mut f| {
            f.source_ts_ns = e.ts_ns;
            f
        })
    }

    /// Join this event with earlier judged events. Call for *every* decoded
    /// event, including ones the judge declined: a CONNECT_RESULT or a FLOW is
    /// useful precisely when it follows a finding the judge already raised.
    ///
    /// The correlator receives the judge's answer rather than re-running it, so
    /// the beaconing tracker is never advanced twice for one dial. Every chain
    /// is observe-only and is emitted as its own stable finding type.
    pub fn correlate(&self, e: &Event, primary: Option<&Finding>) -> Option<Finding> {
        let matched = self.correlator.borrow_mut().observe(e, primary)?;
        let proc = self.enrich(e);
        Some(self.correlator.borrow().finding_for(matched, proc, e))
    }

    /// Which identity, if any, names a shell or scripting host.
    ///
    /// `comm` alone was the W2K-15 hole: 15 bytes the process itself rewrites
    /// with `prctl(PR_SET_NAME)`, and the field an attacker is guaranteed to
    /// control. `/proc/<pid>/exe` is a readlink the kernel owns and `filename`
    /// is the path the `execve` tracepoint actually resolved, so each is
    /// consulted in that order and any of them naming a shell is enough. They
    /// disagree when a symlink or a hardlinked copy is exec'd, which is exactly
    /// when the trusted identity matters.
    ///
    /// Returns the source label — written into `detail.matched_by` so the
    /// analyst sees *why* this matched — and the name it matched.
    fn shell_identity(&self, e: &Event, exe: Option<&str>) -> Option<(&'static str, String)> {
        let filename = if e.filename.is_empty() {
            None
        } else {
            Some(e.filename.as_str())
        };
        for (label, candidate) in [
            ("exe", exe.map(basename)),
            ("filename", filename.map(basename)),
            ("comm", Some(e.comm.as_str())),
        ] {
            if let Some(name) = candidate {
                if self.cfg.exec_rules.shell_comms.iter().any(|s| s == name) {
                    return Some((label, name.to_string()));
                }
            }
        }
        None
    }

    /// `[app].exe_allowlist`, consulted on the resolved exe only: naming
    /// `/usr/local/bin/python3.11` declares that binary legitimate wherever it
    /// lives, so the staged-location rule stands down for it. A `(deleted)` exe
    /// never matches — a fileless binary is the signal, not the exception — and
    /// `comm` is never consulted, because ceasing to trust it is the point.
    fn exe_allowlisted(&self, proc: &ProcessInfo) -> bool {
        proc.exe.as_deref().is_some_and(|raw| {
            !raw.ends_with("(deleted)")
                && self
                    .cfg
                    .app
                    .exe_allowlist
                    .iter()
                    .any(|allowed| allowed == raw)
        })
    }

    /// Was this binary staged somewhere world-writable rather than installed?
    /// The evasion the location rule exists for is `cp /bin/bash /tmp/svc-agent`:
    /// no name in `shell_comms` matches any identity, but the path still says a
    /// directory any local user can write into handed out the executable.
    /// Returns the path that sits under an untrusted prefix.
    fn staged_in_untrusted_dir<'a>(&self, e: &'a Event, exe: Option<&'a str>) -> Option<&'a str> {
        let filename = if e.filename.is_empty() {
            None
        } else {
            Some(e.filename.as_str())
        };
        [exe, filename].into_iter().flatten().find(|path| {
            self.cfg
                .exec_rules
                .untrusted_exe_prefixes
                .iter()
                .any(|dir| under_dir(path, dir))
        })
    }

    fn judge_exec(&self, e: &Event) -> Option<Finding> {
        let proc = self.enrich(e);
        self.judge_exec_with(e, &proc)
    }

    /// The judging half of [`Self::judge_exec`], with the process evidence handed
    /// in rather than read from this host's `/proc`. Split out because the exe
    /// axis is the one W2K-15 moves onto and the test process's own exe is not a
    /// shell — without this seam the strongest identity would have been the only
    /// one no test could exercise.
    fn judge_exec_with(&self, e: &Event, proc: &ProcessInfo) -> Option<Finding> {
        // The `(deleted)` suffix is stripped before matching so a fileless shell
        // is still recognised as a shell by name; `deleted_exe` below reports it
        // with the higher severity that outranks the name match.
        let exe = proc.exe.as_deref().map(exe_identity);
        let matched = self.shell_identity(e, exe);
        let deleted_exe = self.cfg.exec_rules.flag_deleted_exe
            && proc
                .exe
                .as_deref()
                .map(|p| p.ends_with("(deleted)"))
                .unwrap_or(false);

        // A configured app cgroup narrows both context rules to app-spawned
        // processes. With no app cgroup set, we can't attribute, so we stay quiet
        // on plain shells (they're normal on a dev box) and only escalate
        // deleted-exe — exactly as judge_connect/judge_creds/judge_file do with
        // an empty cgroup.
        let have_app_cgroup = !self.cfg.app.cgroup_contains.is_empty();
        let from_app = have_app_cgroup && self.actor_in_app_cgroup(proc);
        let shell_from_app = from_app && matched.is_some();
        let staged = if from_app && !self.exe_allowlisted(proc) {
            self.staged_in_untrusted_dir(e, exe)
        } else {
            None
        };
        let staged_from_app = staged.is_some();

        if !shell_from_app && !staged_from_app && !deleted_exe {
            return None;
        }

        let (severity, summary, reason, wants_kill) = if deleted_exe {
            (
                Severity::Critical,
                format!(
                    "fileless execution: pid {} ({}) runs a binary deleted from disk",
                    proc.pid, proc.comm
                ),
                "deleted_exe",
                self.cfg.respond.kill_reverse_shell,
            )
        } else if shell_from_app {
            (
                Severity::High,
                format!(
                    "app-context shell spawn: {} (pid {}) exec'd inside the application",
                    proc.comm, proc.pid
                ),
                "shell_in_app_cgroup",
                self.cfg.respond.kill_reverse_shell,
            )
        } else {
            // Reached only when `staged_from_app` held, so the path is there.
            let path = staged.unwrap_or(e.filename.as_str());
            (
                Severity::Medium,
                format!(
                    "app-context exec from a staging area: pid {} ({}) ran {path} from a \
                     location any local user can write into",
                    proc.pid, proc.comm
                ),
                "untrusted_exe_location",
                // Never kills, even with kill_reverse_shell armed: "a binary came
                // out of /tmp" is an unexplained exec, not a proven shell, and pip
                // or a deploy script can produce it.
                false,
            )
        };

        let mut detail = serde_json::json!({
            "reason": reason,
            "filename": e.filename,
            "in_app_cgroup": from_app,
        });
        if let Some((matched_by, name)) = matched {
            detail["matched_by"] = serde_json::json!(matched_by);
            detail["matched_name"] = serde_json::json!(name);
        }
        if let Some(path) = staged {
            detail["staged_path"] = serde_json::json!(path);
        }
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::ProcessCreation,
            severity,
            summary,
            detail,
            process: proc.clone(),
            target_pid: None,
            wants_kill,
        })
    }

    fn judge_signal(&self, e: &Event) -> Option<Finding> {
        // A supervisor signalling the process it spawned is terminating its own
        // child — systemd restarting a unit, Docker reaping a timed-out
        // healthcheck, a pool parent recycling a worker. The kernel answers
        // "is the sender the victim's real parent?" at the hook, the only moment
        // both tasks still exist; the tripwire's threat is a signal from OUTSIDE
        // the process tree. Silencing this also keeps an armed responder from
        // killing the supervisor (e.g. containerd-shim) over a routine restart.
        if e.signal_from_parent {
            return None;
        }
        // Otherwise a signal aimed at a protected pid is only *emitted* by the
        // kernel when the target is protected — so reaching here means some process
        // signalled a protected pid. Whether it aimed at someone else (an attack) or
        // at its own process (a death) is decided below; an outside lethal signal is
        // critical.
        //
        // "Protected" here is the kernel's pid-keyed claim, so it is checked
        // against the start time the map was written with first (W2K-10): a
        // recycled number aimed at something innocent is not a takedown.
        if !self.target_is_protected(e.target_pid) {
            return None;
        }
        let proc = self.enrich(e);
        let sig = e.aux;
        // The responder's arm list. W2K-36 left this five-number list exactly as it
        // found it, even though the severity table below is now wider: whether
        // SIGINT or SIGHUP should also be able to kill a process is a posture
        // decision the owner makes, not a defect this stage fixes. See W2K-42.
        let arming = matches!(
            sig as i32,
            libc::SIGKILL | libc::SIGTERM | libc::SIGSTOP | libc::SIGQUIT | libc::SIGABRT
        );
        // W2K-04 — the two things the kernel only tells us at the hook.
        //
        // `signal_delivery` is the si_code class: which call aimed the signal. It is
        // evidence, not a verdict input, and it matters because the shapes differ:
        // `kill(2)` is a command, `sigqueue(3)` is a program with a payload, and `tkill`
        // is also how `raise()`/`abort()` deliver. Userspace cannot reconstruct any of
        // it later — the siginfo is gone. The three classes whose names describe a
        // kernel mechanism (`timer_claimed`, `mqueue_claimed`, `sigio_claimed`) describe
        // a number a SENDER chose instead: -2, -3 and -5 are not reserved to the kernel,
        // and for two of the three the kernel's own delivery demonstrably skips this
        // hook — timer expiry goes through `posixtimer_send_sigqueue()` and fasync
        // through `send_sigio_to_task()` → `do_send_sig_info()`, neither of which calls
        // `check_kill_permission()` (and no kernel caller using `send_sig_info()` does
        // either). A record naming a mechanism can therefore not be attributed to it.
        // Reading one is a lead worth chasing, not proof of a timer.
        //
        // What the class is NOT is a way to tell a kernel-generated signal apart: no
        // kernel-generated signal reaches this sensor at all. `check_kill_permission()`
        // in kernel/signal.c returns before calling the LSM hook unless
        // `si_fromuser(info)` holds, and that means `si_code <= 0`
        // (SI_FROMUSER in uapi/asm-generic/siginfo.h). So a protected process that
        // takes a SIGSEGV/SIGBUS/SIGFPE produces no SIGNAL record, and the OOM
        // killer's SEND_SIG_PRIV is filtered by the sentinel test in the hook itself.
        // The audit's premise for W2K-04 was half wrong, and the header says so with
        // its sources; what is left to fix is the case that really does arrive —
        // below.
        let delivery = e.signal_delivery.unwrap_or(SignalDelivery::User);
        // The reachable misjudgement: the victim aimed the blow at ITSELF. A Rust
        // panic in the signer aborts, glibc's abort() tgkill-s its own thread group,
        // and a process can `kill(getpid(), SIGTERM)` just as easily as anyone else —
        // so a protected process on its way out is recorded with actor == target. That
        // is a death worth reporting and a bad reason to arm a responder: the pid is
        // already going, and killing a recycled number afterwards hits whatever lives
        // there next. Severity drops to Medium and the kill request is withheld; the
        // finding itself is never silenced, because whatever made the guardian abort is
        // exactly what an operator wants to see.
        //
        // An external actor is unaffected: `actor_pid` is the sender's tgid measured
        // in the same namespace as `target_pid`, so no one but the victim's own
        // process can produce this shape — including a privileged one.
        //
        // One exception, and it is the kernel's fault rather than the sender's: the
        // usbfs completion path calls this hook from whatever context took the
        // completion (`kill_pid_usb_asyncio`), so on an SI_ASYNCIO-shaped record the
        // actor may name no sender at all and `actor == target` is an accident of
        // which CPU ran. That class therefore cannot prove self-termination, and an
        // attacker naming -4 in `rt_sigqueueinfo` gets the same conservative answer.
        let self_directed = e.actor_pid == e.target_pid && delivery.actor_names_the_sender();
        // Warden installs SIGHUP -> reload and SIGTERM/SIGINT -> orderly shutdown in
        // main's signal block. A SIGHUP at the agent's own pid therefore does not stop
        // the sensor; it is the documented reload path. Nobody else's handler set is
        // knowable from a hook record, so this stays restricted to the one target whose
        // handlers this binary can state.
        let own_reload =
            !self_directed && sig as i32 == libc::SIGHUP && e.target_pid == self.self_pid;
        // The second authorized sender, and the one W2K-36 was about: pid 1. The hook
        // read the sender's tgid out of its task struct, so no other process can wear
        // that number, and what reaches a protected pid from pid 1 with a userspace
        // siginfo is the service manager stopping or reloading a unit — including the
        // shape the parent exemption cannot cover, where the protected process sits in
        // the unit's cgroup but is not pid 1's own child.
        let init_controlled = !self_directed && e.actor_pid == 1;
        // Severity now follows what the number DOES, with the two identities above
        // taken off the table. An outside signal whose default action is to terminate or
        // freeze the target is a takedown attempt at Critical; a number the kernel would
        // ignore or use to resume a stopped task is not a blow at all, and is Info
        // rather than silence so the operator still sees who poked the guardian.
        let effect = signal_effect(sig);
        let severity = if self_directed {
            Severity::Medium
        } else if own_reload || init_controlled {
            Severity::Low
        } else if effect.stops_the_target() {
            Severity::Critical
        } else {
            Severity::Info
        };
        // W2K-36 and W2K-41 asked for the same thing: keep the record, say WHY it is
        // what it says. `reason` is the machine-readable verdict and `authorization`
        // is the human-readable basis, spelled from what this host could verify — the
        // pid the kernel read off the sender's own task, and the executable the kernel
        // read off /proc. A comm alone never earns a demotion.
        let (reason, authorization) = if self_directed {
            (
                "self_termination",
                format!(
                    "the sender and the target are the same process; {}",
                    identity_note(&proc)
                ),
            )
        } else if own_reload {
            (
                "own_reload_path",
                format!(
                    "SIGHUP at Warden's own pid, whose handler reloads the config instead of \
                     stopping the sensor; {}",
                    identity_note(&proc)
                ),
            )
        } else if init_controlled {
            (
                "service_control",
                format!(
                    "sent by pid 1, the service manager that owns this unit's cgroup; {}",
                    identity_note(&proc)
                ),
            )
        } else {
            (
                if effect.stops_the_target() {
                    "unauthorized_signal"
                } else {
                    "inert_signal"
                },
                format!("no authorization basis found; {}", identity_note(&proc)),
            )
        };
        // The backend stores detail values truncated at its own cap; clamping here keeps
        // the sentence whole rather than cut mid-word.
        let authorization: String = authorization.chars().take(500).collect();
        let summary = if self_directed {
            format!(
                "protected pid {} aimed {} at itself via {} — a self-termination, not an outside \
                 takedown",
                e.target_pid,
                signal_name(sig),
                delivery.as_str()
            )
        } else if init_controlled {
            format!(
                "service control: pid 1 ({}) sent {} to protected pid {} via {} — unit teardown, \
                 not an outside takedown",
                proc.comm,
                signal_name(sig),
                e.target_pid,
                delivery.as_str()
            )
        } else if own_reload {
            format!(
                "reload: pid {} ({}) sent {} to Warden's own pid {} via {} — the handler reloads \
                 the config",
                proc.pid,
                proc.comm,
                signal_name(sig),
                e.target_pid,
                delivery.as_str()
            )
        } else if effect.stops_the_target() {
            format!(
                "takedown attempt: pid {} ({}) sent {} to protected pid {} via {}",
                proc.pid,
                proc.comm,
                signal_name(sig),
                e.target_pid,
                delivery.as_str()
            )
        } else {
            format!(
                "control traffic: pid {} ({}) sent {} to protected pid {} via {} — a signal the \
                 kernel would not act on",
                proc.pid,
                proc.comm,
                signal_name(sig),
                e.target_pid,
                delivery.as_str()
            )
        };
        // `endpoint:self_tamper` is the only host slot Sentinel's allowlist accepts for
        // a signal against a protected pid, so every verdict travels inside the record:
        // the severity alone cannot distinguish a crash from a `kill -9`, and a summary
        // alone cannot say who was allowed to send it.
        let detail = serde_json::json!({
            "signal": signal_name(sig),
            "signal_num": sig,
            "target_pid": e.target_pid,
            "delivery": delivery.as_str(),
            "signal_effect": effect.as_str(),
            "reason": reason,
            "authorization": authorization,
        });
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::SelfTamper,
            severity,
            summary,
            detail,
            process: proc,
            target_pid: Some(e.target_pid),
            // The counter-kill stays gated on the five numbers it has always been armed
            // for, and now also refuses the two senders with an authorization basis:
            // nothing here widens what enforcement may do, only what it claims.
            //
            // `!own_reload` is redundant today and kept on purpose: the class is only
            // reachable for SIGHUP, and SIGHUP is not one of the five armed numbers, so
            // no signal can both be a reload request and ask for a kill. It becomes
            // load-bearing the moment W2K-42 widens the list, which is exactly why
            // `the_responders_arm_list_is_exactly_the_five_numbers_it_has_always_been`
            // pins the list rather than leaving it to be noticed later.
            wants_kill: !self_directed
                && !own_reload
                && !init_controlled
                && arming
                && self.cfg.respond.kill_takedown_attacker,
        })
    }

    /// Judge a ptrace of a protected pid. The kernel LSM hook
    /// `security_ptrace_access_check` fires for TWO distinct classes, told apart
    /// solely by the `mode` bits it carries (recorded in `e.aux`):
    ///   * PTRACE_MODE_ATTACH (0x02) — a real attach / inject / cross-process
    ///     memory access: PTRACE_ATTACH, PTRACE_SEIZE, process_vm_readv/writev,
    ///     open(/proc/<pid>/mem). This is the T7/T8 inspect-and-inject signal the
    ///     sensor exists for (in-memory key theft, code injection into the signer).
    ///   * PTRACE_MODE_READ (0x01, no 0x02) — a /proc metadata read:
    ///     /proc/<pid>/maps, environ, fd, stat. fuser/journald/systemd do this
    ///     constantly to attribute files and supervise pids, which is what flooded
    ///     the live journal with 192 benign High "inspection attempt" lines.
    ///
    /// So: an ATTACH always fires High (the headline threat). A pure READ fires
    /// only when the actor is NOT a known benign scanner — then at Medium, because
    /// a READ of the protected process's /proc/<pid>/environ or maps by an unknown
    /// actor is credential-recon worth surfacing, but a lower tier than injection.
    /// Benign scanners (`ptrace_rules.benign_reader_comms`) reading /proc are
    /// silent. The kernel stays a dumb recorder; the mode+actor policy lives here,
    /// mirroring judge_creds (expected_privilege_comms) and judge_bpf (allow_loaders).
    ///
    /// W2K-41 added the third tier, and it is deliberately a demotion rather than a
    /// suppression: a READ whose reader's executable AND cgroup both resolved, with
    /// `[app] cgroup_contains` configured, and which is not inside the application's own
    /// cgroup, records at Info. The record still ships, so a host that turns out to have
    /// been probed can be replayed; what changed is only how loudly it is called. A name
    /// in `benign_reader_comms` buys silence and can be extended by anyone who renames a
    /// binary to `ps`, which is why the tier below needs evidence a process cannot choose.
    fn judge_ptrace(&self, e: &Event) -> Option<Finding> {
        const PTRACE_MODE_ATTACH: u32 = 0x02;
        let is_attach = e.aux & PTRACE_MODE_ATTACH != 0;

        // The guardian supervising the processes it protects is not an intrusion.
        // Only READs are exempt: an ATTACH from our own pid would be a real bug
        // and must still surface.
        if !is_attach && e.actor_pid == self.self_pid {
            return None;
        }
        // W2K-10: same pid-keyed caveat as the signal path — the kernel fires for
        // the *number*, so confirm the number still belongs to a protected
        // process before calling this an inspection attempt.
        if !self.target_is_protected(e.target_pid) {
            return None;
        }
        let proc = self.enrich(e);

        // Read-only /proc introspection is silent for routine readers (scanner
        // daemons walking /proc, the container runtime joining namespaces); any
        // other actor reading the protected process surfaces at Medium as recon.
        if !is_attach && self.benign_reader(&e.comm, proc.exe.as_deref()) {
            return None;
        }

        // W2K-41: a READ is not something to silence by name without a trust argument,
        // but it is not the same event as an ATTACH either. The lowest tier is earned by
        // four facts, each of which the kernel rather than the process supplied: the
        // reader's executable resolved, its cgroup resolved, the operator declared which
        // cgroup is the application, and the reader is NOT inside it. A reader inside the
        // app's own cgroup is the application poking at its neighbour and stays where it
        // was; so does any reader whose identity could not be read, because "unreadable"
        // is not evidence of good behaviour.
        let reader_verified = proc.exe.is_some()
            && proc.cgroup.is_some()
            && !self.cfg.app.cgroup_contains.is_empty()
            && !self.actor_in_app_cgroup(&proc);
        let (reason, note) = if is_attach {
            (
                "ptrace_attach",
                "an attach/inject request is never excused by who sent it",
            )
        } else if reader_verified {
            (
                "verified_external_reader",
                "the reader's executable and cgroup both resolved, and it is not inside the \
                 application's own cgroup",
            )
        } else if proc.exe.is_none() || proc.cgroup.is_none() {
            (
                "unverified_reader",
                "the reader's identity could not be read, which is not evidence of good \
                 behaviour",
            )
        } else if self.actor_in_app_cgroup(&proc) {
            (
                "in_app_reader",
                "the reader sits inside the application's own cgroup",
            )
        } else {
            (
                "app_cgroup_unconfigured",
                "[app] cgroup_contains is empty, so no reader can be shown to be outside the \
                 application",
            )
        };
        let authorization: String = format!("{note}; {}", identity_note(&proc))
            .chars()
            .take(500)
            .collect();
        // The demotion is a READ-only thing. An ATTACH earns High whatever its reader's
        // identity says, and must not be worded as routine observation on the way.
        let routine_read = reader_verified && !is_attach;
        let severity = if is_attach {
            Severity::High
        } else if routine_read {
            Severity::Info
        } else {
            Severity::Medium
        };
        let verb = if is_attach { "attach to" } else { "read" };
        let summary = if routine_read {
            format!(
                "routine observation: pid {} ({}) read protected pid {} through /proc",
                proc.pid, proc.comm, e.target_pid
            )
        } else {
            format!(
                "inspection attempt: pid {} ({}) tried to {} protected pid {}",
                proc.pid, proc.comm, verb, e.target_pid
            )
        };
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::SelfTamper,
            severity,
            summary,
            detail: serde_json::json!({
                "ptrace_mode": e.aux,
                "is_attach": is_attach,
                "target_pid": e.target_pid,
                "reason": reason,
                "authorization": authorization,
            }),
            process: proc,
            target_pid: Some(e.target_pid),
            // Only a real attach is a takedown candidate; a /proc read never kills.
            wants_kill: is_attach && self.cfg.respond.kill_takedown_attacker,
        })
    }

    /// Judge an outbound connect. This is the C2 / reverse-shell dial-out rule:
    /// a request-serving worker that suddenly reaches out to an unlisted host is
    /// the classic post-exploitation beacon. The verdict is entirely policy —
    /// the kernel just told us "the app connected somewhere"; whether *somewhere*
    /// is sanctioned is the allowlist's call.
    ///
    /// Returns None (benign) when: egress is app-only and this actor isn't the
    /// app; or the destination is explicitly allowed (allowlist / port / loopback).
    fn judge_connect(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.network_rules;
        let proc = self.enrich(e);

        // Attribution first: with app_egress_only, a connect that isn't from the
        // app cgroup is someone's shell, not the worker beaconing. If we can't
        // even identify the app (no cgroup configured), egress detection would be
        // all false positives, so we stay silent — exactly as judge_exec does.
        if rules.app_egress_only {
            let have_app_cgroup = !self.cfg.app.cgroup_contains.is_empty();
            if !have_app_cgroup || !self.actor_in_app_cgroup(&proc) {
                return None;
            }
        }

        // The destination the decoder resolved ("ip:port"), plus its parts. An
        // undecodable family left dest = None; we treat that as an un-attributable
        // dial-out worth surfacing rather than dropping (it's the app connecting
        // over a family we don't parse — unusual by itself).
        let dest = e.dest.clone();
        let (ip, port) = match &dest {
            Some(d) => split_ip_port(d),
            None => (None, None),
        };

        // A socket that has not completed `connect()` reports the unspecified
        // address (0.0.0.0 / ::) and often port 0. That is the kernel saying
        // "no peer yet", not a destination, so it is not egress and must not be
        // judged as any. Treating it as one killed `sshd-session` on `[::]:22`
        // (12 times), `sd-resolve` on NTP and `iptables` on boot — 38 SIGKILLs
        // in 3.5 minutes (§113.2). A destination the decoder could not split at
        // all (`dest = None`) is still surfaced below: that shape is unusual by
        // itself and worth seeing.
        if ip.as_deref().is_some_and(is_unspecified_addr) || port == Some(0) {
            return None;
        }

        // Phase 3 → Phase 7: a configured deny rule is a POLICY DECISION, not
        // a per-connection kernel disposition. The cgroup hook is optional and
        // off by default; even when it is attached, this connect record is an
        // observation, not a denial record from the hook, so `kernel_denied`
        // is deliberately false here. Network deny and process termination
        // stay separate responses: the finding never acquires kill intent
        // from a policy match alone.
        if let Some(d) = &dest {
            let bare = ip.as_deref().unwrap_or("");
            let denied = rules
                .deny_destinations
                .iter()
                .any(|x| x == d || (!bare.is_empty() && x == bare));
            if denied {
                let decision = match self.egress_preflight.get() {
                    Some(proof) => {
                        crate::policy::DenyDecision::verified(self.cfg.mode, proof, false)
                    }
                    None => crate::policy::DenyDecision::observe_only(self.cfg.mode),
                };
                debug_assert!(
                    decision.is_honest(),
                    "a policy decision must never claim enforcement"
                );
                return Some(Finding {
                    source_ts_ns: 0,
                    event_type: FindingType::NetworkConnect,
                    severity: Severity::Critical,
                    summary: format!(
                        "policy DENY (not enforced): pid {} ({}) dialed forbidden destination {}; \
                         traffic was NOT blocked",
                        proc.pid, proc.comm, d
                    ),
                    detail: serde_json::json!({
                        "reason": "egress_denied_by_policy",
                        "policy_decision": decision,
                        "destination": dest,
                        "dest_ip": ip,
                        "dest_port": port,
                        // Deliberately no `protocol` field here: the egress and
                        // listener findings own that ABI slot (pinned by
                        // tests/network_abi.rs). A policy finding needs only the
                        // destination and the honest decision annotation.
                    }),
                    process: proc,
                    target_pid: None,
                    wants_kill: false,
                });
            }
        }

        // Allow rules, cheapest first.
        if let Some(p) = port {
            if rules.allow_ports.contains(&p) {
                return None;
            }
        }
        if rules.allow_loopback {
            if let Some(ip) = &ip {
                if is_loopback(ip) {
                    return None;
                }
            }
        }
        if let Some(d) = &dest {
            // Match against the full "ip:port" and the bare ip — an operator may
            // list either "10.0.0.5:443" or "10.0.0.5".
            let bare = ip.as_deref().unwrap_or("");
            if rules
                .egress_allow
                .iter()
                .any(|allowed| allowed == d || (!bare.is_empty() && allowed == bare))
            {
                return None;
            }
        }

        // Phase 4: only unsanctioned, attributable dials reach this point —
        // allowlisted traffic never poisons the behavioural history. Feed this
        // CONNECT to the bounded beacon tracker and, when the evidence clears
        // its minimum, return the confidence-bearing C2 finding INSTEAD of the
        // generic egress finding so one dial never produces two records.
        if let Some(bare_ip) = ip.as_deref() {
            let sample = ConnectSample {
                ts_ns: e.ts_ns,
                pid: proc.pid,
                starttime: proc.starttime,
                destination: bare_ip.to_string(),
                port,
            };
            let assessment = self
                .c2
                .borrow_mut()
                .observe(&sample, self.c2_ring_loss.get());
            if let Some(a) = assessment {
                let severity = match a.confidence_label {
                    crate::c2::ConfidenceLabel::Low => Severity::Low,
                    crate::c2::ConfidenceLabel::Medium => Severity::Medium,
                    crate::c2::ConfidenceLabel::High => Severity::High,
                };
                return Some(Finding {
                    source_ts_ns: 0,
                    event_type: FindingType::C2Beaconing,
                    severity,
                    summary: format!(
                        "possible local C2 beaconing: pid {} ({}) dialed {} {} time(s) on a \
                         {} cadence (median {:.1}s over {}, confidence {:.2}, {}); traffic was \
                         NOT blocked",
                        proc.pid,
                        proc.comm,
                        bare_ip,
                        a.dial_count,
                        a.pattern.replace('_', " "),
                        a.median_interval_secs,
                        a.interval_statistics_population.replace('_', " "),
                        a.confidence,
                        a.confidence_label.as_str(),
                    ),
                    detail: serde_json::to_value(&a)
                        .unwrap_or_else(|_| serde_json::json!({"detector": "local_beaconing_v1"})),
                    process: proc,
                    target_pid: None,
                    wants_kill: false,
                });
            }
        }

        let where_to = dest
            .clone()
            .unwrap_or_else(|| "an undecoded address".into());
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::NetworkConnect,
            severity: Severity::High,
            summary: format!(
                "unsanctioned egress: pid {} ({}) dialed out to {}",
                proc.pid, proc.comm, where_to
            ),
            detail: serde_json::json!({
                "reason": "egress_not_allowlisted",
                "destination": dest,
                "dest_ip": ip,
                "dest_port": port,
                // The transport the socket carried, stamped by the hook from
                // `sk_protocol`. Null means the record carried no claim (an object
                // predating the field, or a raw socket whose protocol byte is 0) —
                // never guess it, because a policy match on an invented transport
                // reads as evidence.
                "protocol": e.protocol.map(Protocol::as_str),
                "in_app_cgroup": self.actor_in_app_cgroup(&proc),
            }),
            process: proc,
            target_pid: None,
            wants_kill: self.cfg.respond.kill_reverse_shell,
        })
    }

    /// Judge a privilege change. The kernel already filtered to genuine RAISES
    /// (euid crossing into root, or newly-effective capabilities); this decides
    /// whether *this* raise, by *this* actor, is an incident or the box's normal
    /// setuid plumbing.
    ///
    /// Returns None (benign) when: privesc detection is app-scoped and this actor
    /// isn't the app (or we can't attribute — same silence as exec/connect); the
    /// actor is one of the expected privilege daemons (`sudo`/`sshd`/…) whose job
    /// is to change credentials; or the raise is a pure capability gain and
    /// capability-gain flagging is disabled.
    ///
    /// A web worker turning into root is the textbook post-exploitation step, so
    /// an unexplained root transition inside the app is Critical; a capability
    /// gain without full root is High.
    fn judge_creds(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.cred_rules;
        let proc = self.enrich(e);

        // The transition, folded out of the wire slots during decode. A CREDS
        // event without it is malformed — decline rather than guess.
        let change = e.creds.as_ref()?;

        // Attribution first, mirroring judge_connect: with app_privesc_only, a
        // raise that isn't from the app cgroup is someone's login, not the worker
        // being pivoted. If we can't identify the app at all, every `sudo` on the
        // box would be a false positive, so we stay silent.
        if rules.app_privesc_only {
            let have_app_cgroup = !self.cfg.app.cgroup_contains.is_empty();
            if !have_app_cgroup || !self.actor_in_app_cgroup(&proc) {
                return None;
            }
        }

        // The setuid plumbing of a normal login changes credentials as its whole
        // purpose; a raise attributed to one of those comms is expected, even in
        // the app cgroup. An exploit almost never routes its escalation through
        // `sudo`, so suppressing these narrows noise, not coverage.
        //
        // W2K-30a: `comm` is a string the process gave itself with
        // `prctl(PR_SET_NAME)`, so it is evidence of identity only when the
        // executable we read is the binary that name belongs to. Matching on the
        // name alone let any attacker escalate, call their process `sudo`, and be
        // silent. So: `expected_privilege_exes` (paths the operator pinned) is the
        // strongest answer; the name agreeing with the readable path is the
        // configured-free one; and where no exe could be read the name still
        // carries the raise, which is the weaker posture `--check` names.
        let exe = proc.exe.as_deref();
        let comm_expected = rules.expected_privilege_comms.iter().any(|c| c == &e.comm);
        let exe_pinned = exe.is_some_and(|path| {
            rules
                .expected_privilege_exes
                .iter()
                .any(|allowed| allowed == exe_identity(path))
        });
        if exe_pinned || (comm_expected && name_agrees_with_exe(&e.comm, exe)) {
            return None;
        }
        // The shape the old rule swallowed: an expected name worn by a binary that
        // is not that name's program.
        let name_spoofed = comm_expected && exe.is_some();

        let became_root = change.to_root();
        let gained = change.gained_caps();

        // A pure capability gain (no root transition) is only a finding when the
        // operator opted into capability-gain flagging. The case is named rather
        // than inlined: clippy's nonminimal_bool rule (gated in CI) rejects the
        // negated-conjunction spelling of this same test.
        let cap_gain_flagged = gained != 0 && rules.flag_capability_gain;
        if !became_root && !cap_gain_flagged {
            return None;
        }

        let gained_names = cap_names(gained);
        let (severity, summary) = if became_root {
            (
                Severity::Critical,
                format!(
                    "privilege escalation: pid {} ({}) became root inside the application",
                    proc.pid, proc.comm
                ),
            )
        } else {
            (
                Severity::High,
                format!(
                    "capability escalation: pid {} ({}) gained {} inside the application",
                    proc.pid,
                    proc.comm,
                    if gained_names.is_empty() {
                        "new capabilities"
                    } else {
                        &gained_names
                    }
                ),
            )
        };
        // "sudo became root" reads very differently once the binary behind the name
        // is shown, and the name is the part the operator was relying on.
        let summary = if name_spoofed {
            format!(
                "{summary} — its comm is {:?}, which is on the expected-privilege list, \
                 but its executable is {}",
                e.comm,
                exe.unwrap_or_default()
            )
        } else {
            summary
        };

        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::PrivilegeChange,
            severity,
            summary,
            detail: serde_json::json!({
                "reason": if became_root { "uid_to_root" } else { "capability_gain" },
                "old_uid": change.old_uid,
                "new_uid": change.new_uid,
                "gained_caps": gained_names,
                "cap_old": format!("{:#018x}", change.cap_old),
                "cap_new": format!("{:#018x}", change.cap_new),
                "in_app_cgroup": self.actor_in_app_cgroup(&proc),
                "comm_expected": comm_expected,
                "name_spoofed": name_spoofed,
                "actor_exe": exe,
                "how_to_authorize": if name_spoofed {
                    "pin this program's absolute executable path in \
                     [cred_rules].expected_privilege_exes — its comm is settable by \
                     the process itself"
                } else {
                    ""
                },
            }),
            process: proc,
            target_pid: None,
            wants_kill: self.cfg.respond.kill_privilege_escalation,
        })
    }

    /// Judge a kernel-module load. A module runs in ring 0 with total authority —
    /// the classic rootkit vector — so on a locked-down host every runtime load is
    /// interesting. This is a pure allowlist decision, mirroring egress: the
    /// kernel told us "a module named X loaded"; whether X is sanctioned is the
    /// operator's list to answer.
    ///
    /// Returns None (benign) only when the module name is explicitly allowlisted.
    /// Unlike the process-attributed sensors there is no cgroup narrowing: a
    /// module load is a host-global event with no meaningful "app" actor, so the
    /// allowlist is the whole gate. A non-allowlisted load is a finding at the
    /// configured severity (default Critical).
    fn judge_module(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.module_rules;
        let proc = self.enrich(e);
        // The module name rode in on `filename` (best-effort from the tracepoint);
        // the kernel taint flags (mod->taints, standard TAINT_* bit positions)
        // rode in on `aux`.
        let module = e.filename.clone();

        // TAINT_OUT_OF_TREE (bit 12) and TAINT_UNSIGNED_MODULE (bit 13): a stock
        // in-tree signed module carries NEITHER (taints==0), whereas essentially
        // every LKM rootkit / implant .ko is out-of-tree and unsigned. So the name
        // allowlist is honoured ONLY for an untainted module — a hostile .ko that
        // spoofs an allowlisted module name (e.g. names itself "wireguard") still
        // fires, because it carries the out-of-tree/unsigned taint the real module
        // does not. This closes the name-spoof hole a bare name allowlist leaves.
        const TAINT_OUT_OF_TREE: u32 = 1 << 12;
        const TAINT_UNSIGNED_MODULE: u32 = 1 << 13;
        let is_tainted = e.aux & (TAINT_OUT_OF_TREE | TAINT_UNSIGNED_MODULE) != 0;

        if !module.is_empty() && !is_tainted && rules.allow_modules.iter().any(|m| m == &module) {
            return None;
        }

        let severity = parse_severity(&rules.severity).unwrap_or(Severity::Critical);
        let shown = if module.is_empty() {
            "an unnamed module".to_string()
        } else {
            module.clone()
        };

        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::ModuleLoad,
            severity,
            summary: format!(
                "kernel module loaded: pid {} ({}) loaded {} at runtime",
                proc.pid, proc.comm, shown
            ),
            detail: serde_json::json!({
                "reason": if is_tainted && rules.allow_modules.iter().any(|m| m == &module) {
                    "allowlisted_name_but_tainted"
                } else {
                    "module_not_allowlisted"
                },
                "module": module,
                "taints": e.aux,
                "tainted_out_of_tree_or_unsigned": is_tainted,
            }),
            process: proc,
            target_pid: None,
            // No auto-kill: by the time a module is loaded the damage is in-kernel,
            // and killing the loader process doesn't unload it. This is a report-only
            // class; response is an operator's off-box decision.
            wants_kill: false,
        })
    }

    /// Judge a destructive file operation (rename / unlink). Three rules, most to
    /// least specific, over the affected leaf name the kernel captured:
    ///
    /// 1. **Watched name** — a rename/unlink touching an operator-marked sensitive
    ///    name (a keystore, `.env`, an audit log). This is a targeted-tamper signal
    ///    and fires for ANY actor, ignoring the app-cgroup narrowing: destroying the
    ///    crown jewels matters whoever does it. Critical.
    /// 2. **Ransom extension** — a rename INTO a known encryptor marker
    ///    (`report.docx` → `report.docx.locked`). High-confidence single-event
    ///    conviction. Critical.
    /// 3. **Modification burst** — one actor performing `burst_threshold`
    ///    destructive ops within `burst_window_secs`, the behavioural signature of
    ///    an encryptor churning a directory even when its extension isn't known.
    ///    Critical, and the one file rule that (optionally) kills.
    ///
    /// Rules 2 and 3 are subject to app-cgroup attribution (like exec/egress): a
    /// package manager or a build legitimately churns files, so box-wide they'd be
    /// noise. Rule 1 is not — a watched-name hit is always surfaced.
    ///
    /// Returns None when nothing matches (the common case: a routine rename/unlink).
    fn judge_file(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.file_rules;
        let op = FileOp::from_u32(e.aux);
        let name = e.filename.clone();
        let name_l = name.to_ascii_lowercase();

        // Rule 1: a watched sensitive name, for ANY actor. Substring match so an
        // operator can list "shadow" and catch "/etc/shadow"'s leaf "shadow".
        let watched = !name.is_empty()
            && rules
                .watch_names
                .iter()
                .any(|w| name_l.contains(&w.to_ascii_lowercase()));

        if watched {
            let proc = self.enrich(e);
            let op_str = op.map(|o| o.as_str()).unwrap_or("modify");
            return Some(Finding {
                source_ts_ns: 0,
                event_type: FindingType::FileTamper,
                severity: Severity::Critical,
                summary: format!(
                    "sensitive-file tamper: pid {} ({}) {}d watched file {}",
                    proc.pid, proc.comm, op_str, name
                ),
                detail: serde_json::json!({
                    "reason": "watched_name",
                    "operation": op_str,
                    "filename": name,
                    "in_app_cgroup": self.actor_in_app_cgroup(&proc),
                }),
                process: proc,
                target_pid: None,
                wants_kill: self.cfg.respond.kill_ransomware,
            });
        }

        // Rules 2 & 3 are app-attributed. With app_files_only and no identifiable
        // app cgroup, we can't tell an encryptor from a build, so we stay silent —
        // exactly as exec/connect/creds do.
        if rules.app_files_only {
            let proc = self.enrich(e);
            let have_app_cgroup = !self.cfg.app.cgroup_contains.is_empty();
            if !have_app_cgroup || !self.actor_in_app_cgroup(&proc) {
                return None;
            }
        }

        // Rule 2: a rename INTO a known ransom extension/suffix.
        if op == Some(FileOp::Rename) && !name.is_empty() {
            if let Some(ext) = rules
                .ransom_extensions
                .iter()
                .find(|ext| name_l.ends_with(&ext.to_ascii_lowercase()))
            {
                let proc = self.enrich(e);
                return Some(Finding {
                    source_ts_ns: 0,
                    event_type: FindingType::FileTamper,
                    severity: Severity::Critical,
                    summary: format!(
                        "ransomware marker: pid {} ({}) renamed a file to {}",
                        proc.pid, proc.comm, name
                    ),
                    detail: serde_json::json!({
                        "reason": "ransom_extension",
                        "operation": "rename",
                        "filename": name,
                        "matched_extension": ext,
                        "in_app_cgroup": self.actor_in_app_cgroup(&proc),
                    }),
                    process: proc,
                    target_pid: None,
                    wants_kill: self.cfg.respond.kill_ransomware,
                });
            }
        }

        // Rule 3: the behavioural burst. Record this op in the actor's window and
        // see whether the count over the last `burst_window_secs` crosses the
        // threshold. Threshold 0 disables the rule entirely.
        if rules.burst_threshold > 0 {
            let count = self.record_and_count_burst(e.actor_pid, e.ts_ns, rules.burst_window_secs);
            if count >= rules.burst_threshold as usize {
                let proc = self.enrich(e);
                return Some(Finding {
                    source_ts_ns: 0,
                    event_type: FindingType::FileTamper,
                    severity: Severity::Critical,
                    summary: format!(
                        "mass file modification: pid {} ({}) performed {} destructive file ops in {}s",
                        proc.pid, proc.comm, count, rules.burst_window_secs
                    ),
                    detail: serde_json::json!({
                        "reason": "modification_burst",
                        "operation": op.map(|o| o.as_str()).unwrap_or("modify"),
                        "ops_in_window": count,
                        "window_secs": rules.burst_window_secs,
                        "last_filename": name,
                        "in_app_cgroup": self.actor_in_app_cgroup(&proc),
                    }),
                    process: proc,
                    target_pid: None,
                    wants_kill: self.cfg.respond.kill_ransomware,
                });
            }
        }

        None
    }

    /// Judge a persistence-create event. A file appeared in a boot/login-survival
    /// directory — a rogue systemd unit, a cron entry, an autostart .desktop, a
    /// line added by creating `authorized_keys`, an `ld.so.preload`. The kernel
    /// captured the created file's trailing path (leaf + up to three ancestors);
    /// the verdict is a directory allowlist, exactly parallel to `judge_module`'s
    /// module allowlist:
    ///
    /// - If the path matches nothing in `persistence_dirs`, it isn't a persistence
    ///   location we watch — silent (the overwhelming common case: every ordinary
    ///   file create on the box passes through here).
    /// - If it IS under a persistence dir but its path is on `allow_paths` (a unit
    ///   your own provisioning lays down), it's sanctioned — silent.
    /// - Otherwise it's an un-sanctioned write into a persistence location — a
    ///   finding at the configured severity (default Critical).
    ///
    /// Like a watched-name file tamper, this fires for ANY actor and ignores the
    /// app-cgroup narrowing: a foothold planted in `/etc/systemd/system` is an
    /// incident whoever wrote it (an admin's own hardening excepted via
    /// `allow_paths`), and unlike egress there is no "normal app behaviour" that
    /// legitimately drops files there at runtime. Report-only (`wants_kill:false`):
    /// the artifact is already on disk and killing the writer doesn't remove it —
    /// removal/quarantine is an operator's off-box decision.
    fn judge_service(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.service_rules;
        // The created file's rebuilt trailing path (leaf + ancestors) rode in on
        // `filename`; an empty path means every ladder read failed — treat it as
        // unattributable and stay silent rather than guess.
        let path = e.filename.clone();
        if path.is_empty() {
            return None;
        }
        let path_l = path.to_ascii_lowercase();

        // Not under any watched persistence directory ⇒ an ordinary create.
        // Component-boundary match (not raw substring): the xdg-autostart
        // generator writes `app-<id>@autostart.service`, whose LEAF contains the
        // token "autostart" mid-filename while the directory is `generator.late` —
        // raw `contains("autostart")` fired on it every login. `persistence_match`
        // requires the pattern to begin at a component boundary, so a real
        // `~/.config/autostart/evil.desktop` (autostart is a real dir) still fires
        // while the generator leaf does not. Prefix-of-component is preserved so
        // "cron" still catches "cron.d" and "ld.so.conf" catches "ld.so.conf.d".
        let in_persistence_dir = rules
            .persistence_dirs
            .iter()
            .any(|d| persistence_match(&path_l, &d.to_ascii_lowercase()));
        if !in_persistence_dir {
            return None;
        }

        // Under a persistence dir, but explicitly sanctioned ⇒ silent. Matched by
        // ANCHORED path prefix (has_path_prefix), NOT boundary-anywhere: an
        // allow_paths entry must name a full path or a directory prefix the
        // attacker cannot reproduce (e.g. "/etc/systemd/system/warden.service").
        // A leaf-fragment token like "snap." must NOT be honoured here, or an
        // attacker who names their rogue unit `/etc/systemd/system/snap.evil.service`
        // would be silently allowlisted — snapd must be quieted by writer
        // provenance, never by a forgeable filename substring.
        if rules
            .allow_paths
            .iter()
            .any(|p| has_path_prefix(&path_l, &p.to_ascii_lowercase()))
        {
            return None;
        }

        let proc = self.enrich(e);
        let severity = parse_severity(&rules.severity).unwrap_or(Severity::Critical);
        // The kernel stamps which create chokepoint fired in `aux`; render it the
        // same way `judge_file` renders its FileOp, rather than assuming "create".
        let op_str = ServiceOp::from_u32(e.aux)
            .map(|o| o.as_str())
            .unwrap_or("create");
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::NewService,
            severity,
            summary: format!(
                "persistence artifact created: pid {} ({}) wrote {} into a boot/login-survival location",
                proc.pid, proc.comm, path
            ),
            detail: serde_json::json!({
                "reason": "persistence_dir",
                "operation": op_str,
                "path": path,
                "in_app_cgroup": self.actor_in_app_cgroup(&proc),
            }),
            process: proc,
            target_pid: None,
            wants_kill: false,
        })
    }

    /// Judge a listen-socket event. The dual of egress: instead of the app
    /// dialing *out* to a C2, something on the box opened a port and is waiting
    /// for the attacker to dial *in* — a bind shell, a planted sshd on an odd
    /// port, a webshell helper. The kernel told us "a socket entered LISTEN on
    /// this local endpoint"; whether that listener is sanctioned is the
    /// allowlist's call, exactly mirroring `judge_connect`.
    ///
    /// Returns None (benign) when: listener detection is app-scoped and this actor
    /// isn't the app (or we can't attribute — same silence as connect); the bound
    /// port is on `allow_ports` (the app's own service ports); or the bind is to a
    /// loopback address and loopback listeners are allowed (a local-only helper).
    fn judge_listen(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.listen_rules;
        let proc = self.enrich(e);

        // Attribution first, mirroring judge_connect. A listener opened outside
        // the app cgroup is someone's own service, not the worker being
        // backdoored; and with no identifiable app cgroup every sshd/systemd
        // socket would be a false positive, so we stay silent.
        if rules.app_listen_only {
            let have_app_cgroup = !self.cfg.app.cgroup_contains.is_empty();
            if !have_app_cgroup || !self.actor_in_app_cgroup(&proc) {
                return None;
            }
        }

        let endpoint = e.dest.clone();
        let (ip, port) = match &endpoint {
            Some(d) => split_ip_port(d),
            None => (None, None),
        };

        // A sanctioned service port (the app's own 8000/8443/…) is silent.
        if let Some(p) = port {
            if rules.allow_ports.contains(&p) {
                return None;
            }
        }
        // A loopback-only listener is ordinary local plumbing when allowed — it is
        // not reachable from off-box, so it cannot be an inbound backdoor.
        if rules.allow_loopback {
            if let Some(ip) = &ip {
                if is_loopback(ip) {
                    return None;
                }
            }
        }

        let where_at = endpoint
            .clone()
            .unwrap_or_else(|| "an undecoded address".into());
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::ListenBackdoor,
            severity: Severity::High,
            summary: format!(
                "unexpected listener: pid {} ({}) began listening on {}",
                proc.pid, proc.comm, where_at
            ),
            detail: serde_json::json!({
                "reason": "listener_not_allowlisted",
                "endpoint": endpoint,
                "bind_ip": ip,
                "bind_port": port,
                // A listener's transport, read from the socket rather than assumed
                // from `listen(2)`'s contract. Null = no claim, same rule as egress.
                "protocol": e.protocol.map(Protocol::as_str),
                "in_app_cgroup": self.actor_in_app_cgroup(&proc),
            }),
            process: proc,
            target_pid: None,
            // A bind shell is a live inbound channel; killing the listener process
            // closes it, so this is opt-in killable like a reverse shell.
            wants_kill: self.cfg.respond.kill_reverse_shell,
        })
    }

    /// Judge a BPF program load. eBPF is itself an implant vector — a loaded
    /// program can hide processes, tamper with syscall returns, and mask its own
    /// presence, all in-kernel and without a module (so `judge_module` never sees
    /// it). But the init system, systemd-networkd, and container runtimes load
    /// BENIGN programs constantly — cgroup resource filters, socket filters — and
    /// those cannot hook a syscall or hide anything. A bare "a BPF program was
    /// loaded" therefore fires on every service start (pid 1 alone trips it dozens
    /// of times a boot). So the verdict is TWO gates, most-discriminating first:
    /// the program *type* must be one of the implant-capable kinds
    /// (`watch_prog_types` — kprobe/tracepoint/xdp/lsm/…), AND the loader's comm
    /// must not be on `allow_loaders`. A benign cgroup_skb load is silent whoever
    /// loads it; a kprobe-program load by an unknown loader is the finding.
    ///
    /// Returns None (benign) when: the program type is not implant-capable (the
    /// systemd/runtime case), or the loader is AUTHORISED — which since W2K-18 means
    /// its `/proc/<pid>/exe` is on `allow_loader_exes`. `allow_loaders` is a comm, a
    /// string the process chose for itself, so it authorises only where no exe list is
    /// configured at all and where the exe could not be read. An empty
    /// `watch_prog_types` disables the type gate — every unauthorised load fires
    /// (maximally paranoid). A type we couldn't read (UNSPEC/0) is treated as unknown
    /// and does NOT suppress. There is no cgroup narrowing: an in-kernel implant is a
    /// host-global event. A conviction is a finding at the configured severity
    /// (default Critical), report-only — the program is already installed and killing
    /// the loader doesn't detach it.
    fn judge_bpf(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.bpf_rules;

        // Type gate first — the discriminator that separates a rootkit hook from
        // the resource filters the init system loads all day. An empty watch list
        // disables the gate (every load is candidate). A type of 0 (UNSPEC, e.g.
        // an unreadable attr) is "unknown" and falls through — fail toward
        // surfacing rather than silently trusting an unreadable load.
        if !rules.watch_prog_types.is_empty() {
            let prog_type = e.bpf_prog_type.unwrap_or(0);
            let implant_capable = prog_type == 0 || rules.watch_prog_types.contains(&prog_type);
            if !implant_capable {
                return None;
            }
        }

        let proc = self.enrich(e);

        // W2K-18: a comm is not an identity. `prctl(PR_SET_NAME)` sets it from inside
        // any process, so a loader that called itself "warden" used to be permitted to
        // install an implant-capable program by the only check this line made. The
        // executable path is what authorises now. The name list still carries a load
        // whose `/proc/<pid>/exe` could not be read — the process already exited, which
        // is the normal shape for a short-lived loader and the weaker posture the
        // finding's `authorization` field names.
        let exe = proc.exe.as_deref().map(exe_identity);
        let exe_authorised =
            exe.is_some_and(|path| rules.allow_loader_exes.iter().any(|a| a == path));
        if exe_authorised {
            return None;
        }
        let name_allowed = rules.allow_loaders.iter().any(|l| l == &e.comm);
        let identity_unreadable = exe.is_none();
        // W2K-29's residual, answered by the kernel: `/proc/<pid>/exe` needs the task
        // to still be there when userspace looks, and a loader that exits first is the
        // NORMAL case, not an anomaly. The hook cannot be too late for that — the
        // record it wrote names the file that was running (`fill_exe_inode`), so the
        // comparison below is between two facts about the same inode rather than
        // between a name and a hope. It is consulted only when the path is unreadable,
        // so the stats are never on a path that already has its answer.
        let kernel_exe = identity_unreadable.then_some(e.actor_exe_file).flatten();
        let inode_verdict =
            kernel_exe.map(|id| inode_matches_any_path(id, &rules.allow_loader_exes));
        // Three answers, and the middle one is deliberately not a pass: Some(true) =
        // the kernel-named file IS one of the authorized paths; Some(false) = it is
        // provably not; None = nothing was configured (or nothing configured could be
        // stat()ed), so there is no basis to compare against and the weaker evidence
        // below still decides. `allow_loader_exes` is empty by default, so a host that
        // has pinned nothing keeps exactly the posture it had before this field.
        if matches!(inode_verdict, Some(Some(true))) {
            return None;
        }
        let kernel_named_the_stranger = matches!(inode_verdict, Some(Some(false)));
        // W2K-29: the name is the *last* evidence left when the executable could not
        // be read, and the two ways to be unreadable are not equally reassuring. A
        // loader that already exited cannot be named by anyone, and exiting before
        // userspace enriches the record is the normal shape of a short-lived loader —
        // so the name carries that load, and `--check` says the posture is weak. A
        // loader still sitting at that pid is a different story: it is alive, its
        // binary is not on the authorised list, and the only thing standing between it
        // and a silent implant-capable program is a name it chose for itself. That is
        // not a pass. The kernel's pid table answers "is it alive" without `/proc`, so
        // a `hidepid=` mount cannot make a live loader look like an exited one (the
        // same corroboration W2K-39 uses on the kill path).
        // And since this stage the name is no longer the last evidence at all: when
        // the kernel named the file and the file is not authorised, an allowlisted
        // `comm` does not get to clear the load.
        let loader_live = name_allowed && identity_unreadable && self.loader_is_live(e.actor_pid);
        if name_allowed && identity_unreadable && !loader_live && !kernel_named_the_stranger {
            return None;
        }

        let severity = parse_severity(&rules.severity).unwrap_or(Severity::Critical);
        // The load the name list would once have swallowed: an allowlisted comm, an
        // executable that is not on the authorised list. The answer is a path, not a
        // name, so the finding says which path it looked at and what to pin.
        let name_matched_exe_is_not = name_allowed && !identity_unreadable;
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::BpfLoad,
            severity,
            summary: format!(
                "bpf program loaded: pid {} ({}) loaded an eBPF program at runtime{}",
                proc.pid,
                proc.comm,
                match exe {
                    Some(path) => format!(" from {path}"),
                    None if kernel_named_the_stranger => format!(
                        " from a file the kernel named ({}) that no allow_loader_exes path is",
                        kernel_exe.map(|id| id.label()).unwrap_or_default()
                    ),
                    None if loader_live => {
                        " (executable unreadable, and the loader is STILL RUNNING)".to_string()
                    }
                    None => " (executable unreadable)".to_string(),
                }
            ),
            detail: serde_json::json!({
                "reason": if name_matched_exe_is_not {
                    "bpf_loader_comm_allowlisted_exe_not_authorized"
                } else if kernel_named_the_stranger {
                    "bpf_loader_kernel_named_exe_not_authorized"
                } else if loader_live {
                    "bpf_loader_comm_allowlisted_loader_live_exe_unreadable"
                } else {
                    "bpf_loader_not_allowlisted"
                },
                "bpf_cmd": e.aux,
                "prog_type": e.bpf_prog_type,
                "prog_type_name": e.bpf_prog_type.map(bpf_prog_type_name),
                "loader_exe": exe,
                // Stamped by the hook, so they describe the loader even where
                // `loader_exe` is null. Kernel `kdev_t` encoding (major<<20|minor),
                // the same form the guarded-inode keys use.
                "loader_exe_dev": kernel_exe.map(|id| id.dev),
                "loader_exe_ino": kernel_exe.map(|id| id.ino),
                "comm_allowlisted": name_allowed,
                "loader_alive": loader_live,
                "authorization": if !identity_unreadable {
                    "executable path (allow_loader_exes)"
                } else if kernel_named_the_stranger {
                    "kernel-captured executable file (dev/ino of mm->exe_file at load time)"
                } else if kernel_exe.is_some() {
                    "kernel-captured executable file, compared against nothing: no \
                     allow_loader_exes path could be stat()ed"
                } else {
                    "name-only: the executable could not be read"
                },
                "how_to_authorize": if name_matched_exe_is_not {
                    "add this loader's absolute executable path to \
                     [bpf_rules].allow_loader_exes — its comm is settable by the process itself"
                } else if kernel_named_the_stranger {
                    "the kernel recorded WHICH file ran (loader_exe_dev/loader_exe_ino above) \
                     and it is not the file any [bpf_rules].allow_loader_exes path names: find \
                     the real path with `find / -xdev -inum <ino>`, pin that, or read the load \
                     as unauthorised — a comm cannot clear a load whose file is known"
                } else if loader_live {
                    "this loader is alive and its /proc/<pid>/exe could not be read: read it \
                     as root, or find the process by pid and inspect it — an allowlisted comm \
                     authorises a load only when the loader has already exited"
                } else {
                    ""
                },
            }),
            process: proc,
            target_pid: None,
            // Report-only: the program is already installed in the kernel and
            // killing the loader process does not detach it. Removal is an
            // operator's off-box decision, exactly like a module load.
            wants_kill: false,
        })
    }

    /// Judge a mount. A mount is how a contained attacker breaks containment:
    /// bind-mounting the host root or a host device tree into a container, or
    /// exposing the container-runtime socket. The kernel told us "a filesystem was
    /// mounted from source S with flags F"; the verdict is an operator allowlist
    /// over the mount source, mirroring the module/service allowlists.
    ///
    /// The escape signature for these host-path sources is specifically a BIND
    /// mount (MS_BIND) grafting an existing host path into a new location — a plain
    /// filesystem mount's source is a block device (`/dev/sdb1`) or an fs token
    /// (`tmpfs`), which is routine admin work and must not fire. So by default only
    /// bind mounts are judged (`bind_only`); flip it off to police every mount of a
    /// watched source on a host where no runtime mounts are expected at all.
    ///
    /// Returns None (benign) when: `bind_only` is set and this is not a bind mount;
    /// the source is empty (a virtual fs / remount — not the escape shape); the
    /// source is under a sandbox-construction root (`ignore_source_prefixes` —
    /// bwrap/flatpak/polkit namespace assembly, NOT a host escape); the source
    /// matches nothing in `watch_sources` by path component; or it is on
    /// `allow_sources`. A watched, non-allowlisted bind mount is a finding at the
    /// configured severity (default High) — report-only, since the mount has
    /// already taken effect. Like a persistence write it fires for ANY actor: a
    /// bind mount of the host root is an incident whoever performed it.
    fn judge_mount(&self, e: &Event) -> Option<Finding> {
        let rules = &self.cfg.mount_rules;
        let proc = self.enrich(e);

        // MS_BIND (0x1000) is the escape tell — a bind mount grafts an existing
        // host path into a new location. A non-bind mount's source is a device,
        // which is ordinary, so under the default `bind_only` we ignore it.
        const MS_BIND: u32 = 4096;
        let is_bind = e.aux & MS_BIND != 0;
        if rules.bind_only && !is_bind {
            return None;
        }

        // The mount source (device / bind path) rode in on `filename`; an empty
        // source (a virtual fs or a remount) is not the escape shape we police.
        let source = e.filename.clone();
        if source.is_empty() {
            return None;
        }
        let source_l = source.to_ascii_lowercase();

        // Sandbox / namespace construction is not a host escape. A desktop sandbox
        // (bwrap, flatpak, the polkit agent) assembles its mount namespace under a
        // private staging root — /oldroot/dev/null, /proc/self/fd/7, /run/user/… —
        // whose sources CONTAIN "/dev" or "/proc" as a substring but are internals.
        // Reject anything under such a prefix up front, at a path-component
        // boundary (so a real "/proc" host bind is NOT swallowed). This is what
        // stops the polkit-agent / bwrap false-positive storm at the source.
        //
        // W2K-05: that same literal prefix is camouflage. mount(2) resolves
        // "/proc/self/fd/N" through the CALLER's fd table, so a contained actor can
        // bind an arbitrary host path while the recorded source looks like sandbox
        // plumbing. The exemption therefore holds only for actors OUTSIDE the app
        // cgroup (the desktop namespace builders); for a contained actor the source
        // is resolved through that actor's /proc and the REAL target is judged. An
        // unresolvable fd/root/cwd indirection fires as `mount_source_unresolved`
        // — closing the race where the fd is closed right after mount(2) — while
        // staging roots (/oldroot, /run/user/…) that cannot name a host path stay
        // silent, so no new storm is created for sandbox construction.
        let in_app_cgroup = self.actor_in_app_cgroup(&proc);
        let mut resolved_indirection: Option<String> = None;
        let mut indirection_reason: Option<&'static str> = None;
        let prefix_exempt = rules
            .ignore_source_prefixes
            .iter()
            .any(|p| has_path_prefix(&source_l, &p.to_ascii_lowercase()));
        if prefix_exempt {
            if !in_app_cgroup {
                return None;
            }
            match resolve_through_actor(e.actor_pid, &source) {
                Some(resolved) => {
                    let resolved_l = resolved.to_ascii_lowercase();
                    let hits_watch = rules
                        .watch_sources
                        .iter()
                        .any(|s| watch_overlaps_source(&resolved_l, &s.to_ascii_lowercase()));
                    let hits_allow = rules
                        .allow_sources
                        .iter()
                        .any(|s| watch_overlaps_source(&resolved_l, &s.to_ascii_lowercase()));
                    if hits_watch && !hits_allow {
                        indirection_reason = Some("mount_source_indirection");
                        resolved_indirection = Some(resolved);
                    } else {
                        return None;
                    }
                }
                None if is_proc_indirection(&source_l) => {
                    indirection_reason = Some("mount_source_unresolved");
                }
                None => return None,
            }
        }

        // A hardened systemd unit (PrivateDevices=, ProtectSystem=) sets up its
        // private /dev by bind-mounting the REAL host pseudo-devices — /dev/null,
        // /dev/zero, /dev/pts, /dev/shm, … — each of which is a genuine child of
        // the watched "/dev" tree, and (unlike the sandbox staging binds above) is
        // bound to the SAME target path (/dev/null → /dev/null in the new
        // namespace), so neither the source prefix nor the destination distinguishes
        // it from an escape. But the SET of sources is the tell: the standard
        // PrivateDevices node set is a fixed, well-known list of harmless pseudo-
        // devices, and binding one grants no host access — whereas an escape binds
        // the whole /dev tree, a raw disk (/dev/sda, /dev/mem), or a device mapper.
        // So an EXACT match (not a prefix) against the pseudo-device allowlist is
        // silent, while "/dev", "/dev/sda", "/dev/mapper/x" — none of which equal a
        // listed leaf — still fire. This is what quiets the per-service /dev bind
        // storm (polkitd, systemd-logind, every hardened unit) at startup.
        if rules
            .allow_pseudo_device_binds
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&source))
        {
            return None;
        }

        // Only sources overlapping a watched host path (by path component, in
        // either direction) are policed; everything else is an ordinary mount. An
        // empty watch list disables the verdict. Boundary-aware matching is the
        // fix for the substring storm: raw `contains("/dev")` flagged a sandbox's
        // "/oldroot/dev/null"; `watch_overlaps_source` matches only genuine host
        // paths — the watched dir, something under it, or an ancestor exposing it.
        // A resolved (or unresolvable) indirection has already established the
        // verdict above; its literal text need not also overlap a watch entry.
        let watched = indirection_reason.is_some()
            || rules
                .watch_sources
                .iter()
                .any(|s| watch_overlaps_source(&source_l, &s.to_ascii_lowercase()));
        if !watched {
            return None;
        }

        // Watched, but explicitly sanctioned ⇒ silent. Same boundary-aware match.
        // An indirection was already allow-checked against its RESOLVED target, so
        // a literal allow entry cannot launder the camouflage.
        if indirection_reason.is_none()
            && rules
                .allow_sources
                .iter()
                .any(|s| watch_overlaps_source(&source_l, &s.to_ascii_lowercase()))
        {
            return None;
        }

        // Host confinement machinery (snap-confine, systemd per-unit sandboxing)
        // bind-mounts whole host trees (/dev,/etc,/proc,/sys,/root) to BUILD a
        // sandbox — byte-identical in source to an escape binding the same path,
        // so only the ACTOR separates them. Suppress such a bind only when ALL of:
        //   (a) the actor's resolved exe is on allow_actor_exes — matched on
        //       /proc/<pid>/exe, NOT the spoofable `comm`; a "(deleted)" exe never
        //       matches (a fileless/overmounted binary is itself a signal);
        //   (b) the actor is OUTSIDE the app cgroup — a bind from INSIDE the
        //       app/container (a contained attacker breaking out) is never silenced,
        //       whatever its exe;
        //   (c) the source is NOT a never-benign bind (raw disk, kernel memory,
        //       device-mapper, runtime socket) — those fire even for snap-confine,
        //       so the exe allowlist can never short-circuit a raw-disk/socket escape.
        // comm-spoofing is defeated by (a), confused-deputy by (b)+(c).
        let source_is_exempt = rules
            .suppress_exempt_sources
            .iter()
            .any(|p| source_l.starts_with(&p.to_ascii_lowercase()));
        if !source_is_exempt && !self.actor_in_app_cgroup(&proc) {
            if let Some(exe) = proc.exe.as_deref() {
                let exe_ok = !exe.ends_with("(deleted)")
                    && rules
                        .allow_actor_exes
                        .iter()
                        .any(|a| a.eq_ignore_ascii_case(exe));
                if exe_ok {
                    return None;
                }
            }
        }

        let severity = parse_severity(&rules.severity).unwrap_or(Severity::High);
        let reason = indirection_reason.unwrap_or("mount_source_watched");
        let suffix = match (&resolved_indirection, reason) {
            (Some(r), _) => format!(" (sandbox-prefixed source resolving to {r})"),
            (None, "mount_source_unresolved") => " (unresolvable /proc indirection)".to_string(),
            _ if is_bind => " (bind mount)".to_string(),
            _ => String::new(),
        };
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::MountEscape,
            severity,
            summary: format!(
                "suspicious mount: pid {} ({}) mounted {}{}",
                proc.pid, proc.comm, source, suffix
            ),
            detail: serde_json::json!({
                "reason": reason,
                "source": source,
                "resolved_source": resolved_indirection,
                "flags": e.aux,
                "bind_mount": is_bind,
                "in_app_cgroup": in_app_cgroup,
            }),
            process: proc,
            target_pid: None,
            // Report-only: the mount has already taken effect; unmounting is an
            // operator's off-box decision.
            wants_kill: false,
        })
    }

    /// Judge a WARDEN_ACCESS record — the one ENFORCING kind. Unlike every judge
    /// above, the kernel has ALREADY made the security decision by the time this
    /// runs: the BPF-LSM guard matched the accessed inode against its per-inode
    /// policy, found the actor unauthorised for a denied intent, and either
    /// returned -EPERM (armed) or allowed it through (shadow). So there is no
    /// allowlist to re-apply and no context to second-guess here — every record
    /// that reached userspace is by construction a policy-relevant event. This
    /// function's whole job is to phrase it: an ARMED denial is the real incident
    /// (an unauthorised actor was blocked touching a guarded file — an intruder,
    /// an insider, root itself if not permitted); a SHADOW would-deny is the same
    /// access observed but allowed through, the pre-arming dry run that tells the
    /// operator exactly what arming will block before they flip it.
    ///
    /// The decode already reduced the five overloaded ABI slots into `e.access`;
    /// if it's somehow absent (a malformed record), there is nothing to judge.
    fn judge_access(&self, e: &Event) -> Option<Finding> {
        let a = e.access.as_ref()?;
        let proc = self.enrich(e);

        // An armed denial is High: it is a confirmed, unauthorised touch of a
        // guarded file that Warden actively blocked — the crown-jewels tripwire
        // firing. A shadow would-deny is the identical access left un-blocked;
        // it is Medium because it is not (yet) prevention, but it is a true
        // preview of what arming denies, and an operator watching the shadow
        // stream is watching real unauthorised access to a guarded inode.
        let (severity, verb) = if a.denied {
            (Severity::High, "DENIED")
        } else {
            (Severity::Medium, "would deny (shadow)")
        };

        let summary = format!(
            "guarded-file access {}: pid {} ({}) tried to {} a guarded inode \
             (dev={}, ino={})",
            verb,
            proc.pid,
            proc.comm,
            a.hook.as_str(),
            a.dev,
            a.ino,
        );

        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::AccessDenied,
            severity,
            summary,
            detail: serde_json::json!({
                "reason": if a.denied { "guarded_access_denied" } else { "guarded_access_shadow" },
                "hook": a.hook.as_str(),
                "intent": a.intent_str(),
                "denied": a.denied,
                "guarded_dev": a.dev,
                "guarded_ino": a.ino,
                "authorized_uid": a.authorized_uid,
                "actor_uid": proc.uid,
            }),
            process: proc,
            target_pid: None,
            // The kernel is the responder here: an armed guard has already returned
            // -EPERM in-kernel, which is a cleaner, earlier block than killing the
            // process after the fact. So Warden's userspace responder never kills on
            // an ACCESS finding — the denial IS the response.
            wants_kill: false,
        })
    }

    /// `window_secs`, and return the current count. Bounded per actor by the
    /// window itself, and the map is pruned once enough distinct actors have
    /// been seen: a deque that only ever ages out is still a map entry, so
    /// without the prune a host that churns short-lived pids kept one entry per
    /// pid for the life of the process.
    fn record_and_count_burst(&self, pid: u32, ts_ns: u64, window_secs: u64) -> usize {
        let window_ns = window_secs.saturating_mul(1_000_000_000);
        let mut map = self.file_bursts.borrow_mut();
        let count = {
            let dq = map.entry(pid).or_default();
            dq.push_back(ts_ns);
            // Evict from the front anything outside [ts_ns - window_ns, ts_ns].
            let cutoff = ts_ns.saturating_sub(window_ns);
            while let Some(&front) = dq.front() {
                if front < cutoff {
                    dq.pop_front();
                } else {
                    break;
                }
            }
            dq.len()
        };
        // Amortised: only once the map is big enough to be worth the walk. An
        // actor whose newest op is older than the window can never contribute to
        // the current count, so dropping it loses no burst history. Actors still
        // inside the window are kept — they are exactly the state the rule needs.
        if map.len() > BURST_MAP_PRUNE_AT {
            let cutoff = ts_ns.saturating_sub(window_ns);
            map.retain(|_, dq| dq.back().is_some_and(|&t| t >= cutoff));
        }
        count
    }
}

/// A readable name for a `bpf_prog_type`, for finding evidence. Only the kinds
/// Warden reasons about are named; anything else degrades to "type_<n>" so a
/// newer kernel's program type is never silently dropped from the report. Values
/// track `enum bpf_prog_type` in the kernel UAPI (a stable ABI).
pub(crate) fn bpf_prog_type_name(t: u32) -> String {
    let name = match t {
        0 => "unspec",
        1 => "socket_filter",
        2 => "kprobe",
        3 => "sched_cls",
        4 => "sched_act",
        5 => "tracepoint",
        6 => "xdp",
        7 => "perf_event",
        8 => "cgroup_skb",
        9 => "cgroup_sock",
        13 => "sock_ops",
        14 => "sk_skb",
        15 => "cgroup_device",
        16 => "sk_msg",
        17 => "raw_tracepoint",
        18 => "cgroup_sock_addr",
        24 => "raw_tracepoint_writable",
        26 => "tracing",
        27 => "struct_ops",
        28 => "ext",
        29 => "lsm",
        30 => "sk_lookup",
        31 => "syscall",
        32 => "netfilter",
        _ => return format!("type_{t}"),
    };
    name.to_string()
}

/// Parse a config severity string into the ladder, case-insensitively. Returns
/// None for an unknown string so the caller can fall back to a safe default
/// rather than silently mis-tagging.
fn parse_severity(s: &str) -> Option<Severity> {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Split a resolved destination into (ip, port). Handles both IPv4 "1.2.3.4:443"
/// and bracketed IPv6 "[::1]:443". Either part may be None if unparseable — the
/// caller degrades gracefully (a finding with a partial destination still fires).
pub(crate) fn split_ip_port(dest: &str) -> (Option<String>, Option<u16>) {
    if let Some(rest) = dest.strip_prefix('[') {
        // IPv6: "[addr]:port"
        if let Some((addr, port)) = rest.split_once("]:") {
            return (Some(addr.to_string()), port.parse().ok());
        }
        if let Some(addr) = rest.strip_suffix(']') {
            return (Some(addr.to_string()), None);
        }
        return (None, None);
    }
    // IPv4: "addr:port" (rsplit so we don't trip on a stray colon, though v4 has none)
    match dest.rsplit_once(':') {
        Some((addr, port)) => (Some(addr.to_string()), port.parse().ok()),
        None => (Some(dest.to_string()), None),
    }
}

/// Is this the unspecified address — 0.0.0.0, ::, or an IPv4-mapped zero?
///
/// The kernel reports it for a socket that has no peer yet (never connected, or
/// a listener), so it names a local state rather than somewhere the process
/// dialled. Parsing rather than string matching keeps the zero spellings
/// (`::0`, `0:0:0:0:0:0:0:0`, `::ffff:0.0.0.0`) in one place.
fn is_unspecified_addr(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return v4.is_unspecified();
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        return v6.is_unspecified()
            || v6
                .to_ipv4_mapped()
                .is_some_and(|v4: std::net::Ipv4Addr| v4.is_unspecified());
    }
    false
}

/// Is this address loopback? Covers the whole 127.0.0.0/8 block and IPv6 ::1.
fn is_loopback(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

/// Does `path` begin with `prefix` at a *path-component boundary*, rather than as
/// a raw substring? This is the fix for the mount false-positive storm: raw
/// `contains("/dev")` matched a sandbox's `/oldroot/dev/null`, and raw
/// `starts_with("/etc")` would match a sibling directory `/etcetera`. A component
/// boundary means the prefix is the whole string, or the character right after it
/// is a `/`. Two intentional exceptions let a prefix name a *partial* trailing
/// component: a prefix ending in `/` already carries its own boundary, and a
/// prefix ending in `-` (e.g. systemd's `namespace-`) is meant to match the
/// `namespace-<rand>` directory family. Both inputs are expected pre-lowercased.
fn has_path_prefix(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    if path.len() == prefix.len() {
        return true; // exact match
    }
    // prefix carries its own boundary, or names a partial-component family.
    if prefix.ends_with('/') || prefix.ends_with('-') {
        return true;
    }
    // Otherwise the next byte in `path` must be the path separator, so "/etc"
    // matches "/etc/shadow" but not "/etcetera".
    path.as_bytes()[prefix.len()] == b'/'
}

/// Does a watched host path `watch` overlap the mount `source`, judging by path
/// components (not raw substring)? A bind-mount escape is caught in either
/// direction: the source is the watched path or lives *under* it (grafting
/// `/etc/shadow`, watch `/etc`), or the source is an *ancestor* of the watched
/// path (grafting host `/` or `/var/run`, exposing `/var/run/docker.sock`). Both
/// inputs are expected pre-lowercased.
fn watch_overlaps_source(source: &str, watch: &str) -> bool {
    has_path_prefix(source, watch) || has_path_prefix(watch, source)
}

/// Resolve a mount source through the ACTOR's own `/proc`, so
/// `/proc/self/fd/N`, `/proc/<pid>/root/...` and `/proc/<pid>/cwd/...` name the
/// path the kernel actually resolved instead of their camouflage. `self` and
/// `thread-self` are rewritten to the actor pid first: evaluated in Warden's own
/// `/proc` they would name Warden's descriptors, which is exactly the wrong answer.
/// None when the link is already gone (or unreadable) — the caller decides
/// whether that is an unresolvable indirection or an ordinary staging root.
fn resolve_through_actor(actor_pid: u32, source: &str) -> Option<String> {
    let rewritten = if let Some(rest) = source.strip_prefix("/proc/self/") {
        format!("/proc/{actor_pid}/{rest}")
    } else if let Some(rest) = source.strip_prefix("/proc/thread-self/") {
        format!("/proc/{actor_pid}/{rest}")
    } else {
        source.to_string()
    };
    std::fs::canonicalize(&rewritten)
        .ok()?
        .to_str()
        .map(str::to_string)
}

/// The indirection shapes whose target can be any path: `/proc/.../fd/N`,
/// `/proc/.../root/...`, `/proc/.../cwd/...`. Only these fail closed when the
/// link can no longer be resolved. Ordinary staging roots (`/oldroot`,
/// `/run/user/…`) are opaque literals with no fd indirection, so they stay exempt.
fn is_proc_indirection(source_l: &str) -> bool {
    source_l.starts_with("/proc/")
        && (["/fd/", "/root/", "/cwd/"]
            .iter()
            .any(|m| source_l.contains(m))
            || source_l.ends_with("/root")
            || source_l.ends_with("/cwd"))
}

/// Does `pattern` occur in `path` STARTING at a path-component boundary — the
/// start of the string, right after a `/`, or (self-anchored) a pattern that
/// itself begins with `/`? This is the persistence-dir analogue of
/// `has_path_prefix`: it keeps the prefix-of-component matching the defaults rely
/// on ("cron" → "cron.d", "ld.so.conf" → "ld.so.conf.d/") while refusing a match
/// that begins MID-component, which is what made the xdg generator's
/// `app-<id>@autostart.service` leaf trip the "autostart" rule (the token sits
/// inside the filename, not at a boundary). Both inputs expected pre-lowercased.
fn persistence_match(path: &str, pattern: &str) -> bool {
    if pattern.is_empty() || pattern.len() > path.len() {
        return false;
    }
    let (hb, pb) = (path.as_bytes(), pattern.as_bytes());
    for i in 0..=(hb.len() - pb.len()) {
        if &hb[i..i + pb.len()] != pb || !(i == 0 || hb[i - 1] == b'/' || pb[0] == b'/') {
            continue;
        }
        // The match must also END at a token boundary. Prefix-of-component is
        // wanted ("cron" → "cron.d", "ld.so.conf" → "ld.so.conf.d/"), but a
        // longer word that merely starts with the pattern is not the directory
        // it names: "systemd/user" matched logind's /run/systemd/users/ state
        // files on every session update, so each one became Critical
        // persistence. A following '/', end of path, or punctuation (the dot in
        // "cron.d") is a boundary; another word character is not.
        match hb.get(i + pb.len()) {
            Some(&c) if c.is_ascii_alphanumeric() || c == b'-' || c == b'_' => continue,
            _ => return true,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AppIdentity, BpfRules, CredRules, FileRules, ListenRules, ModuleRules, MountRules,
        NetworkRules, ServiceRules, MAX_ENRICH_CACHE_MS,
    };
    use crate::events::{
        AccessHook, AccessInfo, CredChange, FileOp, Kind, WARDEN_INTENT_READ, WARDEN_INTENT_WRITE,
    };

    /// A connect Event from `pid`, destined for `dest`, tagged as inside the app
    /// cgroup or not by choosing a cgroup string the config will/won't match.
    fn connect_event(dest: &str) -> Event {
        Event {
            kind: Kind::Connect,
            actor_pid: std::process::id(),
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 0,
            ts_ns: 0,
            comm: "granian".into(),
            filename: String::new(),
            dest: Some(dest.to_string()),
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    /// A SIGNAL Event: `comm` (pid `actor_pid`) signals protected `target_pid` with
    /// `kill(2)` semantics — every SIGNAL record the kernel writes carries a class,
    /// so set `signal_delivery` on the result for a `tkill`/`sigqueue`/timer shape.
    fn signal_event(actor_pid: u32, comm: &str, sig: u32, target_pid: u32) -> Event {
        Event {
            kind: Kind::Signal,
            actor_pid,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid,
            aux: sig,
            ts_ns: 0,
            comm: comm.into(),
            filename: String::new(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: Some(SignalDelivery::User),
            actor_exe_file: None,
        }
    }

    /// A CREDS Event: `comm` did a privilege raise from `old_uid`→`new_uid` with
    /// effective capability masks `cap_old`→`cap_new`. Actor pid is this process
    /// so the "" cgroup match in `detector_with` counts it as in-app.
    fn creds_event(comm: &str, old_uid: u32, new_uid: u32, cap_old: u64, cap_new: u64) -> Event {
        Event {
            kind: Kind::Creds,
            actor_pid: std::process::id(),
            actor_ppid: 1,
            actor_uid: old_uid,
            target_pid: 0,
            // CREDS judges read `creds`, not `aux`. Keeping the new uid out of
            // this generic slot stops a synthetic fixture from manufacturing a
            // second, log-visible copy of the credential-field source.
            aux: 0,
            ts_ns: 0,
            comm: comm.into(),
            filename: String::new(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: Some(CredChange {
                old_uid,
                new_uid,
                cap_old,
                cap_new,
            }),
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    /// A detector whose app cgroup is "" — which every real cgroup path contains,
    /// so the actor always counts as in-app. Lets the egress rules be exercised
    /// without depending on this test process's actual cgroup path.
    fn detector_with(network_rules: NetworkRules) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()], // matches any cgroup ⇒ actor is "the app"
            exe_allowlist: vec![],
        };
        cfg.network_rules = network_rules;
        Detector::new(cfg)
    }

    #[test]
    fn splits_ipv4_and_ipv6_destinations() {
        assert_eq!(
            split_ip_port("203.0.113.4:443"),
            (Some("203.0.113.4".into()), Some(443))
        );
        assert_eq!(
            split_ip_port("[2001:db8::1]:8443"),
            (Some("2001:db8::1".into()), Some(8443))
        );
    }

    #[test]
    fn loopback_is_recognised_across_the_whole_block() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.5.6.7")); // whole /8, not just .0.0.1
        assert!(is_loopback("::1"));
        assert!(!is_loopback("203.0.113.4"));
    }

    /// An EXEC Event: `comm` exec'd, actor pid defaulting to this process (so the
    /// "" cgroup match in `exec_detector_with` counts it as in-app, and its real
    /// on-disk exe means the deleted-exe rule stays quiet unless asserted).
    fn exec_event(comm: &str) -> Event {
        exec_event_at(comm, &format!("/bin/{comm}"))
    }

    /// The same event with the `execve` path the kernel reported. This is the
    /// axis W2K-15 moves the rule onto: `comm` is 15 bytes the process rewrites
    /// with prctl, `filename` is what was actually executed.
    fn exec_event_at(comm: &str, filename: &str) -> Event {
        Event {
            kind: Kind::Exec,
            actor_pid: std::process::id(),
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 0,
            ts_ns: 0,
            comm: comm.into(),
            filename: filename.into(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    /// A detector whose app cgroup is "" — matches any real cgroup path, so the
    /// actor always counts as in-app. Lets the shell-in-app rule be exercised
    /// without depending on this test process's actual cgroup path.
    fn exec_detector_with_app() -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()], // matches any cgroup ⇒ actor is "the app"
            exe_allowlist: vec![],
        };
        Detector::new(cfg)
    }

    #[test]
    fn plain_shell_with_no_app_cgroup_is_silent() {
        // The regression guard: with [app] cgroup_contains empty we cannot
        // attribute a shell to the app, so a bare `bash` must NOT be a finding —
        // matching judge_connect/judge_creds/judge_file's quiet-with-empty-config
        // behaviour. (An earlier bug fired on every shell here.)
        let det = Detector::new(Config::safe_default());
        assert!(det.config().app.cgroup_contains.is_empty());
        assert!(det.judge(&exec_event("bash")).is_none());
    }

    #[test]
    fn shell_inside_the_app_cgroup_is_flagged_high() {
        // With an app cgroup configured and the actor inside it, a shell exec is
        // the reverse-shell signal we exist to catch.
        let det = exec_detector_with_app();
        let f = det
            .judge(&exec_event("bash"))
            .expect("a shell in the app cgroup must be a finding");
        assert!(matches!(f.event_type, FindingType::ProcessCreation));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detail["reason"], "shell_in_app_cgroup");
        assert_eq!(f.target_pid, None);
    }

    #[test]
    fn every_judged_finding_inherits_the_kernels_event_timestamp() {
        let det = exec_detector_with_app();
        let mut ev = exec_event("bash");
        ev.ts_ns = 1_234_567_890_123_456;
        let f = det
            .judge(&ev)
            .expect("a shell in the app cgroup must produce a finding");
        assert_eq!(f.source_ts_ns, ev.ts_ns);
    }

    #[test]
    fn non_shell_exec_in_the_app_cgroup_is_silent() {
        // Attribution alone isn't a finding: a routine non-shell exec by the app
        // (its own runtime, a helper) must stay quiet.
        let det = exec_detector_with_app();
        assert!(det.judge(&exec_event("granian")).is_none());
    }

    // ---- W2K-15: identity-based exec detection -------------------------------

    #[test]
    fn a_shell_named_only_by_its_path_is_still_a_shell() {
        // THE hole this stage closes: the process called itself `worker` — comm
        // is whatever prctl(PR_SET_NAME) was handed — but the executed path is
        // /bin/bash. The comm-only rule stayed silent; the path identity does not.
        let det = exec_detector_with_app();
        let f = det
            .judge(&exec_event_at("worker", "/bin/bash"))
            .expect("an exec whose path names a shell is a finding whatever comm says");
        assert_eq!(f.detail["reason"], "shell_in_app_cgroup");
        assert_eq!(f.detail["matched_by"], "filename");
        assert_eq!(f.detail["matched_name"], "bash");
    }

    #[test]
    fn the_resolved_path_outranks_comm_in_the_reported_identity() {
        // /bin/sh on Debian is a symlink to dash, so the kernel's resolved exe,
        // the tracepoint path and comm can all disagree. Here only comm and the
        // path name a shell (this test process's exe is the test binary), and the
        // report says which one it believed — the path, not the label.
        let det = exec_detector_with_app();
        let f = det
            .judge(&exec_event_at("sh", "/bin/sh"))
            .expect("sh is a shell by path and by comm");
        assert_eq!(f.detail["matched_by"], "filename");
        assert_eq!(f.detail["matched_name"], "sh");
        assert_eq!(f.detail["reason"], "shell_in_app_cgroup");
    }

    #[test]
    fn a_renamed_copy_from_tmp_is_flagged_by_where_it_came_from() {
        // `cp /bin/bash /tmp/svc-agent && /tmp/svc-agent` — no shell name anywhere
        // in the event, so the name rule cannot see it. The staging area can: an
        // executable handed out by a world-writable directory, from inside the app.
        let det = exec_detector_with_app();
        let f = det
            .judge(&exec_event_at("svc-agent", "/tmp/svc-agent"))
            .expect("a binary staged in /tmp and exec'd by the app is a finding");
        assert!(matches!(f.event_type, FindingType::ProcessCreation));
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.detail["reason"], "untrusted_exe_location");
        assert_eq!(f.detail["staged_path"], "/tmp/svc-agent");
        assert!(
            !f.wants_kill,
            "an unexplained exec must never arm the responder"
        );
    }

    #[test]
    fn a_binary_executed_from_its_installed_path_is_not_staged() {
        let det = exec_detector_with_app();
        assert!(det
            .judge(&exec_event_at("svc-agent", "/usr/local/bin/svc-agent"))
            .is_none());
    }

    #[test]
    fn the_staging_rule_stays_quiet_without_an_app_cgroup() {
        // Same attribution gate as the shell rule: with [app] cgroup_contains
        // empty, /tmp execs are every developer's Tuesday and must not be findings.
        let det = Detector::new(Config::safe_default());
        assert!(det
            .judge(&exec_event_at("svc-agent", "/tmp/svc-agent"))
            .is_none());
    }

    #[test]
    fn an_allowlisted_runtime_is_not_reported_as_staged() {
        // `[app].exe_allowlist` finally consumed: an operator who names the app's
        // real binary vouches for it wherever it lives. Matched on the resolved
        // /proc/<pid>/exe — here this test process's own, which is real.
        let my_exe = exe_of(std::process::id()).expect("the test process has a readable exe");
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![my_exe],
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&exec_event_at("svc-agent", "/tmp/svc-agent"))
            .is_none());
        // …and the allow cannot silence the shell-name rule: the same declared
        // runtime exec'ing /bin/bash is still an app-context shell.
        let f = det
            .judge(&exec_event_at("svc-agent", "/bin/bash"))
            .expect("exe_allowlist suppresses the location rule only");
        assert_eq!(f.detail["reason"], "shell_in_app_cgroup");
    }

    #[test]
    fn the_allowlist_is_never_matched_against_comm() {
        // The comm is "svc-agent" and the allowlist names "svc-agent" — a
        // self-vouching process. The resolved exe is this test binary, which is
        // NOT allowlisted, so the /tmp exec still reports.
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec!["svc-agent".into()],
        };
        let det = Detector::new(cfg);
        let f = det
            .judge(&exec_event_at("svc-agent", "/tmp/svc-agent"))
            .expect("a comm matching the exe allowlist vouches for nothing");
        assert_eq!(f.detail["reason"], "untrusted_exe_location");
    }

    #[test]
    fn the_staging_rule_never_arms_the_responder_even_when_kills_are_enabled() {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![],
        };
        cfg.respond.kill_reverse_shell = true;
        let det = Detector::new(cfg);
        let staged = det
            .judge(&exec_event_at("svc-agent", "/tmp/svc-agent"))
            .expect("staged exec still reports with kills enabled");
        assert!(!staged.wants_kill);
        // The shell rule keeps honouring the operator's kill switch.
        let shell = det.judge(&exec_event("bash")).expect("shell still flagged");
        assert!(shell.wants_kill);
    }

    #[test]
    fn an_empty_prefix_list_disables_the_staging_rule() {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![],
        };
        cfg.exec_rules.untrusted_exe_prefixes.clear();
        let det = Detector::new(cfg);
        assert!(det
            .judge(&exec_event_at("svc-agent", "/tmp/svc-agent"))
            .is_none());
    }

    #[test]
    fn prefix_matching_stops_at_the_directory_boundary() {
        // `/tmpish` is not inside `/tmp`; a raw starts_with would have flagged a
        // host-wide set of paths and made the rule unreportable.
        assert!(under_dir("/tmp", "/tmp"));
        assert!(under_dir("/tmp/x", "/tmp"));
        assert!(under_dir("/tmp/x/y", "/tmp/"));
        assert!(!under_dir("/tmpish/x", "/tmp"));
        assert!(!under_dir("/tmpx", "/tmp"));
        assert!(!under_dir("/var/tmp/x", "/tmp"));
        // basename / exe-suffix pairing the identity rules depend on.
        assert_eq!(basename("/usr/bin/dash"), "dash");
        assert_eq!(basename("/usr/bin/"), "bin");
        assert_eq!(exe_identity("/tmp/x (deleted)"), "/tmp/x");
        assert_eq!(basename(exe_identity("/tmp/x (deleted)")), "x");
        assert_eq!(exe_identity("/tmp/x"), "/tmp/x");
    }

    /// Process evidence with the fields the exec rules read chosen by the test.
    /// `enrich` reads this host's real `/proc`, whose exe is the test binary — so
    /// the resolved-exe axis, the strongest identity W2K-15 adds, is only
    /// judgeable through `judge_exec_with`.
    fn proc_evidence(comm: &str, exe: Option<&str>, cgroup: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            pid: 4242,
            ppid: 1,
            uid: 33,
            comm: comm.into(),
            exe: exe.map(str::to_string),
            cmdline: None,
            cgroup: cgroup.map(str::to_string),
            starttime: None,
        }
    }

    /// A detector scoped to a cgroup substring, so attribution is a fact the test
    /// sets rather than a property of the machine running it.
    fn exec_detector_in_cgroup(needle: &str) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec![needle.into()],
            exe_allowlist: vec![],
        };
        Detector::new(cfg)
    }

    #[test]
    fn the_resolved_exe_catches_a_shell_hiding_behind_an_innocent_name() {
        // Measured on a real host: `ln -s /bin/dash deploy-task`, then exec it.
        // The kernel sets comm from the invoked name — `deploy-task` — while the
        // readlink resolves through the symlink to dash. comm alone was blind.
        let det = exec_detector_in_cgroup("kubepods");
        let e = exec_event_at("deploy-task", "/usr/local/bin/deploy-task");
        let proc = proc_evidence(
            "deploy-task",
            Some("/usr/bin/dash"),
            Some("/kubepods/pod-abc/init.scope"),
        );
        let f = det
            .judge_exec_with(&e, &proc)
            .expect("the resolved binary is dash, whatever the invoked name says");
        assert_eq!(f.detail["reason"], "shell_in_app_cgroup");
        assert_eq!(f.detail["matched_by"], "exe");
        assert_eq!(f.detail["matched_name"], "dash");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn an_innocent_name_installed_in_a_system_path_stays_silent() {
        // The control the previous test needs: attribution plus an unknown binary
        // in a root-owned directory is not evidence of anything.
        let det = exec_detector_in_cgroup("kubepods");
        let e = exec_event_at("helper-agent", "/usr/local/bin/helper-agent");
        let proc = proc_evidence(
            "helper-agent",
            Some("/usr/local/bin/helper-agent"),
            Some("/kubepods/pod-abc/init.scope"),
        );
        assert!(det.judge_exec_with(&e, &proc).is_none());
    }

    #[test]
    fn a_missing_tracepoint_path_still_judges_on_the_resolved_exe() {
        // `filename` is read best-effort in the kernel and can arrive zeroed. The
        // exe identity must not depend on it.
        let det = exec_detector_in_cgroup("kubepods");
        let e = exec_event_at("worker", "");
        let proc = proc_evidence("worker", Some("/usr/bin/bash"), Some("/kubepods/x"));
        assert!(e.filename.is_empty());
        let f = det
            .judge_exec_with(&e, &proc)
            .expect("an empty path leaves the readlink");
        assert_eq!(f.detail["matched_by"], "exe");
        assert_eq!(f.detail["matched_name"], "bash");
    }

    #[test]
    fn a_fileless_shell_is_reported_as_fileless() {
        // deleted-exe outranks the name match: the Critical finding already says
        // everything the High one would, and it is the one an operator acts on.
        let det = exec_detector_in_cgroup("kubepods");
        let e = exec_event_at("agent", "/tmp/svc-agent");
        let proc = proc_evidence(
            "agent",
            Some("/tmp/svc-agent (deleted)"),
            Some("/kubepods/x"),
        );
        let f = det.judge_exec_with(&e, &proc).unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "deleted_exe");
    }

    #[test]
    fn a_shell_keeps_its_name_after_the_deleted_suffix_is_stripped() {
        // With the fileless rule off, "(deleted)" must not hide that the binary
        // was bash: the suffix is stripped before matching, not the path.
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["kubepods".into()],
            exe_allowlist: vec![],
        };
        cfg.exec_rules.flag_deleted_exe = false;
        let det = Detector::new(cfg);
        let e = exec_event_at("agent", "/tmp/bash");
        let proc = proc_evidence("agent", Some("/tmp/bash (deleted)"), Some("/kubepods/x"));
        let f = det.judge_exec_with(&e, &proc).unwrap();
        assert_eq!(f.detail["reason"], "shell_in_app_cgroup");
        assert_eq!(f.detail["matched_by"], "exe");
        assert_eq!(f.detail["matched_name"], "bash");
    }

    #[test]
    fn the_exe_allowlist_suppresses_only_the_path_it_names() {
        // Deterministic version of the allowlist gate: the staged copy `/tmp/x` is
        // vouched for while it is on the list, and reported the moment the
        // resolved exe is a different path — no comm involved anywhere.
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["kubepods".into()],
            exe_allowlist: vec!["/tmp/svc-agent".into()],
        };
        let det = Detector::new(cfg);
        let e = exec_event_at("svc-agent", "/tmp/svc-agent");
        let proc = proc_evidence("svc-agent", Some("/tmp/svc-agent"), Some("/kubepods/x"));
        assert!(det.judge_exec_with(&e, &proc).is_none());

        let moved = proc_evidence("svc-agent", Some("/tmp/svc-agent2"), Some("/kubepods/x"));
        let f = det
            .judge_exec_with(&e, &moved)
            .expect("a different binary is not covered by the allowlist");
        assert_eq!(f.detail["reason"], "untrusted_exe_location");
        // …and an allowlisted path is never vouched for when it is deleted.
        let ghost = proc_evidence(
            "svc-agent",
            Some("/tmp/svc-agent (deleted)"),
            Some("/kubepods/x"),
        );
        let f = det.judge_exec_with(&e, &ghost).unwrap();
        assert_eq!(f.detail["reason"], "deleted_exe");
    }

    #[test]
    fn unlisted_egress_from_the_app_is_flagged_high() {
        // The strictest, most common posture: empty allowlist means the worker is
        // expected to make no outbound connections, so any is a finding.
        let det = detector_with(NetworkRules::default());
        let f = det.judge(&connect_event("203.0.113.4:443")).unwrap();
        assert!(matches!(f.event_type, FindingType::NetworkConnect));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.target_pid, None);
    }

    #[test]
    fn allowlisted_destination_is_silent() {
        let det = detector_with(NetworkRules {
            egress_allow: vec!["203.0.113.4:443".into()],
            ..NetworkRules::default()
        });
        assert!(det.judge(&connect_event("203.0.113.4:443")).is_none());
    }

    #[test]
    fn a_denied_destination_is_a_critical_observe_only_finding() {
        // Phase 3: the deny rule must never be reported as a block. There is no
        // cgroup egress deny program in this build, so the finding is critical
        // (an operator must see it) while its own JSON says traffic_blocked=false
        // and wants_kill=false.
        for rules in [
            NetworkRules {
                deny_destinations: vec!["203.0.113.9:4444".into()],
                ..NetworkRules::default()
            },
            NetworkRules {
                // The bare-IP spelling must match too, as with egress_allow.
                deny_destinations: vec!["203.0.113.9".into()],
                ..NetworkRules::default()
            },
        ] {
            let det = detector_with(rules);
            let f = det
                .judge(&connect_event("203.0.113.9:4444"))
                .expect("a denied destination must produce a finding");
            assert_eq!(f.severity, Severity::Critical);
            assert!(
                !f.wants_kill,
                "a network deny must not request a process kill"
            );
            assert_eq!(f.detail["reason"], "egress_denied_by_policy");
            assert_eq!(f.detail["policy_decision"]["traffic_blocked"], false);
            assert_ne!(f.detail["policy_decision"]["enforcement_state"], "ENFORCE");
            assert_eq!(f.detail["policy_decision"]["action"], "DENY");
            let wire = serde_json::to_string(&f).unwrap();
            assert!(!wire.contains("api_key"));
        }
    }

    #[test]
    fn phase4_a_regular_beacon_produces_one_confidence_bearing_no_kill_finding() {
        let det = detector_with(NetworkRules::default());
        det.set_ring_loss_ratio(Some(0.0));
        let mut found = None;
        for sec in [0u64, 49, 121, 179, 240, 310, 358, 400, 460] {
            let mut e = connect_event("203.0.113.11:443");
            e.ts_ns = sec * 1_000_000_000;
            let verdict = det.judge(&e);
            // The first dials legitimately produce the generic egress finding;
            // keep feeding the tracker until the behavioural rule fires.
            if verdict
                .as_ref()
                .is_some_and(|v| v.event_type_str() == "endpoint:c2_beaconing")
            {
                found = verdict;
                break;
            }
        }
        let f = found.expect("a jittered cadence must eventually fire");
        assert_eq!(f.event_type_str(), "endpoint:c2_beaconing");
        assert!(!f.wants_kill, "local C2 confidence never requests a kill");
        assert!(f.severity <= Severity::High, "C2 alone is never Critical");
        assert_eq!(f.detail["detector"], "local_beaconing_v1");
        assert_eq!(f.detail["reason"], "periodic_connect_beaconing");
        assert_eq!(f.detail["enforcement_requested"], false);
        assert_eq!(f.detail["unsupported_inputs"].as_array().unwrap().len(), 3);
        assert!(f.summary.contains("NOT blocked"));
    }

    #[test]
    fn phase4_ring_loss_weakens_the_finding_confidence() {
        fn confidence_at(ratio: Option<f64>) -> f64 {
            let det = detector_with(NetworkRules::default());
            det.set_ring_loss_ratio(ratio);
            let mut found = None;
            for sec in [0u64, 49, 121, 179, 240, 310, 358, 400, 460] {
                let mut e = connect_event("203.0.113.12:443");
                e.ts_ns = sec * 1_000_000_000;
                let verdict = det.judge(&e);
                if verdict
                    .as_ref()
                    .is_some_and(|v| v.event_type_str() == "endpoint:c2_beaconing")
                {
                    found = verdict;
                    break;
                }
            }
            found.expect("a beacon must fire at this confidence").detail["confidence"]
                .as_f64()
                .unwrap()
        }
        let clean = confidence_at(Some(0.0));
        let lossy = confidence_at(Some(0.30));
        let unknown = confidence_at(None);
        assert!(lossy < clean, "lost events must weaken the claim");
        assert!(unknown <= 0.65, "an unreadable counter caps confidence");
    }

    #[test]
    fn deny_rules_override_an_allowlisted_port_but_not_an_unspecified_address() {
        // A deny rule is evaluated before the allowlist: listing a port as
        // allowed does not make an explicitly denied destination benign.
        let det = detector_with(NetworkRules {
            deny_destinations: vec!["203.0.113.9:4444".into()],
            allow_ports: vec![4444],
            ..NetworkRules::default()
        });
        assert_eq!(
            det.judge(&connect_event("203.0.113.9:4444"))
                .unwrap()
                .detail["reason"],
            "egress_denied_by_policy"
        );
        // A socket with no peer is not a dial to the denied address at all.
        assert!(det.judge(&connect_event("0.0.0.0:4444")).is_none());
    }

    #[test]
    fn the_egress_finding_carries_the_transport_the_kernel_reported() {
        // A dial to 203.0.113.4:53/udp (a resolver the app should not use) and the
        // same dial over tcp are different incidents, and the analyst reading the
        // finding cannot tell them apart from the destination alone. The value is
        // the hook's `sk_protocol` read, so a stamped record must surface it.
        let det = detector_with(NetworkRules::default());
        let f = det
            .judge(&Event {
                protocol: Some(Protocol::Udp),
                ..connect_event("203.0.113.4:53")
            })
            .expect("unlisted egress is a finding whatever the transport");
        assert_eq!(f.detail["protocol"], "udp");
    }

    #[test]
    fn a_record_with_no_transport_claim_yields_json_null_never_a_guess() {
        // Two real sources of "no claim": a record written by an eBPF object that
        // predates the packed `aux2`, and a socket whose `sk_protocol` genuinely
        // is 0. Both decode to `None`, and the finding must show that as null
        // rather than inventing "tcp" — an invented transport reads as evidence
        // to whoever triages the finding, and it makes a policy match look
        // confirmed when nothing on the host confirmed it.
        let det = detector_with(NetworkRules::default());
        let f = det.judge(&connect_event("203.0.113.4:443")).unwrap();
        assert!(
            f.detail["protocol"].is_null(),
            "absent transport must stay absent, got {:?}",
            f.detail["protocol"]
        );

        let ldet = listen_detector(ListenRules::default());
        let lf = ldet
            .judge(&listen_event("granian", "0.0.0.0:4444"))
            .expect("unexpected app listener is a finding");
        assert!(
            lf.detail["protocol"].is_null(),
            "absent transport must stay absent, got {:?}",
            lf.detail["protocol"]
        );
        // And when the record does carry one, the listener finding says so.
        let lf = ldet
            .judge(&Event {
                protocol: Some(Protocol::Tcp),
                ..listen_event("granian", "0.0.0.0:4444")
            })
            .unwrap();
        assert_eq!(lf.detail["protocol"], "tcp");
    }

    #[test]
    fn bare_ip_allowlist_matches_any_port() {
        let det = detector_with(NetworkRules {
            egress_allow: vec!["203.0.113.4".into()],
            ..NetworkRules::default()
        });
        assert!(det.judge(&connect_event("203.0.113.4:443")).is_none());
        assert!(det.judge(&connect_event("203.0.113.4:8080")).is_none());
    }

    #[test]
    fn allowed_port_is_silent_regardless_of_host() {
        let det = detector_with(NetworkRules {
            allow_ports: vec![5432],
            ..NetworkRules::default()
        });
        // A Postgres replica on any address is permitted by port.
        assert!(det.judge(&connect_event("10.9.8.7:5432")).is_none());
        // ...but a different port to the same host still fires.
        assert!(det.judge(&connect_event("10.9.8.7:443")).is_some());
    }

    #[test]
    fn loopback_egress_is_silent_by_default() {
        let det = detector_with(NetworkRules::default());
        assert!(det.judge(&connect_event("127.0.0.1:6379")).is_none());
    }

    #[test]
    fn an_unconnected_socket_is_not_egress() {
        // Live shapes from 2026-11-18 (§113.2). `[::]:22` killed sshd-session,
        // `[2a00::]:0` filled the spool, and the zero spellings are the same
        // state. None of them names a peer, so none of them may fire.
        let det = detector_with(NetworkRules {
            app_egress_only: false,
            ..NetworkRules::default()
        });
        for dest in [
            "0.0.0.0:22",
            "[::]:22",
            "[::]:0",
            "0.0.0.0:0",
            "[2a00::]:0",
            "[::ffff:0.0.0.0]:443",
        ] {
            assert!(
                det.judge(&connect_event(dest)).is_none(),
                "{dest} is a local socket state, not a destination"
            );
        }
    }

    #[test]
    fn a_real_destination_still_fires_after_the_unconnected_filter() {
        // The filter must be a hole in the noise, not in the detector.
        let det = detector_with(NetworkRules {
            app_egress_only: false,
            ..NetworkRules::default()
        });
        let finding = det
            .judge(&connect_event("203.0.113.4:443"))
            .expect("a routable dial to an unlisted port must still fire");
        assert!(matches!(finding.event_type, FindingType::NetworkConnect));
    }

    #[test]
    fn app_egress_only_silences_non_app_actors() {
        // app_egress_only with no configured app cgroup ⇒ we can't attribute, so
        // we must NOT flag every connect on the box.
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity::default(); // cgroup_contains empty
        cfg.network_rules = NetworkRules::default(); // app_egress_only = true
        let det = Detector::new(cfg);
        assert!(det.judge(&connect_event("203.0.113.4:443")).is_none());
    }

    #[test]
    fn disabling_app_egress_only_flags_any_actor() {
        let det = detector_with(NetworkRules {
            app_egress_only: false,
            ..NetworkRules::default()
        });
        assert!(det.judge(&connect_event("203.0.113.4:443")).is_some());
    }

    // ── privilege escalation (T5) ────────────────────────────────────────

    /// A detector whose app cgroup is "" (matches any cgroup ⇒ actor is the app),
    /// with the given cred rules. Lets the privesc rules be exercised without
    /// depending on this test process's real cgroup path.
    fn cred_detector_with(cred_rules: CredRules) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![],
        };
        cfg.cred_rules = cred_rules;
        Detector::new(cfg)
    }

    #[test]
    fn uid_to_root_inside_the_app_is_critical() {
        // The textbook post-exploitation step: a request worker becomes root.
        let det = cred_detector_with(CredRules::default());
        let f = det
            .judge(&creds_event("granian", 33, 0, 0, 0))
            .expect("root transition must be a finding");
        assert!(matches!(f.event_type, FindingType::PrivilegeChange));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.target_pid, None);
        assert_eq!(f.detail["reason"], "uid_to_root");
        assert_eq!(f.detail["old_uid"], 33);
        assert_eq!(f.detail["new_uid"], 0);
    }

    #[test]
    fn capability_gain_without_root_is_high() {
        // Subtler privesc: no uid change, but CAP_SYS_ADMIN (bit 21) newly held.
        let det = cred_detector_with(CredRules::default());
        let f = det
            .judge(&creds_event("granian", 33, 33, 0, 1 << 21))
            .expect("capability gain must be a finding");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detail["reason"], "capability_gain");
        assert_eq!(f.detail["gained_caps"], "CAP_SYS_ADMIN");
    }

    /// A detector judging a hypothetical actor, with only the executable the test
    /// chooses. `--explain`'s seam, used here because W2K-30a weighs a `comm` against
    /// the `/proc/<pid>/exe` read of the SAME process, and no test can make its own
    /// pid answer for both `sudo` and `/usr/bin/sudo`. The cgroup is fabricated too:
    /// `app_privesc_only` needs an in-app actor for the suppression question to be
    /// the live one.
    fn cred_actor(rules: CredRules, exe: Option<&str>) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![],
        };
        cfg.cred_rules = rules;
        Detector::for_explain(
            cfg,
            FabricatedEvidence {
                exe: exe.map(str::to_string),
                cmdline: None,
                cgroup: Some("/system.slice/app.slice/worker.service".into()),
            },
        )
    }

    #[test]
    fn expected_privilege_daemons_are_silent() {
        // `sudo` becoming root is what sudo does — not an incident, even in-app —
        // and the raise by a process whose executable could not be read at all is
        // still carried by its name, which is the weaker posture `--check` prints.
        // Both arms are pinned because W2K-30a split them: the name alone is no
        // longer enough when a path was read and contradicts it (test below).
        let det = cred_actor(CredRules::default(), Some("/usr/bin/sudo"));
        assert!(det.judge(&creds_event("sudo", 1000, 0, 0, 0)).is_none());
        let det = cred_actor(CredRules::default(), Some("/usr/sbin/sshd"));
        assert!(det.judge(&creds_event("sshd", 0, 0, 0, 1 << 21)).is_none());
        let det = cred_actor(CredRules::default(), None);
        assert!(det.judge(&creds_event("sudo", 1000, 0, 0, 0)).is_none());
    }

    #[test]
    fn a_forged_privilege_comm_does_not_hide_the_raise() {
        // W2K-30a: the whole privesc finding used to vanish on a comm match alone,
        // and `prctl(PR_SET_NAME)` sets a comm from inside any process. So an
        // attacker that names its exploit `sudo` and escalates to root inside the app
        // was invisible. The executable WAS read here, and it says otherwise.
        let det = cred_actor(CredRules::default(), Some("/tmp/.cache/sudo-shim"));
        let f = det
            .judge(&creds_event("sudo", 1000, 0, 0, 0))
            .expect("an expected name worn by an unexpected binary must fire");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "uid_to_root");
        assert_eq!(f.detail["comm_expected"], true);
        assert_eq!(f.detail["name_spoofed"], true);
        assert_eq!(f.detail["actor_exe"], "/tmp/.cache/sudo-shim");
        // The operator is told which knob makes this silent for the real program.
        assert!(f.detail["how_to_authorize"]
            .as_str()
            .unwrap_or_default()
            .contains("expected_privilege_exes"));
        assert!(
            f.summary.contains("/tmp/.cache/sudo-shim"),
            "the summary must name the executable behind the borrowed name"
        );

        // The same actor with a name nobody claimed is the ordinary finding: the
        // path decides, and the label only changes what the finding can say.
        let plain = cred_actor(CredRules::default(), Some("/tmp/.cache/sudo-shim"))
            .judge(&creds_event("helper", 1000, 0, 0, 0))
            .expect("an unknown name is a finding on its own");
        assert_eq!(plain.detail["comm_expected"], false);
        assert_eq!(plain.detail["name_spoofed"], false);
    }

    #[test]
    fn a_pinned_privilege_exe_authorizes_a_raise_whatever_its_name() {
        // The identity-based answer `expected_privilege_comms` never was: once the
        // operator names the file, a re-titled or oddly-named build of the same
        // program is plumbing, and a differently-named file is not.
        let det = cred_actor(
            CredRules {
                expected_privilege_exes: vec!["/opt/acme/bin/setuid-helper".to_string()],
                ..CredRules::default()
            },
            Some("/opt/acme/bin/setuid-helper"),
        );
        assert!(det
            .judge(&creds_event("not-on-any-list", 1000, 0, 0, 0))
            .is_none());

        // A pinned path that is not the one read authorises nothing — adding a key is
        // not the same as configuring the rule.
        let det = cred_actor(
            CredRules {
                expected_privilege_exes: vec!["/opt/acme/bin/setuid-helper".to_string()],
                ..CredRules::default()
            },
            Some("/opt/acme/bin/other"),
        );
        assert!(det.judge(&creds_event("sudo", 1000, 0, 0, 0)).is_some());
    }

    #[test]
    fn a_pinned_privilege_exe_matches_a_deleted_binary() {
        // An upgrade that replaced the file under a running program leaves
        // `<path> (deleted)` in the link. It is still that executable (W2K-18's
        // rule for loaders), so pinning the path keeps working across an upgrade
        // instead of firing Critical at every package update.
        let det = cred_actor(
            CredRules {
                expected_privilege_exes: vec!["/usr/bin/sudo".to_string()],
                ..CredRules::default()
            },
            Some("/usr/bin/sudo (deleted)"),
        );
        assert!(det.judge(&creds_event("sudo", 1000, 0, 0, 0)).is_none());
    }

    #[test]
    fn a_spoofed_scanner_comm_does_not_silence_a_read() {
        // W2K-30b: the comm list used to be a switch any process could flip for
        // itself — one prctl(PR_SET_NAME) call to "systemd" and a READ of the
        // protected signer's /proc/<pid>/environ was silent. Now a name only carries
        // a read when the executable we read is that name's binary, and an actor
        // whose path contradicts the claim is recon at Medium.
        let det = Detector::new(Config::safe_default());
        assert!(
            !det.benign_reader("systemd", Some("/tmp/.cache/systemd-scan")),
            "a borrowed name on a different binary is not a scanner"
        );
        assert!(!det.benign_reader("fuser", Some("/tmp/.cache/systemd-scan")));
        // The real daemon, at the path Debian installs it, is still silent — this is
        // not a rule that trades the 192-line storm for a new one.
        assert!(det.benign_reader("systemd", Some("/usr/lib/systemd/systemd")));
        assert!(det.benign_reader("systemd-journal", Some("/usr/lib/systemd/systemd-journald")));
        // And a reader whose executable could not be read is still carried by its
        // name, exactly as before: the weaker posture, not a new silence.
        assert!(det.benign_reader("systemd", None));

        // End to end, so the suppression is proved at the judge and not only in the
        // predicate it calls.
        let spoofed = Detector::for_explain(
            Config::safe_default(),
            FabricatedEvidence {
                exe: Some("/tmp/.cache/systemd-scan".into()),
                cmdline: None,
                cgroup: None,
            },
        );
        let f = spoofed
            .judge(&ptrace_event("systemd", 0x01))
            .expect("a spoofed scanner name must surface as recon");
        assert_eq!(f.severity, Severity::Medium);
        assert!(matches!(f.event_type, FindingType::SelfTamper));
        assert_eq!(f.detail["is_attach"], false);

        // The same READ by the genuine path stays silent: the difference the rule
        // draws is the executable, not the name.
        let genuine = Detector::for_explain(
            Config::safe_default(),
            FabricatedEvidence {
                exe: Some("/usr/lib/systemd/systemd".into()),
                cmdline: None,
                cgroup: None,
            },
        );
        assert!(genuine.judge(&ptrace_event("systemd", 0x01)).is_none());
    }

    #[test]
    fn a_pinned_reader_path_silences_a_read_whatever_it_is_called() {
        // The exe allowlist is consulted first and needs no agreement from the name:
        // a runtime built under an odd comm is still the pinned file, and placing a
        // binary at an allowlisted path is a root-level tamper in its own right.
        let det = Detector::new(Config::safe_default());
        assert!(det.benign_reader("whatever-docker-called-it", Some("/usr/bin/runc")));
        // …and the path list decides nothing about an unreadable exe.
        assert!(!det.benign_reader("whatever-docker-called-it", None));
    }

    #[test]
    fn name_and_executable_agreement_is_a_truth_table() {
        // The whole of W2K-30's new gate, pinned without a /proc to trick: a name is
        // evidence when the binary we read is that name's binary.
        let cases: &[(&str, Option<&str>, bool, &str)] = &[
            // The shipped plumbing, path as Debian installs it.
            (
                "sudo",
                Some("/usr/bin/sudo"),
                true,
                "the name is the binary",
            ),
            ("SSHD", Some("/usr/sbin/sshd"), true, "case-insensitive"),
            (
                "systemd",
                Some("/usr/lib/systemd/systemd"),
                true,
                "a daemon in its own dir",
            ),
            (
                "systemd-journal",
                Some("/usr/lib/systemd/systemd-journald"),
                true,
                "comm truncated at TASK_COMM_LEN-1 by the kernel",
            ),
            (
                "runc:[1:CHILD]",
                Some("/usr/bin/runc"),
                true,
                "a re-titled child of the same binary",
            ),
            (
                "sudo",
                Some("/usr/bin/sudo (deleted)"),
                true,
                "upgraded under itself",
            ),
            // The evasion W2K-30 closes: a borrowed name on a binary that is not it.
            (
                "sudo",
                Some("/tmp/.cache/sudo-shim"),
                false,
                "a shim, not sudo",
            ),
            (
                "systemd",
                Some("/usr/bin/systemd-scan"),
                false,
                "a longer word",
            ),
            (
                "sshd",
                Some("/usr/sbin/sshd-keygen"),
                false,
                "a different program",
            ),
            (
                "sy",
                Some("/usr/bin/systemd"),
                false,
                "a prefix nobody truncates to",
            ),
            (
                "systemdx",
                Some("/usr/bin/systemd"),
                false,
                "a suffix with no separator",
            ),
            ("sudo", Some("/"), false, "no basename at all"),
            (
                "",
                Some("/usr/bin/sudo"),
                false,
                "an empty name claims nothing",
            ),
            // Nothing to contradict the name: the caller's weaker-posture arm.
            ("sudo", None, true, "the executable could not be read"),
        ];
        for (comm, exe, want, why) in cases {
            assert_eq!(
                name_agrees_with_exe(comm, *exe),
                *want,
                "{comm:?} against {exe:?}: {why}"
            );
        }
    }

    #[test]
    fn capability_gain_can_be_disabled_while_root_still_fires() {
        // With flag_capability_gain off, a pure cap gain is silent…
        let det = cred_detector_with(CredRules {
            flag_capability_gain: false,
            ..CredRules::default()
        });
        assert!(det
            .judge(&creds_event("granian", 33, 33, 0, 1 << 21))
            .is_none());
        // …but an outright root transition is never suppressed by that toggle.
        assert!(det.judge(&creds_event("granian", 33, 0, 0, 0)).is_some());
    }

    #[test]
    fn app_privesc_only_silences_non_app_actors() {
        // app_privesc_only with no configured app cgroup ⇒ we can't attribute, so
        // we must NOT flag every `sudo` on the box.
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity::default(); // cgroup_contains empty
        cfg.cred_rules = CredRules::default(); // app_privesc_only = true
        let det = Detector::new(cfg);
        assert!(det.judge(&creds_event("attacker", 33, 0, 0, 0)).is_none());
    }

    #[test]
    fn disabling_app_privesc_only_flags_any_actor() {
        let det = cred_detector_with(CredRules {
            app_privesc_only: false,
            ..CredRules::default()
        });
        assert!(det.judge(&creds_event("attacker", 33, 0, 0, 0)).is_some());
    }

    // ── module load / rootkit (T6) ───────────────────────────────────────

    /// A MODULE Event: a module named `module` loaded with taint flags `taints`.
    /// The name rides in on `filename`, exactly as the kernel tracepoint delivers
    /// it; there is no per-process attribution for a host-global module load.
    fn module_event(module: &str, taints: u32) -> Event {
        Event {
            kind: Kind::Module,
            actor_pid: std::process::id(),
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: taints,
            ts_ns: 0,
            comm: "insmod".into(),
            filename: module.to_string(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    #[test]
    fn a_runtime_module_load_is_critical_by_default() {
        // Empty allowlist ⇒ any runtime module load is the rootkit signature.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&module_event("evil_rootkit", 0))
            .expect("a non-allowlisted module load must be a finding");
        assert!(matches!(f.event_type, FindingType::ModuleLoad));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.target_pid, None);
        assert!(!f.wants_kill); // report-only: the module is already in-kernel
        assert_eq!(f.detail["module"], "evil_rootkit");
        assert_eq!(f.detail["reason"], "module_not_allowlisted");
    }

    #[test]
    fn an_allowlisted_module_is_silent() {
        let mut cfg = Config::safe_default();
        cfg.module_rules = ModuleRules {
            allow_modules: vec!["wireguard".into()],
            ..ModuleRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det.judge(&module_event("wireguard", 0)).is_none());
        // A different module still fires — the allowlist is exact, not a prefix.
        assert!(det.judge(&module_event("wireguard_evil", 0)).is_some());
    }

    #[test]
    fn module_severity_ceiling_is_configurable() {
        let mut cfg = Config::safe_default();
        cfg.module_rules = ModuleRules {
            allow_modules: vec![],
            severity: "high".into(),
        };
        let det = Detector::new(cfg);
        let f = det.judge(&module_event("late_fs_driver", 0)).unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn an_unknown_module_severity_falls_back_to_critical() {
        // A typo'd severity must fail safe (loudest), never silently mis-tag.
        let mut cfg = Config::safe_default();
        cfg.module_rules = ModuleRules {
            allow_modules: vec![],
            severity: "apocalyptic".into(),
        };
        let det = Detector::new(cfg);
        let f = det.judge(&module_event("x", 0)).unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    // ── ransomware / file tamper (T2/T9) ─────────────────────────────────

    /// A FILE Event: actor `pid`, operation `op`, affected leaf `name`, stamped
    /// at `ts_ns`. Actor pid defaults to this process so the "" cgroup match in
    /// `file_detector_with` counts it as in-app.
    fn file_event(pid: u32, op: FileOp, name: &str, ts_ns: u64) -> Event {
        Event {
            kind: Kind::File,
            actor_pid: pid,
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: op as u32,
            ts_ns,
            comm: "granian".into(),
            filename: name.to_string(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    /// A detector whose app cgroup is "" (matches any cgroup ⇒ actor is the app),
    /// with the given file rules. Lets the extension/burst rules be exercised
    /// without depending on this test process's real cgroup path.
    fn file_detector_with(file_rules: FileRules) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![],
        };
        cfg.file_rules = file_rules;
        Detector::new(cfg)
    }

    #[test]
    fn a_rename_into_a_ransom_extension_is_critical() {
        let det = file_detector_with(FileRules::default());
        let me = std::process::id();
        let f = det
            .judge(&file_event(me, FileOp::Rename, "report.docx.locked", 0))
            .expect("a ransom-extension rename must be a finding");
        assert!(matches!(f.event_type, FindingType::FileTamper));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "ransom_extension");
        assert_eq!(f.detail["matched_extension"], ".locked");
    }

    #[test]
    fn a_routine_rename_is_silent() {
        // A rename that isn't into a ransom extension, below the burst threshold,
        // is the common case and must not fire.
        let det = file_detector_with(FileRules::default());
        let me = std::process::id();
        assert!(det
            .judge(&file_event(me, FileOp::Rename, "report.docx.tmp", 0))
            .is_none());
    }

    #[test]
    fn a_watched_name_fires_for_any_actor_even_outside_the_app() {
        // watch_names is the one rule not gated by app attribution: destroying a
        // keystore matters whoever does it. Use a pid that ISN'T ours and rules
        // that would otherwise stay silent (app_files_only, no burst).
        let det = file_detector_with(FileRules {
            app_files_only: true,
            watch_names: vec!["id_rsa".into(), ".env".into()],
            burst_threshold: 0,
            ..FileRules::default()
        });
        let stranger = 999_999; // not this process ⇒ not in the "" app cgroup match
        let f = det
            .judge(&file_event(stranger, FileOp::Unlink, "id_rsa", 0))
            .expect("a watched-name unlink must fire regardless of actor");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "watched_name");
        assert_eq!(f.detail["operation"], "unlink");
    }

    #[test]
    fn app_files_only_silences_non_app_actors_for_extension_and_burst() {
        // With app_files_only and no configured app cgroup, a ransom-extension
        // rename by an unattributable actor must stay silent (we can't tell it
        // from a build). Only watch_names would fire, and none is configured.
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity::default(); // no app cgroup
        cfg.file_rules = FileRules::default();
        let det = Detector::new(cfg);
        assert!(det
            .judge(&file_event(999_999, FileOp::Rename, "x.locked", 0))
            .is_none());
    }

    #[test]
    fn a_modification_burst_from_one_actor_is_critical() {
        // A low threshold over a wide window: the Nth op within the window trips
        // the behavioural rule even though no single name is a ransom extension.
        let det = file_detector_with(FileRules {
            ransom_extensions: vec![], // isolate the burst rule
            burst_threshold: 5,
            burst_window_secs: 10,
            ..FileRules::default()
        });
        let me = std::process::id();
        let sec = 1_000_000_000u64;
        // Four ops: below threshold, all silent.
        for i in 0..4 {
            assert!(det
                .judge(&file_event(me, FileOp::Unlink, "f", i * sec))
                .is_none());
        }
        // The fifth within the window trips it.
        let f = det
            .judge(&file_event(me, FileOp::Unlink, "f", 4 * sec))
            .expect("the burst threshold must trip a finding");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "modification_burst");
        assert_eq!(f.detail["ops_in_window"], 5);
    }

    #[test]
    fn stale_ops_age_out_of_the_burst_window() {
        // Ops spread wider than the window never accumulate: each is alone in its
        // window, so the count stays at 1 and nothing fires.
        let det = file_detector_with(FileRules {
            ransom_extensions: vec![],
            burst_threshold: 3,
            burst_window_secs: 2,
            ..FileRules::default()
        });
        let me = std::process::id();
        let sec = 1_000_000_000u64;
        // Ten ops, each 5s apart — always outside the 2s window from the last.
        for i in 0..10 {
            assert!(det
                .judge(&file_event(me, FileOp::Rename, "f.tmp", i * 5 * sec))
                .is_none());
        }
    }

    #[test]
    fn the_burst_map_forgets_actors_whose_ops_have_all_aged_out() {
        // One entry per pid, all stamped at t=0. None can contribute to a burst
        // at t=10s with a 1s window, so the prune must drop them instead of
        // carrying a deque per pid for the life of the process.
        let det = Detector::new(Config::safe_default());
        for pid in 1..=BURST_MAP_PRUNE_AT as u32 {
            det.record_and_count_burst(pid, 0, 1);
        }
        assert_eq!(det.file_bursts.borrow().len(), BURST_MAP_PRUNE_AT);

        let sec = 1_000_000_000u64;
        det.record_and_count_burst(999_999, 10 * sec, 1);

        let map = det.file_bursts.borrow();
        assert!(!map.contains_key(&1), "a stale actor must be pruned");
        assert_eq!(map.len(), 1, "only the live actor should remain");
    }

    #[test]
    fn a_zero_burst_threshold_disables_the_burst_rule() {
        let det = file_detector_with(FileRules {
            ransom_extensions: vec![],
            burst_threshold: 0,
            burst_window_secs: 5,
            ..FileRules::default()
        });
        let me = std::process::id();
        // A thousand ops in the same instant: still silent, the rule is off.
        for _ in 0..1000 {
            assert!(det.judge(&file_event(me, FileOp::Unlink, "f", 0)).is_none());
        }
    }

    // ── persistence / new service (T3) ───────────────────────────────────

    /// A SERVICE Event: actor `pid` created a file whose rebuilt trailing path is
    /// `path`. The path arrives already joined (the decoder rebuilt it from the
    /// kernel's component ladder); the detector matches it against the
    /// persistence-dir list.
    fn service_event(pid: u32, path: &str) -> Event {
        Event {
            kind: Kind::Service,
            actor_pid: pid,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: crate::events::ServiceOp::Create as u32,
            ts_ns: 0,
            comm: "sh".into(),
            filename: path.to_string(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    #[test]
    fn a_write_into_a_persistence_dir_is_critical_by_default() {
        // A rogue systemd unit dropped under /etc/systemd/system, empty allowlist
        // ⇒ the persistence signature. Critical, report-only, ANY actor.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&service_event(4242, "/etc/systemd/system/evil.service"))
            .expect("a non-allowlisted persistence write must be a finding");
        assert!(matches!(f.event_type, FindingType::NewService));
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.target_pid, None);
        assert!(!f.wants_kill); // report-only: the artifact is already on disk
        assert_eq!(f.detail["reason"], "persistence_dir");
        assert_eq!(f.detail["operation"], "create");
        assert_eq!(f.detail["path"], "/etc/systemd/system/evil.service");
    }

    #[test]
    fn an_ordinary_file_create_outside_persistence_dirs_is_silent() {
        // The overwhelming common case: a create somewhere mundane. Must not fire —
        // otherwise every file written on the box is a finding.
        let det = Detector::new(Config::safe_default());
        assert!(det
            .judge(&service_event(4242, "/home/user/notes.txt"))
            .is_none());
        assert!(det
            .judge(&service_event(4242, "/tmp/build/output.o"))
            .is_none());
        assert!(det
            .judge(&service_event(4242, "/var/lib/app/cache.db"))
            .is_none());
    }

    #[test]
    fn a_persistence_write_fires_for_any_actor_ignoring_app_cgroup() {
        // Unlike egress, persistence isn't app-attributed: a foothold in a cron dir
        // is an incident whoever wrote it. A stranger pid (not in any app cgroup)
        // with the default no-app-cgroup posture must still fire.
        let det = Detector::new(Config::safe_default()); // [app] cgroup_contains empty
        let f = det
            .judge(&service_event(999_999, "/etc/cron.d/backdoor"))
            .expect("a cron persistence write must fire regardless of actor");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "persistence_dir");
    }

    #[test]
    fn an_allowlisted_persistence_path_is_silent() {
        // A sanctioned unit our own provisioning lays down: under a watched dir but
        // on allow_paths, so it must stay silent — while a sibling still fires.
        let mut cfg = Config::safe_default();
        cfg.service_rules = ServiceRules {
            allow_paths: vec!["/etc/systemd/system/warden.service".into()],
            ..ServiceRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&service_event(1, "/etc/systemd/system/warden.service"))
            .is_none());
        assert!(det
            .judge(&service_event(1, "/etc/systemd/system/evil.service"))
            .is_some());
    }

    #[test]
    fn service_severity_is_configurable_and_falls_back_to_critical() {
        // A configured ceiling is honoured…
        let mut cfg = Config::safe_default();
        cfg.service_rules = ServiceRules {
            severity: "high".into(),
            ..ServiceRules::default()
        };
        let det = Detector::new(cfg);
        let f = det.judge(&service_event(1, "/etc/cron.d/x")).unwrap();
        assert_eq!(f.severity, Severity::High);

        // …and a typo'd severity fails safe (loudest) rather than mis-tagging.
        let mut cfg = Config::safe_default();
        cfg.service_rules = ServiceRules {
            severity: "apocalyptic".into(),
            ..ServiceRules::default()
        };
        let det = Detector::new(cfg);
        let f = det.judge(&service_event(1, "/etc/cron.d/x")).unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn an_empty_service_path_is_silent() {
        // Every ladder read failed ⇒ empty path. Unattributable, so silent rather
        // than a fabricated finding.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&service_event(4242, "")).is_none());
    }

    #[test]
    fn an_empty_persistence_dir_list_disables_the_verdict() {
        // With no persistence dirs configured, nothing is a persistence location —
        // every create is allowlisted. The sensor's verdict is fully operator-tunable.
        let mut cfg = Config::safe_default();
        cfg.service_rules = ServiceRules {
            persistence_dirs: vec![],
            ..ServiceRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&service_event(1, "/etc/systemd/system/evil.service"))
            .is_none());
    }

    // ---- listen (bind-shell / inbound backdoor) --------------------------------

    /// A LISTEN Event bound to `endpoint` ("ip:port"). Actor pid is this process
    /// so an "" app-cgroup match counts it as in-app.
    fn listen_event(comm: &str, endpoint: &str) -> Event {
        Event {
            kind: Kind::Listen,
            actor_pid: std::process::id(),
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 0,
            ts_ns: 0,
            comm: comm.into(),
            filename: String::new(),
            dest: Some(endpoint.to_string()),
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    /// A detector whose app cgroup is "" (matches any) with the given listen rules.
    fn listen_detector(rules: ListenRules) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: vec!["".into()],
            exe_allowlist: vec![],
        };
        cfg.listen_rules = rules;
        Detector::new(cfg)
    }

    #[test]
    fn an_app_listener_on_an_unexpected_port_is_a_high_backdoor_finding() {
        // The worker itself opened a listener on an odd port with no allowlist —
        // the textbook bind-shell shape. High, and killable like a reverse shell.
        let det = listen_detector(ListenRules::default());
        let f = det
            .judge(&listen_event("granian", "0.0.0.0:4444"))
            .expect("an unexpected app listener must be a finding");
        assert!(matches!(f.event_type, FindingType::ListenBackdoor));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.target_pid, None);
        assert_eq!(f.detail["reason"], "listener_not_allowlisted");
        assert_eq!(f.detail["bind_port"], 4444);
    }

    #[test]
    fn a_listener_on_a_sanctioned_service_port_is_silent() {
        // The app's own service port (8000) is expected; must not fire.
        let det = listen_detector(ListenRules {
            allow_ports: vec![8000],
            ..ListenRules::default()
        });
        assert!(det
            .judge(&listen_event("granian", "0.0.0.0:8000"))
            .is_none());
        // …but a different port on the same box still fires.
        assert!(det
            .judge(&listen_event("granian", "0.0.0.0:4444"))
            .is_some());
    }

    #[test]
    fn a_loopback_listener_is_silent_when_loopback_is_allowed() {
        // A local-only helper bound to 127.0.0.1 is unreachable off-box, so it
        // cannot be an inbound backdoor — silent under the default allow_loopback.
        let det = listen_detector(ListenRules::default());
        assert!(det
            .judge(&listen_event("python", "127.0.0.1:9001"))
            .is_none());
        // With loopback hunting turned on, the same bind becomes a finding.
        let det = listen_detector(ListenRules {
            allow_loopback: false,
            ..ListenRules::default()
        });
        assert!(det
            .judge(&listen_event("python", "127.0.0.1:9001"))
            .is_some());
    }

    #[test]
    fn a_listener_outside_the_app_cgroup_is_silent() {
        // With the default no-app-cgroup dev posture, app_listen_only means an
        // unattributable listener (sshd, systemd socket) stays quiet — the same
        // stance as egress. safe_default has an EMPTY app cgroup.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&listen_event("sshd", "0.0.0.0:22")).is_none());
    }

    // ---- bpf program load (eBPF rootkit) ---------------------------------------

    /// A BPFLOAD Event: `comm` loaded a program (aux carries the bpf() cmd).
    /// Leaves `bpf_prog_type` unset (None ⇒ decoded as UNSPEC/unknown), the "we
    /// couldn't read the type" case that must fail toward surfacing.
    fn bpf_event(comm: &str) -> Event {
        Event {
            kind: Kind::BpfLoad,
            actor_pid: 4242,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 5, // BPF_PROG_LOAD
            ts_ns: 0,
            comm: comm.into(),
            filename: String::new(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    /// A BPFLOAD Event of a specific `bpf_prog_type` (numeric enum): the depth
    /// dimension the sensor uses to tell an implant hook from a benign filter.
    fn bpf_event_typed(comm: &str, prog_type: u32) -> Event {
        Event {
            bpf_prog_type: Some(prog_type),
            ..bpf_event(comm)
        }
    }

    /// A pid the kernel cannot hand out, so `/proc/<pid>/exe` and `/proc/<pid>/stat`
    /// are UNREADABLE for certain. Since W2K-18 the readability of that exe decides
    /// which rule answers, so a test that means "the loader already exited" must not
    /// lean on a plausible pid: 4242 is free on a freshly booted box and owned by
    /// some live process on a long-lived one, and those are different verdicts.
    const DEAD_PID: u32 = u32::MAX;

    /// A BPFLOAD Event with the loader's pid chosen deliberately — the only variable
    /// that says whether userspace could read the loader's identity at enrichment time.
    fn bpf_event_from(comm: &str, prog_type: u32, pid: u32) -> Event {
        Event {
            actor_pid: pid,
            ..bpf_event_typed(comm, prog_type)
        }
    }

    #[test]
    fn a_bpf_load_by_an_unknown_loader_is_critical() {
        // An implant-capable eBPF program (kprobe) loaded by a comm not on the
        // tight loader allowlist is the stealth-rootkit signature: Critical,
        // host-global (no cgroup narrowing), report-only (already installed).
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&bpf_event_typed("evil-loader", 2)) // 2 = KPROBE
            .expect("an unknown bpf loader must be a finding");
        assert!(matches!(f.event_type, FindingType::BpfLoad));
        assert_eq!(f.severity, Severity::Critical);
        assert!(!f.wants_kill); // report-only: killing the loader doesn't detach it
        assert_eq!(f.detail["reason"], "bpf_loader_not_allowlisted");
        assert_eq!(f.detail["bpf_cmd"], 5);
        assert_eq!(f.detail["prog_type"], 2);
        assert_eq!(f.detail["prog_type_name"], "kprobe");
    }

    #[test]
    fn a_bpf_load_by_an_allowlisted_loader_is_silent() {
        // Warden itself is on the default allow_loaders, so it never trips its own
        // security_bpf probe — even for an implant-capable program type. W2K-18
        // narrowed that fallback: the comm only carries a load whose executable could
        // NOT be read (the loader exited before enrichment). A live pid here would
        // make the exe readable and the load a finding, so the fixture pins a pid no
        // kernel can allocate — which is also the honest liveness answer for a loader
        // that is not there: `pidfd_open` refuses the number, so it is not `Alive`,
        // and W2K-29's new term leaves the name in charge.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&bpf_event_from("warden", 2, DEAD_PID)).is_none());
    }

    #[test]
    fn only_a_loader_the_kernel_says_is_gone_is_carried_by_its_name() {
        // W2K-29's new term, pinned as the pure decision it is: the name may clear a
        // load only on the kernel's own `ESRCH`. `Unknown` clears too — that is the
        // deliberate no-new-noise choice on a host that refuses `pidfd_open`, and it
        // keeps the pre-stage behaviour rather than inventing a finding — while a
        // positive `Alive` never clears, which is the whole evasion the register
        // named: rename to an allowlisted comm, load a kprobe, stay running.
        assert!(name_only_clears_a_load(Liveness::Gone));
        assert!(!name_only_clears_a_load(Liveness::Alive));
        assert!(name_only_clears_a_load(Liveness::Unknown(libc::EPERM)));
        assert!(name_only_clears_a_load(Liveness::Unknown(libc::ENOSYS)));
        assert!(name_only_clears_a_load(Liveness::Unknown(libc::EINVAL)));
    }

    #[test]
    fn the_pid_table_answers_alive_and_gone_without_proc() {
        // The oracle the judge now trusts has to separate its own answers before the
        // judge may act on them, so all three are measured here rather than assumed:
        // a live pid, one the kernel has just reaped, and a number the kernel refuses
        // to talk about. The middle arm is the point — `ESRCH` is the kernel's own
        // answer that nothing is at that number, and unlike a `/proc` read it is not
        // the same reply a `hidepid=` mount gives for a process it merely hides.
        let me = std::process::id();
        assert!(matches!(pidfd_liveness(me), Liveness::Alive));

        let mut child = std::process::Command::new("sleep")
            .arg("0")
            .spawn()
            .expect("the fixture needs a child to reap");
        let gone = child.id();
        child.wait().expect("reap the child");
        assert!(
            matches!(pidfd_liveness(gone), Liveness::Gone),
            "the reaped pid {gone} must answer ESRCH"
        );

        // A number outside the kernel's pid range is not an answer about liveness at
        // all, and the judge must not read it as one: the fixtures' `IMPOSSIBLE_PID`
        // measures as `EINVAL`, i.e. the same arm a seccomp-refused host lands in.
        assert!(
            !matches!(pidfd_liveness(IMPOSSIBLE_PID), Liveness::Alive),
            "an unallocatable number may not report a load as alive"
        );

        // `--explain` runs have no process behind the event, so a hypothetical must
        // never claim liveness — it stays on the name-only arm the finding describes.
        let det = Detector::for_explain(
            Config::safe_default(),
            FabricatedEvidence {
                exe: None,
                cmdline: None,
                cgroup: None,
            },
        );
        assert!(!det.loader_is_live(me));
        assert!(
            det.judge(&bpf_event_from("warden", 2, me)).is_none(),
            "an explanation must stay on the name-only arm it documents"
        );
    }

    #[test]
    fn a_live_loader_wearing_an_allowlisted_name_is_a_finding() {
        // The case W2K-29 is about, end to end: implant-capable type, allowlisted
        // comm, no readable executable — and the loader is REAL and still running.
        // kthreadd (pid 2) is what makes that deterministic: a kernel thread exists
        // on every Linux host and owns no executable, so `readlink /proc/2/exe`
        // answers `ENOENT` for uid 0 and uid 1000 alike, which is the same `None` the
        // daemon gets for a `hidepid=` process or an exited loader. The event claims
        // "warden" — the default allowlisted loader — because that claim is exactly
        // the string a process chooses for itself.
        let kernel_thread = 2u32;
        assert!(
            exe_of(kernel_thread).is_none(),
            "pid {kernel_thread} must be a live process with no readable executable"
        );
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&bpf_event_from("warden", 2, kernel_thread))
            .expect("a live loader whose exe cannot be read must not be cleared by its name");
        assert!(matches!(f.event_type, FindingType::BpfLoad));
        assert_eq!(f.severity, Severity::Critical);
        assert!(!f.wants_kill, "report-only: the program is installed");
        assert_eq!(
            f.detail["reason"],
            "bpf_loader_comm_allowlisted_loader_live_exe_unreadable"
        );
        assert_eq!(f.detail["loader_alive"], true);
        assert_eq!(f.detail["comm_allowlisted"], true);
        assert_eq!(f.detail["loader_exe"], serde_json::Value::Null);
        assert!(
            f.summary.contains("STILL RUNNING"),
            "the summary has to name the live loader"
        );
        // And it has to say what closes it, because pinning a comm answers nothing.
        assert!(f.detail["how_to_authorize"]
            .as_str()
            .unwrap_or_default()
            .contains("already exited"));
    }

    #[test]
    fn a_forged_comm_does_not_authorize_a_bpf_load() {
        // W2K-18 / spec P0-3: the old rule was `allow_loaders.contains(&event.comm)`,
        // and comm is a string a process sets for itself with one prctl(PR_SET_NAME)
        // call. So any process that renamed itself "warden" could install a kprobe —
        // the stealth-rootkit signature this rule exists to catch — and be silent.
        // The test binary IS a readable-executable actor, so it stands in for that
        // attacker: allowlisted name, executable that is not on any authorised list.
        let me = std::process::id();
        let my_exe = exe_of(me).expect("a running process has a readable /proc/self/exe");
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&bpf_event_from("warden", 2, me))
            .expect("a comm that only imitates an authorized loader must be a finding");
        assert_eq!(
            f.detail["reason"],
            "bpf_loader_comm_allowlisted_exe_not_authorized"
        );
        assert_eq!(f.detail["comm_allowlisted"], true);
        assert_eq!(f.detail["loader_exe"], exe_identity(&my_exe));
        assert_eq!(
            f.detail["authorization"],
            "executable path (allow_loader_exes)"
        );
        // The operator has to be told what to pin, and where.
        assert!(f.detail["how_to_authorize"]
            .as_str()
            .unwrap_or_default()
            .contains("allow_loader_exes"));
        assert!(
            f.summary.contains(exe_identity(&my_exe)),
            "the summary must name the executable it judged"
        );
        // The same actor under its own (unlisted) name is the same finding: the
        // verdict is the path, and the name only changes the `reason` label.
        let plain = det
            .judge(&bpf_event_from("someother", 2, me))
            .expect("an unknown loader with a readable exe is a finding");
        assert_eq!(plain.detail["reason"], "bpf_loader_not_allowlisted");
        assert_eq!(plain.detail["comm_allowlisted"], false);
    }

    #[test]
    fn an_exe_on_allow_loader_exes_authorizes_the_load_whatever_its_name() {
        // The point of the new field: identity, not label. Once the loader's absolute
        // path is pinned, the load is silent under a name nobody would have allowed —
        // and a COMM allowlist of one's own no longer buys a pass for a readable exe.
        let me = std::process::id();
        let raw_exe = exe_of(me).expect("readable /proc/self/exe");
        let my_exe = exe_identity(&raw_exe);
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loaders: vec![],
            allow_loader_exes: vec![my_exe.to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&bpf_event_from("totally-untrusted", 2, me))
            .is_none());
        assert!(det.judge(&bpf_event_from("warden", 29, me)).is_none());

        // A NON-matching exe list authorises nothing: adding a path is not the same
        // as configuring the rule, and a loader whose exe is readable must not fall
        // back to the comm list to escape it.
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loader_exes: vec!["/usr/sbin/definitely-not-this-loader".to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        let f = det
            .judge(&bpf_event_from("warden", 2, me))
            .expect("a readable exe that is not on the list must still fire");
        assert_eq!(f.detail["loader_exe"], my_exe);
    }

    #[test]
    fn a_load_whose_exe_could_not_be_read_falls_back_to_the_name_and_says_so() {
        // The residual gap, deliberately kept honest — for a record that carries no
        // kernel-stamped executable. A loader that exits before userspace enriches the
        // record has no readable exe, so with nothing else on the wire the name list
        // decides it, which is the weaker posture, and the finding must not describe it
        // as identity-based when it sees the other case. The tests below are the case
        // this one cannot cover: the same load, with the file named in the hook.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&bpf_event_from("evil-loader", 2, DEAD_PID))
            .expect("an unknown name with no readable exe is still a finding");
        assert!(f.detail["loader_exe"].is_null());
        assert_eq!(
            f.detail["authorization"],
            "name-only: the executable could not be read"
        );
        assert!(f.summary.contains("(executable unreadable)"));
        assert_eq!(f.detail["reason"], "bpf_loader_not_allowlisted");
        // Same actor, allowlisted name: silent, because there is no identity to weigh.
        assert!(det.judge(&bpf_event_from("warden", 2, DEAD_PID)).is_none());
    }

    /// A BPFLOAD record for a loader that is already gone (`DEAD_PID`, so `/proc` has
    /// nothing to add) plus the inode the hook stamped while it was still alive. This
    /// is the shape W2K-29 documented as unanswerable, and the only difference between
    /// it and the test above is the two `__u64` slots.
    fn bpf_event_kernel_named(comm: &str, exe: ExeIdentity) -> Event {
        Event {
            actor_exe_file: Some(exe),
            ..bpf_event_from(comm, 2, DEAD_PID)
        }
    }

    /// The identity of a file this test can count on: the test binary itself.
    fn exe_identity_of(path: &str) -> ExeIdentity {
        ExeIdentity::of_path(path).unwrap_or_else(|| panic!("{path} should resolve to an inode"))
    }

    #[test]
    fn the_file_the_kernel_named_authorises_a_load_whose_loader_is_already_gone() {
        // W2K-29's residual, closed: the loader exited, so `/proc/<pid>/exe` answers
        // nothing — but the record itself says which file ran, and that file IS the
        // authorised one. The pass is now identity-based rather than name-based, which
        // is the difference between a policy and a hope.
        let raw_exe = exe_of(std::process::id()).expect("readable /proc/self/exe");
        let my_exe = exe_identity(&raw_exe);
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loaders: vec![],
            allow_loader_exes: vec![my_exe.to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert!(
            det.judge(&bpf_event_kernel_named("warden", exe_identity_of(my_exe)))
                .is_none(),
            "a kernel-named file that is the authorised file must clear the load"
        );
    }

    #[test]
    fn an_allowlisted_name_does_not_clear_a_load_whose_kernel_named_file_is_not_authorised() {
        // The tightening this stage exists for. Until now, "comm is on allow_loaders" +
        // "the loader exited" was silent, because nothing could contradict the name.
        // Here the kernel contradicts it: the record names the file, and that file is
        // not what the operator authorised. Two real, distinct binaries are enough to
        // say so, and no forged name survives the comparison.
        let raw_exe = exe_of(std::process::id()).expect("readable /proc/self/exe");
        let my_exe = exe_identity(&raw_exe);
        let stranger = exe_identity_of("/bin/true");
        assert_ne!(
            stranger,
            exe_identity_of(my_exe),
            "the test needs two files that are not each other"
        );
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loader_exes: vec![my_exe.to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        let f = det
            .judge(&bpf_event_kernel_named("warden", stranger))
            .expect("an allowlisted comm cannot outrank the file the kernel named");
        assert_eq!(
            f.detail["reason"],
            "bpf_loader_kernel_named_exe_not_authorized"
        );
        assert_eq!(f.detail["comm_allowlisted"], true);
        assert!(f.detail["loader_exe"].is_null());
        // The numbers have to reach the operator, or the verdict is unfalsifiable.
        assert_eq!(f.detail["loader_exe_dev"], stranger.dev);
        assert_eq!(f.detail["loader_exe_ino"], stranger.ino);
        assert!(f.detail["authorization"].to_string().contains("dev/ino"));
        assert!(
            f.summary.contains(&stranger.label()),
            "the summary must quote the identity it judged"
        );
        assert!(f.detail["how_to_authorize"]
            .as_str()
            .unwrap_or_default()
            .contains("-inum"));
    }

    #[test]
    fn an_empty_loader_list_gives_the_kernel_inode_nothing_to_be_against() {
        // `allow_loader_exes` is empty in the shipped default, and an empty list is not
        // a deny: with nothing configured, the kernel's pair has no agreed meaning, so
        // this stage must leave the previous posture exactly where it was rather than
        // convert every unconfigured host's exited-loader-plus-allowlisted-name into a
        // finding. Silence here is a choice about what an unconfigured list claims.
        let mut cfg = Config::safe_default();
        assert!(
            cfg.bpf_rules.allow_loader_exes.is_empty(),
            "the premise of this test is the shipped default"
        );
        cfg.bpf_rules = BpfRules {
            allow_loader_exes: vec![],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&bpf_event_kernel_named(
                "warden",
                exe_identity_of("/bin/true")
            ))
            .is_none());
    }

    #[test]
    fn an_allowlist_that_resolves_to_no_file_gives_the_kernel_inode_no_verdict() {
        // A configured path that cannot be stat()ed — deleted, or living in a mount
        // namespace this agent cannot see, which is the container deployment shape —
        // contributes no inode. Treating "nothing resolved" as "no match" would convict
        // a load against a file the operator was never able to describe, and would
        // silently turn a packaging change into Critical findings.
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loader_exes: vec!["/nonexistent/warden-loader-under-test".to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&bpf_event_kernel_named(
                "warden",
                exe_identity_of("/bin/true")
            ))
            .is_none());
        // And the finding it does make for an unknown name says the truth about which
        // evidence ran out: name-only, with the kernel's pair still quoted.
        let f = det
            .judge(&bpf_event_kernel_named(
                "evil-loader",
                exe_identity_of("/bin/true"),
            ))
            .expect("an unknown name is still a finding");
        assert_eq!(f.detail["reason"], "bpf_loader_not_allowlisted");
        assert!(f.detail["authorization"]
            .as_str()
            .unwrap_or_default()
            .starts_with("kernel-captured executable file, compared against nothing"));
    }

    #[test]
    fn a_readable_exe_decides_first_and_the_kernel_inode_cannot_overrule_it() {
        // Precedence, because the two identities can disagree in one direction that
        // matters: the operator authorised this PATH, /proc read it, and the record
        // carries a different inode (a stale or forged claim, or simply a loader
        // re-exec'd from elsewhere). The readable path is the stronger, agreed-upon
        // basis — `allow_loader_exes` holds paths, and a path is what an operator can
        // audit — so the pass must not be revoked by the slot the kernel filled.
        let raw_exe = exe_of(std::process::id()).expect("readable /proc/self/exe");
        let my_exe = exe_identity(&raw_exe);
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loader_exes: vec![my_exe.to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        let alive = Event {
            actor_exe_file: Some(exe_identity_of("/bin/true")),
            ..bpf_event_from("totally-untrusted", 2, std::process::id())
        };
        assert!(
            det.judge(&alive).is_none(),
            "an authorised, readable exe is authorised whatever the spare slots say"
        );
    }

    #[test]
    fn a_readable_exe_that_is_not_authorised_is_not_rescued_by_a_matching_inode() {
        // The other half of that precedence, and the one that actually bites: `/proc`
        // says this process runs a file the operator never listed, and the record's
        // spare slots claim it is an authorised inode. Two identities that contradict
        // each other are not averaged — the path is what the list contains and what an
        // operator can audit, so it decides, and the contradiction is reported as the
        // finding it is. (A record cannot forge its own kernel stamp; a mismatch this
        // way means something is wrong with the record, the loader, or both.)
        let raw_exe = exe_of(std::process::id()).expect("readable /proc/self/exe");
        let my_exe = exe_identity(&raw_exe);
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            allow_loader_exes: vec!["/bin/cat".to_string()],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        let f = det
            .judge(&Event {
                actor_exe_file: Some(exe_identity_of("/bin/cat")),
                ..bpf_event_from("warden", 2, std::process::id())
            })
            .expect("a readable exe off the list is not made authorised by a spare slot");
        assert_eq!(
            f.detail["reason"],
            "bpf_loader_comm_allowlisted_exe_not_authorized"
        );
        assert_eq!(f.detail["loader_exe"], my_exe);
        assert_eq!(
            f.detail["authorization"],
            "executable path (allow_loader_exes)"
        );
    }

    #[test]
    fn a_benign_prog_type_load_is_silent_whoever_loads_it() {
        // THE false-positive fix: systemd (pid 1) loads cgroup_skb / cgroup_device
        // filters on every service start. Those cannot hook a syscall or hide a
        // process, so a load of a non-implant type is silent even by a comm that
        // is NOT on allow_loaders — the type gate short-circuits before the loader
        // check. Without this the box drowned in [critical] endpoint:bpf_load from
        // pid 1 (systemd) at every unit start/restart.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&bpf_event_typed("systemd", 8)).is_none()); // CGROUP_SKB
        assert!(det.judge(&bpf_event_typed("systemd", 15)).is_none()); // CGROUP_DEVICE
        assert!(det.judge(&bpf_event_typed("systemd", 1)).is_none()); // SOCKET_FILTER
        assert!(det.judge(&bpf_event_typed("systemd-network", 13)).is_none()); // SOCK_OPS
    }

    #[test]
    fn every_implant_capable_prog_type_by_an_unknown_loader_fires() {
        // Each stealth-capable kind — kprobe, tracepoint, xdp, raw_tracepoint,
        // tracing (fentry), lsm — is a finding when loaded by an unknown comm.
        let det = Detector::new(Config::safe_default());
        for &(t, name) in &[
            (2u32, "kprobe"),
            (5, "tracepoint"),
            (6, "xdp"),
            (17, "raw_tracepoint"),
            (26, "tracing"),
            (29, "lsm"),
        ] {
            let f = det
                .judge(&bpf_event_typed("stranger", t))
                .unwrap_or_else(|| panic!("prog_type {t} ({name}) must fire"));
            assert_eq!(f.detail["prog_type_name"], name);
        }
    }

    #[test]
    fn an_unreadable_prog_type_fails_toward_surfacing() {
        // If the kernel read of attr->prog_type failed, userspace sees UNSPEC (0).
        // We must NOT silently trust it — an unknown type by an unknown loader is
        // still a finding (fail open toward surfacing).
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&bpf_event_typed("stranger", 0)).is_some());
    }

    #[test]
    fn an_empty_bpf_watch_prog_types_disables_the_type_gate() {
        // The maximally-paranoid posture for a host that loads NO BPF of its own:
        // an empty watch_prog_types means every non-allowlisted load fires,
        // whatever its type (even a benign cgroup filter).
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            watch_prog_types: vec![],
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det.judge(&bpf_event_typed("systemd", 8)).is_some()); // CGROUP_SKB now fires
    }

    #[test]
    fn bpf_severity_is_configurable_and_falls_back_to_critical() {
        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            severity: "high".into(),
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert_eq!(
            det.judge(&bpf_event_typed("stranger", 2)).unwrap().severity,
            Severity::High
        );

        let mut cfg = Config::safe_default();
        cfg.bpf_rules = BpfRules {
            severity: "nonsense".into(),
            ..BpfRules::default()
        };
        let det = Detector::new(cfg);
        assert_eq!(
            det.judge(&bpf_event_typed("stranger", 2)).unwrap().severity,
            Severity::Critical
        );
    }

    // ---- mount (container escape / host-fs exposure) ---------------------------

    /// A MOUNT Event: `source` (device / bind path) rode in on filename; `flags`
    /// in aux (MS_BIND = 4096). The kernel captures no destination context, so
    /// these exercise the source/flags rules that are the whole verdict.
    fn mount_event(source: &str, flags: u32) -> Event {
        Event {
            kind: Kind::Mount,
            actor_pid: 4242,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: flags,
            ts_ns: 0,
            comm: "mount".into(),
            filename: source.to_string(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    #[test]
    fn a_bind_mount_of_a_watched_host_path_is_a_finding() {
        // The classic container escape: bind-mounting the host /etc into a new
        // mountpoint. Watched source, MS_BIND set ⇒ High, report-only, ANY actor.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&mount_event("/etc", 4096))
            .expect("a bind mount of a watched host path must fire");
        assert!(matches!(f.event_type, FindingType::MountEscape));
        assert_eq!(f.severity, Severity::High);
        assert!(!f.wants_kill); // report-only: the mount already took effect
        assert_eq!(f.detail["reason"], "mount_source_watched");
        assert_eq!(f.detail["bind_mount"], true);
    }

    #[test]
    fn the_docker_socket_bind_is_a_finding() {
        // Mounting the docker socket into a container is full daemon control — a
        // watched source in the defaults.
        let det = Detector::new(Config::safe_default());
        assert!(det
            .judge(&mount_event("/var/run/docker.sock", 4096))
            .is_some());
    }

    #[test]
    fn a_non_bind_mount_of_a_watched_source_is_silent_by_default() {
        // A plain filesystem mount (no MS_BIND) is routine admin work even when its
        // source substring is watched: mounting the block device /dev/sdb1, or a
        // tmpfs, must not fire under the default bind_only posture.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&mount_event("/dev/sdb1", 0)).is_none());
        assert!(det.judge(&mount_event("tmpfs", 0)).is_none());
    }

    #[test]
    fn an_unwatched_mount_source_is_silent() {
        // A mount whose source matches nothing in watch_sources is routine, even as
        // a bind mount (someone bind-mounting their own /home/user/data).
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&mount_event("/home/user/data", 4096)).is_none());
    }

    #[test]
    fn a_non_bind_mount_is_judged_when_bind_only_is_off() {
        // On a host where NO runtime mounts are expected, bind_only can be turned
        // off to police every mount of a watched source, bind or not.
        let mut cfg = Config::safe_default();
        cfg.mount_rules = MountRules {
            bind_only: false,
            ..MountRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det.judge(&mount_event("/dev", 0)).is_some());
    }

    #[test]
    fn an_empty_mount_source_is_silent() {
        // A virtual fs / remount with no source is not the escape shape.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&mount_event("", 4096)).is_none());
    }

    #[test]
    fn an_allowlisted_mount_source_is_silent() {
        // A volume our own orchestrator legitimately mounts: watched substring but
        // on allow_sources ⇒ silent, while a sibling still fires.
        let mut cfg = Config::safe_default();
        cfg.mount_rules = MountRules {
            allow_sources: vec!["/etc/warden".into()],
            ..MountRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det.judge(&mount_event("/etc/warden", 4096)).is_none());
        assert!(det.judge(&mount_event("/etc/shadow", 4096)).is_some());
    }

    #[test]
    fn an_empty_mount_watch_list_disables_the_verdict() {
        let mut cfg = Config::safe_default();
        cfg.mount_rules = MountRules {
            watch_sources: vec![],
            ..MountRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det.judge(&mount_event("/etc", 4096)).is_none());
    }

    #[test]
    fn sandbox_construction_bind_mounts_are_silent() {
        // THE mount false-positive fix. A desktop sandbox (bwrap, flatpak, the
        // polkit agent) assembles its mount namespace by bind-mounting dozens of
        // paths under a private staging root. Their sources CONTAIN "/dev",
        // "/etc", "/proc" as substrings — the old raw `contains()` match flagged
        // every one as a host escape (the 70-finding storm from polkit-agent /
        // bwrap). Under prefix-boundary rejection they are all silent.
        let det = Detector::new(Config::safe_default());
        for src in [
            "/oldroot/dev/null",
            "/oldroot/etc/fonts",
            "/oldroot/proc/cpuinfo",
            "/proc/self/fd/7",
            "/run/systemd/namespace-abc123/etc",
            "/run/user/1000/.flatpak/instance/dev",
            "/newroot/etc/resolv.conf",
        ] {
            assert!(
                det.judge(&mount_event(src, 4096)).is_none(),
                "sandbox source {src} must be silent"
            );
        }
    }

    #[test]
    fn a_real_host_bind_still_fires_after_boundary_matching() {
        // The other half of the fix: boundary matching must NOT stop catching real
        // escapes. A genuine bind of a host path — the watched dir itself, a child
        // under it, or a host-root bind that EXPOSES a watched dir — all still fire.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&mount_event("/dev", 4096)).is_some()); // exact watched dir
        assert!(det.judge(&mount_event("/etc/shadow", 4096)).is_some()); // child of /etc
        assert!(det.judge(&mount_event("/", 4096)).is_some()); // host root exposes /dev, /etc, …
        assert!(det.judge(&mount_event("/proc/sys", 4096)).is_some()); // child of /proc
    }

    #[test]
    fn boundary_matching_rejects_sibling_directories() {
        // A directory whose name merely STARTS with a watched path but is a
        // different component must not fire: "/etcetera" is not "/etc", "/devices"
        // is not "/dev". The old substring match would have flagged both.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&mount_event("/etcetera/config", 4096)).is_none());
        assert!(det.judge(&mount_event("/devices/pci0000", 4096)).is_none());
        assert!(det.judge(&mount_event("/rootkit-staging", 4096)).is_none());
    }

    #[test]
    fn a_configured_ignore_prefix_can_be_extended() {
        // ignore_source_prefixes is operator-tunable: adding a site-specific
        // staging root suppresses its internals while a real host bind still fires.
        let mut cfg = Config::safe_default();
        cfg.mount_rules = MountRules {
            ignore_source_prefixes: vec!["/var/lib/mysandbox".into()],
            ..MountRules::default()
        };
        let det = Detector::new(cfg);
        assert!(det
            .judge(&mount_event("/var/lib/mysandbox/etc/passwd", 4096))
            .is_none());
        // …but the default sandbox roots are gone now (we replaced the list), so a
        // bare /etc bind still fires — the ignore list narrows, it never widens.
        assert!(det.judge(&mount_event("/etc", 4096)).is_some());
    }

    /// A detector whose actor is the current (real) process, attributed to the app
    /// cgroup by its own cgroup path. Needed because W2K-05's exemption is gated on
    /// "inside the app cgroup", which an unresolvable fake pid can never satisfy.
    fn contained_detector(mount_rules: MountRules) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app.cgroup_contains =
            vec![cgroup_of(std::process::id()).expect("read the test process cgroup")];
        cfg.mount_rules = mount_rules;
        Detector::new(cfg)
    }

    /// A throwaway directory to bind through an fd, removed on drop.
    struct TempTarget(std::path::PathBuf);

    impl TempTarget {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("warden-mount-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&p).expect("create temp target");
            TempTarget(p)
        }
    }

    impl Drop for TempTarget {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_contained_actor_cannot_hide_a_host_bind_behind_proc_self_fd() {
        // W2K-05: mount(2) resolves /proc/self/fd/N through the CALLER's fd table,
        // so the literal source reads as sandbox plumbing while the target is any
        // path the fd points at. For an actor inside the app cgroup — a contained
        // attacker breaking out — the prefix no longer silences it: the source is
        // resolved through that actor's /proc and the real target is judged.
        let dir = TempTarget::new("fd");
        let file = std::fs::File::open(&dir.0).expect("open the bind target as an fd");
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);

        let det = contained_detector(MountRules {
            watch_sources: vec![dir.0.to_string_lossy().into_owned()],
            ..MountRules::default()
        });
        let ev = mount_event_by(
            "mount",
            std::process::id(),
            &format!("/proc/self/fd/{fd}"),
            4096,
        );
        let f = det
            .judge(&ev)
            .expect("an fd indirection to a watched dir must fire for a contained actor");
        assert_eq!(f.detail["reason"], "mount_source_indirection");
        assert_eq!(
            f.detail["resolved_source"].as_str(),
            std::fs::canonicalize(&dir.0)
                .ok()
                .as_deref()
                .and_then(|p| p.to_str()),
        );
    }

    #[test]
    fn an_indirection_to_an_unwatched_path_stays_silent() {
        // The same shape resolving to an ordinary path is not an exposure; the
        // resolution exists to judge the TARGET, not to convict the indirection.
        let dir = TempTarget::new("unwatched");
        let file = std::fs::File::open(&dir.0).expect("open the bind target as an fd");
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);

        let det = contained_detector(MountRules::default());
        assert!(det
            .judge(&mount_event_by(
                "mount",
                std::process::id(),
                &format!("/proc/self/fd/{fd}"),
                4096,
            ))
            .is_none());
    }

    #[test]
    fn an_unresolvable_proc_indirection_from_a_contained_actor_fires() {
        // The fd was closed between mount(2) and judgment, or points at a deleted
        // file. Silence there would be a one-line evasion, so the verdict fails
        // closed — but only for the fd/root/cwd SHAPE, never for staging roots.
        let det = contained_detector(MountRules::default());
        let f = det
            .judge(&mount_event_by(
                "mount",
                std::process::id(),
                "/proc/self/fd/987654",
                4096,
            ))
            .expect("an unresolvable fd indirection must fire");
        assert_eq!(f.detail["reason"], "mount_source_unresolved");
    }

    #[test]
    fn a_contained_actor_keeps_the_exemption_for_staging_roots() {
        // /oldroot and /run/user/… are literal staging paths, not fd indirections;
        // binding one mounts the sandbox's own staging dir, so the storm-suppression
        // still applies even for a contained actor.
        let det = contained_detector(MountRules::default());
        for src in ["/oldroot/etc/fonts", "/run/user/1000/.flatpak/instance/dev"] {
            assert!(
                det.judge(&mount_event_by("mount", std::process::id(), src, 4096))
                    .is_none(),
                "staging root {src} must stay silent"
            );
        }
    }

    #[test]
    fn an_outside_actor_keeps_the_sandbox_prefix_exemption() {
        // The desktop storm actors are OUTSIDE the app cgroup (unknown pid here),
        // and their fd-shaped sources stay exempt: no regression for bwrap/flatpak.
        let det = Detector::new(Config::safe_default());
        assert!(det
            .judge(&mount_event_by("bwrap", 424242, "/proc/self/fd/7", 4096))
            .is_none());
    }

    #[test]
    fn the_privatedevices_pseudo_device_binds_are_silent() {
        // THE mount fix. A hardened systemd unit (PrivateDevices=, ProtectSystem=)
        // builds its private /dev by bind-mounting the REAL host pseudo-devices,
        // each to the SAME target path inside its private namespace (/dev/null ->
        // /dev/null). The source is a genuine child of the watched "/dev" tree and
        // the destination is identical, so neither source-prefix nor dest-marker
        // discrimination can silence it — that is what made both Option-2 and the
        // v2 destination approach fire the polkit-agent / logind /dev bind storm.
        // The fix is an EXACT-match allowlist of exactly this well-known set: each
        // grants no host access, so each is silent, and nothing outside the set is.
        let det = Detector::new(Config::safe_default());
        for src in [
            "/dev/null",
            "/dev/zero",
            "/dev/full",
            "/dev/random",
            "/dev/urandom",
            "/dev/tty",
            "/dev/pts",
            "/dev/ptmx",
            "/dev/shm",
            "/dev/mqueue",
            "/dev/hugepages",
        ] {
            assert!(
                det.judge(&mount_event(src, 4096)).is_none(),
                "PrivateDevices bind of {src} must be silent"
            );
        }
    }

    #[test]
    fn the_pseudo_device_allowlist_is_exact_not_a_prefix() {
        // The allowlist must be EXACT so it silences only the harmless leaves. A
        // deeper path that merely starts with an allowlisted name (an attacker
        // staging "/dev/shm/payload", or a bind of the "/dev/pts/ptmx" master) is
        // NOT an allowlisted leaf and stays under the watched-source verdict.
        let det = Detector::new(Config::safe_default());
        assert!(
            det.judge(&mount_event("/dev/shm/payload", 4096)).is_some(),
            "a child of an allowlisted pseudo-device is not itself allowlisted"
        );
    }

    #[test]
    fn a_whole_dev_or_raw_device_bind_still_fires() {
        // The allowlist stays safe because an escape never binds a single benign
        // pseudo-device — it binds the whole /dev tree (every real device node), a
        // raw disk, kernel memory, or the device mapper. None of these EQUALS a
        // listed leaf, so all still fire.
        let det = Detector::new(Config::safe_default());
        for src in [
            "/dev",
            "/dev/sda",
            "/dev/sda1",
            "/dev/mem",
            "/dev/mapper/root",
        ] {
            assert!(
                det.judge(&mount_event(src, 4096)).is_some(),
                "a bind of {src} is an escape shape and must fire"
            );
        }
    }

    #[test]
    fn the_pseudo_device_allowlist_is_case_insensitive() {
        // Kernel device strings are lowercase in practice, but the exact match is
        // case-insensitive so a capitalised variant can never sneak the verdict on.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&mount_event("/DEV/NULL", 4096)).is_none());
    }

    #[test]
    fn other_watched_binds_are_unaffected_by_the_pseudo_device_allowlist() {
        // The allowlist is scoped to the /dev pseudo-device set; it must not blunt
        // any other escape verdict. The docker socket, /etc, and the host root are
        // not pseudo-devices and keep firing exactly as before.
        let det = Detector::new(Config::safe_default());
        assert!(det
            .judge(&mount_event("/var/run/docker.sock", 4096))
            .is_some());
        assert!(det.judge(&mount_event("/etc", 4096)).is_some());
        assert!(det.judge(&mount_event("/", 4096)).is_some());
    }

    // ---- path-boundary matching helpers ----------------------------------------

    #[test]
    fn has_path_prefix_respects_component_boundaries() {
        assert!(has_path_prefix("/etc", "/etc")); // exact
        assert!(has_path_prefix("/etc/shadow", "/etc")); // child
        assert!(!has_path_prefix("/etcetera", "/etc")); // sibling, not a child
        assert!(!has_path_prefix("/et", "/etc")); // shorter
                                                  // A prefix carrying its own boundary matches a partial component.
        assert!(has_path_prefix("/oldroot/dev", "/oldroot/"));
        // A prefix ending in '-' matches the templated-name family (systemd).
        assert!(has_path_prefix(
            "/run/systemd/namespace-xyz",
            "/run/systemd/namespace-"
        ));
        assert!(!has_path_prefix("/anything", "")); // empty prefix never matches
    }

    #[test]
    fn watch_overlaps_source_matches_both_directions() {
        // source under watch (grafting /etc/shadow, watch /etc)
        assert!(watch_overlaps_source("/etc/shadow", "/etc"));
        // watch under source (grafting host /, watch /etc — the root exposes it)
        assert!(watch_overlaps_source("/", "/etc"));
        assert!(watch_overlaps_source("/var/run", "/var/run/docker.sock"));
        // no overlap
        assert!(!watch_overlaps_source("/home/user", "/etc"));
        assert!(!watch_overlaps_source("/etcetera", "/etc"));
    }

    // ---- access (guarded-inode enforcement) ------------------------------------

    /// An ACCESS Event: an unauthorised actor touched a guarded inode. `hook` is
    /// which LSM chokepoint saw it, `intent` what the op would do, `denied` whether
    /// the guard was armed (returned -EPERM) or shadowing (would-deny, allowed).
    /// The guarded inode's identity and authorized uid ride in the AccessInfo, as
    /// the decode folds them out of the overloaded raw slots.
    fn access_event(hook: AccessHook, intent: u32, denied: bool, actor_uid: u32) -> Event {
        Event {
            kind: Kind::Access,
            actor_pid: 6060,
            actor_ppid: 1,
            actor_uid,
            target_pid: 0,
            aux: 0,
            ts_ns: 0,
            comm: "intruder".into(),
            filename: String::new(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: Some(AccessInfo {
                hook,
                intent,
                denied,
                dev: 0x800002,
                ino: 424242,
                authorized_uid: 991,
            }),
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    #[test]
    fn uid_canaries_never_appear_in_operator_facing_summary_text() {
        // Distinctive synthetic account ids, never real uids. They remain in the
        // structured detail for remote telemetry; only the human-readable string
        // that can flow into a log line must stop carrying them.
        const OLD_UID_CANARY: u32 = 424_242_001;
        const AUTHORIZED_UID_CANARY: u32 = 424_242_991;

        let cred_det = cred_detector_with(CredRules::default());
        let access_det = Detector::new(Config::safe_default());
        let creds = creds_event("sudo", OLD_UID_CANARY, 0, 0, 0);
        let mut access = access_event(AccessHook::Open, WARDEN_INTENT_READ, true, 0);
        if let Some(a) = access.access.as_mut() {
            a.authorized_uid = AUTHORIZED_UID_CANARY;
        }

        let cred_finding = cred_det
            .judge(&creds)
            .expect("a synthetic root transition must fire");
        let access_finding = access_det
            .judge(&access)
            .expect("a synthetic guarded denial must fire");

        assert!(
            !cred_finding.summary.contains(&OLD_UID_CANARY.to_string()),
            "privilege summary must not carry an account id"
        );
        assert_eq!(
            cred_finding.detail["old_uid"], OLD_UID_CANARY,
            "structured telemetry keeps the account id"
        );
        assert!(
            !access_finding
                .summary
                .contains(&AUTHORIZED_UID_CANARY.to_string()),
            "guarded-access summary must not carry an account id"
        );
        assert_eq!(
            access_finding.detail["authorized_uid"], AUTHORIZED_UID_CANARY,
            "structured telemetry keeps the authorized account id"
        );

        let proc = ProcessInfo {
            pid: 4242,
            ppid: 1,
            uid: OLD_UID_CANARY,
            comm: "canary-comm".to_string(),
            exe: Some("/usr/bin/canary".to_string()),
            cmdline: None,
            cgroup: None,
            starttime: Some(7),
        };
        let note = identity_note(&proc);
        assert!(
            !note.contains(&OLD_UID_CANARY.to_string()),
            "identity note must not carry an account id"
        );
    }

    #[test]
    fn an_armed_guarded_access_denial_is_a_high_finding() {
        // The crown-jewels tripwire firing: an unauthorised uid tried to open a
        // guarded file for read and the armed guard returned -EPERM in-kernel.
        // High severity, report-only (the denial IS the response — no kill).
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&access_event(
                AccessHook::Open,
                WARDEN_INTENT_READ,
                true,
                1000,
            ))
            .expect("an armed guarded-file denial must fire");
        assert!(matches!(f.event_type, FindingType::AccessDenied));
        assert_eq!(f.severity, Severity::High);
        assert!(!f.wants_kill); // the -EPERM already blocked it; nothing to kill
        assert_eq!(f.detail["reason"], "guarded_access_denied");
        assert_eq!(f.detail["denied"], true);
        assert_eq!(f.detail["hook"], "open");
        assert_eq!(f.detail["intent"], "read");
        assert_eq!(f.detail["authorized_uid"], 991);
        assert_eq!(f.detail["actor_uid"], 1000);
    }

    #[test]
    fn a_shadow_would_deny_access_is_a_medium_finding() {
        // The pre-arming dry run: the SAME unauthorised access, but the guard is
        // shadowing (CFG_ENFORCE_ARM=0), so it observed and allowed it through.
        // Medium — not prevention yet, but a true preview of what arming denies.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&access_event(
                AccessHook::Unlink,
                WARDEN_INTENT_WRITE,
                false,
                0,
            ))
            .expect("a shadow would-deny must still surface");
        assert!(matches!(f.event_type, FindingType::AccessDenied));
        assert_eq!(f.severity, Severity::Medium);
        assert!(!f.wants_kill);
        assert_eq!(f.detail["reason"], "guarded_access_shadow");
        assert_eq!(f.detail["denied"], false);
        assert_eq!(f.detail["hook"], "unlink");
        assert_eq!(f.detail["intent"], "write");
    }

    #[test]
    fn an_access_event_without_decoded_info_is_silent() {
        // A malformed ACCESS record (access folded to None) has nothing to judge;
        // it must not panic or fabricate a finding.
        let det = Detector::new(Config::safe_default());
        let mut e = access_event(AccessHook::Open, WARDEN_INTENT_READ, true, 1000);
        e.access = None;
        assert!(det.judge(&e).is_none());
    }

    // ---- ptrace mode+actor gate (live FP fix: self_tamper storm) ---------------

    /// A PTRACE Event: `comm` tried to ptrace the protected pid with `mode` bits
    /// (0x01 = PTRACE_MODE_READ /proc introspection, 0x02 = PTRACE_MODE_ATTACH
    /// real attach/inject). The kernel only emits for a protected target, so
    /// reaching the judge already means the target is protected.
    fn ptrace_event(comm: &str, mode: u32) -> Event {
        Event {
            kind: Kind::Ptrace,
            // A pid no kernel can allocate, so `/proc/<pid>/exe` is unreadable here
            // for the same reason the bpf fixtures pin it: whether the reader's
            // executable could be resolved is the variable these tests decide on,
            // and a number that happens to be free on this machine is not a fixture.
            // One below [`IMPOSSIBLE_PID`] rather than equal to it, because
            // `Detector::for_explain` *becomes* that pid: `self_pid` is set there so
            // a real actor can never trip the ptrace READ self-exemption, and an
            // actor of the same number would be exempted by it instead of judged.
            actor_pid: IMPOSSIBLE_PID - 1,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 2387,
            aux: mode,
            ts_ns: 0,
            comm: comm.into(),
            filename: String::new(),
            dest: None,
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }

    #[test]
    fn a_ptrace_attach_on_the_protected_pid_is_high() {
        // The headline T7/T8 threat: a real attach/inject (PTRACE_ATTACH, SEIZE,
        // process_vm_writev, /proc/<pid>/mem) carries PTRACE_MODE_ATTACH (0x02) and
        // must always fire High — even from a comm on the benign-reader list.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&ptrace_event("gdb", 0x02))
            .expect("an attach-mode ptrace of the protected pid must fire");
        assert!(matches!(f.event_type, FindingType::SelfTamper));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detail["is_attach"], true);
        // Even a benign-reader comm cannot silence an ATTACH.
        let f2 = det
            .judge(&ptrace_event("fuser", 0x06)) // ATTACH|READ
            .expect("attach bit set ⇒ fires regardless of comm");
        assert_eq!(f2.severity, Severity::High);
    }

    #[test]
    fn a_benign_reader_proc_read_is_silent() {
        // THE self_tamper storm fix: fuser/journald/systemd walking /proc/<pid>/*
        // issue PTRACE_MODE_READ (0x01, no 0x02). Those 192 benign High lines are
        // now silent — the three default benign_reader_comms.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&ptrace_event("fuser", 0x01)).is_none());
        assert!(det.judge(&ptrace_event("systemd-journal", 0x01)).is_none()); // 15-char trunc
        assert!(det.judge(&ptrace_event("systemd", 0x01)).is_none());
        // Docker's runtime joining a container's namespaces; it exits before its
        // exe can be resolved, so the comm is what identifies it.
        assert!(det.judge(&ptrace_event("runc", 0x01)).is_none());
        assert!(det.judge(&ptrace_event("runc:[1:CHILD]", 0x01)).is_none());
    }

    #[test]
    fn a_container_runtime_read_is_silent_but_only_by_exact_path() {
        // Docker's healthcheck execs into the app every few seconds; runc joins
        // the target's namespaces through /proc/<pid>/ns/*, which the kernel
        // reports as a READ of the protected pid. The runtime's resolved path is
        // the allowlist key — its comm alone is not, because a comm is one
        // prctl(PR_SET_NAME) away from impersonating the runtime.
        let det = Detector::new(Config::safe_default());
        assert!(det.benign_reader("custom-runtime", Some("/usr/bin/runc")));
        assert!(!det.benign_reader("custom-runtime", Some("/tmp/runc")));
        assert!(!det.benign_reader("custom-runtime", Some("/usr/bin/runc-helper")));
        assert!(
            !det.benign_reader("custom-runtime", None),
            "an actor whose exe cannot be resolved is not exempt by path"
        );
        // The runtime itself is exempt by comm too: it exits before enrich can
        // resolve its exe, so the path allowlist alone misses the real reads.
        assert!(det.benign_reader("runc", None));
        assert!(det.benign_reader("runc:[1:CHILD]", None));
    }

    #[test]
    fn a_parent_reaping_its_own_child_is_not_a_takedown() {
        // Docker reaping a timed-out healthcheck, a pool parent recycling a
        // worker, systemd restarting a unit: each aims a lethal signal at a
        // protected pid from the victim's own parent. The kernel marks that at
        // the hook; it must not become a Critical finding, or an armed responder
        // would kill the supervisor.
        let det = Detector::new(Config::safe_default());

        let mut reaping = signal_event(4242, "containerd-shim", libc::SIGKILL as u32, 131264);
        reaping.signal_from_parent = true;
        assert!(
            det.judge(&reaping).is_none(),
            "a supervisor terminating the child it spawned is supervision, not takedown"
        );

        let f = det
            .judge(&signal_event(4243, "bash", libc::SIGKILL as u32, 131264))
            .expect("a signal from outside the process tree must still fire");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn a_process_that_aimed_a_lethal_signal_at_itself_is_not_an_attack() {
        // W2K-04, the reachable half: a protected process on its way out — glibc's
        // abort() or a Rust panic tgkill-s SIGABRT to its OWN thread group — arrives
        // as actor == target. It must stay visible ("why did the signer abort?" is the
        // operator's question) and must never arm the responder, because the victim is
        // already dying and a kill aimed at a recycled pid hits whatever lives there
        // next.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        let mut crashing = signal_event(131264, "wallet-signer", libc::SIGABRT as u32, 131264);
        crashing.signal_delivery = Some(SignalDelivery::Tkill);
        let f = det
            .judge(&crashing)
            .expect("a protected process killing itself is still an incident");
        assert_eq!(f.severity, Severity::Medium);
        assert!(
            !f.wants_kill,
            "a self-termination must not arm the responder"
        );
        assert_eq!(f.detail["reason"], "self_termination");
        assert_eq!(f.detail["delivery"], "tkill");
        assert!(f.summary.contains("self-termination"));
        // The label is deliberately the one Sentinel's allowlist already accepts: there
        // is no host slot for "the process ended itself", and inventing one gets the
        // WHOLE batch refused (§38 / F-38.1 of the evaluation report).
        assert!(matches!(f.event_type, FindingType::SelfTamper));

        // kill(getpid(), SIGKILL) is the same shape by a different call.
        let suicide = signal_event(131264, "wallet-signer", libc::SIGKILL as u32, 131264);
        let f = det
            .judge(&suicide)
            .expect("a self-directed SIGKILL is still reported");
        assert_eq!(f.severity, Severity::Medium);
        assert!(!f.wants_kill);
        assert_eq!(f.detail["delivery"], "kill");
    }

    #[test]
    fn the_delivery_class_names_the_call_without_softening_an_outside_attack() {
        // The other half of W2K-04: a record now says WHICH call aimed the signal, and
        // an actor that is not the victim keeps the attack tier and the kill request
        // whatever the class — including the labels a sender chose rather than the calls
        // it made, which are reported as what they are and soften nothing.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        let f = det
            .judge(&signal_event(
                4244,
                "attacker",
                libc::SIGKILL as u32,
                131264,
            ))
            .expect("a plain kill of a protected pid is a takedown attempt");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.wants_kill);
        assert_eq!(f.detail["delivery"], "kill");
        assert_eq!(
            f.detail["reason"], "unauthorized_signal",
            "an attack is named unauthorized, not folded into some authorized class"
        );
        assert!(f.summary.contains("takedown attempt"));

        for (class, name) in [
            (SignalDelivery::Queue, "sigqueue"),
            (SignalDelivery::Timer, "timer_claimed"),
            (SignalDelivery::Mesgq, "mqueue_claimed"),
            (SignalDelivery::Asyncio, "aio_or_usb"),
            (SignalDelivery::Sigio, "sigio_claimed"),
            (SignalDelivery::Tkill, "tkill"),
        ] {
            let mut aimed = signal_event(4245, "attacker", libc::SIGKILL as u32, 131264);
            aimed.signal_delivery = Some(class);
            let f = det
                .judge(&aimed)
                .expect("an outside actor fires for every delivery class");
            assert_eq!(f.severity, Severity::Critical, "{name} was softened");
            assert!(f.wants_kill, "{name} disarmed the responder");
            assert_eq!(f.detail["delivery"], name, "the class was lost");
        }

        // W2K-41 moved the severity gate onto the kernel's own disposition table, and the
        // arm list stayed where W2K-42 left it. SIGUSR1 terminates a process that has not
        // caught it, so an outside actor aiming it at the guardian is a takedown attempt at
        // Critical — and still not one of the five numbers the responder may kill for.
        // The claim is deliberately about the number, not about the target's handler table:
        // reading /proc/<pid>/status to learn what the target catches would cost a
        // ptrace-visible read per record, which is the very noise W2K-41 is about.
        let mut poke = signal_event(4246, "attacker", libc::SIGUSR1 as u32, 131264);
        poke.signal_delivery = Some(SignalDelivery::Queue);
        let f = det
            .judge(&poke)
            .expect("a signal that terminates by default at a protected pid surfaces");
        assert_eq!(f.severity, Severity::Critical);
        assert!(!f.wants_kill, "the arm list is not widened by the table");
        assert_eq!(f.detail["signal_effect"], "terminates");
        assert_eq!(f.detail["reason"], "unauthorized_signal");
        assert!(f.summary.contains("takedown attempt"));

        // An absent class — a hand-built Event, never a decoded record — is the attack
        // class, the same rule the hook applies to an si_code it could not read.
        let mut blind = signal_event(4247, "attacker", libc::SIGKILL as u32, 131264);
        blind.signal_delivery = None;
        let f = det
            .judge(&blind)
            .expect("an unreadable class is still an attack");
        assert_eq!(f.detail["delivery"], "kill");
        assert!(f.wants_kill);
    }

    #[test]
    fn a_class_whose_actor_may_name_no_sender_never_gets_the_self_termination_pass() {
        // The self-termination downgrade rests on `actor_pid == target_pid`, which is
        // only that process's own act when the hook ran in the sender's context. The
        // usbfs completion calls `security_task_kill()` from whatever task the CPU was
        // running (kernel/signal.c `kill_pid_usb_asyncio`), so an SI_ASYNCIO-shaped
        // record can show actor == target with no self-directed send at all — and a
        // sender can name -4 anyway. The shape therefore buys no pass: a lethal one
        // stays Critical and arms the responder, exactly like an outside actor.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        let mut aimed = signal_event(131264, "wallet-signer", libc::SIGKILL as u32, 131264);
        aimed.signal_delivery = Some(SignalDelivery::Asyncio);
        let f = det
            .judge(&aimed)
            .expect("an asyncio-shaped record at a protected pid still surfaces");
        assert_eq!(f.severity, Severity::Critical);
        assert!(
            f.wants_kill,
            "a class that cannot prove who aimed the signal must not stand the responder down"
        );
        assert_eq!(f.detail["delivery"], "aio_or_usb");
        assert_eq!(
            f.detail["reason"], "unauthorized_signal",
            "actor == target is not a verdict when the actor may be an interrupted task"
        );
        assert!(f.summary.contains("takedown attempt"));

        // The kernel-set classes keep the pass, and the invariant is exactly the class
        // list: every other class is reached only from the sender's own context.
        for class in [
            SignalDelivery::User,
            SignalDelivery::Tkill,
            SignalDelivery::Queue,
            SignalDelivery::Timer,
            SignalDelivery::Mesgq,
            SignalDelivery::Sigio,
        ] {
            assert!(
                class.actor_names_the_sender(),
                "{class:?} is sent in the sender's context and must keep the pass"
            );
            let mut self_aimed =
                signal_event(131264, "wallet-signer", libc::SIGKILL as u32, 131264);
            self_aimed.signal_delivery = Some(class);
            let f = det.judge(&self_aimed).expect("self-directed send surfaces");
            assert_eq!(
                f.severity,
                Severity::Medium,
                "{class:?} kept the attack tier"
            );
            assert!(!f.wants_kill, "{class:?} armed the responder on itself");
        }
        assert!(
            !SignalDelivery::Asyncio.actor_names_the_sender(),
            "the usbfs completion is the one context that names no sender"
        );
    }

    #[test]
    fn an_unknown_actor_proc_read_surfaces_at_medium() {
        // A READ-mode ptrace of the protected signer by an actor NOT on the benign
        // list (reading /proc/<pid>/environ for env-injected secrets, or maps for
        // ASLR recon) is credential-recon worth surfacing — Medium, below an
        // ATTACH's High, but never silent. This is the blind-spot the verifier
        // flagged against a blanket READ silence.
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&ptrace_event("curl", 0x01))
            .expect("an unknown actor reading the protected pid's /proc must surface");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.detail["is_attach"], false);
        assert!(!f.wants_kill); // a read never kills
    }

    #[test]
    fn the_guardian_reading_its_own_protected_pids_is_silent() {
        // Live storm: the proc scanner refreshes each protected pid's identity by
        // reading /proc, which raises ptrace_access_check from our own pid ~50
        // times a second. That is supervision, not intrusion, and it filled the
        // bridge spool. A foreign reader keeps surfacing; our own ATTACH would
        // still be reported.
        let det = Detector::new(Config::safe_default());

        let mut ours = ptrace_event("warden", 0x01);
        ours.actor_pid = std::process::id();
        assert!(
            det.judge(&ours).is_none(),
            "the guardian's own /proc read must not become a finding"
        );

        assert!(
            det.judge(&ptrace_event("curl", 0x01)).is_some(),
            "a foreign read must still surface"
        );

        let mut own_attach = ptrace_event("warden", 0x03);
        own_attach.actor_pid = std::process::id();
        assert!(
            det.judge(&own_attach).is_some(),
            "an ATTACH from our own pid would be a bug worth reporting"
        );
    }

    // ---- W2K-36/41/42: what the number does, and who was allowed to send it -----

    /// The signal severity gate rests entirely on this table, so the table itself is
    /// pinned: four numbers freeze the target, four cannot touch it, and everything
    /// else the kernel can deliver takes the process out of service unless the target
    /// catches it. A wrong row here is a wrong finding, not a wrong word.
    #[test]
    fn only_the_freeze_and_resume_numbers_are_inert() {
        let inert: Vec<u32> = (1..=31u32)
            .filter(|s| !signal_effect(*s).stops_the_target())
            .collect();
        assert_eq!(
            inert,
            vec![
                libc::SIGCHLD as u32,
                libc::SIGCONT as u32,
                libc::SIGURG as u32,
                libc::SIGWINCH as u32,
            ]
        );
        let frozen: Vec<u32> = (1..=31u32)
            .filter(|s| signal_effect(*s) == SignalEffect::Freezes)
            .collect();
        assert_eq!(
            frozen,
            vec![
                libc::SIGSTOP as u32,
                libc::SIGTSTP as u32,
                libc::SIGTTIN as u32,
                libc::SIGTTOU as u32,
            ]
        );
        // A number this table does not know is the harsher reading, not a free pass.
        assert_eq!(signal_effect(64), SignalEffect::Terminates);
        assert_eq!(signal_effect(0), SignalEffect::Terminates);
    }

    #[test]
    fn a_number_the_kernel_would_not_act_on_is_recorded_at_info() {
        // W2K-41's storm was largely this class: SIGCONT and SIGWINCH pokes at the
        // guardian. They cannot take it out of service, so they are not takedown
        // attempts — but they are recorded, because "who poked the signer" is the
        // operator's question and the answer is the same shape as the attack's.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        for sig in [libc::SIGCONT, libc::SIGWINCH, libc::SIGCHLD, libc::SIGURG] {
            let f = det
                .judge(&signal_event(
                    IMPOSSIBLE_PID - 1,
                    "attacker",
                    sig as u32,
                    131264,
                ))
                .expect("a poke at a protected pid is still a record");
            assert_eq!(f.severity, Severity::Info, "signal {sig} was escalated");
            assert_eq!(f.detail["signal_effect"], "inert");
            assert_eq!(f.detail["reason"], "inert_signal");
            assert!(
                f.summary.contains("control traffic"),
                "summary must name control traffic"
            );
            assert!(
                !f.wants_kill,
                "a signal that cannot stop the target must not arm a kill"
            );
        }

        // SIGSTOP is the half that looks inert and is not: a frozen signer signs
        // nothing and beats no heartbeat, so it keeps the attack tier — and it has
        // always been on the responder's arm list.
        let f = det
            .judge(&signal_event(
                IMPOSSIBLE_PID - 1,
                "attacker",
                libc::SIGSTOP as u32,
                131264,
            ))
            .expect("freezing a protected pid surfaces");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["signal_effect"], "freezes");
        assert!(f.wants_kill);
    }

    #[test]
    fn the_service_manager_tearing_down_its_unit_is_not_a_takedown() {
        // W2K-36, and the one the live sweep proved: `systemctl stop` of a unit whose
        // protected process is not pid 1's own child (so the parent exemption cannot
        // reach it) used to be a Critical takedown attempt with a kill request behind
        // it. The sender's tgid was read out of its task struct, so the number 1 is
        // not a name someone chose — it is the service manager, and stopping a unit
        // is what it exists to do.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        for sig in [libc::SIGTERM, libc::SIGKILL, libc::SIGSTOP, libc::SIGHUP] {
            let f = det
                .judge(&signal_event(1, "systemd", sig as u32, 131264))
                .expect("a unit teardown aimed at a protected pid is still recorded");
            assert_eq!(
                f.severity,
                Severity::Low,
                "signal {sig} kept the attack tier"
            );
            assert_eq!(f.detail["reason"], "service_control");
            assert!(
                !f.wants_kill,
                "counter-killing pid 1 would take the host down, whatever the number"
            );
            assert!(
                f.summary.contains("service control"),
                "summary must name service control"
            );
            let authorization = f.detail["authorization"].as_str().unwrap_or_default();
            assert!(
                authorization.contains("init, a pid number no other task can hold"),
                "the finding must say WHY this sender was believed"
            );
        }

        // The effect still rides along, so a reader can tell a freeze from a kill
        // without re-deriving it from the number.
        let f = det
            .judge(&signal_event(1, "systemd", libc::SIGSTOP as u32, 131264))
            .unwrap();
        assert_eq!(f.detail["signal_effect"], "freezes");
        let f = det
            .judge(&signal_event(1, "systemd", libc::SIGTERM as u32, 131264))
            .unwrap();
        assert_eq!(f.detail["signal_effect"], "terminates");
    }

    #[test]
    fn pid_zero_names_no_task_and_is_never_called_init() {
        // `--explain` builds a hypothetical actor whose pid is 0, and the old
        // `pid <= 1` test handed that actor the one sentence that makes a sender look
        // authorized. The verdict was never wrong (only `actor_pid == 1` earns
        // `service_control`); the *evidence* was, and the evidence is what an operator
        // reads.
        let mut p = proc_evidence("kill", None, None);

        p.pid = 0;
        let zero = identity_note(&p);
        assert!(
            zero.contains("names no task"),
            "pid 0 must be disclosed as the absence of a sender"
        );
        assert!(
            !zero.contains("init"),
            "pid 0 is not init, and saying it is borrows init's authority for a nobody"
        );

        p.pid = 1;
        let one = identity_note(&p);
        assert!(
            one.contains("actor pid 1 is init, a pid number no other task can hold"),
            "pid 1 must still be named, or the demotion it earns has no stated basis"
        );

        p.pid = 4242;
        let other = identity_note(&p);
        assert!(
            other.contains("not the victim's real parent"),
            "an ordinary pid must say what the kernel did settle"
        );

        // The unreadable-exe tail is the same in all three, so the fix did not quietly
        // turn "could not be read" into a claim that it was.
        for note in [&zero, &one, &other] {
            assert!(
                note.contains("identity NOT verified"),
                "an actor whose exe was not read is never described as verified"
            );
        }
    }

    #[test]
    fn the_reload_pass_applies_only_to_the_target_whose_handlers_we_can_state() {
        let det = Detector::new(Config::safe_default());
        let me = std::process::id();

        // SIGHUP at Warden's own pid: this binary installs a reload handler, so the
        // documented control path is called a reload and asks for no enforcement.
        let f = det
            .judge(&signal_event(
                IMPOSSIBLE_PID - 1,
                "operator",
                libc::SIGHUP as u32,
                me,
            ))
            .expect("a reload of the sensor is recorded");
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.detail["reason"], "own_reload_path");
        assert!(!f.wants_kill);
        assert!(f.summary.contains("reload:"), "summary must name a reload");

        // The identical number at anyone else is a claim about a handler table this
        // process cannot read, so it keeps the terminate-by-default reading.
        let f = det
            .judge(&signal_event(
                IMPOSSIBLE_PID - 1,
                "attacker",
                libc::SIGHUP as u32,
                131264,
            ))
            .expect("SIGHUP at a guarded process surfaces");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "unauthorized_signal");
        assert!(f.summary.contains("takedown attempt"));

        // And only SIGHUP: SIGTERM/SIGINT at our own pid are the orderly-shutdown
        // handlers, which stop the sensor, so an outside one is still an attack.
        for sig in [libc::SIGTERM, libc::SIGINT] {
            let f = det
                .judge(&signal_event(
                    IMPOSSIBLE_PID - 1,
                    "attacker",
                    sig as u32,
                    me,
                ))
                .expect("a stop request at the agent from outside surfaces");
            assert_eq!(f.severity, Severity::Critical, "signal {sig} was excused");
        }

        // The agent signalling itself is the self-termination shape, not a reload —
        // same pid, so the stronger fact wins.
        let f = det
            .judge(&signal_event(me, "warden", libc::SIGHUP as u32, me))
            .expect("a self-directed SIGHUP is recorded");
        assert_eq!(f.detail["reason"], "self_termination");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn a_borrowed_service_name_gets_no_demotion_without_the_number() {
        // `prctl(PR_SET_NAME)` makes "systemd" available to any process, which is why
        // the authorization above keys on pid 1 and never on the comm.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        let f = det
            .judge(&signal_event(
                IMPOSSIBLE_PID - 1,
                "systemd",
                libc::SIGTERM as u32,
                131264,
            ))
            .expect("a name worn by a foreign pid is a takedown attempt");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "unauthorized_signal");
        assert!(f.wants_kill);
        let authorization = f.detail["authorization"].as_str().unwrap_or_default();
        assert!(
            authorization.contains("no authorization basis found"),
            "authorization must say that no basis was found"
        );
        assert!(
            authorization.contains("identity NOT verified"),
            "an unreadable executable must be labelled unreadable, not believed"
        );
    }

    #[test]
    fn the_responders_arm_list_is_exactly_the_five_numbers_it_has_always_been() {
        // W2K-42. W2K-36/41 rewrote what a signal record *claims* and deliberately
        // left what enforcement may *do* alone: the severity table is wider than the
        // arm list, so SIGINT and SIGHUP now reach Critical without ever arming a
        // kill. Pinning the five numbers is what keeps that separation honest — the
        // day the list widens it has to be an edit a reviewer sees, and the
        // `!own_reload`/`!init_controlled` guards in `wants_kill` stop being
        // redundant for the numbers they cover.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        let det = Detector::new(cfg);

        let armed: Vec<i32> = (1..=31i32)
            .filter(|sig| {
                det.judge(&signal_event(
                    IMPOSSIBLE_PID - 1,
                    "attacker",
                    *sig as u32,
                    131264,
                ))
                .is_some_and(|f| f.wants_kill)
            })
            .collect();
        assert_eq!(
            armed,
            vec![
                libc::SIGQUIT,
                libc::SIGABRT,
                libc::SIGKILL,
                libc::SIGTERM,
                libc::SIGSTOP,
            ]
        );
    }

    #[test]
    fn the_verdict_keys_travel_flat_and_bounded() {
        // `endpoint:self_tamper` carries every signal and ptrace verdict, so the
        // vocabulary lives in `detail`. Detail values are stored under the backend's
        // own truncation cap, which means a long sentence must be clamped here (whole,
        // not mid-word) and nothing may nest (a folded object is a lost verdict).
        let det = Detector::new(Config::safe_default());
        let judged = [
            signal_event(1, "systemd", libc::SIGTERM as u32, 131264),
            signal_event(IMPOSSIBLE_PID - 1, "attacker", libc::SIGHUP as u32, 131264),
            signal_event(
                IMPOSSIBLE_PID - 1,
                "attacker",
                libc::SIGWINCH as u32,
                131264,
            ),
            ptrace_event("curl", 0x01),
            ptrace_event("gdb", 0x02),
        ];
        for e in &judged {
            let f = det.judge(e).expect("each fixture above is a finding");
            let map = f.detail.as_object().expect("detail is an object");
            assert!(
                map.len() <= 24,
                "{} keys is a schema, not a verdict",
                map.len()
            );
            for (key, value) in map {
                assert!(
                    value.is_string() || value.is_number() || value.is_boolean(),
                    "{key} is not a flat value: {value}"
                );
                if let Some(text) = value.as_str() {
                    assert!(
                        text.chars().count() <= 500,
                        "{key} is {} chars",
                        text.chars().count()
                    );
                }
            }
            assert!(
                !f.detail["authorization"]
                    .as_str()
                    .unwrap_or_default()
                    .is_empty(),
                "a finding must say who was believed"
            );
        }
    }

    // ---- W2K-41: the reader tiers, earned by facts the reader did not choose -----

    /// A ptrace reader whose `/proc` evidence is whatever the test says, beside the
    /// app-cgroup needles that make that evidence mean something. The four facts the
    /// Info demotion needs are reads of a monitoring daemon, and no test can make its
    /// own pid answer for one.
    fn reader_actor(exe: Option<&str>, cgroup: Option<&str>, app_needles: &[&str]) -> Detector {
        let mut cfg = Config::safe_default();
        cfg.app = AppIdentity {
            cgroup_contains: app_needles.iter().map(|s| s.to_string()).collect(),
            exe_allowlist: vec![],
        };
        Detector::for_explain(
            cfg,
            FabricatedEvidence {
                exe: exe.map(str::to_string),
                cmdline: None,
                cgroup: cgroup.map(str::to_string),
            },
        )
    }

    #[test]
    fn a_verified_reader_outside_the_app_cgroup_is_routine_observation() {
        // W2K-41 asked for the noise to stop being called an incident without being
        // deleted. A monitoring daemon off in its own slice, whose executable AND
        // cgroup the kernel read, is the shape of routine /proc walking: the record
        // still ships, at Info, with the reason the demotion was granted.
        let det = reader_actor(
            Some("/usr/bin/node-monitor"),
            Some("/system.slice/node-monitor.service"),
            &["kubepods"],
        );
        let f = det
            .judge(&ptrace_event("node-monitor", 0x01))
            .expect("the read is still recorded");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.detail["reason"], "verified_external_reader");
        assert_eq!(f.detail["is_attach"], false);
        assert!(
            f.summary.contains("routine observation"),
            "summary must name routine observation"
        );
        assert!(
            !f.summary.contains("inspection attempt"),
            "summary must not name an inspection attempt"
        );
        assert!(!f.wants_kill, "a read never kills");
    }

    #[test]
    fn an_unreadable_reader_identity_is_not_evidence_of_good_behaviour() {
        // Either half of the identity can fail, and both fail the same way: a staged
        // binary whose exe read refuses, or a reader in a namespace whose cgroup line
        // we cannot map. This is where an attacker lands, so it stays at Medium.
        for (exe, cgroup, label) in [
            (None, Some("/system.slice/node-monitor.service"), "no exe"),
            (Some("/usr/bin/node-monitor"), None, "no cgroup"),
            (None, None, "neither"),
        ] {
            let det = reader_actor(exe, cgroup, &["kubepods"]);
            let f = det
                .judge(&ptrace_event("node-monitor", 0x01))
                .unwrap_or_else(|| panic!("{label} reader must still fire"));
            assert_eq!(f.severity, Severity::Medium, "{label} was demoted");
            assert_eq!(f.detail["reason"], "unverified_reader", "{label}");
            assert!(
                f.summary.contains("inspection attempt"),
                "{label}: summary must name the inspection attempt"
            );
        }
    }

    #[test]
    fn a_reader_inside_the_application_cgroup_is_the_app_poking_a_neighbour() {
        // Outside the application is the whole claim the Info tier makes. A reader
        // whose cgroup IS the application's is the compromised app reaching for its
        // neighbour's /proc and keeps the tier it had before this stage.
        let det = reader_actor(
            Some("/usr/local/bin/worker"),
            Some("/kubepods.slice/kubepods-pod123.slice"),
            &["kubepods"],
        );
        let f = det
            .judge(&ptrace_event("worker", 0x01))
            .expect("an in-app read surfaces");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.detail["reason"], "in_app_reader");
    }

    #[test]
    fn an_unconfigured_app_cgroup_demotes_no_reader() {
        // The deployment default (`cgroup_contains = []`) is the conservative one:
        // with no declared application cgroup nothing can be shown to be outside it,
        // so the tier holds and the finding names the missing knob instead of
        // inventing a reason.
        let det = reader_actor(
            Some("/usr/bin/node-monitor"),
            Some("/system.slice/node-monitor.service"),
            &[],
        );
        let f = det
            .judge(&ptrace_event("node-monitor", 0x01))
            .expect("an unattributable read surfaces");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.detail["reason"], "app_cgroup_unconfigured");
        assert!(
            f.detail["authorization"]
                .as_str()
                .unwrap_or_default()
                .contains("cgroup_contains"),
            "the finding must point at the config that would change its answer"
        );
    }

    #[test]
    fn an_attach_from_a_verified_reader_is_high_and_never_called_observation() {
        // The demotion is a READ-only thing. The same daemon, with the same resolved
        // exe and cgroup, asking to ATTACH is asking to write the target's memory and
        // hijack its registers. If the wording followed the identity instead of the
        // mode, the one request worth killing for would arrive labelled routine
        // observation — the exact way a demotion turns into a blind spot.
        let mut cfg = Config::safe_default();
        cfg.respond.kill_takedown_attacker = true;
        cfg.app = AppIdentity {
            cgroup_contains: vec!["kubepods".into()],
            exe_allowlist: vec![],
        };
        let det = Detector::for_explain(
            cfg,
            FabricatedEvidence {
                exe: Some("/usr/bin/node-monitor".into()),
                cmdline: None,
                cgroup: Some("/system.slice/node-monitor.service".into()),
            },
        );

        let f = det
            .judge(&ptrace_event("node-monitor", 0x03)) // ATTACH|READ
            .expect("an attach from a verified reader is still an attach");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detail["is_attach"], true);
        assert_eq!(f.detail["reason"], "ptrace_attach");
        assert!(
            !f.summary.contains("routine observation"),
            "an attach must not be worded as observation"
        );
        assert!(
            f.summary.contains("inspection attempt"),
            "summary must name an inspection attempt"
        );
        assert!(f.wants_kill, "the attach arm keeps its kill gate");

        // READ from the identical identity is the demoted case, so the two assertions
        // above are about the mode bit and not about the fixture.
        let read = det
            .judge(&ptrace_event("node-monitor", 0x01))
            .expect("the same reader's read surfaces");
        assert_eq!(read.severity, Severity::Info);
        assert_eq!(read.detail["reason"], "verified_external_reader");
        assert!(!read.wants_kill);
    }

    // ---- module_load taint-aware gate (live FP fix: boot module storm) ---------

    #[test]
    fn a_stock_boot_module_is_silent_by_default() {
        // THE module storm fix: the standard netfilter/wireguard/bridge set that
        // modprobe loads at boot is on the default allowlist AND untainted
        // (in-tree, signed ⇒ taints==0), so it is silent out of the box.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&module_event("nf_conntrack", 0)).is_none());
        assert!(det.judge(&module_event("wireguard", 0)).is_none());
        assert!(det.judge(&module_event("xt_MASQUERADE", 0)).is_none());
    }

    #[test]
    fn an_allowlisted_name_but_tainted_module_still_fires() {
        // THE name-spoof defence: an out-of-tree/unsigned .ko that borrows an
        // allowlisted module name (names itself "wireguard") carries the taint the
        // real in-tree module does not, so the allowlist does NOT silence it.
        const TAINT_OUT_OF_TREE: u32 = 1 << 12;
        const TAINT_UNSIGNED: u32 = 1 << 13;
        let det = Detector::new(Config::safe_default());
        let f = det
            .judge(&module_event("wireguard", TAINT_OUT_OF_TREE))
            .expect("a tainted module borrowing an allowlisted name must fire");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["reason"], "allowlisted_name_but_tainted");
        assert_eq!(f.detail["tainted_out_of_tree_or_unsigned"], true);
        // Unsigned bit alone also defeats the allowlist.
        assert!(det
            .judge(&module_event("nf_tables", TAINT_UNSIGNED))
            .is_some());
    }

    #[test]
    fn a_nonallowlisted_module_still_fires_untainted() {
        // A module not on the (now populated) allowlist is still the rootkit
        // signature even when untainted — allowlist is exact, not a prefix.
        let det = Detector::new(Config::safe_default());
        assert!(det.judge(&module_event("evil_rootkit", 0)).is_some());
        assert!(det.judge(&module_event("wireguard_evil", 0)).is_some());
    }

    // ---- new_service component-boundary match (live FP fix: autostart storm) ---

    #[test]
    fn an_xdg_autostart_generator_leaf_is_silent() {
        // THE new_service storm fix: the xdg-autostart generator writes
        // `app-<id>@autostart.service` whose LEAF contains "autostart" mid-filename
        // while the directory is generator.late — the old raw contains() fired on
        // it every login. Component-boundary matching makes it silent.
        let det = Detector::new(Config::safe_default());
        let path = "/systemd/generator.late/app-foo@autostart.service";
        assert!(
            det.judge(&service_event(5050, path)).is_none(),
            "a generator.late @autostart.service leaf must not fire"
        );
    }

    #[test]
    fn a_real_autostart_desktop_file_still_fires() {
        // The other half: a genuine persistence write where "autostart" IS a real
        // path component (preceded by '/') still fires.
        let det = Detector::new(Config::safe_default());
        assert!(det
            .judge(&service_event(
                5050,
                "/home/u/.config/autostart/evil.desktop"
            ))
            .is_some());
        // And a real rogue unit directly in a persistence dir still fires.
        assert!(det
            .judge(&service_event(5050, "/etc/systemd/system/evil.service"))
            .is_some());
    }

    #[test]
    fn a_forged_snap_named_unit_is_not_allowlisted_past() {
        // THE allow_paths forgeability defence: an operator who allowlists snapd by
        // a leaf fragment must NOT thereby silence a rogue unit the attacker names
        // to match. allow_paths is matched by ANCHORED prefix, so a bare "snap."
        // fragment does not anchor at the path start and an attacker-named
        // /etc/systemd/system/snap.evil.service still fires.
        let mut cfg = Config::safe_default();
        cfg.service_rules = ServiceRules {
            allow_paths: vec!["snap.".into()], // a tempting-but-unsafe fragment
            ..ServiceRules::default()
        };
        let det = Detector::new(cfg);
        assert!(
            det.judge(&service_event(
                5050,
                "/etc/systemd/system/snap.evil.service"
            ))
            .is_some(),
            "a forged snap.* unit must still fire — fragment allowlist must not anchor"
        );
        // An anchored full-path allowlist entry DOES correctly silence its target.
        let mut cfg2 = Config::safe_default();
        cfg2.service_rules = ServiceRules {
            allow_paths: vec!["/etc/systemd/system/warden.service".into()],
            ..ServiceRules::default()
        };
        let det2 = Detector::new(cfg2);
        assert!(det2
            .judge(&service_event(5050, "/etc/systemd/system/warden.service"))
            .is_none());
    }

    #[test]
    fn persistence_match_requires_component_boundary() {
        assert!(persistence_match(
            "/etc/systemd/system/x.service",
            "systemd/system"
        ));
        assert!(persistence_match(
            "/home/u/.config/autostart/e.desktop",
            "autostart"
        ));
        assert!(persistence_match("/etc/cron.d/job", "/cron")); // self-anchored '/'
                                                                // mid-component occurrence does NOT match
        assert!(!persistence_match(
            "/d/app-x@autostart.service",
            "autostart"
        ));
        assert!(persistence_match("/etc/cron.daily/x", "cron")); // prefix-of-component kept
    }

    #[test]
    fn persistence_match_requires_the_component_to_end_where_the_pattern_does() {
        // Live storm: systemd-logind rewrites /run/systemd/users/<uid> on every
        // session change. The kernel's ladder drops the /run mount root, so the
        // path it reports is "/systemd/users/…" — and "systemd/user" matched its
        // own prefix "users", turning routine logind state into Critical
        // persistence every few seconds.
        assert!(!persistence_match(
            "/systemd/users/.#1000abcd",
            "systemd/user"
        ));
        assert!(!persistence_match(
            "/run/systemd/users/1000",
            "systemd/user"
        ));
        // The real per-user unit directory still matches.
        assert!(persistence_match(
            "/home/u/.config/systemd/user/evil.service",
            "systemd/user"
        ));
    }

    // ---- mount exe-allowlist gate (live FP fix: snap-confine storm) ------------

    /// A mount Event by a specific pid+comm. The actor's exe is resolved from
    /// /proc/<pid>/exe at judge time, so these exe-allowlist tests use the current
    /// test process's pid (a real, non-deleted exe) and assert on the comm/cgroup
    /// axes that CAN be set deterministically; the exe-match path itself is proven
    /// by `mount_suppression_rejects_spoofed_comm` (comm set, exe not allowlisted).
    fn mount_event_by(comm: &str, pid: u32, source: &str, flags: u32) -> Event {
        Event {
            comm: comm.into(),
            actor_pid: pid,
            ..mount_event(source, flags)
        }
    }

    #[test]
    fn mount_suppression_rejects_spoofed_comm() {
        // THE mount defence: suppression is keyed on the resolved exe, never the
        // spoofable comm. A process claiming comm="snap-confine" whose real exe is
        // NOT the snap-confine binary (here, the test runner's own exe) must still
        // fire on a host-tree bind — the comm spoof buys nothing.
        let det = Detector::new(Config::safe_default());
        let f = det.judge(&mount_event_by(
            "snap-confine",
            std::process::id(),
            "/etc",
            4096,
        ));
        assert!(
            f.is_some(),
            "a comm-spoofed mount whose exe is not allowlisted must still fire"
        );
    }

    #[test]
    fn mount_raw_disk_and_socket_fire_even_for_allowlisted_exe() {
        // The carve-out: suppress_exempt_sources (raw disk, kernel mem, runtime
        // sockets) fire even if the actor exe were allowlisted. Proven here against
        // the default config: a raw-disk/socket bind is never silenced on the exe
        // path because the exempt check gates the suppression off entirely.
        let det = Detector::new(Config::safe_default());
        for src in [
            "/dev/sda",
            "/dev/mapper/root",
            "/dev/mem",
            "/var/run/docker.sock",
        ] {
            assert!(
                det.judge(&mount_event_by(
                    "snap-confine",
                    std::process::id(),
                    src,
                    4096
                ))
                .is_some(),
                "never-benign source {src} must fire regardless of actor"
            );
        }
    }

    #[test]
    fn mount_allow_actor_exes_is_configurable_and_boundary_safe() {
        // An operator can allowlist their own confinement builder by exe. Verify
        // the field exists and that a non-matching exe (the test process) is NOT
        // suppressed — i.e. the allowlist is consulted, not ignored, and does not
        // blanket-silence. (The positive exe match requires running AS the
        // allowlisted binary, which a unit test cannot forge — covered by the
        // spoofed-comm negative control above.)
        let mut cfg = Config::safe_default();
        cfg.mount_rules = MountRules {
            allow_actor_exes: vec!["/opt/custom/sandbox-builder".into()],
            ..MountRules::default()
        };
        let det = Detector::new(cfg);
        assert!(
            det.judge(&mount_event_by(
                "sandbox-builder",
                std::process::id(),
                "/etc",
                4096
            ))
            .is_some(),
            "an actor whose exe is not the allowlisted path must still fire"
        );
    }

    #[test]
    fn new_network_implant_prog_types_fire_for_unknown_loader() {
        // THE bpf network-implant gap fix: tc (3/4), sk_skb/sk_msg (14/16),
        // sock_addr (18), sk_lookup (30), netfilter (32) are now watched. Each is
        // an in-kernel network-plane implant and must convict an unknown loader.
        let det = Detector::new(Config::safe_default());
        for &(t, name) in &[
            (3u32, "sched_cls"),
            (4, "sched_act"),
            (14, "sk_skb"),
            (16, "sk_msg"),
            (18, "cgroup_sock_addr"),
            (30, "sk_lookup"),
            (32, "netfilter"),
        ] {
            let f = det
                .judge(&bpf_event_typed("stranger", t))
                .unwrap_or_else(|| panic!("prog_type {t} ({name}) must fire"));
            assert_eq!(f.detail["prog_type_name"], name);
            assert_eq!(f.severity, Severity::Critical);
        }
        // The benign systemd set stays silent — no new storm introduced.
        assert!(det.judge(&bpf_event_typed("systemd", 8)).is_none());
        assert!(det.judge(&bpf_event_typed("systemd", 15)).is_none());
    }

    // ---- W2K-10: the kernel's "protected" claim is only a pid -----------------

    /// The identity table as the kernel saw it: `pid` protected with `recorded`
    /// as its start time at the moment the pid-keyed map was written.
    fn protected_with(pid: u32, recorded: Option<u64>) -> Protected {
        let mut set = Protected::default();
        set.insert(pid, recorded);
        set
    }

    #[test]
    fn a_recycled_target_pid_is_not_reported_as_a_takedown() {
        // The bug: the protected worker died, the kernel map still holds its
        // number for up to one PROTECT_REFRESH, and something signals whatever
        // process inherited that number. The kernel emits; the claim is false.
        // Start time is the only thing that can tell the two apart in userspace.
        let me = std::process::id();
        let live = starttime_of(me).expect("this test reads its own /proc start time");
        let mut det = Detector::new(Config::safe_default());
        det.set_protected(protected_with(me, Some(live + 1)));
        assert!(
            det.judge(&signal_event(7070, "killer", libc::SIGKILL as u32, me))
                .is_none(),
            "a signal to a pid whose start time no longer matches the protected \
             entry is a signal to an unrelated process, not a takedown"
        );
        // Same for the ptrace path, even in ATTACH mode.
        let mut e = ptrace_event("gdb", 0x02);
        e.target_pid = me;
        assert!(det.judge(&e).is_none());
    }

    #[test]
    fn a_target_with_the_recorded_start_time_is_still_a_takedown() {
        // The control: identical start time means the same process, so the
        // kernel's claim stands and the finding must fire exactly as before.
        let me = std::process::id();
        let mut det = Detector::new(Config::safe_default());
        det.set_protected(protected_with(me, starttime_of(me)));
        let f = det
            .judge(&signal_event(7070, "killer", libc::SIGKILL as u32, me))
            .expect("the protected process is still alive at the same start time");
        assert!(matches!(f.event_type, FindingType::SelfTamper));
    }

    #[test]
    fn a_vanished_target_is_never_silenced() {
        // THE branch that must not regress: a successful kill makes the victim
        // disappear, and by the time the ring is drained its start time cannot be
        // read at all. Reading that as "not protected any more" would silence the
        // alarm for the exact attack the sensor exists for, so uncertainty keeps
        // the finding.
        let mut det = Detector::new(Config::safe_default());
        let dead: u32 = 4_000_000_000;
        assert!(
            starttime_of(dead).is_none(),
            "this pid must not exist for the test to mean anything"
        );
        det.set_protected(protected_with(dead, Some(10)));
        assert!(det
            .judge(&signal_event(7070, "killer", libc::SIGKILL as u32, dead))
            .is_some());
        // And a target simply absent from the table is unproven, not innocent.
        let unrecorded = signal_event(7070, "killer", libc::SIGKILL as u32, dead + 1);
        assert!(det.judge(&unrecorded).is_some());
    }

    #[test]
    fn a_recycled_pid_taken_over_by_a_protected_process_still_fires() {
        // The number changed hands — but the new owner matches the protect
        // policy itself (here: a comm on `[[protect]].comms`), so a signal aimed
        // at it IS a takedown attempt against a protected process, just not the
        // one the kernel map was written for. Suppression must not outlive the
        // identity check.
        let me = std::process::id();
        let live = starttime_of(me).expect("this test reads its own /proc start time");
        let comm = ProcIdentity::read(me)
            .comm
            .expect("this test reads its own /proc/<pid>/comm");
        let mut cfg = Config::safe_default();
        cfg.protect.comms = vec![comm];
        let mut det = Detector::new(cfg);
        det.set_protected(protected_with(me, Some(live + 1)));
        assert!(
            det.judge(&signal_event(7070, "killer", libc::SIGKILL as u32, me))
                .is_some(),
            "policy says the current occupant is protected; the finding stands"
        );
    }

    // ── W2K-13: the `/proc` evidence cache ────────────────────────────────

    /// An event of `kind` whose actor is this very test process — the one pid
    /// whose `/proc` entries this suite can count on reading.
    fn actor_event(kind: Kind) -> Event {
        Event {
            kind,
            ..signal_event(std::process::id(), "granian", 0, 0)
        }
    }

    #[test]
    fn a_cached_actor_costs_one_proc_read_per_event_instead_of_four() {
        // The claim W2K-13 makes is about reads, not feelings, so it is asserted
        // against the fetch counter: one storm of events from one unchanged process
        // is one `/proc` fetch, whatever the window says.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = 1_000;
        let det = Detector::new(cfg);
        let connect = actor_event(Kind::Connect);

        let first = det.enrich(&connect);
        assert_eq!(det.enrich_fetches.get(), 1);
        assert_eq!(first.exe, exe_of(first.pid));
        assert_eq!(det.enrich_hits.get(), 0);

        for _ in 0..50 {
            let again = det.enrich(&connect);
            assert_eq!(again.exe, first.exe);
            assert_eq!(again.cmdline, first.cmdline);
            assert_eq!(again.cgroup, first.cgroup);
            assert_eq!(again.starttime, first.starttime);
        }
        assert_eq!(
            det.enrich_fetches.get(),
            1,
            "fifty more events, and still one fetch"
        );
        assert_eq!(det.enrich_hits.get(), 50);
        // The numbers the kernel put on the event are never cached — they come
        // from the record, so a cached answer cannot report a stale uid or comm.
        assert_eq!(first.uid, connect.actor_uid);
        assert_eq!(first.comm, "granian");
    }

    #[test]
    fn an_exec_always_refetches_because_the_key_cannot_see_the_swap() {
        // `execve` keeps the pid and the start time: same (pid, starttime),
        // different binary. The cache is therefore forbidden from answering an
        // exec — the deleted-exe and staged-binary rules judge `exe`, and a
        // pre-exec `exe` is the wrong answer to the only question that matters.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = 1_000;
        let det = Detector::new(cfg);

        det.enrich(&actor_event(Kind::Connect));
        det.enrich(&actor_event(Kind::Exec));
        assert_eq!(
            det.enrich_fetches.get(),
            2,
            "an exec must read /proc even for an actor already cached"
        );
        // …and the republished entry serves later events without another read.
        det.enrich(&actor_event(Kind::Connect));
        assert_eq!(det.enrich_fetches.get(), 2);
        assert_eq!(det.enrich_hits.get(), 1);
    }

    #[test]
    fn a_recycled_pid_misses_because_the_key_carries_its_start_time() {
        // The failure this keying exists to prevent: a dead process's number is
        // handed to a new one, and the new one is judged — and reported — on the
        // dead one's exe and cgroup.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = 1_000;
        let det = Detector::new(cfg);
        let me = std::process::id();
        let start = starttime_of(me).expect("this test reads its own start time");

        det.proc_evidence.borrow_mut().insert(
            (me, start.wrapping_add(1)),
            CachedProc {
                exe: Some("/someone/elses/image".into()),
                cmdline: Some("/someone/elses image --serve-secrets".into()),
                cgroup: Some("/someone/elses/cgroup".into()),
                fetched_at: Instant::now(),
            },
        );

        let proc = det.enrich(&actor_event(Kind::Connect));
        assert_eq!(det.enrich_fetches.get(), 1, "different anchor → miss");
        assert_eq!(det.enrich_hits.get(), 0);
        assert_eq!(proc.exe, exe_of(me));
        assert_ne!(proc.cgroup.as_deref(), Some("/someone/elses/cgroup"));
        assert_eq!(proc.starttime, Some(start));
    }

    #[test]
    fn a_zero_window_pays_the_reads_it_always_paid() {
        // `enrich_cache_ms = 0` is a real policy, not a broken config: every event
        // re-reads, exactly as Warden did before this existed.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = 0;
        let det = Detector::new(cfg);
        for _ in 0..4 {
            det.enrich(&actor_event(Kind::Connect));
        }
        assert_eq!(det.enrich_fetches.get(), 4);
        assert_eq!(det.enrich_hits.get(), 0);
        assert!(det.proc_evidence.borrow().is_empty());
    }

    #[test]
    fn an_unreadable_start_time_caches_nothing() {
        // `hidepid=`, or a process that died between the event and this read: with
        // no anchor there is no way to prove a later hit is the same process, so
        // nothing is stored and each event pays the four reads. Fail-open on cost,
        // never on attribution.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = 1_000;
        let det = Detector::new(cfg);
        let ghost = signal_event(u32::MAX, "ghost", 0, 0);

        let first = det.enrich(&ghost);
        let second = det.enrich(&ghost);
        assert_eq!(det.enrich_fetches.get(), 2);
        assert!(det.proc_evidence.borrow().is_empty());
        assert_eq!(first.starttime, None);
        assert_eq!(second.starttime, None);
    }

    #[test]
    fn the_window_ages_an_entry_out_instead_of_keeping_it_forever() {
        // The window is the maximum attribution lag a finding can carry, so it has
        // to actually expire: a cached `cgroup` from before a `cgclassify` is the
        // stale answer this bounds.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = 1;
        let det = Detector::new(cfg);
        det.enrich(&actor_event(Kind::Connect));
        std::thread::sleep(std::time::Duration::from_millis(50));
        det.enrich(&actor_event(Kind::Connect));
        assert_eq!(
            det.enrich_fetches.get(),
            2,
            "an expired entry is re-read, not trusted"
        );
        assert_eq!(det.enrich_hits.get(), 0);
    }

    #[test]
    fn a_full_cache_is_bounded_rather_than_growing() {
        // 4096 process identities is far more than a VPS runs, but "the guardian's
        // memory grows with the number of pids it has ever seen" is the kind of bug
        // that only shows up after a week of uptime. So the bound is asserted, not
        // assumed: a miss when full costs reads, never memory.
        let mut cfg = Config::safe_default();
        cfg.runtime.enrich_cache_ms = MAX_ENRICH_CACHE_MS;
        let det = Detector::new(cfg);
        {
            let mut cache = det.proc_evidence.borrow_mut();
            for pid in 0..=(ENRICH_CACHE_MAX as u32) {
                cache.insert(
                    (pid, 1),
                    CachedProc {
                        exe: Some("/filled/the/cache".into()),
                        cmdline: None,
                        cgroup: None,
                        fetched_at: Instant::now(),
                    },
                );
            }
            assert!(cache.len() > ENRICH_CACHE_MAX);
        }
        let proc = det.enrich(&actor_event(Kind::Connect));
        assert_eq!(
            det.enrich_fetches.get(),
            1,
            "the insert path ran the eviction"
        );
        assert!(
            det.proc_evidence.borrow().len() <= ENRICH_CACHE_MAX,
            "the cache outgrew its bound"
        );
        assert_eq!(proc.exe, exe_of(std::process::id()));
    }
}
