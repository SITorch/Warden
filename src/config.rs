//! config.rs — Warden's operator-facing policy, loaded from warden.toml.
//!
//! Everything an operator tunes lives here: which processes are "the app", what
//! egress is sanctioned, which paths are secrets, and how aggressive to be. The
//! agent reads this once at start and on SIGHUP; it is data, never code.

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;

use crate::egress::EgressDeny;
use crate::resources::ResourceBudget;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Schema version of the TOML document, not the crate version. Version 0 means
/// "no `schema_version` key was written" — the shape every pre-M16 config had —
/// and is accepted at load so existing deployments keep working. The config
/// engine migrates it to version 1 explicitly; a version greater than 1 is
/// refused rather than guessed at.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;
pub const LEGACY_SCHEMA_VERSION: u32 = 0;

fn current_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Version of this configuration document's schema. Defaults to 1 when
    /// absent so pre-M16 files remain valid; kept in the file so migration,
    /// drift detection and rollback have an explicit anchor.
    #[serde(default = "current_schema_version")]
    pub schema_version: u32,

    /// Global posture. `observe` = never kill, only report. `enforce` = allow
    /// the responders that are individually enabled below to act.
    #[serde(default)]
    pub mode: Mode,

    /// The two costs the W2K-13 audit named: a ring buffer that could only be
    /// resized by rebuilding the kernel object, and four `/proc` reads spent on
    /// every single event. Both have defaults that reproduce exactly what
    /// Warden did before the knobs existed.
    #[serde(default)]
    pub runtime: Runtime,

    /// Phase 9: the resource envelope declared by the shipped systemd unit.
    /// This is evidence for `--check`, not a runtime knob: Warden does not set
    /// these limits itself, so a value that disagrees with the unit is refused
    /// rather than printed as if it were enforced.
    #[serde(default)]
    pub resources: ResourceBudget,

    /// How Warden finds the processes it must protect (Sentinel + itself).
    #[serde(default)]
    pub protect: Protect,

    /// What counts as "the application" for actor attribution.
    #[serde(default)]
    pub app: AppIdentity,

    /// exec-based detection (T1 reverse shell).
    #[serde(default)]
    pub exec_rules: ExecRules,

    /// egress-based detection (T1/T4 C2 / reverse-shell dial-out).
    #[serde(default)]
    pub network_rules: NetworkRules,

    /// Bounded local behavioural beaconing detection over CONNECT telemetry
    /// (Phase 4). Findings are confidence-bearing signals, never kill requests.
    #[serde(default)]
    pub c2_rules: C2Rules,

    /// credential-based detection (T5 privilege escalation).
    #[serde(default)]
    pub cred_rules: CredRules,

    /// ptrace-of-protected-pid detection (T7/T8 inspect / inject).
    #[serde(default)]
    pub ptrace_rules: PtraceRules,

    /// module-load detection (T6 rootkit / LKM implant).
    #[serde(default)]
    pub module_rules: ModuleRules,

    /// file rename/unlink detection (T2/T9 ransomware / tamper).
    #[serde(default)]
    pub file_rules: FileRules,

    /// persistence-create detection (T3 boot/login-survival footholds).
    #[serde(default)]
    pub service_rules: ServiceRules,

    /// listen-socket detection (T4 bind shell / inbound backdoor).
    #[serde(default)]
    pub listen_rules: ListenRules,

    /// The PULL half of network visibility: a periodic read of the kernel's own
    /// socket table. Nothing to do with the sensors — it exists because a sensor
    /// only sees a change while it is attached.
    #[serde(default)]
    pub network_snapshot: NetworkSnapshot,

    /// The CUMULATIVE half of network visibility (N-05): per-cgroup byte and
    /// operation totals kept in a kernel map by six fexit programs, read once
    /// per interval. Where the snapshot says which sockets exist, this says how
    /// much moved through them — a question the lossy events ring cannot answer.
    #[serde(default)]
    pub net_volume: NetVolume,

    /// bpf-program-load detection (T6 eBPF rootkit / stealth-hook implant).
    #[serde(default)]
    pub bpf_rules: BpfRules,

    /// mount detection (T11 container escape / host-fs exposure).
    #[serde(default)]
    pub mount_rules: MountRules,

    /// The enforcing (BPF-LSM) guard layer — the one part of Warden that can DENY
    /// an operation in-kernel, not merely observe it. Default is shadow (log a
    /// would-deny, allow through). See EnforceRules.
    #[serde(default)]
    pub enforce: EnforceRules,

    /// Phase 7 cgroup egress enforcement. Disabled by default: no program is
    /// loaded, no cgroup hook is attached, and no rule can deny traffic until an
    /// operator explicitly enables it AND names an isolated test cgroup. This is
    /// deliberately separate from `network_rules.deny_destinations`, which stays
    /// an observe-only policy signal. See `Egress`.
    #[serde(default)]
    pub egress: Egress,

    /// Which local responders may act (only consulted in enforce mode).
    #[serde(default)]
    pub respond: Respond,

    /// The Sentinel bridge. If absent, findings only hit the local log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bridge: Option<Bridge>,

    /// Dead-man's-switch heartbeat target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<Heartbeat>,

    /// W2K-23 — the keys in the file that no field of this struct ever read.
    /// Filled by `Config::load`; never deserialised or serialised itself, so it
    /// cannot pollute the round-trip it is computed from.
    #[serde(skip)]
    pub unread_keys: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Observe,
    Enforce,
}

/// The ring size baked into `events` in `bpf/warden.bpf.c`. `Runtime`'s default
/// must equal it, so that a config which says nothing about the ring gets the
/// ring Warden has always shipped with; `tests/ringbuf_drop_counter.rs` pins the
/// object side and `the_runtime_defaults_reproduce_the_shipped_behaviour` pins
/// this side.
pub const DEFAULT_RING_KIB: u32 = 256;
/// Smallest configurable ring. 64 KiB is a power-of-two page count on both 4 KiB
/// and 64 KiB-page kernels, so the floor is the same number everywhere.
pub const MIN_RING_KIB: u32 = 64;
/// Largest configurable ring. The ring is kernel memory held for the whole run,
/// and Warden's stated deployment is a small VPS: this ceiling keeps a typo
/// (`ring_size_kib = 16777216`) from becoming an out-of-memory event on the host
/// it is protecting. 16 MiB is already 64× the shipped size; a host that loses
/// events even at that size wants a sensor muted, not a bigger ring, which is
/// exactly what the per-sensor drop counters (W2K-14) exist to identify.
pub const MAX_RING_KIB: u32 = 16 * 1024;
/// How long one process's `/proc` evidence may be reused across events. Short on
/// purpose: `cgroup` can change while a process lives (`cgclassify`, a systemd
/// unit moving its members) and `cmdline` is writable by the process itself, so
/// the TTL *is* the maximum attribution lag — see `Detector::enrich`.
pub const DEFAULT_ENRICH_CACHE_MS: u64 = 100;
/// Refuse a TTL long enough that a finding can be judged against evidence minutes
/// old. Past this, the reads saved are not worth the lag introduced.
pub const MAX_ENRICH_CACHE_MS: u64 = 5_000;

/// Sensor-channel size and per-event cost. Neither knob changes what is
/// detected; both change what a detection costs, which is what made them
/// unactionable before W2K-13 — the journal's own ring-full warning told the
/// operator to "raise `events` in `bpf/warden.bpf.c`", advice nobody running the
/// packaged single binary could follow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Runtime {
    /// `events` ring-buffer capacity in KiB. Applied when the map is created, at
    /// load — a SIGHUP reload cannot resize a live ring, and `main.rs` says so
    /// when the value changes under reload.
    ///
    /// Must be a size the kernel honours verbatim. A BPF ring buffer is allocated
    /// as a power-of-two number of pages, so anything else is silently rounded up
    /// — a config that reads 200 while the kernel built 256 is a policy lie, and
    /// [`Runtime::ring_size_problem`] refuses it at load instead.
    pub ring_size_kib: u32,
    /// Reuse a process's `exe`/`cmdline`/`cgroup` across events for this many
    /// milliseconds. `0` disables the cache and every event pays the four reads
    /// it always paid.
    pub enrich_cache_ms: u64,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            ring_size_kib: DEFAULT_RING_KIB,
            enrich_cache_ms: DEFAULT_ENRICH_CACHE_MS,
        }
    }
}

impl Runtime {
    /// The byte count handed to the map creation syscall.
    pub fn ring_bytes(&self) -> u32 {
        self.ring_size_kib.saturating_mul(1024)
    }

    /// The size the kernel will actually be given, after the same rounding aya's
    /// loader applies (`page_size * ceil(bytes/page).next_power_of_two()`).
    /// Mirrors aya 0.13.1 `bpf::adjust_to_page_size`, which is the code that
    /// creates this map — so `--check` can state the real capacity unprivileged.
    pub fn effective_ring_bytes(&self, page_size: u32) -> u32 {
        let bytes = self.ring_bytes();
        if bytes == 0 || page_size == 0 {
            return bytes;
        }
        page_size * bytes.div_ceil(page_size).next_power_of_two()
    }

    /// Why the configured ring is not one the kernel will build exactly, or
    /// `None` when it is. Split out and page-size-parameterised so the arch-dependent
    /// arithmetic is testable on one host: the caller passes
    /// [`page_size`], the tests pass 4096 and 65536.
    pub fn ring_size_problem(&self, page_size: u32) -> Option<String> {
        if self.ring_size_kib < MIN_RING_KIB || self.ring_size_kib > MAX_RING_KIB {
            return Some(format!(
                "runtime.ring_size_kib = {} is outside the supported range \
                 [{MIN_RING_KIB}, {MAX_RING_KIB}] KiB. The ring is kernel memory \
                 held for the whole run, so size it from what the per-sensor drop \
                 counters report rather than from a guess.",
                self.ring_size_kib
            ));
        }
        let effective = self.effective_ring_bytes(page_size);
        if effective != self.ring_bytes() {
            return Some(format!(
                "runtime.ring_size_kib = {} would not be the ring Warden gets: \
                 the kernel allocates a power-of-two number of {page_size}-byte \
                 pages, so this request rounds up to {} KiB. Say {} instead.",
                self.ring_size_kib,
                effective / 1024,
                effective / 1024,
            ));
        }
        None
    }

    /// The cache window, or `None` when the cache is disabled.
    pub fn enrich_cache_ttl(&self) -> Option<std::time::Duration> {
        match self.enrich_cache_ms {
            0 => None,
            ms => Some(std::time::Duration::from_millis(ms)),
        }
    }
}

/// This host's page size, which is what decides whether a ring request survives
/// rounding. Falls back to 4 KiB if `sysconf` somehow fails, because the
/// fallback only ever makes the check stricter in the direction of the smallest
/// page size anyone runs.
pub fn page_size() -> u32 {
    // SAFETY: sysconf(_SC_PAGESIZE) reads a sysconf value with no arguments and
    // no allocator state; the only failure mode is a negative return, handled.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        n as u32
    } else {
        4096
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protect {
    /// Match protected processes by exact comm (e.g. "granian", "celery").
    ///
    /// Spoofable by construction: comm is 15 bytes any process can set on
    /// itself with `prctl(PR_SET_NAME)`. Kept because it is what existing
    /// deployments use; `targets` below is the strong alternative.
    #[serde(default)]
    pub comms: Vec<String>,
    /// Match protected processes by systemd unit substring in their cgroup path.
    ///
    /// The loosest selector here — a substring, so it matches anything that
    /// happens to contain the needle. `targets[].cgroup` matches the exact path.
    #[serde(default)]
    pub cgroup_contains: Vec<String>,
    /// Always protect Warden's own pid (default true; you want this).
    #[serde(default = "default_true")]
    pub protect_self: bool,
    /// Protected processes matched by identity rather than by name (W-R4).
    ///
    /// Each entry is an AND over the fields it names, and is ORed with the
    /// legacy selectors above — so adding one never takes protection away from
    /// a process `comms`/`cgroup_contains` already covered. Empty by default,
    /// which leaves an existing `warden.toml` behaving exactly as before.
    #[serde(default)]
    pub targets: Vec<ProtectTarget>,
}

impl Default for Protect {
    /// Spelled out rather than derived, because the derived `Default` returns
    /// `false` for every bool — and `protect_self` is the one field whose
    /// default has to agree with the `#[serde(default = "default_true")]`
    /// attribute two lines up. With the derive, a `warden.toml` that omitted the
    /// whole `[protect]` table got *less* protection than one that had the table
    /// with the key omitted, which is the opposite of what the sample documents.
    fn default() -> Self {
        Self {
            comms: Vec::new(),
            cgroup_contains: Vec::new(),
            protect_self: true,
            targets: Vec::new(),
        }
    }
}

/// One `[[protect.targets]]` entry (W-R4): identity constraints that must all
/// hold. Every field is optional; an unnamed field is not a constraint.
///
/// This is the audit's prescribed alternative to deciding what may never be
/// killed from `comm` or a cgroup substring alone. A process cannot rename
/// itself into a different `exe`, a different `uid`, or a different cgroup
/// path, so a tuple that names those is not something an impostor can satisfy
/// by picking a name.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtectTarget {
    /// Exact kernel comm. `/proc/<pid>/comm` is truncated to 15 bytes, so that
    /// is the longest value that can ever match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    /// Exact executable path, as `/proc/<pid>/exe` resolves.
    ///
    /// A path, not an inode: a binary replaced in place is still matched, and a
    /// process holding a deleted binary shows the kernel's `"<path> (deleted)"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Real uid — deliberately the same value the sensors report as
    /// `ProcessInfo.uid` and the guarded-file layer attributes by, so "uid"
    /// means one thing throughout Warden and not two.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Exact cgroup v2 path, e.g. `/system.slice/granian.service`. No substring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
}

impl ProtectTarget {
    /// Whether this target constrains anything a process cannot simply name
    /// itself. False means it is a name-only selector — the thing W-R4 is
    /// about — and also that it can never match, since a target that names no
    /// field is treated as matching nothing.
    pub fn names_identity(&self) -> bool {
        self.exe.is_some() || self.uid.is_some() || self.cgroup.is_some()
    }

    /// A one-line rendering for logs, so an unmatched target can be reported
    /// as the operator wrote it rather than as an index.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(c) = &self.comm {
            parts.push(format!("comm={c:?}"));
        }
        if let Some(e) = &self.exe {
            parts.push(format!("exe={e:?}"));
        }
        if let Some(u) = self.uid {
            parts.push(format!("uid={u}"));
        }
        if let Some(c) = &self.cgroup {
            parts.push(format!("cgroup={c:?}"));
        }
        if parts.is_empty() {
            return "(names no field, so it matches nothing)".to_string();
        }
        parts.join(" ")
    }
}

impl Protect {
    /// The parts of this policy that identify a process by something it can set
    /// for itself, or by a loose substring — everything except a target that
    /// names `exe`, `uid` or an exact `cgroup`.
    ///
    /// Exists so the startup log can say what the policy actually rests on. A
    /// bare "protecting 3 pid(s)" reads like a guarantee, and for a comm-only
    /// policy it is not one.
    pub fn weak_selectors(&self) -> Vec<String> {
        let mut out = Vec::new();
        for c in &self.comms {
            out.push(format!(
                "comms: {c:?} matches a comm any process can set with prctl(PR_SET_NAME)"
            ));
        }
        for n in &self.cgroup_contains {
            if n.trim().is_empty() {
                out.push("cgroup_contains: a blank needle is ignored".to_string());
            } else {
                out.push(format!("cgroup_contains: {n:?} is a substring match"));
            }
        }
        for (i, t) in self.targets.iter().enumerate() {
            if !t.names_identity() {
                out.push(format!(
                    "targets[{i}]: names only comm, so it is no stronger than `comms`"
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppIdentity {
    /// cgroup path substrings that mark a process as "the app" (its egress and
    /// exec are held to the app allowlist).
    #[serde(default)]
    pub cgroup_contains: Vec<String>,
    /// Executable paths that are legitimately part of the app runtime.
    ///
    /// Read by the W2K-15 exec rule: an exec from inside the app cgroup whose
    /// resolved `/proc/<pid>/exe` names one of these exactly is not reported as
    /// "a binary staged in a world-writable directory". The list suppresses only
    /// that rule — it never silences a shell identity match or a deleted-on-disk
    /// exe, and a `(deleted)` exe never matches an entry, because a fileless
    /// binary is itself the signal. Exact path equality, like
    /// `mount_rules.allow_actor_exes`: a comm is one `prctl(PR_SET_NAME)` away
    /// from being anything you like.
    #[serde(default)]
    pub exe_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRules {
    /// Names that mark a shell or a scripting one-liner host. Since W2K-15 these
    /// are matched against the exec's *identity* — `/proc/<pid>/exe`, the path
    /// the `execve` tracepoint saw, and `comm` — not against `comm` alone,
    /// because comm is 15 bytes the process itself may rewrite.
    #[serde(default = "default_shell_comms")]
    pub shell_comms: Vec<String>,
    /// Treat a deleted-on-disk executable as suspicious (fileless / T3).
    #[serde(default = "default_true")]
    pub flag_deleted_exe: bool,
    /// Directory prefixes whose contents are not the app's declared runtime: a
    /// world-writable staging area an attacker can `cp` a shell into and rename.
    /// An exec from inside the app cgroup whose binary lives under one of these
    /// is a finding even when its name matches nothing above. An empty list
    /// disables the rule; `[app].exe_allowlist` entries override it per path.
    #[serde(default = "default_untrusted_exe_prefixes")]
    pub untrusted_exe_prefixes: Vec<String>,
}

impl Default for ExecRules {
    fn default() -> Self {
        Self {
            shell_comms: default_shell_comms(),
            flag_deleted_exe: true,
            untrusted_exe_prefixes: default_untrusted_exe_prefixes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRules {
    /// Only judge egress from a process inside the app cgroup. The app reaching
    /// out to an unknown host is the signal; an admin's `curl` in a login shell
    /// is noise. When true (default) and no app cgroup is configured, the sensor
    /// stays quiet rather than flag every connect on the box.
    #[serde(default = "default_true")]
    pub app_egress_only: bool,

    /// Destinations the app is allowed to reach, matched against the resolved
    /// "ip:port" and, separately, the bare IP. A connect to anything NOT on this
    /// list, from the app, is what the reverse-shell / C2 rule fires on. Empty =
    /// the app is expected to make no outbound connections at all (the strictest
    /// and most common posture for a request-serving worker), so any egress is
    /// flagged.
    #[serde(default)]
    pub egress_allow: Vec<String>,

    /// Destination ports that never warrant a finding regardless of address —
    /// the platform's own datastores, say (5432, 6379). A pragmatic escape hatch
    /// for the "no allowlist, flag everything" default so an operator can permit
    /// backing services by port without enumerating every replica's IP.
    #[serde(default)]
    pub allow_ports: Vec<u16>,

    /// Loopback egress (127.0.0.0/8, ::1) is local IPC, never C2 — allowed by
    /// default. Turn off only if you specifically hunt localhost pivots.
    #[serde(default = "default_true")]
    pub allow_loopback: bool,

    /// Destinations the policy says MUST be denied (same "ip:port"/bare-IP
    /// spelling as `egress_allow`). These do NOT turn into a firewall rule in
    /// this build: there is no cgroup connect/sendmsg deny program, so a match
    /// produces a critical observe-only finding that says traffic was NOT
    /// blocked. The field exists so a policy can be expressed and reviewed
    /// before a kernel primitive is added; it can never claim enforcement on
    /// its own. `policy.rs` pins that guarantee with tests.
    #[serde(default)]
    pub deny_destinations: Vec<String>,
}

impl Default for NetworkRules {
    fn default() -> Self {
        Self {
            app_egress_only: true,
            egress_allow: vec![],
            allow_ports: vec![],
            allow_loopback: true,
            deny_destinations: vec![],
        }
    }
}

/// Phase 7 cgroup egress enforcement. Every field defaults to the inert state:
/// an omitted `[egress]` table changes nothing about what Warden does to traffic.
///
/// `enabled` and `arm` are two separate switches on purpose. `enabled=true`
/// loads and attaches the four cgroup programs to `cgroup_path` (a test/tenant
/// cgroup — never the host root); with `arm=false` they only COUNT would-denies.
/// `arm=true` additionally flips `CFG_EGRESS_ARM`, so a matching rule really
/// returns -EPERM. A config cannot manufacture an enforcement claim: the runtime
/// still reports attachment and map readiness from the kernel before `policy.rs`
/// will say ENFORCE.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Egress {
    #[serde(default)]
    pub enabled: bool,

    /// Absolute path of a cgroup v2 directory to attach to. Required when
    /// `enabled = true`. Warden refuses a path it cannot stat or that is not a
    /// directory; it never attaches to `/sys/fs/cgroup` itself.
    #[serde(default)]
    pub cgroup_path: Option<PathBuf>,

    #[serde(default)]
    pub arm: bool,

    /// Exact deny destinations. `port = 0` means any port for that address.
    /// Only IP literals are accepted — a name would be a mutable, ambiguous rule.
    #[serde(default)]
    pub deny: Vec<EgressDeny>,
}

/// Local behavioural C2 detection (Phase 4). Deliberately conservative: no
/// finding before several regularly-spaced dials to one destination, no
/// finding on sub-floor bursts or very long gaps, and confidence is degraded
/// when the Phase 1 ring-loss measurement is poor or unavailable. All limits
/// are hard memory bounds — the detector must never grow with host uptime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Rules {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_c2_min_dials")]
    pub min_dials: usize,
    #[serde(default = "default_c2_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_c2_min_interval_secs")]
    pub min_interval_secs: u64,
    #[serde(default = "default_c2_max_interval_secs")]
    pub max_interval_secs: u64,
    #[serde(default = "default_c2_max_jitter")]
    pub max_jitter: f64,
    #[serde(default = "default_c2_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default = "default_c2_max_actors")]
    pub max_actors: usize,
    #[serde(default = "default_c2_max_history")]
    pub max_history: usize,
    #[serde(default = "default_c2_max_destinations")]
    pub max_destinations: usize,
}

const fn default_c2_min_dials() -> usize {
    6
}
const fn default_c2_window_secs() -> u64 {
    900
}
const fn default_c2_min_interval_secs() -> u64 {
    10
}
const fn default_c2_max_interval_secs() -> u64 {
    600
}
const fn default_c2_max_jitter() -> f64 {
    0.5
}
const fn default_c2_cooldown_secs() -> u64 {
    900
}
const fn default_c2_max_actors() -> usize {
    512
}
const fn default_c2_max_history() -> usize {
    32
}
const fn default_c2_max_destinations() -> usize {
    32
}

impl Default for C2Rules {
    fn default() -> Self {
        Self {
            enabled: true,
            min_dials: default_c2_min_dials(),
            window_secs: default_c2_window_secs(),
            min_interval_secs: default_c2_min_interval_secs(),
            max_interval_secs: default_c2_max_interval_secs(),
            max_jitter: default_c2_max_jitter(),
            cooldown_secs: default_c2_cooldown_secs(),
            max_actors: default_c2_max_actors(),
            max_history: default_c2_max_history(),
            max_destinations: default_c2_max_destinations(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredRules {
    /// Only judge privilege raises from a process inside the app cgroup. A web
    /// worker becoming root is an incident; an admin running `sudo` in their
    /// login session is routine. When true (default) and no app cgroup is
    /// configured, the sensor stays quiet rather than flag every `sudo` on the
    /// box — mirroring the same attribution stance as exec and egress.
    #[serde(default = "default_true")]
    pub app_privesc_only: bool,

    /// comm values that are expected to change credentials as their whole job —
    /// the setuid plumbing of a normal login. A raise attributed to one of these
    /// (even inside the app cgroup) is suppressed: `sudo`/`su` becoming root is
    /// what they do. An exploit rarely re-execs as `sudo` first, so this narrows
    /// noise without meaningfully narrowing coverage.
    ///
    /// Since W2K-30a a name here clears a raise ONLY when `/proc/<pid>/exe` either
    /// agrees with it (`sudo` running a binary called `sudo`) or could not be read
    /// at all. A comm is set from inside the process with `prctl(PR_SET_NAME)`, so
    /// matched on its own it was an evasion target, not evidence: name your
    /// exploit `sshd` and never be seen escalating. Pin the paths below to make the
    /// suppression identity-based outright.
    #[serde(default = "default_privilege_comms")]
    pub expected_privilege_comms: Vec<String>,

    /// Absolute executable paths whose credential raise is expected plumbing — the
    /// identity-based version of `expected_privilege_comms`, and the only answer
    /// that survives a forged comm. Compared against `/proc/<pid>/exe` with any
    /// `" (deleted)"` suffix stripped, because a program upgraded under a running
    /// process still IS that executable.
    ///
    /// Empty by default, exactly like `bpf_rules.allow_loader_exes` (W2K-18): empty
    /// does not mean "nothing is plumbing", it means nothing is authorised by path
    /// and the name rule plus its executable check decides. Name
    /// `/usr/bin/sudo`, `/usr/sbin/sshd`, `/usr/bin/pkexec` and the rest of this
    /// host's real setuid plumbing to pin the suppression to files.
    #[serde(default)]
    pub expected_privilege_exes: Vec<String>,

    /// Flag a pure capability gain (no uid→root) as well as an outright root
    /// transition. Capability escalation (e.g. gaining CAP_SYS_ADMIN) is the
    /// subtler, more interesting privesc, so this is on by default.
    #[serde(default = "default_true")]
    pub flag_capability_gain: bool,
}

impl Default for CredRules {
    fn default() -> Self {
        Self {
            app_privesc_only: true,
            expected_privilege_comms: default_privilege_comms(),
            expected_privilege_exes: Vec::new(),
            flag_capability_gain: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtraceRules {
    /// Actor comms whose ptrace of the protected process is routine /proc
    /// metadata reading (PTRACE_MODE_READ), not an attach/inject. These are the
    /// daemons that walk /proc constantly — `fuser` (file-user lookup via
    /// /proc/*/fd and /proc/*/maps), `systemd-journald` (reads /proc/<pid>/ to
    /// attribute logs; note the comm is truncated to 15 chars = "systemd-journal"),
    /// and pid-1 `systemd` (supervision). A READ by one of these is silenced; a
    /// READ by ANY OTHER actor still surfaces at Medium (an unknown process
    /// reading the protected signer's /proc/<pid>/environ or maps is credential
    /// recon). An ATTACH (PTRACE_MODE_ATTACH, 0x02) ALWAYS fires High regardless
    /// of this list — the attach/inject path is never silenced by comm.
    #[serde(default = "default_ptrace_benign_reader_comms")]
    pub benign_reader_comms: Vec<String>,

    /// Actor **executable paths** (resolved from /proc/<pid>/exe) whose READ-mode
    /// ptrace is routine namespace plumbing rather than recon. The container
    /// runtime is the case this exists for: every `docker exec` — including the
    /// HEALTHCHECK that Docker runs every few seconds inside a container — makes
    /// `runc` join that container's namespaces by opening its
    /// /proc/<pid>/ns/* entries, and the kernel reports that as a READ of the
    /// protected pid. One healthcheck per container thus produced a steady
    /// Medium finding storm about the application being supervised.
    ///
    /// Matched against the resolved path, never the comm, because
    /// `prctl(PR_SET_NAME)` lets any process call itself "runc"; placing a file
    /// at the exact allowlisted path is a root-level tamper in its own right.
    /// Only READ is silenced — ATTACH from a runtime still fires High.
    #[serde(default = "default_ptrace_benign_reader_exes")]
    pub benign_reader_exes: Vec<String>,
}

impl Default for PtraceRules {
    fn default() -> Self {
        Self {
            benign_reader_comms: default_ptrace_benign_reader_comms(),
            benign_reader_exes: default_ptrace_benign_reader_exes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRules {
    /// Module names that are allowed to load at runtime, matched exactly against
    /// the name the kernel reports (e.g. "nf_conntrack", "xt_MASQUERADE") — BUT
    /// honoured only for an UNTAINTED module (see judge_module). A stock in-tree
    /// signed module carries no taint; an out-of-tree/unsigned .ko that merely
    /// borrows an allowlisted name still fires, so this list is safe to pre-populate
    /// with the host's standard boot set without opening a name-spoof hole. The
    /// default is the standard Linux networking/firewall/container boot modules
    /// (netfilter, iptables/nftables, bridge, wireguard, xfrm) that modprobe loads
    /// in the first seconds of every boot — the FP storm this quiets. Empty-and-
    /// strict is still available (clear the list) for a host that loads nothing.
    #[serde(default = "default_allow_modules")]
    pub allow_modules: Vec<String>,

    /// Severity ceiling for a NON-allowlisted module. A runtime module load on a
    /// server that shouldn't be loading modules is the rootkit signature, so this
    /// defaults to "critical"; drop it to "high" on a host where late module
    /// loads are merely unusual rather than alarming.
    #[serde(default = "default_module_severity")]
    pub severity: String,
}

impl Default for ModuleRules {
    fn default() -> Self {
        Self {
            allow_modules: default_allow_modules(),
            severity: default_module_severity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRules {
    /// Only judge destructive file ops from a process inside the app cgroup, in
    /// keeping with exec/egress/privesc attribution: a request worker rewriting
    /// files is the ransomware signal; an admin's `rm` in a login shell is noise.
    /// The burst rule in particular would be all false positives from a package
    /// manager or a build if it fired box-wide. When true (default) and no app
    /// cgroup is configured, the sensor stays quiet — EXCEPT for a `watch_paths`
    /// hit, which is a targeted-tamper signal worth surfacing no matter who did
    /// it (see `judge_file`).
    #[serde(default = "default_true")]
    pub app_files_only: bool,

    /// Filename substrings whose rename/unlink is always a finding regardless of
    /// actor or cgroup — the crown jewels. Matched against the affected leaf name
    /// (e.g. "shadow", ".env", "audit.log", "id_rsa"). Empty by default: an
    /// operator opts in to the paths that matter on their box.
    #[serde(default)]
    pub watch_names: Vec<String>,

    /// Extensions (or name suffixes) that a rename INTO is the ransomware
    /// signature — the malware renames victim files to mark them encrypted. The
    /// defaults are the most common real-world families' markers; matched
    /// case-insensitively against the new leaf name on a rename.
    #[serde(default = "default_ransom_exts")]
    pub ransom_extensions: Vec<String>,

    /// How many destructive ops from one actor within `burst_window_secs` trip
    /// the behavioural ransomware rule (mass modification). 0 disables the burst
    /// rule, leaving only the name/extension rules. The default catches an
    /// encryptor churning through a directory without waiting for a known
    /// extension to appear.
    #[serde(default = "default_burst_threshold")]
    pub burst_threshold: u32,

    /// The sliding window, in seconds, over which `burst_threshold` is counted.
    #[serde(default = "default_burst_window")]
    pub burst_window_secs: u64,
}

impl Default for FileRules {
    fn default() -> Self {
        Self {
            app_files_only: true,
            watch_names: vec![],
            ransom_extensions: default_ransom_exts(),
            burst_threshold: default_burst_threshold(),
            burst_window_secs: default_burst_window(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRules {
    /// Path substrings that mark a directory as a persistence location — the
    /// boot/login-survival dirs an implant must write into to outlive a reboot or
    /// re-run at logon. A file CREATED anywhere a persistence dir substring
    /// matches is a finding unless its path is on `allow_paths`. Matched
    /// case-insensitively against the rebuilt trailing path (leaf + up to three
    /// ancestors). The defaults cover the standard Linux vectors — systemd unit
    /// trees, cron, XDG autostart, SysV init, the dynamic-linker preload, and the
    /// SSH key store. Trim or extend for your host; an EMPTY list disables the
    /// sensor's verdict entirely (every create is then allowlisted).
    #[serde(default = "default_persistence_dirs")]
    pub persistence_dirs: Vec<String>,

    /// Paths (or path substrings) whose creation under a persistence dir is
    /// expected and must NOT fire — the sanctioned units your own provisioning
    /// lays down. Matched case-insensitively against the rebuilt path, checked
    /// before `persistence_dirs`, so a single sanctioned unit doesn't force you to
    /// drop a whole directory from the watch list. Empty by default: the strictest
    /// posture is that no runtime write into a persistence dir is expected at all.
    #[serde(default)]
    pub allow_paths: Vec<String>,

    /// Severity for a non-allowlisted persistence write. A fresh systemd unit or
    /// cron entry on a server whose service set is fixed at provisioning time is
    /// the textbook persistence signature, so this defaults to "critical"; drop it
    /// to "high" on a host where late unit writes are unusual rather than alarming.
    #[serde(default = "default_service_severity")]
    pub severity: String,
}

impl Default for ServiceRules {
    fn default() -> Self {
        Self {
            persistence_dirs: default_persistence_dirs(),
            allow_paths: vec![],
            severity: default_service_severity(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenRules {
    /// Only judge listeners opened by a process inside the app cgroup. A worker
    /// that suddenly starts listening on a port is the bind-shell / backdoor
    /// signal; sshd, systemd sockets, and an admin's own test server are noise.
    /// When true (default) and no app cgroup is configured, the sensor stays
    /// quiet rather than flag every LISTEN on the box — the same attribution
    /// stance as egress. Set false (with a tight `allow_ports`) only if you want
    /// to police every new listener host-wide.
    #[serde(default = "default_true")]
    pub app_listen_only: bool,

    /// Local bound ports that are the app's own service ports and never warrant a
    /// finding (e.g. 8000, 8443). The dual of `network_rules.allow_ports`. Empty
    /// by default: the strictest posture is that a request worker opens NO new
    /// listeners at runtime, so any listen it performs is surfaced.
    #[serde(default)]
    pub allow_ports: Vec<u16>,

    /// A listener bound to loopback (127.0.0.0/8, ::1) is a local-only helper,
    /// unreachable from off-box, so it cannot be an inbound backdoor — allowed by
    /// default. Turn off only if you specifically hunt localhost pivots.
    #[serde(default = "default_true")]
    pub allow_loopback: bool,
}

impl Default for ListenRules {
    fn default() -> Self {
        Self {
            app_listen_only: true,
            allow_ports: vec![],
            allow_loopback: true,
        }
    }
}

/// Floor for `network_snapshot.interval_secs`. The snapshot walks `/proc` twice
/// over (the table, then the fd links that attribute it), so a sub-5s cadence is
/// a polling loop pointed at the cheapest source of truth available — and the
/// push path already covers change in real time. 5 s is low enough to catch a
/// bind-shell and high enough that the pull path can never out-cost the sensors.
pub const MIN_SNAPSHOT_INTERVAL_SECS: u64 = 5;

/// The pull path: read the kernel's socket table and diff it against what the
/// sensors reported.
///
/// This section exists because of a limitation the push sensors cannot argue
/// with: `security_socket_connect` and `security_socket_listen` see a *change*,
/// so anything that was already true when Warden attached — a listener that
/// predates the daemon, a connection opened during the window the ring was
/// full — is invisible forever. `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` hold
/// the current state, not the transition, and cost no new privilege to read.
///
/// Off by default. It is a periodic `/proc` walk inside the same single-threaded
/// loop that drains the ring, so its cost is a decision, not a free win; and on
/// a host whose app cgroup is not configured (§39 of the report calls this N-11)
/// the pull path reports the whole host's socket table to the journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    /// Whether the reconciler runs at all.
    #[serde(default)]
    pub enabled: bool,

    /// How often to take a snapshot. SIGHUP can move it; the loop re-reads
    /// policy every tick, so unlike `[bridge]` this section is fully live.
    #[serde(default = "default_snapshot_interval")]
    pub interval_secs: u64,

    /// Resolve each socket's inode back to the process that owns it by walking
    /// `/proc/<pid>/fd`. This is the whole point of the pull path — without it
    /// the snapshot is `netstat`, and Warden's contribution is process↔socket
    /// attribution. It is also the expensive half, so it is bounded by the two
    /// knobs below and reported as partial when a bound is hit.
    #[serde(default = "default_true")]
    pub attribute: bool,

    /// Sockets to attribute per tick. Only the sockets that will be *reported*
    /// need an owner, so the walk is bounded by the report, not by the table.
    #[serde(default = "default_snapshot_report_max")]
    pub report_max_sockets: usize,

    /// Cap on the `/proc/<pid>/fd` scans one tick may perform. Hitting it stops
    /// the walk, and the report says the walk "stopped at its N-pid budget"
    /// rather than leaving an unattributed socket to be read as a socket with no
    /// owner — a bound is a different fact from an absence, and the two are never
    /// collapsed into one line.
    #[serde(default = "default_snapshot_scan_max")]
    pub attribute_max_pids: u32,
}

fn default_snapshot_interval() -> u64 {
    300
}
fn default_snapshot_report_max() -> usize {
    32
}
fn default_snapshot_scan_max() -> u32 {
    4096
}

impl Default for NetworkSnapshot {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: default_snapshot_interval(),
            attribute: true,
            report_max_sockets: default_snapshot_report_max(),
            attribute_max_pids: default_snapshot_scan_max(),
        }
    }
}

/// Floor for `net_volume.interval_secs`. The read is one map walk plus a cgroup
/// tree walk — cheap against `/proc`, but it is still a walk, and the totals it
/// reports are cumulative so a shorter interval buys nothing but a shorter
/// sample window. 5 s matches the snapshot floor so the two pull sensors share
/// one cadence rule an operator already knows.
pub const MIN_NET_VOLUME_INTERVAL_SECS: u64 = 5;

/// What the agent can actually deliver. The volume tick runs inside the protect
/// refresh loop, so a request finer than this is not honoured: measured on the
/// deployment host, `interval_secs = 5` produced ticks exactly 10.0 s apart. The
/// constant lives here rather than being read from `main.rs` so the report line
/// can state the deliverable cadence without importing the event loop, and
/// `main.rs` pins it against `PROTECT_REFRESH` with a const assertion — if the
/// loop period ever changes, the build fails instead of the claim going stale.
/// `net_snap`'s interval has the same floor and predates this finding; it is not
/// changed here, only recorded.
pub const NET_VOLUME_TICK_GRANULARITY_SECS: u64 = 10;

/// The kernel-side volume counters (N-05, roadmap stage 16b): per-cgroup byte and
/// operation totals kept in a BPF hash map by four `fexit` programs on
/// `tcp_sendmsg`, `tcp_cleanup_rbuf`, `udp_sendmsg` and `udp_recvmsg`, and read
/// back once per interval.
///
/// This section exists because the events ring cannot answer a volume question. A
/// 344-byte record carrying ~12 bytes of network fact, on a 256 KiB lossy ring
/// that holds ≈760 records in flight, loses the records that would have summed to
/// the answer exactly when the answer matters — under load. Counting in the kernel
/// and reading the totals in userspace inverts the cost: a few atomic adds per
/// syscall, and no per-byte trip into userspace at all.
///
/// Off by default, unlike the sensors' emit gates: attaching three trampolines to
/// the TCP/UDP data path is a change to how every socket on the host does I/O, and
/// "the totals nobody asked for are now costing every send on this box" is not a
/// trade Warden should make silently on a lightweight VPS. When off, the agent
/// says so on the coverage line rather than leaving the absence to be read as a
/// quiet host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetVolume {
    /// Whether the fexit programs count at all. Gates the bump path through
    /// `CFG_NET_VOLUME_EMIT`, so flipping it does not need a detach or a restart.
    #[serde(default)]
    pub enabled: bool,

    /// How often to read the totals and report movement.
    #[serde(default = "default_net_volume_interval")]
    pub interval_secs: u64,

    /// The floor for one cgroup to earn a line in the tick report. Set against
    /// the movement since the last tick, not the lifetime total, so a busy tenant
    /// is reported because it is busy now.
    #[serde(default = "default_net_volume_floor")]
    pub report_min_bytes: u64,

    /// How many cgroups one tick line may name. The tick is a heartbeat, not a
    /// metrics endpoint: an unbounded report is a journal flood with a legit
    /// reason. The count is bounded, the byte totals are not.
    #[serde(default = "default_net_volume_rows")]
    pub max_rows_per_tick: usize,

    /// Cap on the `/sys/fs/cgroup` walk that turns a cgroup id into a path. The
    /// ids are counted regardless; this only bounds how many can be *named*, so
    /// an enormous hierarchy costs a bounded walk and an unresolved id prints as
    /// unresolved rather than as a guess.
    #[serde(default = "default_net_volume_walk_max")]
    pub cgroup_walk_max: usize,

    /// Where to walk for cgroup paths. cgroup v2 is normally mounted here; a host
    /// that mounts it elsewhere (or a test that fakes one) points at its own path
    /// and the rest of the sensor is unchanged.
    #[serde(default = "default_net_volume_cgroup_root")]
    pub cgroup_root: PathBuf,
}

fn default_net_volume_interval() -> u64 {
    60
}
fn default_net_volume_floor() -> u64 {
    65536
}
fn default_net_volume_rows() -> usize {
    8
}
fn default_net_volume_walk_max() -> usize {
    4096
}
fn default_net_volume_cgroup_root() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

impl Default for NetVolume {
    fn default() -> Self {
        Self {
            // Off: the data path is not touched until an operator asks for these
            // totals. See the section comment.
            enabled: false,
            interval_secs: default_net_volume_interval(),
            report_min_bytes: default_net_volume_floor(),
            max_rows_per_tick: default_net_volume_rows(),
            cgroup_walk_max: default_net_volume_walk_max(),
            cgroup_root: default_net_volume_cgroup_root(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfRules {
    /// comm values that may load eBPF programs when the loader's executable cannot be
    /// read. Since W2K-18 this is NOT the authorization: a comm is a string the process
    /// chose with `prctl(PR_SET_NAME)`, so only `allow_loader_exes` can clear a load
    /// whose `/proc/<pid>/exe` was readable. What is left here decides the narrower,
    /// honestly-unverifiable case — the loader had exited before userspace enriched the
    /// record. Keep it tight (Warden itself, a sanctioned tracer); every other load by
    /// an unknown name is a finding.
    #[serde(default = "default_bpf_loaders")]
    pub allow_loaders: Vec<String>,

    /// Absolute executable paths authorised to load an implant-capable program —
    /// the ONLY thing that authorises one. `allow_loaders` is a name, and a name is
    /// forged with one `prctl(PR_SET_NAME)` call, so it was never evidence of identity
    /// (spec P0-3, W2K-18). A load whose `/proc/<pid>/exe` could be read is suppressed
    /// ONLY by an exact match against that path. The comm list still carries a load
    /// whose exe is unreadable — the loader already exited, which is the normal shape
    /// for a short-lived one — and that is the weaker posture `--check` names. An
    /// empty list here therefore means NO loader is authorised by identity, and every
    /// readable-exe implant load is a finding. Matched after stripping a `" (deleted)"`
    /// suffix, because a loader upgraded under a running process still IS that
    /// executable.
    #[serde(default)]
    pub allow_loader_exes: Vec<String>,

    /// Severity for a NON-allowlisted BPF program load. An unexpected in-kernel
    /// eBPF implant is a stealth-rootkit signature, so this defaults to
    /// "critical"; drop it to "high" on a host where ad-hoc tracing is common.
    #[serde(default = "default_bpf_severity")]
    pub severity: String,

    /// The `bpf_prog_type` values worth surfacing — the program kinds that can
    /// actually act as an implant: hook kernel functions, read or tamper kernel
    /// memory, hide a process, or silently steer packets (kprobe, tracepoint,
    /// raw_tracepoint, perf_event, tracing/fentry, lsm, xdp, struct_ops, ext,
    /// syscall). The init system, systemd-networkd, and container runtimes load
    /// BENIGN cgroup/socket filters (cgroup_skb, cgroup_device, sock_ops,
    /// socket_filter, …) constantly — those cannot hook syscalls or hide anything,
    /// so a bare "a BPF program was loaded" fires on every service start. Matched
    /// by numeric `enum bpf_prog_type` (a stable kernel ABI): 2=kprobe, 5=tracepoint,
    /// 6=xdp, 7=perf_event, 17=raw_tracepoint, 24=raw_tracepoint_writable,
    /// 26=tracing, 27=struct_ops, 28=ext, 29=lsm, 31=syscall. A load whose type is
    /// NOT on this list is silent (a benign filter); a load of UNSPEC/unknown type
    /// (0, e.g. an unreadable attr) fails toward surfacing. An EMPTY list disables
    /// the type narrowing entirely — every non-allowlisted load fires, the
    /// maximally-paranoid posture for a host that loads no BPF of its own.
    #[serde(default = "default_bpf_watch_prog_types")]
    pub watch_prog_types: Vec<u32>,
}

impl Default for BpfRules {
    fn default() -> Self {
        Self {
            allow_loaders: default_bpf_loaders(),
            allow_loader_exes: Vec::new(),
            severity: default_bpf_severity(),
            watch_prog_types: default_bpf_watch_prog_types(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRules {
    /// Only judge BIND mounts (MS_BIND). A bind mount grafting a host path into a
    /// new location is the escape signature; a plain filesystem mount's source is
    /// a block device or an fs token, which is routine admin work. On by default
    /// so ordinary `mount /dev/sdb1 …` never fires. Turn off to police every mount
    /// of a watched source on a host where NO runtime mounts are expected at all.
    #[serde(default = "default_true")]
    pub bind_only: bool,

    /// Mount-source substrings worth policing — the shapes a contained attacker
    /// uses to break out. Matched case-insensitively against the mount source
    /// (device / bind path). The defaults catch the classic container-escape
    /// tells: a bind mount grafting the host root or a host device tree
    /// ("/dev", "/proc", "/sys", "/etc", "/root", "/var/run/docker.sock") into a
    /// new location. An EMPTY list disables the sensor's verdict entirely.
    #[serde(default = "default_mount_watch_sources")]
    pub watch_sources: Vec<String>,

    /// Mount sources whose mount is expected and must NOT fire — the volumes your
    /// own provisioning/orchestrator legitimately mounts. Matched
    /// case-insensitively against the source, checked before `watch_sources`.
    /// Empty by default.
    #[serde(default)]
    pub allow_sources: Vec<String>,

    /// Source-path PREFIXES that are sandbox/namespace construction, not host
    /// escape, and must never fire regardless of what they contain. A desktop
    /// sandbox (bwrap, flatpak, the polkit agent) builds its mount namespace by
    /// bind-mounting dozens of paths UNDER a private staging root — `/oldroot/...`
    /// (the pivot_root old-root), `/proc/self/fd/N` (an fd-relative bind),
    /// `/run/systemd/namespace-*` and `/run/user/*/.flatpak/*` (private runtime
    /// dirs). Their leaf still contains "/dev", "/etc", "/proc" as a SUBSTRING, so
    /// without this they read as host-path escapes. Anything whose source begins
    /// with one of these prefixes (after boundary-aware matching) is sandbox
    /// internals and is dropped up front. Matched case-insensitively as a genuine
    /// path prefix (component boundary), so "/proc" here does NOT swallow a real
    /// "/proc" host bind — only "/proc/self/fd/..." and the like.
    ///
    /// W2K-05: that prefix is also camouflage, because mount(2) resolves
    /// "/proc/self/fd/N" through the CALLER's fd table. The exemption is therefore
    /// honoured only for actors OUTSIDE the app cgroup; a contained actor's source
    /// is resolved through its own /proc and the real target is judged.
    #[serde(default = "default_mount_ignore_prefixes")]
    pub ignore_source_prefixes: Vec<String>,

    /// Pseudo-device sources whose BIND is benign no matter where it lands —
    /// matched by EXACT path (case-insensitive), never as a prefix. This is the
    /// discriminator the source-prefix and destination-marker approaches could
    /// not give. A hardened systemd unit (PrivateDevices=, ProtectSystem=) builds
    /// its private /dev by bind-mounting the REAL host pseudo-devices — /dev/null,
    /// /dev/zero, /dev/pts, /dev/shm, … — each to the SAME target path in its new
    /// namespace (/dev/null -> /dev/null). The source is a genuine child of the
    /// watched "/dev" tree AND the destination is identical, so neither source-
    /// watch nor dest-marker can tell it from an escape; every hardened unit start
    /// therefore fired the /dev bind storm (polkitd, systemd-logind, …). The SET
    /// of sources is the tell: this is a fixed, well-known list of harmless nodes,
    /// binding one grants no host access. Because the match is EXACT, an escape —
    /// which binds the whole "/dev" tree, a raw disk ("/dev/sda", "/dev/mem"), or
    /// the device mapper, none of which EQUALS a listed leaf — still fires. An
    /// empty list disables the allowlist (every /dev bind is then policed again).
    #[serde(default = "default_mount_allow_pseudo_device_binds")]
    pub allow_pseudo_device_binds: Vec<String>,

    /// Severity for a watched, non-allowlisted mount. A bind mount of the host
    /// root into a container is the textbook escape, so this defaults to "high";
    /// raise to "critical" on a host where NO runtime mounts are ever expected.
    #[serde(default = "default_mount_severity")]
    pub severity: String,

    /// Executable paths (resolved from /proc/<pid>/exe, NOT the spoofable comm)
    /// whose bind mounts are host confinement CONSTRUCTION, not escape. snap-confine
    /// and systemd build a sandbox by bind-mounting whole host trees (/dev, /etc,
    /// /proc, /sys, /root), byte-identical to an escape binding the same path — so
    /// no source allowlist can separate them, but the real on-disk binary can. Keyed
    /// on exe because `comm` is a 15-char label any process sets via prctl: a comm
    /// allowlist would let a contained attacker name itself "snap-confine" and bind
    /// host / silently. Suppression here is further gated (see judge_mount) by the
    /// actor being OUTSIDE the app cgroup, a non-deleted exe, and the source NOT
    /// being a never-benign bind (`suppress_exempt_sources`). Empty disables it.
    #[serde(default = "default_mount_allow_actor_exes")]
    pub allow_actor_exes: Vec<String>,

    /// Sources whose bind ALWAYS fires, even by an `allow_actor_exes` actor — the
    /// never-benign host-control shapes that are never part of sandbox /dev
    /// construction: raw block devices (/dev/sd*, /dev/nvme*, /dev/mapper), kernel
    /// memory (/dev/mem, /dev/kmem), and the container-runtime sockets. Matched as
    /// a leading prefix of the source. This is the carve-out that stops the exe
    /// allowlist from ever short-circuiting a raw-disk or docker.sock escape.
    #[serde(default = "default_mount_suppress_exempt_sources")]
    pub suppress_exempt_sources: Vec<String>,
}

impl Default for MountRules {
    fn default() -> Self {
        Self {
            bind_only: true,
            watch_sources: default_mount_watch_sources(),
            allow_sources: vec![],
            ignore_source_prefixes: default_mount_ignore_prefixes(),
            allow_pseudo_device_binds: default_mount_allow_pseudo_device_binds(),
            severity: default_mount_severity(),
            allow_actor_exes: default_mount_allow_actor_exes(),
            suppress_exempt_sources: default_mount_suppress_exempt_sources(),
        }
    }
}

/// A single guarded file: a path plus who is allowed to touch it and how. The
/// enforcing layer resolves the path to its (dev, ino) at load time and installs
/// a per-inode policy the kernel's BPF-LSM programs consult on every open / mmap
/// / unlink / rename / setattr. This is the one Warden rule that can PREVENT — an
/// unauthorised actor (including root, unless `allow_root`) touching the file with
/// a denied intent is refused in-kernel with -EPERM, before the bytes are handed
/// over. Keyed on the resolved inode (not the path string) so it is unspoofable by
/// symlink / hardlink / bind / `..`, and re-resolved on the refresh tick so a
/// file rewritten in place (new inode) stays protected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardedFile {
    /// Absolute path to the file to guard (e.g. "/etc/warden/wallet.key"). Stat'd
    /// to (dev, ino) at load and on each refresh; a path that doesn't resolve is
    /// skipped with a warning (nothing is guarded rather than everything).
    pub path: String,

    /// The ONE uid permitted the denied operations — the app's own service account
    /// (e.g. the uid the wallet-signing process runs as). Every other uid touching
    /// the file with a denied intent is the incident. Root is NOT special unless
    /// `allow_root` is set: a stolen root shell reading the key is exactly what this
    /// prevents. Note the interaction with `allow_root`: `0` here permits root by
    /// definition, so naming uid 0 while leaving `allow_root` off is a
    /// contradiction `Config::validate` refuses to load. To deny every writer,
    /// including root, name a uid that is not a login and cannot write the file
    /// (the deploy helper uses nobody, 65534), leaving `allow_root` off.
    pub authorized_uid: u32,

    /// Which intents are denied to an unauthorised actor: any of "read", "write",
    /// "exec". A secret key denies ["read","write"]; an append-only audit log might
    /// deny only ["write"]. Empty means nothing is denied (the file is watched-only
    /// — every access still emits a shadow record, but none would ever be blocked),
    /// which is rarely what you want; default is read+write when omitted.
    #[serde(default = "default_deny_intents")]
    pub deny: Vec<String>,

    /// Also allow uid 0 (root) the denied intents — for a file the app legitimately
    /// touches AS root (a root-owned daemon's key). Off by default: the whole point
    /// is that root is not implicitly trusted with a guarded secret.
    #[serde(default)]
    pub allow_root: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforceRules {
    /// The ENFORCING gate — the single, deliberate flip from observation to
    /// prevention. When false (DEFAULT), every guard runs in SHADOW: it does the
    /// full lookup and decision and emits a "would-deny" record, but ALLOWS the
    /// operation through. When true, an unauthorised access to a guarded inode with
    /// a denied intent is REFUSED in-kernel (-EPERM). This is shadow-first by
    /// design: a wrong deny can lock the box out of its own files, and arming
    /// denial for a file whose authorized_uid is wrong is self-inflicted downtime,
    /// so an operator watches the shadow findings until they trust them, THEN arms.
    /// Fails CLOSED to shadow: anything but an explicit true is treated as shadow.
    #[serde(default)]
    pub arm: bool,

    /// The files the BPF-LSM layer guards. Empty by default — the enforcing layer
    /// installs no policy and denies nothing until an operator names the crown
    /// jewels (wallet keys, the audit log, the allowlist itself). Each entry is
    /// resolved to its (dev, ino) at load and on the refresh tick.
    #[serde(default)]
    pub guarded_files: Vec<GuardedFile>,
}

/// WARDEN_INTENT_* bits — mirror the defines in warden.h. Kept here (not only in
/// events.rs) so config can turn a `deny` string list into the kernel's mask
/// without a cross-module dependency on the wire decoder.
pub const WARDEN_INTENT_READ: u32 = 0x1;
pub const WARDEN_INTENT_WRITE: u32 = 0x2;
pub const WARDEN_INTENT_EXEC: u32 = 0x4;
/// warden_guard_policy.flags bit — mirror of WARDEN_GUARD_ALLOW_ROOT in warden.h.
pub const WARDEN_GUARD_ALLOW_ROOT: u32 = 0x1;

impl GuardedFile {
    /// The `deny` string list turned into the kernel's WARDEN_INTENT_* mask.
    /// Unknown intent words are ignored (a typo denies nothing rather than
    /// everything — fail toward not locking the box out). Matched case-insensitively.
    pub fn deny_mask(&self) -> u32 {
        let mut m = 0u32;
        for word in &self.deny {
            match word.trim().to_ascii_lowercase().as_str() {
                "read" | "r" => m |= WARDEN_INTENT_READ,
                "write" | "w" => m |= WARDEN_INTENT_WRITE,
                "exec" | "x" | "execute" => m |= WARDEN_INTENT_EXEC,
                _ => {} // unknown → ignore; never widens the deny set
            }
        }
        m
    }

    /// The warden_guard_policy.flags value for this file.
    pub fn flags(&self) -> u32 {
        if self.allow_root {
            WARDEN_GUARD_ALLOW_ROOT
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Respond {
    /// Allow killing a confirmed reverse shell (bpf_send_signal path is future;
    /// today userspace kill(2)). Opt-in — the riskiest responder (self-DoS).
    #[serde(default)]
    pub kill_reverse_shell: bool,
    /// Allow killing a process that signalled/ptraced a protected pid.
    #[serde(default)]
    pub kill_takedown_attacker: bool,
    /// Allow killing a process that just escalated privilege inside the app.
    /// Off by default: a false positive here kills a process that is now root,
    /// so the bar to enable is deliberately high.
    #[serde(default)]
    pub kill_privilege_escalation: bool,
    /// Allow killing a process caught mass-modifying files (ransomware). Off by
    /// default like the rest, but this is the one responder whose *benefit* most
    /// outweighs its risk once findings are trusted: stopping an encryptor a few
    /// hundred files in saves the rest. Enable only after observing clean bursts.
    #[serde(default)]
    pub kill_ransomware: bool,
    /// W2K-25 — may a SIGKILL be delivered to a process whose identity the
    /// event cannot anchor?
    ///
    /// The arm this governs is narrow: `/proc` was unreadable when the finding
    /// was enriched (so no start time was recorded), yet readable now. The
    /// responder can see *a* process at that number but cannot show it is the
    /// one the event named, so "kill it anyway" is an unproven signal — and
    /// §۷۰-۱۰ T2 measured that the code did exactly that. Spec 4.2 item 7
    /// forbids it, so the default refuses.
    ///
    /// `false` restores the previous behaviour (warn, then kill). Choose `false`
    /// only where killing an occasional wrong process costs less than letting an
    /// attacker live for the length of one event; the log line says which policy
    /// is in force either way, so a refusal is never mistaken for a kill.
    #[serde(default = "default_true")]
    pub require_anchored_identity: bool,
}

impl Default for Respond {
    /// Hand-written rather than derived, so the two ways a `Respond` is built
    /// cannot disagree. `#[derive(Default)]` would make
    /// `require_anchored_identity` false — the permissive value — while serde's
    /// `default = "default_true"` made it true, so a test or a struct literal
    /// built from `Default` would be measuring a policy no config file can ask
    /// for, and the four kill toggles would still be off by luck of their type.
    fn default() -> Self {
        Self {
            kill_reverse_shell: false,
            kill_takedown_attacker: false,
            kill_privilege_escalation: false,
            kill_ransomware: false,
            require_anchored_identity: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bridge {
    /// Full URL of the Sentinel host-ingest endpoint.
    pub url: String,
    /// X-API-Key value (a Sentinel ClientAPIKey with service == "sentinel").
    pub api_key: String,
    /// Logical host/asset id to stamp on every finding.
    #[serde(default = "default_host")]
    pub host: String,
    /// One budget for one delivery attempt, in ms — resolve + connect + write +
    /// read together, not each of them separately. A finding that cannot be
    /// shipped inside it is retried later, out of a queue; it is no longer
    /// dropped.
    #[serde(default = "default_bridge_timeout")]
    pub timeout_ms: u64,
    /// How many findings may wait in memory for the sender thread. The queue is
    /// what absorbs a burst while the network is slower than the event stream;
    /// when it fills, the finding goes straight to the spool instead of being
    /// discarded, and if the spool is full too it is dropped and counted.
    #[serde(default = "default_queue_max")]
    pub queue_max: usize,
    /// Where undelivered findings wait out a Sentinel outage. Append-only, one
    /// JSON envelope per line, mode 0600 — it holds process paths, command
    /// lines and pids, so it is as sensitive as the journal and is treated that
    /// way. Under systemd this lives in the service's StateDirectory.
    #[serde(default = "default_spool_path")]
    pub spool_path: PathBuf,
    /// Hard cap on the spool's size on disk. Reaching it is the one case where a
    /// finding is dropped outright during an outage, and it is logged as such:
    /// the alternative — an unbounded file on the host's root filesystem — turns
    /// a Sentinel outage into a host outage.
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
    /// First retry delay after a transient failure. Doubles per consecutive
    /// failure up to `max_backoff_ms`, and resets on the first success.
    #[serde(default = "default_backoff_ms")]
    pub backoff_ms: u64,
    /// Ceiling on the retry delay, so a long outage is still probed often enough
    /// to notice that it ended promptly.
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    /// W2K-19: the deployment constraint that keeps "TLS terminates at the edge"
    /// honest. A `bridge.url` whose host is a public IP literal is refused at load,
    /// because the request carries `X-API-Key` and every finding's command line,
    /// executable path and pid in the clear. W2K-28 closed the spelling around it:
    /// a NAME is resolved once at startup (`resolve_uplink_names`) and the same
    /// refusal applies to the answer, and the delivery path classifies the address
    /// it actually connects to (`BridgeClient::resolve`), because a load-time answer
    /// is not the answer a request gets. Set this to `true` only when that path
    /// really is protected by something Warden cannot see (an IPsec or WireGuard
    /// tunnel, a provider-private VPC); it is an attestation, not a transport.
    #[serde(default)]
    pub allow_public_plaintext: bool,
    /// Where findings Sentinel REFUSED with a per-index HTTP 400 are kept.
    /// A 400 means the server read the finding and named it unacceptable; the
    /// old code dropped the whole batch, including up to 63 good findings.
    /// Named findings now go here — append-only JSON lines, mode 0600, exact
    /// envelope preserved — for an operator to inspect and replay after the
    /// contract is fixed. `None` means a sibling of `spool_path` named
    /// `bridge_quarantine.jsonl`. Optional so existing deploy configs need no
    /// edit; the `unread_keys` audit knows the field either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_path: Option<PathBuf>,
    /// Phase 8: CA certificate used to verify the Sentinel server. Together
    /// with the two fields below this turns the bridge into a mutual-TLS client
    /// instead of a cleartext HTTP client. All three are required; a partial
    /// triple is a config error, never a silent downgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_file: Option<PathBuf>,
    /// Phase 8: the agent's own certificate, issued to this agent identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_file: Option<PathBuf>,
    /// Phase 8: the agent's private key. Only its path is ever logged. OpenSSL
    /// requires mode 0600; Warden checks that at load time and refuses a
    /// group/world-readable key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_file: Option<PathBuf>,
    /// TLS SNI / hostname to verify. Defaults to the URL host; set it when the
    /// endpoint is an IP literal but the certificate names a DNS host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_sni: Option<String>,
}

impl Bridge {
    /// True only when a COMPLETE mTLS material set is configured. A half-set is
    /// rejected by `Config::validate`, so this predicate is also the transport
    /// decision: no partial configuration can accidentally mean "TLS, but
    /// without client identity".
    pub fn mtls_enabled(&self) -> bool {
        self.tls_ca_file.is_some() && self.tls_cert_file.is_some() && self.tls_key_file.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// URL pinged every `interval_secs`; a gap is the dead-man's-switch alarm
    /// on the far side (off-box collector).
    pub url: String,
    #[serde(default = "default_hb_interval")]
    pub interval_secs: u64,
    /// Optional shared secret. When set, each beat carries an HMAC-SHA256 over
    /// `host|seq|ts` so an attacker who merely reads this URL out of warden.toml
    /// cannot FORGE a "still alive" ping to mask a takedown — the collector
    /// verifies the MAC and rejects an unsigned or wrong-key beat. Strongly
    /// recommended: an unauthenticated heartbeat is spoofable. Guard warden.toml
    /// (see [[enforce.guarded_files]]) so the secret itself is not root-readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// Where the monotonic beat sequence number is persisted (0600) so it keeps
    /// climbing across restarts — the collector rejects a replayed/stale seq.
    /// Defaults to /var/lib/warden/hb_seq.
    #[serde(default = "default_hb_seq_file")]
    pub seq_file: String,
    /// W2K-19, same constraint as `bridge.allow_public_plaintext` and the same
    /// reason: a beat over a public cleartext hop tells anyone on the path that
    /// this host is alive, which is precisely what a dead-man's switch must not do.
    #[serde(default)]
    pub allow_public_plaintext: bool,
}

/// Where a cleartext-HTTP uplink address actually points. The type exists because
/// the accepted design boundary ("TLS terminates at the edge; the Warden→edge hop
/// is a trusted path") is a claim about *the path*, and only part of it is checkable
/// from config: an IP literal is classified by `classify_uplink` alone, a hostname
/// only by asking DNS — which is why the NAME case is settled by
/// `resolve_uplink_names`, once per process at startup, and not inside `validate()`:
/// a resolver at config-load is a network dependency, a delay, and an answer the
/// attacker can influence. The influence is not unlimited, though: the delivery path
/// re-checks the address it actually connects to (`BridgeClient::resolve`), so the
/// lookup here is the audible answer and that one is the enforced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UplinkTarget {
    /// 127.0.0.0/8 or ::1 — the frame never reaches a wire.
    Loopback,
    /// RFC1918, RFC6598 CGNAT (what WireGuard/Tailscale networks usually hand out),
    /// link-local, or IPv6 ULA. Private does not mean safe; it means not routable
    /// on the public internet, which is the part an operator can be held to.
    Private,
    /// Routable on the public internet. Refused over cleartext unless the operator
    /// attests the path is protected some other way.
    Public,
    /// A hostname, or anything else that is not an IP literal: unclassifiable here.
    Name,
}

/// The authority (host[:port]) of an `http://`/`https://` URL, with userinfo and a
/// bracketed IPv6 literal handled. Deliberately forgiving about the rest of the URL:
/// this feeds a security classification, not a request, and a URL the HTTP client
/// dislikes is already rejected by it.
pub fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest)?;
    let authority = after_scheme.split('/').next().unwrap_or("");
    // userinfo can only precede the last '@' of the authority.
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed
            .split(']')
            .next()
            .filter(|h| !h.is_empty())
            .map(str::to_string);
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// Classify the destination of an uplink URL. Returns `Name` for anything that is
/// not an IP literal, including a URL this parser cannot read — the conservative
/// answer, since `Name` is reported and `Public` is refused.
pub fn classify_uplink(url: &str) -> UplinkTarget {
    let host = match url_host(url) {
        Some(host) => host,
        None => return UplinkTarget::Name,
    };
    classify_host(&host)
}

/// The same classification from a bare host string, so an IPv4-mapped IPv6 literal
/// can be judged by the v4 it carries instead of looping back into itself.
fn classify_host(host: &str) -> UplinkTarget {
    let Ok(ip) = host.parse::<std::net::IpAddr>() else {
        return UplinkTarget::Name;
    };
    classify_ip(ip)
}

/// The classification of an address already in hand — which is what a resolved
/// hostname yields, and the only way a NAME can be judged at all (W2K-28).
pub fn classify_ip(ip: std::net::IpAddr) -> UplinkTarget {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // RFC6598 CGNAT (100.64.0.0/10) — the range overlay networks like
            // WireGuard and Tailscale usually hand out, so leaving it out would
            // refuse the exact deployment this constraint documents. Checked by
            // hand because `Ipv4Addr::is_shared` is still an unstable feature.
            let cgnat = octets[0] == 100 && (octets[1] & 0xC0) == 0x40;
            if v4.is_loopback() {
                UplinkTarget::Loopback
            } else if v4.is_private() || cgnat || v4.is_link_local() {
                UplinkTarget::Private
            } else {
                UplinkTarget::Public
            }
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return classify_host(&mapped.to_string());
            }
            if v6.is_loopback() {
                UplinkTarget::Loopback
            } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                UplinkTarget::Private
            } else {
                UplinkTarget::Public
            }
        }
    }
}

/// The `--check` line for the two uplinks: which side of the trusted-path line the
/// configured destinations sit on, and what cleartext therefore carries.
pub fn uplink_constraint_line(cfg: &Config) -> String {
    let describe = |label: &str, url: &str, attested: bool| {
        match classify_uplink(url) {
        UplinkTarget::Loopback => format!("warden: {label} transport: cleartext HTTP to a loopback address — no wire, no exposure ({url})"),
        UplinkTarget::Private => format!("warden: {label} transport: cleartext HTTP to a private-range address ({url}) — trusted only if THAT network is yours; a shared VPC is not a tunnel"),
        UplinkTarget::Public if attested => format!("warden: {label} transport: cleartext HTTP to a PUBLIC address ({url}) — allowed because {label}.allow_public_plaintext = true; the API key and every finding's command line cross this hop unencrypted, so the path must be protected by something Warden cannot see"),
        UplinkTarget::Public => format!("warden: {label} transport: cleartext HTTP to a public address ({url}) — refused at load"),
        UplinkTarget::Name => format!("warden: {label} transport: cleartext HTTP to {url} — a host NAME, so its classification is the address it resolves to; Warden asks once at startup and prints the answer below this line (or refuses if it is publicly routable), because the key and the finding payloads ride that path in the clear"),
    }
    };
    let mut lines = Vec::new();
    if let Some(b) = &cfg.bridge {
        if b.mtls_enabled() {
            let verified: String = b
                .tls_sni
                .clone()
                .unwrap_or_else(|| url_host(&b.url).unwrap_or_else(|| "the URL host".to_string()));
            lines.push(format!(
                "warden: bridge transport: MUTUAL TLS to {}, verifying the server certificate \
                 for {verified:?} against bridge.tls_ca_file and presenting the agent certificate \
                 from bridge.tls_cert_file (private key path stays out of this line); the \
                 W2K-19 cleartext gate does not apply to this transport",
                b.url
            ));
        } else {
            lines.push(describe("bridge", &b.url, b.allow_public_plaintext));
        }
    }
    if let Some(h) = &cfg.heartbeat {
        lines.push(describe("heartbeat", &h.url, h.allow_public_plaintext));
    }
    if lines.is_empty() {
        "warden: no uplink configured — findings stop at this host's journal".to_string()
    } else {
        lines.join("\n")
    }
}

/// How long one config-time DNS lookup may take before Warden stops waiting for it.
/// `std`'s resolver has no timeout parameter, so the lookup goes on a helper thread
/// and this is the deadline its caller holds — the same shape
/// `heartbeat::resolve_bounded` uses for the beat. Abandoned at the deadline, the
/// thread keeps the libc resolver slot until the lookup returns; nothing waits on it.
const UPLINK_DNS_BUDGET: Duration = Duration::from_secs(2);

/// The real resolver behind [`resolve_uplink_names`]: every `A`/`AAAA` an
/// `http://host` uplink name answers with, in one bounded lookup. An IP literal
/// short-circuits and never touches the resolver, which is why the shipped
/// `url = "http://127.0.0.1:…"` shape costs no DNS at all.
pub fn lookup_uplink_host(host: &str) -> anyhow::Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let host = host.to_string();
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("warden-uplink-dns".into())
        .spawn(move || {
            let found = (host.as_str(), 0u16)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|a| a.ip()).collect::<Vec<_>>());
            // Capacity 1: this send never blocks, even if the caller gave up.
            let _ = tx.send(found);
        })?;
    match rx.recv_timeout(UPLINK_DNS_BUDGET) {
        Ok(Ok(ips)) => Ok(ips),
        Ok(Err(e)) => anyhow::bail!("DNS lookup failed: {e}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!("DNS lookup did not finish within {UPLINK_DNS_BUDGET:?}")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => anyhow::bail!("DNS helper thread died"),
    }
}

/// W2K-28: the half of the W2K-19 gate that an IP literal could not reach.
///
/// `validate()` refuses cleartext HTTP to a publicly routable address, but it can
/// only classify a URL written as an IP literal — so a NAME was a way around the
/// gate: `http://sentinel.example.com` answered by a record that points at the
/// public internet loaded, started, and put `X-API-Key` plus every finding's command
/// line, executable path and pid on that path unencrypted, with nothing said.
///
/// This asks each configured uplink NAME once, classifies the answer with the same
/// [`UplinkTarget`] the literal path uses, and refuses the same refusal. It is a
/// separate function rather than part of `validate()` because it needs a resolver:
/// the pure checks stay pure, the tests stay deterministic, and the modes that
/// promise to read only the config file (`--health`, `--explain`) never issue a
/// lookup. An unresolvable name is a note, not a refusal — a host whose DNS is down
/// must still start, and its posture is then what it was before this function
/// existed, printed where an operator reads it.
///
/// The answer used here is this process's own first lookup, so it is an *advisory*
/// classification: records move, and a name can answer differently by the time a
/// request goes out. That is why the delivery path re-checks the address it actually
/// connects to (`BridgeClient::resolve`) and refuses to send an unattested public
/// one. Between the two, the gate no longer depends on how the URL was spelled.
pub fn resolve_uplink_names(
    cfg: &Config,
    lookup: impl Fn(&str) -> anyhow::Result<Vec<IpAddr>>,
) -> anyhow::Result<Vec<String>> {
    let mut notes = Vec::new();
    let uplinks = [
        cfg.bridge.as_ref().map(|b| {
            (
                "bridge",
                b.url.clone(),
                b.allow_public_plaintext,
                b.mtls_enabled(),
            )
        }),
        cfg.heartbeat
            .as_ref()
            .map(|h| ("heartbeat", h.url.clone(), h.allow_public_plaintext, false)),
    ];
    for (label, url, attested, mtls) in uplinks.into_iter().flatten() {
        // Phase 8: with mutual TLS the peer's identity comes from its verified
        // certificate, not from which IP range happens to answer DNS. Resolving
        // here would add a misleading cleartext-classification note.
        if mtls {
            notes.push(format!(
                "warden: bridge uplink {url} uses mutual TLS — the server identity is verified \
                 from bridge.tls_ca_file and tls_sni, so the W2K-19 cleartext gate does not apply"
            ));
            continue;
        }
        // A literal was already judged — and refused if it needed to be — by
        // `validate()`, so it needs neither a lookup nor a second opinion.
        if classify_uplink(&url) != UplinkTarget::Name {
            continue;
        }
        let Some(host) = url_host(&url) else {
            notes.push(format!(
                "warden: {label} uplink {url} — no host could be read out of this URL, so its \
                 address could not be classified; the key and the finding payloads ride that \
                 path in the clear"
            ));
            continue;
        };
        let ips = match lookup(&host) {
            Ok(ips) if !ips.is_empty() => ips,
            Ok(_) => {
                notes.push(format!(
                    "warden: {label} uplink host {host} resolved to no addresses — its address \
                     could not be classified; the key and the finding payloads ride that path \
                     in the clear"
                ));
                continue;
            }
            Err(e) => {
                notes.push(format!(
                    "warden: {label} uplink host {host} could not be classified ({e}) — Warden \
                     still starts, because a dead resolver is not a security decision, but \
                     until this name answers inside a network you control the key and every \
                     finding's command line ride that path unencrypted"
                ));
                continue;
            }
        };
        let described = ips
            .iter()
            .map(|ip| format!("{ip} ({})", describe_target(classify_ip(*ip))))
            .collect::<Vec<_>>()
            .join(", ");
        let public = ips
            .iter()
            .filter(|ip| classify_ip(**ip) == UplinkTarget::Public)
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>();
        if !public.is_empty() && !attested {
            anyhow::bail!(
                "{label}.url ({url}) is cleartext HTTP to a PUBLICLY ROUTABLE address: {host} \
                 resolved to {described}. Warden sends `X-API-Key` and, in every finding, \
                 command lines, executable paths and pids — all unencrypted on that path. This \
                 is the same refusal Warden already makes for a URL written as an IP literal; \
                 spelling the destination as a NAME was not a way around it. Point the uplink \
                 at the loopback or private-network address of your edge (a WireGuard/Tailscale \
                 address counts), or, if this address really does sit inside a network you \
                 protect, set {label}.allow_public_plaintext = true and treat that as an \
                 attestation, not a transport.",
            );
        }
        notes.push(format!(
            "warden: {label} uplink host {host} resolved to {described}{}",
            if attested {
                " — kept in the clear by allow_public_plaintext, which is an attestation about \
                 a path Warden cannot see"
            } else {
                ""
            }
        ));
    }
    Ok(notes)
}

/// The operator-facing name of a class, so a resolution note says what it found in
/// the same words the rest of the transport lines use.
fn describe_target(t: UplinkTarget) -> &'static str {
    match t {
        UplinkTarget::Loopback => "loopback, no wire, no exposure",
        UplinkTarget::Private => "private range — trusted only if that network is yours",
        UplinkTarget::Public => "PUBLICLY ROUTABLE",
        UplinkTarget::Name => "not an address",
    }
}

fn default_true() -> bool {
    true
}
fn default_untrusted_exe_prefixes() -> Vec<String> {
    ["/tmp", "/var/tmp", "/dev/shm", "/run/user"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_shell_comms() -> Vec<String> {
    [
        "sh", "bash", "dash", "zsh", "nc", "ncat", "socat", "perl", "ruby",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_privilege_comms() -> Vec<String> {
    [
        "sudo",
        "su",
        "sshd",
        "login",
        "polkitd",
        "pkexec",
        "systemd",
        "systemd-logind",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_module_severity() -> String {
    "critical".to_string()
}
fn default_allow_modules() -> Vec<String> {
    // The standard Linux networking / firewall / container module set that
    // modprobe loads in the first seconds of boot on any host running iptables/
    // nftables, bridging, WireGuard or containers. All in-tree + signed, so the
    // taint gate in judge_module still convicts any out-of-tree/unsigned .ko that
    // borrows one of these names. This is the boot-storm the live test surfaced.
    // Operators on a truly locked-down host may clear this for strict-empty.
    [
        "nf_conntrack",
        "nf_tables",
        "nf_nat",
        "nf_defrag_ipv4",
        "nf_defrag_ipv6",
        "nf_reject_ipv4",
        "nfnetlink",
        "nft_chain_nat",
        "nft_compat",
        "ip_tables",
        "ip6_tables",
        "iptable_filter",
        "iptable_nat",
        "x_tables",
        "xt_tcpudp",
        "xt_conntrack",
        "xt_MASQUERADE",
        "xt_CHECKSUM",
        "xt_addrtype",
        "xt_set",
        "xt_mark",
        "xt_connmark",
        "xt_comment",
        "ipt_REJECT",
        "ip_set",
        "bridge",
        "stp",
        "llc",
        "br_netfilter",
        "wireguard",
        "libcurve25519",
        "xfrm_user",
        "xfrm_algo",
        "overlay",
        "veth",
        "snd_hrtimer",
        "snd_seq_dummy",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_ptrace_benign_reader_comms() -> Vec<String> {
    // The daemons that read /proc/<pid>/* of every process (including the
    // protected one) as routine work — silenced for READ-mode ptrace only, never
    // for ATTACH. "systemd-journald" is truncated to 15 chars by TASK_COMM_LEN.
    //
    // The container runtime is here for the same reason and one of its own: a
    // runc that joins namespaces usually exits before userspace can resolve its
    // /proc/<pid>/exe, so the path allowlist below misses exactly the reads this
    // list must catch. Any process can already adopt "fuser" or "systemd" with
    // prctl(PR_SET_NAME), so this does not widen the bypass the comm list has by
    // construction; it only closes the reliable-exe gap for the runtime.
    [
        "fuser",
        "systemd-journal",
        "systemd",
        "runc",
        "runc:[1:CHILD]",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn default_ptrace_benign_reader_exes() -> Vec<String> {
    // Container runtimes join a target's namespaces through /proc/<pid>/ns/*;
    // `docker exec` and container healthchecks do this by design. Paths, not
    // comms (see the field doc): /usr/bin/runc is where Debian's docker.io and
    // containerd.io install it, and crun is the common drop-in alternative.
    ["/usr/bin/runc", "/usr/bin/crun"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_service_severity() -> String {
    "critical".to_string()
}
fn default_bpf_loaders() -> Vec<String> {
    // Warden loads its own programs before the security_bpf probe attaches, so it
    // never trips itself; still, list its comm defensively. Add your sanctioned
    // tracers here ("bpftool", an APM/observability agent) — keep it tight. This
    // list only decides loads whose executable could not be read; to authorize a
    // load by identity, name the loader's absolute path in allow_loader_exes.
    ["warden"].iter().map(|s| s.to_string()).collect()
}
fn default_bpf_severity() -> String {
    "critical".to_string()
}
fn default_bpf_watch_prog_types() -> Vec<u32> {
    // The implant-capable program kinds (numeric enum bpf_prog_type — a stable
    // kernel ABI). These can hook kernel functions, read/tamper kernel memory,
    // hide processes, or steer packets. The benign filters the init system and
    // container runtimes load constantly (cgroup_skb=8, cgroup_device=15,
    // sock_ops=13, socket_filter=1, cgroup_sock=9, …) are deliberately ABSENT, so
    // a systemd service start no longer trips the sensor while a real rootkit
    // hook still does. See BpfRules::watch_prog_types.
    vec![
        2,  // KPROBE — the classic tracing/hook implant
        3,  // SCHED_CLS (tc) — reads AND rewrites packet bytes, bidirectional
        4,  // SCHED_ACT (tc) — packet-mangling action, same plane as SCHED_CLS
        5,  // TRACEPOINT
        6,  // XDP — silent packet steering / drop
        7,  // PERF_EVENT
        14, // SK_SKB (sockmap) — redirect/intercept socket data streams
        16, // SK_MSG (sockmap) — intercept sendmsg payloads
        17, // RAW_TRACEPOINT
        18, // CGROUP_SOCK_ADDR — rewrites connect/sendmsg dest (transparent C2 redirect)
        24, // RAW_TRACEPOINT_WRITABLE
        26, // TRACING (fentry/fexit/fmod_ret) — the modern hook vector
        27, // STRUCT_OPS — can replace kernel operation tables
        28, // EXT (freplace)
        29, // LSM — can override security decisions in-kernel
        30, // SK_LOOKUP — steer inbound packets to an attacker socket (kernel backdoor)
        31, // SYSCALL
        32, // NETFILTER — drop/modify packets at netfilter hooks
    ]
    // NOTE: the network-plane implant types (3/4/14/16/18/30/32) are watched
    // alongside the tracing/hook family: a tc covert channel, a sock_addr C2
    // redirect, or an sk_lookup inbound backdoor is as much an in-kernel implant
    // as a kprobe rootkit. The high-volume BENIGN systemd/runtime loads
    // (socket_filter=1, cgroup_skb=8, cgroup_sock=9, cgroup_device=15, …) stay
    // ABSENT, so no new false-positive storm — a non-warden loader of any watched
    // type still convicts at the loader-allowlist gate.
}
fn default_mount_severity() -> String {
    "high".to_string()
}
fn default_mount_allow_actor_exes() -> Vec<String> {
    // Resolved on-disk paths of the host confinement machinery whose whole-tree
    // binds are sandbox construction, not escape. Keyed on exe (not comm) so an
    // attacker cannot assume the identity with prctl(PR_SET_NAME). The two common
    // snap-confine install paths; systemd per-unit sandbox binds (comm = the unit)
    // are left for operators to add after watching the shadow stream.
    [
        "/usr/lib/snapd/snap-confine",
        "/usr/libexec/snapd/snap-confine",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_mount_suppress_exempt_sources() -> Vec<String> {
    // Never-benign bind sources that must fire even when the actor exe is on
    // allow_actor_exes: raw disks, kernel memory, device-mapper, and the
    // container-runtime control sockets. A confinement builder never binds these;
    // an escape does. Matched as a leading prefix of the (lowercased) source.
    [
        "/dev/sd",
        "/dev/nvme",
        "/dev/vd",
        "/dev/mapper",
        "/dev/dm-",
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/run/containerd",
        "/run/containerd",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_mount_ignore_prefixes() -> Vec<String> {
    // Sandbox / namespace construction roots. A desktop sandbox (bwrap, flatpak,
    // the polkit agent) assembles its mount namespace by bind-mounting many paths
    // under a private staging root; their sources contain "/dev", "/etc", "/proc"
    // as substrings but are sandbox internals, not a host escape. Matched as a
    // genuine path prefix (component boundary) so a real "/proc" host bind is not
    // swallowed — only these staging locations are.
    [
        "/oldroot",                // pivot_root old-root (bwrap/flatpak)
        "/newroot",                // the sandbox's assembled new root
        "/proc/self/fd",           // fd-relative bind sources
        "/run/systemd/namespace-", // systemd per-unit private mounts
        "/run/systemd/unit-root",  // systemd RootDirectory= staging
        "/run/user",               // per-user runtime (flatpak/portal private dirs)
        "/tmp/newroot",            // some sandboxes stage under /tmp
        "/tmp/.private",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_mount_allow_pseudo_device_binds() -> Vec<String> {
    // The standard systemd PrivateDevices= pseudo-device set. A hardened unit
    // bind-mounts exactly these real host nodes into its private /dev, each to the
    // same target path — a benign, contentless device grant that fires no escape.
    // EXACT-matched (not a prefix), so the whole "/dev" tree, a raw disk, or the
    // device mapper — none of which equals a listed leaf — still fires. Keep this
    // list tight: every entry is a source we agree to ignore a bind of, forever.
    [
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
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_mount_watch_sources() -> Vec<String> {
    // The classic container-escape / host-fs-exposure bind-mount tells: grafting
    // a host device tree or sensitive path into a new mountpoint. Matched
    // case-insensitively as substrings of the mount source.
    [
        "/dev",                 // host device tree (raw disk access)
        "/proc",                // host /proc (pid1 escape, kcore)
        "/sys",                 // host /sys (cgroup-release-agent escape)
        "/etc",                 // host config (shadow, sudoers)
        "/root",                // host root home
        "/var/run/docker.sock", // the docker socket (full daemon control)
        "/run/docker.sock",     // same, alternate path
        "/var/run/containerd",  // containerd socket
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_persistence_dirs() -> Vec<String> {
    // The standard Linux boot/login-survival vectors. Matched case-insensitively
    // as substrings of the rebuilt trailing path, so "systemd/system" catches
    // /etc/systemd/system AND /usr/lib/systemd/system AND /run/systemd/system in
    // one entry, and "cron" catches /etc/cron.d, /etc/cron.daily, /var/spool/cron.
    // The three-ancestor ladder the kernel captures is deep enough for every
    // substring here to be visible in the path we match against.
    [
        "systemd/system",  // rogue unit: /etc/, /usr/lib/, /run/ systemd/system
        "systemd/user",    // per-user unit (logon persistence)
        "/cron",           // /etc/cron.d, cron.daily/hourly/…, /var/spool/cron
        "crontab",         // /etc/crontab, /var/spool/cron/crontabs
        "autostart",       // XDG ~/.config/autostart/*.desktop (desktop logon)
        "init.d",          // SysV /etc/init.d script
        "rc.local",        // /etc/rc.local boot hook
        "ld.so.preload",   // /etc/ld.so.preload — library-injection persistence
        "ld.so.conf",      // /etc/ld.so.conf.d/* — linker search-path injection
        "profile.d",       // /etc/profile.d/*.sh — shell-logon persistence
        "authorized_keys", // ~/.ssh/authorized_keys — SSH key implant
        "sudoers.d",       // /etc/sudoers.d/* — privilege persistence
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_ransom_exts() -> Vec<String> {
    // Real-world encryptor markers. Not exhaustive — the burst rule is the
    // net that catches families not on this list — but these are cheap, high-
    // confidence single-event convictions when they appear.
    [
        ".locked",
        ".encrypted",
        ".crypt",
        ".crypto",
        ".enc",
        ".locky",
        ".wncry",
        ".wcry",
        ".cerber",
        ".zepto",
        ".cryptolocker",
        ".ryuk",
        ".conti",
        ".lockbit",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}
fn default_burst_threshold() -> u32 {
    50
}
fn default_burst_window() -> u64 {
    5
}
fn default_deny_intents() -> Vec<String> {
    // A guarded file with an unspecified deny mask is treated as a secret: an
    // unauthorised actor may neither read nor write it. Exec is not denied by
    // default (a guarded config/key is not an executable); add "exec" explicitly
    // for a guarded binary you want to stop from running.
    vec!["read".to_string(), "write".to_string()]
}
fn default_host() -> String {
    hostname()
}
fn default_bridge_timeout() -> u64 {
    // 15 s, not 3 s. Measured live (§113.5): a 64-finding batch takes 3.4 s and
    // a 1010-finding spool replay takes ~150 s. A budget shorter than the
    // server's own p100 cannot be won by retrying — every retry lands inside
    // the attempt it is retrying, which is how a healthy endpoint turned into a
    // permanent 503 loop. The retry path is idempotent either way; this only
    // removes the self-inflicted overlap.
    15_000
}
fn default_queue_max() -> usize {
    // Findings are judged, not raw: even a host under an active intrusion does
    // not produce these at a rate that needs a bigger cushion. 1024 envelopes of
    // a few hundred bytes is a few hundred KiB of memory in the worst case.
    1024
}
fn default_spool_path() -> PathBuf {
    // Matches StateDirectory=warden in systemd/warden.service. ProtectSystem=strict
    // makes every other path read-only for the service, so this is the only
    // place a spool can live under the shipped unit.
    PathBuf::from("/var/lib/warden/bridge_spool.jsonl")
}
fn default_spool_max_bytes() -> u64 {
    // 64 MiB. At roughly 600 bytes per envelope that is ~100k findings — far more
    // than a Sentinel outage is expected to generate, and small enough to be a
    // rounding error on any host. The cap exists so that "Sentinel is down for a
    // week" cannot become "the root filesystem is full".
    64 * 1024 * 1024
}
fn default_backoff_ms() -> u64 {
    1000
}
fn default_max_backoff_ms() -> u64 {
    // Five minutes. Long enough that a multi-hour outage is ~12 requests/hour
    // instead of thousands, short enough that the first finding after recovery
    // is delayed by minutes and not hours.
    300_000
}
fn default_hb_interval() -> u64 {
    30
}
fn default_hb_seq_file() -> String {
    "/var/lib/warden/hb_seq".to_string()
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string())
}

/// W2K-23 — every key the operator wrote that Warden never read.
///
/// serde drops an unmatched key without a word, and the shape the deploy script
/// produces makes that silent loss likely: `wire-bridge.sh` appends its own
/// `[bridge]` table at the END of the file, so the sample's commented bridge block
/// sits structurally under `[respond]`. Uncomment `spool_path` there and the config
/// parses, loads, and ignores it. Measured on the deployment host on 2026-11-02:
/// `--check` reported the default `/var/lib/warden/bridge_spool.jsonl` for a file
/// that named a different path, and the durable queue kept writing where the unit
/// file expected it, not where the operator thought they had moved it.
///
/// The schema is derived, not hand-listed, so it cannot drift from the structs:
/// serde serialises a loaded `Config` back into a TOML value using exactly its own
/// field names, and any key present in the file but absent from that round-trip was
/// never read. `Option` fields are skipped while `None` — which is the same case in
/// which the operator did not write them — so the comparison has no false positive
/// to report. If the round-trip itself fails the audit says so rather than reporting
/// a clean config, because "no warnings" and "no audit" must never look alike.
pub fn unread_keys(cfg: &Config, text: &str) -> Vec<String> {
    let Ok(written) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let read = match toml::Value::try_from(cfg) {
        Ok(v) => v,
        Err(e) => {
            return vec![format!(
                "<audit unavailable: config could not be re-serialised: {e}>"
            )]
        }
    };
    let mut out = Vec::new();
    diff_unread(&written, &read, "", &mut out);
    out.sort();
    out
}

fn diff_unread(written: &toml::Value, read: &toml::Value, path: &str, out: &mut Vec<String>) {
    if let (Some(w), Some(r)) = (written.as_table(), read.as_table()) {
        for (key, value) in w {
            let child = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            match r.get(key) {
                None => out.push(child),
                Some(known) => diff_unread(value, known, &child, out),
            }
        }
        return;
    }
    if let (Some(w), Some(entries)) = (written.as_array(), read.as_array()) {
        for (index, entry) in w.iter().enumerate() {
            if let Some(known) = entries.get(index) {
                diff_unread(entry, known, &format!("{path}[{index}]"), out);
            }
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
        let cfg: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing config {}: {e}", path.display()))?;
        cfg.validate()
            .map_err(|e| anyhow::anyhow!("invalid config {}: {e}", path.display()))?;
        let mut cfg = cfg;
        cfg.unread_keys = unread_keys(&cfg, &text);
        Ok(cfg)
    }

    /// Reject configurations whose stated intent contradicts what the kernel
    /// will actually do.
    ///
    /// The one case today is a guarded file with `authorized_uid = 0` and
    /// `allow_root = false`. `authorized_uid` is the uid the policy *permits*,
    /// so 0 there means root is allowed — which is the exact opposite of what
    /// `allow_root = false` documents and what the operator wrote it to mean.
    /// The kernel only sees the numeric policy, so the guard silently permits
    /// root while the config, the docs and the operator all say it shouldn't;
    /// a host intrusion that wrote a guarded key as root would be recorded as
    /// authorised. Refusing to start is the only outcome that cannot be
    /// mistaken for protection.
    ///
    /// SIGHUP reload keeps the previous config on error (main.rs), so a bad
    /// edit cannot silently disable a running guard.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            anyhow::bail!(
                "schema_version = {} is not supported by this build (supports {}); \
                 run `warden --config-migrate --target-version {}` after backing up the file, \
                 or restore a known-good version",
                self.schema_version,
                CURRENT_SCHEMA_VERSION,
                CURRENT_SCHEMA_VERSION
            );
        }
        // Phase 9: these numbers are a promise about the shipped unit, not a
        // budget Warden applies. Refuse a config whose promise cannot be true,
        // so `--check` can never report a limit the service does not have.
        if let Some(problem) = self.resources.problem() {
            anyhow::bail!("{problem}");
        }

        for (index, g) in self.enforce.guarded_files.iter().enumerate() {
            if g.authorized_uid == 0 && !g.allow_root {
                anyhow::bail!(
                    "enforce.guarded_files[{index}] ({}) names authorized_uid = 0 \
                     with allow_root = false: authorized_uid is the uid the policy \
                     PERMITS, so this permits root, while allow_root = false says \
                     root must be denied. Name the app's real uid, or set \
                     allow_root = true if root really is the authorised toucher.",
                    g.path
                );
            }
        }

        // A burst rule with a zero window can never fire: every earlier op is
        // evicted at `now - 0`, so the count stays at 1 and a threshold above 1
        // is dead policy that still reads as armed in the config.
        if self.file_rules.burst_threshold > 0 && self.file_rules.burst_window_secs == 0 {
            anyhow::bail!(
                "file_rules.burst_window_secs is 0 while burst_threshold = {}: a zero \
                 window evicts every earlier op, so the burst rule can never fire. Set \
                 a window (e.g. 5 seconds), or set burst_threshold = 0 to disable the rule.",
                self.file_rules.burst_threshold
            );
        }

        // The W2K-15 location rule compares these prefixes against absolute
        // paths, so a relative one matches nothing and "/" would make every
        // exec on the host look staged — a flooded spool, not a defence.
        for (index, prefix) in self.exec_rules.untrusted_exe_prefixes.iter().enumerate() {
            if prefix.trim().is_empty() || !prefix.starts_with('/') || prefix == "/" {
                anyhow::bail!(
                    "exec_rules.untrusted_exe_prefixes[{index}] ({prefix:?}) is not a usable \
                     directory prefix: it must be an absolute path deeper than /, because the \
                     rule matches it against resolved executable paths. A relative prefix \
                     matches nothing and / flags every exec on the host. Remove the entry, or \
                     set untrusted_exe_prefixes = [] to disable the rule.",
                );
            }
        }

        // W2K-18: this list is the authorization, so an entry that can never equal a
        // `/proc/<pid>/exe` target does not narrow the rule — it quietly retires it,
        // which is worse than a config error.
        for (index, exe) in self.bpf_rules.allow_loader_exes.iter().enumerate() {
            if exe.trim().is_empty() || !exe.starts_with('/') || exe == "/" {
                anyhow::bail!(
                    "bpf_rules.allow_loader_exes[{index}] ({exe:?}) is not a usable executable \
                     path: it is compared against /proc/<pid>/exe, so it must be an absolute \
                     path to a file. Leave the list empty to keep name-only (comm) \
                     authorization — which --check reports on every run — or name the real \
                     path (e.g. /usr/sbin/bpftool).",
                );
            }
        }

        // W2K-30a: same trap as the loader list two blocks above. This field exists
        // to authorize a privilege raise by executable, so an entry that can never
        // equal a `/proc/<pid>/exe` target does not narrow the rule — it retires it
        // while still reading as pinned identity.
        for (index, exe) in self.cred_rules.expected_privilege_exes.iter().enumerate() {
            if exe.trim().is_empty() || !exe.starts_with('/') || exe == "/" {
                anyhow::bail!(
                    "cred_rules.expected_privilege_exes[{index}] ({exe:?}) is not a usable \
                     executable path: it is compared against /proc/<pid>/exe, so it must be an \
                     absolute path to a file. Leave the list empty to keep name-plus-path \
                     agreement (which --check reports on every run) or name the real path \
                     (e.g. /usr/bin/sudo).",
                );
            }
        }

        // A target that names nothing (or names only a blank string) can never
        // match, so it protects nobody while looking like protection. That is
        // exactly the silent failure W-R4 exists to prevent.
        let blank = |s: &Option<String>| s.as_deref().is_some_and(|v| v.trim().is_empty());
        for (index, target) in self.protect.targets.iter().enumerate() {
            if (target.comm.is_none() && !target.names_identity())
                || blank(&target.comm)
                || blank(&target.exe)
                || blank(&target.cgroup)
            {
                anyhow::bail!(
                    "protect.targets[{index}] names no usable field: an empty (or blank) \
                     target matches nothing, so it protects nobody. Name comm, exe, uid or \
                     cgroup (every named field must match), or remove the entry."
                );
            }
        }

        // W2K-13: the ring is created once, at load, with whatever size policy
        // names — so a size the kernel would round up is a config that lies about
        // the capacity the drop counters are measured against. Refuse it here
        // rather than let `ringbuf: N dropped` be read against the wrong number.
        if let Some(problem) = self.runtime.ring_size_problem(page_size()) {
            anyhow::bail!("{problem}");
        }
        if self.runtime.enrich_cache_ms > MAX_ENRICH_CACHE_MS {
            anyhow::bail!(
                "runtime.enrich_cache_ms = {} exceeds the {MAX_ENRICH_CACHE_MS} ms ceiling: \
                 cached /proc evidence is what the app-cgroup attribution is judged on, so \
                 the window is the maximum lag a finding can carry. Use 0 to disable the \
                 cache and read /proc for every event.",
                self.runtime.enrich_cache_ms
            );
        }

        // The pull path reads /proc on a timer inside the same loop that drains
        // the ring, so a cadence that never sleeps is a policy that starves the
        // push sensors, and a report that itemises nothing still pays the reads.
        let snap = &self.network_snapshot;
        if snap.enabled {
            if snap.interval_secs < MIN_SNAPSHOT_INTERVAL_SECS {
                anyhow::bail!(
                    "network_snapshot.interval_secs = {} while the snapshot is enabled: the \
                     floor is {MIN_SNAPSHOT_INTERVAL_SECS}s, because the pull path walks /proc \
                     inside the loop that drains the events ring. Leave it enabled with a real \
                     interval, or set enabled = false to stop the walk.",
                    snap.interval_secs
                );
            }
            if snap.report_max_sockets == 0 {
                anyhow::bail!(
                    "network_snapshot.report_max_sockets = 0 while the snapshot is enabled: the \
                     tables would still be read every {}s and nothing would ever be named. Set \
                     enabled = false if the pull path is not wanted.",
                    snap.interval_secs
                );
            }
            if snap.attribute && snap.attribute_max_pids == 0 {
                anyhow::bail!(
                    "network_snapshot.attribute is true with attribute_max_pids = 0: the \
                     inode→pid walk would scan no process and every socket would report \
                     an unknown owner, which is the failure mode attribution exists to \
                     avoid. Give it a real budget (4096 covers a busy host) or set \
                     attribute = false."
                );
            }
        }

        // Net volume counters (N-05). Same shape as the snapshot rules: only
        // reject what is not a policy but a guaranteed no-op, so an operator who
        // asked for volume totals and configured one of these to zero gets told
        // they will not be told anything, rather than watching the agent read a
        // map every minute and print nothing.
        let vol = &self.net_volume;
        if vol.enabled {
            if vol.interval_secs < MIN_NET_VOLUME_INTERVAL_SECS {
                anyhow::bail!(
                    "net_volume.interval_secs = {} while the volume counters are enabled: the \
                     floor is {MIN_NET_VOLUME_INTERVAL_SECS}s, because each tick reads the \
                     kernel map and walks the cgroup tree inside the loop that drains the events \
                     ring. The totals are cumulative, so a faster tick shortens the sample \
                     window without revealing anything new.",
                    vol.interval_secs
                );
            }
            if vol.max_rows_per_tick == 0 {
                anyhow::bail!(
                    "net_volume.max_rows_per_tick = 0 while the volume counters are enabled: the \
                     kernel would keep counting into its map and no tick could ever name a \
                     cgroup. Set enabled = false to stop the counting instead."
                );
            }
            if vol.cgroup_walk_max == 0 {
                anyhow::bail!(
                    "net_volume.cgroup_walk_max = 0 while the volume counters are enabled: every \
                     total would be reported against an unresolved cgroup id, which is a number \
                     an operator cannot act on. Give the walk a real budget (4096 names a busy \
                     host) or set enabled = false."
                );
            }
            if vol.cgroup_root.as_os_str().is_empty() {
                anyhow::bail!(
                    "net_volume.cgroup_root is empty while the volume counters are enabled: \
                     cgroup ids could not be resolved to paths at all. The cgroup v2 mount is \
                     normally /sys/fs/cgroup."
                );
            }
        }

        // Bridge values whose zero spelling is not a policy but a guaranteed
        // failure: the code clamps them to 1 or times out immediately, so the
        // process looks configured while delivering nothing.
        if let Some(b) = &self.bridge {
            if b.queue_max == 0 {
                anyhow::bail!(
                    "bridge.queue_max must be at least 1: 0 leaves the sender no memory \
                     to absorb a burst, so every finding takes the spool/fsync path."
                );
            }
            if b.spool_max_bytes == 0 {
                anyhow::bail!(
                    "bridge.spool_max_bytes must be greater than 0: a zero cap refuses \
                     every finding as soon as Sentinel is unreachable."
                );
            }
            if b.timeout_ms == 0 {
                anyhow::bail!(
                    "bridge.timeout_ms must be greater than 0: a zero budget expires \
                     before the request can reach Sentinel, so nothing is ever delivered."
                );
            }

            // Phase 8: mTLS material is all-or-nothing, and the URL scheme has
            // to agree with it. A half-set must not become "TLS without client
            // cert", and an https:// URL without material must not become a
            // cleartext request to a TLS port.
            let material = [
                ("tls_ca_file", &b.tls_ca_file),
                ("tls_cert_file", &b.tls_cert_file),
                ("tls_key_file", &b.tls_key_file),
            ];
            let present = material
                .iter()
                .filter(|(_, v)| v.is_some())
                .map(|(k, _)| *k)
                .collect::<Vec<_>>();
            if !present.is_empty() && present.len() != 3 {
                anyhow::bail!(
                    "bridge mTLS material is incomplete: {} set, but tls_ca_file, tls_cert_file \
                     and tls_key_file must all be set together (no silent downgrade)",
                    present.join(", ")
                );
            }
            let https = b.url.starts_with("https://");
            if b.mtls_enabled() && !https {
                anyhow::bail!(
                    "bridge has complete mTLS material but bridge.url is not https://: refusing \
                     to send a client certificate over cleartext HTTP"
                );
            }
            if https && !b.mtls_enabled() {
                anyhow::bail!(
                    "bridge.url is https:// but the Phase 8 mTLS material is missing: set \
                     tls_ca_file, tls_cert_file and tls_key_file together"
                );
            }
            if b.mtls_enabled() {
                for (label, path) in [
                    ("tls_ca_file", b.tls_ca_file.as_ref().unwrap()),
                    ("tls_cert_file", b.tls_cert_file.as_ref().unwrap()),
                    ("tls_key_file", b.tls_key_file.as_ref().unwrap()),
                ] {
                    std::fs::File::open(path).with_context(|| {
                        format!("bridge.{label} ({}) is not readable", path.display())
                    })?;
                }
                let key = b.tls_key_file.as_ref().unwrap();
                let mode = std::fs::metadata(key)
                    .with_context(|| format!("cannot stat bridge.tls_key_file {}", key.display()))?
                    .permissions()
                    .mode()
                    & 0o777;
                if mode & 0o077 != 0 {
                    anyhow::bail!(
                        "bridge.tls_key_file ({}) has mode {:04o}; OpenSSL requires 0600 so the \
                         agent key is not group/world readable",
                        key.display(),
                        mode
                    );
                }
                if let Some(sni) = &b.tls_sni {
                    if sni.trim().is_empty() {
                        anyhow::bail!("bridge.tls_sni must not be empty when set");
                    }
                }
            }
            // W2K-19. The accepted design is cleartext HTTP with TLS at the edge, and
            // the sentence that makes that safe — "the Warden→edge hop is a trusted
            // path" — used to live only in SECURITY.md. A routable IP literal is the
            // part of that claim checkable without DNS, so it is refused here rather
            // than trusted to prose: the body carries `X-API-Key` plus every finding's
            // command line, executable path and pid.
            //
            // W2K-28: this cannot be the whole rule, because a NAME is the same
            // destination written differently. It is checked in
            // `resolve_uplink_names`, which needs a resolver and therefore runs at
            // startup rather than inside these pure checks.
            if !b.mtls_enabled()
                && classify_uplink(&b.url) == UplinkTarget::Public
                && !b.allow_public_plaintext
            {
                anyhow::bail!(
                    "bridge.url ({}) is cleartext HTTP to a PUBLICLY ROUTABLE address. \
                     Warden sends `X-API-Key` and, in every finding, command lines, \
                     executable paths and pids — all unencrypted on that path. Point the \
                     bridge at the loopback or private-network address of your edge (a \
                     WireGuard/Tailscale address counts), or, if this address really does \
                     sit inside a network you protect, set bridge.allow_public_plaintext \
                     = true and treat that as an attestation, not a transport.",
                    b.url
                );
            }
        }

        // The heartbeat has no key to steal but the same exposure: an off-box
        // dead-man's switch whose beat is readable by anyone on the path tells an
        // attacker exactly when the host went quiet — the one thing the switch is
        // for. Same rule, same attestation flag.
        if let Some(h) = &self.heartbeat {
            if classify_uplink(&h.url) == UplinkTarget::Public && !h.allow_public_plaintext {
                anyhow::bail!(
                    "heartbeat.url ({}) is cleartext HTTP to a PUBLICLY ROUTABLE address. A \
                     beat anyone can read tells an attacker when this host stopped sending \
                     them, which is the takedown the dead-man's switch exists to notice. \
                     Point it at a loopback or private-network collector, or set \
                     heartbeat.allow_public_plaintext = true if that path is protected by \
                     something Warden cannot see.",
                    h.url
                );
            }
        }

        // Phase 7 egress. The switches are inert unless enabled, but once an
        // operator opts in the config must be specific enough that the kernel
        // cannot be attached to a broad cgroup or denied a rule it cannot hold.
        let eg = &self.egress;
        if eg.arm && !eg.enabled {
            anyhow::bail!(
                "egress.arm = true while egress.enabled = false: arming a deny primitive that is \
                 never attached would read as protection in the journal while no cgroup hook \
                 exists. Set enabled = false and arm = false for observe-only, or enable egress \
                 with an explicit cgroup_path."
            );
        }
        if eg.enabled {
            let Some(path) = eg.cgroup_path.as_ref() else {
                anyhow::bail!(
                    "egress.enabled = true requires egress.cgroup_path: Warden attaches cgroup \
                     socket programs to ONE named cgroup, never to the host root implicitly. \
                     Name an isolated test/tenant cgroup."
                );
            };
            if !path.is_absolute() || path.as_os_str().is_empty() {
                anyhow::bail!(
                    "egress.cgroup_path ({}) must be an absolute path to a cgroup v2 directory.",
                    path.display()
                );
            }
            // Textual root checks are not enough: `..`, a symlink, a bind mount,
            // or this process's cgroup namespace can all make a different string
            // name the same kernel directory. The loader helper opens the path
            // without following links, verifies cgroup2 identity, and compares
            // (dev, ino) against the mount-namespace root before accepting it.
            crate::loader::open_validated_cgroup(path).map_err(|e| {
                anyhow::anyhow!("egress.cgroup_path {} is not usable: {e}", path.display())
            })?;
            if eg.deny.is_empty() {
                anyhow::bail!(
                    "egress.enabled = true with an empty egress.deny list: attaching four cgroup \
                     programs that can never match a rule is cost without coverage. Add an exact \
                     deny, or set enabled = false."
                );
            }
            // Reject a bad address here (at --check time) rather than at 03:00 on
            // SIGHUP, and enforce the kernel map's capacity bound.
            for (i, d) in eg.deny.iter().enumerate() {
                d.to_key()
                    .map_err(|e| anyhow::anyhow!("egress.deny[{i}] is not an exact rule: {e}"))?;
            }
            crate::egress::EgressPolicy::plan(&eg.deny, 1)
                .map_err(|e| anyhow::anyhow!("egress.deny cannot be installed: {e}"))?;
        }

        Ok(())
    }
    /// A safe default when no config file is present: observe-only, protect
    /// self, sensible shell list. Never kills anything.
    pub fn safe_default() -> Self {
        Config {
            schema_version: CURRENT_SCHEMA_VERSION,
            mode: Mode::Observe,
            runtime: Runtime::default(),
            resources: ResourceBudget::default(),
            protect: Protect {
                comms: vec!["granian".into(), "celery".into(), "daphne".into()],
                cgroup_contains: vec![],
                protect_self: true,
                targets: vec![],
            },
            app: AppIdentity::default(),
            exec_rules: ExecRules::default(),
            network_rules: NetworkRules::default(),
            c2_rules: C2Rules::default(),
            cred_rules: CredRules::default(),
            ptrace_rules: PtraceRules::default(),
            module_rules: ModuleRules::default(),
            file_rules: FileRules::default(),
            service_rules: ServiceRules::default(),
            listen_rules: ListenRules::default(),
            network_snapshot: NetworkSnapshot::default(),
            net_volume: NetVolume::default(),
            bpf_rules: BpfRules::default(),
            mount_rules: MountRules::default(),
            enforce: EnforceRules::default(),
            egress: Egress::default(),
            respond: Respond::default(),
            bridge: None,
            heartbeat: None,
            unread_keys: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "warden-config-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create the test's own temp dir");
        p
    }

    #[test]
    fn enforce_defaults_to_shadow_with_no_guarded_files() {
        // The safe default and an empty [enforce] section must both be shadow (arm
        // = false) with nothing guarded — the enforcing layer denies NOTHING until
        // an operator both names files and deliberately arms. This is the whole
        // shadow-first safety contract; a regression here could lock a box out.
        let d = Config::safe_default();
        assert!(!d.enforce.arm);
        assert!(d.enforce.guarded_files.is_empty());

        let cfg: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert!(!cfg.enforce.arm);
        assert!(cfg.enforce.guarded_files.is_empty());
    }

    #[test]
    fn omitting_the_protect_table_still_protects_self() {
        // The `[protect]` table carries `protect_self = true` in the sample, and
        // the field itself defaults to true. A config that omits the whole table
        // must land in the same place: `Config.protect` is `#[serde(default)]`,
        // so what it gets is `Protect::default()`, and a derived `Default` would
        // have answered `false` here — quietly dropping self-protection for
        // exactly the operator who wrote the least config.
        let cfg: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert!(
            cfg.protect.protect_self,
            "a config with no [protect] table must still protect Warden's own pid"
        );

        // And the same for an explicitly empty table.
        let cfg: Config = toml::from_str("[protect]\n").unwrap();
        assert!(cfg.protect.protect_self);
        assert!(cfg.protect.targets.is_empty());
    }

    #[test]
    fn a_protect_target_parses_and_is_optional_field_by_field() {
        let cfg: Config = toml::from_str(
            "[protect]\ncomms = [\"granian\"]\n\n\
             [[protect.targets]]\ncomm = \"granian\"\nexe = \"/usr/bin/granian\"\nuid = 999\n\
             cgroup = \"/system.slice/granian.service\"\n\n\
             [[protect.targets]]\ncomm = \"celery\"\n",
        )
        .unwrap();
        assert_eq!(cfg.protect.targets.len(), 2);
        let t = &cfg.protect.targets[0];
        assert_eq!(t.comm.as_deref(), Some("granian"));
        assert_eq!(t.exe.as_deref(), Some("/usr/bin/granian"));
        assert_eq!(t.uid, Some(999));
        assert!(t.names_identity());
        // The second names only comm: a name-only selector, reported as weak.
        assert!(!cfg.protect.targets[1].names_identity());
        assert_eq!(cfg.protect.weak_selectors().len(), 2);
    }

    #[test]
    fn a_guarded_file_parses_and_its_deny_mask_defaults_to_read_write() {
        // An [[enforce.guarded_files]] entry with no `deny` denies read+write (the
        // secret-file default) and does not allow root; the mask is exactly the two
        // intent bits.
        let toml = r#"
mode = "observe"
[enforce]
arm = false
[[enforce.guarded_files]]
path = "/etc/warden/wallet.key"
authorized_uid = 991
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.enforce.guarded_files.len(), 1);
        let g = &cfg.enforce.guarded_files[0];
        assert_eq!(g.path, "/etc/warden/wallet.key");
        assert_eq!(g.authorized_uid, 991);
        assert_eq!(g.deny_mask(), WARDEN_INTENT_READ | WARDEN_INTENT_WRITE);
        assert_eq!(g.flags(), 0); // allow_root off → no ALLOW_ROOT bit
    }

    #[test]
    fn a_guarded_file_whose_uid_contradicts_allow_root_is_refused() {
        // authorized_uid is the permitted uid. 0 therefore permits root, while
        // allow_root = false promises root is denied. The kernel would enforce
        // the former and every human reading the config would believe the
        // latter, so the config must not load at all.
        let toml = r#"
mode = "enforce"
[enforce]
arm = true
[[enforce.guarded_files]]
path = "/etc/warden/warden.toml"
authorized_uid = 0
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("/etc/warden/warden.toml"),
            "error names the entry: {err}"
        );
        assert!(
            err.contains("allow_root"),
            "error says how to resolve it: {err}"
        );
    }

    #[test]
    fn a_guarded_file_saying_root_is_its_authorised_uid_is_accepted() {
        // The same uid 0, this time stating what it means. Redundant with
        // allow_root alone, but honest — and the only spelling of "root may
        // touch this" the loader accepts.
        let toml = r#"
[[enforce.guarded_files]]
path = "/var/log/warden/audit.log"
authorized_uid = 0
allow_root = true
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn a_burst_rule_with_no_window_is_refused() {
        // window 0 evicts every earlier op, so the threshold can never be
        // reached; refusing at load beats running with a rule that looks armed.
        let cfg: Config = toml::from_str(
            r#"
[file_rules]
burst_threshold = 5
burst_window_secs = 0
"#,
        )
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("burst_window_secs"), "{err}");
        assert!(err.contains("burst_threshold"), "{err}");
    }

    #[test]
    fn a_disabled_burst_rule_may_keep_a_zero_window() {
        let cfg: Config = toml::from_str(
            r#"
[file_rules]
burst_threshold = 0
burst_window_secs = 0
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn an_empty_or_blank_protect_target_is_refused() {
        for toml_src in [
            "[[protect.targets]]\n",
            "[[protect.targets]]\nexe = \"   \"\n",
        ] {
            let cfg: Config = toml::from_str(toml_src).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("protect.targets[0]"), "{toml_src}: {err}");
            assert!(err.contains("protects nobody"), "{toml_src}: {err}");
        }
    }

    #[test]
    fn a_staging_prefix_that_cannot_match_anything_is_refused() {
        // W2K-15 compares `untrusted_exe_prefixes` against absolute executable
        // paths. A relative or blank entry matches nothing — dead policy that
        // reads as an armed rule — and "/" flags every exec on the host, so all
        // three spellings are refused at load rather than discovered in a log.
        for prefix in ["\"tmp\"", "\"\"", "\"/\"", "\"  /dev/shm  \""] {
            let cfg: Config = toml::from_str(&format!(
                "[exec_rules]\nshell_comms = [\"bash\"]\nuntrusted_exe_prefixes = [{prefix}]\n"
            ))
            .unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("untrusted_exe_prefixes[0]"), "{prefix}: {err}");
            assert!(err.contains("directory prefix"), "{prefix}: {err}");
        }
        // A deeper-than-root absolute path is accepted, as is an empty list,
        // which is the documented way to turn the rule off.
        for body in [
            "untrusted_exe_prefixes = []",
            "untrusted_exe_prefixes = [\"/tmp\", \"/var/tmp\"]",
        ] {
            let cfg: Config =
                toml::from_str(&format!("[exec_rules]\nshell_comms = [\"bash\"]\n{body}\n"))
                    .unwrap();
            assert!(cfg.validate().is_ok(), "{body}");
        }
    }

    #[test]
    fn the_staging_prefixes_default_and_the_allowlist_are_optional() {
        // An operator's file written before W2K-15 must keep parsing with the
        // rule armed on the shipped defaults, `[app] exe_allowlist` must stay
        // optional now that a rule reads it, and a `[exec_rules]` block written
        // only to set the new prefix list must not demand the old keys.
        let cfg: Config = toml::from_str("[app]\ncgroup_contains = [\"x\"]\n").unwrap();
        assert_eq!(
            cfg.exec_rules.untrusted_exe_prefixes,
            vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/dev/shm".to_string(),
                "/run/user".to_string()
            ]
        );
        assert_eq!(
            cfg.exec_rules.shell_comms,
            vec!["sh", "bash", "dash", "zsh", "nc", "ncat", "socat", "perl", "ruby"]
        );
        assert!(cfg.app.exe_allowlist.is_empty());
        assert!(cfg.validate().is_ok());

        let cfg: Config =
            toml::from_str("[exec_rules]\nuntrusted_exe_prefixes = [\"/srv/stage\"]\n").unwrap();
        assert_eq!(
            cfg.exec_rules.untrusted_exe_prefixes,
            ["/srv/stage".to_string()]
        );
        assert_eq!(
            cfg.exec_rules.shell_comms.len(),
            9,
            "still the shipped list"
        );
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn the_loader_exe_allowlist_is_optional_and_its_entries_must_be_paths() {
        // W2K-18. Two halves, and the second is the one that matters operationally.
        //
        // (a) Back-compat: a file written before the rule existed must still parse,
        // with the list EMPTY. Empty is not "allow nothing by name" — it is "nothing
        // on this host is authorized by identity", which `--check` prints every run.
        let cfg: Config = toml::from_str("[app]\ncgroup_contains = [\"x\"]\n").unwrap();
        assert!(
            cfg.bpf_rules.allow_loader_exes.is_empty(),
            "a pre-W2K-18 file must not gain an armed exe allowlist"
        );
        assert_eq!(cfg.bpf_rules.allow_loaders, vec!["warden".to_string()]);
        assert!(cfg.validate().is_ok());

        // (b) A dead entry here does not merely fail to match: it reads as a pinned
        // loader while authorizing nothing, which is the silent-failure shape W-R4
        // exists to prevent. Relative (can never equal a /proc/<pid>/exe target),
        // blank, "/" (would be a path root, not a file), and whitespace-padded all
        // get refused at load rather than discovered in a log.
        for exe in ["\"\"", "\"bpftool\"", "\"/\"", "\"  /usr/sbin/bpftool  \""] {
            let cfg: Config =
                toml::from_str(&format!("[bpf_rules]\nallow_loader_exes = [{exe}]\n")).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("allow_loader_exes[0]"), "{exe}: {err}");
            assert!(err.contains("absolute"), "{exe}: {err}");
        }
        for body in [
            "allow_loader_exes = []",
            "allow_loader_exes = [\"/usr/local/sbin/warden\", \"/usr/sbin/bpftool\"]",
        ] {
            let cfg: Config = toml::from_str(&format!("[bpf_rules]\n{body}\n")).unwrap();
            assert!(cfg.validate().is_ok(), "{body}");
        }
        // The index is named, so a long list points at the bad line.
        let cfg: Config = toml::from_str(
            "[bpf_rules]\nallow_loader_exes = [\"/usr/sbin/ok\", \"relative/nope\"]\n",
        )
        .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("allow_loader_exes[1]"), "{err}");
    }

    #[test]
    fn the_privilege_exe_allowlist_is_optional_and_its_entries_must_be_paths() {
        // W2K-30a, the same two halves as the loader list above.
        //
        // (a) Back-compat: a file written before this field existed still parses,
        // with the list EMPTY. Empty is not "nothing is plumbing" — the comm list
        // still answers, now only where the readable executable agrees with the
        // name — it is "nothing here is authorised by path", which `--check` names.
        let cfg: Config = toml::from_str("[app]\ncgroup_contains = [\"x\"]\n").unwrap();
        assert!(
            cfg.cred_rules.expected_privilege_exes.is_empty(),
            "a pre-W2K-30 file must not gain an armed exe allowlist"
        );
        assert!(cfg
            .cred_rules
            .expected_privilege_comms
            .contains(&"sudo".to_string()));
        assert!(cfg.validate().is_ok());

        // (b) A dead entry is worse than a non-match here: it reads as pinned
        // identity while authorizing nothing. Relative, blank, "/", and a padded path
        // are refused at load, indexed so a long list points at the bad line.
        for exe in ["\"\"", "\"sudo\"", "\"/\"", "\"  /usr/bin/sudo  \""] {
            let cfg: Config = toml::from_str(&format!(
                "[cred_rules]\nexpected_privilege_exes = [{exe}]\n"
            ))
            .unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("expected_privilege_exes[0]"), "{exe}: {err}");
            assert!(err.contains("absolute"), "{exe}: {err}");
        }
        for body in [
            "expected_privilege_exes = []",
            "expected_privilege_exes = [\"/usr/bin/sudo\", \"/usr/sbin/sshd\"]",
        ] {
            let cfg: Config = toml::from_str(&format!("[cred_rules]\n{body}\n")).unwrap();
            assert!(cfg.validate().is_ok(), "{body}");
        }
        let cfg: Config =
            toml::from_str("[cred_rules]\nexpected_privilege_exes = [\"/usr/bin/sudo\", \"su\"]\n")
                .unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("expected_privilege_exes[1]"), "{err}");
    }

    #[test]
    fn every_uplink_shape_is_classified_as_the_address_it_really_is() {
        // W2K-19. The whole enforceable claim rests on this table, so every range
        // that changes an answer is a row: the CGNAT boundaries (100.64.0.0 and
        // 100.127.255.255 are overlay-network addresses, 100.128.0.0 is not), the
        // IPv4-mapped IPv6 form that would otherwise smuggle a public v4 past the
        // rule, and the shapes a URL carries around the host — port, userinfo,
        // brackets. `Name` is the conservative bucket: an unclassifiable host is
        // reported, never refused on a guess.
        let cases: &[(&str, UplinkTarget)] = &[
            ("http://127.0.0.1:9099/api/", UplinkTarget::Loopback),
            ("http://localhost:9099/api/", UplinkTarget::Name),
            ("http://[::1]:9099/beat", UplinkTarget::Loopback),
            ("http://10.8.0.5:9099/x", UplinkTarget::Private),
            ("http://172.16.0.1/x", UplinkTarget::Private),
            ("http://192.168.100.10:9099/api/", UplinkTarget::Private),
            ("http://100.64.0.0/x", UplinkTarget::Private),
            ("http://100.127.255.255/x", UplinkTarget::Private),
            ("http://100.128.0.0/x", UplinkTarget::Public),
            ("http://169.254.1.1/x", UplinkTarget::Private),
            ("http://[fd00::5]:9099/beat", UplinkTarget::Private),
            ("http://[fe80::1%eth0]/beat", UplinkTarget::Name),
            ("http://[fe80::1]/beat", UplinkTarget::Private),
            ("http://1.1.1.1/x", UplinkTarget::Public),
            ("http://[2606:4700::1]/x", UplinkTarget::Public),
            // A public v4 written in IPv6-dotted form is still a public v4.
            ("http://[::ffff:8.8.8.8]/x", UplinkTarget::Public),
            ("http://[::ffff:192.168.1.9]/x", UplinkTarget::Private),
            // The host is the authority, not the userinfo or the port.
            ("http://user:pass@8.8.4.4:8080/p", UplinkTarget::Public),
            ("http://8.8.4.4", UplinkTarget::Public),
            // Not classifiable — reported as a name, and never refused on a guess.
            ("http://sentinel.internal:9099/api/", UplinkTarget::Name),
            ("sentinel:9099", UplinkTarget::Name),
            ("http:///no-host", UplinkTarget::Name),
        ];
        for (url, want) in cases {
            assert_eq!(classify_uplink(url), *want, "{url}");
        }
    }

    #[test]
    fn a_cleartext_uplink_to_a_routable_address_is_refused_unless_attested() {
        // W2K-19: the sentence "TLS terminates at the edge, the Warden→edge hop is a
        // trusted path" was only prose. Now a publicly routable IP literal over
        // cleartext HTTP does not load, because that request carries `X-API-Key` and
        // every finding's command line, executable path and pid.
        let public = |url: &str, extra: &str| {
            let cfg: Config = toml::from_str(&format!(
                "[bridge]\nurl = \"{url}\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n{extra}\n"
            ))
            .unwrap();
            cfg.validate().err().map(|e| e.to_string())
        };

        let err = public("http://203.0.113.9:9099/api/v1/", "").expect("must refuse");
        assert!(err.contains("bridge.url"), "{err}");
        assert!(err.contains("PUBLICLY ROUTABLE"), "{err}");
        assert!(err.contains("allow_public_plaintext"), "{err}");

        // The same target, attested, loads — and the loopback/private/hostname
        // shapes that the live deployment and every documented install use are
        // untouched, which is what makes this a guard rather than a breaking change.
        assert!(public(
            "http://203.0.113.9:9099/api/v1/",
            "allow_public_plaintext = true"
        )
        .is_none());
        for url in [
            "http://127.0.0.1:9099/api/v1/sentinel/host/",
            "http://192.168.100.10:9099/api/",
            "http://100.64.0.10/api/",
            "http://[::1]:9099/api/",
            "http://sentinel.internal:9099/api/",
        ] {
            assert!(public(url, "").is_none(), "{url} must load");
        }

        // Same rule, same reasoning, on the beat: an off-box switch whose beats are
        // readable tells an attacker when the host went quiet.
        let hb = |url: &str, extra: &str| {
            let cfg: Config =
                toml::from_str(&format!("[heartbeat]\nurl = \"{url}\"\n{extra}\n")).unwrap();
            cfg.validate().err().map(|e| e.to_string())
        };
        let err = hb("http://203.0.113.9:9099/beat", "").expect("must refuse");
        assert!(err.contains("heartbeat.url"), "{err}");
        assert!(hb("http://127.0.0.1:9099/beat", "").is_none());
        assert!(hb(
            "http://203.0.113.9:9099/beat",
            "allow_public_plaintext = true"
        )
        .is_none());
    }

    #[test]
    fn a_name_that_resolves_to_a_public_address_is_refused_before_it_sends() {
        // W2K-28: the W2K-19 gate could only classify a URL written as an IP
        // literal, so spelling the same destination as a NAME walked around it. The
        // answer of one bounded startup lookup is now judged by the same rule.
        let cfg: Config = toml::from_str(
            "[bridge]\nurl = \"http://sentinel.internal:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n",
        )
        .unwrap();
        let err = resolve_uplink_names(&cfg, |_| Ok(vec!["8.8.8.8".parse().unwrap()]))
            .err()
            .map(|e| e.to_string())
            .expect("a public answer must be refused");
        assert!(err.contains("bridge.url"), "{err}");
        assert!(err.contains("PUBLICLY ROUTABLE"), "{err}");
        assert!(err.contains("8.8.8.8"), "{err}");
        assert!(err.contains("allow_public_plaintext"), "{err}");
        assert!(err.contains("NAME was not a way around"), "{err}");

        // The same attestation that lets a literal through lets the name through —
        // and says so in the note, because the flag is a claim about a path Warden
        // cannot see, not a transport.
        let cfg: Config = toml::from_str(
            "[bridge]\nurl = \"http://sentinel.internal:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\nallow_public_plaintext = true\n",
        )
        .unwrap();
        let notes = resolve_uplink_names(&cfg, |_| Ok(vec!["8.8.8.8".parse().unwrap()]))
            .expect("attested path loads");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("PUBLICLY ROUTABLE"), "{}", notes[0]);
        assert!(notes[0].contains("allow_public_plaintext"), "{}", notes[0]);
    }

    #[test]
    fn a_name_that_answers_inside_a_trusted_range_is_reported_not_refused() {
        // The deployment this gate must NOT break: an internal name whose record
        // points at a private or loopback address. Note the ranges are named in the
        // note — an operator reading `--check` sees the address AND the judgement.
        for (answer, phrase) in [
            ("10.8.0.5", "private range"),
            ("100.64.0.10", "private range"),
            ("192.168.100.10", "private range"),
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("fd00::5", "private range"),
            // An IPv4-mapped IPv6 answer is judged by the v4 it carries, exactly as
            // a literal of the same shape is.
            ("::ffff:10.8.0.5", "private range"),
        ] {
            let cfg: Config = toml::from_str(
                "[bridge]\nurl = \"http://sentinel.internal:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n",
            )
            .unwrap();
            let ip: IpAddr = answer.parse().unwrap();
            let shown = ip.to_string();
            let notes = resolve_uplink_names(&cfg, |_| Ok(vec![ip]))
                .unwrap_or_else(|e| panic!("{answer} must not be refused: {e}"));
            assert_eq!(notes.len(), 1, "{answer}: {notes:?}");
            assert!(notes[0].contains(&shown), "{}", notes[0]);
            assert!(notes[0].contains(phrase), "{}", notes[0]);
            assert!(!notes[0].contains("PUBLICLY"), "{}", notes[0]);
        }
    }

    #[test]
    fn one_public_answer_in_a_multi_record_name_refuses_the_uplink() {
        // `BridgeClient::resolve` takes the FIRST address the resolver returns, and
        // the order is the resolver's to choose. A name with both a private and a
        // public record is therefore a name that can answer publicly, so the gate
        // asks whether ANY answer is routable — not whether the first one was.
        let cfg: Config = toml::from_str(
            "[bridge]\nurl = \"http://sentinel.internal:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n",
        )
        .unwrap();
        let err = resolve_uplink_names(&cfg, |_| {
            Ok(vec![
                "10.8.0.5".parse().unwrap(),
                "203.0.113.9".parse().unwrap(),
            ])
        })
        .err()
        .map(|e| e.to_string())
        .expect("a routable record among the answers must refuse");
        assert!(err.contains("203.0.113.9"), "{err}");
        assert!(err.contains("10.8.0.5"), "{err}");

        // IPv6-only public answer: same rule, same refusal.
        let err = resolve_uplink_names(&cfg, |_| Ok(vec!["2606:4700::1".parse().unwrap()]))
            .err()
            .map(|e| e.to_string())
            .expect("a public v6 answer must refuse");
        assert!(err.contains("2606:4700::1"), "{err}");
    }

    #[test]
    fn an_unresolvable_name_warns_and_the_host_still_starts() {
        // The resolver is a network service, and a dead one is not a security
        // decision. Refusing to start because DNS did not answer would turn an
        // outage into a host with no detection agent — and the crash-loop history
        // (P0-1) is why a config gate that depends on the network has to be able to
        // say "unknown" without stopping the process.
        let cfg: Config = toml::from_str(
            "[bridge]\nurl = \"http://sentinel.internal:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n",
        )
        .unwrap();
        let notes = resolve_uplink_names(&cfg, |_| {
            anyhow::bail!("DNS lookup failed: no route to host")
        })
        .expect("a failed lookup must not refuse the config");
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("could not be classified"), "{}", notes[0]);
        assert!(notes[0].contains("no route to host"), "{}", notes[0]);
        assert!(notes[0].contains("still starts"), "{}", notes[0]);

        // An answer of zero addresses is the same case: nothing was classified.
        let notes = resolve_uplink_names(&cfg, |_| Ok(vec![])).expect("no answers must not refuse");
        assert!(
            notes[0].contains("resolved to no addresses"),
            "{}",
            notes[0]
        );
    }

    #[test]
    fn an_ip_literal_uplink_costs_no_dns_lookup_at_all() {
        // The shipped shape — and every install that followed the documented
        // example — must still start with zero resolver calls: no stall, no
        // network dependency, no new startup cost. This is the assertion that keeps
        // the gate from quietly making Warden's startup depend on DNS.
        let looked_up = std::sync::atomic::AtomicUsize::new(0);
        let count = |host: &str| {
            looked_up.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(vec![host.parse::<IpAddr>().unwrap()])
        };
        let cfg: Config = toml::from_str(
            "[bridge]\nurl = \"http://127.0.0.1:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n[heartbeat]\nurl = \"http://10.8.0.9:9000/beat\"\n",
        )
        .unwrap();
        assert!(resolve_uplink_names(&cfg, count).unwrap().is_empty());
        assert_eq!(looked_up.load(std::sync::atomic::Ordering::SeqCst), 0);

        // An attested public LITERAL is also already judged by `validate()`, so it
        // does not come back here for a second opinion.
        let cfg: Config = toml::from_str(
            "[bridge]\nurl = \"http://203.0.113.9/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\nallow_public_plaintext = true\n",
        )
        .unwrap();
        assert!(resolve_uplink_names(&cfg, count).unwrap().is_empty());
        assert_eq!(looked_up.load(std::sync::atomic::Ordering::SeqCst), 0);

        // No uplink at all — the safe default an agent runs with when no `--config`
        // was given — resolves nothing either.
        assert!(resolve_uplink_names(&Config::safe_default(), count)
            .unwrap()
            .is_empty());
        assert_eq!(looked_up.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn the_heartbeat_name_gets_the_same_gate_and_both_are_reported_in_order() {
        // Same exposure rule as W2K-19 already applies to the beat: a beat anyone on
        // the path can read tells them when this host went quiet. And with both
        // uplinks named, `--check` must print both lines, bridge first, the order
        // the rest of the transport lines use.
        let hb: Config =
            toml::from_str("[heartbeat]\nurl = \"http://collector.internal:9000/beat\"\n").unwrap();
        let err = resolve_uplink_names(&hb, |_| Ok(vec!["203.0.113.10".parse().unwrap()]))
            .err()
            .map(|e| e.to_string())
            .expect("a public beat collector must be refused");
        assert!(err.contains("heartbeat.url"), "{err}");
        let hb_attested: Config =
            toml::from_str("[heartbeat]\nurl = \"http://collector.internal:9000/beat\"\nallow_public_plaintext = true\n")
                .unwrap();
        assert!(
            resolve_uplink_names(&hb_attested, |_| Ok(vec!["203.0.113.10".parse().unwrap()]))
                .map(|n| n.len() == 1)
                .unwrap_or(false)
        );

        let both: Config = toml::from_str(
            "[bridge]\nurl = \"http://sentinel.internal:9099/api/\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n[heartbeat]\nurl = \"http://collector.internal:9000/beat\"\n",
        )
        .unwrap();
        let notes = resolve_uplink_names(&both, |host| {
            Ok(vec![if host.starts_with("sentinel") {
                "10.8.0.5".parse().unwrap()
            } else {
                "100.64.0.10".parse().unwrap()
            }])
        })
        .unwrap();
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(
            notes[0].contains("bridge uplink host sentinel.internal"),
            "{}",
            notes[0]
        );
        assert!(
            notes[1].contains("heartbeat uplink host collector.internal"),
            "{}",
            notes[1]
        );
        assert!(notes[1].contains("100.64.0.10"), "{}", notes[1]);
    }

    #[test]
    fn the_real_resolver_answers_a_literal_without_reaching_the_network() {
        // `lookup_uplink_host` is the function that actually touches the resolver,
        // so the one thing that can be asserted about it without a network is that
        // an IP literal short-circuits it. The shipped config shape depends on this
        // (the test above proves the CALLER skips it; this proves the function
        // would too if asked directly).
        assert_eq!(
            lookup_uplink_host("127.0.0.1").unwrap(),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            lookup_uplink_host("::1").unwrap(),
            vec!["::1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            lookup_uplink_host("203.0.113.9").unwrap(),
            vec!["203.0.113.9".parse::<IpAddr>().unwrap()]
        );
        // The failure and timeout paths of the REAL resolver are not exercised here:
        // a unit test cannot make DNS hang or go away. They are covered by an
        // injected Err in `an_unresolvable_name_warns_and_the_host_still_starts`,
        // and the 2 s deadline itself is measured live (report §۸۰).
    }

    #[test]
    fn the_check_line_names_the_side_of_the_line_for_each_uplink() {
        // `--check` is the only place an operator reads this. A loopback target must
        // not be described like a public one, and a name must not be described like
        // an IP — the honest statement about a name is that Warden cannot classify it.
        let loopback: Config = toml::from_str(
            "[bridge]\nurl = \"http://127.0.0.1:9099/x\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\n",
        )
        .unwrap();
        let line = uplink_constraint_line(&loopback);
        assert!(line.contains("bridge transport"), "{line}");
        assert!(line.contains("loopback"), "{line}");
        assert!(!line.contains("PUBLIC"), "{line}");

        let named: Config = toml::from_str(
            "[bridge]\nurl = \"http://sentinel.internal:9099/x\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\nallow_public_plaintext = true\n",
        )
        .unwrap();
        let line = uplink_constraint_line(&named);
        assert!(line.contains("host NAME"), "{line}");
        assert!(line.contains("resolves to"), "{line}");

        let attested: Config = toml::from_str(
            "[bridge]\nurl = \"http://203.0.113.9/x\"\napi_key = \"k\"\nspool_path = \"/tmp/t\"\nallow_public_plaintext = true\n[heartbeat]\nurl = \"http://203.0.113.10/beat\"\nallow_public_plaintext = true\n",
        )
        .unwrap();
        let line = uplink_constraint_line(&attested);
        assert!(line.contains("bridge transport"), "{line}");
        assert!(line.contains("heartbeat transport"), "{line}");
        assert!(line.contains("PUBLIC address"), "{line}");

        let none: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert!(uplink_constraint_line(&none).contains("no uplink configured"));
    }

    #[test]
    fn the_runtime_defaults_reproduce_the_shipped_behaviour() {
        // W2K-13 added two knobs, and the whole point is that an operator who never
        // hears about them gets exactly what Warden shipped with: the 256 KiB ring
        // baked into `bpf/warden.bpf.c`, and an enrichment cache short enough that
        // no finding is ever judged against attribution more than a tenth of a
        // second old.
        let cfg: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert_eq!(cfg.runtime.ring_size_kib, DEFAULT_RING_KIB);
        assert_eq!(cfg.runtime.ring_bytes(), 256 * 1024);
        assert_eq!(cfg.runtime.effective_ring_bytes(4096), 256 * 1024);
        assert_eq!(
            cfg.runtime.effective_ring_bytes(65536),
            256 * 1024,
            "256 KiB is four 64 KiB pages, so the shipped size survives rounding on \
             a large-page kernel too"
        );
        assert!(cfg.runtime.ring_size_problem(4096).is_none());
        assert!(cfg.runtime.ring_size_problem(65536).is_none());
        assert_eq!(
            cfg.runtime.enrich_cache_ttl(),
            Some(std::time::Duration::from_millis(DEFAULT_ENRICH_CACHE_MS))
        );
        assert!(cfg.validate().is_ok());
        assert!(Config::safe_default().validate().is_ok());
    }

    #[test]
    fn resource_budget_defaults_match_the_unit_and_drift_is_refused() {
        let cfg: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert_eq!(cfg.resources.memory_max_mb, crate::resources::MEMORY_MAX_MB);
        assert_eq!(
            cfg.resources.cpu_quota_percent,
            crate::resources::CPU_QUOTA_PERCENT
        );
        assert_eq!(cfg.resources.tasks_max, crate::resources::TASKS_MAX);
        assert_eq!(
            cfg.resources.open_files_max,
            crate::resources::OPEN_FILES_MAX
        );
        assert_eq!(cfg.resources.io_weight, crate::resources::IO_WEIGHT);
        assert!(cfg.validate().is_ok());

        let drifted: Config =
            toml::from_str("mode = \"observe\"\n[resources]\nmemory_max_mb = 1024\n").unwrap();
        let err = drifted.validate().unwrap_err().to_string();
        assert!(err.contains("resources.memory_max_mb"), "{err}");
        assert!(err.contains("systemd/warden.service"), "{err}");
    }

    #[test]
    fn phase3_deny_destinations_default_empty_and_parse_without_changing_posture() {
        // A deny rule is inert policy data in this build (no kernel primitive),
        // so it must not become fatal config, must not flip mode, and must not
        // appear as protection. Default = empty: an operator who never hears
        // about the field sees no behaviour change.
        let bare: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert!(bare.network_rules.deny_destinations.is_empty());
        assert_eq!(bare.mode, Mode::Observe);

        let with_rules: Config = toml::from_str(
            "mode = \"observe\"\n\
             [network_rules]\n\
             deny_destinations = [\"203.0.113.9:4444\", \"198.51.100.7\"]\n",
        )
        .unwrap();
        assert_eq!(
            with_rules.network_rules.deny_destinations,
            vec!["203.0.113.9:4444", "198.51.100.7"]
        );
        assert_eq!(with_rules.mode, Mode::Observe, "a rule cannot flip posture");
        assert!(with_rules.validate().is_ok());
        // The parsed field feeds the honest startup posture, which must never
        // claim enforcement just because a rule was written down.
        let posture = crate::policy::PolicyPosture::new(
            with_rules.mode,
            with_rules.network_rules.deny_destinations.len(),
        );
        assert_eq!(
            posture.enforcement,
            crate::policy::EnforcementState::Observe
        );
        assert!(posture.summary().contains("NOT be blocked"));
    }

    #[test]
    fn a_ring_the_kernel_would_silently_resize_is_refused() {
        // The ring is allocated as a power-of-two number of pages. Accept 200 and
        // the host gets 256 — and every "N events dropped" the counters report is
        // then measured against a capacity the config never named.
        for (kib, page, want) in [
            (200u32, 4096u32, 256),
            (96, 4096, 128),
            (192, 65536, 256),
            (65, 4096, 128),
        ] {
            let rt = Runtime {
                ring_size_kib: kib,
                ..Runtime::default()
            };
            assert_eq!(
                rt.effective_ring_bytes(page),
                want * 1024,
                "{kib} KiB on a {page}-byte page host"
            );
            let problem = rt
                .ring_size_problem(page)
                .unwrap_or_else(|| panic!("{kib} KiB should be refused"));
            assert!(problem.contains("rounds up to"), "{problem}");
            assert!(
                problem.contains(&format!("Say {want} instead")),
                "the message must name the size the operator gets: {problem}"
            );
        }
        // Sizes the kernel honours verbatim, at both page sizes.
        for (kib, page) in [
            (64u32, 4096u32),
            (256, 4096),
            (16384, 4096),
            (64, 65536),
            (128, 65536),
        ] {
            let rt = Runtime {
                ring_size_kib: kib,
                ..Runtime::default()
            };
            assert_eq!(rt.effective_ring_bytes(page), kib * 1024);
            assert!(rt.ring_size_problem(page).is_none(), "{kib} KiB");
        }
        // Out-of-range values are refused by range, not by rounding.
        for kib in [0u32, 32, MAX_RING_KIB + 1024] {
            let rt = Runtime {
                ring_size_kib: kib,
                ..Runtime::default()
            };
            let problem = rt.ring_size_problem(4096).expect("refused");
            assert!(problem.contains("outside the supported range"), "{problem}");
        }
        // …and the same through the real load path, so a file with 200 KiB never
        // reaches a running Warden.
        let cfg: Config = toml::from_str("[runtime]\nring_size_kib = 200\n").unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("runtime.ring_size_kib"), "{err}");
        assert!(err.contains("rounds up to"), "{err}");
    }

    #[test]
    fn the_ring_default_is_the_ring_baked_into_the_shipped_object() {
        // W2K-13 turned the ring into policy, but `bpf/warden.bpf.c` still bakes a
        // size into the object this binary embeds, and the loader overrides it when
        // the map is created. If the two drift, the *default* config quietly changes
        // the capacity every drop counter is a fraction of — which is the W-02
        // failure in a new hat. So: read the shipping bytes, not a comment.
        fn embedded_object() -> &'static [u8] {
            aya::include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
        }
        let obj =
            aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");
        let ring = obj
            .maps
            .get("events")
            .expect("the embedded object has no `events` ring buffer");
        assert_eq!(
            DEFAULT_RING_KIB * 1024,
            ring.max_entries(),
            "`[runtime].ring_size_kib` defaults to {DEFAULT_RING_KIB} KiB but the object \
             baked into the binary says otherwise; a config that says nothing would then \
             resize the ring the drop counters were measured against"
        );
    }

    #[test]
    fn the_enrichment_cache_window_is_bounded_or_disabled() {
        // 0 is a real policy ("read /proc for every event, like before W2K-13"), so
        // it must stay accepted; a window long enough to age a finding is not a
        // performance knob any more, so it is refused.
        for ms in [0u64, 1, DEFAULT_ENRICH_CACHE_MS, MAX_ENRICH_CACHE_MS] {
            let cfg: Config =
                toml::from_str(&format!("[runtime]\nenrich_cache_ms = {ms}\n")).unwrap();
            assert!(cfg.validate().is_ok(), "{ms} ms");
        }
        let cfg: Config = toml::from_str("[runtime]\nenrich_cache_ms = 5001\n").unwrap();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("enrich_cache_ms"), "{err}");
        assert!(err.contains("ceiling"), "{err}");
        assert_eq!(
            Runtime {
                enrich_cache_ms: 0,
                ..Runtime::default()
            }
            .enrich_cache_ttl(),
            None
        );
    }

    #[test]
    fn bridge_values_that_can_only_fail_are_refused() {
        // Each of these looks configured but guarantees no delivery: a zero
        // queue, a zero spool cap (drop everything on outage), and a zero
        // timeout (expire before connect).
        for (field, body) in [
            ("queue_max", "queue_max = 0"),
            ("spool_max_bytes", "spool_max_bytes = 0"),
            ("timeout_ms", "timeout_ms = 0"),
        ] {
            let toml_src =
                format!("[bridge]\nurl = \"http://127.0.0.1:9/x\"\napi_key = \"k\"\n{body}\n");
            let cfg: Config = toml::from_str(&toml_src).unwrap();
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(field), "{field}: {err}");
        }
    }

    #[test]
    fn an_enabled_snapshot_that_starves_or_says_nothing_is_refused() {
        // Each of these is a pull path that costs the loop without paying the
        // operator anything: a cadence that never sleeps (it walks /proc inside
        // the loop that drains the ring), a report bound of zero (the tables are
        // read and nothing is ever named), and attribution with no pid budget
        // (every socket comes back with an unknown owner, which is the exact
        // thing attribution exists to avoid).
        for (want, body) in [
            ("interval_secs", "interval_secs = 1"),
            ("report_max_sockets", "report_max_sockets = 0"),
            (
                "attribute_max_pids",
                "attribute = true\nattribute_max_pids = 0",
            ),
        ] {
            let cfg: Config =
                toml::from_str(&format!("[network_snapshot]\nenabled = true\n{body}\n")).unwrap();
            assert!(cfg.network_snapshot.enabled);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains(want), "{want}: {err}");
        }

        // The same values are legal once the pull path is off: the floor is about
        // the walk, and a disabled section performs none.
        let cfg: Config = toml::from_str(
            "[network_snapshot]\nenabled = false\ninterval_secs = 1\nreport_max_sockets = 0\n",
        )
        .unwrap();
        assert!(cfg.validate().is_ok(), "off must not be refused");
    }

    /// The section is additive: absent means off, and a host that has not opted
    /// in pays no /proc walk. This is the shipped default, so it is pinned here
    /// rather than left to the `Default` impl alone.
    #[test]
    fn the_pull_path_is_off_until_an_operator_turns_it_on() {
        let cfg: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert!(
            !cfg.network_snapshot.enabled,
            "the socket snapshot must not activate itself"
        );
        assert_eq!(cfg.network_snapshot.interval_secs, 300);
        assert_eq!(cfg.network_snapshot.report_max_sockets, 32);
        assert_eq!(cfg.network_snapshot.attribute_max_pids, 4096);
        // Attribution is on *within* the section: when an operator enables the
        // pull path, an unattributed socket table is `netstat`, not Warden.
        assert!(cfg.network_snapshot.attribute);

        let cfg: Config =
            toml::from_str("[network_snapshot]\nenabled = true\ninterval_secs = 900\n").unwrap();
        assert!(cfg.network_snapshot.enabled);
        assert_eq!(cfg.network_snapshot.interval_secs, 900);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn deny_mask_honours_explicit_intents_and_allow_root() {
        // An append-only audit log: deny only write, but allow the root-owned
        // writer. The mask is write-only and the ALLOW_ROOT flag is set. Case and
        // whitespace are normalised; an unknown intent word is ignored (never
        // widens the deny set — fail toward not locking the box out).
        let toml = r#"
mode = "enforce"
[enforce]
arm = true
[[enforce.guarded_files]]
path = "/var/log/warden/audit.log"
authorized_uid = 0
deny = [" Write ", "bogus"]
allow_root = true
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.enforce.arm);
        let g = &cfg.enforce.guarded_files[0];
        assert_eq!(g.deny_mask(), WARDEN_INTENT_WRITE); // "bogus" dropped
        assert_eq!(g.flags(), WARDEN_GUARD_ALLOW_ROOT);
    }

    #[test]
    fn deny_mask_can_express_all_three_intents() {
        let toml = r#"
[[enforce.guarded_files]]
path = "/opt/app/signer"
authorized_uid = 991
deny = ["read", "write", "exec"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let g = &cfg.enforce.guarded_files[0];
        assert_eq!(
            g.deny_mask(),
            WARDEN_INTENT_READ | WARDEN_INTENT_WRITE | WARDEN_INTENT_EXEC
        );
    }

    // ---- W2K-17: property tests over arbitrary config input ------------------

    const CFG_SEED: u64 = 0x5EED_C0F1;
    const CFG_ITERS: u32 = 2048;

    /// The three intent bits plus nothing — the only mask the kernel understands.
    const ALL_INTENTS: u32 = WARDEN_INTENT_READ | WARDEN_INTENT_WRITE | WARDEN_INTENT_EXEC;

    #[test]
    fn the_config_parser_surves_arbitrary_documents_and_only_refuses() {
        // Warden reads its policy from a file an operator edited under pressure,
        // and the loader runs as root before anything is sanitised. Two
        // properties hold the line: (1) no input panics — a panic here is a
        // supervisor restart loop on a host that is already under attack, and
        // (2) the only failure mode is a refusal, never a partial config. The
        // corpus mixes raw noise (`text`) with structure-shaped documents
        // (`tomlish`) so both the reject path and the accept path get driven.
        for i in 0..CFG_ITERS {
            let mut a = crate::arb::Arb::new(CFG_SEED + i as u64);
            let src = if i % 2 == 0 {
                a.text_below(400)
            } else {
                a.tomlish()
            };
            match toml::from_str::<Config>(&src) {
                Ok(cfg) => {
                    // An accepted document must be usable: validate may refuse,
                    // but it may not panic and it may not refuse silently.
                    if let Err(e) = cfg.validate() {
                        let msg = e.to_string();
                        assert!(
                            !msg.trim().is_empty(),
                            "iteration {i}: validation refused with no reason\n---\n{src}\n---"
                        );
                    }
                }
                Err(e) => {
                    // A parse error is a message, not a crash; it is what the
                    // operator sees before the restart loop, so it has to say
                    // something.
                    assert!(
                        !e.to_string().is_empty(),
                        "iteration {i}: parse failure with no message"
                    );
                }
            }
        }
    }

    #[test]
    fn a_loaded_config_always_passes_validation_and_keeps_the_shadow_default() {
        // The load path is the contract: `Config::load` validates, SIGHUP keeps
        // the previous config when it refuses, and everything downstream assumes
        // a validated `Config`. So anything that comes out of `load` must
        // validate — if the call ever drops, this is what notices — and a
        // document that never names the two kill-switches must still land
        // observe-only and un-armed, so garbage can never turn prevention on by
        // accident.
        let dir = temp_dir("config-arbitrary");
        let path = dir.join("warden.toml");
        for i in 0..CFG_ITERS {
            let mut a = crate::arb::Arb::new(CFG_SEED + 7919 * i as u64);
            let src = a.tomlish();
            let names = |key: &str| {
                src.lines()
                    .any(|l| l.trim_start().starts_with(&format!("{key} =")))
            };
            std::fs::write(&path, &src).expect("write the test's own config");

            match Config::load(&path) {
                Err(_) => continue,
                Ok(cfg) => {
                    assert!(
                        cfg.validate().is_ok(),
                        "iteration {i}: load returned a config validation refuses\n---\n{src}\n---"
                    );
                    if !names("mode") {
                        assert!(
                            matches!(cfg.mode, Mode::Observe),
                            "iteration {i}: a document that never set mode is not observe-only\n---\n{src}\n---"
                        );
                    }
                    if !names("arm") {
                        assert!(
                            !cfg.enforce.arm,
                            "iteration {i}: a document that never set arm is armed\n---\n{src}\n---"
                        );
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unreadable_deny_list_never_widens_past_the_three_kernel_intents() {
        // `deny_mask` feeds a numeric field straight into the BPF map. Unknown
        // words are ignored on purpose (a typo must not lock the box out of its
        // own files), so the invariant is that the mask is always a subset of
        // the three bits the kernel knows, and that a word never maps to more
        // than its own bit however it is spelled.
        for i in 0..CFG_ITERS {
            let mut a = crate::arb::Arb::new(CFG_SEED + 104729 * i as u64);
            let words: Vec<String> = (0..a.u32_below(8))
                .map(|_| match a.u32_below(3) {
                    0 => a.text(12),
                    1 => {
                        let known = ["read", "write", "exec", "r", "w", "x", "execute"]
                            [a.u32_below(7) as usize];
                        let mut s = known.to_string();
                        // random case + surrounding whitespace, which the mapper
                        // is documented to normalise
                        s.make_ascii_uppercase();
                        format!("  {s} ")
                    }
                    _ => a.text(6),
                })
                .collect();
            let g = GuardedFile {
                path: "/x".to_string(),
                authorized_uid: a.u32_below(70000),
                deny: words.clone(),
                allow_root: a.boolean(),
            };
            let mask = g.deny_mask();
            assert_eq!(
                mask & !ALL_INTENTS,
                0,
                "iteration {i}: {words:?} produced a mask {mask:#x} outside WARDEN_INTENT_*"
            );
            if g.allow_root {
                assert_eq!(g.flags(), WARDEN_GUARD_ALLOW_ROOT, "iteration {i}");
            } else {
                assert_eq!(g.flags(), 0, "iteration {i}");
            }
            // Every word that was recognised must still be recognised when it is
            // the only entry — a mask never depends on the order or the company
            // of the rest of the list.
            for (n, word) in words.iter().enumerate() {
                let solo = GuardedFile {
                    path: "/x".to_string(),
                    authorized_uid: 0,
                    deny: vec![word.clone()],
                    allow_root: false,
                };
                let bit = solo.deny_mask();
                assert_eq!(
                    bit & !ALL_INTENTS,
                    0,
                    "iteration {i}: word {n} {word:?} produced {bit:#x}"
                );
                assert!(
                    mask & bit == bit,
                    "iteration {i}: word {n} {word:?} means {bit:#x} alone but the list {words:?} \
                     lost it ({mask:#x})"
                );
            }
        }
    }

    // ---- W2K-23: keys Warden never read ----------------------------------------

    /// The shipped sample, comment for comment, is what the audit is calibrated
    /// against: if a documented key ever stops matching a struct field, that is a
    /// real defect and this test says so instead of a host discovering it.
    const SAMPLE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/config/warden.toml"));

    fn unread_of(text: &str) -> Vec<String> {
        let cfg: Config = toml::from_str(text)
            .unwrap_or_else(|e| panic!("the test's own config must parse: {e}"));
        unread_keys(&cfg, text)
    }

    /// The 2026-11-18 live observe window was dominated by benign bind mounts:
    /// systemd-executor building per-unit namespaces, dockerd attaching networks,
    /// runc's /proc/bus bind, and the hardened socat forwarder. Their exes are
    /// now allowlisted in the shipped sample. This pins that decision AND the
    /// carve-out that keeps raw disks and runtime sockets firing even for them.
    #[test]
    fn shipped_sample_quiets_live_mount_noise_without_disarming_the_carveout() {
        let cfg: Config =
            toml::from_str(SAMPLE).unwrap_or_else(|e| panic!("the shipped sample must parse: {e}"));
        for exe in [
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd-executor",
            "/usr/bin/dockerd",
            "/usr/bin/containerd",
            "/usr/bin/runc",
            "/usr/bin/socat1",
        ] {
            assert!(
                cfg.mount_rules
                    .allow_actor_exes
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(exe)),
                "the shipped sample must quiet the live {exe} mount noise"
            );
        }
        for source in ["/dev/sd", "/dev/mem", "/var/run/docker.sock"] {
            assert!(
                cfg.mount_rules
                    .suppress_exempt_sources
                    .iter()
                    .any(|s| source.starts_with(s)),
                "a never-benign source must still fire for an allowlisted exe: {source}"
            );
        }
    }

    #[test]
    fn a_key_written_under_the_wrong_section_is_named_with_that_section() {
        // Exactly the live shape: `wire-bridge.sh` appends its own [bridge] at the end
        // of the file, so the sample's commented bridge keys belong to [respond] as far
        // as TOML is concerned. Uncommenting one used to buy a silent no-op.
        let unread =
            unread_of("[respond]\nkill_reverse_shell = false\nspool_path = \"/tmp/moved.jsonl\"\n");
        assert_eq!(unread, vec!["respond.spool_path".to_string()]);
    }

    #[test]
    fn a_misspelled_section_is_reported_as_a_whole_unread_section() {
        let unread = unread_of("mode = \"observe\"\n[brige]\nurl = \"http://127.0.0.1:9/x\"\n");
        assert_eq!(unread, vec!["brige".to_string()]);
    }

    #[test]
    fn a_misspelled_leaf_key_is_named_exactly() {
        let unread = unread_of(
            "[bridge]\nurl = \"http://127.0.0.1:9/x\"\napi_key = \"k\"\ntimout_ms = 500\n",
        );
        assert_eq!(unread, vec!["bridge.timout_ms".to_string()]);
    }

    #[test]
    fn a_key_inside_a_guard_entry_carries_which_entry_it_was() {
        // Two entries, one with the typo: the index is what makes the warning
        // actionable, because `[[enforce.guarded_files]]` blocks read alike.
        let unread = unread_of(
            "[[enforce.guarded_files]]\npath = \"/etc/shadow\"\nauthorized_uid = 0\n\
             allow_root = false\nallow_rooot = true\n\
             [[enforce.guarded_files]]\npath = \"/keep\"\nauthorized_uid = 0\nallow_root = true\n",
        );
        assert_eq!(
            unread,
            vec!["enforce.guarded_files[0].allow_rooot".to_string()]
        );
    }

    #[test]
    fn the_shipped_sample_config_leaves_nothing_unread() {
        // The false-positive gate AND the drift gate: every key the sample documents
        // must be a field the structs actually read.
        let cfg: Config = toml::from_str(SAMPLE).expect("the shipped sample must parse");
        let unread = unread_keys(&cfg, SAMPLE);
        assert!(
            unread.is_empty(),
            "the sample names keys Warden does not read: {unread:?}"
        );
    }

    #[test]
    fn a_deploy_shaped_file_with_bridge_appended_last_is_fully_read() {
        // The live file's real structure: [respond], then guard tables, then the
        // marker-managed [bridge] at the very end. Nothing there may look unread.
        let text = "[respond]\nkill_reverse_shell = false\n\n[[enforce.guarded_files]]\n\
                    path = \"/etc/shadow\"\nauthorized_uid = 0\nallow_root = true\n\n\
                    [bridge]\nurl = \"http://127.0.0.1:9099/x\"\nhost = \"debian\"\n\
                    timeout_ms = 3000\napi_key = \"k\"\nspool_path = \"/tmp/s.jsonl\"\n";
        assert!(
            unread_of(text).is_empty(),
            "the deploy shape must read as fully understood"
        );
    }

    #[test]
    fn an_unread_key_is_reported_without_stopping_the_agent() {
        // Deliberate design choice, recorded as a test: a sensor that will not start
        // over a typo is a coverage gap. The audit must be loud, never fatal.
        let dir = temp_dir("unread-key");
        let path = dir.join("warden.toml");
        std::fs::write(
            &path,
            "[respond]\nkill_reverse_shell = false\nspool_path = \"/tmp/moved.jsonl\"\n",
        )
        .expect("write the test's own config");
        let cfg = Config::load(&path).expect("an unread key must not refuse the config");
        assert_eq!(cfg.unread_keys, vec!["respond.spool_path".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_config_and_a_default_one_have_nothing_to_report() {
        assert!(unread_of("mode = \"observe\"\n").is_empty());
        let d = Config::safe_default();
        assert!(d.unread_keys.is_empty());
    }

    // ── N-05: the per-cgroup volume counters ────────────────────────────────

    #[test]
    fn the_volume_counters_are_off_until_asked_for_and_default_to_a_quiet_cadence() {
        // The default is a claim about cost: three programs on the TCP/UDP data
        // path of every socket on the host, attached only because an operator read
        // the section above and said yes. A future change that flips this default
        // flips a performance decision on every existing deployment, so it is
        // pinned here rather than left to the struct.
        let cfg: Config = toml::from_str("mode = \"observe\"\n").unwrap();
        assert!(!cfg.net_volume.enabled, "off by default");
        assert_eq!(cfg.net_volume.interval_secs, 60);
        assert_eq!(cfg.net_volume.report_min_bytes, 65536);
        assert_eq!(cfg.net_volume.max_rows_per_tick, 8);
        assert_eq!(cfg.net_volume.cgroup_walk_max, 4096);
        assert_eq!(cfg.net_volume.cgroup_root, Path::new("/sys/fs/cgroup"));
        assert!(!Config::safe_default().net_volume.enabled);
    }

    #[test]
    fn an_enabled_volume_section_that_could_only_ever_report_nothing_is_refused() {
        for (body, needle) in [
            ("interval_secs = 1", "net_volume.interval_secs"),
            ("max_rows_per_tick = 0", "net_volume.max_rows_per_tick"),
            ("cgroup_walk_max = 0", "net_volume.cgroup_walk_max"),
            ("cgroup_root = \"\"", "net_volume.cgroup_root"),
        ] {
            let err = toml::from_str::<Config>(&format!("[net_volume]\nenabled = true\n{body}\n"))
                .unwrap()
                .validate()
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "{body} → {err}");
        }
    }

    #[test]
    fn the_same_zeroes_are_accepted_while_the_sensor_is_off() {
        // Consistent with every other section here: a value that will never be
        // consulted is not a misconfiguration, and refusing it would make it
        // impossible to leave a disabled section in a file for later.
        let cfg = toml::from_str::<Config>(
            "[net_volume]\nenabled = false\ninterval_secs = 1\nmax_rows_per_tick = 0\n\
             cgroup_walk_max = 0\ncgroup_root = \"\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.net_volume.enabled);
    }

    #[test]
    fn a_real_volume_policy_round_trips_through_the_schema() {
        // W2K-23's mechanism depends on every field being serialisable, and this
        // section carries the one PathBuf the rest of the config does not.
        let src = "[net_volume]\nenabled = true\ninterval_secs = 90\nreport_min_bytes = 1048576\n\
                   max_rows_per_tick = 12\ncgroup_walk_max = 256\ncgroup_root = \"/tmp/cg\"\n";
        let cfg = toml::from_str::<Config>(src).unwrap();
        cfg.validate().unwrap();
        assert_eq!(
            unread_of(src),
            Vec::<String>::new(),
            "{:?}",
            cfg.unread_keys
        );
        assert_eq!(cfg.net_volume.cgroup_root, Path::new("/tmp/cg"));
        assert_eq!(cfg.net_volume.report_min_bytes, 1_048_576);
    }

    #[test]
    fn phase7_egress_defaults_are_fully_inert() {
        let cfg = toml::from_str::<Config>("").unwrap();
        cfg.validate().unwrap();
        assert!(!cfg.egress.enabled);
        assert!(!cfg.egress.arm);
        assert!(cfg.egress.cgroup_path.is_none());
        assert!(cfg.egress.deny.is_empty());
    }

    #[test]
    fn phase7_arming_without_enabling_is_rejected() {
        let cfg = toml::from_str::<Config>("[egress]\narm = true\n").unwrap();
        assert!(cfg.validate().is_err());
    }

    fn existing_cgroup_child() -> String {
        let text = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("0::") {
                let relative = rest.trim();
                if relative.starts_with('/') && relative != "/" {
                    return format!("/sys/fs/cgroup{}", relative.trim_end_matches('/'));
                }
            }
        }
        // A process at the namespace root has no child path to name; pick any
        // real directory under the cgroup2 mount. Never attach in this test.
        let entries = std::fs::read_dir("/sys/fs/cgroup").unwrap();
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                return entry.path().display().to_string();
            }
        }
        panic!("no existing cgroup child is available for a non-attaching validation test");
    }

    #[test]
    fn phase7_enabling_requires_an_isolated_cgroup_and_a_real_rule() {
        let no_path = toml::from_str::<Config>(
            "[egress]\nenabled = true\n[[egress.deny]]\naddress = \"203.0.113.9\"\nport = 443\n",
        )
        .unwrap();
        assert!(no_path.validate().is_err());

        let root = toml::from_str::<Config>(
            "[egress]\nenabled = true\ncgroup_path = \"/sys/fs/cgroup\"\n\
             [[egress.deny]]\naddress = \"203.0.113.9\"\nport = 443\n",
        )
        .unwrap();
        assert!(root.validate().is_err());

        let alias = toml::from_str::<Config>(
            "[egress]\nenabled = true\ncgroup_path = \"/sys/fs/cgroup/../cgroup\"\n\
             [[egress.deny]]\naddress = \"203.0.113.9\"\nport = 443\n",
        )
        .unwrap();
        assert!(alias.validate().is_err());

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("warden-cg-symlink-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let symlink = dir.join("root-alias");
        std::os::unix::fs::symlink("/sys/fs/cgroup", &symlink).unwrap();
        let symlink_cfg = toml::from_str::<Config>(&format!(
            "[egress]\nenabled = true\ncgroup_path = \"{}\"\n\
             [[egress.deny]]\naddress = \"203.0.113.9\"\nport = 443\n",
            symlink.display()
        ))
        .unwrap();
        assert!(symlink_cfg.validate().is_err());
        let _ = std::fs::remove_dir_all(&dir);

        let child = existing_cgroup_child();
        let no_rules = toml::from_str::<Config>(&format!(
            "[egress]\nenabled = true\ncgroup_path = \"{child}\"\n"
        ))
        .unwrap();
        assert!(no_rules.validate().is_err());

        let bad_addr = toml::from_str::<Config>(&format!(
            "[egress]\nenabled = true\ncgroup_path = \"{child}\"\n\
             [[egress.deny]]\naddress = \"evil.example.com\"\nport = 443\n"
        ))
        .unwrap();
        assert!(bad_addr.validate().is_err());

        let src = format!(
            "[egress]\nenabled = true\ncgroup_path = \"{child}\"\narm = false\n\
             [[egress.deny]]\naddress = \"203.0.113.9\"\nport = 4444\nprotocol = \"tcp\"\n"
        );
        let good = toml::from_str::<Config>(&src).unwrap();
        good.validate().unwrap();
        assert_eq!(unread_of(&src), Vec::<String>::new());
    }

    /// Phase 8 config tests never place an api_key value in an assertion: the
    /// hard rule is that credentials are never printed or stored in reports.
    fn mtls_fixture(mode: u32) -> (std::path::PathBuf, String) {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("warden-cfg-tls-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["ca.pem", "cert.pem", "key.pem"] {
            let path = dir.join(name);
            std::fs::write(&path, b"not-a-real-certificate").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::set_permissions(dir.join("key.pem"), std::fs::Permissions::from_mode(mode))
            .unwrap();
        let ca = dir.join("ca.pem").display().to_string();
        let cert = dir.join("cert.pem").display().to_string();
        let key = dir.join("key.pem").display().to_string();
        let toml_src = format!(
            "[bridge]\nurl = \"https://sentinel.internal:8443/api/\"\n\
             api_key = \"SENTINEL_TEST_CREDENTIAL\"\n\
             spool_path = \"/tmp/warden-cfg-spool\"\ntls_ca_file = \"{ca}\"\n\
             tls_cert_file = \"{cert}\"\ntls_key_file = \"{key}\"\n"
        );
        (dir, toml_src)
    }

    #[test]
    fn phase8_https_without_complete_mtls_material_is_refused() {
        let cfg = toml::from_str::<Config>(
            "[bridge]\nurl = \"https://sentinel.internal/api/\"\napi_key = \"k\"\n\
             spool_path = \"/tmp/warden-cfg-spool\"\n",
        )
        .unwrap();
        let err = format!("{:#}", cfg.validate().unwrap_err());
        assert!(err.contains("mTLS material is missing"), "{err}");
    }

    #[test]
    fn phase8_partial_mtls_material_is_never_a_silent_downgrade() {
        let (dir, full) = mtls_fixture(0o600);
        let partial = full.replacen("tls_ca_file", "# tls_ca_file", 1);
        let cfg = toml::from_str::<Config>(&partial).unwrap();
        let err = format!("{:#}", cfg.validate().unwrap_err());
        assert!(err.contains("material is incomplete"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn phase8_mtls_material_over_cleartext_http_is_refused() {
        let (dir, full) = mtls_fixture(0o600);
        let clear = full.replace("https://", "http://");
        let cfg = toml::from_str::<Config>(&clear).unwrap();
        let err = format!("{:#}", cfg.validate().unwrap_err());
        assert!(err.contains("not https://"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn phase8_group_or_world_readable_agent_key_is_refused() {
        let (dir, full) = mtls_fixture(0o644);
        let cfg = toml::from_str::<Config>(&full).unwrap();
        let err = format!("{:#}", cfg.validate().unwrap_err());
        assert!(err.contains("requires 0600"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn phase8_complete_mtls_config_is_accepted_and_the_line_stays_credential_free() {
        let (dir, full) = mtls_fixture(0o600);
        let cfg = toml::from_str::<Config>(&full).unwrap();
        cfg.validate().unwrap();
        assert!(cfg.bridge.as_ref().unwrap().mtls_enabled());
        let line = uplink_constraint_line(&cfg);
        assert!(line.contains("MUTUAL TLS"), "{line}");
        assert!(!line.contains("SENTINEL_TEST_CREDENTIAL"), "{line}");
        assert!(!line.contains("key.pem"), "{line}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
