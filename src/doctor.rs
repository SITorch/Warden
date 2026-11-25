//! doctor.rs — `warden --doctor`: the host half of the question `--check` refuses
//! to answer.
//!
//! `--check` is a *policy* check: it reads the config file and prints what the
//! agent would do, and it deliberately never touches the kernel (that is why it
//! can run as systemd's `ExecStartPre` and in CI without privileges). The cost of
//! that purity is that four of the lines it prints end with a hedge — `net_vol`'s
//! coverage sentence says the hooks are "unknown here", and the volume sensor has
//! no way to say whether THIS kernel even has the functions it hooks.
//!
//! `--doctor` answers exactly that, and nothing more: it reads a handful of
//! world-readable kernel files and reports, per attach target, one of three
//! states. It loads nothing, attaches nothing, opens no map, and starts nothing.
//! It does make one syscall that looks like an action — `pidfd_send_signal(fd, 0)`
//! in the kill-delivery probe — and signal 0 is the kernel's own permission check
//! with the delivery suppressed, so it cannot affect any process, including pid 1.
//!
//! THE THREE STATES ARE THE WHOLE DESIGN. `present` / `absent` / `unreadable`.
//! A collapsed third state is how a false negative gets published: on the
//! deployment host, `/sys/kernel/tracing/available_filter_functions` is mode 0440
//! root:root, and reading its `Permission denied` as "the function is not there"
//! would have reported four working hooks as missing (§23 of
//! `scripts/LIVE_VALIDATION.md`, step 1). Wherever this module cannot see, it says
//! it cannot see.
//!
//! WHAT THE ANSWER STILL DOES NOT MEAN. Symbol presence is the weakest of the
//! three levels that decide whether a sensor exists on a host:
//! `make bpf` (clang accepts the C) < `bpftool prog loadall` (the verifier accepts
//! the bytecode and the BTF relocations) < attach, and then a bump landing in the
//! right map row. `--doctor` speaks only to the first rung, so its own output
//! carries the caveat rather than letting a green list read as a working sensor.

use std::collections::BTreeSet;
use std::io;
use std::io::Read;

use crate::config::page_size;
use crate::loader::{obj_fingerprint, obj_len};
use crate::net_vol::VolumeHook;

/// The kernel's own name for itself, which is what decides whether an fexit
/// target exists at all.
const OS_RELEASE: &str = "/proc/sys/kernel/osrelease";
/// CO-RE needs this; without it every program in the shipped object fails to
/// load, and the failure is the host's, not the operator's.
const BTF: &str = "/sys/kernel/btf/vmlinux";
/// The volume counters are keyed on a cgroup id. No v2 hierarchy, no key.
const CGROUP_V2: &str = "/sys/fs/cgroup/cgroup.controllers";
/// Every kernel symbol by name. Addresses are hidden from unprivileged readers
/// when `kptr_restrict` is 1 or 2, but the NAMES — which is all this needs — stay
/// readable while the file itself is (mode 0444 on the deployment host).
const KALLSYMS: &str = "/proc/kallsyms";
/// The list ftrace itself would accept a probe on. Authoritative for
/// attachability and root-readable only, so it is the fallback, not the source.
const FILTER_FUNCTIONS: &str = "/sys/kernel/tracing/available_filter_functions";

/// What one probe could say about one thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The file/symbol is there and was seen.
    Present,
    /// The probe looked and it genuinely is not there.
    Absent,
    /// The probe could not look. Reported as its own state on purpose: this is
    /// the one an operator must be able to tell apart from `Absent`, and a
    /// implementation that maps it to either of those publishes a lie about the
    /// host.
    Unreadable,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Present => "present",
            State::Absent => "ABSENT",
            State::Unreadable => "CANNOT TELL",
        }
    }

    /// Only an explicit `Absent` is a gap worth naming; `Unreadable` must not be
    /// summed into a count of missing things.
    pub fn is_absent(self) -> bool {
        self == State::Absent
    }

    /// The io error that means "this is not there" as opposed to "I was not
    /// allowed to know". Everything else — EACCES, EPERM, ELOOP, an EIO from a
    /// failing mount — is `Unreadable`.
    ///
    /// `pub(crate)` because `health.rs` classifies the same errno on the same
    /// axis: two commands that turned `Permission denied` into two different
    /// words would be the beginning of the drift this type exists to prevent.
    pub(crate) fn from_open_error(err: &io::Error) -> Self {
        if err.kind() == io::ErrorKind::NotFound {
            State::Absent
        } else {
            State::Unreadable
        }
    }
}

/// Present / Absent / Unreadable for one path, without reading its contents.
fn path_state(path: &str) -> State {
    match std::fs::File::open(path) {
        Ok(_) => State::Present,
        Err(err) => State::from_open_error(&err),
    }
}

/// Read a whole kernel file with a hard ceiling. These files are procfs/sysfs,
/// not disks: `/proc/kallsyms` is ~300k lines and a `read_to_string` on a
/// pathological sysfs file can block or balloon, so the ceiling is the reason
/// this is not a `fs::read_to_string`.
fn read_capped(path: &str, max_bytes: usize) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "symbol source exceeded the read ceiling",
            ));
        }
    }
    // Kernel files are not always valid UTF-8 at a boundary; a lossy read cannot
    // turn a symbol match into a false one, and it cannot hide one either.
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Exact-name match against a `/proc/kallsyms` body.
///
/// The exactness is the point. A substring search for `udp_recvmsg` matches
/// `udpv6_recvmsg`'s neighbourhood only by luck, but a *prefix* search matches
/// `tcp_sendmsg_locked`, and the `.cold` out-of-line fragments of
/// `bpf/warden.bpf.c`'s neighbours (`udp_sendmsg.cold`) are real lines in a real
/// file that would satisfy a sloppy check for a function the verifier would
/// refuse. Each line is `<address> <type> <name>`; the address may be all zeros
/// for an unprivileged reader, which is irrelevant here.
fn scan_kallsyms(body: &str, targets: &[&'static str]) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for line in body.lines() {
        if let Some(name) = line.split_whitespace().nth(2) {
            if let Ok(t) = targets.binary_search(&name) {
                found.insert(targets[t]);
            }
        }
    }
    found
}

/// The same for `available_filter_functions`, which is one bare name per line.
fn scan_filter_functions(body: &str, targets: &[&'static str]) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for line in body.lines() {
        // Some kernels append `[模块]`-style suffixes or a tab; the first field is
        // the function name.
        if let Some(name) = line.split_whitespace().next() {
            if let Ok(t) = targets.binary_search(&name) {
                found.insert(targets[t]);
            }
        }
    }
    found
}

/// Which symbol source the preflight actually used, so the report can say where
/// its own answer came from — and say nothing when neither was readable.
#[derive(Debug, Clone)]
struct SymbolSource {
    /// The path actually read, or "none".
    name: &'static str,
    found: BTreeSet<&'static str>,
    /// True for `available_filter_functions` and false for `/proc/kallsyms`,
    /// which lists a symbol but says nothing about ftrace attachability: a
    /// kallsyms name can be an inlined function with no ftrace record.
    authoritative_for_attach: bool,
}

/// Read the symbol sources in preference order: the authoritative list first, the
/// name list only if that one cannot be read.
///
/// The order is the whole point. `available_filter_functions` is the list ftrace
/// itself would accept a probe on, so a name missing from it is the strongest
/// userspace statement that `fexit/<name>` cannot attach — which is what an
/// operator running `--doctor` as root wants to hear. `/proc/kallsyms` answers a
/// weaker question (the symbol exists) and is world-readable, so it is the
/// fallback that lets an unprivileged run say anything at all. One capped read,
/// either way.
fn symbol_source(targets: &[&'static str]) -> SymbolSource {
    if let Ok(body) = read_capped(FILTER_FUNCTIONS, 16 * 1024 * 1024) {
        return SymbolSource {
            name: FILTER_FUNCTIONS,
            found: scan_filter_functions(&body, targets),
            authoritative_for_attach: true,
        };
    }
    if let Ok(body) = read_capped(KALLSYMS, 32 * 1024 * 1024) {
        return SymbolSource {
            name: KALLSYMS,
            found: scan_kallsyms(&body, targets),
            authoritative_for_attach: false,
        };
    }
    SymbolSource {
        name: "none",
        found: BTreeSet::new(),
        authoritative_for_attach: false,
    }
}

/// Every attach target this build cares about: one per volume hook, including
/// the two IPv6 datagram functions added in this revision. Sorted, because
/// `binary_search` is what forces the exact-name discipline above.
fn targets() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = VolumeHook::ALL.iter().map(|h| h.func()).collect();
    v.sort_unstable();
    v
}

fn kernel_release() -> String {
    std::fs::read_to_string(OS_RELEASE)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "CANNOT TELL".to_string())
}

/// What one signal-0 probe through `pidfd_send_signal` could say about one pid.
///
/// Four answers, and the distinction between the middle two is the reason this
/// type exists: `Denied` means the kernel reached a decision about delivering a
/// signal, `NoPidFd` means the probe never got that far. Collapsing them is the
/// same error `State` refuses to make between `Absent` and `Unreadable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalProbe {
    /// The permission check passed. With signal 0 nothing was delivered, so this
    /// says only that a real signal *would* have been accepted.
    Permitted,
    /// The check was reached and refused. EPERM/EACCES is the kernel's ownership
    /// decision; a seccomp filter configured with `SystemCallErrorNumber=EPERM`
    /// answers the same way, which is why the self probe is what tells them apart.
    Denied(i32),
    /// `pidfd_open` itself failed, so delivery was never asked about. ENOSYS here
    /// means a kernel older than 5.3; EACCES means the pid is not even visible.
    NoPidFd(i32),
    /// Nothing is at that pid (ESRCH, from either step).
    Gone,
}

impl SignalProbe {
    pub fn word(self) -> &'static str {
        match self {
            SignalProbe::Permitted => "permitted",
            SignalProbe::Denied(_) => "DENIED",
            SignalProbe::NoPidFd(_) => "NO PIDFD",
            SignalProbe::Gone => "no such pid",
        }
    }
}

/// The errno number as the operator would read it, because the bare integer in a
/// denial is the one part of this line they cannot act on.
fn errno_name(err: i32) -> &'static str {
    match err {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::ESRCH => "ESRCH",
        libc::ENOSYS => "ENOSYS",
        libc::EINVAL => "EINVAL",
        _ => "an errno this build has no name for",
    }
}

/// Ask whether a signal could be delivered to `pid`, using signal 0.
///
/// Signal 0 is the kernel's own idiom for this question: the permission check
/// runs in full and nothing is delivered. It is not a no-op probe of existence —
/// `pidfd_open` already answered that — it is a probe of *authority*, which is
/// the half W2K-38 found nothing in the agent's output said anything about.
fn probe_signal(pid: u32) -> SignalProbe {
    // SAFETY: pidfd_open(2) takes (pid, flags); 0 is the only valid flags value.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0) };
    if fd < 0 {
        // Read errno before anything else can clobber it, including close(2).
        let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return if err == libc::ESRCH {
            SignalProbe::Gone
        } else {
            SignalProbe::NoPidFd(err)
        };
    }
    let fd = fd as libc::c_int;
    // SAFETY: `fd` is the pidfd just opened and still open here; signal 0 with a
    // null siginfo and no flags is the documented permission check that delivers
    // nothing.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    // Same discipline as respond.rs: the errno belongs to the syscall that set it,
    // so it is captured before the close, not after.
    let err = if rc < 0 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    // SAFETY: we own `fd` and do not use it again.
    unsafe { libc::close(fd) };
    match rc {
        0.. => SignalProbe::Permitted,
        _ if err == libc::ESRCH => SignalProbe::Gone,
        _ => SignalProbe::Denied(err),
    }
}

/// The two probes read together. Neither answer alone is a verdict: the same EPERM
/// on pid 1 means "no privilege" or "no syscall" depending on what self said, and
/// that is the ambiguity this function exists to remove.
///
/// Deliberately worded so a non-root run cannot be misread as an indictment of the
/// service: `--doctor` answers for the process that ran it, which in CI, in a
/// shell, and in the unit's own context are three different capability sets.
fn delivery_verdict(me: SignalProbe, other: SignalProbe) -> String {
    match (me, other) {
        (SignalProbe::Denied(e), _) | (SignalProbe::NoPidFd(e), _) => format!(
            "REFUSED BEFORE PRIVILEGE: our own process was denied ({}) with errno {}. A process \
             may always check its own signal rights, so a denial here cannot be about ownership — \
             the syscall itself is being refused, by a seccomp SystemCallFilter (which answers \
             EPERM when SystemCallErrorNumber says so) or because the kernel predates pidfd. \
             Enforce mode delivers nothing at all under this filter, whatever the capabilities \
             say.",
            errno_name(e),
            e
        ),
        (SignalProbe::Permitted, SignalProbe::Denied(e)) => format!(
            "NO DELIVERY TO PROCESSES WE DO NOT OWN: self is permitted and pid 1 is denied ({} \
             with errno {}), which is the kernel's ownership check, not a filter. This process \
             could not signal an offender outside its own uid — an unprivileged agent would log a \
             kill it never sent. CAP_KILL (or root) is what changes this answer; whether it is \
             permitted for the daemon is decided by the unit, not by this run.",
            errno_name(e),
            e
        ),
        (SignalProbe::Permitted, SignalProbe::Permitted) => {
            "DELIVERY POSSIBLE ACROSS OWNERSHIP: both permitted, so this process holds the \
             privilege enforce mode needs. That is an answer about the process running --doctor, \
             and root in a shell is the common reason for it."
                .to_string()
        }
        (SignalProbe::Permitted, SignalProbe::Gone) => {
            "self is permitted but the other-owner control disappeared, so only half of the \
             question is answered: nothing is concluded about signalling a process we do not own."
                .to_string()
        }
        (SignalProbe::Permitted, SignalProbe::NoPidFd(e)) => format!(
            "self is permitted and pid 1 has no pidfd (errno {}), so the other-owner control is \
             unavailable and nothing is concluded about cross-ownership delivery.",
            errno_name(e)
        ),
        (SignalProbe::Gone, _) => {
            "our own pid reported as gone, which cannot happen while this process is running, so \
             no conclusion is drawn from either probe."
                .to_string()
        }
    }
}

/// The gap line for attach targets this build hooks and this kernel does not
/// export. `None` when nothing is ABSENT — and `CANNOT TELL` never contributes,
/// because an unreadable source is not a missing function.
///
/// The wording matters in both directions. A target that is genuinely absent is
/// not fatal: `Loaded::attach` attempts each fexit on its own, records the outcome
/// per hook, and starts anyway, and `net_vol::coverage_line` then names the missing
/// half on every run. Saying "Warden will refuse to start" would be the opposite
/// error to the one this module exists to prevent.
fn missing_target_line(attached: &[&'static str], states: &[State]) -> Option<String> {
    let missing: Vec<&'static str> = attached
        .iter()
        .zip(states.iter())
        .filter(|(_, s)| s.is_absent())
        .map(|(f, _)| *f)
        .collect();
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "warden: doctor: {} of the {} attached targets are ABSENT on this kernel ({}). That \
         half of the totals stays empty and Warden still starts: each fexit is attempted on its \
         own, the outcome is recorded per hook, and net_vol::coverage_line names what is missing \
         on every run — a one-sided counter with a loud caveat, not a zero that reads as quiet \
         traffic.",
        missing.len(),
        attached.len(),
        missing.join(", ")
    ))
}

/// W2K-43: the co-residency line, printed whether or not anything was found.
///
/// The startup path stays silent when it is the only agent, because a warning
/// that fires on every healthy boot teaches an operator to ignore the one that
/// matters. `--doctor` is a checklist, so it says what it counted instead —
/// including the count of one, which is the answer the operator came for.
///
/// This run is not in that count and must not be: `peer_instances` drops our
/// own pid, and an inspection mode is filtered out anyway, because a diagnostic
/// that loads nothing amplifies nothing. Naming it would turn every `--doctor`
/// beside a healthy daemon into a false two-instance warning.
///
/// `observer_is_agent` is a parameter rather than a read of our own command
/// line so that both answers — one peer seen by an inspector, one peer seen by
/// an agent — are testable on a host that holds neither. `report()` supplies it
/// from the real command line.
fn peer_line(peers: &[crate::procscan::PeerInstance], observer_is_agent: bool) -> String {
    if let Some(notice) = crate::procscan::peer_notice(peers, observer_is_agent) {
        return format!("warden: doctor: co-resident instances: {notice}");
    }
    let seen = if peers.is_empty() {
        "none found".to_string()
    } else {
        format!("{}: {}", peers.len(), crate::procscan::peer_listing(peers))
    };
    format!(
        "warden: doctor: co-resident instances: {seen}. No W2K-43 pair on this host as seen by \
         this reader: what makes the finding is two or more live agents, each enriching its \
         records from /proc while the other reports them, and an instance that loads nothing \
         and delivers nothing is not one of them. A process whose executable and command line \
         are both unreadable, like another user's on a hidepid= host, is not provable and is \
         not listed here; that is a limit of the reader, not a statement about the host. \
         Nothing in this line changes what any instance does."
    )
}

/// The report's own call: the line, with the observer kind read from this
/// process's command line.
///
/// Split out for the same reason `peer_line` takes the flag as data: the flag
/// has to be measured at the one place the report uses it, and that place is
/// only decidable by a test if it is a function. Passing a literal here would
/// make every `--doctor` beside a healthy daemon report a collision — which is
/// how a warning stops being read.
fn doctor_peer_line(peers: &[crate::procscan::PeerInstance]) -> String {
    peer_line(peers, crate::procscan::this_process_is_agent())
}

/// The report: one line per thing an operator would otherwise have to remember
/// to check by hand, and one last line about what the lines above are not.
pub fn report() -> Vec<String> {
    let targets = targets();
    let src = symbol_source(&targets);
    let page = page_size();
    let mut lines = Vec::new();

    lines.push(format!(
        "warden: doctor: build: warden {}, eBPF object {} bytes (fnv-1a {:016x}). The digest \
         names WHICH object is compiled in: {} bytes is a size, and a comment-only edit to \
         bpf/warden.bpf.c changes the object's bytes without changing its length, so the \
         length alone cannot tell a current build from a stale one.",
        env!("CARGO_PKG_VERSION"),
        obj_len(),
        obj_fingerprint(),
        obj_len()
    ));

    lines.push(format!(
        "warden: doctor: host: kernel {}, page {} bytes.",
        kernel_release(),
        page
    ));

    let btf = path_state(BTF);
    lines.push(format!(
        "warden: doctor: BTF ({}): {}. {}",
        BTF,
        btf.word(),
        match btf {
            State::Present =>
                "CO-RE relocations can resolve against it, which every program in the shipped \
                 object needs to LOAD.",
            State::Absent =>
                "without it every program in the shipped object fails to LOAD — that is a host \
                 fact, not a config mistake, and Warden's fix is a kernel with CONFIG_DEBUG_INFO_BTF.",
            State::Unreadable =>
                "the file exists but could not be read by this user, so nothing is concluded; \
                 re-run as root before treating any load failure below as a missing BTF.",
        }
    ));

    // M15: a symbol name in the ftrace list is only half of the fexit contract.
    // The other half is the kernel's own FUNC prototype: an fexit program whose
    // arguments disagree with it is rejected by the verifier, so --doctor now
    // reads the raw BTF and says which of the six this build can even attempt.
    lines.push(crate::btf_compat::doctor_line(
        &crate::btf_compat::check_all(crate::btf_compat::BTF_PATH),
    ));

    // The perf gate, read from the same world-readable files this module is
    // limited to. It is here because it is the one host fact that can stop
    // every sensor from existing, and it is invisible in the failure: an
    // attach refused by it surfaces as `Permission denied (os error 13)`.
    let gate = crate::loader::PerfGate::read();
    lines.push(format!(
        "warden: doctor: perf gate: kernel.perf_event_paranoid={}, this process holds \
         CAP_SYS_ADMIN={} ({}). {}",
        match gate.paranoid() {
            Some(p) => p.to_string(),
            None => "CANNOT TELL".to_string(),
        },
        match gate.holds_sys_admin() {
            Some(true) => "yes",
            Some(false) => "no",
            None => "CANNOT TELL",
        },
        // The answer belongs to the process that asked. The daemon's own set comes
        // from the unit, so an operator running this as a plain user must not read
        // a "no" as a verdict on the service — that is how a false negative gets
        // published, and this module exists to avoid exactly that.
        if gate.holds_sys_admin().is_some() {
            "measured for the user running --doctor"
        } else {
            "/proc/self/status could not be read, so nothing is concluded"
        },
        match (gate.paranoid(), gate.holds_sys_admin()) {
            (Some(p), Some(admin)) if p > 1 && !admin =>
                "REFUSED: above 1, the kernel gates perf_event_open() for tracepoints and kprobes \
                 on CAP_SYS_ADMIN specifically — CAP_BPF and CAP_PERFMON do not satisfy it — so the \
                 exec tracepoint and every security_* kprobe fail with EACCES and Warden attaches \
                 nothing. Grant CAP_SYS_ADMIN in the unit's AmbientCapabilities, or set the knob to \
                 1 host-wide (weaker: it opens kernel tracing to every unprivileged process). \
                 Loaded::attach refuses the start up front with this same sentence.",
            (Some(p), Some(true)) if p > 1 =>
                "above 1, so CAP_SYS_ADMIN is what lets the tracepoint and kprobe sensors attach \
                 here — a unit granting only CAP_BPF+CAP_PERFMON would fail at the first attach on \
                 this host, and this process is not that unit: read the service's own \
                 AmbientCapabilities before concluding anything about the daemon.",
            (Some(_), Some(_)) =>
                "at or below 1, so tracepoints and kprobes need only CAP_PERFMON here. Note that \
                 mainline's default is 2 and Debian's is 3: a host that reads 1 today may have \
                 been set there by a drop-in, and Warden's unit depends on that choice.",
            (Some(p), None) if p > 1 =>
                "above 1, so the sensors need CAP_SYS_ADMIN; whether this process has it is \
                 unknown, so no verdict is given.",
            (_, _) =>
                "one of the two facts could not be read, so nothing is concluded about this \
                 host's tracing privileges.",
        }
    ));

    // W2K-38: can enforcement actually DELIVER a signal? `pidfd_open` answering
    // successfully proves only that the process exists and is visible — measured
    // cross-uid, the open succeeds and `pidfd_send_signal` then returns EPERM. So
    // the question is asked with signal 0, which the kernel checks and does not
    // deliver, against two targets: our own pid (which any process may signal, so
    // a denial here can only mean the syscall itself is refused) and pid 1 (always
    // owned by another user, so a denial there is the permission check the daemon
    // would hit against an offender it does not own). The two answers together
    // distinguish a filter from a privilege gap — which the errno alone cannot.
    let self_probe = probe_signal(std::process::id());
    let init_probe = probe_signal(1);
    lines.push(format!(
        "warden: doctor: kill delivery: signal-0 to self={}, to pid 1={}. {} The measurement is \
         of the process running --doctor, not of the daemon: read the unit's User= and \
         AmbientCapabilities before treating any of this as a verdict on the service. Pid 1 is \
         used only as the other-owner control — Warden refuses to signal init on its own, so \
         nothing here proposes killing it.",
        self_probe.word(),
        init_probe.word(),
        delivery_verdict(self_probe, init_probe),
    ));

    // W2K-43: the sensor's own traffic, which is the largest producer of
    // `endpoint:self_tamper` this project has measured with no attacker. Two
    // agents on one host each enrich their records from /proc, so each one's
    // reads arrive at the other as activity at a protected pid, and both write
    // findings. The walk is the same one the protect policy uses; this run of
    // --doctor is left out of it because it loads nothing and delivers nothing.
    let peers = crate::procscan::peer_instances();
    lines.push(doctor_peer_line(&peers));

    let cgroup = path_state(CGROUP_V2);
    lines.push(format!(
        "warden: doctor: cgroup v2 ({}): {}. {}",
        CGROUP_V2,
        cgroup.word(),
        match cgroup {
            State::Present =>
                "The volume counters are keyed on a cgroup id, so the totals have a key to sit \
                 under on this host.",
            State::Absent =>
                "the volume counters are keyed on a cgroup id, and without the unified \
                 hierarchy there is no such key: the map would stay empty however much traffic \
                 moved.",
            State::Unreadable =>
                "nothing is concluded about the hierarchy; the volume totals are keyed on a \
                 cgroup id, so this is the one host fact that can turn a working counter into an \
                 empty map.",
        }
    ));

    // Phase 9: the resource envelope is a property of the service manager, not
    // of Warden's config, so this line reads the kernel's own cgroup controls
    // rather than repeating the declared [resources] values. It is placed beside
    // the other cgroup fact and before the "what this did NOT do" caveat: the
    // values belong to the process running --doctor, not necessarily the daemon.
    lines.push(crate::resources::doctor_line());

    let attached: Vec<&'static str> = VolumeHook::ALL.iter().map(|h| h.func()).collect();
    let attached_states: Vec<State> = attached.iter().map(|f| state_of(&src, f)).collect();
    let attached_report = attached
        .iter()
        .zip(attached_states.iter())
        .map(|(f, s)| format!("{f}={}", s.word()))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!(
        "warden: doctor: the {} volume fexit targets this build attaches: {}. Source: {}{}. \
         present here means attachable on this kernel — it does NOT mean counted: only a bump \
         in the right map row is a measurement.",
        attached.len(),
        attached_report,
        src.name,
        if src.authoritative_for_attach {
            " (the list ftrace itself accepts, so a name here is an attachable one)"
        } else {
            ", which lists names but not whether ftrace can take a probe on them — an ABSENT \
             here is worth re-running as root against available_filter_functions"
        }
    ));

    // Only an explicit ABSENT gets a line of its own. Extracted because no host
    // this tree has been run on produces it — every target so far was present —
    // and an untestable branch is how a gap-reporting line rots.
    if let Some(line) = missing_target_line(&attached, &attached_states) {
        lines.push(line);
    }

    if src.name == "none" {
        lines.push(
            "warden: doctor: no symbol source was readable, so the target line above says \
             CANNOT TELL and nothing has been concluded about this kernel. That is a different \
             answer from ABSENT and is deliberately not rounded up to one."
                .to_string(),
        );
    }

    lines.push(
        "warden: doctor: what this did NOT do: it loaded nothing, attached nothing, opened no \
         map and started nothing. Three levels decide whether a sensor exists — clang accepts \
         the C, the verifier accepts the bytecode and its BTF relocations, and attach plus a \
         bump in the right row — and only the last is a measurement. The live record for the \
         deployment kernel is §22/§23 of scripts/LIVE_VALIDATION.md; the policy lines above \
         came from the config file and these came from the kernel, and neither is a statement \
         about a Warden that is currently running."
            .to_string(),
    );
    lines
}

fn state_of(src: &SymbolSource, target: &str) -> State {
    if src.name == "none" {
        // Nothing was read. An empty set here would otherwise read as "every
        // symbol is missing", which is the false negative this type exists to
        // prevent.
        return State::Unreadable;
    }
    if src.found.contains(target) {
        State::Present
    } else {
        State::Absent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetVolume;
    use crate::net_vol::VolumeHooks;

    /// A kallsyms body shaped like the real file: address, type, name — with the
    /// three neighbours that make a substring check wrong.
    const FAKE_KALLSYMS: &str = "ffffffffa000 t tcp_sendmsg_locked\n\
                                  ffffffffa001 T tcp_sendmsg\n\
                                  ffffffffa002 T udp_sendmsg\n\
                                  0000000000000000 t udp_sendmsg.cold\n\
                                  0000000000000000 T tcp_cleanup_rbuf\n\
                                  0000000000000000 T udpv6_recvmsg\n\
                                  0000000000000000 T udpv6_sendmsg\n";

    fn t(targets: &[&'static str]) -> Vec<&'static str> {
        let mut v = targets.to_vec();
        v.sort_unstable();
        v
    }

    /// The §23 step-1 trap, as a test: a build that only has `udpv6_recvmsg` must
    /// not be told it can hook `udp_recvmsg`, and neither may a `.cold` fragment
    /// nor a `_locked` helper pass for the function the verifier was asked about.
    #[test]
    fn the_scan_matches_exact_names_and_no_neighbours() {
        let targets = t(&[
            "tcp_sendmsg",
            "tcp_cleanup_rbuf",
            "udp_sendmsg",
            "udp_recvmsg",
            "udpv6_sendmsg",
            "udpv6_recvmsg",
        ]);
        let found = scan_kallsyms(FAKE_KALLSYMS, &targets);
        assert!(found.contains("tcp_sendmsg"), "the bare name must match");
        assert!(
            !found.contains("udp_recvmsg"),
            "udpv6_recvmsg is a DIFFERENT function and must not satisfy udp_recvmsg"
        );
        assert!(found.contains("udpv6_recvmsg"));
        assert!(
            !found.contains("tcp_sendmsg_locked"),
            "not even requested, but a prefix match would have invented it"
        );
        // `udp_sendmsg` matches once, and its `.cold` line must not double-count:
        // a set, not a count.
        assert_eq!(found.len(), 5, "found {found:?}");
    }

    /// The other half of the kallsyms line format: an unprivileged reader sees
    /// zeroed addresses, which must not disturb matching.
    #[test]
    fn zeroed_addresses_from_kptr_restrict_still_match() {
        let targets = t(&["udp_recvmsg"]);
        let found = scan_kallsyms("0000000000000000 T udp_recvmsg\n", &targets);
        assert!(found.contains("udp_recvmsg"));
    }

    /// `available_filter_functions` is one name per line, and it is the source
    /// whose `Permission denied` once nearly became a published false negative.
    #[test]
    fn the_filter_function_scan_reads_the_first_field() {
        let targets = t(&["udp_recvmsg", "udpv6_recvmsg"]);
        let found = scan_filter_functions("udpv6_recvmsg\nudp_recvmsg\n", &targets);
        assert_eq!(found.len(), 2);
        let only_v6 = scan_filter_functions("udpv6_recvmsg\n", &targets);
        assert!(!only_v6.contains("udp_recvmsg"));
    }

    #[test]
    fn an_error_that_is_not_missing_is_not_reported_as_missing() {
        assert_eq!(
            State::from_open_error(&io::Error::from(io::ErrorKind::NotFound)),
            State::Absent
        );
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert_eq!(
                State::from_open_error(&io::Error::new(kind, "no")),
                State::Unreadable,
                "{kind:?} must never read as ABSENT"
            );
        }
        assert_eq!(
            State::from_open_error(&io::Error::from_raw_os_error(libc::EPERM)),
            State::Unreadable
        );
        assert!(!State::Unreadable.is_absent());
        assert!(State::Absent.is_absent());
    }

    /// The three words are the contract with the operator: `CANNOT TELL` is not a
    /// synonym for `ABSENT`, and only the second is shouted about.
    #[test]
    fn the_three_states_have_three_distinct_words() {
        assert_eq!(State::Present.word(), "present");
        assert_eq!(State::Absent.word(), "ABSENT");
        assert_eq!(State::Unreadable.word(), "CANNOT TELL");
    }

    #[test]
    fn the_target_list_is_every_hook_this_build_attaches() {
        let targets = targets();
        assert_eq!(
            targets.len(),
            6,
            "four original hooks + two IPv6 datagram hooks"
        );
        for h in VolumeHook::ALL {
            assert!(targets.contains(&h.func()));
        }
        // `binary_search` in the scanners silently returns "not found" for an
        // unsorted list, which would make every symbol look ABSENT.
        assert!(targets.is_sorted());
    }

    /// Drift guard, and the reason the two names are a constant instead of prose:
    /// the sentence the agent logs about IPv6 must name the same two functions
    /// this command probes.
    #[test]
    fn the_coverage_sentence_and_the_doctor_name_the_same_two_functions() {
        let policy: NetVolume = toml::from_str("enabled = true\n").unwrap();
        let mut hooks = VolumeHooks::default();
        for h in VolumeHook::ALL {
            hooks.attach(h);
        }
        let line = crate::net_vol::coverage_line(&policy, Some(&hooks));
        let report = report().join("\n");
        for h in VolumeHook::ALL
            .iter()
            .filter(|h| h.measures().starts_with("IPv6"))
        {
            let f = h.func();
            assert!(
                line.contains(f) && report.contains(f),
                "coverage_line and doctor must name the same attached v6 function {f}"
            );
        }
    }

    /// The ABSENT branch cannot be produced on a kernel that has every target, so
    /// it is exercised directly: one absent half must be named, all-present must
    /// stay silent, and `CANNOT TELL` must never be summed into a gap.
    #[test]
    fn the_gap_line_names_absent_targets_and_nothing_else() {
        let attached: Vec<&'static str> = VolumeHook::ALL.iter().map(|h| h.func()).collect();
        let all_present = vec![State::Present; attached.len()];
        assert_eq!(
            missing_target_line(&attached, &all_present),
            None,
            "a complete kernel gets no gap line"
        );
        let mut one_absent = all_present.clone();
        one_absent[1] = State::Absent;
        let one_missing = missing_target_line(&attached, &one_absent)
            .expect("an absent ingress half must be named");
        assert!(one_missing.contains("1 of the 6"));
        assert!(one_missing.contains("tcp_cleanup_rbuf"));
        assert!(
            !one_missing.contains("udp_recvmsg"),
            "a present target must not be listed as missing: {one_missing}"
        );
        // The sentence that keeps this from reading as a fatal condition.
        assert!(one_missing.contains("Warden still starts"));
        assert_eq!(
            missing_target_line(&attached, &[State::Unreadable; 6]),
            None,
            "CANNOT TELL is not a gap; reporting six missing functions because a file was \
             mode 0440 is the false negative this module was written against"
        );
        assert_eq!(
            missing_target_line(&attached, &[State::Absent; 6])
                .expect("all six absent")
                .matches("ABSENT")
                .count(),
            1,
            "the word belongs to the summary, not to six repetitions"
        );
    }

    #[test]
    fn every_line_is_prefixed_and_the_caveat_is_always_printed() {
        let lines = report();
        assert!(lines.len() >= 6, "got {}", lines.len());
        for l in &lines {
            assert!(l.starts_with("warden: doctor: "), "bad prefix: {l}");
            assert!(!l.contains('\n'), "a report line must stay one line: {l}");
        }
        let joined = lines.join("\n");
        // The two claims that make this command safe to trust as a preflight.
        assert!(joined.contains("loaded nothing, attached nothing"));
        assert!(joined.contains("does NOT mean counted"));
        assert!(joined.contains("fnv-1a"));
        for h in VolumeHook::ALL {
            assert!(joined.contains(h.func()), "doctor omitted {}", h.func());
        }
    }

    /// The report must not be able to say `ABSENT` while admitting it read
    /// nothing: `state_of` returns `Unreadable` for the "none" source even though
    /// its set is empty, which is exactly the shape an absent-only
    /// implementation would get wrong.
    #[test]
    fn an_empty_source_set_is_cannot_tell_never_absent() {
        let src = SymbolSource {
            name: "none",
            found: BTreeSet::new(),
            authoritative_for_attach: false,
        };
        assert_eq!(state_of(&src, "udp_recvmsg"), State::Unreadable);
        assert!(
            !report()
                .iter()
                .any(|l| l.contains("are ABSENT on this kernel")),
            "with no readable source nothing may be called absent: {:?}",
            report()
        );
        let readable = SymbolSource {
            name: KALLSYMS,
            found: BTreeSet::new(),
            authoritative_for_attach: false,
        };
        assert_eq!(state_of(&readable, "udp_recvmsg"), State::Absent);
    }

    /// W2K-38: the self probe is the only probe whose result is fixed for every
    /// user, so it is the only one a test may assert on. A process checking its
    /// own signal rights cannot be denied by ownership — a denial there means the
    /// syscall is filtered, which is a property of the sandbox the tests run in,
    /// not of Warden. Pid 1 is deliberately absent from this assertion: the honest
    /// answer depends on the uid of whoever runs `cargo test`, and a test that
    /// guessed it would be the false negative this module was written against.
    #[test]
    fn a_process_may_always_ask_about_its_own_signals() {
        assert_eq!(
            probe_signal(std::process::id()),
            SignalProbe::Permitted,
            "signal 0 to our own pid must be permitted; if this fails, the kernel has no pidfd \
             or the test harness filters pidfd_send_signal, and the kill-delivery line in \
             --doctor is describing that sandbox rather than a deployment"
        );
    }

    /// The four words are the contract with the operator, on the same axis as
    /// `State::word`: "DENIED" and "NO PIDFD" must not be synonyms, because one is
    /// a decision about delivery and the other means the question was never asked.
    #[test]
    fn the_probe_states_have_four_distinct_words() {
        assert_eq!(SignalProbe::Permitted.word(), "permitted");
        assert_eq!(SignalProbe::Denied(libc::EPERM).word(), "DENIED");
        assert_eq!(SignalProbe::NoPidFd(libc::ENOSYS).word(), "NO PIDFD");
        assert_eq!(SignalProbe::Gone.word(), "no such pid");
        assert_eq!(errno_name(libc::EPERM), "EPERM");
        assert_eq!(errno_name(libc::EACCES), "EACCES");
        assert_eq!(errno_name(libc::ENOSYS), "ENOSYS");
        assert!(errno_name(4242).contains("no name"));
    }

    /// The whole point of probing two pids: the same EPERM means two different
    /// things, and which one it means is decided by what self said. A verdict that
    /// let a filtered syscall read as "grant CAP_KILL", or the reverse, would send
    /// an operator to edit the wrong file.
    #[test]
    fn the_self_answer_decides_what_the_pid_1_denial_means() {
        let denied_by_filter = delivery_verdict(
            SignalProbe::Denied(libc::EPERM),
            SignalProbe::Denied(libc::EPERM),
        );
        assert!(denied_by_filter.contains("REFUSED BEFORE PRIVILEGE"));
        assert!(denied_by_filter.contains("seccomp"));
        assert!(
            !denied_by_filter.contains("CAP_KILL"),
            "a filtered syscall is not a privilege gap: {denied_by_filter}"
        );
        // The same denial, when self was permitted, IS a privilege statement.
        let no_privilege =
            delivery_verdict(SignalProbe::Permitted, SignalProbe::Denied(libc::EPERM));
        assert!(no_privilege.contains("NO DELIVERY TO PROCESSES WE DO NOT OWN"));
        assert!(no_privilege.contains("CAP_KILL"));
        // A failed pidfd_open on our own pid is the filter case too, and says so.
        let no_pidfd = delivery_verdict(SignalProbe::NoPidFd(libc::ENOSYS), SignalProbe::Gone);
        assert!(no_pidfd.contains("REFUSED BEFORE PRIVILEGE"));
        assert!(no_pidfd.contains("ENOSYS"));
        // Both permitted: the run has privilege, and the sentence refuses to
        // generalise that to the daemon.
        let both = delivery_verdict(SignalProbe::Permitted, SignalProbe::Permitted);
        assert!(both.contains("DELIVERY POSSIBLE ACROSS OWNERSHIP"));
        assert!(both.contains("process running --doctor"));
    }

    /// A vanished control is not a denial, and must not be reported as one. Same
    /// for the impossible "our own pid is gone": the line says nothing rather than
    /// saying something wrong.
    #[test]
    fn an_unavailable_control_concludes_nothing() {
        let gone = delivery_verdict(SignalProbe::Permitted, SignalProbe::Gone);
        assert!(gone.contains("nothing is concluded"));
        assert!(
            !gone.contains("DENIED"),
            "a disappeared pid 1 is not a permission verdict: {gone}"
        );
        let no_pidfd_control =
            delivery_verdict(SignalProbe::Permitted, SignalProbe::NoPidFd(libc::EACCES));
        assert!(no_pidfd_control.contains("nothing is concluded"));
        let impossible = delivery_verdict(SignalProbe::Gone, SignalProbe::Denied(libc::EPERM));
        assert!(impossible.contains("no conclusion"));
    }

    /// The line exists in the shipped report, carries both probes, and never
    /// claims to have delivered anything — signal 0 does not deliver.
    #[test]
    fn the_kill_delivery_line_is_in_the_report_and_claims_nothing_more() {
        let lines = report();
        let line = lines
            .iter()
            .find(|l| l.contains("kill delivery:"))
            .expect("--doctor must answer the delivery question");
        assert!(line.contains("signal-0 to self=permitted"), "{line}");
        assert!(line.contains("to pid 1="), "{line}");
        assert!(
            !line.contains("killed") && !line.contains("delivered a signal"),
            "signal 0 delivers nothing; the line must not imply otherwise: {line}"
        );
        assert!(!line.contains('\n'));
    }

    // ── W2K-43: the co-residency line ───────────────────────────────────────

    fn peer(pid: u32, basis: crate::procscan::PeerBasis) -> crate::procscan::PeerInstance {
        crate::procscan::PeerInstance {
            pid,
            exe: Some("/usr/local/sbin/warden".into()),
            comm: Some("warden".into()),
            basis,
        }
    }

    /// One daemon beside one `--doctor` run is the healthy host, and the line
    /// must not be worded as a collision. This is the false warning that would
    /// otherwise fire on every diagnostic an operator ever runs next to a
    /// running agent — and a warning that always fires is a warning that is
    /// never read.
    #[test]
    fn one_agent_beside_the_doctor_run_is_reported_as_healthy() {
        let line = peer_line(
            &[peer(945, crate::procscan::PeerBasis::SameExecutable)],
            false,
        );
        assert!(
            line.starts_with("warden: doctor: co-resident instances: 1:"),
            "{line}"
        );
        assert!(line.contains("pid 945"), "{line}");
        assert!(line.contains("No W2K-43 pair"), "{line}");
        assert!(!line.contains("are live on this host"), "{line}");
        assert!(!line.contains('\n'));
    }

    /// The same scan, seen by an agent: one peer means two instances, and that
    /// is the finding. The count is what differs between the two lines above
    /// and below, and it is the number an operator acts on.
    #[test]
    fn the_same_single_peer_seen_by_an_agent_is_a_pair() {
        let peers = [peer(945, crate::procscan::PeerBasis::SameExecutable)];
        assert!(peer_line(&peers, false).contains("No W2K-43 pair"));
        assert!(peer_line(&peers, true).contains("2 Warden instances are live"));
    }

    /// With nothing found the line still answers, and still does not claim a
    /// pair — but it must not claim the host is empty either: the reader's
    /// limits are stated, not smoothed over.
    #[test]
    fn an_empty_scan_says_none_found_and_not_none_exist() {
        let line = peer_line(&[], false);
        assert!(
            line.starts_with("warden: doctor: co-resident instances: none found"),
            "{line}"
        );
        assert!(line.contains("as seen by this reader"), "{line}");
        assert!(line.contains("not provable"), "{line}");
        assert!(!line.contains("are live on this host"), "{line}");
    }

    /// Two agents is the finding, and the doctor line then carries the same
    /// sentence the startup warning writes — same evidence, same words.
    #[test]
    fn two_agents_get_the_startup_sentence() {
        let peers = [
            peer(945, crate::procscan::PeerBasis::SameExecutable),
            peer(3122, crate::procscan::PeerBasis::SameNameOnly),
        ];
        let line = peer_line(&peers, false);
        assert!(
            line.starts_with("warden: doctor: co-resident instances: 2 Warden instances"),
            "{line}"
        );
        assert!(line.contains("dev/ino match"), "{line}");
        assert!(line.contains("identity NOT verified"), "{line}");
        assert!(line.contains("operator's call"), "{line}");
        assert_eq!(
            line,
            format!(
                "warden: doctor: co-resident instances: {}",
                crate::procscan::peer_notice(&peers, false).expect("two agents")
            )
        );
    }

    /// The line is in the report, prefixed like every other doctor line, and
    /// `report()` is the only place that decides it is printed at all.
    #[test]
    fn the_report_carries_the_co_residency_line() {
        let lines = report();
        let line = lines
            .iter()
            .find(|l| l.contains("co-resident instances:"))
            .expect("--doctor must answer the co-residency question");
        assert!(!line.contains('\n'));
        assert!(line.starts_with("warden: doctor: "), "{line}");
    }

    /// The observer's kind is read from the command line at the seam `report()`
    /// uses — not hardcoded there, and not re-derived in the test. In this
    /// process it reads as an agent, because the test harness carries none of
    /// Warden's inspection flags, so one peer through that seam is a pair.
    ///
    /// The mutation this pins is `peer_line(peers, false)` inside
    /// `doctor_peer_line`: a literal at the report's own call site would make
    /// every `--doctor` beside a healthy daemon claim a collision, which is how
    /// this warning would stop being read.
    #[test]
    fn the_observer_kind_comes_from_the_command_line() {
        assert!(
            crate::procscan::this_process_is_agent(),
            "a test binary is not one of the ask-and-exit modes"
        );
        let peers = [peer(945, crate::procscan::PeerBasis::SameExecutable)];
        assert_eq!(
            doctor_peer_line(&peers),
            peer_line(&peers, true),
            "the report seam must count this process as an agent"
        );
        assert_ne!(
            doctor_peer_line(&peers),
            peer_line(&peers, false),
            "an inspector's answer is a different sentence, and the seam must not produce it"
        );
    }
}
