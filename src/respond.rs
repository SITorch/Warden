//! respond.rs — the local responder. The last resort: when policy says a
//! finding is bad enough *and* the operator has opted into enforcement, Warden
//! can kill the offending process itself.
//!
//! This is the riskiest thing the daemon does — a bad kill is self-inflicted
//! downtime — so it is gated three ways and defaults off:
//!
//!   1. global `mode = enforce` (observe never kills),
//!   2. the specific `respond.kill_*` toggle for this finding class,
//!   3. `Finding.wants_kill`, which the detector already set from (2).
//!
//! A fourth gate is not about permission but about proof: `act` will not signal
//! a process it cannot anchor to the event that named it. `require_anchored_identity`
//! (W2K-25) controls only the narrow case where the event recorded no identity
//! while `/proc` is readable now; the two cases where `/proc` cannot be read at
//! all are refused outright as `Unverifiable` (W2K-37).
//!
//! main wires these together; this module only executes an authorized kill and
//! refuses obviously-suicidal targets (pid 1, our own pid, a protected pid).

use crate::config::Mode;
use crate::detect::Finding;
use crate::events::{identity_of, ProcIdentity};
use crate::procscan::Protected;

/// Why a kill was or wasn't performed — surfaced in the log line and shipped to
/// Sentinel as the envelope's `action` key, so every enforcement decision is
/// auditable from the platform rather than only from this box. `Action::as_str`
/// is the one mapping both surfaces read (W2K-27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Observe mode, or the responder for this class is disabled: reported only.
    Observed,
    /// Enforcement fired: SIGKILL delivered to the actor.
    Killed,
    /// Enforcement was requested but the target was refused (self/init/protected).
    Refused,
    /// Enforcement was requested, but between the event and here the pid was
    /// reused: it now names a different process. Nothing was signalled (W-R3).
    IdentityChanged,
    /// Enforcement fired but the kill(2) failed (already gone, or EPERM).
    Failed,
    /// Enforcement was requested and the target may well be alive, but its
    /// identity could not be read (`hidepid=`, a ptrace rule, an unparseable
    /// stat). Nothing was signalled: a pid we cannot name is not a pid we may
    /// kill. This is a coverage gap and is reported as one (W2K-37) — the
    /// previous shape logged it as "the process had already exited", which made
    /// a blind agent look like a lucky one.
    Unverifiable,
    /// Enforcement was requested, `/proc` is readable now, but the event
    /// recorded no start time — so there is nothing to compare the live process
    /// against. The signal was withheld under spec 4.2 item 7 ("no unproven
    /// signal"), unless the operator opted into it with
    /// `respond.require_anchored_identity = false` (W2K-25).
    ///
    /// Deliberately not folded into `Refused`: that word means "this pid is
    /// protected, self, or init", which is a decision we are glad to repeat.
    /// This word means "we could not name the target", and an operator reading a
    /// monitor built on `refused` would be told the wrong thing.
    Unproven,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Observed => "observed",
            Action::Killed => "killed",
            Action::Refused => "refused",
            Action::IdentityChanged => "identity-changed",
            Action::Failed => "failed",
            Action::Unverifiable => "unverifiable",
            Action::Unproven => "unproven",
        }
    }
}

pub struct Responder {
    mode: Mode,
    /// W2K-25 — refuse to signal a target the event cannot anchor. Comes from
    /// `respond.require_anchored_identity`; see that field for the trade.
    require_anchored_identity: bool,
}

impl Responder {
    pub fn new(mode: Mode, require_anchored_identity: bool) -> Self {
        Self {
            mode,
            require_anchored_identity,
        }
    }

    /// The mode this responder was built with. The field stays private; this is
    /// here so the reload path in `main.rs` can tell whether the operator
    /// actually changed the mode (W-04) instead of guessing.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The identity policy in force. Like `mode()`, only so the reload path can
    /// report what actually moved: `mode` and this knob are rebuilt together, and
    /// a reload that changed only this knob must not be logged as "mode X → X".
    pub fn requires_anchored_identity(&self) -> bool {
        self.require_anchored_identity
    }

    /// Decide and act on one finding. `protected` is the current protected set,
    /// so we never kill a process we're supposed to be guarding (an attacker
    /// spoofing a protected comm can't turn us into their weapon).
    pub fn act(&self, f: &Finding, protected: &Protected) -> Action {
        // Gate 1+2 already folded into wants_kill by the detector; gate on mode.
        if self.mode != Mode::Enforce || !f.wants_kill {
            return Action::Observed;
        }

        let pid = f.process.pid;

        // Never kill init, never kill ourselves.
        if pid <= 1 || pid == std::process::id() {
            log::warn!(
                "refusing to kill pid {} ({}): self/init",
                pid,
                f.process.comm
            );
            return Action::Refused;
        }

        // W-R3 / W2K-24: a pid is a number the kernel reuses, so "pid 4711" does
        // not name one process for all time. Open the pidfd FIRST — the handle is
        // bound to the process, not the number — and only then read the identity
        // that decides everything below. The order is the whole fix: reading
        // first and pinning second leaves a window in which the number changes
        // hands between the two, and the handle then pins (and we signal) the
        // impostor while the check has just been satisfied about the original.
        //
        // Measured (report §۷۰-۱۰): the window the old order left is ~4.0 µs wide,
        // and pid numbers are not reused until `pid_max` (4194304) wraps, so the
        // likelihood is low — but the fix costs nothing and the comment here has
        // always claimed this order.
        let pidfd = open_pidfd(pid);
        let fallback_reason = match &pidfd {
            Ok(_) => None,
            // ESRCH is the kernel's own, race-free answer that nothing is there.
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => None,
            Err(err) => Some(err.raw_os_error().unwrap_or(0)),
        };

        // The identity of the process the handle pins, read after the pin. The
        // same one reading feeds both decisions below: whether the pid is still a
        // process we protect, and whether it is still the process the event named.
        let live = identity_of(pid);

        // W-R4: membership in the protected set is not a bare pid match. The set
        // records the start time each protected process had when the policy was
        // resolved, so a number the kernel has since handed to a different
        // process does not inherit immunity — which is what a recycled pid would
        // otherwise do, for up to one PROTECT_REFRESH, and the attacker it would
        // shield is precisely the one this responder exists to stop.
        //
        // This runs before the ESRCH answer is reported, on purpose: "I refused
        // to touch it because you protect it" is the operator-meaningful fact, and
        // it stays true whether or not the process is still there.
        if protected.immune(pid, live.as_starttime()) {
            log::warn!(
                "refusing to kill pid {} ({}): protected",
                pid,
                f.process.comm
            );
            close_pidfd(pidfd);
            return Action::Refused;
        }

        // Nothing to signal, and said accurately: the earlier shape reached this
        // only through the /proc read below and described every failure to read
        // /proc as an exited process. pidfd_open's ESRCH is the race-free version
        // of that answer, so it is preferred when we have it.
        if let Err(err) = &pidfd {
            if err.raw_os_error() == Some(libc::ESRCH) {
                log::warn!(
                    "kill(pid {pid}) skipped: pidfd_open reported ESRCH, so nothing is at that \
                     number now ({} was the actor)",
                    f.process.comm
                );
                return Action::Failed;
            }
        }

        // W2K-39: `ENOENT` from /proc means "not there" only if /proc can see the
        // process at all. Under `hidepid=2` another user's `/proc/<pid>` is not
        // merely unreadable, it is *absent*, so the same answer a real exit gives
        // also means "alive and hidden from us". A live offender reported as
        // "already exited" is the exact silent coverage gap W2K-37 was filed
        // against, only relocated: this is why the handle, which no mount option
        // can hide, is asked before `/proc` is allowed to have the last word.
        //
        // The probe costs one syscall and only runs on the arm where it changes
        // the answer.
        let pin = match &pidfd {
            Ok(fd) if live == ProcIdentity::Gone => probe_pin(*fd),
            _ => PinLife::NotAsked,
        };

        match identity_outcome(f.process.starttime, live, pin_corroborates_exit(live, pin)) {
            IdentityOutcome::Match => {}
            IdentityOutcome::Recycled => {
                log::error!(
                    "refusing to kill pid {pid} ({}): the pid has been recycled — the process \
                     that holds the number now started at {}, not at the start time recorded \
                     at event time",
                    f.process.comm,
                    live.explain()
                );
                close_pidfd(pidfd);
                return Action::IdentityChanged;
            }
            // Nothing at that pid now, and the proof is stated in `Exited`'s own
            // terms: either the handle confirms the `ENOENT`, or there was no
            // handle to ask and the exit is assumed rather than shown.
            IdentityOutcome::Exited => {
                log::warn!(
                    "kill(pid {pid}) skipped: the process ({}) had already exited before \
                     enforcement reached it ({}).",
                    f.process.comm,
                    match pin {
                        PinLife::Dead =>
                            "pidfd_open pinned it and signal 0 on that handle now \
                                          answers ESRCH, so the exit is proven by the kernel",
                        _ => "/proc answered ENOENT and no pidfd exists to corroborate it",
                    }
                );
                close_pidfd(pidfd);
                return Action::Failed;
            }
            // W2K-37: /proc could not be read by this user, so the pid may be
            // live and may be the attacker — and we cannot say which. Not
            // killing is the only defensible half; saying so loudly is the other.
            // An operator who sees this on a live host has a coverage gap to fix
            // (run the agent with the privilege to read the target's /proc, or
            // stop mounting /proc hidepid= over it), not a threat that expired.
            IdentityOutcome::Unverifiable => {
                log::error!(
                    "ENFORCEMENT NOT DELIVERED: kill(pid {pid}) ({}) was requested but the \
                     target's identity could not be read — {}. {} Refusing to signal a process \
                     we cannot name; this finding is a COVERAGE GAP, not a neutralised threat.",
                    f.process.comm,
                    live.explain(),
                    unverifiable_reason(live, pin, pidfd.is_ok())
                );
                close_pidfd(pidfd);
                return Action::Unverifiable;
            }
            // /proc was unreadable when the event was judged, so there is
            // nothing to compare against — but /proc IS readable now, which is
            // how this differs from `Unverifiable` above.
            //
            // W2K-25: this arm used to fall through and signal anyway, and
            // §۷۰-۱۰ T2 measured it doing exactly that to a live process
            // (`Action::Killed`, `signal=Some(9)`) with no anchor behind the
            // decision. Spec 4.2 item 7 forbids an unproven signal, so the
            // default now withholds it; the operator can opt back in, and then
            // the log says so in as many words instead of hiding it.
            IdentityOutcome::Unproven => {
                if self.require_anchored_identity {
                    log::error!(
                        "ENFORCEMENT WITHHELD: kill(pid {pid}) ({}) was requested, but the event \
                         recorded no start time — /proc was unreadable when the finding was \
                         enriched and is readable only now. Nothing proves the process behind \
                         this number is the one the finding named, and spec 4.2 item 7 forbids \
                         signalling a process we cannot anchor. No signal was sent. \
                         respond.require_anchored_identity = false opts back into killing anyway.",
                        f.process.comm
                    );
                    close_pidfd(pidfd);
                    return Action::Unproven;
                }
                log::warn!(
                    "pid {pid} ({}) cannot be identity-checked: /proc was unreadable at event \
                     time, so this signal cannot be proven to reach the process the event named. \
                     Sending it anyway because respond.require_anchored_identity = false.",
                    f.process.comm
                );
            }
        }

        if let Some(errno) = fallback_reason {
            log::warn!(
                "no pidfd for pid {pid}: pidfd_open failed with {} — the signal goes through \
                 kill(2) instead, so the identity verified above is the only thing separating \
                 this decision from the process that holds the number when the syscall runs",
                std::io::Error::from_raw_os_error(errno)
            );
        }

        let (result, mechanism) = kill_via(pidfd, pid);
        match result {
            Ok(()) => {
                log::warn!(
                    "ENFORCED: SIGKILL → pid {} ({}) via {mechanism} [{}]",
                    pid,
                    f.process.comm,
                    f.summary
                );
                Action::Killed
            }
            Err(err) => {
                log::error!("kill(pid {pid}) via {mechanism} failed: {err}");
                Action::Failed
            }
        }
    }
}

/// Open a pidfd for `pid` — an immutable handle to one specific process.
///
/// W2K-26: the `errno` is returned, not dropped. The three ways this fails mean
/// three different things, and the caller has to act on the difference:
///
///  - `ESRCH` — nothing is at that number. The kernel's own, race-free answer,
///    better than a `/proc` read, and it ends the decision there.
///  - `ENOSYS` — pre-5.3 kernel, no pidfd support at all.
///  - `EPERM`/`EACCES` — a seccomp filter or capability set that refuses the
///    syscall. Under the shipped unit this does not happen
///    (`SystemCallFilter=@system-service` permits `pidfd_open`), but a stricter
///    operator profile turns it into a silent downgrade to `kill(2)`, and the
///    log must say so.
///
/// The last two both fall through to `kill(2)`, which is why the caller logs the
/// downgrade rather than treating it as routine.
fn open_pidfd(pid: u32) -> Result<libc::c_int, std::io::Error> {
    // SAFETY: pidfd_open(2) takes (pid, flags); 0 is the only valid flags value.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0) };
    if fd < 0 {
        // Read errno immediately: any later call may clobber it.
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as libc::c_int)
    }
}

/// The identity decision on its own, so the whole table is testable without a
/// live process to recycle. `act` turns each outcome into one log line and one
/// [`Action`]; nothing else may re-derive it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityOutcome {
    /// The start times agree: the pid still names the process the event named.
    Match,
    /// The event recorded no start time, so agreement can be shown neither way.
    /// Enforcement proceeds, logged as unproven.
    Unproven,
    /// Nothing is at that pid — the `ESRCH` pidfd path, or an `ENOENT` from
    /// `/proc` that the handle corroborates (W2K-39).
    Exited,
    /// The number was reused. Signalling it would hit an unrelated process.
    Recycled,
    /// `/proc` refused the read, the read did not parse, or `/proc` answered
    /// `ENOENT` while the handle we hold says the process is alive: the target
    /// may be live and may be the attacker, and no signal is delivered (W2K-37).
    Unverifiable,
}

/// What the handle — never `/proc` — says about whether the process it pins is
/// still running.
///
/// The reason this exists apart from [`ProcIdentity`]: `hidepid=2` makes another
/// user's `/proc/<pid>` answer `ENOENT`, which is the same answer a real exit
/// gives, and a handle cannot be hidden by a mount option. W2K-39.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinLife {
    /// We never opened a handle, so there is nothing to ask.
    NotAsked,
    /// The pinned process is still a task in the kernel.
    Alive,
    /// The pinned process is gone.
    Dead,
    /// The question itself failed (an errno this build has no branch for).
    Unknown(i32),
}

/// Ask the pinned process whether it is still there, with signal 0.
///
/// Signal 0 delivers nothing; the kernel still resolves the task, checks
/// ownership, and reports the difference. The order is what makes this useful:
/// `pidfd_send_signal` reaches `pid_task()` before it consults credentials, so
/// `ESRCH` means the process this handle pins has gone, while `EPERM`/`EACCES`
/// means it is alive and merely not ours to signal. Both answers come from the
/// kernel's process table, which is the one thing a `hidepid=` mount cannot
/// conceal.
fn probe_pin(pidfd: libc::c_int) -> PinLife {
    // SAFETY: `fd` is a live pidfd owned by the caller; signal 0 with a null
    // siginfo is the standard permission-and-existence probe and delivers nothing.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if rc == 0 {
        return PinLife::Alive;
    }
    // Read errno before anything else can clobber it.
    let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    match err {
        libc::ESRCH => PinLife::Dead,
        libc::EPERM | libc::EACCES => PinLife::Alive,
        _ => PinLife::Unknown(err),
    }
}

/// The half of the identity decision that only the handle can supply: whether an
/// `ENOENT` from `/proc` is evidence of an exit or evidence of a mount option.
///
/// `NotAsked` accepts the exit. There the kernel refused `pidfd_open` for a
/// non-`ESRCH` reason, and the targets `hidepid=` conceals are exactly the ones
/// belonging to *other* uids — which a same-uid agent could not signal anyway.
/// Accepting `ENOENT` there keeps a genuinely dead offender from raising an
/// alarm on every run; the log line still says the proof is uncorroborated.
fn pin_corroborates_exit(live: ProcIdentity, pin: PinLife) -> bool {
    matches!(
        (live, pin),
        (ProcIdentity::Gone, PinLife::Dead) | (ProcIdentity::Gone, PinLife::NotAsked)
    )
}

fn identity_outcome(
    recorded: Option<u64>,
    live: ProcIdentity,
    corroborated: bool,
) -> IdentityOutcome {
    match (recorded, live) {
        (Some(r), ProcIdentity::Known(l)) if l == r => IdentityOutcome::Match,
        (Some(_), ProcIdentity::Known(_)) => IdentityOutcome::Recycled,
        (None, ProcIdentity::Known(_)) => IdentityOutcome::Unproven,
        // `ENOENT` alone is not an exit: only a handle that says so, or the
        // absence of a handle to ask, turns it into `Exited` (W2K-39).
        (_, ProcIdentity::Gone) if corroborated => IdentityOutcome::Exited,
        (_, ProcIdentity::Gone) | (_, ProcIdentity::Hidden(_)) | (_, ProcIdentity::Malformed) => {
            IdentityOutcome::Unverifiable
        }
    }
}

/// Why a refusal happened, in the operator's terms. The shapes of
/// `Unverifiable` need different fixes, and one sentence cannot tell the
/// operator which file to edit.
fn unverifiable_reason(live: ProcIdentity, pin: PinLife, has_pidfd: bool) -> &'static str {
    if live == ProcIdentity::Gone {
        return if has_pidfd {
            match pin {
                PinLife::Alive => {
                    "/proc does not show a process the kernel still has a live handle for, which \
                     is what a hidepid= mount over /proc does to another user's processes: the \
                     target is ALIVE and unnamed, so the mount is the thing to fix, not the \
                     finding."
                }
                _ => {
                    "/proc answered ENOENT and the handle could not settle it, so the target's \
                     liveness is unknown."
                }
            }
        } else {
            "/proc answered ENOENT and no pidfd existed to corroborate it, so the exit is \
             assumed rather than proven."
        };
    }
    "the identity could not be read from /proc."
}

/// Release the handle on every path that decides not to signal.
fn close_pidfd(pidfd: Result<libc::c_int, std::io::Error>) {
    if let Ok(fd) = pidfd {
        // SAFETY: `fd` came from pidfd_open, is owned by us, and is not used again.
        unsafe { libc::close(fd) };
    }
}

/// Deliver SIGKILL, through the pidfd when we have one and `kill(2)` when we do
/// not. Returns the result and which mechanism ran, so the log records it.
fn kill_via(
    pidfd: Result<libc::c_int, std::io::Error>,
    pid: u32,
) -> (std::io::Result<()>, &'static str) {
    if let Ok(fd) = pidfd {
        // SAFETY: `fd` came from pidfd_open and is still open; a null siginfo
        // is the documented way to send a bare signal.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        // Read errno before `close`, which may clobber it.
        let err = std::io::Error::last_os_error();
        // SAFETY: `fd` is owned by us and not used again.
        unsafe { libc::close(fd) };
        return (if rc == 0 { Ok(()) } else { Err(err) }, "pidfd_send_signal");
    }

    // No pidfd: the identity check above still ran, so this is the same
    // decision on a kernel whose pidfd support is missing. The remaining window
    // between the check and this call is what pidfd exists to close.
    // SAFETY: kill(2) is a straightforward syscall; the pid may have exited.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    (
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        },
        "kill(2)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{FindingType, ProcessInfo, Severity};
    use crate::events::starttime_of;

    fn finding(pid: u32, wants_kill: bool) -> Finding {
        finding_with_starttime(pid, wants_kill, None)
    }

    /// Build a finding whose process identity is `starttime`. `None` models a
    /// host where /proc was unreadable at event time (the unverified path).
    fn finding_with_starttime(pid: u32, wants_kill: bool, starttime: Option<u64>) -> Finding {
        Finding {
            source_ts_ns: 0,
            event_type: FindingType::ProcessCreation,
            severity: Severity::High,
            summary: "test".into(),
            process: ProcessInfo {
                pid,
                ppid: 0,
                uid: 0,
                comm: "victim".into(),
                exe: None,
                cmdline: None,
                cgroup: None,
                starttime,
            },
            target_pid: None,
            wants_kill,
            detail: serde_json::Value::Null,
        }
    }

    /// F09 acceptance: a process that copies a protected `comm` is visible to
    /// the tripwire but never reaches `Action::Refused`. This exercises the real
    /// responder decision path and asserts the resulting SIGKILL wait status.
    #[test]
    fn f09_comm_only_selector_cannot_grant_sigkill_immunity() {
        use std::os::unix::process::ExitStatusExt;
        use std::time::{Duration, Instant};

        let spoof_comm = "f09spoof";
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf '{spoof_comm}' > /proc/self/comm; sleep 30"))
            .spawn()
            .expect("spawn a sacrificial shell that renames itself");
        let pid = child.id();

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let current = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_default()
                .trim_end()
                .to_string();
            if current == spoof_comm {
                break;
            }
            assert!(Instant::now() < deadline, "child comm was never set");
            std::thread::sleep(Duration::from_millis(10));
        }

        let cfg = crate::config::Protect {
            comms: vec![spoof_comm.into()],
            cgroup_contains: Vec::new(),
            protect_self: false,
            targets: Vec::new(),
        };
        let resolution = crate::procscan::resolve_protected(&cfg);
        assert!(
            resolution.protected.is_empty(),
            "a mutable comm must not create immunity"
        );
        assert!(resolution.tripwire.pids().contains(&pid));

        let r = Responder::new(Mode::Enforce, true);
        let recorded = starttime_of(pid).expect("child start time is readable");
        let mut f = finding_with_starttime(pid, true, Some(recorded));
        f.process.comm = spoof_comm.into();

        assert_eq!(
            r.act(&f, &resolution.protected),
            Action::Killed,
            "the original F09 decision path must no longer return Refused"
        );
        let status = child.wait().expect("wait for the killed child");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the spoofed comm must not prevent the real SIGKILL"
        );
    }

    /// F09 compatibility: an anchored target keeps the documented protection.
    #[test]
    fn f09_anchored_target_still_refuses_sigkill() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`");
        let pid = child.id();
        let recorded = starttime_of(pid).expect("child start time is readable");
        let exe = crate::events::exe_of(pid).expect("child executable is readable");
        let uid = unsafe { libc::getuid() };

        let cfg = crate::config::Protect {
            comms: Vec::new(),
            cgroup_contains: Vec::new(),
            protect_self: false,
            targets: vec![crate::config::ProtectTarget {
                comm: Some("sleep".into()),
                exe: Some(exe),
                uid: Some(uid),
                cgroup: None,
            }],
        };
        let resolution = crate::procscan::resolve_protected(&cfg);
        assert!(
            resolution.protected.pids().contains(&pid),
            "an anchored identity target must still grant immunity"
        );

        let r = Responder::new(Mode::Enforce, true);
        let mut f = finding_with_starttime(pid, true, Some(recorded));
        f.process.comm = "sleep".into();
        assert_eq!(r.act(&f, &resolution.protected), Action::Refused);

        // Clean up the protected child without going through the responder.
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        let _ = child.wait();
    }

    #[test]
    fn observe_mode_never_kills() {
        let r = Responder::new(Mode::Observe, true);
        let empty = Protected::default();
        assert_eq!(r.act(&finding(999999, true), &empty), Action::Observed);
    }

    #[test]
    fn enforce_without_wants_kill_is_observed() {
        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(r.act(&finding(999999, false), &empty), Action::Observed);
    }

    #[test]
    fn refuses_init() {
        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(r.act(&finding(1, true), &empty), Action::Refused);
    }

    #[test]
    fn refuses_self() {
        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(
            r.act(&finding(std::process::id(), true), &empty),
            Action::Refused
        );
    }

    #[test]
    fn refuses_protected() {
        let r = Responder::new(Mode::Enforce, true);
        // Recorded with no start time — the `hidepid=` case, where there is
        // nothing to compare against and protection therefore holds (W-R4).
        let mut protected = Protected::default();
        protected.insert(4242, None);
        assert_eq!(r.act(&finding(4242, true), &protected), Action::Refused);
    }

    // ── the acceptance tests for the kill claim (W-R1) ──────────────────────
    //
    // Every test above asserts only the *decision* — and all of them pass a pid
    // that does not exist (999999) or a special one (1, self, the protected set),
    // so they would still pass if `act` never reached `libc::kill(2)` at all. The
    // audit's W-R1 asks for a test of the claim itself: that enforce mode really
    // kills, and that observe mode really does not. These two spawn a live child
    // and check the outcome both ways, so the pair cannot pass on a decision-path
    // stub.

    /// Enforce mode + `wants_kill` must actually terminate the offender with
    /// SIGKILL. Asserts the *wait status*, not just the returned `Action`: a
    /// `Killed` return with a child that is still running would be the exact
    /// false-confidence the audit is about.
    #[test]
    fn enforce_kills_a_real_offender() {
        use std::os::unix::process::ExitStatusExt;

        // 30s: far longer than the test can take, so a natural exit can never
        // race the kill and turn a real failure into a pass.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`; it must exist on PATH");
        let pid = child.id();

        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        // The identity the detector would have recorded for this child at
        // enrichment time, so this exercises the verified path and not the
        // unverified fallback.
        let recorded = starttime_of(pid).expect("read the child's start time from /proc");
        assert_eq!(
            r.act(&finding_with_starttime(pid, true, Some(recorded)), &empty),
            Action::Killed,
            "enforce mode did not report the offender as killed"
        );

        let status = child.wait().expect("reap the offender");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the offender was not killed by SIGKILL — status {status:?}. `Action::Killed` \
             is returned only when kill(2) reports success, so a mismatch here means the \
             pid was wrong or the signal was not the one the responder claims to send"
        );
        assert!(
            !status.success(),
            "a SIGKILLed process cannot report a successful exit: {status:?}"
        );
    }

    /// The negative control: the same live child, the same `wants_kill`, but the
    /// responder in observe mode must leave it running. Without this, a responder
    /// that killed unconditionally would pass the test above.
    #[test]
    fn observe_mode_leaves_a_real_offender_running() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`; it must exist on PATH");
        let pid = child.id();

        let r = Responder::new(Mode::Observe, true);
        let empty = Protected::default();
        assert_eq!(
            r.act(&finding(pid, true), &empty),
            Action::Observed,
            "observe mode must never kill, whatever `wants_kill` says"
        );

        // `try_wait` returning Ok(None) means the child is still alive — i.e. the
        // observe-mode responder did not signal it. Reaping first would race the
        // kernel's exit delivery and could read as "gone" for the wrong reason.
        assert_eq!(
            child.try_wait().expect("poll the offender"),
            None,
            "observe mode killed the process it was only supposed to watch"
        );

        // Clean up so a failing assertion above cannot leave a stray `sleep`.
        let _ = child.kill();
        let _ = child.wait();
    }

    // ── W-R3: the pid is a number, and the kernel reuses it ─────────────────
    //
    // The audit's W-R3 is that signalling a bare pid number is a TOCTOU: the
    // pid captured at event time may, by the time enforcement runs, name a
    // *different* process. The catastrophic outcome is not a missed kill — it
    // is SIGKILL delivered to an innocent successor, self-inflicted downtime
    // caused by the tool that exists to prevent it.
    //
    // A true recycled-pid race cannot be staged deterministically: it needs the
    // kernel to wrap pid_max inside a millisecond. But the *check* is fully
    // testable, and the check is what closes the race — so this test forces the
    // disagreement the race would produce (a live pid whose start time differs
    // from the one recorded at event time) and asserts nothing is signalled.

    /// A finding whose recorded start time does not match the live process must
    /// refuse, and must leave the process running. This is the deterministic
    /// stand-in for the recycle race: from the responder's side, "the pid now
    /// names something that started at a different time" is exactly what a
    /// recycle looks like, and it is the same input either way.
    #[test]
    fn a_pid_that_no_longer_matches_its_recorded_identity_is_not_killed() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`; it must exist on PATH");
        let pid = child.id();

        let live = starttime_of(pid).expect("read the child's start time from /proc");
        // One tick earlier: the same pid, a *different* process identity. Ticks
        // since boot only increase, so a recycled pid always looks like this —
        // a later time than the process it replaced.
        let stale = live - 1;

        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(
            r.act(&finding_with_starttime(pid, true, Some(stale)), &empty),
            Action::IdentityChanged,
            "the responder signalled a pid whose identity it could not confirm; a recycled \
             pid would have received this SIGKILL instead of the offender"
        );

        // The load-bearing half: the return value above is a claim, this is the
        // fact. Nothing may have been signalled. `try_wait` (not `wait`) —
        // `wait` would block out the child's whole 30s and then read a natural
        // exit, which proves nothing.
        assert_eq!(
            child.try_wait().expect("poll the bystander"),
            None,
            "the bystander was killed even though its identity did not match — this is \
             precisely the wrong-process kill W-R3 describes"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// The other side of the same gate: when the recorded identity *does* match,
    /// the kill must still go through. Without this, a responder broken to
    /// always return `IdentityChanged` would pass the test above.
    #[test]
    fn a_pid_that_matches_its_recorded_identity_is_killed() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`; it must exist on PATH");
        let pid = child.id();
        let recorded = starttime_of(pid).expect("read the child's start time from /proc");

        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(
            r.act(&finding_with_starttime(pid, true, Some(recorded)), &empty),
            Action::Killed,
            "a matching identity must still be enforced against"
        );

        let _ = child.wait();
    }

    /// A pid with nothing behind it is reported as gone, not as an identity
    /// change: the operator reading the log needs to tell "it exited first"
    /// apart from "the pid was reused".
    #[test]
    fn a_pid_that_is_already_gone_reports_failed_not_identity_changed() {
        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(
            r.act(&finding_with_starttime(999_999, true, Some(12345)), &empty),
            Action::Failed,
            "a pid with no process behind it must report Failed, so the log does not read \
             as though a recycle was suspected"
        );
    }

    // ── W-R4: protection is an identity, not a pid number ───────────────────
    //
    // The protected set records each guarded process's start time, so immunity
    // is bound to the process and not to the number it happens to occupy. The
    // failure this closes is the mirror image of W-R3's: there, a recycled pid
    // could receive a kill meant for an offender; here, a recycled pid could
    // *inherit* the immunity of the guarded process it replaced and make itself
    // unkillable for the rest of the refresh window.

    /// A protected pid that has been recycled must not stay immune. This is the
    /// spoof an attacker gets without it: wait for a protected process to exit,
    /// land your own process on its pid, and the responder refuses to touch you
    /// until the next resolve comes round.
    #[test]
    fn a_recycled_pid_does_not_inherit_protection() {
        use std::os::unix::process::ExitStatusExt;

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`; it must exist on PATH");
        let pid = child.id();
        let live = starttime_of(pid).expect("read the child's start time from /proc");

        // What the policy resolved earlier: this pid, as a *different* process —
        // the protected occupant it named, which has since exited. A recycled
        // pid always looks like this, because it starts later than the process
        // whose number it took.
        let mut protected = Protected::default();
        protected.insert(pid, Some(live - 1));

        let r = Responder::new(Mode::Enforce, true);
        assert_eq!(
            r.act(&finding_with_starttime(pid, true, Some(live)), &protected),
            Action::Killed,
            "a pid whose protected occupant is gone must not keep its immunity — inheriting \
             the protected set by landing on a recycled number is exactly what W-R4 is about"
        );

        let status = child.wait().expect("reap the offender");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the returned Action claims a kill; the wait status is the fact: {status:?}"
        );
    }

    /// The other side of the same gate: while the recorded identity still holds,
    /// protection holds. Without this, a responder that ignored the protected
    /// set entirely would pass the test above.
    #[test]
    fn a_live_protected_pid_is_still_refused() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`; it must exist on PATH");
        let pid = child.id();
        let live = starttime_of(pid).expect("read the child's start time from /proc");

        let mut protected = Protected::default();
        protected.insert(pid, Some(live));

        let r = Responder::new(Mode::Enforce, true);
        assert_eq!(
            r.act(&finding_with_starttime(pid, true, Some(live)), &protected),
            Action::Refused
        );

        assert_eq!(
            child.try_wait().expect("poll the protected process"),
            None,
            "the responder signalled a process the operator's policy protects"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    // ── the identity table (W2K-24, W2K-37) ─────────────────────────────────
    //
    // `hidepid=` and an exited target used to be the same `None`, and the
    // responder resolved both to "already exited". These tests pin the four
    // answers apart, and pin them apart in the sentence that gets logged, because
    // the log is what an operator audits an outage from.

    #[test]
    fn the_identity_table_answers_every_combination_once() {
        use IdentityOutcome::*;
        assert_eq!(
            identity_outcome(Some(10), ProcIdentity::Known(10), false),
            Match
        );
        assert_eq!(
            identity_outcome(Some(10), ProcIdentity::Known(11), false),
            Recycled
        );
        assert_eq!(
            identity_outcome(None, ProcIdentity::Known(11), false),
            Unproven
        );
        // `ENOENT` is an exit only when something other than /proc agrees.
        assert_eq!(identity_outcome(Some(10), ProcIdentity::Gone, true), Exited);
        assert_eq!(
            identity_outcome(Some(10), ProcIdentity::Gone, false),
            Unverifiable,
            "a hidden live process and an exited one answer /proc identically"
        );
        assert_eq!(identity_outcome(None, ProcIdentity::Gone, true), Exited);
        assert_eq!(
            identity_outcome(None, ProcIdentity::Gone, false),
            Unverifiable
        );
        assert_eq!(
            identity_outcome(Some(10), ProcIdentity::Hidden(libc::EACCES), false),
            Unverifiable
        );
        assert_eq!(
            identity_outcome(None, ProcIdentity::Hidden(libc::EPERM), false),
            Unverifiable
        );
        assert_eq!(
            identity_outcome(Some(10), ProcIdentity::Malformed, false),
            Unverifiable
        );
        // Corroboration is only ever about `Gone`; a readable identity needs none.
        assert_eq!(
            identity_outcome(Some(10), ProcIdentity::Known(10), true),
            Match
        );
    }

    /// W2K-39: the handle, not `/proc`, is what decides whether `ENOENT` meant an
    /// exit. The full table, including the two shapes where corroboration must not
    /// be granted.
    #[test]
    fn only_the_handle_can_turn_enoent_into_an_exit() {
        use PinLife::*;
        assert!(pin_corroborates_exit(ProcIdentity::Gone, Dead));
        assert!(pin_corroborates_exit(ProcIdentity::Gone, NotAsked));
        assert!(
            !pin_corroborates_exit(ProcIdentity::Gone, Alive),
            "a live pin plus ENOENT is hidepid=, not an exit"
        );
        assert!(
            !pin_corroborates_exit(ProcIdentity::Gone, Unknown(libc::ENOSYS)),
            "a probe that could not run proves nothing"
        );
        assert!(!pin_corroborates_exit(ProcIdentity::Known(7), Dead));
        assert!(!pin_corroborates_exit(
            ProcIdentity::Hidden(libc::EACCES),
            Dead
        ));
        assert!(!pin_corroborates_exit(ProcIdentity::Malformed, Alive));
    }

    /// The claim `probe_pin` is built on: signal 0 through a pidfd reports the
    /// task's existence before it reports ownership, and the handle keeps working
    /// after the number it pinned is gone. Measured on this kernel, in-process.
    #[test]
    fn the_handle_answers_alive_then_dead_for_the_same_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`");
        let pid = child.id();
        let fd = open_pidfd(pid).expect("a live child must yield a pidfd");

        assert_eq!(
            probe_pin(fd),
            PinLife::Alive,
            "signal 0 on a live pin must not report ESRCH"
        );

        let _ = child.kill();
        let _ = child.wait().expect("reap it");

        // Same fd, same handle, same process — and the process is now gone.
        assert_eq!(
            probe_pin(fd),
            PinLife::Dead,
            "the handle outlives the task, so it is the answer that does not depend on /proc"
        );
        // SAFETY: `fd` is ours and unused after this.
        unsafe { libc::close(fd) };
    }

    #[test]
    fn the_refusal_sentence_names_which_file_the_operator_must_fix() {
        // Three different `Unverifiable` shapes, three different repairs; one
        // sentence for all three is how a coverage gap stays open.
        let hidden_live = unverifiable_reason(ProcIdentity::Gone, PinLife::Alive, true);
        assert!(hidden_live.contains("hidepid="), "{hidden_live}");
        assert!(hidden_live.contains("ALIVE"), "{hidden_live}");
        let uncorroborated = unverifiable_reason(ProcIdentity::Gone, PinLife::NotAsked, false);
        assert!(
            uncorroborated.contains("assumed rather than proven"),
            "{uncorroborated}"
        );
        let unreadable =
            unverifiable_reason(ProcIdentity::Hidden(libc::EACCES), PinLife::NotAsked, true);
        assert_eq!(unreadable, "the identity could not be read from /proc.");
    }

    #[test]
    fn an_unreadable_proc_is_never_worded_as_an_exited_process() {
        // The false sentence W2K-37 produced was "the process had already
        // exited". A hidden /proc must not be able to borrow it.
        let hidden = ProcIdentity::Hidden(libc::EACCES).explain();
        assert!(
            !hidden.contains("already exited"),
            "the log still lies: {hidden}"
        );
        assert!(
            hidden.contains("hidepid="),
            "the log must name the mechanism: {hidden}"
        );
        assert_eq!(ProcIdentity::Gone.explain(), "nothing at that pid (ENOENT)");
        // Both are still "no start time" for callers that only ever had Option.
        assert_eq!(ProcIdentity::Hidden(libc::EACCES).as_starttime(), None);
        assert_eq!(ProcIdentity::Gone.as_starttime(), None);
    }

    #[test]
    fn the_handle_is_opened_before_the_identity_is_read() {
        // W2K-24 is an ordering property, and an ordering is exactly what a
        // compiler will not stop someone from "simplifying" back. The doc comment
        // has claimed this order for as long as the pidfd has existed; the code
        // read /proc first. Pin the source, so the revert is a red test rather
        // than a 4.0 µs window restored in silence.
        let src = include_str!("respond.rs");
        let body = &src[src.find("pub fn act(").expect("act exists")..];
        let opened = body
            .find("let pidfd = open_pidfd(pid);")
            .expect("act opens a pidfd");
        let read = body
            .find("let live = identity_of(pid);")
            .expect("act reads the identity");
        assert!(
            opened < read,
            "the identity must be read AFTER pidfd_open: opening second leaves a window in \
             which the number changes hands between the read and the pin, and the handle then \
             pins the impostor (offsets {opened} vs {read})"
        );
    }

    #[test]
    fn pidfd_open_keeps_the_errno_that_explains_its_failure() {
        // W2K-26: `None` conflated "the process is gone" with "this kernel or
        // seccomp profile will not give us a pidfd". The second one is a downgrade
        // to kill(2) that the operator must be told about, the first is not.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`");
        let pid = child.id();
        let fd = open_pidfd(pid).expect("a live process must yield a pidfd here");
        assert!(fd >= 0);
        unsafe { libc::close(fd) };

        let _ = child.kill();
        let _ = child.wait().expect("reap the offender");
        let err = open_pidfd(pid).expect_err("a reaped pid must not yield a pidfd");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ESRCH),
            "ESRCH is the race-free 'nothing is here', and act() ends the decision on it"
        );
    }

    #[test]
    fn a_reaped_target_is_not_delivered_to_kill_via() {
        // The ESRCH short-circuit: no signal, and an Action that says the target
        // was already gone rather than that enforcement failed.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`");
        let pid = child.id();
        let recorded = starttime_of(pid).expect("read the child's start time");
        let _ = child.kill();
        let _ = child.wait().expect("reap it first");

        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        assert_eq!(
            r.act(&finding_with_starttime(pid, true, Some(recorded)), &empty),
            Action::Failed,
            "a reaped pid is 'already exited', and must not be reported as a kill"
        );
    }

    #[test]
    fn a_hidden_target_yields_unverifiable_not_failed() {
        // `Action` is what the log line and any monitor built on it read, so the
        // coverage gap needs its own word: `failed` would be indistinguishable
        // from a kill that was delivered and refused by the kernel.
        assert_ne!(Action::Unverifiable, Action::Failed);
        assert_eq!(Action::Unverifiable.as_str(), "unverifiable");
        assert_eq!(
            identity_outcome(Some(1), ProcIdentity::Hidden(libc::EACCES), false),
            IdentityOutcome::Unverifiable
        );
    }

    #[test]
    fn an_unanchored_target_is_not_signalled_by_default() {
        // The arm §۷۰-۱۰ T2 measured delivering SIGKILL (`Action::Killed`,
        // `signal=Some(9)`) with nothing behind the decision. With the default
        // policy the finding is reported, the process is left running, and the
        // action says which of the two it was.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`");
        let pid = child.id();

        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        // `None` here is the whole hypothesis: the event recorded no start time.
        let action = r.act(&finding(pid, true), &empty);
        let still_running = child.try_wait().expect("poll the child").is_none();
        println!(
            "respond: enforce request with no recorded identity, pid {pid}: act() said {}, \
             child still running = {still_running}",
            action.as_str()
        );
        assert_eq!(
            action,
            Action::Unproven,
            "an enforce request against a live pid with no recorded identity must be withheld"
        );
        assert!(
            still_running,
            "the withheld target must still be running — an action of 'unproven' that \
             follows a real SIGKILL would be a lie in the other direction"
        );

        let _ = child.kill();
        let _ = child.wait().expect("reap the withheld target");
    }

    #[test]
    fn the_opt_in_still_delivers_the_unanchored_kill() {
        // The other half of the knob: `false` must actually mean what the log
        // line claims, or the refusal test above is proving a dead flag.
        use std::os::unix::process::ExitStatusExt;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sacrificial `sleep 30`");
        let pid = child.id();

        let r = Responder::new(Mode::Enforce, false);
        let empty = Protected::default();
        let action = r.act(&finding(pid, true), &empty);
        let status = child.wait().expect("reap the killed offender");
        println!(
            "respond: same request with require_anchored_identity = false, pid {pid}: act() \
             said {}, delivered signal = {:?}",
            action.as_str(),
            status.signal()
        );
        assert_eq!(
            action,
            Action::Killed,
            "require_anchored_identity = false keeps the pre-W2K-25 behaviour"
        );
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the opted-in path must really signal: status {status:?}"
        );
    }

    #[test]
    fn unproven_and_refused_are_not_the_same_word() {
        // `Refused` is "we guard this pid, or it is us, or it is init" — a
        // decision to repeat. `Unproven` is "we could not name the target". A
        // monitor that counts only `refused` must not merge the two.
        assert_ne!(Action::Unproven, Action::Refused);
        assert_eq!(Action::Unproven.as_str(), "unproven");
    }

    #[test]
    fn the_withheld_sentence_points_at_the_key_that_changes_it() {
        // An operator reading one log line has to be able to act on it without
        // opening the source, so the refusal names the config key — and the
        // opt-in branch names it too, in the tense of what was chosen.
        let src = include_str!("respond.rs");
        let start = src
            .find("IdentityOutcome::Unproven => {")
            .expect("the Unproven arm exists");
        let arm = &src[start..];
        let arm = &arm[..arm
            .find("if let Some(errno) = fallback_reason")
            .expect("the arm ends before the delivery block")];
        assert!(
            arm.contains("respond.require_anchored_identity"),
            "the Unproven arm must name the key that controls it"
        );
        assert!(
            arm.contains("ENFORCEMENT WITHHELD"),
            "the refusal must be findable by a phrase no other arm uses"
        );
    }

    /// W2K-39, run against a real hidden process rather than a table row.
    ///
    /// `#[ignore]`d because the shape it needs cannot exist inside an ordinary
    /// test run: a target belonging to another uid, and a `/proc` mounted
    /// `hidepid=2` over this process. That is a VM experiment, and it is exactly
    /// the §۷۰-۱۰ T7 setup, so this test re-runs the measurement instead of
    /// re-asserting the classification the earlier run already established:
    ///
    /// ```text
    /// # on the lab VM, as root; target is root-owned, agent runs as uid 1000
    /// unshare --mount --propagation private -- \
    ///   sh -c 'mount -t proc -o hidepid=2 proc /proc &&
    ///          su debian -s /bin/sh -c "WARDEN_HIDDEN_TARGET=$TARGET_PID cargo test --bin \
    ///          warden -- respond::tests::the_hidepid_enoent_is_not_an_exit -- --exact \
    ///          --ignored --nocapture"'
    /// ```
    ///
    /// It fails loudly if `/proc` turns out to show the target after all, because
    /// then it is not measuring what it claims to measure.
    #[test]
    #[ignore = "needs a hidepid=2 /proc and a foreign-uid target; run on the lab VM"]
    fn the_hidepid_enoent_is_not_an_exit() {
        let raw = std::env::var("WARDEN_HIDDEN_TARGET").expect(
            "set WARDEN_HIDDEN_TARGET to a live process owned by another uid, under a /proc \
             mounted hidepid=2",
        );
        let pid: u32 = raw
            .trim()
            .parse()
            .expect("WARDEN_HIDDEN_TARGET must be a pid");
        let live = identity_of(pid);
        assert!(
            matches!(live, ProcIdentity::Gone | ProcIdentity::Hidden(_)),
            "this test only measures the hidden case; /proc answered {live:?} for pid {pid}, \
             so the mount is not in effect and the result would mean nothing"
        );

        let r = Responder::new(Mode::Enforce, true);
        let empty = Protected::default();
        // Both finding shapes: the one that reached here with an identity, and the
        // one enriched on a host where /proc was already blind at event time.
        let action = r.act(&finding_with_starttime(pid, true, Some(1)), &empty);
        assert_eq!(
            action,
            Action::Unverifiable,
            "a hidden live target must be a coverage gap, never a kill and never an exit"
        );

        // And the target must still be running: the claim under test is that
        // Warden refused to touch a process that is alive.
        // SAFETY: signal 0 asks only whether we may signal it; nothing is delivered.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        let err = (rc != 0)
            .then(std::io::Error::last_os_error)
            .map(|e| e.raw_os_error().unwrap_or(0));
        assert!(
            rc == 0 || err == Some(libc::EPERM) || err == Some(libc::EACCES),
            "the target was not alive any more (rc={rc}, errno={err:?}), so this run proves \
             nothing about the hidden case"
        );
        println!(
            "respond: live hidden target pid {pid}: /proc said {:?}, act() said {}, and the \
             process is still running (kill -0 rc={rc})",
            live,
            action.as_str(),
        );
    }
}
