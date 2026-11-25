//! explain.rs — `warden --explain <kind>`: what THIS config would say about an
//! event that is not happening.
//!
//! `--check` answers "is the config readable and what does it name"; `--doctor`
//! answers "what does this host allow". Neither answers the question an operator
//! actually has after an incident drill or a quiet week: *if* a web worker
//! `execve`'d `/tmp/sh` and dialled 203.0.113.7:443, would Warden have said
//! anything — and if it would have said nothing, which knob is why?
//!
//! THE WHOLE DESIGN IS THAT NOTHING HERE JUDGES. `--explain` builds a decoded
//! [`Event`], hands it to the same [`Detector::judge`] the running agent calls,
//! and prints what comes back. It re-implements no rule, so it cannot drift from
//! one: an answer from `--explain` and an answer from the daemon are the same
//! function's output on the same config, and the tests in this file assert that
//! rather than asserting a re-derived expectation.
//!
//! What that forces is one seam — the three `/proc` reads the detector makes per
//! actor (`exe`, `cmdline`, `cgroup`). A hypothetical actor has no `/proc` entry,
//! so [`FabricatedEvidence`] supplies them and [`Detector::for_explain`] is the
//! only constructor that can. Every other field of the event is the caller's.
//!
//! And what it does NOT answer, printed in the output rather than left to be
//! inferred:
//!
//!  - **Whether the record exists at all.** This judges the userspace detector. A
//!    hook that never attached, a ring that dropped the record, or a sensor
//!    disabled by config means the event never reached `judge`. `--doctor` and
//!    `--check` are the commands that say which sensors were live; a quiet
//!    journal has two different reasons and this one only rules out the third.
//!  - **Whether Warden would have killed.** The responder re-checks live identity
//!    (`pidfd`, start time, the protected set) before signalling; those are
//!    questions about a process that does not exist here.
//!  - **Whether the journal would show it.** Findings are judged and delivered in
//!    full, but the journal *line* is coalesced per actor and class
//!    (`FindingLogThrottle` in `main.rs`), so "would produce a finding" is not
//!    "would print another line".
//!
//! The second half of the answer is the probes. "Which knob is why" is not
//! something this module may assert — asserting it would be re-implementing the
//! rules it exists not to duplicate. So it asks the engine instead: it changes
//! one configured thing at a time (clears a list, flips a bool, names the record's
//! own value in an allowlist, moves one piece of evidence) and re-judges. A probe
//! that flips the verdict names a load-bearing knob, empirically and in the
//! engine's own words. Probes that change nothing are counted, not listed, and
//! the count is printed — silence in that list is a measurement, not a claim.

use std::collections::BTreeMap;

use anyhow::{bail, Result};

use crate::config::Config;
use crate::detect::{
    basename, bpf_prog_type_name, split_ip_port, Detector, FabricatedEvidence, IMPOSSIBLE_PID,
};
use crate::detect::{Finding, Severity};
use crate::events::{
    AccessHook, AccessInfo, CredChange, Event, ExeIdentity, FileOp, Kind, Protocol, ServiceOp,
    SignalDelivery, WARDEN_INTENT_EXEC, WARDEN_INTENT_READ, WARDEN_INTENT_WRITE,
};

/// `MS_BIND` as `judge_mount` spells it — the bit that makes a mount an escape
/// candidate rather than ordinary admin work.
const MS_BIND: u32 = 4096;
/// `PTRACE_MODE_READ` / `PTRACE_MODE_ATTACH`, the two classes `judge_ptrace`
/// separates. The attach bit is the one that decides High-vs-Medium and
/// kill-vs-never-kill.
const PTRACE_MODE_READ: u32 = 1;
const PTRACE_MODE_ATTACH: u32 = 2;
/// `TAINT_OUT_OF_TREE` | `TAINT_UNSIGNED_MODULE`: the two bits that make an
/// allowlisted module NAME stop being honoured (a hostile `.ko` can copy a name,
/// it cannot un-taint itself).
const TAINT_OUT_OF_TREE_OR_UNSIGNED: u32 = (1 << 12) | (1 << 13);

/// Every kind `--explain` accepts, in the words `Kind::as_str` uses — so the
/// spelling in an error message is the spelling the wire format uses and cannot
/// drift from it. `connect_result` and `flow` are listed for the same reason:
/// they are real kinds, and a command that said "unknown kind" about them would
/// hide the one answer the detector already has for them (no finding, by design).
const KIND_NAMES: [&str; 14] = [
    "exec",
    "signal",
    "ptrace",
    "connect",
    "connect_result",
    "creds",
    "module",
    "file",
    "service",
    "listen",
    "bpfload",
    "mount",
    "access",
    "flow",
];

/// The `--event` keys this command understands, whatever the kind. The
/// kind-specific ones are appended per kind in [`kind_keys`]; a key outside both
/// sets is refused, because W2K-23's lesson is that a value nobody reads is worse
/// than an error: it makes the answer look like it was about the thing the
/// operator typed.
const COMMON_KEYS: [&str; 7] = ["pid", "ppid", "uid", "comm", "exe", "cmdline", "cgroup"];

/// What one kind may be told about its record, beyond [`COMMON_KEYS`].
fn kind_keys(kind: Kind) -> &'static [&'static str] {
    match kind {
        Kind::Exec => &["path"],
        Kind::Signal => &["target", "signal", "delivery", "from_parent"],
        Kind::Ptrace => &["target", "mode"],
        Kind::Connect | Kind::Listen => &["dest", "proto"],
        Kind::Creds => &["old_uid", "new_uid", "cap_old", "cap_new"],
        Kind::Module => &["path", "taints"],
        Kind::File => &["path", "op", "ops"],
        Kind::Service => &["path", "op"],
        Kind::BpfLoad => &["prog_type", "bpf_cmd", "exe_dev", "exe_ino"],
        Kind::Mount => &["path", "bind"],
        Kind::Access => &["hook", "intent", "denied", "dev", "ino", "guard_uid"],
        // These two are answered from the config alone — the detector declines
        // them by design — so accepting fields for them would mean accepting
        // values nobody reads. Their answer names the design reason instead.
        Kind::ConnectResult | Kind::Flow => &[],
    }
}

fn parse_kind(want: &str) -> Result<Kind> {
    // The wire names first, then the two spellings an operator reaches for
    // before remembering how the ABI calls them.
    let alias = match want {
        "bpf-load" | "bpf_load" | "bpf" => "bpfload",
        "connect-result" | "connect_result" => "connect_result",
        "execve" => "exec",
        "priv" | "privesc" | "creds_change" => "creds",
        other => other,
    };
    Kind::ALL
        .iter()
        .copied()
        .find(|k| k.as_str() == alias)
        .ok_or_else(|| anyhow::anyhow!("unknown event kind {want:?}"))
}

/// One parsed request: a kind and the fields the operator named.
#[derive(Debug, Clone)]
pub struct Request {
    pub kind: Kind,
    pub given: BTreeMap<String, String>,
}

impl Request {
    /// Validate a kind token and a list of `--event key=value` strings.
    ///
    /// Refuses: a kind outside [`KIND_NAMES`], a token without `=`, a key no kind
    /// uses at all, and — the one that matters for a dry run — a key that is real
    /// but belongs to a different kind. `--explain exec --event dest=1.2.3.4:80`
    /// would otherwise answer a question about a connect while looking like it
    /// answered the one that was asked.
    pub fn parse(kind: &str, raw: &[String]) -> Result<Self> {
        let kind = parse_kind(kind)
            .map_err(|e| anyhow::anyhow!("{e}; expected one of: {}", KIND_NAMES.join(", ")))?;
        let mut given = BTreeMap::new();
        for token in raw {
            let (key, value) = token.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "--event needs key=value, got {token:?} (a bare value has no field to set)"
                )
            })?;
            if COMMON_KEYS.contains(&key) || kind_keys(kind).contains(&key) {
                given.insert(key.to_string(), value.to_string());
                continue;
            }
            let owners: Vec<&str> = Kind::ALL
                .iter()
                .filter(|k| kind_keys(**k).contains(&key))
                .map(|k| k.as_str())
                .collect();
            if owners.is_empty() {
                bail!(
                    "--event key {key:?} is not a field this command reads. Known keys: {}.",
                    COMMON_KEYS.join(", ")
                );
            }
            bail!(
                "--event key {key:?} does not belong to kind {:?}; it is a field of {}. \
                 The value was not ignored — the command refuses, because a dry run that \
                 silently drops a field answers a different question from the one asked.",
                kind.as_str(),
                owners.join(", ")
            );
        }
        Ok(Self { kind, given })
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.given.get(key).map(String::as_str)
    }

    /// A required-to-parse number. Absent is the caller's business (each field
    /// has an explicit default); present-but-unparseable is always an error.
    fn num(&self, key: &str) -> Result<u64> {
        match self.get(key) {
            Some(v) => parse_int(v).ok_or_else(|| {
                anyhow::anyhow!("{key}={v:?} is not a number — decimal, or 0x/0o/0b prefixed")
            }),
            None => Ok(0),
        }
    }

    fn boolean(&self, key: &str) -> Result<bool> {
        match self.get(key) {
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "y" | "on" => Ok(true),
                "0" | "false" | "no" | "n" | "off" => Ok(false),
                _ => bail!("{key}={v:?} is not a yes/no value"),
            },
            None => Ok(false),
        }
    }
}

/// One integer, in either spelling the operator can legitimately have in front of
/// them: the decimal they type, or the hex the detector itself prints. `cap_old`,
/// `cap_new` and the taint mask leave a finding as `{:#018x}`, so a value copied
/// out of a real finding has to be re-enterable — a dry run that refused its own
/// output would be useless for the one job it has.
fn parse_int(v: &str) -> Option<u64> {
    let v = v.trim();
    let lower = v.to_ascii_lowercase();
    let (radix, digits) = match lower.strip_prefix("0") {
        Some(rest) => match rest.chars().next() {
            Some('x') => (16, &rest[1..]),
            Some('o') => (8, &rest[1..]),
            Some('b') => (2, &rest[1..]),
            _ => (10, v),
        },
        None => (10, v),
    };
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

/// The same two spellings for the fields the wire carries in 32 bits. A value too
/// large for the field is a typo, not a number, so it fails the same way.
fn parse_int32(v: &str) -> Option<u32> {
    parse_int(v).and_then(|n| u32::try_from(n).ok())
}

/// The judged event, the evidence standing in for `/proc`, the config it is
/// judged against, and how many times to feed the record to one detector.
#[derive(Clone)]
struct Scenario {
    cfg: Config,
    ev: Event,
    evidence: FabricatedEvidence,
    /// The file burst rule counts destructive ops *per actor over a window*, so
    /// one record cannot cross a threshold of two. `--event ops=N` replays the
    /// same record N times, 1 ms apart, into one detector.
    ops: u32,
}

impl Scenario {
    /// Ask the real detector. A fresh `Detector` per call: `--explain` answers
    /// one question at a time and must not carry burst state between them.
    fn judge(&self) -> Option<Finding> {
        let det = Detector::for_explain(self.cfg.clone(), self.evidence.clone());
        let mut last = None;
        for i in 0..self.ops.max(1) {
            let mut e = self.ev.clone();
            e.ts_ns = self.ev.ts_ns + u64::from(i) * 1_000_000;
            last = det.judge(&e);
        }
        last
    }

    fn with(&self, change: impl FnOnce(&mut Scenario)) -> Scenario {
        let mut s = self.clone();
        change(&mut s);
        s
    }
}

/// What the engine said, reduced to the parts a probe can change. `Finding` has
/// no `PartialEq` and adding one for this would mean comparing free-text
/// summaries; the three fields below are the whole of what a config knob can
/// move.
#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    event_type: Option<&'static str>,
    severity: Option<Severity>,
    wants_kill: bool,
}

impl Verdict {
    fn of(finding: &Option<Finding>) -> Self {
        match finding {
            None => Self {
                event_type: None,
                severity: None,
                wants_kill: false,
            },
            Some(f) => Self {
                event_type: Some(f.event_type.as_str()),
                severity: Some(f.severity),
                wants_kill: f.wants_kill,
            },
        }
    }

    fn fires(&self) -> bool {
        self.event_type.is_some()
    }
}

/// One thing changed, and the answer to "so what".
struct Probe {
    change: String,
    /// False when the knob is already in the state the probe would move it to
    /// (clearing a list that is empty, naming a value the caller never gave).
    /// Such a probe is skipped and counted, never reported as "changed nothing" —
    /// that would read as evidence about a knob that was never tested.
    applies: bool,
    apply: Box<dyn Fn(&mut Scenario)>,
}

fn probe(applies: bool, change: String, apply: impl Fn(&mut Scenario) + 'static) -> Probe {
    Probe {
        applies,
        change,
        apply: Box::new(apply),
    }
}

/// Clear one configured list — the state that most often *allows* an event.
fn clear_list(key: &str, already_empty: bool, clear: impl Fn(&mut Config) + 'static) -> Probe {
    probe(!already_empty, format!("clear {key}"), move |s| {
        clear(&mut s.cfg)
    })
}

/// Put the record's own value into one list — the operator's real question when
/// the answer was "finding": which line would sanction this? A value the caller
/// never supplied makes the probe inapplicable rather than silently skipped.
fn add_value(
    key: &str,
    value: Option<String>,
    push: impl Fn(&mut Config, String) + 'static,
) -> Probe {
    match value {
        Some(v) => probe(true, format!("add {v:?} to {key}"), move |s| {
            push(&mut s.cfg, v.clone())
        }),
        None => probe(
            false,
            format!("add the record's own value to {key}"),
            |_| {},
        ),
    }
}

/// Move one bool to the other state. Always applies — a bool has no unset.
fn flip_bool(key: &str, now: bool, set: impl Fn(&mut Config, bool) + 'static) -> Probe {
    let next = if now { "false" } else { "true" };
    probe(true, format!("set {key} = {next}"), move |s| {
        set(&mut s.cfg, !now)
    })
}

/// Change one piece of *evidence* rather than one knob: the actor's cgroup, exe,
/// or cmdline. These answer "whose event is this" questions, which no config
/// change can reach.
fn evidence_probe(
    applies: bool,
    change: String,
    set: impl Fn(&mut FabricatedEvidence) + 'static,
) -> Probe {
    probe(applies, change, move |s| set(&mut s.evidence))
}

/// Change one field of the *record* rather than the config or the evidence: the
/// signal number, the ptrace mode, the bind flag. These are the kernel's claims,
/// so the probe is labelled as a different question, not as a knob the operator
/// owns.
fn record_probe(applies: bool, change: String, set: impl Fn(&mut Event) + 'static) -> Probe {
    probe(applies, change, move |s| set(&mut s.ev))
}

/// The attribution probes, shared by every kind that narrows to the app cgroup
/// (`exec`, `connect`, `creds`, `file`, `listen`, `bpfload`, `mount`). Two of them
/// move a config knob and two move the *evidence*, because "is this the app?" has
/// two independent answers: whether the config names an app, and whether the
/// record's actor is said to be inside it. Only one of each pair can apply — an
/// empty matcher list cannot be cleared, and an actor outside the app cannot be
/// moved outside it — so the four collapse to the two that are the real answer.
fn attribution_probes(s: &Scenario) -> Vec<Probe> {
    let needle = s.cfg.app.cgroup_contains.first().cloned();
    let shown = needle.clone();
    let inside = needle.is_some();
    let unreadable = s.evidence.cgroup.is_none();
    // Does the record AS GIVEN already sit inside the app? The detector's matcher
    // is a substring test (`actor_in_app_cgroup`), and this mirrors only the
    // `applies` question — never the verdict, which the engine still owns. An
    // actor already outside the app cannot be moved outside it, so the probe
    // would be reported as tested when it could not have done anything.
    let in_app_now = s
        .evidence
        .cgroup
        .as_ref()
        .is_some_and(|cg| s.cfg.app.cgroup_contains.iter().any(|n| cg.contains(n)));
    // The empty-matcher case is the one that silently costs deployments their
    // coverage — with no app named, every app-scoped rule answers "no finding"
    // for every actor, which is indistinguishable from a clean host. So when the
    // list is unnamed this offers the line that would name it, taken from the
    // cgroup in the record rather than invented.
    let unnamed_app = if inside {
        None
    } else {
        s.evidence
            .cgroup
            .as_ref()
            .and_then(|cg| cg.rsplit('/').find(|p| !p.is_empty()).map(str::to_string))
    };
    vec![
        clear_list(
            "[app].cgroup_contains",
            s.cfg.app.cgroup_contains.is_empty(),
            |c| c.app.cgroup_contains.clear(),
        ),
        evidence_probe(
            inside && !in_app_now,
            format!(
                "say the actor IS the app (cgroup containing {:?})",
                shown.as_deref().unwrap_or_default()
            ),
            move |e| {
                if let Some(n) = &needle {
                    e.cgroup = Some(format!("/sys/fs/cgroup.slice/{n}"));
                }
            },
        ),
        evidence_probe(
            inside && !unreadable && in_app_now,
            "say the actor is NOT the app (cgroup matches no matcher)".to_string(),
            |e| e.cgroup = Some("/sys/fs/cgroup/system.slice/something-else".to_string()),
        ),
        add_value("[app].cgroup_contains", unnamed_app, |c, v| {
            c.app.cgroup_contains.push(v)
        }),
    ]
}

/// Build the event, the fabricated evidence and the probe table for one request.
fn scenario(cfg: &Config, req: &Request) -> Result<Scenario> {
    let text = |key: &str| req.get(key).map(str::to_string);
    let num = |key: &str| req.num(key);

    let ev = Event {
        kind: req.kind,
        actor_pid: num("pid")? as u32,
        actor_ppid: num("ppid")? as u32,
        actor_uid: num("uid")? as u32,
        target_pid: num("target")? as u32,
        aux: aux_for(req)?,
        ts_ns: 0,
        comm: text("comm").unwrap_or_default(),
        filename: text("path").unwrap_or_default(),
        dest: text("dest"),
        protocol: match text("proto") {
            Some(v) => Some(parse_protocol(&v)?),
            None => None,
        },
        // The two kinds whose whole payload is a verdict or a listener are not
        // explainable as findings and say so below; `kind_keys` gives them no keys,
        // so no `--event` can carry a port and there is never a flow to fold in.
        connect_outcome: None,
        flow: None,
        creds: creds_for(req)?,
        bpf_prog_type: prog_type_for(req)?,
        // The loader's executable as the kernel's hook would have named it. Both
        // numbers are the ones a real finding prints (`loader_exe_dev`/`loader_exe_ino`),
        // so an operator can copy a verdict back in and ask why. A record with no
        // inode is the norm — every kind but BPFLOAD, and any BPFLOAD whose slots
        // were left zero — and `ino = 0` means no claim rather than inode zero, so a
        // half-supplied pair cannot become a comparison against zero.
        actor_exe_file: {
            let ino = req.num("exe_ino")?;
            let dev = req.num("exe_dev")?;
            (ino != 0).then_some(ExeIdentity { dev, ino })
        },
        access: access_for(req)?,
        signal_from_parent: req.boolean("from_parent")?,
        signal_delivery: match text("delivery") {
            Some(v) => Some(parse_delivery(&v)?),
            None => None,
        },
    };

    let evidence = FabricatedEvidence {
        exe: text("exe"),
        cmdline: text("cmdline"),
        cgroup: text("cgroup"),
    };

    let ops = match text("ops") {
        Some(v) => parse_int32(&v).ok_or_else(|| anyhow::anyhow!("ops={v:?} is not a count"))?,
        None => 1,
    };

    Ok(Scenario {
        cfg: cfg.clone(),
        ev,
        evidence,
        ops: ops.clamp(1, 1_000_000),
    })
}

fn aux_for(req: &Request) -> Result<u32> {
    let aux = match req.kind {
        // The signal number, lethal or not, rides in `aux`.
        Kind::Signal => num_or_name(req, "signal", SIGNAL_NAMES)?,
        Kind::Ptrace => match req.get("mode") {
            Some("read") => PTRACE_MODE_READ,
            Some("attach") => PTRACE_MODE_READ | PTRACE_MODE_ATTACH,
            Some(other) => parse_int32(other).ok_or_else(|| {
                anyhow::anyhow!("mode={other:?} is not read, attach, or a mode bitmask")
            })?,
            None => 0,
        },
        Kind::File => match req.get("op") {
            Some("rename") => FileOp::Rename as u32,
            Some("unlink") => FileOp::Unlink as u32,
            Some(other) => {
                bail!("op={other:?} is not rename or unlink — a file record names one of the two destructive ops")
            }
            None => 0,
        },
        Kind::Service => match req.get("op") {
            Some("create") | None => ServiceOp::Create as u32,
            Some(other) => {
                bail!("op={other:?} is not create — a service record only carries one operation")
            }
        },
        Kind::Module => req.num("taints")? as u32,
        Kind::BpfLoad => req.num("bpf_cmd")? as u32,
        // A bind mount is the flag the detector tests; a false one falls through
        // to the `_` arm, which is the same zero this used to spell as an if/else.
        Kind::Mount if req.boolean("bind")? => MS_BIND,
        _ => 0,
    };
    Ok(aux)
}

/// Signal names the detector can name, with their numbers, so `signal=SIGKILL`
/// and `signal=9` mean the same thing. A number is accepted either way.
const SIGNAL_NAMES: &[(&str, u32)] = &[
    ("SIGHUP", 1),
    ("SIGINT", 2),
    ("SIGQUIT", 3),
    ("SIGABRT", 6),
    ("SIGKILL", 9),
    ("SIGTERM", 15),
    ("SIGSTOP", 19),
];

fn num_or_name(req: &Request, key: &str, table: &[(&str, u32)]) -> Result<u32> {
    match req.get(key) {
        Some(v) => {
            if let Some((_, n)) = table.iter().find(|(name, _)| name.eq_ignore_ascii_case(v)) {
                return Ok(*n);
            }
            parse_int32(v).ok_or_else(|| {
                anyhow::anyhow!(
                    "{key}={v:?} is neither a number nor a name this command knows ({})",
                    table.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                )
            })
        }
        None => Ok(0),
    }
}

fn parse_protocol(v: &str) -> Result<Protocol> {
    Ok(match v.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        "other" => Protocol::Other,
        _ => bail!(
            "proto={v:?} is not one of: {}",
            Protocol::ALL
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

fn parse_delivery(v: &str) -> Result<SignalDelivery> {
    // The same seven labels the finding carries, so an operator can paste what a
    // journal line said straight back into this command.
    let found = SignalDelivery::ALL
        .iter()
        .copied()
        .find(|d| d.as_str() == v.to_ascii_lowercase());
    found.ok_or_else(|| {
        anyhow::anyhow!(
            "delivery={v:?} is not one of: {}",
            SignalDelivery::ALL
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn creds_for(req: &Request) -> Result<Option<CredChange>> {
    if req.kind != Kind::Creds {
        return Ok(None);
    }
    // Every field defaults to 0, which is the *shape the kernel would not send*
    // (a real CREDS record is a change), so a creds event with no fields named is
    // a no-op transition and the detector declines it. That is the honest
    // starting point: the operator has to say what changed.
    Ok(Some(CredChange {
        old_uid: req.num("old_uid")? as u32,
        new_uid: req.num("new_uid")? as u32,
        cap_old: req.num("cap_old")?,
        cap_new: req.num("cap_new")?,
    }))
}

fn prog_type_for(req: &Request) -> Result<Option<u32>> {
    if req.kind != Kind::BpfLoad {
        return Ok(None);
    }
    let raw = match req.get("prog_type") {
        Some(v) => v,
        // Unnamed means "the attribute could not be read", which the detector
        // treats as unknown and fails toward surfacing. The `--event prog_type=`
        // form below prints the alternative rather than guessing one.
        None => return Ok(None),
    };
    if let Some((_, n)) = PROG_TYPES.iter().find(|(name, _)| *name == raw) {
        return Ok(Some(*n));
    }
    parse_int32(raw).map(Some).ok_or_else(|| {
        anyhow::anyhow!(
            "prog_type={raw:?} is neither a number nor a name this command knows ({})",
            PROG_TYPES
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// The program types an operator names rather than numbers, kept as the pairs
/// [`bpf_prog_type_name`] renders. A test in this file asserts every entry
/// round-trips, so a renamed type in `detect.rs` fails the build instead of
/// making this command refuse a spelling that used to work.
const PROG_TYPES: &[(&str, u32)] = &[
    ("unspec", 0),
    ("socket_filter", 1),
    ("kprobe", 2),
    ("sched_cls", 3),
    ("sched_act", 4),
    ("tracepoint", 5),
    ("xdp", 6),
    ("perf_event", 7),
    ("cgroup_skb", 8),
    ("cgroup_sock", 9),
    ("sock_ops", 13),
    ("sk_skb", 14),
    ("cgroup_device", 15),
    ("sk_msg", 16),
    ("raw_tracepoint", 17),
    ("cgroup_sock_addr", 18),
    ("raw_tracepoint_writable", 24),
    ("tracing", 26),
    ("struct_ops", 27),
    ("ext", 28),
    ("lsm", 29),
    ("sk_lookup", 30),
    ("syscall", 31),
    ("netfilter", 32),
];

fn access_for(req: &Request) -> Result<Option<AccessInfo>> {
    if req.kind != Kind::Access {
        return Ok(None);
    }
    let hook = match req.get("hook") {
        Some(v) => parse_hook(v)?,
        None => AccessHook::Open,
    };
    let mut intent = 0;
    for part in req
        .get("intent")
        .unwrap_or("")
        .split(['|', ',', ' '])
        .filter(|p| !p.is_empty())
    {
        intent |= match part.to_ascii_lowercase().as_str() {
            "read" | "r" => WARDEN_INTENT_READ,
            "write" | "w" => WARDEN_INTENT_WRITE,
            "exec" | "x" => WARDEN_INTENT_EXEC,
            other => bail!("intent={other:?} is not read, write or exec"),
        };
    }
    Ok(Some(AccessInfo {
        hook,
        intent,
        denied: req.boolean("denied")?,
        dev: req.num("dev")?,
        ino: req.num("ino")?,
        authorized_uid: req.num("guard_uid")? as u32,
    }))
}

fn parse_hook(v: &str) -> Result<AccessHook> {
    let found = AccessHook::ALL
        .iter()
        .copied()
        .find(|h| h.as_str() == v.to_ascii_lowercase());
    found.ok_or_else(|| {
        anyhow::anyhow!(
            "hook={v:?} is not one of: {}",
            AccessHook::ALL
                .iter()
                .map(|h| h.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

/// The probe table. Every entry changes exactly ONE thing relative to the config
/// the operator loaded, so a flip says which single knob was load-bearing rather
/// than "some combination". The list is not exhaustive and does not claim to be:
/// it covers the knobs each judge reads, and the footer says what a probe cannot
/// reach.
fn probes(s: &Scenario) -> Vec<Probe> {
    let cfg = &s.cfg;
    let ev = &s.ev;
    let evidence = &s.evidence;

    // Values the record itself carries, which is what an allowlist probe needs.
    let comm = (!ev.comm.is_empty()).then(|| ev.comm.clone());
    let path = (!ev.filename.is_empty()).then(|| ev.filename.clone());
    let exe = evidence.exe.clone();
    let exe_name = evidence.exe.as_deref().map(|p| basename(p).to_string());
    let exe_parent = evidence
        .exe
        .as_deref()
        .and_then(|p| p.rsplit_once('/').map(|(dir, _)| dir.to_string()));
    let dest = ev.dest.clone();
    let port = ev.dest.as_deref().and_then(|d| split_ip_port(d).1);

    // Attribution is the gate four different kinds share, so it is built once.
    let attribution = attribution_probes(s);

    match ev.kind {
        Kind::Exec => {
            let mut p = attribution;
            p.push(clear_list(
                "[exec_rules].shell_comms",
                cfg.exec_rules.shell_comms.is_empty(),
                |c| c.exec_rules.shell_comms.clear(),
            ));
            p.push(add_value(
                "[exec_rules].shell_comms",
                exe_name.clone(),
                |c, v| c.exec_rules.shell_comms.push(v),
            ));
            p.push(add_value(
                "[exec_rules].shell_comms",
                comm.clone(),
                |c, v| c.exec_rules.shell_comms.push(v),
            ));
            p.push(clear_list(
                "[exec_rules].untrusted_exe_prefixes",
                cfg.exec_rules.untrusted_exe_prefixes.is_empty(),
                |c| c.exec_rules.untrusted_exe_prefixes.clear(),
            ));
            p.push(add_value(
                "[exec_rules].untrusted_exe_prefixes",
                exe_parent.clone(),
                |c, v| c.exec_rules.untrusted_exe_prefixes.push(v),
            ));
            p.push(flip_bool(
                "[exec_rules].flag_deleted_exe",
                cfg.exec_rules.flag_deleted_exe,
                |c, v| c.exec_rules.flag_deleted_exe = v,
            ));
            p.push(clear_list(
                "[app].exe_allowlist",
                cfg.app.exe_allowlist.is_empty(),
                |c| c.app.exe_allowlist.clear(),
            ));
            p.push(add_value("[app].exe_allowlist", exe.clone(), |c, v| {
                c.app.exe_allowlist.push(v)
            }));
            p.push(flip_bool(
                "[respond].kill_reverse_shell",
                cfg.respond.kill_reverse_shell,
                |c, v| c.respond.kill_reverse_shell = v,
            ));
            // The suffix is what the kernel puts on the readlink, so a hypothetical
            // actor carries it only if the operator says so — hence a probe on the
            // evidence axis, and it outranks every name rule in this class.
            p.push(evidence_probe(
                exe.is_some(),
                "say the binary was deleted after exec (exe ends with \" (deleted)\")".to_string(),
                |e| {
                    if let Some(p) = e.exe.clone() {
                        if !p.ends_with("(deleted)") {
                            e.exe = Some(format!("{p} (deleted)"));
                        }
                    }
                },
            ));
            p
        }
        Kind::Connect => {
            let mut p = attribution;
            p.push(flip_bool(
                "[network_rules].app_egress_only",
                cfg.network_rules.app_egress_only,
                |c, v| c.network_rules.app_egress_only = v,
            ));
            p.push(clear_list(
                "[network_rules].egress_allow",
                cfg.network_rules.egress_allow.is_empty(),
                |c| c.network_rules.egress_allow.clear(),
            ));
            p.push(add_value(
                "[network_rules].egress_allow",
                dest.clone(),
                |c, v| c.network_rules.egress_allow.push(v),
            ));
            p.push(clear_list(
                "[network_rules].allow_ports",
                cfg.network_rules.allow_ports.is_empty(),
                |c| c.network_rules.allow_ports.clear(),
            ));
            p.push(probe(
                port.is_some(),
                format!(
                    "add port {} to [network_rules].allow_ports",
                    port.unwrap_or_default()
                ),
                move |s| {
                    if let Some(p) = s.ev.dest.as_deref().and_then(split_ip_port_for) {
                        s.cfg.network_rules.allow_ports.push(p);
                    }
                },
            ));
            p.push(flip_bool(
                "[network_rules].allow_loopback",
                cfg.network_rules.allow_loopback,
                |c, v| c.network_rules.allow_loopback = v,
            ));
            p.push(flip_bool(
                "[respond].kill_reverse_shell",
                cfg.respond.kill_reverse_shell,
                |c, v| c.respond.kill_reverse_shell = v,
            ));
            p
        }
        Kind::Listen => {
            let mut p = attribution;
            p.push(flip_bool(
                "[listen_rules].app_listen_only",
                cfg.listen_rules.app_listen_only,
                |c, v| c.listen_rules.app_listen_only = v,
            ));
            p.push(clear_list(
                "[listen_rules].allow_ports",
                cfg.listen_rules.allow_ports.is_empty(),
                |c| c.listen_rules.allow_ports.clear(),
            ));
            p.push(probe(
                port.is_some(),
                format!(
                    "add port {} to [listen_rules].allow_ports",
                    port.unwrap_or_default()
                ),
                move |s| {
                    if let Some(p) = s.ev.dest.as_deref().and_then(split_ip_port_for) {
                        s.cfg.listen_rules.allow_ports.push(p);
                    }
                },
            ));
            p.push(flip_bool(
                "[listen_rules].allow_loopback",
                cfg.listen_rules.allow_loopback,
                |c, v| c.listen_rules.allow_loopback = v,
            ));
            p.push(flip_bool(
                "[respond].kill_reverse_shell",
                cfg.respond.kill_reverse_shell,
                |c, v| c.respond.kill_reverse_shell = v,
            ));
            p
        }
        Kind::Creds => {
            let mut p = attribution;
            p.push(flip_bool(
                "[cred_rules].app_privesc_only",
                cfg.cred_rules.app_privesc_only,
                |c, v| c.cred_rules.app_privesc_only = v,
            ));
            p.push(clear_list(
                "[cred_rules].expected_privilege_comms",
                cfg.cred_rules.expected_privilege_comms.is_empty(),
                |c| c.cred_rules.expected_privilege_comms.clear(),
            ));
            p.push(add_value(
                "[cred_rules].expected_privilege_comms",
                comm.clone(),
                |c, v| c.cred_rules.expected_privilege_comms.push(v),
            ));
            p.push(flip_bool(
                "[cred_rules].flag_capability_gain",
                cfg.cred_rules.flag_capability_gain,
                |c, v| c.cred_rules.flag_capability_gain = v,
            ));
            p.push(flip_bool(
                "[respond].kill_privilege_escalation",
                cfg.respond.kill_privilege_escalation,
                |c, v| c.respond.kill_privilege_escalation = v,
            ));
            p.push(record_probe(
                true,
                "make the transition land on root (new_uid = 0)".to_string(),
                |e| {
                    if let Some(c) = &mut e.creds {
                        c.new_uid = 0;
                    }
                },
            ));
            p.push(record_probe(
                true,
                "remove the capability gain (cap_new = cap_old)".to_string(),
                |e| {
                    if let Some(c) = &mut e.creds {
                        c.cap_new = c.cap_old;
                    }
                },
            ));
            p
        }
        Kind::Ptrace => {
            // W2K-41 made `[app].cgroup_contains` a knob for this class as well:
            // whether a /proc read is called routine observation or an inspection
            // attempt now turns on the reader being provably OUTSIDE the
            // application, so the app attribution probes belong here too.
            let mut p = attribution;
            p.extend([
                clear_list(
                    "[ptrace_rules].benign_reader_comms",
                    cfg.ptrace_rules.benign_reader_comms.is_empty(),
                    |c| c.ptrace_rules.benign_reader_comms.clear(),
                ),
                add_value(
                    "[ptrace_rules].benign_reader_comms",
                    comm.clone(),
                    |c, v| c.ptrace_rules.benign_reader_comms.push(v),
                ),
                clear_list(
                    "[ptrace_rules].benign_reader_exes",
                    cfg.ptrace_rules.benign_reader_exes.is_empty(),
                    |c| c.ptrace_rules.benign_reader_exes.clear(),
                ),
                add_value("[ptrace_rules].benign_reader_exes", exe.clone(), |c, v| {
                    c.ptrace_rules.benign_reader_exes.push(v)
                }),
                flip_bool(
                    "[respond].kill_takedown_attacker",
                    cfg.respond.kill_takedown_attacker,
                    |c, v| c.respond.kill_takedown_attacker = v,
                ),
                record_probe(
                    ev.aux & PTRACE_MODE_ATTACH == 0,
                    "make it an ATTACH, not a /proc read (mode = attach)".to_string(),
                    |e| e.aux |= PTRACE_MODE_ATTACH,
                ),
                record_probe(
                    ev.aux & PTRACE_MODE_ATTACH != 0,
                    "make it a READ of /proc, not an attach (mode = read)".to_string(),
                    |e| e.aux &= !PTRACE_MODE_ATTACH,
                ),
                // The one exemption in this class that is not a config knob: a READ by
                // the guardian itself. In a live agent the number is Warden's own pid;
                // an explaining process cannot be that, so `for_explain` sets its
                // self-pid to a number no process can hold and the probe moves the
                // RECORD to that number instead.
                record_probe(
                    ev.actor_pid != IMPOSSIBLE_PID,
                    format!(
                        "make the actor Warden itself (pid = {}, which is the daemon's own slot \
                     for a live agent) and keep it a read",
                        IMPOSSIBLE_PID
                    ),
                    |e| {
                        e.actor_pid = IMPOSSIBLE_PID;
                        e.aux &= !PTRACE_MODE_ATTACH;
                    },
                ),
            ]);
            p
        }
        Kind::Signal => vec![
            flip_bool(
                "[respond].kill_takedown_attacker",
                cfg.respond.kill_takedown_attacker,
                |c, v| c.respond.kill_takedown_attacker = v,
            ),
            record_probe(
                !ev.signal_from_parent,
                "say the sender is the victim's real parent (from_parent = yes)".to_string(),
                |e| e.signal_from_parent = true,
            ),
            record_probe(
                ev.actor_pid != 0 && ev.actor_pid != ev.target_pid,
                "say the victim aimed the signal at itself (actor = target)".to_string(),
                |e| e.target_pid = e.actor_pid,
            ),
            record_probe(
                !stops_target(ev.aux),
                "make it a signal that stops the target (SIGKILL)".to_string(),
                |e| e.aux = 9,
            ),
            record_probe(
                stops_target(ev.aux),
                "make it a signal the kernel would not act on (SIGCONT)".to_string(),
                |e| e.aux = 18,
            ),
            record_probe(
                ev.signal_delivery.is_none(),
                "say the class the kernel reported (delivery = sigqueue)".to_string(),
                |e| e.signal_delivery = Some(SignalDelivery::Queue),
            ),
        ],
        Kind::Module => vec![
            clear_list(
                "[module_rules].allow_modules",
                cfg.module_rules.allow_modules.is_empty(),
                |c| c.module_rules.allow_modules.clear(),
            ),
            add_value("[module_rules].allow_modules", path.clone(), |c, v| {
                c.module_rules.allow_modules.push(v)
            }),
            record_probe(
                ev.aux & TAINT_OUT_OF_TREE_OR_UNSIGNED == 0,
                "carry the out-of-tree/unsigned taint".to_string(),
                |e| e.aux |= TAINT_OUT_OF_TREE_OR_UNSIGNED,
            ),
            record_probe(
                ev.aux & TAINT_OUT_OF_TREE_OR_UNSIGNED != 0,
                "carry no taint (an in-tree signed module)".to_string(),
                |e| e.aux &= !TAINT_OUT_OF_TREE_OR_UNSIGNED,
            ),
            severity_probe(
                "[module_rules].severity",
                &cfg.module_rules.severity,
                |c, v| c.module_rules.severity = v,
            ),
        ],
        Kind::File => {
            let mut p = attribution;
            p.push(flip_bool(
                "[file_rules].app_files_only",
                cfg.file_rules.app_files_only,
                |c, v| c.file_rules.app_files_only = v,
            ));
            p.push(clear_list(
                "[file_rules].watch_names",
                cfg.file_rules.watch_names.is_empty(),
                |c| c.file_rules.watch_names.clear(),
            ));
            p.push(add_value(
                "[file_rules].watch_names",
                path.clone(),
                |c, v| c.file_rules.watch_names.push(v),
            ));
            p.push(clear_list(
                "[file_rules].ransom_extensions",
                cfg.file_rules.ransom_extensions.is_empty(),
                |c| c.file_rules.ransom_extensions.clear(),
            ));
            p.push(probe(
                path.is_some(),
                "add the file's own suffix to [file_rules].ransom_extensions".to_string(),
                |s| {
                    if let Some(name) = s.ev.filename.clone().rsplit_once('.') {
                        s.cfg
                            .file_rules
                            .ransom_extensions
                            .push(format!(".{}", name.1));
                    }
                },
            ));
            p.push(probe(
                cfg.file_rules.burst_threshold > 1,
                format!(
                    "set [file_rules].burst_threshold = 1 (was {})",
                    cfg.file_rules.burst_threshold
                ),
                |s| s.cfg.file_rules.burst_threshold = 1,
            ));
            p.push(probe(
                cfg.file_rules.burst_threshold > 0,
                format!(
                    "set [file_rules].burst_threshold = 0 (the rule is {})",
                    if cfg.file_rules.burst_threshold == 0 {
                        "already off"
                    } else {
                        "on"
                    }
                ),
                |s| s.cfg.file_rules.burst_threshold = 0,
            ));
            p.push(record_probe(
                ev.aux != FileOp::Rename as u32,
                "make it a rename, not an unlink".to_string(),
                |e| e.aux = FileOp::Rename as u32,
            ));
            p.push(flip_bool(
                "[respond].kill_ransomware",
                cfg.respond.kill_ransomware,
                |c, v| c.respond.kill_ransomware = v,
            ));
            p.push(probe(
                true,
                format!("replay the record {} times in one window", s.ops + 1),
                |s| s.ops += 1,
            ));
            p
        }
        Kind::Service => vec![
            clear_list(
                "[service_rules].persistence_dirs",
                cfg.service_rules.persistence_dirs.is_empty(),
                |c| c.service_rules.persistence_dirs.clear(),
            ),
            add_value("[service_rules].persistence_dirs", path.clone(), |c, v| {
                c.service_rules.persistence_dirs.push(v)
            }),
            clear_list(
                "[service_rules].allow_paths",
                cfg.service_rules.allow_paths.is_empty(),
                |c| c.service_rules.allow_paths.clear(),
            ),
            add_value("[service_rules].allow_paths", path.clone(), |c, v| {
                c.service_rules.allow_paths.push(v)
            }),
            severity_probe(
                "[service_rules].severity",
                &cfg.service_rules.severity,
                |c, v| c.service_rules.severity = v,
            ),
        ],
        Kind::BpfLoad => {
            let mut p = attribution;
            p.push(clear_list(
                "[bpf_rules].watch_prog_types",
                cfg.bpf_rules.watch_prog_types.is_empty(),
                |c| c.bpf_rules.watch_prog_types.clear(),
            ));
            p.push(clear_list(
                "[bpf_rules].allow_loader_exes",
                cfg.bpf_rules.allow_loader_exes.is_empty(),
                |c| c.bpf_rules.allow_loader_exes.clear(),
            ));
            p.push(add_value(
                "[bpf_rules].allow_loader_exes",
                exe.clone(),
                |c, v| c.bpf_rules.allow_loader_exes.push(v),
            ));
            p.push(clear_list(
                "[bpf_rules].allow_loaders",
                cfg.bpf_rules.allow_loaders.is_empty(),
                |c| c.bpf_rules.allow_loaders.clear(),
            ));
            p.push(add_value(
                "[bpf_rules].allow_loaders",
                comm.clone(),
                |c, v| c.bpf_rules.allow_loaders.push(v),
            ));
            // W2K-18: the name list only carries a load whose exe could not be
            // read, so the pair of probes below is the only way to show that
            // sentence means something.
            p.push(evidence_probe(
                cfg.bpf_rules.allow_loaders.iter().any(|l| l == &ev.comm),
                "make the loader's executable unreadable (it exited)".to_string(),
                |e| e.exe = None,
            ));
            // W2K-29's residual was a question with no answer once the loader was
            // gone; this is the evidence that outlives it, so both directions of it
            // are probes. Stamping an identity uses the real inode of a configured
            // path — the same `stat` the engine performs when it judges — so the
            // answer stays the engine's and never a number this command invented.
            p.push(record_probe(
                ev.actor_exe_file.is_some(),
                format!(
                    "let the kernel name no file at all (this record says {})",
                    ev.actor_exe_file
                        .map(|i| i.label())
                        .unwrap_or_else(|| "nothing".to_string())
                ),
                |e| e.actor_exe_file = None,
            ));
            p.push(probe(
                ev.actor_exe_file.is_none() && !cfg.bpf_rules.allow_loader_exes.is_empty(),
                format!(
                    "have the kernel name the file the configured {} is",
                    cfg.bpf_rules
                        .allow_loader_exes
                        .first()
                        .cloned()
                        .unwrap_or_default()
                ),
                |s| {
                    let names = s.cfg.bpf_rules.allow_loader_exes.clone();
                    s.ev.actor_exe_file = names.iter().find_map(|n| ExeIdentity::of_path(n));
                },
            ));
            p.push(probe(
                true,
                "make the actor's name one on [bpf_rules].allow_loaders".to_string(),
                |s| {
                    if let Some(name) = s.cfg.bpf_rules.allow_loaders.first().cloned() {
                        s.ev.comm = name;
                    }
                },
            ));
            p.push(record_probe(
                ev.bpf_prog_type.is_some(),
                format!(
                    "read no program type at all (an unreadable attr; this record says {})",
                    ev.bpf_prog_type
                        .map(bpf_prog_type_name)
                        .unwrap_or_else(|| "nothing".to_string())
                ),
                |e| e.bpf_prog_type = None,
            ));
            p.push(probe(
                !cfg.bpf_rules.watch_prog_types.is_empty(),
                format!(
                    "load a type on [bpf_rules].watch_prog_types ({})",
                    cfg.bpf_rules
                        .watch_prog_types
                        .first()
                        .copied()
                        .map(bpf_prog_type_name)
                        .unwrap_or_default()
                ),
                |s| {
                    if let Some(t) = s.cfg.bpf_rules.watch_prog_types.first().copied() {
                        s.ev.bpf_prog_type = Some(t);
                    }
                },
            ));
            p.push(severity_probe(
                "[bpf_rules].severity",
                &cfg.bpf_rules.severity,
                |c, v| c.bpf_rules.severity = v,
            ));
            p
        }
        Kind::Mount => {
            let mut p = attribution;
            p.push(flip_bool(
                "[mount_rules].bind_only",
                cfg.mount_rules.bind_only,
                |c, v| c.mount_rules.bind_only = v,
            ));
            p.push(record_probe(
                ev.aux & MS_BIND == 0,
                "make it a bind mount (MS_BIND)".to_string(),
                |e| e.aux |= MS_BIND,
            ));
            p.push(clear_list(
                "[mount_rules].watch_sources",
                cfg.mount_rules.watch_sources.is_empty(),
                |c| c.mount_rules.watch_sources.clear(),
            ));
            p.push(add_value(
                "[mount_rules].watch_sources",
                path.clone(),
                |c, v| c.mount_rules.watch_sources.push(v),
            ));
            p.push(clear_list(
                "[mount_rules].allow_sources",
                cfg.mount_rules.allow_sources.is_empty(),
                |c| c.mount_rules.allow_sources.clear(),
            ));
            p.push(add_value(
                "[mount_rules].allow_sources",
                path.clone(),
                |c, v| c.mount_rules.allow_sources.push(v),
            ));
            p.push(clear_list(
                "[mount_rules].ignore_source_prefixes",
                cfg.mount_rules.ignore_source_prefixes.is_empty(),
                |c| c.mount_rules.ignore_source_prefixes.clear(),
            ));
            p.push(clear_list(
                "[mount_rules].allow_pseudo_device_binds",
                cfg.mount_rules.allow_pseudo_device_binds.is_empty(),
                |c| c.mount_rules.allow_pseudo_device_binds.clear(),
            ));
            p.push(clear_list(
                "[mount_rules].allow_actor_exes",
                cfg.mount_rules.allow_actor_exes.is_empty(),
                |c| c.mount_rules.allow_actor_exes.clear(),
            ));
            p.push(add_value(
                "[mount_rules].allow_actor_exes",
                exe.clone(),
                |c, v| c.mount_rules.allow_actor_exes.push(v),
            ));
            p.push(clear_list(
                "[mount_rules].suppress_exempt_sources",
                cfg.mount_rules.suppress_exempt_sources.is_empty(),
                |c| c.mount_rules.suppress_exempt_sources.clear(),
            ));
            p.push(severity_probe(
                "[mount_rules].severity",
                &cfg.mount_rules.severity,
                |c, v| c.mount_rules.severity = v,
            ));
            p
        }
        Kind::Access => vec![
            record_probe(
                !ev.access.as_ref().is_some_and(|a| a.denied),
                "let the guard deny it (armed) instead of shadowing".to_string(),
                |e| {
                    if let Some(a) = &mut e.access {
                        a.denied = true;
                    }
                },
            ),
            probe(
                true,
                format!("set [enforce].arm = {}", !cfg.enforce.arm),
                |s| s.cfg.enforce.arm = !s.cfg.enforce.arm,
            ),
            probe(
                !cfg.enforce.guarded_files.is_empty(),
                format!(
                    "drop the {} guarded file(s) policy carries",
                    cfg.enforce.guarded_files.len()
                ),
                |s| s.cfg.enforce.guarded_files.clear(),
            ),
        ],
        Kind::ConnectResult | Kind::Flow => Vec::new(),
    }
}

/// The severity a finding carries for this kind comes from one config string, and
/// nothing else. Probing it is how the output says "critical is yours, not the
/// detector's" without the operator having to know which field to look at.
fn severity_probe(key: &str, now: &str, set: impl Fn(&mut Config, String) + 'static) -> Probe {
    let next = if now.eq_ignore_ascii_case("critical") {
        "medium"
    } else {
        "critical"
    };
    let owned = now.to_string();
    probe(
        true,
        format!("set {key} = \"{next}\" (it is \"{owned}\")"),
        move |s| set(&mut s.cfg, next.to_string()),
    )
}

fn split_ip_port_for(dest: &str) -> Option<u16> {
    split_ip_port(dest).1
}

/// Whether the finding's tier treats this number as a blow at all. Asked of the
/// detector's own disposition table rather than re-derived here: the arm list and
/// the severity table are different sets now, and a probe worded against the wrong
/// one offers a change that changes nothing.
fn stops_target(sig: u32) -> bool {
    crate::detect::signal_stops_target(sig)
}

/// Render one verdict the way the operator needs to read it: the Sentinel slot,
/// the tier, the sentence the agent would have logged, and the fields the finding
/// itself carries — which is where "which matcher" is answered in the engine's
/// own words rather than in a re-derived one.
fn verdict_lines(f: &Option<Finding>) -> Vec<String> {
    let mut out = Vec::new();
    match f {
        None => out.push("warden: explain: verdict: NO FINDING from this config".to_string()),
        Some(f) => {
            out.push(format!(
                "warden: explain: verdict: FINDING {} at {} — {}",
                f.event_type.as_str(),
                f.severity.as_str(),
                f.summary
            ));
            out.push(format!(
                "warden: explain: wants_kill: {} ({})",
                f.wants_kill,
                kill_reason(f)
            ));
            if let Some(obj) = f.detail.as_object() {
                for (k, v) in obj {
                    let rendered = match v {
                        serde_json::Value::String(s) => format!("{s:?}"),
                        serde_json::Value::Null => "unread".to_string(),
                        other => other.to_string(),
                    };
                    out.push(format!("warden: explain: finding carries {k} = {rendered}"));
                }
            }
        }
    }
    out
}

/// Which `[respond]` toggle is behind `wants_kill`, for the classes that have
/// one. Read from the field the detector read, not guessed from the class: the
/// two are the same config key, so this cannot disagree with the verdict above.
fn kill_reason(f: &Finding) -> String {
    use crate::detect::FindingType as F;
    let toggle = match f.event_type {
        F::ProcessCreation | F::NetworkConnect | F::ListenBackdoor => {
            "[respond].kill_reverse_shell"
        }
        F::SelfTamper => "[respond].kill_takedown_attacker",
        F::PrivilegeChange => "[respond].kill_privilege_escalation",
        F::FileTamper => "[respond].kill_ransomware",
        F::ModuleLoad | F::NewService | F::BpfLoad | F::MountEscape => {
            "report-only: no responder toggle exists for this class"
        }
        F::AccessDenied => "report-only: the kernel already denied it in-kernel",
        F::SelfDegraded => "report-only: an operational finding about Warden's own uplink",
        F::C2Beaconing => "report-only: a confidence-bearing behavioural signal, never a kill",
    };
    format!("the class's own gate is {toggle}")
}

fn echo_lines(s: &Scenario, req: &Request) -> Vec<String> {
    let mut out = vec![format!(
        "warden: explain: kind {} — judged by the same Detector::judge the running agent calls, \
         on the config loaded above.",
        req.kind.as_str()
    )];
    out.push(format!(
        "warden: explain: actor: pid={} ppid={} uid={} comm={:?}",
        s.ev.actor_pid, s.ev.actor_ppid, s.ev.actor_uid, s.ev.comm
    ));
    out.push(format!(
        "warden: explain: evidence (supplied, NOT read from /proc): exe={:?} cmdline={:?} cgroup={:?}",
        s.evidence.exe, s.evidence.cmdline, s.evidence.cgroup
    ));
    // The record line shows the fields THIS kind accepts — the same table that
    // decides what `--event` may set. Printing `path=""` for a connect, or
    // `proto=unread` for an exec, would claim the answer weighed a field that no
    // rule for this event ever reads.
    let keys = kind_keys(s.ev.kind);
    let mut record = Vec::new();
    if keys.contains(&"path") || !s.ev.filename.is_empty() {
        record.push(format!("path={:?}", s.ev.filename));
    }
    if let Some(d) = &s.ev.dest {
        record.push(format!("dest={d:?}"));
    }
    if keys.contains(&"proto") || s.ev.protocol.is_some() {
        record.push(format!(
            "proto={}",
            s.ev.protocol.map(|p| p.as_str()).unwrap_or("unread")
        ));
    }
    if matches!(s.ev.kind, Kind::Signal | Kind::Ptrace) {
        record.push(format!("target={}", s.ev.target_pid));
    }
    if s.ev.kind == Kind::Signal {
        record.push(format!("signal={}", crate::events::signal_name(s.ev.aux)));
        record.push(format!(
            "from_parent={}",
            if s.ev.signal_from_parent { "yes" } else { "no" }
        ));
        record.push(format!(
            "delivery={}",
            s.ev.signal_delivery
                .unwrap_or(SignalDelivery::User)
                .as_str()
        ));
    }
    if s.ev.kind == Kind::BpfLoad {
        record.push(format!(
            "prog_type={}",
            s.ev.bpf_prog_type
                .map(|t| format!("{} ({t})", bpf_prog_type_name(t)))
                .unwrap_or("unread".to_string())
        ));
    }
    if s.ev.kind == Kind::Mount {
        record.push(format!(
            "bind={}",
            if s.ev.aux & MS_BIND != 0 { "yes" } else { "no" }
        ));
    }
    if s.ev.kind == Kind::Module {
        record.push(format!(
            "taints={} ({})",
            s.ev.aux,
            if s.ev.aux & TAINT_OUT_OF_TREE_OR_UNSIGNED != 0 {
                "out-of-tree or unsigned"
            } else {
                "none this rule reads"
            }
        ));
    }
    if s.ev.kind == Kind::Creds {
        if let Some(c) = &s.ev.creds {
            record.push(format!(
                "uid {}→{} caps {:#018x}→{:#018x}",
                c.old_uid, c.new_uid, c.cap_old, c.cap_new
            ));
        }
    }
    if s.ev.kind == Kind::Access {
        if let Some(a) = &s.ev.access {
            record.push(format!(
                "hook={} intent={:?} denied={} guarded dev={} ino={} authorized_uid={}",
                a.hook.as_str(),
                a.intent_str(),
                a.denied,
                a.dev,
                a.ino,
                a.authorized_uid
            ));
        }
    }
    if s.ops > 1 {
        record.push(format!("replayed {} times, 1 ms apart", s.ops));
    }
    if !record.is_empty() {
        out.push(format!("warden: explain: record: {}", record.join(" ")));
    } else {
        out.push(
            "warden: explain: record: this kind carries no field the dry run reads — the \
             answer below does not depend on any --event."
                .to_string(),
        );
    }

    // A field left unset is a claim the command made on the operator's behalf, so
    // it is named rather than hidden in a default.
    let mut defaults = Vec::new();
    if s.ev.actor_pid == 0 {
        defaults.push("pid=0 (no process; pass pid= when a per-pid rule matters)");
    }
    if s.ev.comm.is_empty() {
        defaults.push("comm=\"\" (a name no name list can match)");
    }
    if s.evidence.exe.is_none() {
        defaults.push("exe absent (the strongest identity the detector has is then unread)");
    }
    if s.evidence.cgroup.is_none() {
        defaults.push("cgroup absent (attribution rules read it, and absent is not \"outside\")");
    }
    if !defaults.is_empty() {
        out.push(format!(
            "warden: explain: not supplied, and this is what that means: {}",
            defaults.join("; ")
        ));
    }
    out
}

/// What the verdict does not claim — the part the caller cannot see from a
/// one-word answer.
fn limits(cfg: &Config, kind: Kind) -> Vec<String> {
    let mut out = vec![
        "warden: explain: not claimed: this is the userspace detector's answer. Whether the \
         kernel emitted the record at all — a hook that did not attach, a ring that dropped it, \
         a sensor the config disables — is what --doctor and --check print, and a quiet journal \
         has those reasons too."
            .to_string(),
        format!(
            "warden: explain: not claimed: the responder re-checks live identity before it \
             signals (self/init, the protected set, the pid's start time through a pidfd). mode = \
             {:?}, so {} — and either way that is a decision about a process that does not exist \
             here.",
            cfg.mode,
            if cfg.mode == crate::config::Mode::Enforce {
                "a wants_kill finding would have reached the responder"
            } else {
                "nothing is signalled whatever the finding says"
            }
        ),
        "warden: explain: not claimed: the protected-pid set is not loaded, so a signal or \
         ptrace aimed at a hypothetical target is judged with the detector's fail-open — Warden \
         keeps the finding when it cannot disprove protection. The live agent fills the set from \
         [protect] and its refresh tick."
            .to_string(),
        "warden: explain: not claimed: every finding is judged and delivered, but the journal \
         LINE for a repeated actor and class is coalesced for 10 s (FindingLogThrottle), so \
         \"would produce a finding\" is not \"would print another line\"."
            .to_string(),
    ];
    if kind == Kind::Mount {
        out.push(
            "warden: explain: not claimed: a sandbox-prefixed mount source is resolved through \
             /proc/<pid>/root of the ACTOR on a live host. That read is made here against a \
             hypothetical pid, so it fails, and the unresolved branch is the one judged."
                .to_string(),
        );
    }
    if kind == Kind::Access {
        out.push(
            "warden: explain: not claimed: whether a guarded access is DENIED rather than \
             shadowed is decided in the kernel from [enforce].arm and the per-file deny masks \
             installed into the map. This command does not evaluate that; the denied= field is \
             what you assert, and [enforce] coverage is --check's line."
                .to_string(),
        );
    }
    out.push(
        "warden: explain: probes change one configured thing at a time and re-ask the engine. A \
         knob that flips the verdict when several move together — and a rule with no knob at all, \
         like the path-component boundary tests — are outside what they can show."
            .to_string(),
    );
    out
}

/// The answer, as lines the caller prints.
pub fn run(cfg: &Config, req: &Request) -> Result<Vec<String>> {
    // The same fact the config gate prints, in the journal rather than in the
    // answer: an unread key means the verdict below is Warden's response on its
    // DEFAULTS, which may not be what the operator wrote.
    if !cfg.unread_keys.is_empty() {
        log::warn!(
            "explain: this config has {} key(s) Warden never reads ({}) — the verdict below is \
             what the defaults produce, and `--check` names them",
            cfg.unread_keys.len(),
            cfg.unread_keys.join(", ")
        );
    }

    let base = scenario(cfg, req)?;
    let mut out = Vec::new();
    out.extend(echo_lines(&base, req));

    // Two kinds answer "no finding" as a documented design decision, and the
    // reader deserves the reason rather than a verdict that looks like a gap.
    match req.kind {
        Kind::ConnectResult => {
            out.push(
                "warden: explain: verdict: NO FINDING, by design: the dial's VERDICT is not a \
                 second finding. judge_connect already raises the one High record for an \
                 unsanctioned egress when the socket is aimed; raising again when the transport \
                 answers would double-count one dial, which is the flood this detector was tuned \
                 down for. The verdict belongs to the platform flow contract, not to this \
                 detector."
                    .to_string(),
            );
            return Ok(out);
        }
        Kind::Flow => {
            out.push(
                "warden: explain: verdict: NO FINDING, by design: an accepted connection is \
                 expected traffic on a host whose job is serving connections — the deployment \
                 host measured about four accepts a second in a quiet window, so a finding per \
                 accept would bury the detector. The judgement that could use the record is \
                 \"this peer is not a sanctioned listener\", and that allowlist is the platform's \
                 to own. Ask about the dial instead: --explain connect."
                    .to_string(),
            );
            return Ok(out);
        }
        _ => {}
    }

    let finding = base.judge();
    let verdict = Verdict::of(&finding);
    out.extend(verdict_lines(&finding));
    out.extend(response_lines(cfg, &finding));

    let mut flips = Vec::new();
    let mut tested = 0usize;
    let mut skipped = 0usize;
    for p in probes(&base) {
        if !p.applies {
            skipped += 1;
            continue;
        }
        tested += 1;
        let mutated = base.with(|s| (p.apply)(s));
        let other = mutated.judge();
        let other_verdict = Verdict::of(&other);
        if other_verdict == verdict {
            continue;
        }
        flips.push(describe_flip(&p.change, &verdict, &other_verdict, &other));
    }

    for line in &flips {
        out.push(line.clone());
    }
    out.push(format!(
        "warden: explain: probes: {tested} single-knob change(s) tested, {} moved the answer; \
         {skipped} skipped because the knob is already there or the value was never given{}",
        flips.len(),
        if tested == 0 {
            " (this kind has no configured knob to move — the answer is in the record, not the policy)"
        } else {
            "."
        }
    ));
    out.extend(limits(cfg, req.kind));
    Ok(out)
}

fn response_lines(cfg: &Config, finding: &Option<Finding>) -> Vec<String> {
    let Some(f) = finding else {
        return Vec::new();
    };
    if !f.wants_kill {
        return vec![
            "warden: explain: response: nothing signalled — the detector set wants_kill=false for \
             this finding, which is the second of the responder's three gates and holds whatever \
             mode says."
                .to_string(),
        ];
    }
    vec![format!(
        "warden: explain: response: mode={:?} and this finding wants a kill — {} The responder's \
         remaining checks (self/init, the protected set, the pid still naming this process) are \
         answered by live state, so this is as far as a dry run goes.",
        cfg.mode,
        if cfg.mode == crate::config::Mode::Enforce {
            "in enforce the responder would be invoked for pid the record names."
        } else {
            "in observe nothing is signalled; the kill is armed by mode = \"enforce\"."
        }
    )]
}

fn describe_flip(
    change: &str,
    before: &Verdict,
    after: &Verdict,
    finding: &Option<Finding>,
) -> String {
    // Four shapes, named differently, because "it changed" is not the answer the
    // operator wants: which way it changed is the whole point.
    let lead = match (before.fires(), after.fires()) {
        (false, true) => "GATE",
        (true, false) => "SILENCED",
        (a, b) if a == b && before.severity != after.severity => "SEVERITY",
        (a, b) if a == b && before.wants_kill != after.wants_kill => "RESPONSE",
        _ => "CHANGED",
    };
    let to = match (lead, finding.as_ref()) {
        ("GATE", Some(f)) => format!(
            "→ {} at {} — {}",
            f.event_type.as_str(),
            f.severity.as_str(),
            f.summary
        ),
        ("SILENCED", _) => "→ no finding".to_string(),
        ("SEVERITY", Some(f)) => format!(
            "→ {} at {} instead",
            f.event_type.as_str(),
            f.severity.as_str()
        ),
        ("RESPONSE", Some(f)) => format!("→ wants_kill={}", f.wants_kill),
        _ => "→ a different answer".to_string(),
    };
    format!("warden: explain: {lead}: {change} {to}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn base_cfg() -> Config {
        Config::safe_default()
    }

    fn req(kind: &str, fields: &[&str]) -> Request {
        let raw: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        Request::parse(kind, &raw).unwrap()
    }

    fn ask(cfg: &Config, kind: &str, fields: &[&str]) -> Vec<String> {
        run(cfg, &req(kind, fields)).unwrap()
    }

    #[test]
    fn a_misspelled_kind_or_key_is_refused_not_ignored() {
        let err = Request::parse("conect", &[]).err().unwrap().to_string();
        assert!(err.contains("unknown event kind"), "{err}");
        assert!(err.contains("connect"), "{err}");

        let err = Request::parse("exec", &["dest=1.2.3.4:80".to_string()])
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("does not belong to kind"), "{err}");
        assert!(err.contains("connect"), "{err}");

        let err = Request::parse("exec", &["nonsense=1".to_string()])
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("not a field this command reads"), "{err}");

        let err = Request::parse("exec", &["/tmp/x".to_string()])
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("needs key=value"), "{err}");
    }

    #[test]
    fn every_kind_names_an_event_and_accepts_its_own_keys() {
        for kind in Kind::ALL {
            let names: Vec<String> = COMMON_KEYS
                .iter()
                .chain(kind_keys(kind).iter())
                .map(|k| format!("{k}=0"))
                .collect();
            let raw: Vec<String> = names.clone();
            // `=0` is a number-shaped value; text fields accept it as their text.
            let parsed = Request::parse(kind.as_str(), &raw);
            assert!(
                parsed.is_ok(),
                "{}: {:?} — {}",
                kind.as_str(),
                parsed.err().map(|e| e.to_string()),
                raw.join(" ")
            );
        }
        // And every name the command prints in its error is a kind it accepts.
        for name in KIND_NAMES {
            assert!(parse_kind(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn the_prog_type_names_round_trip_through_the_detector_own_rendering() {
        for (name, number) in PROG_TYPES {
            assert_eq!(
                bpf_prog_type_name(*number),
                *name,
                "detect.rs renamed program type {number}; explain's name list is stale"
            );
        }
    }

    #[test]
    fn an_egress_dial_out_of_the_app_cgroup_is_silenced_and_the_probe_says_so() {
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        cfg.network_rules.egress_allow = vec!["10.0.0.5:443".to_string()];
        let lines = ask(
            &cfg,
            "connect",
            &[
                "dest=203.0.113.7:443",
                "proto=tcp",
                "comm=python3",
                "cgroup=/sys/fs/cgroup/user.slice",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("NO FINDING"), "{text}");
        // The two things that flip it are the attribution itself and the flag
        // that makes attribution mandatory. Clearing [app].cgroup_contains is NOT
        // one of them: with app_egress_only on, an empty matcher list is the other
        // half of the same silence, so the probe is correctly reported as not
        // load-bearing rather than as a second gate.
        assert!(
            text.contains("GATE: say the actor IS the app (cgroup containing \"wallet\")"),
            "the evidence gate must be named: {text}"
        );
        assert!(
            text.contains("GATE: set [network_rules].app_egress_only = false"),
            "{text}"
        );
        assert!(!text.contains("clear [app].cgroup_contains →"), "{text}");
    }

    #[test]
    fn an_unnamed_app_is_the_reason_for_the_silence_and_is_named_as_the_fix() {
        // The deployment shape that loses the most coverage: a config that never
        // names its app cgroup. Every app-scoped rule then answers "no finding"
        // for every actor, and a bare "NO FINDING" would read as health. The
        // probe has to say which line would have made this a finding, and the
        // value it offers is the cgroup from the record, not an invented one.
        let cfg = base_cfg();
        assert!(cfg.app.cgroup_contains.is_empty());
        let lines = ask(
            &cfg,
            "exec",
            &[
                "path=/bin/bash",
                "comm=bash",
                "exe=/usr/bin/python3.11",
                "cgroup=/sys/fs/cgroup.slice/wallet",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("NO FINDING"), "{text}");
        assert!(
            text.contains("GATE: add \"wallet\" to [app].cgroup_contains"),
            "the unnamed app must be named as the gate: {text}"
        );
        assert!(
            !text.contains("say the actor IS the app"),
            "there is no matcher to move into a cgroup, so that probe must not be counted as tested: {text}"
        );
    }

    #[test]
    fn a_number_copied_out_of_a_finding_is_re_enterable() {
        // The detector renders capability masks and taints as `{:#018x}`, so the
        // hex an operator reads in a journal line is the same spelling `--event`
        // has to accept. A dry run that refused its own output would answer only
        // questions nobody has to ask.
        assert_eq!(parse_int("4096"), Some(4096));
        assert_eq!(parse_int("0x1ffffffffff"), Some(2_199_023_255_551));
        assert_eq!(parse_int("0X2000"), Some(8192));
        assert_eq!(parse_int("0b1000"), Some(8));
        assert_eq!(parse_int("0o755"), Some(493));
        assert_eq!(parse_int(""), None);
        assert_eq!(parse_int("0x"), None);
        assert_eq!(parse_int("wallet"), None);
        assert_eq!(parse_int32("4294967296"), None, "too wide for a wire u32");

        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        cfg.cred_rules.app_privesc_only = false;
        let lines = ask(
            &cfg,
            "creds",
            &[
                "old_uid=1000",
                "new_uid=0",
                "cap_old=0x0",
                "cap_new=0x1ffffffffff",
                "comm=bash",
                "cgroup=/sys/fs/cgroup.slice/wallet",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("FINDING endpoint:privilege_change"), "{text}");
        assert!(
            text.contains("uid 1000→0 caps 0x0000000000000000→0x000001ffffffffff"),
            "the hex the operator typed is what the record echoes back: {text}"
        );
    }

    #[test]
    fn the_record_line_shows_only_the_fields_this_kind_carries() {
        let cfg = base_cfg();
        let record = |kind: &str, fields: &[&str]| -> String {
            ask(&cfg, kind, fields)
                .into_iter()
                .find(|l| l.contains("explain: record:"))
                .unwrap()
        };
        // An exec has no protocol and no destination, so neither may appear; a
        // connect has no path, and printing `path=""` would claim the rule looked
        // at a field nothing reads for this kind.
        let exec = record("exec", &["path=/bin/bash"]);
        assert!(exec.contains("path=\"/bin/bash\""), "{exec}");
        assert!(!exec.contains("proto="), "{exec}");
        assert!(!exec.contains("taints="), "{exec}");
        let connect = record("connect", &["dest=203.0.113.7:443", "proto=tcp"]);
        assert!(connect.contains("dest=\"203.0.113.7:443\""), "{connect}");
        assert!(connect.contains("proto=tcp"), "{connect}");
        assert!(!connect.contains("path="), "{connect}");
    }

    #[test]
    fn an_unsanctioned_dial_fires_and_the_allowlist_probe_shows_how_to_silence_it() {
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        let lines = ask(
            &cfg,
            "connect",
            &[
                "dest=203.0.113.7:443",
                "proto=tcp",
                "comm=python3",
                "cgroup=/sys/fs/cgroup/wallet.slice/app",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("endpoint:network_connect"), "{text}");
        assert!(text.contains("egress_not_allowlisted"), "{text}");
        assert!(
            text.contains("SILENCED: add \"203.0.113.7:443\" to [network_rules].egress_allow"),
            "the operator needs the sanctioning knob: {text}"
        );
    }

    #[test]
    fn the_shell_exec_needs_both_the_name_and_the_attribution_and_each_is_a_probe() {
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        // Name matches, attribution does not.
        let lines = ask(
            &cfg,
            "exec",
            &["exe=/bin/bash", "comm=bash", "cgroup=/sys/fs/cgroup/other"],
        );
        let text = lines.join("\n");
        assert!(text.contains("NO FINDING"), "{text}");
        assert!(text.contains("GATE: say the actor IS the app"), "{text}");

        // Both halves: the finding then carries which identity matched.
        let lines = ask(
            &cfg,
            "exec",
            &[
                "exe=/bin/bash",
                "comm=bash",
                "cgroup=/sys/fs/cgroup/wallet.slice/app",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("endpoint:process_creation"), "{text}");
        assert!(text.contains("matched_by = \"exe\""), "{text}");
        assert!(text.contains("matched_name = \"bash\""), "{text}");
        assert!(
            text.contains("SILENCED: clear [exec_rules].shell_comms"),
            "{text}"
        );
    }

    #[test]
    fn the_deleted_exe_outranks_the_name_match_and_is_visible_without_a_config_change() {
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        let lines = ask(
            &cfg,
            "exec",
            &[
                "exe=/tmp/agent (deleted)",
                "comm=agent",
                "cgroup=/sys/fs/cgroup/wallet.slice/app",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("fileless execution"), "{text}");
        assert!(text.contains("deleted_exe"), "{text}");
        assert!(
            text.contains("SEVERITY: set [exec_rules].flag_deleted_exe = false"),
            "{text}"
        );
    }

    #[test]
    fn a_bpf_load_from_a_readable_exe_is_not_authorized_by_its_name() {
        let mut cfg = base_cfg();
        cfg.bpf_rules.allow_loaders = vec!["systemd".to_string()];
        cfg.bpf_rules.watch_prog_types = vec![29];
        let lines = ask(
            &cfg,
            "bpfload",
            &[
                "comm=systemd",
                "exe=/usr/lib/systemd/systemd",
                "prog_type=lsm",
            ],
        );
        let text = lines.join("\n");
        assert!(text.contains("endpoint:bpf_load"), "{text}");
        assert!(
            text.contains("comm_allowlisted = true"),
            "the W2K-18 tell must be printed: {text}"
        );
        assert!(
            text.contains(
                "SILENCED: add \"/usr/lib/systemd/systemd\" to [bpf_rules].allow_loader_exes"
            ),
            "{text}"
        );
    }

    #[test]
    fn the_signal_probe_reports_the_self_directed_downgrade_as_an_event_change_not_a_knob() {
        let mut cfg = base_cfg();
        cfg.respond.kill_takedown_attacker = true;
        let lines = ask(&cfg, "signal", &["pid=4711", "target=99", "signal=SIGKILL"]);
        let text = lines.join("\n");
        assert!(text.contains("endpoint:self_tamper"), "{text}");
        assert!(text.contains("wants_kill: true"), "{text}");
        assert!(
            text.contains("RESPONSE:") || text.contains("SILENCED:"),
            "actor=target changes the kill or the tier: {text}"
        );
    }

    #[test]
    fn a_file_burst_needs_replays_and_the_threshold_probe_shows_the_number() {
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        cfg.file_rules.burst_threshold = 3;
        let fields = [
            "pid=4711",
            "op=unlink",
            "path=ledger-1.csv",
            "cgroup=/sys/fs/cgroup/wallet.slice/app",
        ];
        let one = ask(&cfg, "file", &fields);
        assert!(one.join("\n").contains("NO FINDING"), "{}", one.join("\n"));
        let many = ask(&cfg, "file", &[&fields[..], &["ops=3"]].concat());
        assert!(
            many.join("\n").contains("modification_burst"),
            "{}",
            many.join("\n")
        );
    }

    #[test]
    fn connect_result_and_flow_answer_with_their_design_reason_not_a_bare_no() {
        let cfg = base_cfg();
        let text = ask(&cfg, "connect_result", &[]).join("\n");
        assert!(text.contains("by design"), "{text}");
        assert!(text.contains("double-count"), "{text}");

        let text = ask(&cfg, "flow", &[]).join("\n");
        assert!(text.contains("by design"), "{text}");
        assert!(!text.contains("probes:"), "{text}");
    }

    /// The test above pins the wording; this one pins the *claim* underneath it.
    /// "No finding, by design" is a statement about the detector, and it stays true
    /// only as long as `judge` declines these two kinds — so ask the detector
    /// directly. If a rule is ever added for `CONNECT_RESULT`/`FLOW`, the by-design
    /// line becomes a lie an operator would act on, and this is where it fails.
    #[test]
    fn the_two_by_design_kinds_are_unfireable_in_the_detector_too() {
        let cfg = base_cfg();
        for kind in ["connect_result", "flow"] {
            let sc = scenario(&cfg, &req(kind, &[]))
                .unwrap_or_else(|e| panic!("{kind} takes no fields, so it must build: {e}"));
            assert!(
                sc.judge().is_none(),
                "`--explain {kind}` answers \"never a finding, by design\" while the detector \
                 now raises one: the design line has to be rewritten or the rule removed"
            );
        }
    }

    /// Six kinds were only ever driven through the prefix walk: `run` executed on
    /// them, but no test said what the detector answers. Each gets a firing and a
    /// silent event here at the smallest field set `Config::safe_default()` makes
    /// deterministic — and `access` gets its odd truth stated rather than left as a
    /// missing case, because it has no silent event this command can build.
    #[test]
    fn the_six_kinds_that_never_had_a_verdict_answer_with_one() {
        fn fires(kind: &str, fields: &[&str], cfg: &Config) -> bool {
            scenario(cfg, &req(kind, fields))
                .unwrap_or_else(|e| panic!("{kind} {fields:?} must parse: {e}"))
                .judge()
                .is_some()
        }

        let mut cfg = base_cfg();
        // `listen` is app-scoped by default, and a fabricated request carries no
        // cgroup, so under the untouched default every listener answers None for the
        // wrong reason. The host-wide stance is what makes the rule reachable here —
        // and the default being the other way is itself pinned, so this test cannot
        // silently start answering a different question.
        assert!(
            base_cfg().listen_rules.app_listen_only,
            "the shipped default is app-scoped; if that changed, the setup below is stale"
        );
        cfg.listen_rules.app_listen_only = false;

        let firing: [(&str, &[&str]); 6] = [
            ("ptrace", &["target=99", "mode=attach"][..]),
            ("module", &["path=evil_implant"][..]),
            ("service", &["path=/etc/systemd/system/evil.service"][..]),
            ("listen", &["dest=0.0.0.0:4444", "proto=tcp"][..]),
            ("mount", &["path=/root", "bind=true"][..]),
            (
                "access",
                &["denied=true", "dev=2049", "ino=123", "guard_uid=1000"][..],
            ),
        ];
        for (kind, fields) in firing {
            assert!(
                fires(kind, fields, &cfg),
                "{kind} with {fields:?} must raise a finding"
            );
        }

        let silent: [(&str, &[&str]); 5] = [
            // a routine /proc reader doing a read, not an attach.
            ("ptrace", &["target=99", "mode=read", "comm=fuser"][..]),
            // allowlisted name AND clean taints — the pair, not either half.
            ("module", &["path=nf_conntrack"][..]),
            ("service", &["path=/etc/passwd"][..]),
            // loopback, which `allow_loopback` exempts.
            ("listen", &["dest=127.0.0.1:4444", "proto=tcp"][..]),
            // `bind_only`: a plain mount is not an escape candidate.
            ("mount", &["path=/root"][..]),
        ];
        for (kind, fields) in silent {
            assert!(
                !fires(kind, fields, &cfg),
                "{kind} with {fields:?} must stay silent"
            );
        }

        // The name-collision spoof stays a finding: an allowlisted name carrying the
        // out-of-tree bit. This is the half of the module rule that the pair above
        // would hide if it were written as "in the allowlist ⇒ silent".
        assert!(
            fires("module", &["path=nf_conntrack", "taints=4096"], &cfg),
            "an out-of-tree module borrowing an allowlisted name must not pass"
        );

        // `access_for` returns `Some` for every access request, so even a record with
        // no fields at all is an access record — Medium, because nothing was denied.
        assert!(
            fires("access", &[], &cfg),
            "an access event with no fields must still be judged, not declined"
        );
        // The only silent path in `judge_access` is a record carrying no access
        // payload. The kernel never sends one, and this command cannot build one, so
        // it is pinned directly rather than left implied.
        let sc = scenario(&cfg, &req("access", &["denied=true"])).unwrap();
        let mut bare = sc.ev.clone();
        bare.access = None;
        assert!(
            Detector::for_explain(sc.cfg.clone(), sc.evidence.clone())
                .judge(&bare)
                .is_none(),
            "a record with no access payload must be the only thing that declines \
             judge_access — anything else and the firing set above is an accident"
        );
    }

    /// `delivery=` is the one key whose whole job is to name a class the record
    /// carries, and nothing drove it: an operator pasting `aio_or_usb` from a journal
    /// line today gets either an answer or a refusal that names every accepted label.
    #[test]
    fn a_delivery_label_from_a_journal_line_is_re_enterable_and_a_wrong_one_is_refused_by_name() {
        let cfg = base_cfg();
        for label in SignalDelivery::ALL.iter().map(|d| d.as_str()) {
            let delivery = format!("delivery={label}");
            let lines = ask(
                &cfg,
                "signal",
                &["pid=4711", "target=99", "signal=SIGKILL", delivery.as_str()],
            );
            assert!(
                lines
                    .iter()
                    .any(|l| l.starts_with("warden: explain: verdict:")),
                "delivery={label} produced no verdict: {lines:#?}"
            );
        }
        // `Request::parse` owns key NAMES; the value check is downstream, in the
        // build of the record. Asking parse alone would pass on a command that
        // accepted the typo and then silently dropped it.
        let err = scenario(&cfg, &req("signal", &["pid=4711", "delivery=killish"]))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("delivery=\"killish\" is not one of"), "{err}");
        for label in SignalDelivery::ALL.iter().map(|d| d.as_str()) {
            assert!(
                err.contains(label),
                "the refusal must print every accepted label so the fix is copyable; {label} \
                 is missing: {err}"
            );
        }
    }

    #[test]
    fn the_verdict_comes_from_the_same_function_the_daemon_calls() {
        // The whole contract of this module: `--explain` re-implements no rule,
        // so its answer IS `Detector::judge` on the same config and the same
        // evidence. If a future change makes explain compute a verdict of its
        // own, this stops holding.
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        cfg.network_rules.app_egress_only = true;
        let evidence = FabricatedEvidence {
            exe: Some("/usr/bin/python3.11".to_string()),
            cmdline: Some("gunicorn".to_string()),
            cgroup: Some("/sys/fs/cgroup/wallet.slice/app".to_string()),
        };
        let mut ev = Event {
            kind: Kind::Connect,
            actor_pid: 4711,
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 0,
            ts_ns: 0,
            comm: "gunicorn".to_string(),
            filename: String::new(),
            dest: Some("203.0.113.7:443".to_string()),
            protocol: Some(Protocol::Tcp),
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        };
        ev.ts_ns = 0;
        let direct = Detector::for_explain(cfg.clone(), evidence.clone()).judge(&ev);

        let lines = ask(
            &cfg,
            "connect",
            &[
                "pid=4711",
                "ppid=1",
                "uid=33",
                "comm=gunicorn",
                "exe=/usr/bin/python3.11",
                "cmdline=gunicorn",
                "cgroup=/sys/fs/cgroup/wallet.slice/app",
                "dest=203.0.113.7:443",
                "proto=tcp",
            ],
        )
        .join("\n");
        let direct = direct.expect("the engine says finding");
        assert!(
            lines.contains(direct.severity.as_str()),
            "explain's tier {:?} vs engine {:?}",
            lines,
            direct.severity
        );
        assert!(
            lines.contains(&direct.summary),
            "explain must print the engine's own sentence, not a paraphrase"
        );
    }

    #[test]
    fn an_explain_bpfload_reads_the_pasted_pair_back_as_the_kernel_named_verdict() {
        // The loop an operator actually walks. A finding prints
        // `loader_exe_dev`/`loader_exe_ino`; `--explain` takes the same two keys
        // (`exe_dev=`/`exe_ino=`); pasting the numbers back must reproduce the same
        // sentence, which is only true if the scenario builder folds them into the
        // same field the engine reads and the engine's precedence is unchanged.
        // `ino = 0` has to keep its own answer too: it is the no-claim encoding, not
        // a file called inode zero, and the posture before this stage was built on
        // it.
        let mut cfg = base_cfg();
        cfg.bpf_rules.allow_loader_exes = vec!["/bin/cat".to_string()];
        let authorised = ExeIdentity::of_path("/bin/cat").expect("/bin/cat resolves");
        let stranger = ExeIdentity::of_path("/bin/true").expect("/bin/true resolves");
        assert_ne!(
            authorised, stranger,
            "the test needs two files that are not each other"
        );
        let _ = authorised;

        // (1) An allowlisted comm and no kernel claim — the weak name-only pass,
        //     untouched by this stage, and nothing in it quoting a file.
        let quiet = ask(
            &cfg,
            "bpfload",
            &["pid=4294967295", "comm=warden", "prog_type=2", "exe_ino=0"],
        )
        .join("\n");
        assert!(quiet.contains("NO FINDING"), "{quiet}");
        assert!(
            !quiet.contains("the kernel named"),
            "a record that claims no inode must not be read as a file: {quiet}"
        );

        // (2) The same comm, and now the hook named a file that is not the
        //     authorised one. The conviction is the engine's own sentence, and the
        //     numbers in it are the numbers that went in.
        let loud = ask(
            &cfg,
            "bpfload",
            &[
                "pid=4294967295",
                "comm=warden",
                "prog_type=2",
                &format!("exe_dev={}", stranger.dev),
                &format!("exe_ino={}", stranger.ino),
            ],
        )
        .join("\n");
        assert!(loud.contains("from a file the kernel named"), "{loud}");
        assert!(loud.contains(&stranger.label()), "{loud}");
        assert!(loud.contains("dev/ino"), "{loud}");
        // With a claim in the record, taking it away must move the answer back to
        // the name-only pass — otherwise this command would be showing an operator
        // a knob that is not there.
        assert!(
            loud.contains("let the kernel name no file at all"),
            "{loud}"
        );

        // (3) The other direction, on a name that is not allowlisted: with nothing
        //     claimed, stamping the inode of a configured path has to be offered,
        //     and it has to move the answer to silence.
        let unclaimed = ask(
            &cfg,
            "bpfload",
            &["pid=4294967295", "comm=evil", "prog_type=2"],
        )
        .join("\n");
        assert!(
            unclaimed.contains("have the kernel name the file the configured /bin/cat is"),
            "{unclaimed}"
        );
    }

    #[test]
    fn an_unread_cgroup_and_an_absent_cgroup_are_not_the_same_answer() {
        // Three-state honesty again, on the evidence axis: "no cgroup given" must
        // not read as "outside the app". The command prints what it means.
        let mut cfg = base_cfg();
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        let text = ask(&cfg, "connect", &["dest=203.0.113.7:443", "proto=tcp"]).join("\n");
        assert!(
            text.contains("cgroup absent"),
            "the default must be named: {text}"
        );
        assert!(text.contains("NO FINDING"), "{text}");
    }

    #[test]
    fn every_line_is_prefixed_so_the_output_can_be_grepped_or_piped_as_one_voice() {
        let cfg = base_cfg();
        for kind in Kind::ALL {
            let fields: Vec<String> = match kind {
                Kind::Creds => vec!["old_uid=33".to_string(), "new_uid=0".to_string()],
                Kind::Access => vec!["hook=open".to_string(), "intent=read".to_string()],
                Kind::Mount => vec!["path=/dev".to_string(), "bind=yes".to_string()],
                _ => vec![],
            };
            let raw = fields;
            let r = Request::parse(kind.as_str(), &raw).unwrap();
            for line in run(&cfg, &r).unwrap() {
                assert!(line.starts_with("warden: explain: "), "{line}");
                assert!(!line.contains('\n'), "one line per claim: {line}");
            }
        }
    }

    #[test]
    fn a_probe_that_could_not_have_done_anything_is_counted_not_reported() {
        // Clearing an empty list is not evidence about a knob, and printing it as
        // "changed nothing" would let an untested knob look tested.
        let cfg = base_cfg();
        let text = ask(&cfg, "connect", &["dest=203.0.113.7:443", "proto=tcp"]).join("\n");
        assert!(
            !text.contains("clear [network_rules].egress_allow\n"),
            "{text}"
        );
        let line = text
            .lines()
            .find(|l| l.contains("probes:"))
            .expect("the probe count is always printed");
        assert!(line.contains("skipped"), "{line}");
    }

    #[test]
    fn the_mode_line_says_what_the_responder_would_have_been_asked_for() {
        let mut cfg = base_cfg();
        cfg.mode = crate::config::Mode::Enforce;
        cfg.app.cgroup_contains = vec!["wallet".to_string()];
        cfg.respond.kill_reverse_shell = true;
        let text = ask(
            &cfg,
            "connect",
            &[
                "dest=203.0.113.7:443",
                "proto=tcp",
                "comm=python3",
                "cgroup=/sys/fs/cgroup/wallet.slice/app",
            ],
        )
        .join("\n");
        assert!(text.contains("mode=Enforce"), "{text}");
        assert!(text.contains("would be invoked"), "{text}");
        assert!(text.contains("live state"), "{text}");
    }
}
