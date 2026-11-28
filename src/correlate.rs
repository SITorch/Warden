//! correlate.rs — bounded, privilege-free joins of kernel observations.
//!
//! A single event is often ambiguous in a way that two events are not: an exec
//! of a shell is only a shell, a dial is only a dial, but a shell followed by an
//! unsanctioned dial from the same pid is reverse-shell evidence. This module
//! makes those joins. It adds no kernel program, no ABI field and no privilege:
//! it consumes the same decoded `Event` and the finding the ordinary judge
//! already produced, and returns at most one additional finding per event.
//!
//! Three rules keep this honest:
//!
//! 1. **Only judged evidence anchors a chain.** A raw exec or connect that the
//!    detector judged benign never becomes an anchor. The correlator does not
//!    re-run a judge (which would mutate the C2 tracker a second time), it
//!    consumes the judge's answer.
//! 2. **No clock, no chain.** Anchors and triggers are stamped with the kernel's
//!    monotonic `ts_ns`. A zero timestamp, a backwards timestamp, or an age
//!    beyond the window means no match — never an inferred one.
//! 3. **A chain is evidence, never authority.** `wants_kill` is false for every
//!    chain, and nothing here changes what the responder or the egress gate may
//!    do. A chain is also emitted at most once per anchor, so a stream of
//!    verdicts for one dial cannot multiply a single finding.
//!
//! The state is bounded twice: a fixed number of anchors per actor and a fixed
//! number of actors. Eviction is deterministic and fails closed — dropping an
//! anchor can lose a chain, but can never invent one.

use crate::config::CorrelationRules;
use crate::detect::{Finding, FindingType, ProcessInfo, Severity};
use crate::events::{Event, Kind};
use serde_json::json;
use std::collections::{HashMap, VecDeque};

/// How many anchors one pid may hold. Four chain rules plus headroom: enough
/// for a real sequence, bounded against a hostile event flood.
const MAX_ANCHORS_PER_ACTOR: usize = 8;

/// The joins this build ships. These strings are written into the envelope's
/// `detail.chain` and mirrored in the operator docs, so they are append-only:
/// renaming one is a breaking change for a downstream consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    /// A judged suspicious exec followed by a judged unsanctioned dial from
    /// the same pid (reverse-shell / staged downloader shape).
    SuspiciousExecThenEgress,
    /// A judged privilege raise followed by a persistence write, module load
    /// or BPF load from the same pid (post-exploitation foothold shape).
    PrivilegeThenPersistence,
    /// A judged bind-shell listener followed by a kernel-accepted connection
    /// on that exact local port (the listener actually served a peer).
    SuspiciousListenerAccepted,
    /// A judged unsanctioned dial followed by the kernel's `Established`
    /// verdict for that exact destination (the egress was not merely attempted).
    UnsanctionedDialEstablished,
}

impl ChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainKind::SuspiciousExecThenEgress => "suspicious_exec_then_egress",
            ChainKind::PrivilegeThenPersistence => "privilege_then_persistence",
            ChainKind::SuspiciousListenerAccepted => "suspicious_listener_accepted",
            ChainKind::UnsanctionedDialEstablished => "unsanctioned_dial_established",
        }
    }

    /// Deliberately capped at High. A join is stronger evidence than either
    /// half alone, but it is still not a kernel denial or a confirmed compromise,
    /// so it never reaches Critical or requests a kill.
    pub fn severity(self) -> Severity {
        match self {
            ChainKind::SuspiciousExecThenEgress | ChainKind::PrivilegeThenPersistence => {
                Severity::High
            }
            ChainKind::SuspiciousListenerAccepted | ChainKind::UnsanctionedDialEstablished => {
                Severity::Medium
            }
        }
    }
}

/// One completed join. `first_ts_ns`/`second_ts_ns` are the kernel timestamps
/// of the two observations, both carried onto the finding's clock lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainMatch {
    pub kind: ChainKind,
    pub actor_pid: u32,
    pub first_ts_ns: u64,
    pub second_ts_ns: u64,
    pub dest: Option<String>,
    pub local_port: Option<u16>,
}

impl ChainMatch {
    /// A summary built only from kernel-observed facts: a pid, an endpoint and
    /// the two events. No comm, exe, cmdline, credential or payload is included,
    /// so this text is safe in the remote envelope and would still be safe if an
    /// operator pasted it into a local note.
    pub fn summary(&self) -> String {
        let where_to = self
            .dest
            .as_deref()
            .unwrap_or("an endpoint the kernel did not decode");
        match self.kind {
            ChainKind::SuspiciousExecThenEgress => format!(
                "attack chain: a suspicious exec was followed by unsanctioned egress \
                 from pid {} to {} within the correlation window",
                self.actor_pid, where_to
            ),
            ChainKind::PrivilegeThenPersistence => format!(
                "attack chain: pid {} raised privileges and then wrote a persistence \
                 location / loaded a module / loaded a BPF program within the correlation \
                 window",
                self.actor_pid
            ),
            ChainKind::SuspiciousListenerAccepted => format!(
                "attack chain: a suspicious listener on port {} accepted a connection \
                 from {} (pid {}) within the correlation window",
                self.local_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "an unknown port".into()),
                where_to,
                self.actor_pid
            ),
            ChainKind::UnsanctionedDialEstablished => format!(
                "attack chain: an unsanctioned dial from pid {} to {} was confirmed \
                 established by the kernel's connect verdict within the correlation window",
                self.actor_pid, where_to
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnchorKind {
    SuspiciousExec,
    UnsanctionedConnect,
    SuspiciousListen,
    PrivilegeChange,
}

#[derive(Clone)]
struct Anchor {
    kind: AnchorKind,
    ts_ns: u64,
    /// `/proc` start time captured on the anchor's own finding. When both halves
    /// of a chain carry one, they must agree: a recycled pid cannot inherit an
    /// earlier process's suspicious history.
    starttime: Option<u64>,
    dest: Option<String>,
    local_port: Option<u16>,
}

/// A pid is only a number; `/proc` start time is the identity behind it. When
/// both halves carry a start time, require equality. When either is unknown
/// (`hidepid=`, or a verdict event with no finding to enrich), fall back to the
/// kernel timestamp and endpoint rather than losing a real chain — the window
/// stays bounded either way.
fn same_process(anchor: Option<u64>, current: Option<u64>) -> bool {
    match (anchor, current) {
        (Some(a), Some(c)) => a == c,
        _ => true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trigger {
    EstablishedDial,
    AcceptedFlow,
    SuspiciousEgress,
    PostPrivilegeWrite,
}

impl Trigger {
    /// What the current event can prove. A CONNECT_RESULT only counts when the
    /// kernel reported an established transport — a refusal confirms nothing.
    fn of(e: &Event, primary: Option<&Finding>) -> Option<Self> {
        if e.kind == Kind::ConnectResult
            && e.connect_outcome.and_then(|o| o.conn_state_hint()) == Some("S1")
        {
            return Some(Trigger::EstablishedDial);
        }
        if e.kind == Kind::Flow && e.flow.is_some() {
            return Some(Trigger::AcceptedFlow);
        }
        match primary.map(|f| f.event_type) {
            // C2Beaconing is returned INSTEAD of NetworkConnect once the beacon
            // tracker clears its minimum; both mean "this dial was unsanctioned".
            Some(FindingType::NetworkConnect) | Some(FindingType::C2Beaconing) => {
                Some(Trigger::SuspiciousEgress)
            }
            Some(FindingType::NewService)
            | Some(FindingType::ModuleLoad)
            | Some(FindingType::BpfLoad) => Some(Trigger::PostPrivilegeWrite),
            _ => None,
        }
    }
}

/// Which judged event may become an anchor. The match is on the event kind as
/// well as the finding type so a finding synthesised from a different sensor
/// can never be used as the first half of a chain.
fn anchor_for(e: &Event, primary: Option<&Finding>) -> Option<AnchorKind> {
    let event_type = primary?.event_type;
    match (e.kind, event_type) {
        (Kind::Exec, FindingType::ProcessCreation) => Some(AnchorKind::SuspiciousExec),
        (Kind::Connect, FindingType::NetworkConnect | FindingType::C2Beaconing) => {
            Some(AnchorKind::UnsanctionedConnect)
        }
        (Kind::Listen, FindingType::ListenBackdoor) => Some(AnchorKind::SuspiciousListen),
        (Kind::Creds, FindingType::PrivilegeChange) => Some(AnchorKind::PrivilegeChange),
        _ => None,
    }
}

/// Which local port an event names. FLOW carries it in its folded `FlowInfo`;
/// LISTEN carries it in the rendered bound endpoint (`0.0.0.0:4444` or
/// `[::]:4444`), so the same parser must handle both address families. Every
/// other event kind reports no local port — a CONNECT's remote port is not one.
fn local_port_of(e: &Event) -> Option<u16> {
    if let Some(flow) = e.flow {
        return Some(flow.local_port);
    }
    if e.kind != Kind::Listen {
        return None;
    }
    e.dest
        .as_deref()
        .and_then(|endpoint| endpoint.rsplit_once(':'))
        .and_then(|(_, port)| port.parse::<u16>().ok())
}

/// Drop anchors that can no longer fall inside the window. A queue is kept in
/// kernel-time order, so the front is the oldest; the `now < ts` guard is a
/// second line of defence against a record that predates its own anchor.
fn prune(queue: &mut VecDeque<Anchor>, now: u64, window_ns: u64) {
    while let Some(front) = queue.front() {
        if now < front.ts_ns || now - front.ts_ns > window_ns {
            queue.pop_front();
        } else {
            break;
        }
    }
}

/// Find the first (oldest) anchor that completes a chain with this event. At
/// most one chain is emitted per event, and the caller removes that anchor so
/// one observation is never counted twice.
fn find_match(
    e: &Event,
    primary: Option<&Finding>,
    queue: &VecDeque<Anchor>,
    window_ns: u64,
) -> Option<(usize, ChainMatch)> {
    let trigger = Trigger::of(e, primary)?;
    let starttime = primary.and_then(|f| f.process.starttime);
    for (index, anchor) in queue.iter().enumerate() {
        if e.ts_ns < anchor.ts_ns || e.ts_ns - anchor.ts_ns > window_ns {
            continue;
        }
        if !same_process(anchor.starttime, starttime) {
            continue;
        }
        let kind = match (trigger, anchor.kind) {
            (Trigger::EstablishedDial, AnchorKind::UnsanctionedConnect)
                if e.dest.is_some() && anchor.dest == e.dest =>
            {
                ChainKind::UnsanctionedDialEstablished
            }
            (Trigger::AcceptedFlow, AnchorKind::SuspiciousListen)
                if anchor.local_port.is_some() && local_port_of(e) == anchor.local_port =>
            {
                ChainKind::SuspiciousListenerAccepted
            }
            (Trigger::SuspiciousEgress, AnchorKind::SuspiciousExec) => {
                ChainKind::SuspiciousExecThenEgress
            }
            (Trigger::PostPrivilegeWrite, AnchorKind::PrivilegeChange) => {
                ChainKind::PrivilegeThenPersistence
            }
            _ => continue,
        };
        return Some((
            index,
            ChainMatch {
                kind,
                actor_pid: e.actor_pid,
                first_ts_ns: anchor.ts_ns,
                second_ts_ns: e.ts_ns,
                dest: e.dest.clone().or_else(|| anchor.dest.clone()),
                local_port: local_port_of(e).or(anchor.local_port),
            },
        ));
    }
    None
}

/// The bounded state machine. `RefCell`-held by `Detector`; the event loop is
/// single-threaded, so no locking is needed.
pub struct Correlator {
    rules: CorrelationRules,
    anchors: HashMap<u32, VecDeque<Anchor>>,
    last_ts_ns: u64,
}

impl Correlator {
    pub fn new(rules: CorrelationRules) -> Self {
        Self {
            rules,
            anchors: HashMap::new(),
            last_ts_ns: 0,
        }
    }

    /// Feed one decoded event and its ordinary judge result. `None` means no
    /// chain fired; a `Some` is a new, separate finding for the caller to emit.
    pub fn observe(&mut self, e: &Event, primary: Option<&Finding>) -> Option<ChainMatch> {
        if !self.rules.enabled || e.ts_ns == 0 {
            return None;
        }
        // A backwards clock is not a short window — it is unusable evidence.
        // Drop the history rather than join across a discontinuity.
        if self.last_ts_ns != 0 && e.ts_ns < self.last_ts_ns {
            self.anchors.clear();
            self.last_ts_ns = e.ts_ns;
            return None;
        }
        self.last_ts_ns = e.ts_ns;
        let window_ns = self.rules.window_ms.saturating_mul(1_000_000);

        let matched = {
            let queue = self.anchors.entry(e.actor_pid).or_default();
            prune(queue, e.ts_ns, window_ns);
            let hit = find_match(e, primary, queue, window_ns);
            // Consume the anchor: one dial, one listener or one exec may only
            // contribute to one chain.
            if let Some((index, _)) = hit.as_ref() {
                queue.remove(*index);
            }
            // Insert after matching so an event can never chain with itself.
            if let Some(kind) = anchor_for(e, primary) {
                if queue.len() >= MAX_ANCHORS_PER_ACTOR {
                    queue.pop_front();
                }
                queue.push_back(Anchor {
                    kind,
                    ts_ns: e.ts_ns,
                    starttime: primary.and_then(|f| f.process.starttime),
                    dest: e.dest.clone(),
                    local_port: local_port_of(e),
                });
            }
            hit.map(|(_, m)| m)
        };

        // Bound the actor map. Evict the entry whose newest anchor is oldest,
        // and never the actor we just touched. On overflow we lose a possible
        // chain, never create one.
        if self.anchors.len() > self.rules.max_actors {
            let victim = self
                .anchors
                .iter()
                .filter(|(pid, _)| **pid != e.actor_pid)
                .min_by_key(|(_, q)| q.back().map(|a| a.ts_ns).unwrap_or(0))
                .map(|(pid, _)| *pid);
            if let Some(pid) = victim {
                self.anchors.remove(&pid);
            }
        }
        matched
    }

    /// Convert a match into a finding at the `Detector` layer. Kept here so the
    /// envelope's `detail` shape lives next to the chain vocabulary it describes.
    pub fn finding_for(&self, m: ChainMatch, proc: ProcessInfo, e: &Event) -> Finding {
        Finding {
            event_type: FindingType::AttackChain,
            severity: m.kind.severity(),
            summary: m.summary(),
            source_ts_ns: e.ts_ns,
            process: proc,
            target_pid: None,
            // Structural invariant: a correlation is never an authorization to kill.
            wants_kill: false,
            detail: json!({
                "chain": m.kind.as_str(),
                "first_event_ts_ns": m.first_ts_ns,
                "second_event_ts_ns": m.second_ts_ns,
                "window_ms": self.rules.window_ms,
                "destination": m.dest,
                "local_port": m.local_port,
                "first_kind": Kind::as_str(kind_of_first(&m)),
                "second_kind": e.kind.as_str(),
                "evidence": "two kernel-observed events joined in userspace; no payload, DNS or TLS metadata",
                "enforcement": "observation only; no kill requested",
            }),
        }
    }
}

/// The detail block names the first event's sensor, so an analyst can tell a
/// shell→dial chain from a privilege→persistence chain without reading prose.
fn kind_of_first(m: &ChainMatch) -> Kind {
    match m.kind {
        ChainKind::SuspiciousExecThenEgress => Kind::Exec,
        ChainKind::PrivilegeThenPersistence => Kind::Creds,
        ChainKind::SuspiciousListenerAccepted => Kind::Listen,
        ChainKind::UnsanctionedDialEstablished => Kind::Connect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{ConnectOutcome, FlowInfo, Protocol};

    fn rules() -> CorrelationRules {
        CorrelationRules {
            enabled: true,
            window_ms: 10_000,
            max_actors: 64,
        }
    }

    fn ev(kind: Kind, pid: u32, ts_ns: u64) -> Event {
        Event {
            kind,
            actor_pid: pid,
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 0,
            ts_ns,
            comm: "worker".into(),
            filename: String::new(),
            dest: None,
            protocol: Some(Protocol::Tcp),
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            actor_exe_file: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
        }
    }

    fn finding(event_type: FindingType) -> Finding {
        finding_with_starttime(event_type, Some(11))
    }

    fn finding_with_starttime(event_type: FindingType, starttime: Option<u64>) -> Finding {
        Finding {
            event_type,
            severity: Severity::Medium,
            summary: "CANARY_NOT_REAL_SUMMARY".into(),
            source_ts_ns: 0,
            process: ProcessInfo {
                pid: 7,
                ppid: 1,
                uid: 33,
                comm: "CANARY_NOT_REAL_COMM".into(),
                exe: Some("CANARY_NOT_REAL_EXE".into()),
                cmdline: Some("CANARY_NOT_REAL_CMDLINE --token=SECRET".into()),
                cgroup: None,
                starttime,
            },
            target_pid: None,
            wants_kill: false,
            detail: json!({"canary": "CANARY_NOT_REAL_DETAIL"}),
        }
    }

    #[test]
    fn suspicious_exec_then_unsanctioned_egress_is_one_chain() {
        let mut c = Correlator::new(rules());
        let exec = ev(Kind::Exec, 7, 1_000_000_000);
        assert!(c
            .observe(&exec, Some(&finding(FindingType::ProcessCreation)))
            .is_none());

        let mut dial = ev(Kind::Connect, 7, 3_000_000_000);
        dial.dest = Some("203.0.113.4:4444".into());
        let hit = c
            .observe(&dial, Some(&finding(FindingType::NetworkConnect)))
            .expect("the pair must chain");
        assert_eq!(hit.kind, ChainKind::SuspiciousExecThenEgress);
        assert_eq!(hit.dest.as_deref(), Some("203.0.113.4:4444"));
        assert_eq!(hit.first_ts_ns, 1_000_000_000);
        assert_eq!(hit.second_ts_ns, 3_000_000_000);

        // The anchor was consumed: a second dial does not re-report the same exec.
        assert!(c
            .observe(&dial, Some(&finding(FindingType::NetworkConnect)))
            .is_none());
    }

    #[test]
    fn raw_events_without_a_judged_finding_never_anchor_a_chain() {
        let mut c = Correlator::new(rules());
        assert!(c.observe(&ev(Kind::Exec, 7, 1_000_000_000), None).is_none());
        let mut dial = ev(Kind::Connect, 7, 2_000_000_000);
        dial.dest = Some("203.0.113.4:4444".into());
        assert!(c.observe(&dial, None).is_none());
        assert!(
            c.observe(&dial, Some(&finding(FindingType::NetworkConnect)))
                .is_none(),
            "a benign exec must not become half of a conviction"
        );
    }

    #[test]
    fn chains_do_not_cross_pid_or_window_boundaries() {
        let mut c = Correlator::new(rules());
        let exec = ev(Kind::Exec, 7, 1_000_000_000);
        assert!(c
            .observe(&exec, Some(&finding(FindingType::ProcessCreation)))
            .is_none());

        let other_pid = ev(Kind::Connect, 8, 1_500_000_000);
        assert!(c
            .observe(&other_pid, Some(&finding(FindingType::NetworkConnect)))
            .is_none());

        let late = ev(Kind::Connect, 7, 12_000_000_000);
        assert!(
            c.observe(&late, Some(&finding(FindingType::NetworkConnect)))
                .is_none(),
            "an anchor outside the window must be evicted"
        );
    }

    #[test]
    fn a_recycled_pid_cannot_inherit_an_earlier_suspicious_anchor() {
        let mut c = Correlator::new(rules());
        let exec = ev(Kind::Exec, 7, 1_000_000_000);
        assert!(c
            .observe(
                &exec,
                Some(&finding_with_starttime(
                    FindingType::ProcessCreation,
                    Some(11)
                ))
            )
            .is_none());

        let mut dial = ev(Kind::Connect, 7, 2_000_000_000);
        dial.dest = Some("203.0.113.4:4444".into());
        assert!(
            c.observe(
                &dial,
                Some(&finding_with_starttime(
                    FindingType::NetworkConnect,
                    Some(12)
                ))
            )
            .is_none(),
            "the same pid number with a different /proc start time is a different process"
        );

        // Unknown identity must not silently disable the rule: a fresh anchor
        // with no readable /proc start time can still chain to an equally
        // unknown dial, because the kernel timestamps remain the fallback.
        let mut c2 = Correlator::new(rules());
        assert!(c2
            .observe(
                &exec,
                Some(&finding_with_starttime(FindingType::ProcessCreation, None))
            )
            .is_none());
        assert!(
            c2.observe(
                &dial,
                Some(&finding_with_starttime(FindingType::NetworkConnect, None))
            )
            .is_some(),
            "an unreadable /proc must not silently disable the rule"
        );
    }

    #[test]
    fn established_verdict_confirms_only_the_matching_unsanctioned_dial() {
        let mut dial = ev(Kind::Connect, 7, 1_000_000_000);
        dial.dest = Some("198.51.100.9:443".into());

        let mut c = Correlator::new(rules());
        assert!(c
            .observe(&dial, Some(&finding(FindingType::C2Beaconing)))
            .is_none());

        let mut verdict = ev(Kind::ConnectResult, 7, 1_200_000_000);
        verdict.connect_outcome = Some(ConnectOutcome::Established);
        verdict.dest = Some("198.51.100.9:443".into());
        let hit = c
            .observe(&verdict, None)
            .expect("established dial must chain");
        assert_eq!(hit.kind, ChainKind::UnsanctionedDialEstablished);

        // A refused verdict is not evidence of a completed egress.
        let mut refused = verdict.clone();
        refused.connect_outcome = Some(ConnectOutcome::Refused);
        let mut c2 = Correlator::new(rules());
        assert!(c2
            .observe(&dial, Some(&finding(FindingType::NetworkConnect)))
            .is_none());
        assert!(c2.observe(&refused, None).is_none());

        // Nor is an established verdict for a different destination.
        let mut other = verdict.clone();
        other.dest = Some("198.51.100.10:443".into());
        let mut c3 = Correlator::new(rules());
        assert!(c3
            .observe(&dial, Some(&finding(FindingType::NetworkConnect)))
            .is_none());
        assert!(c3.observe(&other, None).is_none());
    }

    #[test]
    fn accepted_flow_confirms_only_a_suspicious_listener_on_that_port() {
        let mut listen = ev(Kind::Listen, 7, 1_000_000_000);
        listen.dest = Some("0.0.0.0:4444".into());
        let mut c = Correlator::new(rules());
        assert!(c
            .observe(&listen, Some(&finding(FindingType::ListenBackdoor)))
            .is_none());

        let mut flow = ev(Kind::Flow, 7, 1_100_000_000);
        flow.flow = Some(FlowInfo {
            local_port: 4444,
            netns_ino: 42,
        });
        flow.dest = Some("203.0.113.7:51000".into());
        let hit = c.observe(&flow, None).expect("accepted flow must chain");
        assert_eq!(hit.kind, ChainKind::SuspiciousListenerAccepted);
        assert_eq!(hit.local_port, Some(4444));
        assert_eq!(hit.dest.as_deref(), Some("203.0.113.7:51000"));

        let mut mismatch = flow.clone();
        mismatch.flow = Some(FlowInfo {
            local_port: 8080,
            netns_ino: 42,
        });
        let mut c2 = Correlator::new(rules());
        assert!(c2
            .observe(&listen, Some(&finding(FindingType::ListenBackdoor)))
            .is_none());
        assert!(c2.observe(&mismatch, None).is_none());
    }

    #[test]
    fn privilege_raise_then_persistence_write_chains() {
        let mut c = Correlator::new(rules());
        assert!(c
            .observe(
                &ev(Kind::Creds, 7, 1_000_000_000),
                Some(&finding(FindingType::PrivilegeChange))
            )
            .is_none());
        for kind in [Kind::Service, Kind::Module, Kind::BpfLoad] {
            let mut c = Correlator::new(rules());
            assert!(c
                .observe(
                    &ev(Kind::Creds, 7, 1_000_000_000),
                    Some(&finding(FindingType::PrivilegeChange))
                )
                .is_none());
            let hit = c
                .observe(
                    &ev(kind, 7, 2_000_000_000),
                    Some(&finding(FindingType::NewService)),
                )
                .expect("post-privilege persistence must chain");
            assert_eq!(hit.kind, ChainKind::PrivilegeThenPersistence);
        }
    }

    #[test]
    fn zero_and_backwards_kernel_timestamps_never_chain() {
        let mut c = Correlator::new(rules());
        assert!(c
            .observe(
                &ev(Kind::Creds, 7, 0),
                Some(&finding(FindingType::PrivilegeChange))
            )
            .is_none());
        assert!(c
            .observe(
                &ev(Kind::Creds, 7, 5_000_000_000),
                Some(&finding(FindingType::PrivilegeChange))
            )
            .is_none());
        assert!(
            c.observe(
                &ev(Kind::Service, 7, 4_000_000_000),
                Some(&finding(FindingType::NewService))
            )
            .is_none(),
            "a backwards clock must clear history, not join across it"
        );
    }

    #[test]
    fn disabled_rules_and_bounded_actor_state() {
        let mut off = rules();
        off.enabled = false;
        let mut c = Correlator::new(off);
        assert!(c
            .observe(
                &ev(Kind::Creds, 7, 1_000_000_000),
                Some(&finding(FindingType::PrivilegeChange))
            )
            .is_none());
        assert!(c
            .observe(
                &ev(Kind::Service, 7, 2_000_000_000),
                Some(&finding(FindingType::NewService))
            )
            .is_none());

        let mut tight = rules();
        tight.max_actors = 2;
        let mut c = Correlator::new(tight);
        for pid in 1..=200 {
            let _ = c.observe(
                &ev(Kind::Creds, pid, u64::from(pid) * 1_000_000_000),
                Some(&finding(FindingType::PrivilegeChange)),
            );
        }
        assert!(c.anchors.len() <= 2, "actor state must stay bounded");
    }

    #[test]
    fn the_finding_is_observe_only_and_carries_no_canary_text() {
        let c = Correlator::new(rules());
        let mut dial = ev(Kind::Connect, 7, 2_000_000_000);
        dial.dest = Some("203.0.113.4:4444".into());
        let m = ChainMatch {
            kind: ChainKind::UnsanctionedDialEstablished,
            actor_pid: 7,
            first_ts_ns: 1_000_000_000,
            second_ts_ns: 2_000_000_000,
            dest: dial.dest.clone(),
            local_port: None,
        };
        let f = c.finding_for(m, finding(FindingType::NetworkConnect).process, &dial);
        assert_eq!(f.event_type_str(), "endpoint:attack_chain");
        assert_eq!(f.severity_str(), "medium");
        assert!(!f.wants_kill);
        assert_eq!(f.source_ts_ns, 2_000_000_000);
        let wire = serde_json::to_string(&f).unwrap();
        // Only the allowlisted ProcessInfo fields carry CANARY strings; the
        // chain's own summary/detail must add none of them.
        assert!(!f.summary.contains("CANARY"));
        assert!(!f.detail.to_string().contains("CANARY"));
        assert!(wire.contains("endpoint:attack_chain"));
    }

    #[test]
    fn listening_port_is_parsed_for_both_address_families_only() {
        let mut v4 = ev(Kind::Listen, 7, 1_000_000_000);
        v4.dest = Some("0.0.0.0:4444".into());
        assert_eq!(local_port_of(&v4), Some(4444));

        let mut v6 = ev(Kind::Listen, 7, 1_000_000_000);
        v6.dest = Some("[::]:4444".into());
        assert_eq!(local_port_of(&v6), Some(4444));

        // A CONNECT's remote port is not a listening port and must never be
        // used to match a FLOW to a listener.
        let mut dial = ev(Kind::Connect, 7, 1_000_000_000);
        dial.dest = Some("203.0.113.4:4444".into());
        assert_eq!(local_port_of(&dial), None);
    }
}
