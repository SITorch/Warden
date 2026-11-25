//! telemetry.rs — structured, fail-safe telemetry health (Phase 1).
//!
//! The journal already prints ring drops, queue depth and delivery failures,
//! and `health.rs` already prints a per-claim evidence word for what a
//! *cap-less* command can see from `/proc`. What was missing was a single
//! structured answer to "can I trust this sensor's view right now?" — one that
//! a central platform can consume without parsing prose, and that never turns
//! an unreadable counter into the reassuring number zero.
//!
//! Two rules are enforced here rather than left to callers:
//!
//! 1. **Unknown is not zero.** A measurement whose source could not be read has
//!    `status = UNKNOWN` and `value = null`. Summing it must never produce a
//!    green state. [`TelemetryState::from_claims`] therefore ranks `Unknown`
//!    above `Healthy`.
//! 2. **A known blind spot is not full coverage.** A capability that is
//!    genuinely unsupported (DNS payload, egress enforcement, another
//!    namespace's sockets) yields `PARTIALLY_BLIND`, not `HEALTHY`, even when
//!    every readable counter is clean.
//!
//! This module is deliberately free of `bpf()` calls, `/proc` reads, secrets
//! and I/O. It transforms measurements handed to it. That keeps the state
//! machine unit-testable with no privileges and makes it usable both from the
//! live event loop (which *can* read the kernel maps) and from `--health --json`
//! (which cannot, and says so).

use serde::Serialize;

use crate::detect::{Finding, FindingType, ProcessInfo, Severity};

/// The aggregate trust state of a sensor's telemetry. Ordered by severity in
/// [`TelemetryState::from_claims`], not derived by `Ord` — the ranking is a
/// security decision and is pinned by tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TelemetryState {
    /// Every claim was read and nothing is degraded or unsupported.
    Healthy,
    /// A readable signal says loss or pressure is happening (recoverable).
    Degraded,
    /// At least one known capability is unsupported: the sensor is deaf to a
    /// defined slice of the host even while its other counters are clean.
    PartiallyBlind,
    /// A critical signal (loss of the only path that reports loss, or a dead
    /// enforcement primitive that is claimed active) is degraded.
    Critical,
    /// At least one claim could not be read. Never collapsed into `Healthy`.
    Unknown,
}

impl TelemetryState {
    pub fn word(self) -> &'static str {
        match self {
            TelemetryState::Healthy => "HEALTHY",
            TelemetryState::Degraded => "DEGRADED",
            TelemetryState::PartiallyBlind => "PARTIALLY_BLIND",
            TelemetryState::Critical => "CRITICAL",
            TelemetryState::Unknown => "UNKNOWN",
        }
    }
}

/// Evidence status of one measurement. Mirrors the vocabulary already used by
/// `--doctor` / `--health`; the point of a separate enum is that the state
/// machine can match on it without parsing rendered lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MeasurementStatus {
    /// The source was consulted and the value is what it said.
    Verified,
    /// The source exists but this process cannot consult it. Not a pass.
    Unknown,
    /// There is no source for this on the current path (a declared gap).
    Unsupported,
}

impl MeasurementStatus {
    pub fn word(self) -> &'static str {
        match self {
            MeasurementStatus::Verified => "VERIFIED",
            MeasurementStatus::Unknown => "UNKNOWN",
            MeasurementStatus::Unsupported => "UNSUPPORTED",
        }
    }
}

/// One input to [`TelemetryState::from_claims`].
#[derive(Debug, Clone, Copy)]
pub struct CoverageClaim {
    pub name: &'static str,
    pub status: MeasurementStatus,
    /// Only meaningful when `status == Verified`: did the reading say that
    /// something is wrong (loss, pressure, failed hook)?
    pub degraded: bool,
    /// A degraded *critical* claim escalates all the way to `Critical`.
    pub critical: bool,
}

impl CoverageClaim {
    pub fn verified(name: &'static str, degraded: bool) -> Self {
        Self {
            name,
            status: MeasurementStatus::Verified,
            degraded,
            critical: false,
        }
    }
    pub fn critical(name: &'static str, degraded: bool) -> Self {
        Self {
            name,
            status: MeasurementStatus::Verified,
            degraded,
            critical: true,
        }
    }
    pub fn unknown(name: &'static str) -> Self {
        Self {
            name,
            status: MeasurementStatus::Unknown,
            degraded: false,
            critical: false,
        }
    }
    pub fn unsupported(name: &'static str) -> Self {
        Self {
            name,
            status: MeasurementStatus::Unsupported,
            degraded: false,
            critical: false,
        }
    }
}

/// Reduce a set of measured/unmeasurable claims to one state.
///
/// Priority (highest first): a degraded critical claim → `Critical`; any
/// declared unsupported capability → `PartiallyBlind`; any degraded verified
/// claim → `Degraded`; any unreadable claim → `Unknown`; otherwise `Healthy`.
/// An empty input is `Unknown`, never `Healthy`: "I did not check" is not a
/// clean bill of health.
pub fn state_from_claims(claims: &[CoverageClaim]) -> TelemetryState {
    if claims.is_empty() {
        return TelemetryState::Unknown;
    }
    let mut critical = false;
    let mut degraded = false;
    let mut unsupported = false;
    let mut unknown = false;
    for c in claims {
        match c.status {
            MeasurementStatus::Verified if c.degraded && c.critical => {
                log::debug!("critical telemetry claim is degraded: {}", c.name);
                critical = true;
            }
            MeasurementStatus::Verified if c.degraded => {
                log::debug!("telemetry claim is degraded: {}", c.name);
                degraded = true;
            }
            MeasurementStatus::Verified if !c.degraded => {}
            // Guard exhaustiveness is not inferred across arms, so keep an
            // explicit fall-through for any future Verified combination.
            MeasurementStatus::Verified => {}
            MeasurementStatus::Unsupported => unsupported = true,
            MeasurementStatus::Unknown => unknown = true,
        }
    }
    if critical {
        TelemetryState::Critical
    } else if unsupported {
        TelemetryState::PartiallyBlind
    } else if degraded {
        TelemetryState::Degraded
    } else if unknown {
        TelemetryState::Unknown
    } else {
        TelemetryState::Healthy
    }
}

/// The ring-buffer loss measurement, as seen by whoever can read the kernel
/// maps. `unknown()` is the honest answer for a cap-less diagnostic process.
#[derive(Debug, Clone, Serialize)]
pub struct RingLoss {
    pub status: MeasurementStatus,
    pub drops: Option<u64>,
    pub submitted: Option<u64>,
    /// `drops / (drops + submitted)`; `None` when either side is unreadable.
    pub loss_rate: Option<f64>,
    pub note: String,
}

impl RingLoss {
    /// A diagnostic process that cannot issue `bpf()`: no numbers, no rate,
    /// and an explicit reason. This is what `--health --json` reports.
    pub fn unknown() -> Self {
        Self {
            status: MeasurementStatus::Unknown,
            drops: None,
            submitted: None,
            loss_rate: None,
            note: "live ring-buffer counters need bpf()/CAP_BPF; this process does not take them"
                .to_string(),
        }
    }

    /// Measurements read from the live per-CPU maps. Two counters are read
    /// together by the caller in one `sensor_counters()` call, so a `Some`
    /// here means both sides were available.
    pub fn observed(drops: u64, submitted: u64) -> Self {
        let attempted = drops.saturating_add(submitted);
        let loss_rate = if attempted == 0 {
            // No events were produced at all in the window. That is a rate of
            // zero *loss*, but it is also a sensor that may be dead — the note
            // says so rather than letting `0.0` read as "host was quiet".
            None
        } else {
            Some(drops as f64 / attempted as f64)
        };
        let note = if attempted == 0 {
            "neither drops nor submits were counted; no loss can be inferred".to_string()
        } else {
            format!("{drops} dropped of {attempted} counted submissions since start")
        };
        Self {
            status: MeasurementStatus::Verified,
            drops: Some(drops),
            submitted: Some(submitted),
            loss_rate,
            note,
        }
    }

    pub fn is_degraded(&self, warn_rate: f64) -> bool {
        self.status == MeasurementStatus::Verified && self.loss_rate.is_some_and(|r| r > warn_rate)
    }

    pub fn claim(&self) -> CoverageClaim {
        CoverageClaim {
            name: "ring_loss",
            status: self.status,
            degraded: self.is_degraded(0.0),
            critical: false,
        }
    }
}

/// Pipeline counters with explicitly defined semantics. Every field is
/// optional; a missing field means "not measured", which is never summed as
/// zero. The live event loop may fill the ones it can; a standalone diagnostic
/// fills none and reports `UNKNOWN`.
#[derive(Debug, Clone, Serialize)]
pub struct PipelineCounters {
    pub status: MeasurementStatus,
    pub decode_rejected: Option<u64>,
    pub enrichment_failed: Option<u64>,
    pub queue_full: Option<u64>,
    pub spool_failed: Option<u64>,
    pub quarantined: Option<u64>,
    pub replay_failed: Option<u64>,
}

impl PipelineCounters {
    pub fn unknown() -> Self {
        Self {
            status: MeasurementStatus::Unknown,
            decode_rejected: None,
            enrichment_failed: None,
            queue_full: None,
            spool_failed: None,
            quarantined: None,
            replay_failed: None,
        }
    }

    pub fn claim(&self) -> CoverageClaim {
        CoverageClaim {
            name: "pipeline_counters",
            status: self.status,
            // These are operational counters; the component that can read them
            // decides whether they are degraded. An UNKNOWN set is never a pass.
            degraded: false,
            critical: false,
        }
    }
}

/// The structured block embedded in `--health --json`. Kept as one object so
/// the JSON schema is stable while individual measurements evolve.
#[derive(Debug, Clone, Serialize)]
pub struct TelemetryReport {
    pub state: TelemetryState,
    pub ring_loss: RingLoss,
    pub pipeline: PipelineCounters,
    /// What the sensor knows it cannot see, even when its counters are clean.
    pub declared_blind_spots: Vec<&'static str>,
}

impl TelemetryReport {
    /// The cap-less view used by `warden --health --json`. Live kernel signals
    /// are UNKNOWN; the declared blind spots come from the shipped capability
    /// matrix, not from a guess.
    pub fn cap_less() -> Self {
        let ring_loss = RingLoss::unknown();
        let pipeline = PipelineCounters::unknown();
        let blind_spots = vec![
            "egress enforcement: optional cgroup2 gate only; no full-host deny \
             and no claim without verified hooks and an armed map",
            "DNS payload metadata: no DNS event source in the local pipeline",
            "unconnected UDP flow: inet_accept is stream-only",
            "other network namespaces: /proc/net snapshot is host-namespace only",
        ];
        let mut claims = vec![
            ring_loss.claim(),
            pipeline.claim(),
            CoverageClaim::unknown("live_hook_attachment"),
            CoverageClaim::unknown("protected_pid_map"),
            CoverageClaim::unknown("ipv6_datagram_volume_live_bump"),
        ];
        claims.extend(blind_spots.iter().map(|n| CoverageClaim::unsupported(n)));
        let state = state_from_claims(&claims);
        Self {
            state,
            ring_loss,
            pipeline,
            declared_blind_spots: blind_spots,
        }
    }

    /// The live view, assembled in the event loop from real map readings and
    /// the delivery counters. `critical_ring` marks the case where the loss
    /// counter itself is unreadable (the sensor that reports blindness is
    /// blind), which is a `Critical` claim rather than a clean one.
    /// Recompute the state after a cap-less diagnostic has parsed its own
    /// rendered claims. The live kernel measurements stay UNKNOWN (this process
    /// still cannot read them), but a claim that explicitly says `DEGRADED` or
    /// `UNAVAILABLE` must move the aggregate off `Unknown` rather than be
    /// hidden by the cap-less baseline.
    pub fn with_claim_overrides(mut self, extra: &[CoverageClaim]) -> Self {
        let mut claims = vec![
            self.ring_loss.claim(),
            self.pipeline.claim(),
            CoverageClaim::unknown("live_hook_attachment"),
            CoverageClaim::unknown("protected_pid_map"),
            CoverageClaim::unknown("ipv6_datagram_volume_live_bump"),
        ];
        claims.extend(
            self.declared_blind_spots
                .iter()
                .map(|n| CoverageClaim::unsupported(n)),
        );
        claims.extend(extra.iter().copied());
        self.state = state_from_claims(&claims);
        self
    }

    pub fn live(
        ring_loss: RingLoss,
        pipeline: PipelineCounters,
        delivery_degraded: bool,
        ring_counter_unreadable: bool,
    ) -> Self {
        let mut claims = vec![
            ring_loss.claim(),
            pipeline.claim(),
            CoverageClaim::verified("delivery", delivery_degraded),
            CoverageClaim::critical("ring_loss_counter", ring_counter_unreadable),
        ];
        // The same declared blind spots apply live: a healthy ring does not
        // prove the optional cgroup gate is attached and armed, and it does not
        // make DNS payload observation exist.
        claims.push(CoverageClaim::unsupported("full_host_egress_enforcement"));
        claims.push(CoverageClaim::unsupported("dns_payload"));
        let state = state_from_claims(&claims);
        Self {
            state,
            ring_loss,
            pipeline,
            declared_blind_spots: vec![
                "egress enforcement: optional cgroup2 gate only; no full-host deny \
                 and no claim without verified hooks and an armed map",
                "DNS payload metadata: no DNS event source in the local pipeline",
            ],
        }
    }
}

/// The small, secret-free summary of sensor trust that rides on EVERY host
/// finding (Phase 5). Sentinel must be able to tell "this box was deaf while it
/// reported nothing" from "this box was quiet": an absent or unmeasured health
/// block is `UNKNOWN`, never `HEALTHY`. Only words and optional counters cross
/// the wire — never a config path, an API key, a command line or a pid.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SensorHealth {
    pub state: &'static str,
    pub ring_loss: &'static str,
    /// `None` means "not measured", which must not be read as zero loss.
    pub loss_rate: Option<f64>,
    pub source: &'static str,
}

impl SensorHealth {
    /// The honest value before the first live measurement (and for any old
    /// spooled record replayed after an upgrade).
    pub fn unknown() -> Self {
        Self {
            state: TelemetryState::Unknown.word(),
            ring_loss: MeasurementStatus::Unknown.word(),
            loss_rate: None,
            source: "no live measurement in this process",
        }
    }

    /// Fold one live report into the wire shape. Both halves come from the
    /// same reading: a report whose ring source was unreadable cannot produce a
    /// clean `HEALTHY` state here, because [`TelemetryReport::live`] ranks the
    /// unreadable critical claim above a clean ring.
    pub fn from_report(report: &TelemetryReport) -> Self {
        Self {
            state: report.state.word(),
            ring_loss: report.ring_loss.status.word(),
            loss_rate: report.ring_loss.loss_rate,
            source: "live ring counters and declared blind spots",
        }
    }
}

/// Build the off-box `endpoint:self_degraded` finding for a tick in which the
/// kernel reported ring loss. A journal warning alone is invisible to the
/// platform: a sensor that went deaf would look like a quiet host. This takes
/// the ordinary delivery path, so if the bridge itself is broken the record
/// spools and waits like any other finding.
///
/// No credential, config path or command line is included — the detail block
/// contains only counters and coverage facts.
pub fn ring_loss_finding(
    dropped: u64,
    received: u64,
    total: u64,
    worst: &str,
    ring_note: &str,
) -> Finding {
    let attempted = dropped.saturating_add(received);
    let pct = if attempted == 0 {
        0.0
    } else {
        dropped as f64 / attempted as f64 * 100.0
    };
    let detail = serde_json::json!({
        "kind": "self_observability",
        "signal": "ring_loss",
        "dropped_since_last_report": dropped,
        "received_since_last_report": received,
        "loss_percent_in_window": (pct * 10.0).round() / 10.0,
        "total_dropped_since_start": total,
        "worst_kind": worst,
        "ring_capacity": ring_note,
        "coverage": TelemetryState::PartiallyBlind.word(),
        // This is the sensor reporting on itself: no attacker, no kill intent.
        "enforcement_requested": false,
    });
    Finding {
        source_ts_ns: 0,
        event_type: FindingType::SelfDegraded,
        severity: if pct >= 25.0 {
            Severity::High
        } else {
            Severity::Medium
        },
        summary: format!(
            "warden telemetry degraded: {dropped} event(s) DROPPED in the last report window \
             ({received} reached userspace, {pct:.1}% loss); host coverage is incomplete"
        ),
        process: ProcessInfo {
            pid: std::process::id(),
            ppid: 0,
            uid: 0,
            comm: "warden".to_string(),
            exe: std::env::current_exe()
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
            cmdline: None,
            cgroup: None,
            starttime: None,
        },
        target_pid: None,
        wants_kill: false,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_check_is_unknown_not_healthy() {
        assert_eq!(state_from_claims(&[]), TelemetryState::Unknown);
    }

    #[test]
    fn all_clean_readable_claims_are_healthy() {
        let claims = [
            CoverageClaim::verified("ring", false),
            CoverageClaim::verified("delivery", false),
            CoverageClaim::verified("enrichment", false),
        ];
        assert_eq!(state_from_claims(&claims), TelemetryState::Healthy);
    }

    #[test]
    fn an_unreadable_counter_never_becomes_healthy() {
        let claims = [
            CoverageClaim::verified("delivery", false),
            CoverageClaim::unknown("ring_loss_counter"),
        ];
        assert_eq!(state_from_claims(&claims), TelemetryState::Unknown);
    }

    #[test]
    fn a_declared_blind_spot_is_partially_blind_even_with_clean_counters() {
        let claims = [
            CoverageClaim::verified("delivery", false),
            CoverageClaim::unsupported("egress_enforcement"),
        ];
        assert_eq!(state_from_claims(&claims), TelemetryState::PartiallyBlind);
    }

    #[test]
    fn degraded_and_critical_claims_escalate() {
        let degraded = [CoverageClaim::verified("queue", true)];
        assert_eq!(state_from_claims(&degraded), TelemetryState::Degraded);
        let critical = [
            CoverageClaim::verified("queue", true),
            CoverageClaim::critical("ring_loss_counter", true),
        ];
        assert_eq!(state_from_claims(&critical), TelemetryState::Critical);
        // A critical claim does not escalate unless it is actually degraded.
        let critical_clean = [CoverageClaim::critical("ring_loss_counter", false)];
        assert_eq!(state_from_claims(&critical_clean), TelemetryState::Healthy);
    }

    #[test]
    fn unknown_ring_loss_has_no_numbers_and_no_rate() {
        let r = RingLoss::unknown();
        assert_eq!(r.status, MeasurementStatus::Unknown);
        assert!(r.drops.is_none() && r.submitted.is_none() && r.loss_rate.is_none());
        assert!(!r.is_degraded(0.0));
        assert_eq!(r.claim().status, MeasurementStatus::Unknown);
    }

    #[test]
    fn observed_ring_loss_computes_a_rate_and_flags_degradation() {
        let clean = RingLoss::observed(0, 100);
        assert_eq!(clean.loss_rate, Some(0.0));
        assert!(!clean.is_degraded(0.01));
        let lossy = RingLoss::observed(26, 74);
        assert!((lossy.loss_rate.unwrap() - 0.26).abs() < 1e-9);
        assert!(lossy.is_degraded(0.05));
        // No events produced is not a measured zero-loss success.
        let idle = RingLoss::observed(0, 0);
        assert!(idle.loss_rate.is_none());
    }

    #[test]
    fn cap_less_report_is_never_healthy() {
        let report = TelemetryReport::cap_less();
        // Declared blind spots make this PARTIALLY_BLIND rather than UNKNOWN:
        // the gaps are known even though the live counters are not readable.
        // Both are strictly below HEALTHY in the ranking.
        assert_eq!(report.state, TelemetryState::PartiallyBlind);
        assert_eq!(report.ring_loss.status, MeasurementStatus::Unknown);
        assert_eq!(report.pipeline.status, MeasurementStatus::Unknown);
        assert!(!report.declared_blind_spots.is_empty());
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["state"], "PARTIALLY_BLIND");
        assert!(json["ring_loss"]["drops"].is_null());
    }

    #[test]
    fn live_report_with_a_deaf_loss_counter_is_critical() {
        let report = TelemetryReport::live(
            RingLoss::unknown(),
            PipelineCounters::unknown(),
            false,
            true,
        );
        assert_eq!(report.state, TelemetryState::Critical);
    }

    #[test]
    fn phase5_sensor_health_is_unknown_until_measured_and_never_carries_a_secret() {
        let unknown = SensorHealth::unknown();
        assert_eq!(unknown.state, "UNKNOWN");
        assert_eq!(unknown.ring_loss, "UNKNOWN");
        assert!(unknown.loss_rate.is_none(), "unmeasured is not zero loss");
        let live = SensorHealth::from_report(&TelemetryReport::live(
            RingLoss::observed(26, 74),
            PipelineCounters::unknown(),
            false,
            false,
        ));
        assert_ne!(live.state, "HEALTHY", "declared blind spots stay visible");
        assert_eq!(live.ring_loss, "VERIFIED");
        assert!((live.loss_rate.unwrap() - 0.26).abs() < 1e-9);
        let deaf = SensorHealth::from_report(&TelemetryReport::live(
            RingLoss::unknown(),
            PipelineCounters::unknown(),
            false,
            true,
        ));
        assert_eq!(deaf.state, "CRITICAL");
        assert!(deaf.loss_rate.is_none());
        // The wire form must never contain a credential of any spelling.
        let wire =
            serde_json::to_string(&unknown).unwrap() + &serde_json::to_string(&live).unwrap();
        for needle in ["api_key", "api-key", "API-Key", "secret", "token"] {
            assert!(!wire.contains(needle), "{needle} leaked into sensor health");
        }
    }

    #[test]
    fn ring_loss_finding_is_a_no_kill_self_signal_without_secrets() {
        let f = ring_loss_finding(26, 74, 570, "ptrace", "256 KiB ring");
        assert_eq!(f.event_type.as_str(), "endpoint:self_degraded");
        assert!(!f.wants_kill);
        assert_eq!(f.detail["signal"], "ring_loss");
        assert_eq!(f.detail["enforcement_requested"], false);
        let wire = serde_json::to_string(&f).unwrap();
        assert!(!wire.contains("api_key"));
        assert!(!wire.contains("X-API-Key"));
    }
}
