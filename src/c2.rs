//! c2.rs — bounded local beaconing detection over CONNECT telemetry (Phase 4).
//!
//! This is a *behavioural signal*, not a verdict. It watches one process's
//! repeated dials to one destination and asks a narrow question: are they
//! regular enough, over a long enough window, from a destination new to this
//! process, to be worth an analyst's attention? Everything it cannot know —
//! DNS query names, TLS/SNI, payloads, flow byte counts — is declared
//! **UNSUPPORTED** rather than inferred from a port number.
//!
//! Design rules that keep this safe to run by default:
//!
//! - **Bounded memory.** At most `max_actors` processes, `max_history`
//!   observations each, `max_destinations` known destinations each. The oldest
//!   actor is evicted at capacity; no unbounded `HashMap` growth.
//! - **Minimum evidence.** No finding until `min_dials` dials to the same
//!   destination inside the window. Bursts (interval below the floor) and
//!   long gaps (above the ceiling) are rejected rather than averaged away.
//! - **Confidence, not certainty.** The finding carries a numeric confidence,
//!   a label, the interval statistics and the ATT&CK technique. It never asks
//!   for a kill and is never more severe than High on its own.
//! - **Quality-aware.** A ring-loss ratio from Phase 1 lowers confidence; no
//!   reading caps it. A sensor that lost events has a weaker claim, not a
//!   stronger one.
//! - **Cooldown.** One finding per actor+destination per cooldown window, so a
//!   beacon cannot flood the bridge with one record per dial.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use serde::Serialize;

use crate::config::C2Rules;

/// The only input this detector can honestly consume. The other three are
/// named so that documentation and findings can say what is missing instead
/// of leaving an implicit gap that a port number might appear to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum C2Input {
    /// A kernel-stamped CONNECT record: destination, port, actor, timestamp.
    Connect,
    /// A DNS query event (name, type, rcode). No such source exists locally.
    DnsQuery,
    /// TLS metadata (SNI, ALPN, certificate). Not collected by any hook.
    TlsMetadata,
    /// Per-flow byte counts. Only per-cgroup cumulative counters exist.
    FlowBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InputSupport {
    Supported,
    Unsupported,
}

impl C2Input {
    pub fn support(self) -> InputSupport {
        match self {
            C2Input::Connect => InputSupport::Supported,
            C2Input::DnsQuery | C2Input::TlsMetadata | C2Input::FlowBytes => {
                InputSupport::Unsupported
            }
        }
    }

    pub fn unsupported_reason(self) -> Option<&'static str> {
        match self {
            C2Input::Connect => None,
            C2Input::DnsQuery => {
                Some("no DNS event source: a port-53 dial is not a DNS query; query names, types and rcodes are unavailable")
            }
            C2Input::TlsMetadata => {
                Some("no TLS metadata source: SNI/ALPN/certificate cannot be read from the shipped hooks")
            }
            C2Input::FlowBytes => {
                Some("no per-flow byte counts: only cumulative per-cgroup volume counters ship")
            }
        }
    }
}

/// Declare, in one place, every input this local detector explicitly does
/// NOT have. Embedded in each finding so a consumer cannot mistake silence
/// for coverage.
pub fn unsupported_inputs() -> Vec<(&'static str, &'static str)> {
    [C2Input::DnsQuery, C2Input::TlsMetadata, C2Input::FlowBytes]
        .into_iter()
        .filter_map(|i| i.unsupported_reason().map(|r| (i.name(), r)))
        .collect()
}

/// All four inputs, with their honest support status, embedded in the finding
/// so a consumer can see both the one source used and the three missing ones.
pub fn input_support_matrix() -> Vec<(&'static str, InputSupport)> {
    [
        C2Input::Connect,
        C2Input::DnsQuery,
        C2Input::TlsMetadata,
        C2Input::FlowBytes,
    ]
    .into_iter()
    .map(|i| (i.name(), i.support()))
    .collect()
}

impl C2Input {
    fn name(self) -> &'static str {
        match self {
            C2Input::Connect => "connect",
            C2Input::DnsQuery => "dns_query",
            C2Input::TlsMetadata => "tls_metadata",
            C2Input::FlowBytes => "flow_bytes",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectSample {
    pub ts_ns: u64,
    pub pid: u32,
    /// Clock ticks at process start, when /proc could read it. Part of the key
    /// so a recycled pid does not inherit the previous occupant's history.
    pub starttime: Option<u64>,
    /// Bare IP (no port) from the decoded CONNECT record.
    pub destination: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLabel {
    Low,
    Medium,
    High,
}

impl ConfidenceLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            ConfidenceLabel::Low => "low",
            ConfidenceLabel::Medium => "medium",
            ConfidenceLabel::High => "high",
        }
    }
}

/// The assessment embedded verbatim in the finding's `detail` block. Every
/// number an analyst needs to judge the signal is present; nothing is hidden
/// behind a bare "malicious" flag.
#[derive(Debug, Clone, Serialize)]
pub struct C2Assessment {
    pub detector: &'static str,
    /// Stable rule-schema version. A consumer can tell a jitter-tolerant
    /// assessment from the older fixed-cadence-only one without guessing from
    /// the presence of a key.
    pub detector_version: &'static str,
    /// Which regularity model produced the finding. A jittered sequence is
    /// weaker evidence than a fixed cadence and is capped accordingly.
    pub pattern: &'static str,
    pub confidence: f64,
    pub confidence_label: ConfidenceLabel,
    pub reason: &'static str,
    /// What the telemetry actually supports. A port number is never upgraded
    /// to a protocol observation here.
    pub evidence: &'static str,
    pub technique: &'static str,
    pub technique_name: &'static str,
    pub tactic: &'static str,
    /// Structured destination for the backend's cross-layer join. The summary
    /// is prose and capped; this is the field Sentinel anchors on so a local
    /// beacon and an NDR beacon to the same IP become one story.
    pub dest_ip: String,
    pub dest_port: Option<u16>,
    pub dial_count: usize,
    pub interval_count: usize,
    pub mean_interval_secs: f64,
    /// Median and median absolute deviation of the intervals, in seconds.
    /// Robust to a single outlier; only the jittered path relies on them, but
    /// both paths ship them so the numbers are comparable across findings.
    pub median_interval_secs: f64,
    pub mad_interval_secs: f64,
    /// The decision statistic, ALWAYS computed from the same interval
    /// population as `median_interval_secs` and `mad_interval_secs`.
    pub jitter_coefficient: f64,
    /// Coefficient of variation over the full evidence window. Shipped beside
    /// the decision statistic so a reader can see when the finding depends on
    /// a recent in-band run rather than on the whole window.
    pub window_jitter_coefficient: f64,
    /// MAD/median over the current in-band run. Shipped even for fixed-cadence
    /// findings so the two populations remain comparable across findings.
    pub run_jitter_coefficient: f64,
    /// Which population produced `jitter_coefficient`, median and MAD:
    /// `full_window` or `current_in_band_run`.
    pub interval_statistics_population: &'static str,
    pub destination_novelty: bool,
    pub data_quality: &'static str,
    pub ring_loss_ratio: Option<f64>,
    pub unsupported_inputs: Vec<(&'static str, &'static str)>,
    pub input_support_matrix: Vec<(&'static str, InputSupport)>,
    /// Reiterated at the finding level: this signal must never request a kill.
    pub enforcement_requested: bool,
}

#[derive(Debug, Clone)]
struct ActorState {
    /// Timestamp, destination, and whether that destination was new to this
    /// actor at the moment of the dial. Novelty must be remembered per sample:
    /// evaluating it only on the latest dial would always say "seen before"
    /// by the time enough evidence accumulates.
    observations: VecDeque<(u64, String, bool)>,
    known_destinations: VecDeque<String>,
    last_seen_ns: u64,
    reported: HashMap<String, u64>,
}

impl ActorState {
    fn new(now: u64) -> Self {
        Self {
            observations: VecDeque::new(),
            known_destinations: VecDeque::new(),
            last_seen_ns: now,
            reported: HashMap::new(),
        }
    }

    fn remember_destination(&mut self, dest: &str, cap: usize) -> bool {
        let novel = !self.known_destinations.iter().any(|d| d == dest);
        if novel {
            if self.known_destinations.len() == cap {
                self.known_destinations.pop_front();
            }
            self.known_destinations.push_back(dest.to_string());
        }
        novel
    }
}

/// Median of a sample, with the input left untouched. The copy is bounded by
/// the caller's `max_history`, so sorting cannot grow without limit.
fn median(values: &[u64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] as f64 + sorted[mid] as f64) / 2.0
    } else {
        sorted[mid] as f64
    }
}

/// Median absolute deviation: a dispersion estimate one extreme interval
/// cannot inflate the way mean/variance can. That is precisely what a jittered
/// implant does — it varies its cadence to escape a standard-deviation rule.
fn median_absolute_deviation(values: &[u64], center: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut deviations: Vec<f64> = values.iter().map(|&v| (v as f64 - center).abs()).collect();
    deviations.sort_unstable_by(|a, b| a.total_cmp(b));
    let mid = deviations.len() / 2;
    if deviations.len().is_multiple_of(2) {
        (deviations[mid - 1] + deviations[mid]) / 2.0
    } else {
        deviations[mid]
    }
}

/// Per-process, destination-scoped beacon tracker. All mutation happens behind
/// `Detector`'s `RefCell` on the single-threaded event loop.
pub struct C2Tracker {
    enabled: bool,
    min_dials: usize,
    window: Duration,
    min_interval: Duration,
    max_interval: Duration,
    max_jitter: f64,
    cooldown: Duration,
    max_actors: usize,
    max_history: usize,
    max_destinations: usize,
    actors: HashMap<(u32, Option<u64>), ActorState>,
}

impl C2Tracker {
    pub fn new(rules: C2Rules) -> Self {
        Self {
            enabled: rules.enabled,
            min_dials: rules.min_dials.max(3),
            window: Duration::from_secs(rules.window_secs.max(60)),
            min_interval: Duration::from_secs(rules.min_interval_secs),
            max_interval: Duration::from_secs(rules.max_interval_secs.max(1)),
            max_jitter: rules.max_jitter.clamp(0.05, 2.0),
            cooldown: Duration::from_secs(rules.cooldown_secs.max(60)),
            max_actors: rules.max_actors.max(1),
            max_history: rules.max_history.max(2),
            max_destinations: rules.max_destinations.max(1),
            actors: HashMap::new(),
        }
    }

    /// Drop actors whose last observation is older than twice the window, and
    /// enforce the hard actor cap by evicting the least recently seen one.
    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(2 * self.window.as_nanos() as u64);
        self.actors.retain(|_, s| s.last_seen_ns >= cutoff);
        self.enforce_actor_cap();
    }

    fn enforce_actor_cap(&mut self) {
        while self.actors.len() > self.max_actors {
            let oldest = self
                .actors
                .iter()
                .min_by_key(|(_, s)| s.last_seen_ns)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    self.actors.remove(&k);
                }
                None => break,
            }
        }
    }

    /// Record one CONNECT and, if the evidence is sufficient, return an
    /// assessment. `ring_loss_ratio` is the Phase 1 measurement for the
    /// current sensor window; `None` means it could not be read.
    pub fn observe(
        &mut self,
        sample: &ConnectSample,
        ring_loss_ratio: Option<f64>,
    ) -> Option<C2Assessment> {
        if !self.enabled || sample.destination.is_empty() || sample.ts_ns == 0 {
            return None;
        }
        let key = (sample.pid, sample.starttime);
        // The ring is per-CPU, so record order is not a timestamp order. A
        // re-delivered or cross-CPU-late CONNECT must not be appended behind a
        // newer one: `w[1] - w[0]` below would underflow, and even where it did
        // not panic it would turn a clock anomaly into a "negative" interval
        // that no honest beacon assessment may rest on. Reject the sample before
        // pruning, so a late record cannot evict a live actor either.
        if self
            .actors
            .get(&key)
            .is_some_and(|state| sample.ts_ns < state.last_seen_ns)
        {
            return None;
        }
        self.prune(sample.ts_ns);
        // Labeled block: every "not enough evidence" path breaks out with None,
        // so the actor-cap enforcement below runs on EVERY event — including
        // the one that created the actor. A plain `return None` here would let
        // the newest actor leave the map one over its hard bound.
        let result = 'evaluate: {
            let state = self
                .actors
                .entry(key)
                .or_insert_with(|| ActorState::new(sample.ts_ns));
            state.last_seen_ns = sample.ts_ns;
            let novelty = state.remember_destination(&sample.destination, self.max_destinations);
            state
                .observations
                .push_back((sample.ts_ns, sample.destination.clone(), novelty));
            while state.observations.len() > self.max_history {
                state.observations.pop_front();
            }

            let cutoff = sample.ts_ns.saturating_sub(self.window.as_nanos() as u64);
            let samples: Vec<(u64, bool)> = state
                .observations
                .iter()
                .filter(|(ts, d, _)| *ts >= cutoff && d == &sample.destination)
                .map(|(ts, _, new)| (*ts, *new))
                .collect();
            let times: Vec<u64> = samples.iter().map(|(ts, _)| *ts).collect();
            // Novelty of the *sequence*, not of the newest dial: the first dial
            // in the evidence window is the one that was (or wasn't) new.
            let sequence_novelty = samples.first().is_some_and(|(_, new)| *new);
            if times.len() < self.min_dials {
                break 'evaluate None;
            }

            let intervals_ns: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
            // Require one more interval than the bare minimum of dials: six
            // intervals is seven dials, enough to survive one outlier without
            // lowering the evidence bar to a five-dial burst.
            if intervals_ns.len() < self.min_dials {
                break 'evaluate None;
            }
            let min_ns = self.min_interval.as_nanos() as u64;
            let max_ns = self.max_interval.as_nanos() as u64;
            let n = intervals_ns.len() as f64;
            let mean_ns = intervals_ns.iter().sum::<u64>() as f64 / n;
            let variance = intervals_ns
                .iter()
                .map(|&d| (d as f64 - mean_ns).powi(2))
                .sum::<f64>()
                / n;
            // The full-window coefficient of variation is the fixed-cadence
            // decision statistic. `median`/`MAD` below are computed from the
            // SAME population; if the jittered model wins, all three are
            // replaced together by the in-band run's values. Shipping one
            // statistic from one population beside a median from another is
            // the M15 defect: it makes a long-gap shape look like the run that
            // followed it without saying so.
            let window_jitter = variance.sqrt() / mean_ns.max(1.0);
            let mut median_ns = median(&intervals_ns);
            let mut mad_ns = median_absolute_deviation(&intervals_ns, median_ns);
            let mut decision_jitter = window_jitter;
            let mut statistics_population = "full_window";

            // Layer B has two regularity models, deliberately different in the
            // strength of their evidence:
            //   * fixed cadence — the original rule. Every interval is inside
            //     the configured band and the coefficient of variation is low.
            //   * jittered cadence — a real implant pattern the old rule threw
            //     away completely. It needs a run of at least eight CONSECUTIVE
            //     dials inside the configured band (a short random run looks
            //     like a human; a gap or retry burst starts a new sequence),
            //     plus a low MAD/median ratio. MAD tolerates one outlier without
            //     moving the estimate the way mean/variance does.
            // The second model's confidence is capped below the first's: a
            // jittered sequence is a heuristic, not a conviction.
            let fixed_ok = intervals_ns.iter().all(|&d| d >= min_ns && d <= max_ns)
                && window_jitter <= self.max_jitter;
            // Only the *current in-band run* counts. A long gap or a retry
            // burst starts a new sequence; it must not be averaged into an
            // older one and called a beacon. This is what makes jitter
            // tolerance safe against the "long gap then normal polling" shape.
            let in_band = intervals_ns
                .iter()
                .rev()
                .take_while(|&&d| d >= min_ns && d <= max_ns)
                .count();
            let run = &intervals_ns[intervals_ns.len() - in_band..];
            let run_median = median(run);
            let run_mad = median_absolute_deviation(run, run_median);
            let run_jitter = run_mad / run_median.max(1.0);
            let jittered_ok = !fixed_ok
                && in_band > self.min_dials
                && run_median >= min_ns as f64
                && run_median <= max_ns as f64
                && run_jitter <= self.max_jitter;
            if jittered_ok {
                // Replace the statistic, its population label AND its two
                // companion numbers in one place. A reader can now say "the
                // median and jitter describe the current run", which is what
                // the detector actually used to decide.
                median_ns = run_median;
                mad_ns = run_mad;
                decision_jitter = run_jitter;
                statistics_population = "current_in_band_run";
            }
            if !fixed_ok && !jittered_ok {
                break 'evaluate None;
            }
            let (pattern, reason, regularity, cap) = if fixed_ok {
                (
                    "fixed_cadence",
                    "periodic_connect_beaconing",
                    1.0 - window_jitter / self.max_jitter,
                    1.0,
                )
            } else {
                (
                    "jittered_cadence",
                    "jittered_connect_beaconing",
                    1.0 - run_jitter / self.max_jitter,
                    0.72,
                )
            };

            // Cooldown: one finding per actor+destination per window.
            if let Some(&last) = state.reported.get(&sample.destination) {
                if sample.ts_ns.saturating_sub(last) < self.cooldown.as_nanos() as u64 {
                    break 'evaluate None;
                }
            }
            state
                .reported
                .insert(sample.destination.clone(), sample.ts_ns);

            let evidence = (intervals_ns.len() as f64 / self.min_dials as f64).min(1.0);
            let mut confidence = (0.30 + 0.25 * evidence + 0.20 * regularity).min(cap);
            if sequence_novelty {
                confidence += 0.10;
            }
            let (data_quality, ring_loss_ratio) = match ring_loss_ratio {
                Some(r) if r <= 0.01 => ("VERIFIED_CLEAN", Some(r)),
                Some(r) => {
                    confidence -= r.min(0.30);
                    ("DEGRADED", Some(r))
                }
                None => {
                    confidence = confidence.min(0.65);
                    ("UNKNOWN", None)
                }
            };
            let (technique, technique_name, evidence, port_53_only) = match sample.port {
                Some(53) => (
                    "T1095",
                    "Non-Layer Protocol / Application Layer Protocol",
                    "DNS-like port-53 CONNECT activity only; no DNS query metadata was observed",
                    true,
                ),
                Some(80 | 443 | 8080 | 8443) => (
                    "T1071.001",
                    "Application Layer Protocol: Web Protocols",
                    "periodic CONNECT to a common web-protocol port; no payload or SNI observed",
                    false,
                ),
                _ => (
                    "T1095",
                    "Non-Layer Protocol / Application Layer Protocol",
                    "periodic CONNECT to a destination and port; no application metadata observed",
                    false,
                ),
            };
            let confidence = if port_53_only {
                // Port 53 without a DNS query is weaker evidence than a web
                // port is for T1071.001; keep the beacon signal, but do not
                // present it with web-protocol-level certainty.
                confidence.min(0.65)
            } else {
                confidence
            };
            let confidence = confidence.clamp(0.0, cap);
            if confidence < 0.45 {
                break 'evaluate None;
            }
            let confidence_label = if confidence >= 0.75 {
                ConfidenceLabel::High
            } else if confidence >= 0.55 {
                ConfidenceLabel::Medium
            } else {
                ConfidenceLabel::Low
            };

            break 'evaluate Some(C2Assessment {
                detector: "local_beaconing_v1",
                detector_version: "2",
                pattern,
                confidence,
                confidence_label,
                reason,
                evidence,
                technique,
                technique_name,
                tactic: "Command and Control",
                dest_ip: sample.destination.clone(),
                dest_port: sample.port,
                dial_count: times.len(),
                interval_count: intervals_ns.len(),
                mean_interval_secs: mean_ns / 1_000_000_000.0,
                median_interval_secs: median_ns / 1_000_000_000.0,
                mad_interval_secs: mad_ns / 1_000_000_000.0,
                jitter_coefficient: decision_jitter,
                window_jitter_coefficient: window_jitter,
                run_jitter_coefficient: run_jitter,
                interval_statistics_population: statistics_population,
                destination_novelty: sequence_novelty,
                data_quality,
                ring_loss_ratio,
                unsupported_inputs: unsupported_inputs(),
                input_support_matrix: input_support_matrix(),
                enforcement_requested: false,
            });
        };
        self.enforce_actor_cap();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> C2Rules {
        C2Rules {
            enabled: true,
            min_dials: 6,
            window_secs: 3600,
            min_interval_secs: 10,
            max_interval_secs: 600,
            max_jitter: 0.5,
            cooldown_secs: 900,
            max_actors: 4,
            max_history: 16,
            max_destinations: 8,
        }
    }

    fn dial(sec: u64) -> ConnectSample {
        // +1 keeps the synthetic epoch off zero: a real ring record with
        // ts_ns == 0 carries no kernel timestamp and is rejected by the
        // detector, so tests that need a valid clock must not use it.
        ConnectSample {
            ts_ns: (sec + 1) * 1_000_000_000,
            pid: 42,
            starttime: Some(7),
            destination: "203.0.113.9".to_string(),
            port: Some(443),
        }
    }

    /// A beacon with ±20% jitter on a 60-second cadence.
    fn jittery_beacon() -> Vec<ConnectSample> {
        [0, 49, 121, 179, 240, 310, 358]
            .into_iter()
            .map(dial)
            .collect()
    }

    #[test]
    fn unsupported_inputs_are_declared_not_guessed() {
        assert_eq!(C2Input::Connect.support(), InputSupport::Supported);
        for input in [C2Input::DnsQuery, C2Input::TlsMetadata, C2Input::FlowBytes] {
            assert_eq!(input.support(), InputSupport::Unsupported);
            assert!(input.unsupported_reason().unwrap().len() > 20);
        }
        let matrix = input_support_matrix();
        assert_eq!(matrix.len(), 4);
        assert_eq!(matrix[0], ("connect", InputSupport::Supported));
        assert_eq!(matrix[1].1, InputSupport::Unsupported);
        let declared = unsupported_inputs();
        assert_eq!(declared.len(), 3);
        assert!(declared.iter().any(|(n, _)| *n == "dns_query"));
        assert!(declared.iter().any(|(n, _)| *n == "tls_metadata"));
        assert!(declared.iter().any(|(n, _)| *n == "flow_bytes"));
    }

    #[test]
    fn a_regular_beacon_reaches_a_confidence_bearing_finding() {
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        for d in jittery_beacon() {
            if found.is_none() {
                found = tracker.observe(&d, Some(0.0));
            }
        }
        let a = found.expect("seven jittered dials are enough evidence");
        assert_eq!(a.reason, "periodic_connect_beaconing");
        assert_eq!(a.technique, "T1071.001");
        assert_eq!(a.tactic, "Command and Control");
        assert_eq!(a.dial_count, 7);
        assert!(a.jitter_coefficient <= 0.5);
        assert!(a.confidence >= 0.45);
        assert!(!a.enforcement_requested);
        assert_eq!(a.data_quality, "VERIFIED_CLEAN");
        assert_eq!(a.unsupported_inputs.len(), 3);
    }

    #[test]
    fn a_benign_burst_never_fires() {
        let mut tracker = C2Tracker::new(rules());
        // Twenty dials in ten seconds: a retry loop, not a beacon.
        let mut found = None;
        for i in 0..20u64 {
            if found.is_none() {
                found = tracker.observe(&dial(i), Some(0.0));
            }
        }
        assert!(found.is_none(), "a sub-floor burst must be rejected");
    }

    #[test]
    fn zero_and_rewound_kernel_timestamps_are_never_counted() {
        let mut tracker = C2Tracker::new(rules());
        let mut unsigned = dial(60);
        unsigned.ts_ns = 0;
        assert!(tracker.observe(&unsigned, Some(0.0)).is_none());
        assert!(
            tracker.actors.is_empty(),
            "a clockless sample is not an actor"
        );

        let mut found = None;
        for d in jittery_beacon() {
            if found.is_none() {
                found = tracker.observe(&d, Some(0.0));
            }
        }
        assert!(found.is_some(), "the valid run must still be judged");

        // The per-CPU ring can hand userspace an older record after a newer
        // one. Before the monotonic guard this subtracted the timestamps in
        // the wrong order and panicked in debug builds; here it is ignored
        // without poisoning the sequence or emptying the actor's history.
        let late = dial(1);
        assert!(tracker.observe(&late, Some(0.0)).is_none());
        let state = &tracker.actors[&(42, Some(7))];
        assert_eq!(state.observations.len(), 7);
        assert_eq!(state.last_seen_ns, 359 * 1_000_000_000);
    }

    #[test]
    fn random_intervals_do_not_fire() {
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        for sec in [0, 12, 400, 430, 900, 2500, 3200] {
            if found.is_none() {
                found = tracker.observe(&dial(sec), Some(0.0));
            }
        }
        assert!(found.is_none(), "wildly varying intervals are not a beacon");
    }

    #[test]
    fn a_destination_behind_a_long_gap_is_a_new_sequence() {
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        // Three cadenced dials, a 13x gap beyond the 600 s ceiling, then more.
        // The ceiling rejects the whole series rather than smoothing the outlier.
        for sec in [0, 60, 120, 900, 960, 1020, 1080, 1140] {
            if found.is_none() {
                found = tracker.observe(&dial(sec), Some(0.0));
            }
        }
        assert!(found.is_none());
    }

    #[test]
    fn ring_loss_lowers_confidence_and_no_reading_caps_it() {
        let clean = {
            let mut t = C2Tracker::new(rules());
            let mut out = None;
            for d in jittery_beacon() {
                if out.is_none() {
                    out = t.observe(&d, Some(0.0));
                }
            }
            out.unwrap()
        };
        let lossy = {
            let mut t = C2Tracker::new(rules());
            let mut out = None;
            for d in jittery_beacon() {
                if out.is_none() {
                    out = t.observe(&d, Some(0.30));
                }
            }
            out.unwrap()
        };
        let unknown = {
            let mut t = C2Tracker::new(rules());
            let mut out = None;
            for d in jittery_beacon() {
                if out.is_none() {
                    out = t.observe(&d, None);
                }
            }
            out.unwrap()
        };
        assert!(lossy.confidence < clean.confidence);
        assert_eq!(lossy.data_quality, "DEGRADED");
        assert_eq!(unknown.data_quality, "UNKNOWN");
        assert!(
            unknown.confidence <= 0.65,
            "an unread loss counter caps confidence"
        );
    }

    #[test]
    fn a_jittered_cadence_is_detected_with_robust_statistics_and_capped_confidence() {
        // Intervals alternate short/long: the mean-based rule sees a CV above
        // max_jitter and used to discard the whole series. Median/MAD see a
        // stable centre (≈74 s) with bounded dispersion, which is the shape of
        // an implant adding jitter to a heartbeat.
        let intervals = [30u64, 140, 25, 150, 35, 145, 40, 135, 45];
        let mut at = 0u64;
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        for step in intervals {
            at += step;
            if found.is_none() {
                found = tracker.observe(&dial(at), Some(0.0));
            }
        }
        let a = found.expect("a sustained jittered cadence must be assessed");
        assert_eq!(a.pattern, "jittered_cadence");
        assert_eq!(a.reason, "jittered_connect_beaconing");
        assert_eq!(a.detector_version, "2");
        assert!(
            a.confidence <= 0.72,
            "jitter is weaker evidence: {}",
            a.confidence
        );
        assert!(a.median_interval_secs > 20.0 && a.median_interval_secs < 200.0);
        assert!(a.mad_interval_secs > 0.0);
        assert_eq!(a.interval_statistics_population, "current_in_band_run");
        assert!(a.window_jitter_coefficient > a.jitter_coefficient);
        assert_eq!(a.jitter_coefficient, a.run_jitter_coefficient);
        assert!(!a.enforcement_requested);
    }

    #[test]
    fn a_long_gap_does_not_borrow_the_statistics_of_the_run_after_it() {
        // The old rule could decide from the final in-band run while shipping a
        // median/MAD/jitter triplet that mixed the 30-minute gap into the same
        // numbers. The finding may still be raised from the run, but it must
        // name that population and keep the full-window jitter visible.
        // The first step places a dial at the synthetic epoch; the second is
        // the 30-minute gap, so the intervals really are [1800, 60, ...].
        let intervals = [0u64, 1800, 60, 60, 60, 60, 60, 60, 60];
        let mut at = 0u64;
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        for step in intervals {
            at += step;
            if found.is_none() {
                found = tracker.observe(&dial(at), Some(0.0));
            }
        }
        let a = found.expect("the seven-dial run after the gap is valid evidence");
        assert_eq!(a.pattern, "jittered_cadence");
        assert_eq!(a.interval_statistics_population, "current_in_band_run");
        assert_eq!(a.median_interval_secs, 60.0);
        assert_eq!(a.mad_interval_secs, 0.0);
        assert_eq!(a.jitter_coefficient, 0.0);
        assert!(
            a.window_jitter_coefficient > 0.5,
            "the gap must still be visible as full-window dispersion: {}",
            a.window_jitter_coefficient
        );
    }

    #[test]
    fn short_jittered_runs_stay_below_the_evidence_bar() {
        // Seven dials is enough for a FIXED cadence; a jittered pattern needs
        // two more so a handful of coincidentally spaced retries is not called
        // a beacon.
        let mut at = 0u64;
        let mut tracker = C2Tracker::new(rules());
        for step in [30u64, 120, 40, 110, 35, 125] {
            at += step;
            assert!(tracker.observe(&dial(at), Some(0.0)).is_none());
        }
    }

    #[test]
    fn jitter_does_not_excuse_bursts_or_day_long_gaps() {
        let mut tracker = C2Tracker::new(rules());
        let mut at = 0u64;
        for step in [5u64, 120, 5, 110, 5, 125, 5, 115, 5] {
            at += step;
            assert!(
                tracker.observe(&dial(at), Some(0.0)).is_none(),
                "a sub-floor retry burst is not a beacon"
            );
        }
        let mut slow = C2Tracker::new(rules());
        let mut at = 0u64;
        for step in [1600u64, 120, 1800, 110, 1700, 125, 1900, 115, 1650] {
            at += step;
            assert!(
                slow.observe(&dial(at), Some(0.0)).is_none(),
                "a once-every-30-minute poll is not a beacon inside this window"
            );
        }
    }

    #[test]
    fn cooldown_prevents_one_finding_per_dial() {
        let mut tracker = C2Tracker::new(rules());
        let mut count = 0;
        // 60 dials at one-minute spacing is one hour. A 900 s cooldown allows
        // at most five findings (t=0, 15, 30, 45, 60 min), not one per dial.
        for step in 0..60u64 {
            if tracker.observe(&dial(step * 60), Some(0.0)).is_some() {
                count += 1;
            }
        }
        assert!(count <= 5, "a one-hour beacon produced {count} findings");
    }

    #[test]
    fn a_recycled_pid_does_not_inherit_history() {
        let mut tracker = C2Tracker::new(rules());
        for d in jittery_beacon() {
            let _ = tracker.observe(&d, Some(0.0));
        }
        let key_old = (42, Some(7));
        let key_new = (42, Some(9));
        assert!(tracker.actors.contains_key(&key_old));
        assert!(!tracker.actors.contains_key(&key_new));
        let mut reused = dial(1000);
        reused.starttime = Some(9);
        let mut fired = false;
        for _ in 0..3 {
            if tracker.observe(&reused, Some(0.0)).is_some() {
                fired = true;
            }
        }
        assert!(
            !fired,
            "a new process under the same pid starts with no history"
        );
    }

    #[test]
    fn memory_is_bounded_by_actor_and_history_caps() {
        let mut r = rules();
        r.min_dials = 20; // prevent findings from distracting the bound check
        r.max_actors = 3;
        r.max_history = 5;
        r.max_destinations = 2;
        let mut tracker = C2Tracker::new(r);
        for pid in 1..100u32 {
            for sec in 1..20u64 {
                let mut s = dial(sec * 60);
                s.pid = pid;
                s.starttime = Some(pid as u64);
                s.destination = format!("203.0.113.{}", sec % 4);
                let _ = tracker.observe(&s, Some(0.0));
            }
        }
        assert!(tracker.actors.len() <= 3);
        for state in tracker.actors.values() {
            assert!(state.observations.len() <= 5);
            assert!(state.known_destinations.len() <= 2);
        }
    }

    #[test]
    fn a_disabled_detector_records_nothing() {
        let mut r = rules();
        r.enabled = false;
        let mut tracker = C2Tracker::new(r);
        for d in jittery_beacon() {
            assert!(tracker.observe(&d, Some(0.0)).is_none());
        }
        assert!(tracker.actors.is_empty());
    }

    fn dial_on(sec: u64, port: Option<u16>) -> ConnectSample {
        ConnectSample { port, ..dial(sec) }
    }

    fn beacon_on(port: Option<u16>) -> Vec<ConnectSample> {
        [0, 49, 121, 179, 240, 310, 358]
            .into_iter()
            .map(|sec| dial_on(sec, port))
            .collect()
    }

    #[test]
    fn port_53_connects_are_dns_like_never_definitive_dns() {
        // The CONNECT sample has no transport discriminator in the shipped
        // detector, so a TCP/53 dial and a connected-UDP/53 dial are represented
        // identically here. That is itself the honesty boundary being tested:
        // neither becomes a DNS transaction.
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        for sample in beacon_on(Some(53)) {
            if found.is_none() {
                found = tracker.observe(&sample, Some(0.0));
            }
        }
        let a = found.expect("a cadenced port-53 dial sequence is still beaconing evidence");
        assert_ne!(
            a.technique, "T1071.004",
            "port 53 alone is not DNS evidence"
        );
        assert_eq!(a.technique, "T1095");
        assert!(
            a.evidence
                .contains("DNS-like port-53 CONNECT activity only"),
            "{}",
            a.evidence
        );
        assert!(a.confidence <= 0.65, "port-53 certainty must be capped");
        assert!(a.unsupported_inputs.iter().any(|(n, _)| *n == "dns_query"));

        // The same cadence with no port at all is still beaconing evidence, but
        // it must not borrow DNS-like wording from the port-53 case.
        let mut unknown_port = C2Tracker::new(rules());
        let mut found = None;
        for sample in beacon_on(None) {
            if found.is_none() {
                found = unknown_port.observe(&sample, Some(0.0));
            }
        }
        let a = found.expect("an unknown-port dial sequence is still beaconing evidence");
        assert_eq!(a.technique, "T1095");
        assert!(
            !a.evidence.contains("DNS-like"),
            "no port means no DNS-like claim: {}",
            a.evidence
        );
    }

    #[test]
    fn a_connect_event_without_dns_metadata_cannot_claim_a_dns_query() {
        let mut tracker = C2Tracker::new(rules());
        let mut found = None;
        for sample in beacon_on(Some(53)) {
            if found.is_none() {
                found = tracker.observe(&sample, None);
            }
        }
        let a = found.unwrap();
        assert_eq!(a.data_quality, "UNKNOWN");
        assert!(a.evidence.contains("no DNS query metadata"));
        assert_eq!(a.input_support_matrix[1].1, InputSupport::Unsupported);
        assert!(!a.enforcement_requested);
    }
}
