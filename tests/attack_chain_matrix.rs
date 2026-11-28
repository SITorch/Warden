//! Structural freeze for the cross-event correlation contract.
//!
//! This test runs unprivileged and reads source text only. It exists for the
//! same reason `capability_matrix.rs` exists: prose can drift away from code
//! without a compile error, and a correlation rule described as "observe only"
//! must stay observe only. It does NOT claim a live kernel result; the chains
//! are proven here by synthetic events in `src/correlate.rs` unit tests.

const CORRELATE: &str = include_str!("../src/correlate.rs");
const DETECT: &str = include_str!("../src/detect.rs");
const MAIN: &str = include_str!("../src/main.rs");
const README: &str = include_str!("../README.md");
const EXAMPLE: &str = include_str!("../config/warden.example.toml");

#[test]
fn all_four_chain_names_are_pinned_in_code_and_in_the_operator_doc() {
    for name in [
        "suspicious_exec_then_egress",
        "privilege_then_persistence",
        "suspicious_listener_accepted",
        "unsanctioned_dial_established",
    ] {
        assert!(
            CORRELATE.contains(name),
            "the correlator lost the chain {name:?}"
        );
        assert!(
            README.contains(name),
            "README lost the chain {name:?}; an operator would be running a rule they cannot read"
        );
    }
}

#[test]
fn the_chain_finding_type_is_stable_and_observe_only() {
    assert!(
        DETECT.contains("#[serde(rename = \"endpoint:attack_chain\")]"),
        "the wire event type must not be renamed or derived from a Rust variant"
    );
    assert!(README.contains("endpoint:attack_chain"));
    assert!(
        CORRELATE.contains("wants_kill: false"),
        "a chained observation must never become a kill request"
    );
    assert!(
        !CORRELATE.contains("wants_kill: true"),
        "no chain may ever request enforcement"
    );
    assert!(
        CORRELATE.contains("no payload, DNS or TLS metadata"),
        "the correlator must keep its no-claim boundary visible"
    );
}

#[test]
fn every_decoded_event_reaches_the_correlator_with_the_judge_answer() {
    assert!(
        MAIN.contains("detector.judge(&event)"),
        "the daemon must still run the ordinary judge"
    );
    assert!(
        MAIN.contains("detector.correlate(&event, primary.as_ref())"),
        "the correlator must see every decoded event, including ones the judge declined"
    );
}

#[test]
fn the_example_config_documents_the_bounded_defaults() {
    for phrase in [
        "[correlation]",
        "enabled = true",
        "window_ms = 10000",
        "max_actors = 4096",
    ] {
        assert!(
            EXAMPLE.contains(phrase),
            "the example config lost {phrase:?} for the correlation rules"
        );
    }
}

#[test]
fn correlator_state_is_bounded_and_uses_the_kernel_clock() {
    assert!(
        CORRELATE.contains("MAX_ANCHORS_PER_ACTOR: usize = 8"),
        "per-actor anchor state must stay bounded"
    );
    assert!(
        CORRELATE.contains("if !self.rules.enabled || e.ts_ns == 0"),
        "an event without a kernel timestamp must not anchor a chain"
    );
    assert!(
        CORRELATE.contains("e.ts_ns < self.last_ts_ns"),
        "a backwards clock must clear correlation history"
    );
    assert!(
        CORRELATE.contains("same_process(anchor.starttime, starttime)"),
        "a recycled pid must not inherit an earlier process's chain"
    );
}
