//! policy.rs — network policy evaluation and enforcement preflight (Phase 3).
//!
//! This module separates four things the old code conflated:
//!
//! 1. **policy evaluation** — what the configured rules say about a destination;
//! 2. **enforcement** — whether a kernel primitive can actually deny it;
//! 3. **verification** — whether the primitive is attached and ready;
//! 4. **reporting** — what Warden is allowed to *claim* about protection.
//!
//! The shipped build has no cgroup connect/sendmsg deny program. That is a fact
//! pinned by `tests/capability_matrix.rs::no_egress_block_program_ships` and
//! `tests/network_coverage_matrix.rs`. Consequently `Preflight::state()` can
//! never return `EnforcementState::Enforce` in this build: the only constructor
//! of that state requires positive proof of a kernel deny primitive. A config
//! knob cannot manufacture that proof, and a `deny_destinations` rule cannot
//! silently upgrade "we would like to block this" into "this is blocked".
//!
//! A deny-rule match therefore produces a **critical observe-only finding**
//! that says, in its own JSON, that traffic was NOT blocked. This is a policy
//! signal, not a firewall. Nothing here changes host networking, mode, or the
//! observe-only deploy invariants.

use serde::Serialize;

use crate::config::Mode;

/// What a policy rule says about a destination. Independent of what the kernel
/// can do — a `Deny` decision with no primitive is still `Deny` as a decision,
/// and must be reported as unenforced rather than as allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkAction {
    Allow,
    Observe,
    Deny,
}

/// What Warden may truthfully report about network enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementState {
    /// No deny rules configured; nothing to enforce.
    Disabled,
    /// Rules are evaluated and findings emitted, traffic is untouched.
    Observe,
    /// A primitive exists but attachment or policy-map readiness failed.
    Degraded,
    /// Deny rules exist and no kernel deny primitive is available.
    EnforcementUnavailable,
    /// Positive proof of a kernel deny primitive, attachment and policy map.
    /// Unreachable in the shipped build; see [`Preflight::state`].
    Enforce,
}

impl EnforcementState {
    pub fn word(self) -> &'static str {
        match self {
            EnforcementState::Disabled => "DISABLED",
            EnforcementState::Observe => "OBSERVE",
            EnforcementState::Degraded => "DEGRADED",
            EnforcementState::EnforcementUnavailable => "ENFORCEMENT_UNAVAILABLE",
            EnforcementState::Enforce => "ENFORCE",
        }
    }

    /// True unless every preflight condition was positively verified.
    pub fn cannot_claim_protection(self) -> bool {
        self != EnforcementState::Enforce
    }
}

/// Capability preflight. Every field defaults to "not proven": a failed or
/// unperformed check must never be read as success.
#[derive(Debug, Clone, Copy, Default)]
pub struct Preflight {
    pub kernel_deny_program: bool,
    pub hooks_attached: bool,
    pub policy_map_ready: bool,
}

impl Preflight {
    /// The conservative default preflight: proof of NO attached deny program.
    /// Phase 7 does ship four cgroup socket-address programs, but they attach
    /// only for an explicitly enabled isolated cgroup. This constant is the
    /// Rust-side "not proven" baseline, not a config switch and not a claim
    /// that the programs are absent from the object. Only replace it with
    /// [`Preflight::from_facts`] when the kernel returned positive proof.
    pub fn shipped() -> Self {
        Self {
            kernel_deny_program: false,
            hooks_attached: false,
            policy_map_ready: false,
        }
    }

    /// Build a preflight from facts the kernel actually returned (program
    /// loaded, every cgroup hook attached, policy map in a known generation).
    /// Phase 7's `egress::EgressRuntime` calls this; nothing in the config can
    /// call it. The default remains [`Preflight::shipped`], so every existing
    /// caller that has not been handed positive proof still reports observe-only.
    pub fn from_facts(
        kernel_deny_program: bool,
        hooks_attached: bool,
        policy_map_ready: bool,
    ) -> Self {
        Self {
            kernel_deny_program,
            hooks_attached,
            policy_map_ready,
        }
    }

    /// Resolve the reportable state from mode, rules and positive proof.
    ///
    /// `Enforce` is constructed only when the mode asks for it, deny rules
    /// exist, **and** all three preflight facts are true. Observe mode always
    /// degrades to `Observe`/`Disabled`: posture is decided by mode, never by
    /// the presence of a rule alone.
    pub fn state(self, mode: Mode, deny_rules_present: bool) -> EnforcementState {
        if !deny_rules_present {
            return EnforcementState::Disabled;
        }
        if mode != Mode::Enforce {
            return EnforcementState::Observe;
        }
        if !self.kernel_deny_program {
            return EnforcementState::EnforcementUnavailable;
        }
        if !self.hooks_attached || !self.policy_map_ready {
            return EnforcementState::Degraded;
        }
        EnforcementState::Enforce
    }
}

/// The annotation attached to a deny-rule finding. It exists so that no reader
/// of the record can mistake a policy decision for a kernel disposition.
#[derive(Debug, Clone, Serialize)]
pub struct DenyDecision {
    pub action: NetworkAction,
    pub enforcement_state: EnforcementState,
    pub traffic_blocked: bool,
    pub note: &'static str,
}

/// The startup/reload posture of the network policy, logged so an operator can
/// see that deny rules are *decisions only* in this build. Constructed from
/// config, never from a guess: no rule → `Allow`, rules in observe mode →
/// `Observe`, rules in enforce mode → `Deny` (with an honest, non-Enforce
/// enforcement state from `Preflight::shipped()`).
#[derive(Debug, Clone, Serialize)]
pub struct PolicyPosture {
    pub action: NetworkAction,
    pub enforcement: EnforcementState,
    pub deny_rules: usize,
}

impl PolicyPosture {
    pub fn new(mode: Mode, deny_rules: usize) -> Self {
        Self::with_preflight(mode, deny_rules, Preflight::shipped())
    }

    /// Posture built from verified runtime facts. Used after the cgroup hooks
    /// are attached so the startup journal can say "kernel deny primitive
    /// verified" truthfully; before that, [`PolicyPosture::new`] reports the
    /// shipped observe-only posture.
    pub fn with_preflight(mode: Mode, deny_rules: usize, preflight: Preflight) -> Self {
        let present = deny_rules > 0;
        let enforcement = preflight.state(mode, present);
        let action = if !present {
            NetworkAction::Allow
        } else if mode != Mode::Enforce {
            NetworkAction::Observe
        } else {
            NetworkAction::Deny
        };
        Self {
            action,
            enforcement,
            deny_rules,
        }
    }

    /// The one-line summary used by the startup journal. It says both what the
    /// policy asks for and what can actually be enforced, because those are
    /// different facts and conflating them is exactly the W-01 failure mode.
    pub fn summary(&self) -> String {
        let caveat = if self.enforcement.cannot_claim_protection() {
            "traffic will NOT be blocked — findings only"
        } else {
            "kernel deny primitive verified"
        };
        format!(
            "network policy: action={:?}, enforcement={} ({} deny rule(s)); {}",
            self.action,
            self.enforcement.word(),
            self.deny_rules,
            caveat
        )
    }
}

impl DenyDecision {
    /// Build the honest annotation for this build. `traffic_blocked` is always
    /// false here: there is no primitive to set it true, and hard-coding the
    /// false is deliberate — no config or caller argument can override it.
    pub fn observe_only(mode: Mode) -> Self {
        let state = Preflight::shipped().state(mode, true);
        Self {
            action: NetworkAction::Deny,
            enforcement_state: state,
            traffic_blocked: false,
            note: "policy says deny; no egress deny primitive is active for this finding (the \
                   cgroup hooks attach only with [egress] enabled=true, and denial only with \
                   arm=true), so the connection was NOT blocked by Warden — this is an \
                   observe-only finding, not enforcement",
        }
    }

    /// The annotation for a Phase 7 kernel-backed finding. `traffic_blocked`
    /// is set ONLY when the caller supplies positive evidence that the kernel
    /// actually returned a denial — a matched DENY rule or an ARMED config alone
    /// is not such evidence. A DENY decision is not a traffic disposition.
    pub fn verified(mode: Mode, preflight: Preflight, kernel_denied: bool) -> Self {
        let state = preflight.state(mode, true);
        let actually_blocked = kernel_denied && state == EnforcementState::Enforce;
        Self {
            action: NetworkAction::Deny,
            enforcement_state: state,
            traffic_blocked: actually_blocked,
            note: if actually_blocked {
                "kernel cgroup egress program returned -EPERM for this destination; traffic was \
                 blocked and this is an enforcement record"
            } else {
                "a DENY rule matched, but this finding carries no verified kernel denial for its \
                 own connection (hooks not all attached, policy map degraded, arm=false, or no \
                 denial observed); do not read it as traffic having been blocked"
            },
        }
    }

    pub fn is_honest(&self) -> bool {
        // The observe-only constructor must never claim a block. The verified
        // constructor is honest when any claimed block is backed by Enforce.
        !self.traffic_blocked || self.enforcement_state == EnforcementState::Enforce
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_build_cannot_report_enforce() {
        for mode in [Mode::Observe, Mode::Enforce] {
            let state = Preflight::shipped().state(mode, true);
            assert_ne!(state, EnforcementState::Enforce, "{mode:?}");
            assert!(state.cannot_claim_protection());
        }
    }

    #[test]
    fn no_rules_is_disabled_and_observe_mode_is_never_enforce() {
        let full = Preflight {
            kernel_deny_program: true,
            hooks_attached: true,
            policy_map_ready: true,
        };
        assert_eq!(full.state(Mode::Enforce, false), EnforcementState::Disabled);
        assert_eq!(full.state(Mode::Observe, true), EnforcementState::Observe);
    }

    #[test]
    fn enforce_requires_all_three_positive_facts() {
        let all = Preflight {
            kernel_deny_program: true,
            hooks_attached: true,
            policy_map_ready: true,
        };
        assert_eq!(all.state(Mode::Enforce, true), EnforcementState::Enforce);
        let missing_hook = Preflight {
            hooks_attached: false,
            ..all
        };
        assert_eq!(
            missing_hook.state(Mode::Enforce, true),
            EnforcementState::Degraded
        );
        let missing_map = Preflight {
            policy_map_ready: false,
            ..all
        };
        assert_eq!(
            missing_map.state(Mode::Enforce, true),
            EnforcementState::Degraded
        );
        let no_program = Preflight {
            kernel_deny_program: false,
            ..all
        };
        assert_eq!(
            no_program.state(Mode::Enforce, true),
            EnforcementState::EnforcementUnavailable
        );
    }

    #[test]
    fn a_deny_decision_never_claims_traffic_was_blocked() {
        for mode in [Mode::Observe, Mode::Enforce] {
            let d = DenyDecision::observe_only(mode);
            assert_eq!(d.action, NetworkAction::Deny);
            assert!(!d.traffic_blocked);
            assert!(d.is_honest());
            let json = serde_json::to_value(&d).unwrap();
            assert_eq!(json["traffic_blocked"], false);
            assert_ne!(json["enforcement_state"], "ENFORCE");
            assert!(json["note"].as_str().unwrap().contains("NOT blocked"));
        }
    }

    #[test]
    fn a_verified_decision_requires_both_proof_and_an_observed_denial() {
        let full = Preflight::from_facts(true, true, true);
        // A matched rule with no observed kernel denial is still not a block.
        let matched_only = DenyDecision::verified(Mode::Enforce, full, false);
        assert!(!matched_only.traffic_blocked);
        assert!(matched_only.is_honest());
        // Observed denial + full proof + enforce mode is the one honest block.
        let blocked = DenyDecision::verified(Mode::Enforce, full, true);
        assert!(blocked.traffic_blocked);
        assert_eq!(blocked.enforcement_state, EnforcementState::Enforce);
        assert!(blocked.is_honest());
        // Observed denial in observe mode still cannot claim a block.
        let observe = DenyDecision::verified(Mode::Observe, full, true);
        assert!(!observe.traffic_blocked);
        // Partial proof degrades the claim even with an observed denial.
        let partial = DenyDecision::verified(
            Mode::Enforce,
            Preflight::from_facts(true, false, true),
            true,
        );
        assert!(!partial.traffic_blocked);
        assert_eq!(partial.enforcement_state, EnforcementState::Degraded);
    }
}
