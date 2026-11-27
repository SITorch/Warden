//! egress.rs — the userspace half of Phase 7's cgroup egress enforcement.
//!
//! This module is deliberately separate from `network_rules.deny_destinations`
//! (the Phase 3 OBSERVE policy) and from `policy.rs` (the honesty layer). Three
//! distinct facts are kept apart here, because conflating any two of them is
//! how a policy engine grows a false "traffic blocked" claim:
//!
//!   1. **desired rules** — exact `(family, protocol, addr, port)` tuples an
//!      operator wrote in `[egress].deny`;
//!   2. **verified attachment** — which of the four cgroup programs actually
//!      loaded and attached to the configured cgroup (a fact returned by the
//!      kernel, never by the config);
//!   3. **kernel disposition** — the `egress_stats` counters the kernel bumped
//!      when a rule matched or a denial happened.
//!
//! Two independent switches must be on before a matching DENY actually refuses
//! traffic: the hooks must be attached (only when `[egress] enabled = true` and
//! a cgroup path was supplied) **and** `CFG_EGRESS_ARM` must be 1. Both default
//! OFF. A rule in the map with arm=0 is an audit record that says "would deny",
//! nothing more.
//!
//! Map updates are transactional with rollback: a generation is published only
//! when every insert landed. A failed insert restores the previous generation's
//! entries and reports `policy_map_ready = false`, so `policy.rs` degrades its
//! claim instead of silently reporting partial coverage.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use aya::maps::{Array, HashMap, MapData};
use serde::{Deserialize, Serialize};

use crate::policy::Preflight;

/// Capacity of `egress_policy` — must match `WARDEN_EGRESS_POLICY_MAX` in
/// `bpf/warden.h`, checked against the shipped object by a structural test.
pub const EGRESS_POLICY_MAX: usize = 256;

/// Slot count of `egress_stats` — must match `WARDEN_EGRESS_STATS`.
pub const EGRESS_STATS: usize = 4;

/// `enum warden_egress_stat` in warden.h.
pub const STAT_HIT_ALLOW: u32 = 0;
pub const STAT_HIT_DENY: u32 = 1;
pub const STAT_DENIED: u32 = 2;
pub const STAT_MAP_FULL: u32 = 3;

/// `CFG_EGRESS_ARM` — must match warden.h. The kernel fails closed to SHADOW
/// when this slot is absent or 0, so an unseeded map can never deny by mistake.
pub const CFG_EGRESS_ARM: u32 = 13;

/// Wire-identical to `struct warden_egress_key` in `bpf/warden.h`.
///
/// `port` carries the port in NETWORK byte order as a *native integer value*:
/// the BPF side stores `ctx->user_port` verbatim (a 16-bit load of
/// `sockaddr_in.sin_port`), and this side stores `port.to_be()`. On either
/// endianness those are the same integer, hence the same bytes in the map.
/// `addr` carries 4 (IPv4) or 16 (IPv6) network-order octets in the leading
/// bytes; the rest stay zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EgressKey {
    pub family: u32,
    pub protocol: u32,
    pub addr: [u8; 16],
    pub port: u16,
    pub _pad: u16,
}

// SAFETY: repr(C), fixed size (28 bytes), all integer fields, every bit pattern
// valid, no pointer/padding-sensitive layout in the value semantics — the
// aya::Pod contract, same as guard::InodeKey.
unsafe impl aya::Pod for EgressKey {}

/// Wire-identical to `struct warden_egress_rule` in `bpf/warden.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressRule {
    pub deny: u32,
    pub generation: u32,
}

// SAFETY: repr(C), two u32s, no padding, every bit pattern valid.
unsafe impl aya::Pod for EgressRule {}

/// The smallest surface of `egress_policy` the reload state machine needs.
///
/// Keeping this as a trait is what lets map insert/remove/enumeration failures
/// be injected in an unprivileged test. The production implementation is the
/// real aya hash map; no test-only fallback exists in `Loader`.
pub trait EgressPolicyMap {
    fn entries(&self) -> anyhow::Result<BTreeMap<EgressKey, EgressRule>>;
    fn insert(&mut self, key: &EgressKey, value: &EgressRule) -> anyhow::Result<()>;
    fn remove(&mut self, key: &EgressKey) -> anyhow::Result<()>;
}

impl EgressPolicyMap for HashMap<MapData, EgressKey, EgressRule> {
    fn entries(&self) -> anyhow::Result<BTreeMap<EgressKey, EgressRule>> {
        let mut out = BTreeMap::new();
        for entry in self.iter() {
            let (key, value) =
                entry.map_err(|e| anyhow::anyhow!("could not enumerate egress_policy: {e}"))?;
            out.insert(key, value);
        }
        Ok(out)
    }

    fn insert(&mut self, key: &EgressKey, value: &EgressRule) -> anyhow::Result<()> {
        self.insert(key, value, 0).map_err(|e| {
            anyhow::anyhow!("could not insert egress rule {key:?}; map full or kernel refused: {e}")
        })
    }

    fn remove(&mut self, key: &EgressKey) -> anyhow::Result<()> {
        self.remove(key)
            .map_err(|e| anyhow::anyhow!("could not remove egress rule {key:?}: {e}"))
    }
}

/// The arm slot is a second, independent switch. Writes are never trusted until
/// read back, so the same interface exposes both directions.
pub trait EgressArmSlot {
    fn write(&mut self, on: bool) -> anyhow::Result<()>;
    fn read(&self) -> anyhow::Result<bool>;
}

impl EgressArmSlot for Array<MapData, u32> {
    fn write(&mut self, on: bool) -> anyhow::Result<()> {
        self.set(CFG_EGRESS_ARM, u32::from(on), 0)
            .map_err(|e| anyhow::anyhow!("could not write CFG_EGRESS_ARM: {e}"))
    }

    fn read(&self) -> anyhow::Result<bool> {
        let raw = self
            .get(&CFG_EGRESS_ARM, 0)
            .map_err(|e| anyhow::anyhow!("could not read CFG_EGRESS_ARM: {e}"))?;
        Ok(raw == 1)
    }
}

/// The one counter a *userspace* writer must increment: a refused rule insert.
///
/// The kernel increments slots 0-2 from the decision path; slot 3 exists so a
/// failed `egress_policy` update is visible in the same array the operator
/// samples. Before this trait existed the slot was documented and read but
/// never written, so "map_full=0" could not be distinguished from "failures
/// are not counted".
pub trait EgressStatsWriter {
    fn note_map_full(&mut self) -> anyhow::Result<()>;
}

impl EgressStatsWriter for Array<MapData, u64> {
    fn note_map_full(&mut self) -> anyhow::Result<()> {
        let before = self
            .get(&STAT_MAP_FULL, 0)
            .map_err(|e| anyhow::anyhow!("could not read WARDEN_EGRESS_MAP_FULL: {e}"))?;
        let after = before
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("WARDEN_EGRESS_MAP_FULL counter overflow"))?;
        self.set(STAT_MAP_FULL, after, 0)
            .map_err(|e| anyhow::anyhow!("could not write WARDEN_EGRESS_MAP_FULL: {e}"))?;
        if self.get(&STAT_MAP_FULL, 0)? != after {
            anyhow::bail!("WARDEN_EGRESS_MAP_FULL read back did not match the write");
        }
        Ok(())
    }
}

#[cfg(test)]
struct NoOpStats;

#[cfg(test)]
impl EgressStatsWriter for NoOpStats {
    fn note_map_full(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The four cgroup hook families this build can attach. Order is stable and
/// used for reporting; a hook is only ever marked attached when the kernel
/// accepted `bpf_link_create`, never because config asked for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressHook {
    Connect4,
    Connect6,
    Sendmsg4,
    Sendmsg6,
}

impl EgressHook {
    pub const ALL: [EgressHook; 4] = [
        EgressHook::Connect4,
        EgressHook::Connect6,
        EgressHook::Sendmsg4,
        EgressHook::Sendmsg6,
    ];

    pub fn program_name(self) -> &'static str {
        match self {
            EgressHook::Connect4 => "warden_egress_connect4",
            EgressHook::Connect6 => "warden_egress_connect6",
            EgressHook::Sendmsg4 => "warden_egress_sendmsg4",
            EgressHook::Sendmsg6 => "warden_egress_sendmsg6",
        }
    }

    pub fn section(self) -> &'static str {
        match self {
            EgressHook::Connect4 => "cgroup/connect4",
            EgressHook::Connect6 => "cgroup/connect6",
            EgressHook::Sendmsg4 => "cgroup/sendmsg4",
            EgressHook::Sendmsg6 => "cgroup/sendmsg6",
        }
    }
}

/// Which hooks are confirmed attached. `Default` is all false — "nothing
/// attached" is the safe initial fact, and `all()` is the only thing that may
/// upgrade a policy claim.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressHooks {
    pub connect4: bool,
    pub connect6: bool,
    pub sendmsg4: bool,
    pub sendmsg6: bool,
}

impl EgressHooks {
    pub fn mark(&mut self, hook: EgressHook) {
        match hook {
            EgressHook::Connect4 => self.connect4 = true,
            EgressHook::Connect6 => self.connect6 = true,
            EgressHook::Sendmsg4 => self.sendmsg4 = true,
            EgressHook::Sendmsg6 => self.sendmsg6 = true,
        }
    }

    pub fn has(self, hook: EgressHook) -> bool {
        match hook {
            EgressHook::Connect4 => self.connect4,
            EgressHook::Connect6 => self.connect6,
            EgressHook::Sendmsg4 => self.sendmsg4,
            EgressHook::Sendmsg6 => self.sendmsg6,
        }
    }

    /// True only when every hook the object ships is attached. A one-sided
    /// attach (IPv4 only, say) is a partial view and must be reported as such —
    /// it must never be read as "egress is enforced".
    pub fn all(self) -> bool {
        EgressHook::ALL.iter().all(|h| self.has(*h))
    }

    pub fn count(self) -> usize {
        EgressHook::ALL.iter().filter(|h| self.has(**h)).count()
    }

    pub fn summary(self) -> String {
        let names: Vec<&str> = EgressHook::ALL
            .iter()
            .filter(|h| self.has(**h))
            .map(|h| h.section())
            .collect();
        if names.is_empty() {
            "none attached".to_string()
        } else {
            names.join(", ")
        }
    }
}

/// L4 protocol in an exact rule. Default TCP because the pre-existing
/// `deny_destinations` spelling (`ip:port`) has always described a TCP dial.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressProtocol {
    #[default]
    Tcp,
    Udp,
}

impl EgressProtocol {
    pub fn as_ipproto(self) -> u32 {
        match self {
            EgressProtocol::Tcp => 6,  // IPPROTO_TCP
            EgressProtocol::Udp => 17, // IPPROTO_UDP
        }
    }
}

/// One operator-authored deny rule. `port = 0` is the only wildcard the kernel
/// understands: "any port for this address+protocol". There is no hostname,
/// CIDR, or process-name wildcard — a deny must name an address an operator can
/// read and audit. An IPv4-mapped IPv6 literal names the same endpoint as the
/// equivalent dotted IPv4 literal and compiles to the same canonical key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDeny {
    pub address: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub protocol: EgressProtocol,
}

impl EgressDeny {
    /// Compile the human rule into the exact ABI key the BPF map is keyed by.
    /// Invalid input is an error, never a silently-looser rule: an unparseable
    /// address must not become "deny 0.0.0.0" (which could block far more than
    /// the operator intended) or be dropped from the map unnoticed.
    pub fn to_key(&self) -> anyhow::Result<EgressKey> {
        let ip = IpAddr::from_str(self.address.trim())
            .map_err(|e| anyhow::anyhow!("invalid egress deny address {:?}: {e}", self.address))?;
        let mut full = [0u8; 16];
        let family = match ip {
            IpAddr::V4(v4) => {
                full[..4].copy_from_slice(&v4.octets());
                2u32 // AF_INET
            }
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                // F06: `::ffff:a.b.c.d` is the same logical endpoint as `a.b.c.d`.
                // Canonicalize it here, the single policy-key boundary, so a
                // dotted IPv4 deny and a mapped observation share one key.
                Some(v4) => {
                    full[..4].copy_from_slice(&v4.octets());
                    2u32 // AF_INET
                }
                None => {
                    full[..16].copy_from_slice(&v6.octets());
                    10u32 // AF_INET6
                }
            },
        };
        Ok(EgressKey {
            family,
            protocol: self.protocol.as_ipproto(),
            addr: full,
            port: self.port.to_be(),
            _pad: 0,
        })
    }
}

/// The live view of the egress policy. `generation` is monotonically increasing
/// and only advances on a fully successful sync; `ready` is false after a failed
/// sync whose rollback could not be fully confirmed.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    generation: u32,
    current: BTreeMap<EgressKey, EgressRule>,
    ready: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            generation: 0,
            current: BTreeMap::new(),
            ready: true, // an empty, never-written policy is a valid policy
        }
    }
}

impl EgressPolicy {
    /// Build the exact desired map contents. Duplicate keys collapse (last wins)
    /// so a config with the same rule twice cannot waste one of the 256 slots.
    pub fn plan(
        denies: &[EgressDeny],
        generation: u32,
    ) -> anyhow::Result<BTreeMap<EgressKey, EgressRule>> {
        let mut out = BTreeMap::new();
        for d in denies {
            let key = d.to_key()?;
            out.insert(
                key,
                EgressRule {
                    deny: 1,
                    generation,
                },
            );
        }
        if out.len() > EGRESS_POLICY_MAX {
            anyhow::bail!(
                "{} distinct egress deny rule(s) exceed the kernel map capacity of {EGRESS_POLICY_MAX}",
                out.len()
            );
        }
        Ok(out)
    }

    /// Reconcile `denies` into the live kernel map.
    ///
    /// Rollback contract: snapshot the old contents first. On any kernel write
    /// failure, remove everything this call touched and re-install the snapshot.
    /// `ready` is set false if rollback cannot be confirmed, which propagates to
    /// `Preflight::policy_map_ready` and therefore degrades the enforcement
    /// claim — a partial map is never presented as complete coverage.
    /// Same transactional reconciliation, but records a refused insert in the
    /// shared `egress_stats` array so an operator sees the coverage gap.
    pub fn sync_with_stats<M: EgressPolicyMap, S: EgressStatsWriter>(
        &mut self,
        map: &mut M,
        denies: &[EgressDeny],
        stats: &mut S,
    ) -> anyhow::Result<usize> {
        let next_gen = self.generation.wrapping_add(1).max(1);
        let desired = Self::plan(denies, next_gen)?;
        let snapshot = self.current.clone();

        // Reads of the live map are the authoritative "what is actually there"
        // before we change it; `self.current` is a cache of our own last write.
        let present = match map.entries() {
            Ok(entries) => entries,
            Err(e) => {
                self.ready = false;
                return Err(e);
            }
        };
        let actually_present: Vec<EgressKey> = present.keys().copied().collect();

        let mut touched: Vec<EgressKey> = actually_present.clone();
        for k in desired.keys() {
            if !touched.contains(k) {
                touched.push(*k);
            }
        }

        let mut failed: Option<anyhow::Error> = None;
        for k in &actually_present {
            if !desired.contains_key(k) && map.remove(k).is_err() {
                failed = Some(anyhow::anyhow!("could not remove stale egress rule {k:?}"));
                break;
            }
        }
        let mut stats_note: Option<anyhow::Error> = None;
        if failed.is_none() {
            for (k, v) in &desired {
                if map.insert(k, v).is_err() {
                    // Exactly once, at the refusal itself: no later rollback
                    // step may inflate this count with its own bookkeeping.
                    stats_note = stats.note_map_full().err();
                    failed = Some(anyhow::anyhow!(
                        "could not insert egress rule {k:?}; map full or kernel refused"
                    ));
                    break;
                }
            }
        }

        if let Some(err) = failed {
            // Best-effort rollback to the pre-call snapshot. Every key we might
            // have changed is in `touched`; restore old rules, remove new ones.
            let mut rollback_ok = true;
            for k in &touched {
                if map.remove(k).is_err() {
                    rollback_ok = false;
                }
            }
            for (k, v) in &snapshot {
                if map.insert(k, v).is_err() {
                    rollback_ok = false;
                }
            }
            self.ready = false;
            let stats_detail = match stats_note {
                Some(e) => format!("; map-full counter write FAILED: {e}"),
                None => String::new(),
            };
            return Err(anyhow::anyhow!(
                "{err}; rollback {}{stats_detail}",
                if rollback_ok {
                    "restored the previous generation"
                } else {
                    "COULD NOT BE CONFIRMED — treat egress policy as DEGRADED"
                }
            ));
        }

        self.current = desired;
        self.generation = next_gen;
        self.ready = true;
        Ok(self.current.len())
    }

    pub fn generation(&self) -> u32 {
        self.generation
    }

    pub fn ready(&self) -> bool {
        self.ready
    }

    pub fn len(&self) -> usize {
        self.current.len()
    }

    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    /// The kernel facts this policy contributes to `policy::Preflight`. The
    /// program and hook bits come from the caller (verified at attach time);
    /// this only answers "is the policy map in a known-good generation".
    pub fn preflight_part(&self) -> bool {
        self.ready
    }

    /// Read the live map back and require the exact generation that was just
    /// planned. A write that returned success but did not land is not a policy.
    pub fn verify<M: EgressPolicyMap>(
        map: &M,
        expected: &BTreeMap<EgressKey, EgressRule>,
    ) -> anyhow::Result<()> {
        let actual = map.entries()?;
        if actual != *expected {
            anyhow::bail!(
                "egress policy verification failed: kernel map has {} entr(y/ies), expected {}",
                actual.len(),
                expected.len()
            );
        }
        for (key, rule) in expected {
            let live = actual.get(key).expect("the key was just compared");
            if live.deny != rule.deny || live.generation != rule.generation {
                anyhow::bail!(
                    "egress policy verification failed for {key:?}: live {:?} != planned {:?}",
                    live,
                    rule
                );
            }
        }
        Ok(())
    }

    pub fn verify_map<M: EgressPolicyMap>(&self, map: &M) -> anyhow::Result<()> {
        Self::verify(map, &self.current)
    }
}

/// A snapshot of the kernel's egress counters. Every field is monotonic since
/// load; callers that want "just now" must difference two samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EgressStats {
    pub hit_allow: u64,
    pub hit_deny: u64,
    pub denied: u64,
    pub map_full: u64,
}

impl EgressStats {
    pub fn read(map: &Array<MapData, u64>) -> anyhow::Result<Self> {
        // Read every slot declared by the shared ABI, then name them. If
        // warden.h and this file disagree on the count, the read fails loudly
        // rather than leaving a counter unobserved (a silent zero would be the
        // same false reassurance W-02 removed for the ring).
        let mut slots = [0u64; EGRESS_STATS];
        for (index, slot) in slots.iter_mut().enumerate() {
            *slot = map.get(&(index as u32), 0)?;
        }
        Ok(Self {
            hit_allow: slots[STAT_HIT_ALLOW as usize],
            hit_deny: slots[STAT_HIT_DENY as usize],
            denied: slots[STAT_DENIED as usize],
            map_full: slots[STAT_MAP_FULL as usize],
        })
    }

    /// True when this sample proves an armed rule actually refused an operation.
    /// A nonzero `hit_deny` alone is only a shadow-mode "would deny"; it must
    /// never be reported as a block.
    pub fn has_verified_denial(self) -> bool {
        self.denied > 0
    }
}

/// Everything the rest of the agent needs to state an honest egress claim.
#[derive(Debug, Clone)]
pub struct EgressRuntime {
    pub hooks: EgressHooks,
    pub armed: bool,
    pub enabled: bool,
    /// A load-time fact that a reload cannot change must be named in the status
    /// line. This is never a substitute for `enabled`/`armed` — it is the reason
    /// a truthful "DISABLED" line may still mention hooks attached at startup.
    pub note: Option<String>,
    policy: EgressPolicy,
}

impl EgressRuntime {
    pub fn new(enabled: bool, armed: bool) -> Self {
        Self {
            hooks: EgressHooks::default(),
            armed,
            enabled,
            note: None,
            policy: EgressPolicy::default(),
        }
    }

    pub fn policy_mut(&mut self) -> &mut EgressPolicy {
        &mut self.policy
    }

    pub fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Positive proof, assembled from facts the kernel returned — never from
    /// config. An arm bit written by userspace is included because the reader
    /// can confirm it back from `runtime_cfg`; see `Loader::egress_armed`.
    pub fn preflight(&self) -> Preflight {
        Preflight::from_facts(
            self.enabled && self.hooks.all(),
            self.hooks.all(),
            !self.enabled || self.policy.preflight_part(),
        )
    }

    /// A one-line startup/reload summary that says what is true, not what was
    /// requested. Shadow mode is stated explicitly so nobody reads "deny
    /// rules loaded" as "traffic is being blocked".
    pub fn summary(&self) -> String {
        let base = if !self.enabled {
            // Hooks are attached only at load. After a reload disables egress,
            // they are still present in the kernel but the arm slot and policy
            // have been cleared. Saying "hooks not attached" there would be a
            // false statement about a still-live bpf_link.
            if self.hooks.count() > 0 {
                "egress enforcement: DISABLED BY POLICY (startup hooks still attached, arm \
                 cleared and policy cleared; restart to detach; no rule can deny while arm=0)"
                    .to_string()
            } else {
                "egress enforcement: DISABLED (cgroup hooks not attached; observe-only policy only)"
                    .to_string()
            }
        } else {
            let mode = if self.armed { "ARMED" } else { "SHADOW" };
            let rules = if self.policy.is_empty() {
                "no rules".to_string()
            } else {
                format!("{} rule(s)", self.policy.len())
            };
            format!(
                "egress enforcement: {mode}, hooks {}/4 attached ({}), policy generation {} ({rules}, ready={})",
                self.hooks.count(),
                self.hooks.summary(),
                self.policy.generation(),
                self.policy.ready()
            )
        };
        match &self.note {
            Some(note) => format!("{base} [{note}]"),
            None => base,
        }
    }
}

/// The five reload situations that matter for a cgroup egress deny primitive.
///
/// Hook attachment is a load-time fact. `classify` deliberately uses the
/// *running* config (the one the process booted with), not the last requested
/// one, so a restart-required request keeps being reported as restart-required
/// on every later SIGHUP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressReloadTransition {
    /// A: enabled at load → disabled in the new config.
    EnabledToDisabled,
    /// B: enabled at load → still enabled; rules and arm may change.
    EnabledToEnabled,
    /// C: enabled at load and the named cgroup changed. Hooks are on the OLD one.
    CgroupPathChanged,
    /// D: disabled at load → enabled in the new config. No hooks were ever attached.
    DisabledToEnabled,
    /// E: the new config could not be loaded; nothing may move.
    FailedConfig,
    /// Both old and new configs leave egress disabled: nothing to do.
    NoChange,
}

impl EgressReloadTransition {
    pub fn classify(running_enabled: bool, fresh_enabled: bool, cgroup_path_changed: bool) -> Self {
        if !running_enabled && !fresh_enabled {
            return Self::NoChange;
        }
        if running_enabled && cgroup_path_changed {
            return Self::CgroupPathChanged;
        }
        match (running_enabled, fresh_enabled) {
            (true, false) => Self::EnabledToDisabled,
            (true, true) => Self::EnabledToEnabled,
            (false, true) => Self::DisabledToEnabled,
            (false, false) => Self::NoChange,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::EnabledToDisabled => "A enabled→disabled",
            Self::EnabledToEnabled => "B enabled→enabled",
            Self::CgroupPathChanged => "C cgroup_path changed",
            Self::DisabledToEnabled => "D disabled→enabled",
            Self::FailedConfig => "E config load failed",
            Self::NoChange => "egress unchanged",
        }
    }
}

/// What the operator is told after one reload attempt. The booleans are kernel
/// facts (write + read-back), not copies of the requested config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressReloadReport {
    pub transition: EgressReloadTransition,
    pub applied: bool,
    pub restart_required: Vec<String>,
    pub disarm_confirmed: bool,
    pub map_cleared: bool,
    pub rules: usize,
    pub generation: u32,
    pub summary: String,
}

impl EgressReloadReport {
    /// A read-only report for a reload that was rejected before any kernel
    /// write (state E, or a no-op). It describes the runtime that stayed live.
    pub fn preserved(transition: EgressReloadTransition, runtime: &EgressRuntime) -> Self {
        Self {
            transition,
            applied: false,
            restart_required: Vec::new(),
            disarm_confirmed: false,
            map_cleared: false,
            rules: runtime.policy().len(),
            generation: runtime.policy().generation(),
            summary: runtime.summary(),
        }
    }
}

fn clear_policy_raw<M: EgressPolicyMap>(map: &mut M) -> anyhow::Result<()> {
    let keys: Vec<EgressKey> = map.entries()?.into_keys().collect();
    for key in &keys {
        map.remove(key)?;
    }
    let after = map.entries()?;
    if !after.is_empty() {
        anyhow::bail!(
            "egress policy map still has {} entr(y/ies) after clear",
            after.len()
        );
    }
    Ok(())
}

fn disarm_and_confirm<A: EgressArmSlot>(
    arm: &mut A,
    runtime: &mut EgressRuntime,
) -> anyhow::Result<()> {
    arm.write(false)?;
    if arm.read()? {
        anyhow::bail!("egress arm read back 1 after disarm; refusing to change policy");
    }
    runtime.armed = false;
    Ok(())
}

fn restore_exact<M: EgressPolicyMap, A: EgressArmSlot>(
    map: &mut M,
    arm: &mut A,
    runtime: &mut EgressRuntime,
    old_map: &BTreeMap<EgressKey, EgressRule>,
    old_arm: bool,
    old_runtime: &EgressRuntime,
) -> anyhow::Result<()> {
    clear_policy_raw(map)?;
    for (key, rule) in old_map {
        map.insert(key, rule)?;
    }
    EgressPolicy::verify(map, old_map)?;

    // Restore the userspace view before touching the arm bit. If arming fails,
    // the reported state is SHADOW/false, never the old "ARMED" claim.
    *runtime.policy_mut() = old_runtime.policy.clone();
    runtime.enabled = old_runtime.enabled;
    runtime.hooks = old_runtime.hooks;
    runtime.note = old_runtime.note.clone();
    runtime.armed = false;
    arm.write(old_arm)?;
    let confirmed = arm.read()?;
    if confirmed != old_arm {
        anyhow::bail!(
            "egress arm read back {} while restoring {}",
            confirmed,
            old_arm
        );
    }
    runtime.armed = confirmed;
    Ok(())
}

fn restore_after_failure<M: EgressPolicyMap, A: EgressArmSlot>(
    map: &mut M,
    arm: &mut A,
    runtime: &mut EgressRuntime,
    old_map: &BTreeMap<EgressKey, EgressRule>,
    old_arm: bool,
    old_runtime: &EgressRuntime,
    primary: anyhow::Error,
) -> anyhow::Error {
    match restore_exact(map, arm, runtime, old_map, old_arm, old_runtime) {
        Ok(()) => anyhow::anyhow!("{primary}; old runtime preserved by rollback"),
        Err(rollback) => {
            runtime.note = Some(
                "reload rollback INCOMPLETE: egress state DEGRADED; restart required".to_string(),
            );
            anyhow::anyhow!(
                "{primary}; rollback failed: {rollback}; egress state DEGRADED, restart required"
            )
        }
    }
}

/// Apply one classified reload to the arm slot, policy map and verified runtime
/// view. Failure never leaves a half-applied policy as "enforced": the previous
/// map contents and arm bit are restored where the kernel still permits it, and
/// an unconfirmed rollback is marked DEGRADED in the returned error and summary.
#[cfg(test)]
pub fn apply_egress_reload<M: EgressPolicyMap, A: EgressArmSlot>(
    runtime: &mut EgressRuntime,
    arm: &mut A,
    map: &mut M,
    transition: EgressReloadTransition,
    desired_arm: bool,
    denies: &[EgressDeny],
) -> anyhow::Result<EgressReloadReport> {
    apply_egress_reload_with_stats(
        runtime,
        arm,
        map,
        transition,
        desired_arm,
        denies,
        &mut NoOpStats,
    )
}

/// Production variant: additionally records a refused rule insert in the
/// shared `egress_stats` array. The no-stats wrapper exists for injectable
/// test doubles and for callers that hold no kernel counter handle.
pub fn apply_egress_reload_with_stats<
    M: EgressPolicyMap,
    A: EgressArmSlot,
    S: EgressStatsWriter,
>(
    runtime: &mut EgressRuntime,
    arm: &mut A,
    map: &mut M,
    transition: EgressReloadTransition,
    desired_arm: bool,
    denies: &[EgressDeny],
    stats: &mut S,
) -> anyhow::Result<EgressReloadReport> {
    let old_runtime = runtime.clone();
    let old_arm = arm.read()?;
    let old_map = map.entries()?;

    let mut report = EgressReloadReport::preserved(transition, &old_runtime);

    match transition {
        EgressReloadTransition::FailedConfig | EgressReloadTransition::NoChange => Ok(report),
        EgressReloadTransition::DisabledToEnabled => {
            // No hook was attached at load. Writing arm=1 here would arm a deny
            // primitive with no program reading the map — the exact false
            // protection this state machine exists to prevent.
            let reason = "enabled requested on reload but no cgroup hooks were attached at startup; restart required";
            runtime.note = Some(reason.to_string());
            report.restart_required.push(reason.to_string());
            report.summary = runtime.summary();
            Ok(report)
        }
        EgressReloadTransition::EnabledToDisabled | EgressReloadTransition::CgroupPathChanged => {
            if let Err(e) = disarm_and_confirm(arm, runtime) {
                return Err(restore_after_failure(
                    map,
                    arm,
                    runtime,
                    &old_map,
                    old_arm,
                    &old_runtime,
                    e,
                ));
            }
            report.disarm_confirmed = true;
            if let Err(e) = clear_policy_raw(map) {
                return Err(restore_after_failure(
                    map,
                    arm,
                    runtime,
                    &old_map,
                    old_arm,
                    &old_runtime,
                    e,
                ));
            }
            *runtime.policy_mut() = EgressPolicy::default();
            runtime.enabled = false;
            runtime.armed = false;
            report.map_cleared = true;

            let reason = if transition == EgressReloadTransition::CgroupPathChanged {
                "cgroup_path changed; startup hooks remain on the OLD cgroup and are now disarmed/cleared; restart required"
            } else {
                "enabled→disabled applied; startup hooks remain attached but are disarmed/cleared; restart required to detach"
            };
            runtime.note = Some(reason.to_string());
            report.restart_required.push(reason.to_string());
            report.applied = true;
            report.rules = 0;
            report.generation = runtime.policy().generation();
            report.summary = runtime.summary();
            Ok(report)
        }
        EgressReloadTransition::EnabledToEnabled => {
            if let Err(e) = disarm_and_confirm(arm, runtime) {
                return Err(restore_after_failure(
                    map,
                    arm,
                    runtime,
                    &old_map,
                    old_arm,
                    &old_runtime,
                    e,
                ));
            }
            report.disarm_confirmed = true;

            if let Err(e) = runtime.policy_mut().sync_with_stats(map, denies, stats) {
                return Err(restore_after_failure(
                    map,
                    arm,
                    runtime,
                    &old_map,
                    old_arm,
                    &old_runtime,
                    e,
                ));
            }
            if let Err(e) = runtime.policy().verify_map(map) {
                return Err(restore_after_failure(
                    map,
                    arm,
                    runtime,
                    &old_map,
                    old_arm,
                    &old_runtime,
                    e,
                ));
            }

            // Re-arm only after the map has been read back and matched. A
            // failed arm write restores the old policy and the old arm bit.
            if desired_arm {
                if let Err(e) = arm.write(true) {
                    return Err(restore_after_failure(
                        map,
                        arm,
                        runtime,
                        &old_map,
                        old_arm,
                        &old_runtime,
                        e,
                    ));
                }
                match arm.read() {
                    Ok(true) => runtime.armed = true,
                    Ok(false) => {
                        return Err(restore_after_failure(
                            map,
                            arm,
                            runtime,
                            &old_map,
                            old_arm,
                            &old_runtime,
                            anyhow::anyhow!("egress arm read back 0 after re-arm"),
                        ))
                    }
                    Err(e) => {
                        return Err(restore_after_failure(
                            map,
                            arm,
                            runtime,
                            &old_map,
                            old_arm,
                            &old_runtime,
                            e,
                        ))
                    }
                }
            } else {
                match arm.read() {
                    Ok(false) => runtime.armed = false,
                    Ok(true) => {
                        return Err(restore_after_failure(
                            map,
                            arm,
                            runtime,
                            &old_map,
                            old_arm,
                            &old_runtime,
                            anyhow::anyhow!("egress arm read back 1 for a SHADOW reload"),
                        ))
                    }
                    Err(e) => {
                        return Err(restore_after_failure(
                            map,
                            arm,
                            runtime,
                            &old_map,
                            old_arm,
                            &old_runtime,
                            e,
                        ))
                    }
                }
            }

            runtime.enabled = true;
            runtime.note = None;
            report.applied = true;
            report.rules = runtime.policy().len();
            report.generation = runtime.policy().generation();
            report.summary = runtime.summary();
            Ok(report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct FakePolicyMap {
        entries: BTreeMap<EgressKey, EgressRule>,
        log: Rc<RefCell<Vec<String>>>,
        fail_insert_once: Option<EgressKey>,
        fail_remove_once: Option<EgressKey>,
        fail_entries_on: Option<usize>,
        entries_calls: Rc<RefCell<usize>>,
    }

    impl FakePolicyMap {
        fn new(entries: BTreeMap<EgressKey, EgressRule>, log: Rc<RefCell<Vec<String>>>) -> Self {
            Self {
                entries,
                log,
                fail_insert_once: None,
                fail_remove_once: None,
                fail_entries_on: None,
                entries_calls: Rc::new(RefCell::new(0)),
            }
        }
    }

    impl EgressPolicyMap for FakePolicyMap {
        fn entries(&self) -> anyhow::Result<BTreeMap<EgressKey, EgressRule>> {
            self.log.borrow_mut().push("map.entries".to_string());
            // `entries_calls` is interior state of a test double only; production
            // aya maps have no such switch.
            let mut calls = self.entries_calls.borrow_mut();
            *calls += 1;
            let call = *calls;
            drop(calls);
            if self.fail_entries_on == Some(call) {
                anyhow::bail!("injected egress_policy enumeration failure on call {call}");
            }
            Ok(self.entries.clone())
        }

        fn insert(&mut self, key: &EgressKey, value: &EgressRule) -> anyhow::Result<()> {
            self.log.borrow_mut().push("map.insert".to_string());
            if self.fail_insert_once.as_ref() == Some(key) {
                self.fail_insert_once = None;
                anyhow::bail!("injected egress_policy insert failure");
            }
            self.entries.insert(*key, *value);
            Ok(())
        }

        fn remove(&mut self, key: &EgressKey) -> anyhow::Result<()> {
            self.log.borrow_mut().push("map.remove".to_string());
            if self.fail_remove_once.as_ref() == Some(key) {
                self.fail_remove_once = None;
                anyhow::bail!("injected egress_policy remove failure");
            }
            self.entries.remove(key);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeArm {
        on: bool,
        log: Rc<RefCell<Vec<String>>>,
        writes: Rc<RefCell<Vec<bool>>>,
        fail_write_on: Option<bool>,
        fail_consumed: bool,
    }

    impl FakeArm {
        fn new(on: bool, log: Rc<RefCell<Vec<String>>>) -> Self {
            Self {
                on,
                log,
                writes: Rc::new(RefCell::new(Vec::new())),
                fail_write_on: None,
                fail_consumed: false,
            }
        }
    }

    impl EgressArmSlot for FakeArm {
        fn write(&mut self, on: bool) -> anyhow::Result<()> {
            self.log.borrow_mut().push(format!("arm.write({on})"));
            self.writes.borrow_mut().push(on);
            if !self.fail_consumed && self.fail_write_on == Some(on) {
                self.fail_consumed = true;
                anyhow::bail!("injected CFG_EGRESS_ARM write failure");
            }
            self.on = on;
            Ok(())
        }

        fn read(&self) -> anyhow::Result<bool> {
            self.log.borrow_mut().push("arm.read".to_string());
            Ok(self.on)
        }
    }

    #[derive(Clone, Default)]
    struct FakeStats {
        full: Rc<RefCell<u64>>,
    }

    impl EgressStatsWriter for FakeStats {
        fn note_map_full(&mut self) -> anyhow::Result<()> {
            *self.full.borrow_mut() += 1;
            Ok(())
        }
    }

    fn deny(addr: &str, port: u16, protocol: EgressProtocol) -> EgressDeny {
        EgressDeny {
            address: addr.into(),
            port,
            protocol,
        }
    }

    fn runtime_with_rules(
        enabled: bool,
        armed: bool,
        rules: &[EgressDeny],
        attach_hooks: bool,
    ) -> (EgressRuntime, BTreeMap<EgressKey, EgressRule>) {
        let mut runtime = EgressRuntime::new(enabled, armed);
        if attach_hooks {
            for hook in EgressHook::ALL {
                runtime.hooks.mark(hook);
            }
        }
        let plan = EgressPolicy::plan(rules, 1).unwrap();
        *runtime.policy_mut() = EgressPolicy {
            generation: 1,
            current: plan.clone(),
            ready: true,
        };
        (runtime, plan)
    }

    fn fixture(
        enabled: bool,
        armed: bool,
        rules: &[EgressDeny],
        attach_hooks: bool,
    ) -> (
        EgressRuntime,
        FakeArm,
        FakePolicyMap,
        Rc<RefCell<Vec<String>>>,
    ) {
        let (runtime, plan) = runtime_with_rules(enabled, armed, rules, attach_hooks);
        let log = Rc::new(RefCell::new(Vec::new()));
        let arm = FakeArm::new(armed, Rc::clone(&log));
        let map = FakePolicyMap::new(plan, Rc::clone(&log));
        (runtime, arm, map, log)
    }

    fn one_rule() -> Vec<EgressDeny> {
        vec![deny("203.0.113.9", 4444, EgressProtocol::Tcp)]
    }

    #[test]
    fn key_encoding_matches_the_kernel_abi() {
        let k = deny("1.2.3.4", 443, EgressProtocol::Tcp).to_key().unwrap();
        assert_eq!(k.family, 2);
        assert_eq!(k.protocol, 6);
        assert_eq!(&k.addr[..4], &[1, 2, 3, 4]);
        assert_eq!(&k.addr[4..], &[0; 12]);
        // The stored value is the network-order port integer, which is what
        // ctx->user_port yields on this (little-endian) host.
        assert_eq!(k.port, 443u16.to_be());
        assert_eq!(k.port.to_be(), 443);

        let k6 = deny("2001:db8::1", 0, EgressProtocol::Udp)
            .to_key()
            .unwrap();
        assert_eq!(k6.family, 10);
        assert_eq!(k6.protocol, 17);
        assert_eq!(&k6.addr[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        assert_eq!(k6.addr[15], 1);
        assert_eq!(k6.port, 0); // wildcard
    }

    #[test]
    fn f06_canonical_key_contract() {
        // Only the exact ::ffff: prefix is an IPv4 endpoint. Everything else,
        // including loopback, unspecified, NAT64 and a late ffff word, stays
        // AF_INET6.
        let cases: [(&str, u32, [u8; 4]); 8] = [
            ("192.0.2.10", 2, [192, 0, 2, 10]),
            ("::ffff:192.0.2.10", 2, [192, 0, 2, 10]),
            ("::ffff:c000:020a", 2, [192, 0, 2, 10]),
            ("2001:db8::10", 10, [0x20, 0x01, 0x0d, 0xb8]),
            ("::1", 10, [0, 0, 0, 0]),
            ("::", 10, [0, 0, 0, 0]),
            ("64:ff9b::c000:020a", 10, [0x00, 0x64, 0xff, 0x9b]),
            ("2001:db8::ffff:c000:020a", 10, [0x20, 0x01, 0x0d, 0xb8]),
        ];
        for (text, family, prefix) in cases {
            let key = deny(text, 443, EgressProtocol::Tcp).to_key().unwrap();
            assert_eq!(key.family, family, "{text}");
            assert_eq!(&key.addr[..4], &prefix, "{text}");
            if family == 2 {
                assert_eq!(&key.addr[4..], &[0u8; 12], "{text}");
            }
        }
    }

    #[test]
    fn f06_ipv4_deny_matches_equivalent_ipv4_mapped_endpoint() {
        // The cgroup/connect6 and cgroup/sendmsg6 hooks evaluate an IPv4-mapped
        // destination with a mapped address; the key compiler below is the
        // userspace half of the same ABI. An IPv4 deny must therefore produce a
        // key that the mapped spelling also resolves to. Regression for F06.
        let planned =
            EgressPolicy::plan(&[deny("192.0.2.10", 443, EgressProtocol::Tcp)], 1).unwrap();
        for endpoint in ["::ffff:192.0.2.10", "::ffff:c000:020a"] {
            let observed = deny(endpoint, 443, EgressProtocol::Tcp).to_key().unwrap();
            assert!(
                planned.contains_key(&observed),
                "IPv4-mapped endpoint key {observed:?} for {endpoint} missed the IPv4 deny policy"
            );
        }
    }

    #[test]
    fn f06_plan_is_symmetric_and_does_not_broaden_denial() {
        let ipv4 = deny("192.0.2.10", 443, EgressProtocol::Tcp);
        let mapped = deny("::ffff:192.0.2.10", 443, EgressProtocol::Tcp);
        let from_ipv4 = EgressPolicy::plan(&[ipv4], 1).unwrap();
        let from_mapped = EgressPolicy::plan(&[mapped], 1).unwrap();
        assert_eq!(from_ipv4, from_mapped);
        assert_eq!(from_ipv4.len(), 1);

        let cases = [
            ("192.0.2.10", 443, EgressProtocol::Tcp, true),
            ("::ffff:192.0.2.10", 443, EgressProtocol::Tcp, true),
            ("::ffff:c000:020a", 443, EgressProtocol::Tcp, true),
            ("192.0.2.11", 443, EgressProtocol::Tcp, false),
            ("::ffff:192.0.2.11", 443, EgressProtocol::Tcp, false),
            ("2001:db8::10", 443, EgressProtocol::Tcp, false),
            ("2001:db8::ffff:c000:020a", 443, EgressProtocol::Tcp, false),
            ("::1", 443, EgressProtocol::Tcp, false),
            ("::", 443, EgressProtocol::Tcp, false),
            ("192.0.2.10", 444, EgressProtocol::Tcp, false),
            ("::ffff:192.0.2.10", 443, EgressProtocol::Udp, false),
        ];
        for (endpoint, port, protocol, expected) in cases {
            let key = deny(endpoint, port, protocol).to_key().unwrap();
            assert_eq!(
                from_ipv4.contains_key(&key),
                expected,
                "{endpoint}:{port}:{protocol:?}"
            );
        }
    }

    #[test]
    fn f06_wildcard_and_protocol_semantics_survive_canonicalization() {
        let wildcard =
            EgressPolicy::plan(&[deny("::ffff:192.0.2.10", 0, EgressProtocol::Udp)], 1).unwrap();
        assert!(
            wildcard.contains_key(&deny("192.0.2.10", 0, EgressProtocol::Udp).to_key().unwrap())
        );
        assert!(!wildcard.contains_key(
            &deny("192.0.2.10", 53, EgressProtocol::Udp)
                .to_key()
                .unwrap()
        ));

        let exact_and_wildcard = EgressPolicy::plan(
            &[
                deny("192.0.2.10", 443, EgressProtocol::Tcp),
                deny("::ffff:192.0.2.10", 0, EgressProtocol::Tcp),
            ],
            1,
        )
        .unwrap();
        assert_eq!(exact_and_wildcard.len(), 2);
        assert!(exact_and_wildcard.contains_key(
            &deny("192.0.2.10", 443, EgressProtocol::Tcp)
                .to_key()
                .unwrap()
        ));
        assert!(exact_and_wildcard
            .contains_key(&deny("192.0.2.10", 0, EgressProtocol::Tcp).to_key().unwrap()));
    }

    #[test]
    fn f06_serde_round_trip_preserves_canonical_key() {
        let original = deny("::ffff:192.0.2.10", 443, EgressProtocol::Tcp);
        let json = serde_json::to_string(&original).unwrap();
        let restored: EgressDeny = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
        assert_eq!(
            restored.to_key().unwrap(),
            deny("192.0.2.10", 443, EgressProtocol::Tcp)
                .to_key()
                .unwrap()
        );
    }

    #[test]
    fn invalid_addresses_and_oversized_plans_are_refused() {
        assert!(deny("not-an-ip", 1, EgressProtocol::Tcp).to_key().is_err());
        assert!(deny("", 1, EgressProtocol::Tcp).to_key().is_err());
        let too_many: Vec<EgressDeny> = (1..=EGRESS_POLICY_MAX + 1)
            .map(|n| {
                deny(
                    &format!("10.0.0.{}", (n % 254) + 1),
                    n as u16,
                    EgressProtocol::Tcp,
                )
            })
            .collect();
        // Distinct addresses are bounded by 254 here, so add IPv6 variants to
        // force more than EGRESS_POLICY_MAX distinct keys.
        let mut many: Vec<EgressDeny> = (0..EGRESS_POLICY_MAX + 1)
            .map(|n| deny(&format!("2001:db8::{:x}", n + 1), 1, EgressProtocol::Tcp))
            .collect();
        many.extend(too_many);
        assert!(EgressPolicy::plan(&many, 1).is_err());
    }

    #[test]
    fn duplicate_rules_collapse_to_one_slot() {
        let d = deny("203.0.113.9", 4444, EgressProtocol::Tcp);
        let plan = EgressPolicy::plan(&[d.clone(), d], 7).unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.values().next().unwrap().generation, 7);
    }

    #[test]
    fn hooks_require_all_four_to_claim_coverage() {
        let mut h = EgressHooks::default();
        assert!(!h.all());
        h.mark(EgressHook::Connect4);
        h.mark(EgressHook::Connect6);
        assert_eq!(h.count(), 2);
        assert!(!h.all());
        h.mark(EgressHook::Sendmsg4);
        h.mark(EgressHook::Sendmsg6);
        assert!(h.all());
        assert_eq!(h.count(), 4);
    }

    #[test]
    fn disabled_runtime_never_claims_a_kernel_deny_program() {
        let r = EgressRuntime::new(false, true);
        let p = r.preflight();
        assert!(!p.kernel_deny_program);
        assert!(!p.hooks_attached);
        // Arming without enabling must not manufacture an enforcement claim.
        assert!(!r.summary().contains("ARMED"));
    }

    #[test]
    fn armed_runtime_still_reports_shadow_when_hooks_are_partial() {
        let mut r = EgressRuntime::new(true, true);
        r.hooks.mark(EgressHook::Connect4);
        assert!(r.summary().contains("ARMED"));
        assert!(r.summary().contains("1/4"));
        assert!(!r.preflight().hooks_attached);
    }

    #[test]
    fn stat_slots_are_distinct_and_bounded() {
        let all = [STAT_HIT_ALLOW, STAT_HIT_DENY, STAT_DENIED, STAT_MAP_FULL];
        let mut seen = std::collections::BTreeSet::new();
        for s in all {
            assert!(s < EGRESS_STATS as u32);
            assert!(seen.insert(s));
        }
        assert_eq!(seen.len(), EGRESS_STATS);
    }

    #[test]
    fn reload_transitions_are_classified_from_the_running_config() {
        use EgressReloadTransition as T;
        assert_eq!(T::classify(true, false, false), T::EnabledToDisabled);
        assert_eq!(T::classify(true, true, false), T::EnabledToEnabled);
        assert_eq!(T::classify(true, true, true), T::CgroupPathChanged);
        assert_eq!(T::classify(true, false, true), T::CgroupPathChanged);
        assert_eq!(T::classify(false, true, false), T::DisabledToEnabled);
        assert_eq!(T::classify(false, true, true), T::DisabledToEnabled);
        assert_eq!(T::classify(false, false, true), T::NoChange);
    }

    #[test]
    fn a_disabling_after_multiple_rules_clears_and_reports_attached_but_disarmed() {
        let rules = vec![
            deny("203.0.113.9", 4444, EgressProtocol::Tcp),
            deny("203.0.113.10", 4444, EgressProtocol::Tcp),
            deny("198.51.100.7", 53, EgressProtocol::Udp),
        ];
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &rules, true);
        let report = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToDisabled,
            false,
            &[],
        )
        .unwrap();

        assert!(report.applied);
        assert!(report.disarm_confirmed);
        assert!(report.map_cleared);
        assert!(!arm.on);
        assert!(map.entries().unwrap().is_empty());
        assert!(!runtime.enabled);
        assert!(!runtime.armed);
        assert_eq!(runtime.policy().generation(), 0);
        let summary = runtime.summary();
        assert!(summary.contains("DISABLED BY POLICY"), "{summary}");
        assert!(
            summary.contains("startup hooks still attached"),
            "{summary}"
        );
        assert!(
            summary.contains("no rule can deny while arm=0"),
            "{summary}"
        );
        assert!(!runtime.preflight().kernel_deny_program);
    }

    #[test]
    fn b_rule_change_while_armed_disarms_syncs_verifies_then_rearms() {
        let old = one_rule();
        let fresh = vec![
            deny("198.51.100.1", 443, EgressProtocol::Tcp),
            deny("198.51.100.2", 53, EgressProtocol::Udp),
        ];
        let (mut runtime, mut arm, mut map, log) = fixture(true, true, &old, true);
        let report = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &fresh,
        )
        .unwrap();

        assert!(report.applied);
        assert!(report.disarm_confirmed);
        assert_eq!(report.rules, 2);
        assert_eq!(report.generation, 2);
        assert!(arm.on);
        assert_eq!(arm.writes.borrow().as_slice(), &[false, true]);
        assert_eq!(
            map.entries().unwrap(),
            EgressPolicy::plan(&fresh, 2).unwrap()
        );
        assert_eq!(runtime.policy().generation(), 2);
        assert!(runtime.summary().contains("ARMED"));

        let events = log.borrow().clone();
        let disarm = events.iter().position(|e| e == "arm.write(false)").unwrap();
        let first_insert = events.iter().position(|e| e == "map.insert").unwrap();
        let rearm = events.iter().position(|e| e == "arm.write(true)").unwrap();
        assert!(
            disarm < first_insert && first_insert < rearm,
            "re-arm happened before the map was rewritten: {events:?}"
        );
    }

    #[test]
    fn c_cgroup_path_change_clears_and_requires_a_restart() {
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &one_rule(), true);
        let report = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::CgroupPathChanged,
            false,
            &one_rule(),
        )
        .unwrap();

        assert!(report.applied);
        assert!(report.disarm_confirmed);
        assert!(report.map_cleared);
        assert!(!arm.on);
        assert!(map.entries().unwrap().is_empty());
        let summary = runtime.summary();
        assert!(summary.contains("cgroup_path changed"), "{summary}");
        assert!(summary.contains("OLD cgroup"), "{summary}");
        assert!(summary.contains("restart required"), "{summary}");
        assert_eq!(report.restart_required.len(), 1);
        assert!(!runtime.preflight().kernel_deny_program);
    }

    #[test]
    fn d_disabled_to_enabled_never_arms_or_writes_rules() {
        let (mut runtime, mut arm, mut map, _) = fixture(false, false, &[], false);
        let report = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::DisabledToEnabled,
            true,
            &one_rule(),
        )
        .unwrap();

        assert!(!report.applied);
        assert!(!report.disarm_confirmed);
        assert!(!report.map_cleared);
        assert!(
            arm.writes.borrow().is_empty(),
            "no arm write is permitted here"
        );
        assert!(!arm.on);
        assert!(map.entries().unwrap().is_empty());
        assert!(!runtime.enabled);
        assert!(!runtime.armed);
        let summary = runtime.summary();
        assert!(summary.contains("DISABLED"), "{summary}");
        assert!(summary.contains("restart required"), "{summary}");
        assert!(summary.contains("cgroup hooks not attached"), "{summary}");
        assert!(!runtime.preflight().kernel_deny_program);
    }

    #[test]
    fn e_failed_load_preserves_the_old_runtime_exactly() {
        let old = one_rule();
        let old_plan = EgressPolicy::plan(&old, 1).unwrap();
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &old, true);
        let before = runtime.summary();
        let report = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::FailedConfig,
            false,
            &[],
        )
        .unwrap();

        assert!(!report.applied);
        assert!(arm.writes.borrow().is_empty());
        assert!(arm.on);
        assert_eq!(map.entries().unwrap(), old_plan);
        assert_eq!(runtime.summary(), before);
        assert!(runtime.armed && runtime.enabled);
    }

    #[test]
    fn disarm_failure_rolls_back_and_preserves_old_runtime() {
        let old = one_rule();
        let old_plan = EgressPolicy::plan(&old, 1).unwrap();
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &old, true);
        arm.fail_write_on = Some(false);
        let err = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &[deny("198.51.100.1", 443, EgressProtocol::Tcp)],
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("old runtime preserved by rollback"), "{err}");
        assert!(arm.on);
        assert_eq!(map.entries().unwrap(), old_plan);
        assert_eq!(runtime.policy().generation(), 1);
        assert!(runtime.armed && runtime.enabled);
    }

    #[test]
    fn insert_failure_rolls_back_the_previous_generation() {
        let old = one_rule();
        let old_plan = EgressPolicy::plan(&old, 1).unwrap();
        let fresh = vec![
            deny("198.51.100.1", 443, EgressProtocol::Tcp),
            deny("198.51.100.2", 443, EgressProtocol::Tcp),
        ];
        let fresh_plan = EgressPolicy::plan(&fresh, 2).unwrap();
        let fail_key = *fresh_plan.keys().last().unwrap();
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &old, true);
        map.fail_insert_once = Some(fail_key);

        let err = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &fresh,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("could not insert egress rule"), "{err}");
        assert!(err.contains("old runtime preserved by rollback"), "{err}");
        assert_eq!(map.entries().unwrap(), old_plan);
        assert!(arm.on);
        assert_eq!(runtime.policy().generation(), 1);
        assert!(runtime.policy().ready());
    }

    #[test]
    fn refused_insert_records_a_single_map_full_counter() {
        let old = one_rule();
        let (mut runtime, _arm, mut map, _log) = fixture(true, true, &old, true);
        let fresh = vec![
            deny("198.51.100.1", 443, EgressProtocol::Tcp),
            deny("198.51.100.2", 443, EgressProtocol::Tcp),
        ];
        let fail_key = *EgressPolicy::plan(&fresh, 2)
            .unwrap()
            .keys()
            .last()
            .unwrap();
        map.fail_insert_once = Some(fail_key);
        let mut stats = FakeStats::default();

        assert!(runtime
            .policy_mut()
            .sync_with_stats(&mut map, &fresh, &mut stats)
            .is_err());
        assert_eq!(
            *stats.full.borrow(),
            1,
            "one refused insert, one counted failure"
        );
    }

    #[test]
    fn refused_insert_during_reload_records_a_single_map_full_counter() {
        let old = one_rule();
        let fresh = vec![
            deny("198.51.100.1", 443, EgressProtocol::Tcp),
            deny("198.51.100.2", 443, EgressProtocol::Tcp),
        ];
        let fail_key = *EgressPolicy::plan(&fresh, 2)
            .unwrap()
            .keys()
            .last()
            .unwrap();
        let (mut runtime, mut arm, mut map, _log) = fixture(true, true, &old, true);
        map.fail_insert_once = Some(fail_key);
        let mut stats = FakeStats::default();

        assert!(apply_egress_reload_with_stats(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &fresh,
            &mut stats,
        )
        .is_err());
        assert_eq!(
            *stats.full.borrow(),
            1,
            "rollback bookkeeping must not inflate the count"
        );
    }

    #[test]
    fn successful_sync_does_not_record_a_map_full_counter() {
        let (mut runtime, _arm, mut map, _log) = fixture(true, true, &[], true);
        let mut stats = FakeStats::default();
        runtime
            .policy_mut()
            .sync_with_stats(&mut map, &one_rule(), &mut stats)
            .unwrap();
        assert_eq!(*stats.full.borrow(), 0);
    }

    #[test]
    fn remove_failure_rolls_back_the_previous_generation() {
        let old = vec![
            deny("203.0.113.9", 4444, EgressProtocol::Tcp),
            deny("203.0.113.10", 4444, EgressProtocol::Tcp),
        ];
        let old_plan = EgressPolicy::plan(&old, 1).unwrap();
        let fresh = vec![deny("203.0.113.9", 4444, EgressProtocol::Tcp)];
        let fresh_plan = EgressPolicy::plan(&fresh, 2).unwrap();
        let fail_key = *old_plan
            .keys()
            .find(|k| !fresh_plan.contains_key(*k))
            .unwrap();
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &old, true);
        map.fail_remove_once = Some(fail_key);

        let err = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &fresh,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("could not remove stale egress rule"), "{err}");
        assert!(err.contains("old runtime preserved by rollback"), "{err}");
        assert_eq!(map.entries().unwrap(), old_plan);
        assert!(arm.on);
        assert_eq!(runtime.policy().generation(), 1);
    }

    #[test]
    fn failed_rearm_restores_the_old_arm_bit_and_policy() {
        let old = one_rule();
        let old_plan = EgressPolicy::plan(&old, 1).unwrap();
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &old, true);
        arm.fail_write_on = Some(true);

        let err = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &[deny("198.51.100.1", 443, EgressProtocol::Tcp)],
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("old runtime preserved by rollback"), "{err}");
        assert!(arm.on, "the old ARMED bit must be restored");
        assert_eq!(map.entries().unwrap(), old_plan);
        assert_eq!(runtime.policy().generation(), 1);
        assert!(runtime.armed && runtime.enabled);
    }

    #[test]
    fn verification_failure_restores_the_old_generation() {
        let old = one_rule();
        let old_plan = EgressPolicy::plan(&old, 1).unwrap();
        let (mut runtime, mut arm, mut map, _) = fixture(true, true, &old, true);
        // Call 1 is the pre-flight snapshot, call 2 is sync's enumeration,
        // call 3 is the post-write verification.
        map.fail_entries_on = Some(3);

        let err = apply_egress_reload(
            &mut runtime,
            &mut arm,
            &mut map,
            EgressReloadTransition::EnabledToEnabled,
            true,
            &[deny("198.51.100.1", 443, EgressProtocol::Tcp)],
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("injected egress_policy enumeration failure"),
            "{err}"
        );
        assert_eq!(map.entries().unwrap(), old_plan);
        assert!(arm.on);
        assert_eq!(runtime.policy().generation(), 1);
    }

    #[test]
    fn all_four_egress_families_have_exact_keys_and_real_hook_sections() {
        let cases = [
            (
                deny("192.0.2.10", 443, EgressProtocol::Tcp),
                2,
                6,
                EgressHook::Connect4,
                "cgroup/connect4",
            ),
            (
                deny("192.0.2.11", 53, EgressProtocol::Udp),
                2,
                17,
                EgressHook::Sendmsg4,
                "cgroup/sendmsg4",
            ),
            (
                deny("2001:db8::10", 443, EgressProtocol::Tcp),
                10,
                6,
                EgressHook::Connect6,
                "cgroup/connect6",
            ),
            (
                deny("2001:db8::11", 53, EgressProtocol::Udp),
                10,
                17,
                EgressHook::Sendmsg6,
                "cgroup/sendmsg6",
            ),
        ];
        for (rule, family, protocol, hook, section) in cases {
            let key = rule.to_key().unwrap();
            assert_eq!(key.family, family);
            assert_eq!(key.protocol, protocol);
            assert_eq!(hook.section(), section);
            assert!(EgressHook::ALL.contains(&hook));
        }
        assert_eq!(
            EgressHook::Sendmsg6.program_name(),
            "warden_egress_sendmsg6"
        );
    }
}
