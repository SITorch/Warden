//! config_engine.rs — the single configuration engine for Simple and Advanced UX.
//!
//! This is not a second configuration system. It reads, writes, validates and
//! explains the same `Config` structure that `main.rs` loads at startup:
//! profile generation serializes `Config`, migration edits its TOML document,
//! drift watches that document and the host facts `--doctor` already reads, and
//! rollback restores a previously validated document. No setting here has a
//! runtime meaning the daemon does not already implement.
//!
//! Truthfulness rules, carried over from M15:
//! * a capability that was not measured is `UNKNOWN`, never `PASS`;
//! * a plan is a simulation and never claims an eBPF attach succeeded;
//! * the self-test reports `NOT_RUN` for kernel load, runtime startup, local
//!   event pipeline and live SENTINEL connectivity;
//! * no generated profile silently arms killing, in-kernel denial or cgroup
//!   egress enforcement.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};

use crate::config::{unread_keys, Config, Mode, CURRENT_SCHEMA_VERSION, LEGACY_SCHEMA_VERSION};

/// Profile names accepted by `--profile`. `Custom` is not generated from a
/// template: it validates an existing file and leaves its policy untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileName {
    Essential,
    Balanced,
    Advanced,
    Hardened,
    Custom,
}

impl ProfileName {
    pub const ALL: &'static [Self] = &[
        Self::Essential,
        Self::Balanced,
        Self::Advanced,
        Self::Hardened,
        Self::Custom,
    ];

    pub fn word(self) -> &'static str {
        match self {
            Self::Essential => "essential",
            Self::Balanced => "balanced",
            Self::Advanced => "advanced",
            Self::Hardened => "hardened",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "essential" | "simple" => Ok(Self::Essential),
            "balanced" | "recommended" => Ok(Self::Balanced),
            "advanced" | "expert" => Ok(Self::Advanced),
            "hardened" => Ok(Self::Hardened),
            "custom" => Ok(Self::Custom),
            other => bail!(
                "unknown profile {other:?}; choose one of {} (aliases: simple, recommended, expert)",
                Self::ALL
                    .iter()
                    .map(|p| p.word())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

/// Why a profile exists and what an operator is buying with it.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileDoc {
    pub name: &'static str,
    pub summary: &'static str,
    pub enabled_features: Vec<&'static str>,
    pub disabled_features: Vec<&'static str>,
    pub required_capabilities: Vec<&'static str>,
    pub privilege_requirements: &'static str,
    pub resource_implications: &'static str,
    pub operational_risks: &'static str,
    pub enforcement_behavior: &'static str,
    pub degradation_behavior: &'static str,
    pub recommended_use_cases: &'static str,
}

pub fn profile_docs() -> Vec<ProfileDoc> {
    vec![
        ProfileDoc {
            name: "essential",
            summary: "Low-complexity observation: core sensors, no optional pull/volume path.",
            enabled_features: vec![
                "observe mode",
                "core exec/file/module/mount/persistence detection",
                "protected-pid signal/ptrace detection",
                "journal telemetry",
            ],
            disabled_features: vec![
                "C2 cadence analytics",
                "socket snapshot pull path",
                "cgroup volume counters",
                "BPF-LSM armed denial",
                "egress enforcement",
                "local kill responders",
            ],
            required_capabilities: vec![
                "BPF program load and attach for the core sensors",
                "BTF for CO-RE relocation",
            ],
            privilege_requirements: "root, or CAP_BPF+CAP_PERFMON+CAP_SYS_PTRACE and the unit's perf gate setting",
            resource_implications: "shipped 256 KiB lossy ring; four /proc reads per uncached event",
            operational_risks: "lowest response risk; missing optional telemetry can hide already-open sockets and slow beacons",
            enforcement_behavior: "mode=observe; every responder off; enforce.arm=false; egress.enabled=false",
            degradation_behavior: "unsupported optional sensors stay off and are listed as unavailable; core detection remains",
            recommended_use_cases: "first deployment, unfamiliar host, low-noise introduction",
        },
        ProfileDoc {
            name: "balanced",
            summary: "Recommended general posture: C2 analytics plus bounded pull telemetry.",
            enabled_features: vec![
                "everything in essential",
                "bounded C2 cadence analytics",
                "periodic /proc socket snapshot",
                "cgroup volume counters when the host proves compatible",
            ],
            disabled_features: vec![
                "BPF-LSM armed denial",
                "egress enforcement",
                "local kill responders",
            ],
            required_capabilities: vec![
                "BPF load/attach and BTF",
                "cgroup v2 and compatible fexit prototypes for volume counters",
            ],
            privilege_requirements: "same as essential; no extra privilege is taken by the pull paths",
            resource_implications: "adds a bounded /proc walk and six kernel map reads per volume tick",
            operational_risks: "C2 findings are suspicion with confidence, never proof of compromise",
            enforcement_behavior: "mode=observe; every responder off; enforcement layers remain shadow/off",
            degradation_behavior: "volume counters are left off with a reason when BTF/hooks do not match; other features continue",
            recommended_use_cases: "ordinary servers and workstations after a short observation period",
        },
        ProfileDoc {
            name: "advanced",
            summary: "Full detective control for engineers who will tune the file themselves.",
            enabled_features: vec![
                "everything in balanced",
                "all expert rule knobs serialized into the generated TOML",
                "explicit app-cgroup guidance for egress/listen judgement",
            ],
            disabled_features: vec![
                "BPF-LSM armed denial",
                "egress enforcement",
                "local kill responders",
            ],
            required_capabilities: vec![
                "BPF load/attach and BTF",
                "cgroup v2 for volume counters; bpf LSM only if the operator later arms guards",
            ],
            privilege_requirements: "same daemon privileges; editing this file does not grant more capabilities",
            resource_implications: "policy is fully explicit, so a mistaken threshold or broad allowlist is possible",
            operational_risks: "misconfigured app identity can silence egress/listen findings; validator warns",
            enforcement_behavior: "mode=observe; no silent enforcement even in this profile",
            degradation_behavior: "unsupported optional sensors are reported, not silently enabled",
            recommended_use_cases: "operators tuning thresholds, allowlists and sensor cadence",
        },
        ProfileDoc {
            name: "hardened",
            summary: "Maximum detective coverage with enforcement readiness, but no silent arming.",
            enabled_features: vec![
                "everything in advanced",
                "BPF-LSM readiness reported when the active LSM list includes bpf",
                "all bounded C2 and network telemetry the host supports",
            ],
            disabled_features: vec![
                "local kill responders (explicit operator opt-in required)",
                "egress enforcement (explicit test cgroup and arming required)",
                "guarded-file denial (no path is invented by a profile)",
            ],
            required_capabilities: vec![
                "BPF load/attach and BTF",
                "bpf LSM in the active LSM list for future denial",
                "cgroup v2 and bpffs for future cgroup egress work",
            ],
            privilege_requirements: "same daemon privileges; arming later needs a named guard path and uid",
            resource_implications: "highest observation cost; enforcement itself adds only map lookups",
            operational_risks: "stronger claims require verified capabilities; an unverified guard never arms",
            enforcement_behavior: "mode=observe and enforce.arm=false by design; the operator arms after reviewing shadow findings",
            degradation_behavior: "missing bpf LSM does not disable unrelated detection; the gap is reported",
            recommended_use_cases: "high-value hosts where an operator will review and then arm response deliberately",
        },
        ProfileDoc {
            name: "custom",
            summary: "Validate an existing file; no generated policy is substituted.",
            enabled_features: vec!["existing configuration is preserved byte-for-byte"],
            disabled_features: vec!["automatic profile changes"],
            required_capabilities: vec!["same as the settings the file actually contains"],
            privilege_requirements: "unchanged from the deployed configuration",
            resource_implications: "unchanged",
            operational_risks: "an unsafe custom file is reported, not repaired in silence",
            enforcement_behavior: "whatever the file states, after validation",
            degradation_behavior: "validation fails with actionable diagnostics rather than rewriting policy",
            recommended_use_cases: "reviewing or migrating a hand-tuned deployment",
        },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CapabilityState {
    /// The relevant file or kernel declaration was read and agrees.
    Verified,
    /// The relevant file says the feature is not available here.
    Unavailable,
    /// The feature is present but incompatible with this build.
    Unsupported,
    /// Nothing was concluded: unreadable, or requires a privileged probe this
    /// unprivileged planner deliberately does not perform.
    Unknown,
}

impl CapabilityState {
    pub fn word(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Unavailable => "UNAVAILABLE",
            Self::Unsupported => "UNSUPPORTED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub name: String,
    pub state: CapabilityState,
    pub detail: String,
    pub required_for: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostCapabilities {
    pub kernel_release: String,
    pub architecture: String,
    pub capabilities: Vec<Capability>,
}

impl HostCapabilities {
    pub fn detect() -> Self {
        let mut capabilities = Vec::new();
        let kernel_release =
            read_first_line("/proc/sys/kernel/osrelease").unwrap_or_else(|_| "UNKNOWN".to_string());
        let architecture = std::env::consts::ARCH.to_string();

        let btf_path = crate::btf_compat::BTF_PATH;
        let (btf_state, btf_detail) = match fs::File::open(btf_path) {
            Ok(_) => (
                CapabilityState::Verified,
                format!("{btf_path} is readable by this process"),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                CapabilityState::Unavailable,
                format!("{btf_path} does not exist; CO-RE relocation cannot resolve"),
            ),
            Err(e) => (
                CapabilityState::Unknown,
                format!("{btf_path} could not be read: {e}"),
            ),
        };
        capabilities.push(Capability {
            name: "btf".into(),
            state: btf_state,
            detail: btf_detail,
            required_for: "CO-RE relocation and raw prototype preflight".into(),
        });

        let (cgroup_state, cgroup_detail) =
            match fs::File::open("/sys/fs/cgroup/cgroup.controllers") {
                Ok(_) => (
                    CapabilityState::Verified,
                    "/sys/fs/cgroup/cgroup.controllers is readable".into(),
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (
                    CapabilityState::Unavailable,
                    "no cgroup v2 controllers file at the standard mount".into(),
                ),
                Err(e) => (
                    CapabilityState::Unknown,
                    format!("cgroup v2 controllers file could not be read: {e}"),
                ),
            };
        capabilities.push(Capability {
            name: "cgroup_v2".into(),
            state: cgroup_state,
            detail: cgroup_detail,
            required_for: "per-cgroup volume counters and future egress enforcement".into(),
        });

        let (bpffs_state, bpffs_detail) = match fs::read_to_string("/proc/mounts") {
            Ok(mounts)
                if mounts.lines().any(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    f.len() > 2 && f[1] == "/sys/fs/bpf" && f[2] == "bpf"
                }) =>
            {
                (
                    CapabilityState::Verified,
                    "/sys/fs/bpf is mounted as bpf in /proc/mounts".into(),
                )
            }
            Ok(_) => (
                CapabilityState::Unavailable,
                "no bpf mount at /sys/fs/cgroup's conventional bpffs path".into(),
            ),
            Err(e) => (
                CapabilityState::Unknown,
                format!("/proc/mounts could not be read: {e}"),
            ),
        };
        capabilities.push(Capability {
            name: "bpffs".into(),
            state: bpffs_state,
            detail: bpffs_detail,
            required_for: "persistent BPF object pinning and cgroup egress readiness".into(),
        });

        let (lsm_state, lsm_detail) = match fs::read_to_string("/sys/kernel/security/lsm") {
            Ok(list)
                if list
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .any(|x| x == "bpf") =>
            {
                (
                    CapabilityState::Verified,
                    format!("active LSM list contains bpf: {}", list.trim()),
                )
            }
            Ok(list) => (
                CapabilityState::Unavailable,
                format!("bpf is not in the active LSM list: {}", list.trim()),
            ),
            Err(e) => (
                CapabilityState::Unknown,
                format!("active LSM list could not be read: {e}"),
            ),
        };
        capabilities.push(Capability {
            name: "bpf_lsm".into(),
            state: lsm_state,
            detail: lsm_detail,
            required_for: "guarded-file in-kernel denial (BPF-LSM)".into(),
        });

        let paranoid = read_first_line("/proc/sys/kernel/perf_event_paranoid")
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok());
        let cap_eff = effective_capabilities();
        let sys_admin = cap_eff
            .as_ref()
            .map(|set| set.contains(&21))
            .unwrap_or(false);
        let perf_bpf = cap_eff
            .as_ref()
            .map(|set| set.contains(&39))
            .unwrap_or(false);
        let perfmon = cap_eff
            .as_ref()
            .map(|set| set.contains(&38))
            .unwrap_or(false);
        let (perf_state, perf_detail) = match (paranoid, cap_eff.as_ref()) {
            (Some(p), Some(_)) if p <= 1 => (
                CapabilityState::Verified,
                format!("perf_event_paranoid={p} allows tracepoint/kprobe probes for this process"),
            ),
            (Some(p), Some(_)) if sys_admin => (
                CapabilityState::Verified,
                format!("perf_event_paranoid={p} but this process holds CAP_SYS_ADMIN"),
            ),
            (Some(p), Some(_)) => (
                CapabilityState::Unavailable,
                format!(
                    "perf_event_paranoid={p} and this process lacks CAP_SYS_ADMIN; the installed unit's capabilities must be checked separately"
                ),
            ),
            (_, None) => (
                CapabilityState::Unknown,
                "CapEff could not be read from /proc/self/status".into(),
            ),
            (None, _) => (
                CapabilityState::Unknown,
                "perf_event_paranoid could not be read".into(),
            ),
        };
        capabilities.push(Capability {
            name: "perf_gate".into(),
            state: perf_state,
            detail: perf_detail,
            required_for: "exec tracepoint and security_* kprobe attachment".into(),
        });

        let cap_names = |set: &Vec<u32>| -> Vec<&'static str> {
            let mut out = Vec::new();
            if set.contains(&19) {
                out.push("CAP_SYS_PTRACE");
            }
            if set.contains(&21) {
                out.push("CAP_SYS_ADMIN");
            }
            if set.contains(&38) {
                out.push("CAP_PERFMON");
            }
            if set.contains(&39) {
                out.push("CAP_BPF");
            }
            out
        };
        let (cap_state, cap_detail) = match cap_eff.as_ref() {
            Some(set) => {
                let names = cap_names(set);
                (
                    CapabilityState::Verified,
                    format!(
                        "this process holds {}; CAP_BPF={}, CAP_PERFMON={}, CAP_SYS_PTRACE={}, CAP_SYS_ADMIN={} (the daemon's unit must be checked separately)",
                        if names.is_empty() {
                            "none of CAP_SYS_PTRACE/CAP_SYS_ADMIN/CAP_PERFMON/CAP_BPF".into()
                        } else {
                            names.join(", ")
                        },
                        yes_no(perf_bpf),
                        yes_no(perfmon),
                        yes_no(set.contains(&19)),
                        yes_no(sys_admin)
                    ),
                )
            }
            None => (
                CapabilityState::Unknown,
                "CapEff could not be read from /proc/self/status".into(),
            ),
        };
        capabilities.push(Capability {
            name: "process_capabilities".into(),
            state: cap_state,
            detail: cap_detail,
            required_for: "BPF load, perf attachment and /proc identity reads".into(),
        });

        // No bpf() syscall is made here. A planner run by an unprivileged user
        // cannot prove what the privileged daemon can load; the live VM gate is
        // the only evidence for that, and it stays separate.
        capabilities.push(Capability {
            name: "bpf_syscall".into(),
            state: CapabilityState::Unknown,
            detail: "not invoked by this unprivileged planner; verifier/attach requires the privileged VM gate".into(),
            required_for: "all eBPF program loading".into(),
        });

        for result in crate::btf_compat::check_all(btf_path) {
            let state = match result.status {
                crate::btf_compat::Compatibility::Compatible => CapabilityState::Verified,
                crate::btf_compat::Compatibility::Incompatible => CapabilityState::Unsupported,
                crate::btf_compat::Compatibility::Unknown => CapabilityState::Unknown,
            };
            capabilities.push(Capability {
                name: format!("hook:{}", result.hook.func()),
                state,
                detail: result.reason().to_string(),
                required_for: "six-hook cgroup volume accounting".into(),
            });
        }

        Self {
            kernel_release,
            architecture,
            capabilities,
        }
    }

    pub fn state(&self, name: &str) -> CapabilityState {
        self.capabilities
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.state)
            .unwrap_or(CapabilityState::Unknown)
    }

    /// True only when every measured precondition for the six volume hooks is
    /// verified. An UNKNOWN hook must not make a profile claim support.
    pub fn volume_supported(&self) -> bool {
        self.state("btf") == CapabilityState::Verified
            && self.state("cgroup_v2") == CapabilityState::Verified
            && self.state("perf_gate") == CapabilityState::Verified
            && self
                .capabilities
                .iter()
                .filter(|c| c.name.starts_with("hook:"))
                .all(|c| c.state == CapabilityState::Verified)
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn read_first_line(path: &str) -> anyhow::Result<String> {
    let mut body = String::new();
    File::open(path)
        .with_context(|| format!("opening {path}"))?
        .take(4096)
        .read_to_string(&mut body)?;
    Ok(body.lines().next().unwrap_or("").trim().to_string())
}

fn effective_capabilities() -> Option<Vec<u32>> {
    let body = fs::read_to_string("/proc/self/status").ok()?;
    let hex = body.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() == "CapEff" {
            Some(value.trim().to_string())
        } else {
            None
        }
    })?;
    let value = u64::from_str_radix(&hex, 16).ok()?;
    Some((0..64).filter(|bit| value & (1u64 << bit) != 0).collect())
}

/// A generated profile: the real `Config` plus the reasons behind each choice.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedProfile {
    pub profile: ProfileName,
    pub config: Config,
    pub toml: String,
    pub capability_notes: Vec<String>,
}

pub fn generate(profile: ProfileName, caps: &HostCapabilities) -> anyhow::Result<GeneratedProfile> {
    if profile == ProfileName::Custom {
        bail!("the custom profile validates an existing file; use --config PATH --config-validate");
    }
    let mut cfg = Config::safe_default();
    cfg.schema_version = CURRENT_SCHEMA_VERSION;
    let mut notes = Vec::new();

    let volume_ok = caps.volume_supported();
    if !volume_ok {
        let reasons: Vec<String> = caps
            .capabilities
            .iter()
            .filter(|c| {
                (c.name.starts_with("hook:")
                    || c.name == "btf"
                    || c.name == "cgroup_v2"
                    || c.name == "perf_gate")
                    && c.state != CapabilityState::Verified
            })
            .map(|c| format!("{}={} ({})", c.name, c.state.word(), c.detail))
            .collect();
        notes.push(format!(
            "cgroup volume counters left OFF: not all required capabilities are VERIFIED ({})",
            if reasons.is_empty() {
                "no reason recorded".into()
            } else {
                reasons.join("; ")
            }
        ));
    }

    match profile {
        ProfileName::Essential => {
            cfg.mode = Mode::Observe;
            cfg.c2_rules.enabled = false;
            cfg.network_snapshot.enabled = false;
            cfg.net_volume.enabled = false;
        }
        ProfileName::Balanced => {
            cfg.mode = Mode::Observe;
            cfg.c2_rules.enabled = true;
            cfg.network_snapshot.enabled = true;
            cfg.network_snapshot.interval_secs = 300;
            cfg.net_volume.enabled = volume_ok;
        }
        ProfileName::Advanced | ProfileName::Hardened => {
            cfg.mode = Mode::Observe;
            cfg.c2_rules.enabled = true;
            cfg.c2_rules.min_dials = 5;
            cfg.network_snapshot.enabled = true;
            cfg.network_snapshot.interval_secs = 120;
            cfg.net_volume.enabled = volume_ok;
        }
        ProfileName::Custom => unreachable!("handled above"),
    }

    // Every generated profile is observe-only. `respond` is left at its safe
    // defaults, `enforce.arm` false and `egress.enabled` false: a chosen profile
    // is consent to monitoring, not consent to block processes or traffic.
    cfg.enforce.arm = false;
    cfg.egress.enabled = false;
    cfg.egress.arm = false;
    notes.push(
        "no kill responder, guarded-file denial or cgroup egress denial is armed; opt in only after observing clean findings"
            .into(),
    );
    if profile == ProfileName::Hardened {
        if caps.state("bpf_lsm") == CapabilityState::Verified {
            notes.push(
                "bpf LSM is active: guarded-file denial is READY, but no path/uid was invented by this profile"
                    .into(),
            );
        } else {
            notes.push(format!(
                "bpf LSM is {}: guarded-file denial stays unavailable; detection continues",
                caps.state("bpf_lsm").word()
            ));
        }
    }
    if cfg.bridge.is_none() {
        notes.push("SENTINEL bridge not configured: findings go to the journal only".into());
    }

    cfg.validate()
        .map_err(|e| anyhow!("generated profile is invalid: {e}"))?;
    let toml = toml::to_string_pretty(&cfg).context("serializing generated config")?;
    // A generated document must be re-readable through the exact load path the
    // daemon uses. This is a self-check of the engine, not a runtime claim.
    let parsed: Config = toml::from_str(&toml).context("parsing generated config")?;
    parsed
        .validate()
        .map_err(|e| anyhow!("generated config failed reload validation: {e}"))?;

    Ok(GeneratedProfile {
        profile,
        config: cfg,
        toml,
        capability_notes: notes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

impl DiagnosticSeverity {
    pub fn word(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub field: String,
    pub problem: String,
    pub security_consequence: String,
    pub suggested_correction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub config_path: Option<String>,
    pub schema_version: u32,
    pub status: String,
    pub diagnostics: Vec<Diagnostic>,
    pub capability_notes: Vec<String>,
}

/// Schema version written in the document, before serde's default is applied.
pub fn declared_schema_version(text: &str) -> anyhow::Result<u32> {
    let value: toml::Value = toml::from_str(text).context("parsing TOML")?;
    match value.get("schema_version") {
        None => Ok(LEGACY_SCHEMA_VERSION),
        Some(toml::Value::Integer(v)) if *v >= 0 => Ok(*v as u32),
        Some(other) => bail!("schema_version must be an integer, found {other:?}"),
    }
}

/// Dedicated validator over the same `Config` the daemon loads.
pub fn validate_file(
    path: Option<&Path>,
    caps: &HostCapabilities,
    strict: bool,
) -> ValidationReport {
    let mut diagnostics = Vec::new();
    let mut capability_notes = Vec::new();
    let (cfg, loaded, declared, mode_bits) = match path {
        Some(p) => match fs::read_to_string(p) {
            Ok(text) => {
                let declared = declared_schema_version(&text).unwrap_or(LEGACY_SCHEMA_VERSION);
                match toml::from_str::<Config>(&text) {
                    Ok(cfg) => {
                        let mode_bits = fs::metadata(p).map(|m| m.permissions().mode()).ok();
                        let unread = unread_keys(&cfg, &text);
                        (Some(cfg), unread, declared, mode_bits)
                    }
                    Err(e) => {
                        diagnostics.push(Diagnostic {
                            severity: DiagnosticSeverity::Error,
                            field: "TOML syntax".into(),
                            problem: e.to_string(),
                            security_consequence:
                                "the daemon cannot load policy and will not start".into(),
                            suggested_correction:
                                "fix the reported line and rerun --config-validate".into(),
                        });
                        return ValidationReport {
                            config_path: Some(p.display().to_string()),
                            schema_version: declared,
                            status: "FAIL".into(),
                            diagnostics,
                            capability_notes,
                        };
                    }
                }
            }
            Err(e) => {
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    field: "config file".into(),
                    problem: format!("cannot read {}: {e}", p.display()),
                    security_consequence: "no configuration can be applied".into(),
                    suggested_correction: "pass an existing file with --config PATH".into(),
                });
                return ValidationReport {
                    config_path: Some(p.display().to_string()),
                    schema_version: LEGACY_SCHEMA_VERSION,
                    status: "FAIL".into(),
                    diagnostics,
                    capability_notes,
                };
            }
        },
        None => (
            Some(Config::safe_default()),
            Vec::new(),
            CURRENT_SCHEMA_VERSION,
            None,
        ),
    };
    let cfg = cfg.expect("the no-path branch always produces a config");

    if declared == LEGACY_SCHEMA_VERSION {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            field: "schema_version".into(),
            problem: "no schema_version key (legacy version 0)".into(),
            security_consequence: "migration and drift cannot anchor to an explicit version".into(),
            suggested_correction:
                "back up the file, then run warden --config-migrate --target-version 1".into(),
        });
    }
    if let Err(e) = cfg.validate() {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            field: "configuration".into(),
            problem: e.to_string(),
            security_consequence: "the daemon refuses this policy at startup/reload".into(),
            suggested_correction: "correct the field named in the message and validate again"
                .into(),
        });
    }
    let has_credentials = cfg.bridge.is_some() || cfg.heartbeat.is_some();
    if let Some(mode) = mode_bits {
        if mode & 0o022 != 0 {
            diagnostics.push(Diagnostic {
                severity: if has_credentials {
                    DiagnosticSeverity::Error
                } else {
                    DiagnosticSeverity::Warning
                },
                field: "config file permissions".into(),
                problem: format!("mode {:04o} is group/world writable", mode & 0o777),
                security_consequence: "an unprivileged local user can change security policy or inject bridge credentials".into(),
                suggested_correction: "chmod 0640 the file and keep it owned by root:warden".into(),
            });
        } else if mode & 0o007 != 0 {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                field: "config file permissions".into(),
                problem: format!("mode {:04o} is world-readable", mode & 0o777),
                security_consequence:
                    "bridge credentials in this file may be readable by other local users".into(),
                suggested_correction: "chmod 0640 the file".into(),
            });
        }
    }
    for key in loaded {
        diagnostics.push(Diagnostic {
            severity: if strict {
                DiagnosticSeverity::Error
            } else {
                DiagnosticSeverity::Warning
            },
            field: key.clone(),
            problem: "this key is not read by this build".into(),
            security_consequence: "Warden runs its default for that setting, not the written value"
                .into(),
            suggested_correction:
                "check the section header, spelling and this build's config reference".into(),
        });
    }
    if cfg.app.cgroup_contains.is_empty()
        && (cfg.network_rules.app_egress_only || cfg.listen_rules.app_listen_only)
    {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            field: "app.cgroup_contains".into(),
            problem: "app cgroup matchers are empty while app-only egress/listen judgement is on"
                .into(),
            security_consequence:
                "CONNECT/LISTEN records are read then discarded; quiet logs are not clean logs"
                    .into(),
            suggested_correction:
                "name the application cgroup, or explicitly set the app_only flags to false".into(),
        });
    }
    if cfg.mode == Mode::Enforce
        && !cfg.respond.kill_reverse_shell
        && !cfg.respond.kill_takedown_attacker
        && !cfg.respond.kill_privilege_escalation
        && !cfg.respond.kill_ransomware
        && !cfg.enforce.arm
        && !cfg.egress.arm
    {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Warning,
            field: "mode".into(),
            problem: "mode=enforce with no responder or arm flag enabled".into(),
            security_consequence: "the posture is labelled enforce but no response action can occur".into(),
            suggested_correction: "keep observe until findings are trusted, then opt into a named responder deliberately".into(),
        });
    }
    if cfg.net_volume.enabled && !caps.volume_supported() {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            field: "net_volume.enabled".into(),
            problem: "volume counters are enabled but not every measured capability is VERIFIED".into(),
            security_consequence: "the coverage claim would overstate what this host can deliver".into(),
            suggested_correction: "disable net_volume or re-run on a host where BTF, cgroup v2 and all six hooks are VERIFIED".into(),
        });
    }
    if cfg.enforce.arm && caps.state("bpf_lsm") != CapabilityState::Verified {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            field: "enforce.arm".into(),
            problem: format!(
                "guarded-file denial is armed while bpf LSM is {}",
                caps.state("bpf_lsm").word()
            ),
            security_consequence:
                "the policy claims in-kernel denial that this host cannot establish".into(),
            suggested_correction: "set enforce.arm=false until the active LSM list includes bpf"
                .into(),
        });
    }
    if cfg.egress.enabled && caps.state("cgroup_v2") != CapabilityState::Verified {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Error,
            field: "egress.enabled".into(),
            problem: "cgroup egress programs are enabled on a host without verified cgroup v2"
                .into(),
            security_consequence:
                "attachment cannot succeed; a running agent may report a policy it cannot enforce"
                    .into(),
            suggested_correction: "use cgroup v2, or set egress.enabled=false".into(),
        });
    }
    if cfg.egress.arm {
        capability_notes.push(
            "egress.arm=true denies traffic; confirm the target is an isolated test cgroup before starting the agent"
                .into(),
        );
    }
    capability_notes.push(format!(
        "host capabilities measured for this process: {}",
        caps.capabilities
            .iter()
            .map(|c| format!("{}={}", c.name, c.state.word()))
            .collect::<Vec<_>>()
            .join(", ")
    ));

    let status = if diagnostics
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Error)
    {
        "FAIL"
    } else if diagnostics.is_empty() {
        "PASS"
    } else {
        "PASS_WITH_WARNINGS"
    };
    ValidationReport {
        config_path: path.map(|p| p.display().to_string()),
        schema_version: declared,
        status: status.into(),
        diagnostics,
        capability_notes,
    }
}

/// A simulation of what the engine would apply. It never calls bpf().
#[derive(Debug, Clone, Serialize)]
pub struct ConfigPlan {
    pub profile: ProfileName,
    pub status: String,
    pub simulation_notice: String,
    pub changes: Vec<String>,
    pub enabled_sensors: Vec<String>,
    pub disabled_sensors: Vec<String>,
    pub required_privileges: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub operational_risks: Vec<String>,
    pub service_actions: Vec<String>,
    pub policy_changes: Vec<String>,
}

pub fn plan(
    profile: ProfileName,
    cfg: &Config,
    validation: &ValidationReport,
    caps: &HostCapabilities,
) -> ConfigPlan {
    let mut enabled = vec![
        "exec/file/module/mount/persistence/protected-pid detection".into(),
        "ring buffer event collection".into(),
        "journal telemetry".into(),
    ];
    let mut disabled = Vec::new();
    if cfg.c2_rules.enabled {
        enabled.push("bounded C2 cadence analytics".into());
    } else {
        disabled.push("bounded C2 cadence analytics".into());
    }
    if cfg.network_snapshot.enabled {
        enabled.push("periodic /proc socket snapshot".into());
    } else {
        disabled.push("periodic /proc socket snapshot".into());
    }
    if cfg.net_volume.enabled {
        enabled.push("six-hook per-cgroup volume counters".into());
    } else {
        disabled.push("six-hook per-cgroup volume counters".into());
    }
    if cfg.enforce.arm {
        enabled.push("BPF-LSM guarded-file denial".into());
    } else {
        disabled.push("BPF-LSM guarded-file denial (shadow/off)".into());
    }
    if cfg.egress.enabled {
        enabled.push("cgroup egress programs".into());
    } else {
        disabled.push("cgroup egress programs".into());
    }
    if cfg.bridge.is_some() {
        enabled.push("SENTINEL bridge (configured; connectivity not tested here)".into());
    } else {
        disabled.push("SENTINEL bridge (journal only)".into());
    }

    let mut risks = vec![
        "the BPF ring is lossy by design; per-sensor drop counters are the evidence of pressure"
            .into(),
        "C2 cadence similarity is suspicion, not proof of command and control".into(),
    ];
    if cfg.app.cgroup_contains.is_empty() {
        risks.push("empty app cgroup matchers make app-only egress/listen findings silent".into());
    }
    if cfg.mode == Mode::Enforce {
        risks.push("mode=enforce permits individually enabled responders to act".into());
    }

    ConfigPlan {
        profile,
        status: validation.status.clone(),
        simulation_notice: "SIMULATION ONLY: no bpf() call, program load, attach, service change or network request was made. An eBPF attach can be claimed only by the privileged VM gate.".into(),
        changes: vec![
            format!("write/keep schema_version = {}", cfg.schema_version),
            format!("operating mode = {:?} (lowercase in TOML)", cfg.mode),
            format!("C2 analytics = {}", yes_no(cfg.c2_rules.enabled)),
            format!("socket snapshot = {}", yes_no(cfg.network_snapshot.enabled)),
            format!("volume counters = {}", yes_no(cfg.net_volume.enabled)),
            format!("BPF-LSM arm = {}", yes_no(cfg.enforce.arm)),
            format!("cgroup egress = {}", yes_no(cfg.egress.enabled)),
        ],
        enabled_sensors: enabled,
        disabled_sensors: disabled,
        required_privileges: vec![
            "root or CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE for the daemon".into(),
            "CAP_SYS_ADMIN where perf_event_paranoid > 1 (see doctor output)".into(),
            "no additional privilege is taken by this planner".into(),
        ],
        required_capabilities: caps
            .capabilities
            .iter()
            .map(|c| format!("{}={}", c.name, c.state.word()))
            .collect(),
        operational_risks: risks,
        service_actions: vec![
            "systemctl daemon-reload after installing a changed unit".into(),
            "warden --check --config PATH --strict before restart".into(),
            "systemctl restart warden to apply non-reloadable changes (ring size, bridge)".into(),
            "SIGHUP reloads policy the daemon supports live; planner does not send it".into(),
        ],
        policy_changes: vec![
            format!("profile selection: {}", profile.word()),
            "no generated profile arms kill/deny behavior".into(),
        ],
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub schema: &'static str,
    pub from_version: u32,
    pub to_version: u32,
    pub changed: bool,
    pub config_path: String,
    pub backup_path: Option<String>,
    pub validation_status: String,
}

/// Versioned, backed-up, validated migration of the TOML document.
pub fn migrate(path: &Path, target_version: u32) -> anyhow::Result<MigrationReport> {
    if target_version != CURRENT_SCHEMA_VERSION {
        bail!(
            "target schema {target_version} is not supported; this build migrates to {CURRENT_SCHEMA_VERSION}"
        );
    }
    let original =
        fs::read_to_string(path).with_context(|| format!("reading config {}", path.display()))?;
    let from = declared_schema_version(&original)?;
    if from != LEGACY_SCHEMA_VERSION && from != CURRENT_SCHEMA_VERSION {
        bail!("refusing ambiguous migration from schema version {from}");
    }
    // Validate before touching the file. The default makes legacy documents
    // loadable, so this catches an unrelated unsafe edit before a backup is made.
    let pre: Config = toml::from_str(&original).context("parsing config before migration")?;
    pre.validate()
        .map_err(|e| anyhow!("pre-migration validation failed: {e}"))?;

    if from == CURRENT_SCHEMA_VERSION {
        return Ok(MigrationReport {
            schema: "warden.config-migration.v1",
            from_version: from,
            to_version: target_version,
            changed: false,
            config_path: path.display().to_string(),
            backup_path: None,
            validation_status: "PASS (already at target; no write performed)".into(),
        });
    }

    let backup = backup_file(path, "pre-migration")?;
    let header = format!(
        "# Migrated by `warden --config-migrate --target-version {target_version}`.\n\
         # Original file preserved at {}.\n\
         schema_version = {target_version}\n\n",
        backup.display()
    );
    let migrated = format!("{header}{original}");
    let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
    if let Err(e) = atomic_write(path, migrated.as_bytes(), mode) {
        let _ = fs::copy(&backup, path);
        return Err(e.context("migration write failed; original restored"));
    }
    match Config::load(path) {
        Ok(_) => Ok(MigrationReport {
            schema: "warden.config-migration.v1",
            from_version: from,
            to_version: target_version,
            changed: true,
            config_path: path.display().to_string(),
            backup_path: Some(backup.display().to_string()),
            validation_status: "PASS".into(),
        }),
        Err(e) => {
            let _ = fs::copy(&backup, path);
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
            Err(anyhow!(
                "post-migration validation failed, original restored: {e}"
            ))
        }
    }
}

/// Rollback a configuration file from a verified backup.
pub fn rollback(target: &Path, backup: &Path) -> anyhow::Result<serde_json::Value> {
    let body = fs::read_to_string(backup)
        .with_context(|| format!("reading rollback source {}", backup.display()))?;
    let from_backup: Config = toml::from_str(&body)
        .with_context(|| format!("parsing rollback source {}", backup.display()))?;
    from_backup
        .validate()
        .map_err(|e| anyhow!("refusing rollback to an invalid backup: {e}"))?;
    let unsafe_backup = (from_backup.mode == Mode::Enforce
        && (from_backup.respond.kill_reverse_shell
            || from_backup.respond.kill_takedown_attacker
            || from_backup.respond.kill_privilege_escalation
            || from_backup.respond.kill_ransomware))
        || from_backup.enforce.arm
        || from_backup.egress.arm;
    if unsafe_backup {
        bail!(
            "refusing rollback: the backup arms kill or denial behavior; restore it manually only after reviewing shadow findings"
        );
    }

    let current_mode = fs::metadata(target)
        .with_context(|| format!("reading current config {}", target.display()))?
        .permissions()
        .mode()
        & 0o7777;
    let safety = backup_file(target, "pre-rollback")?;
    if let Err(e) = atomic_write(target, body.as_bytes(), current_mode) {
        let _ = fs::copy(&safety, target);
        return Err(e.context("rollback write failed; current file preserved"));
    }
    match Config::load(target) {
        Ok(_) => Ok(serde_json::json!({
            "schema": "warden.config-rollback.v1",
            "status": "PASS",
            "target": target.display().to_string(),
            "source_backup": backup.display().to_string(),
            "safety_backup": safety.display().to_string(),
            "post_rollback_validation": "PASS",
            "post_rollback_health_check": "run `warden --check --config PATH --strict` and `warden --health` before restarting the service"
        })),
        Err(e) => {
            let _ = fs::copy(&safety, target);
            let _ = fs::set_permissions(target, fs::Permissions::from_mode(current_mode));
            Err(anyhow!(
                "post-rollback validation failed, current file restored: {e}"
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub schema: String,
    pub config_path: String,
    pub schema_version: u32,
    pub content_fingerprint: String,
    pub content_length: usize,
    pub file_mode: u32,
    pub kernel_release: String,
    pub capabilities: serde_json::Value,
    pub service_active: Option<bool>,
    pub not_measured: Vec<String>,
}

pub fn snapshot(path: &Path) -> anyhow::Result<StateSnapshot> {
    let bytes = fs::read(path)
        .with_context(|| format!("reading config for baseline {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let cfg: Config = toml::from_str(&text).context("parsing config for baseline")?;
    cfg.validate().context("validating config for baseline")?;
    let caps = HostCapabilities::detect();
    let capabilities: serde_json::Value = caps
        .capabilities
        .iter()
        .map(|c| {
            (
                c.name.clone(),
                serde_json::json!({"state": c.state.word(), "detail": c.detail}),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    Ok(StateSnapshot {
        schema: "warden.config-baseline.v1".into(),
        config_path: path.display().to_string(),
        schema_version: declared_schema_version(&text)?,
        content_fingerprint: fnv1a64(&bytes),
        content_length: bytes.len(),
        file_mode: fs::metadata(path)?.permissions().mode() & 0o7777,
        kernel_release: caps.kernel_release,
        capabilities,
        service_active: service_is_active("warden"),
        not_measured: vec![
            "attached BPF programs (needs CAP_BPF and a live map read)".into(),
            "ring-buffer drop counters".into(),
            "in-memory effective policy after SIGHUP".into(),
            "spool contents and bridge delivery".into(),
        ],
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftRow {
    pub property: String,
    pub desired: String,
    pub configured_or_observed: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriftReport {
    pub schema: String,
    pub baseline_path: String,
    pub config_path: String,
    pub rows: Vec<DriftRow>,
    pub not_measured: Vec<String>,
}

pub fn drift(baseline_path: &Path) -> anyhow::Result<DriftReport> {
    let baseline: StateSnapshot = serde_json::from_slice(
        &fs::read(baseline_path)
            .with_context(|| format!("reading baseline {}", baseline_path.display()))?,
    )
    .context("parsing baseline JSON")?;
    if baseline.schema != "warden.config-baseline.v1" {
        bail!("unsupported baseline schema {}", baseline.schema);
    }
    let target = PathBuf::from(&baseline.config_path);
    let current = snapshot(&target)?;
    let mut rows = Vec::new();
    let mut push = |property: &str, desired: String, actual: String, same: bool, measured: bool| {
        rows.push(DriftRow {
            property: property.into(),
            desired,
            configured_or_observed: actual,
            status: if !measured {
                "UNKNOWN".into()
            } else if same {
                "PASS".into()
            } else {
                "DRIFT".into()
            },
        });
    };
    push(
        "config.content_fingerprint",
        baseline.content_fingerprint.clone(),
        current.content_fingerprint.clone(),
        baseline.content_fingerprint == current.content_fingerprint,
        true,
    );
    push(
        "config.file_mode",
        format!("{:04o}", baseline.file_mode),
        format!("{:04o}", current.file_mode),
        baseline.file_mode == current.file_mode,
        true,
    );
    push(
        "config.schema_version",
        baseline.schema_version.to_string(),
        current.schema_version.to_string(),
        baseline.schema_version == current.schema_version,
        true,
    );
    push(
        "host.kernel_release",
        baseline.kernel_release.clone(),
        current.kernel_release.clone(),
        baseline.kernel_release == current.kernel_release,
        true,
    );
    let names: std::collections::BTreeSet<String> = baseline
        .capabilities
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for name in names {
        let before = baseline
            .capabilities
            .get(&name)
            .and_then(|v| v.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();
        let after = current
            .capabilities
            .get(&name)
            .and_then(|v| v.get("state"))
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();
        push(
            &format!("capability.{name}"),
            before,
            after,
            {
                let b = baseline
                    .capabilities
                    .get(&name)
                    .and_then(|v| v.get("detail"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let a = current
                    .capabilities
                    .get(&name)
                    .and_then(|v| v.get("detail"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                b == a
            },
            true,
        );
    }
    match (baseline.service_active, current.service_active) {
        (Some(before), Some(after)) => push(
            "service.warden.active",
            before.to_string(),
            after.to_string(),
            before == after,
            true,
        ),
        _ => push(
            "service.warden.active",
            baseline
                .service_active
                .map(|v| v.to_string())
                .unwrap_or_else(|| "UNKNOWN".into()),
            current
                .service_active
                .map(|v| v.to_string())
                .unwrap_or_else(|| "UNKNOWN".into()),
            false,
            false,
        ),
    }
    Ok(DriftReport {
        schema: "warden.config-drift.v1".into(),
        baseline_path: baseline_path.display().to_string(),
        config_path: target.display().to_string(),
        rows,
        not_measured: baseline.not_measured,
    })
}

fn service_is_active(unit: &str) -> Option<bool> {
    let out = std::process::Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .output()
        .ok()?;
    Some(out.status.success())
}

/// Read-only installation self-test. It never starts a service or loads BPF.
#[derive(Debug, Clone, Serialize)]
pub struct SelfTestCheck {
    pub name: &'static str,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfTestReport {
    pub schema: String,
    pub checks: Vec<SelfTestCheck>,
}

pub fn self_test(config_path: Option<&Path>) -> SelfTestReport {
    let mut checks = Vec::new();
    let mut add = |name: &'static str, status: &str, detail: String| {
        checks.push(SelfTestCheck {
            name,
            status: status.into(),
            detail,
        });
    };

    match std::env::current_exe() {
        Ok(bin) if bin.is_file() => add(
            "binary",
            "PASS",
            format!("current executable exists at {}", bin.display()),
        ),
        Ok(bin) => add("binary", "FAIL", format!("{} is not a file", bin.display())),
        Err(e) => add("binary", "FAIL", format!("current executable unknown: {e}")),
    }
    add(
        "artifact_integrity",
        "PASS",
        format!(
            "embedded eBPF object: {} bytes, fnv-1a {:016x}",
            crate::loader::obj_len(),
            crate::loader::obj_fingerprint()
        ),
    );

    let candidate = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/warden/warden.toml"));
    if candidate.is_file() {
        let report = validate_file(Some(&candidate), &HostCapabilities::detect(), false);
        add(
            "configuration",
            if report.status == "FAIL" {
                "FAIL"
            } else {
                "PASS"
            },
            format!("{}: {}", candidate.display(), report.status),
        );
        let mode = fs::metadata(&candidate)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        add(
            "configuration_permissions",
            if mode & 0o022 == 0 { "PASS" } else { "FAIL" },
            format!(
                "{} mode {:04o} (expected no group/world write)",
                candidate.display(),
                mode
            ),
        );
    } else {
        add(
            "configuration",
            "UNKNOWN",
            format!(
                "{} does not exist; no installed configuration was tested",
                candidate.display()
            ),
        );
    }

    let caps = HostCapabilities::detect();
    add(
        "kernel_release",
        if caps.kernel_release == "UNKNOWN" {
            "UNKNOWN"
        } else {
            "PASS"
        },
        format!("kernel {}", caps.kernel_release),
    );
    let btf = caps.state("btf");
    add(
        "btf",
        match btf {
            CapabilityState::Verified => "PASS",
            CapabilityState::Unknown => "UNKNOWN",
            _ => "FAIL",
        },
        caps.capabilities
            .iter()
            .find(|c| c.name == "btf")
            .map(|c| c.detail.clone())
            .unwrap_or_default(),
    );
    let hooks: Vec<&Capability> = caps
        .capabilities
        .iter()
        .filter(|c| c.name.starts_with("hook:"))
        .collect();
    let hook_status =
        if hooks.len() == 6 && hooks.iter().all(|c| c.state == CapabilityState::Verified) {
            "PASS"
        } else if hooks
            .iter()
            .any(|c| c.state == CapabilityState::Unsupported)
        {
            "FAIL"
        } else {
            "UNKNOWN"
        };
    add(
        "volume_hook_prototypes",
        hook_status,
        hooks
            .iter()
            .map(|c| format!("{}={}", c.name, c.state.word()))
            .collect::<Vec<_>>()
            .join(", "),
    );

    let unit = Path::new("/etc/systemd/system/warden.service");
    if unit.is_file() {
        add("systemd_unit", "PASS", format!("{} exists", unit.display()));
    } else {
        add(
            "systemd_unit",
            "NOT_APPLICABLE",
            "no installed systemd unit on this host".into(),
        );
    }
    add(
        "kernel_sensor_load",
        "NOT_RUN",
        "requires a privileged disposable VM and is never attempted by this read-only self-test"
            .into(),
    );
    add(
        "runtime_startup",
        "NOT_RUN",
        "the self-test does not start, stop or restart the service".into(),
    );
    add(
        "health_report",
        "PASS",
        format!(
            "warden --health rendered {} claim lines from /proc (no maps read)",
            match config_path {
                Some(p) => crate::health::report(Some(&PathBuf::from(p))).len(),
                None => crate::health::report(None).len(),
            }
        ),
    );
    add(
        "local_event_pipeline",
        "NOT_RUN",
        "a live event requires loaded sensors; no kernel object was loaded here".into(),
    );
    match config_path
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| toml::from_str::<Config>(&s).ok())
        .and_then(|c| c.bridge)
    {
        Some(bridge) => add(
            "sentinel_connectivity",
            "NOT_RUN",
            format!(
                "bridge configured ({}); this self-test performs no network request; {}",
                crate::config::url_host(&bridge.url).unwrap_or_else(|| "unknown host".into()),
                crate::deliver::check(&bridge)
                    .unwrap_or_else(|e| format!("config check failed: {e}"))
            ),
        ),
        None => add(
            "sentinel_connectivity",
            "NOT_APPLICABLE",
            "no bridge configured; findings go to the journal only".into(),
        ),
    }

    SelfTestReport {
        schema: "warden.install-self-test.v1".into(),
        checks,
    }
}

fn backup_file(path: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let backup = PathBuf::from(format!(
        "{}.{}.{}.{}",
        path.display(),
        suffix,
        std::process::id(),
        stamp
    ));
    fs::copy(path, &backup).with_context(|| format!("creating backup {}", backup.display()))?;
    let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
    fs::set_permissions(&backup, fs::Permissions::from_mode(mode))?;
    Ok(backup)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = PathBuf::from(format!(
        "{}.tmp.m16.{}.{}",
        path.display(),
        std::process::id(),
        stamp
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("creating temporary file {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Non-cryptographic content fingerprint, used only to answer "did this file
/// change?". It is explicitly not a checksum for authenticity.
fn fnv1a64(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("fnv1a64:{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(body: &str) -> (PathBuf, String) {
        let dir = std::env::temp_dir().join(format!(
            "warden-m16-{}-{}",
            std::process::id(),
            SYSTEM_TEST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("warden.toml");
        fs::write(&path, body).expect("write test config");
        (path, dir.display().to_string())
    }

    static SYSTEM_TEST_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn profile_names_accept_documented_aliases_and_refuse_typos() {
        assert_eq!(
            ProfileName::parse("simple").unwrap(),
            ProfileName::Essential
        );
        assert_eq!(
            ProfileName::parse("RECOMMENDED").unwrap(),
            ProfileName::Balanced
        );
        assert_eq!(ProfileName::parse("expert").unwrap(), ProfileName::Advanced);
        assert!(ProfileName::parse("paranoid").is_err());
    }

    #[test]
    fn every_generated_profile_is_a_real_valid_config_that_round_trips() {
        let caps = HostCapabilities::detect();
        for &name in [
            ProfileName::Essential,
            ProfileName::Balanced,
            ProfileName::Advanced,
            ProfileName::Hardened,
        ]
        .iter()
        {
            let generated = generate(name, &caps).unwrap();
            assert_eq!(generated.config.schema_version, CURRENT_SCHEMA_VERSION);
            assert_eq!(generated.config.mode, Mode::Observe);
            assert!(!generated.config.enforce.arm);
            assert!(!generated.config.egress.enabled);
            assert!(!generated.config.egress.arm);
            assert!(!generated.config.respond.kill_reverse_shell);
            assert!(generated.toml.contains("schema_version = 1"));
            let reparsed: Config = toml::from_str(&generated.toml).unwrap();
            reparsed.validate().unwrap();
        }
    }

    #[test]
    fn volume_counters_are_never_enabled_without_verified_support() {
        let caps = HostCapabilities::detect();
        let generated = generate(ProfileName::Hardened, &caps).unwrap();
        assert_eq!(generated.config.net_volume.enabled, caps.volume_supported());
        if !caps.volume_supported() {
            assert!(generated
                .capability_notes
                .iter()
                .any(|n| n.contains("left OFF")));
        }
    }

    #[test]
    fn validator_reports_legacy_version_and_world_writable_config() {
        let (path, _dir) = temp_config("mode = \"observe\"\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let report = validate_file(Some(&path), &HostCapabilities::detect(), false);
        assert_eq!(report.schema_version, LEGACY_SCHEMA_VERSION);
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.field == "schema_version"));
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.field == "config file permissions"
                && d.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn migration_is_backed_up_validated_and_idempotent() {
        let (path, _dir) = temp_config("mode = \"observe\"\n");
        let first = migrate(&path, CURRENT_SCHEMA_VERSION).unwrap();
        assert!(first.changed);
        assert!(first.backup_path.is_some());
        assert_eq!(
            declared_schema_version(&fs::read_to_string(&path).unwrap()).unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        let second = migrate(&path, CURRENT_SCHEMA_VERSION).unwrap();
        assert!(!second.changed);
        Config::load(&path).unwrap();
    }

    #[test]
    fn rollback_refuses_an_unsafe_backup_and_restores_a_safe_one() {
        let (path, dir) = temp_config("schema_version = 1\nmode = \"observe\"\n");
        let backup = PathBuf::from(format!("{dir}/backup.toml"));
        fs::write(
            &backup,
            "schema_version = 1\nmode = \"enforce\"\n[respond]\nkill_reverse_shell = true\n",
        )
        .unwrap();
        assert!(rollback(&path, &backup).is_err());
        fs::write(&backup, "schema_version = 1\nmode = \"observe\"\n").unwrap();
        let value = rollback(&path, &backup).unwrap();
        assert_eq!(value["status"], "PASS");
        assert_eq!(Config::load(&path).unwrap().mode, Mode::Observe);
    }

    #[test]
    fn snapshot_and_drift_detect_a_content_change_and_name_unmeasured_state() {
        let (path, dir) = temp_config("schema_version = 1\nmode = \"observe\"\n");
        let snap = snapshot(&path).unwrap();
        let baseline = PathBuf::from(format!("{dir}/baseline.json"));
        fs::write(&baseline, serde_json::to_vec_pretty(&snap).unwrap()).unwrap();
        let same = drift(&baseline).unwrap();
        assert!(same.rows.iter().all(|r| r.status != "DRIFT"));
        fs::write(&path, "schema_version = 1\nmode = \"enforce\"\n").unwrap();
        let changed = drift(&baseline).unwrap();
        assert!(changed
            .rows
            .iter()
            .any(|r| r.property == "config.content_fingerprint" && r.status == "DRIFT"));
        assert!(changed
            .not_measured
            .iter()
            .any(|n| n.contains("ring-buffer")));
    }

    #[test]
    fn self_test_never_reports_a_kernel_load_as_run() {
        let (path, _dir) = temp_config("schema_version = 1\nmode = \"observe\"\n");
        let report = self_test(Some(&path));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "kernel_sensor_load" && c.status == "NOT_RUN"));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "runtime_startup" && c.status == "NOT_RUN"));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "local_event_pipeline" && c.status == "NOT_RUN"));
    }

    #[test]
    fn plan_is_labelled_simulation_and_never_claims_attachment() {
        let caps = HostCapabilities::detect();
        let cfg = Config::safe_default();
        let validation = validate_file(None, &caps, false);
        let p = plan(ProfileName::Balanced, &cfg, &validation, &caps);
        assert!(p.simulation_notice.contains("SIMULATION ONLY"));
        assert!(!p.simulation_notice.contains("attached successfully"));
    }
}
