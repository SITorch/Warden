//! Phase 9 — the production resource envelope.
//!
//! `--check` is deliberately allowed to run without privileges, so it cannot
//! prove that systemd is actually enforcing anything. What it *can* do is make
//! the shipped contract explicit: these are the hard caps in
//! `systemd/warden.service`, and a config that claims a different envelope is a
//! config that `--check` has no business calling OK. Defaults reproduce the
//! unit exactly; changing a value here and in the unit together is a deliberate
//! deployment change, not a typo that silently widens the guardian's footprint.
//!
//! `--doctor` answers the other half from the kernel's own cgroup files. It
//! reports what it can see for the process running the command and says plainly
//! that this is not a measurement of the daemon unless the command was run in
//! the daemon's cgroup.

use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::doctor::State;

/// Hard caps in the shipped systemd unit. These are ceilings, not targets: the
/// daemon is expected to stay well under them.
pub const MEMORY_MAX_MB: u64 = 768;
pub const CPU_QUOTA_PERCENT: u32 = 200;
pub const TASKS_MAX: u32 = 128;
pub const OPEN_FILES_MAX: u32 = 4096;
pub const IO_WEIGHT: u32 = 20;

/// Declared ceilings that are still meaningful if an operator tightens them in
/// a drop-in. Values outside these ranges cannot correspond to a sane guardian.
pub const MIN_MEMORY_MAX_MB: u64 = 128;
pub const MAX_MEMORY_MAX_MB: u64 = 4096;
pub const MIN_CPU_QUOTA_PERCENT: u32 = 10;
pub const MAX_CPU_QUOTA_PERCENT: u32 = 800;
pub const MIN_TASKS_MAX: u32 = 32;
pub const MAX_TASKS_MAX: u32 = 1024;
pub const MIN_OPEN_FILES_MAX: u32 = 256;
pub const MAX_OPEN_FILES_MAX: u32 = 65_536;
pub const MIN_IO_WEIGHT: u32 = 1;
pub const MAX_IO_WEIGHT: u32 = 10_000;

/// The resource envelope asserted by `warden --check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceBudget {
    pub memory_max_mb: u64,
    pub cpu_quota_percent: u32,
    pub tasks_max: u32,
    pub open_files_max: u32,
    pub io_weight: u32,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            memory_max_mb: MEMORY_MAX_MB,
            cpu_quota_percent: CPU_QUOTA_PERCENT,
            tasks_max: TASKS_MAX,
            open_files_max: OPEN_FILES_MAX,
            io_weight: IO_WEIGHT,
        }
    }
}

impl ResourceBudget {
    /// Why this declaration cannot be verified against the shipped unit, or
    /// `None` when it matches.
    ///
    /// Equality with the unit values is deliberate. A config that says "512 MB"
    /// while the unit says 768 MB is not a tighter policy Warden enforces — it is
    /// a false statement in `--check`. A drop-in that really changes the cap must
    /// change the unit and these constants together.
    pub fn problem(&self) -> Option<String> {
        for (key, value, shipped, min, max) in [
            (
                "resources.memory_max_mb",
                self.memory_max_mb,
                MEMORY_MAX_MB,
                MIN_MEMORY_MAX_MB,
                MAX_MEMORY_MAX_MB,
            ),
            (
                "resources.cpu_quota_percent",
                self.cpu_quota_percent as u64,
                CPU_QUOTA_PERCENT as u64,
                MIN_CPU_QUOTA_PERCENT as u64,
                MAX_CPU_QUOTA_PERCENT as u64,
            ),
            (
                "resources.tasks_max",
                self.tasks_max as u64,
                TASKS_MAX as u64,
                MIN_TASKS_MAX as u64,
                MAX_TASKS_MAX as u64,
            ),
            (
                "resources.open_files_max",
                self.open_files_max as u64,
                OPEN_FILES_MAX as u64,
                MIN_OPEN_FILES_MAX as u64,
                MAX_OPEN_FILES_MAX as u64,
            ),
            (
                "resources.io_weight",
                self.io_weight as u64,
                IO_WEIGHT as u64,
                MIN_IO_WEIGHT as u64,
                MAX_IO_WEIGHT as u64,
            ),
        ] {
            if value < min || value > max {
                return Some(format!(
                    "{key} = {value} is outside the supported range [{min}, {max}]. \
                     These numbers describe the shipped systemd unit, not a \
                     tunable Warden applies at runtime."
                ));
            }
            if value != shipped {
                return Some(format!(
                    "{key} = {value} does not match the shipped unit's {shipped}. \
                     --check cannot verify a resource envelope it cannot see, so \
                     change this value and systemd/warden.service together (and \
                     restart deliberately), or restore the shipped value."
                ));
            }
        }
        None
    }

    /// The `--check` line. Policy only: no cgroup file is read here.
    pub fn check_line(&self) -> String {
        format!(
            "warden: resource budget: memory {mem} MiB, CPU {cpu}% of one CPU, \
             tasks {tasks}, open files {fds}, IO weight {io}. These are the hard \
             caps declared in [resources] and enforced by the shipped systemd \
             unit; warden --doctor reports what this host's cgroup exposes. \
             LimitMEMLOCK remains unlimited for older kernels' BPF map charging.",
            mem = self.memory_max_mb,
            cpu = self.cpu_quota_percent,
            tasks = self.tasks_max,
            fds = self.open_files_max,
            io = self.io_weight
        )
    }
}

/// One cgroup control file, read with the same three-state discipline as the
/// rest of `--doctor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupLimit {
    pub file: &'static str,
    pub state: State,
    pub value: String,
}

/// The set of limits plus the path the answer came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupReport {
    pub source: String,
    pub limits: Vec<CgroupLimit>,
}

/// Read a bounded amount from a cgroup control file. A pathological sysfs read
/// must not be able to grow `--doctor`'s memory without limit.
fn read_bounded(path: &str, max_bytes: usize) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = Vec::with_capacity(64);
    let mut chunk = [0u8; 512];
    loop {
        let n = file.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "cgroup control file exceeded the read ceiling",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Parse one control file's body. Kept separate from the filesystem walk so
/// every branch — including `max` and malformed numbers — is testable.
pub(crate) fn parse_limit(file: &'static str, body: &str) -> CgroupLimit {
    let body = body.trim();
    if body.is_empty() {
        return CgroupLimit {
            file,
            state: State::Unreadable,
            value: "empty file".to_string(),
        };
    }
    let value = match file {
        "memory.max" => {
            if body == "max" {
                "unlimited at this level".to_string()
            } else {
                match body.parse::<u64>() {
                    Ok(bytes) => format!("{} MiB", bytes / (1024 * 1024)),
                    Err(_) => {
                        return CgroupLimit {
                            file,
                            state: State::Unreadable,
                            value: "malformed byte count".to_string(),
                        }
                    }
                }
            }
        }
        "pids.max" => {
            if body == "max" {
                "unlimited at this level".to_string()
            } else {
                match body.parse::<u64>() {
                    Ok(n) => format!("{n} tasks"),
                    Err(_) => {
                        return CgroupLimit {
                            file,
                            state: State::Unreadable,
                            value: "malformed task count".to_string(),
                        }
                    }
                }
            }
        }
        "cpu.max" => {
            let mut parts = body.split_whitespace();
            let quota = parts.next().unwrap_or("");
            let period = parts.next().unwrap_or("");
            if parts.next().is_some() {
                return CgroupLimit {
                    file,
                    state: State::Unreadable,
                    value: "malformed cpu.max".to_string(),
                };
            }
            if quota == "max" {
                "unlimited at this level".to_string()
            } else {
                match (quota.parse::<u64>(), period.parse::<u64>()) {
                    (Ok(quota), Ok(period)) if period > 0 => format!(
                        "{}% of one CPU ({quota}/{period} per period)",
                        quota.saturating_mul(100) / period
                    ),
                    _ => {
                        return CgroupLimit {
                            file,
                            state: State::Unreadable,
                            value: "malformed cpu.max".to_string(),
                        }
                    }
                }
            }
        }
        _ => {
            return CgroupLimit {
                file,
                state: State::Unreadable,
                value: "unknown control file".to_string(),
            }
        }
    };
    CgroupLimit {
        file,
        state: State::Present,
        value,
    }
}

fn v2_path() -> Option<String> {
    let text = read_bounded("/proc/self/cgroup", 16 * 1024).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let path = rest.trim();
            if path.starts_with('/') {
                return Some(path.to_string());
            }
        }
    }
    None
}

/// What this process's cgroup actually exposes. Never claims to describe a
/// service that was not measured.
pub fn observed() -> CgroupReport {
    let relative = match v2_path() {
        Some(path) => path,
        None => {
            return CgroupReport {
                source: "/proc/self/cgroup (no cgroup v2 path)".to_string(),
                limits: ["memory.max", "pids.max", "cpu.max"]
                    .into_iter()
                    .map(|file| CgroupLimit {
                        file,
                        state: State::Unreadable,
                        value: "no cgroup v2 path".to_string(),
                    })
                    .collect(),
            }
        }
    };
    let base = if relative == "/" {
        "/sys/fs/cgroup".to_string()
    } else {
        format!("/sys/fs/cgroup{}", relative.trim_end_matches('/'))
    };
    let limits = ["memory.max", "pids.max", "cpu.max"]
        .into_iter()
        .map(|file| {
            let path = format!("{base}/{file}");
            match read_bounded(&path, 4096) {
                Ok(body) => parse_limit(file, &body),
                Err(err) => {
                    let state = State::from_open_error(&err);
                    CgroupLimit {
                        file,
                        state,
                        value: match state {
                            State::Absent => "not exposed".to_string(),
                            State::Unreadable => "could not read".to_string(),
                            State::Present => unreachable!(),
                        },
                    }
                }
            }
        })
        .collect();
    CgroupReport {
        source: format!("/proc/self/cgroup → {base}"),
        limits,
    }
}

/// The `--doctor` line for Phase 9. It reports the kernel's values for the
/// process running the command, never a guessed value for the daemon: an
/// operator who needs the service's numbers must run this in that cgroup.
pub fn doctor_line() -> String {
    let report = observed();
    let limits = report
        .limits
        .iter()
        .map(|limit| format!("{}={} ({})", limit.file, limit.state.word(), limit.value))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "warden: doctor: resource cgroup ({}): {}. Only memory.max, pids.max and cpu.max are \
         read here; open files and IO weight are declared in the shipped [resources] budget and \
         systemd unit but are NOT measured by --doctor. These are the kernel's values for the \
         process running --doctor, not a measurement of the warden service unless this command \
         was run inside that service's cgroup; a drop-in or an unmounted controller can make the \
         daemon's limits differ from these and from the shipped unit.",
        report.source, limits
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_budget_reproduces_the_shipped_unit() {
        let budget = ResourceBudget::default();
        assert!(budget.problem().is_none(), "{:?}", budget.problem());
        let line = budget.check_line();
        for needle in ["768 MiB", "200%", "128", "4096", "IO weight 20"] {
            assert!(line.contains(needle), "{needle} missing from {line}");
        }
        assert!(line.contains("LimitMEMLOCK remains unlimited"));
    }

    #[test]
    fn a_config_cannot_claim_a_different_resource_envelope() {
        let budget = ResourceBudget {
            memory_max_mb: 1024,
            ..ResourceBudget::default()
        };
        let problem = budget.problem().expect("drift must be refused");
        assert!(problem.contains("resources.memory_max_mb"));
        assert!(problem.contains("systemd/warden.service"));

        let budget = ResourceBudget {
            cpu_quota_percent: 4,
            ..ResourceBudget::default()
        };
        assert!(budget
            .problem()
            .unwrap()
            .contains("outside the supported range"));
    }

    #[test]
    fn cgroup_limits_use_three_states_and_never_guess() {
        let present = parse_limit("memory.max", "805306368\n");
        assert_eq!(present.state, State::Present);
        assert_eq!(present.value, "768 MiB");

        let unlimited = parse_limit("pids.max", "max\n");
        assert_eq!(unlimited.state, State::Present);
        assert!(unlimited.value.contains("unlimited"));

        let cpu = parse_limit("cpu.max", "200000 100000\n");
        assert_eq!(cpu.state, State::Present);
        assert!(cpu.value.contains("200%"));

        for (file, body) in [
            ("memory.max", "not-a-number\n"),
            ("pids.max", ""),
            ("cpu.max", "20\n"),
            ("cpu.max", "20 0\n"),
        ] {
            let limit = parse_limit(file, body);
            assert_eq!(limit.state, State::Unreadable, "{file}: {body:?}");
        }
    }

    #[test]
    fn the_observation_always_names_its_source_and_three_controls() {
        let report = observed();
        assert!(report.source.starts_with("/proc/self/cgroup"));
        assert_eq!(report.limits.len(), 3);
        for limit in &report.limits {
            assert!(matches!(limit.file, "memory.max" | "pids.max" | "cpu.max"));
            assert!(!limit.value.is_empty());
        }
    }

    #[test]
    fn the_doctor_line_never_claims_to_have_measured_the_daemon() {
        let line = doctor_line();
        assert!(line.contains("/proc/self/cgroup"));
        assert!(line.contains("memory.max="));
        assert!(line.contains("pids.max="));
        assert!(line.contains("cpu.max="));
        assert!(line.contains("Only memory.max, pids.max and cpu.max are read here"));
        assert!(line.contains("open files and IO weight"));
        assert!(line.contains("NOT measured by --doctor"));
        assert!(line.contains("not a measurement of the warden service"));
    }
}
