//! P0-1: the shipped systemd unit must be able to *fail loudly*, not only restart.
//!
//! The live shape this guards against: a host where `/etc/warden/warden.toml`
//! stopped satisfying `Config::validate`. The unit that shipped with the tree at
//! that commit carried `StartLimitIntervalSec=0` plus `Restart=always` and no
//! pre-start check, so the daemon was refused by its own config ~every two
//! seconds forever, the unit stayed in the `active`/`activating` band, and
//! `systemctl is-active warden` answered *yes* about a host with zero coverage.
//! Measured on the deployment host: 13,649 restarts since the first failure at
//! 10:20, no alert of any kind — because the only alert Warden ships
//! (`src/heartbeat.rs`) is a thread inside the process that never started.
//!
//! These tests are structural and unprivileged: they read the artefacts the
//! packaging installs, so they fail on a tree that has drifted from the shape
//! that makes the outage visible, and they cannot pass by asserting on a code
//! path that did not run. The behaviour itself — limiter trips, unit reaches
//! `failed`, the alert unit runs — is proven on a disposable VM (report §۷۱).

use std::path::PathBuf;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    let p = manifest_dir().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {rel}: {e}"))
}

/// One `(key, value)` pair per assignment in `section`, with `#` comment lines
/// dropped and `\`-continued values joined — systemd does both, and a parser
/// that does not join continuations would silently miss the `ExecStart` of a
/// unit that wraps its command across lines.
fn assignments(text: &str, section: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut in_section = false;
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            in_section = rest.trim_end_matches(']') == section;
            continue;
        }
        if !in_section {
            continue;
        }
        // Join `\` continuations before splitting on `=`, so a command wrapped
        // across lines is read as the one command systemd actually execs.
        let (logical, continued) = match trimmed.strip_suffix('\\') {
            Some(rest) => (rest.trim_end().to_string(), true),
            None => (trimmed.to_string(), false),
        };
        let logical = match pending.take() {
            Some(acc) => format!("{acc} {logical}"),
            None => logical,
        };
        if continued {
            pending = Some(logical);
            continue;
        }
        if let Some((k, v)) = logical.split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    assert!(
        pending.is_none(),
        "{section} ends inside a line continuation — the unit file is malformed."
    );
    out
}

/// Every line systemd would exec, in order, for a directive.
fn execs(text: &str, key: &str) -> Vec<String> {
    assignments(text, "Service")
        .into_iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v)
        .collect()
}

fn first_word(cmd: &str) -> &str {
    cmd.split_whitespace().next().unwrap_or("")
}

/// `-` / `@` prefixes that change how systemd treats a failure are stripped, so
/// an assertion about *which binary runs* is not fooled by `-/usr/bin/foo`.
fn executable(cmd: &str) -> &str {
    first_word(cmd).trim_start_matches(['-', '@', '+', ':'])
}

#[test]
fn the_unit_arms_a_start_limiter_in_the_unit_section() {
    let text = read("systemd/warden.service");
    let unit = assignments(&text, "Unit");
    let get = |k: &str| {
        unit.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };

    let interval = get("StartLimitIntervalSec").expect(
        "warden.service sets no StartLimitIntervalSec: the limiter is systemd-default armed, \
                 which is fine until someone reads the old comment here and sets it to 0 again",
    );
    let burst = get("StartLimitBurst").expect(
        "warden.service arms an interval but no burst: the default burst silently bounds what \
                 the test is trying to assert",
    );
    assert_ne!(
        interval.trim(),
        "0",
        "StartLimitIntervalSec=0 disables the limiter, so Restart=always can never reach `failed` \
         and no OnFailure= alert can ever fire. That is the exact shape that let a config-refusing \
         host restart-loop 13,649 times while reporting itself active."
    );
    assert_ne!(
        burst.trim(),
        "0",
        "StartLimitBurst=0 means no start is ever counted as a failure."
    );

    // Placement is part of the property: systemd logs "Unknown key … in section
    // [Service], ignoring" rather than refusing the unit, so a limiter written
    // under [Service] looks configured and is inert.
    let service = assignments(&text, "Service");
    for (k, _) in service {
        assert!(
            !k.starts_with("StartLimit"),
            "{k} is set under [Service] where systemd ignores it; StartLimit* belong in [Unit]."
        );
    }
}

#[test]
fn the_unit_checks_the_config_before_touching_the_kernel() {
    let text = read("systemd/warden.service");
    let pre = execs(&text, "ExecStartPre");
    let start = execs(&text, "ExecStart");
    assert!(
        !pre.is_empty(),
        "no ExecStartPre: a config Config::validate refuses is discovered by killing an attached \
         daemon mid-start instead of before anything is loaded. `warden --check` reads only the \
         file — no bpf(), no map, no attach — and exists for exactly this gate."
    );
    let check = pre
        .iter()
        .find(|c| c.contains("--check"))
        .expect("ExecStartPre does not run `--check`");
    assert!(
        executable(check).ends_with("/warden"),
        "the config gate must be Warden's own: {check}"
    );
    // Same file, same path, or the gate validates a config the daemon never
    // loads — the divergence the audit found for the SIGHUP path, in the
    // pre-start step instead.
    let cfg_of = |c: &str| {
        c.split("--config")
            .nth(1)
            .map(|rest| rest.split_whitespace().next().unwrap_or("").to_string())
    };
    assert!(!start.is_empty(), "warden.service has no ExecStart at all");
    let gate_cfg = cfg_of(check).unwrap_or_default();
    assert!(
        !gate_cfg.is_empty(),
        "the --check gate names no --config path, so it validates defaults rather than the deployed file: {check}"
    );
    for s in &start {
        assert_eq!(
            cfg_of(s).unwrap_or_default(),
            gate_cfg,
            "ExecStartPre validates {gate_cfg} but ExecStart loads a different file"
        );
    }
}

#[test]
fn entering_failed_has_an_alert_unit_that_ships() {
    let text = read("systemd/warden.service");
    let unit = assignments(&text, "Unit");
    let on_failure = unit
        .iter()
        .find(|(k, _)| k == "OnFailure")
        .map(|(_, v)| v.clone())
        .expect(
            "no OnFailure=: with the limiter armed the unit now DOES reach `failed`, and a terminal \
             state nobody watches is a coverage gap with better manners.",
        );

    // The target must be a real template in this package, not a name.
    let name = on_failure
        .trim_end_matches(".service")
        .strip_suffix("@%n")
        .or_else(|| {
            on_failure
                .trim_end_matches(".service")
                .strip_suffix("@warden")
        })
        .unwrap_or_else(|| panic!("unsupported OnFailure= shape: {on_failure}"));
    let rel = format!("systemd/{name}@.service");
    let alert = manifest_dir().join(&rel);
    assert!(
        alert.exists(),
        "OnFailure= names {on_failure} but {rel} is not in the package; systemd fails to start a \
         missing alert unit, which is the silent-failure class this change exists to end."
    );
    let alert_text = std::fs::read_to_string(alert).unwrap();

    let asvc = assignments(&alert_text, "Service");
    let type_line = asvc
        .iter()
        .find(|(k, _)| k == "Type")
        .map(|(_, v)| v.clone())
        .expect("the alert unit sets no Type=");
    assert_eq!(
        type_line, "oneshot",
        "the alert unit must be oneshot; a service that stays up is a second thing to monitor."
    );
    for (k, v) in &asvc {
        if k == "Restart" {
            panic!(
                "the alert unit sets Restart={v}: an alert that restarts is an outage of its own, \
                 and the daemon it is announcing is already dead."
            );
        }
    }

    // The announcer must not depend on the thing it announces: if the alert
    // shells out to the warden binary, a broken build takes both down.
    let alert_exec = execs(&alert_text, "ExecStart");
    assert!(
        !alert_exec.is_empty(),
        "{rel} has no ExecStart, so OnFailure= fires an empty unit."
    );
    for cmd in &alert_exec {
        assert!(
            !executable(cmd).ends_with("/warden"),
            "the alert unit execs the Warden binary ({cmd}). The failure it announces may be that \
             very binary failing to start; the announcer must not be able to inherit the breakage."
        );
    }
    assert!(
        alert_text.contains("%i") || alert_text.contains("%n"),
        "{rel} never names which unit failed — an alert that cannot say what died is not triageable."
    );
}

#[test]
fn packaging_installs_and_removes_both_units() {
    let makefile = read("Makefile");
    let install = makefile
        .split("uninstall:")
        .next()
        .expect("Makefile has no uninstall target");
    for unit in ["systemd/warden.service", "systemd/warden-deadman@.service"] {
        assert!(
            install.contains(&format!("install -m 0644 {unit}")),
            "Makefile `install` does not copy {unit}, so the OnFailure= dependency names a unit \
             that only exists in the git tree."
        );
    }
    let tail = makefile
        .split("uninstall:")
        .nth(1)
        .expect("Makefile has no uninstall body");
    let rm_line = tail
        .lines()
        .find(|l| l.trim_start().starts_with("rm -f"))
        .expect("uninstall removes nothing");
    for unit in ["warden.service", "warden-deadman@.service"] {
        assert!(
            rm_line.contains(unit),
            "`make uninstall` leaves $(UNITDIR)/{unit} behind — an orphaned OnFailure= target is a \
             stale alert path on a host that no longer runs Warden."
        );
    }
}

#[test]
fn the_unit_grants_the_capability_the_sensors_actually_need() {
    // The other half of the same outage: a unit that restart-loops is bad, a unit
    // that can never start is worse. `perf_event_open()` for a tracepoint or a
    // kprobe is gated on CAP_SYS_ADMIN while kernel.perf_event_paranoid > 1, and
    // CAP_PERFMON does not satisfy it — measured on Debian 13 / 6.12.107+deb13
    // (paranoid=3): with the four caps this file shipped until that measurement,
    // Warden died at attach #1 with EACCES; with CAP_SYS_ADMIN added, all 14
    // sensors plus the 6 BPF-LSM programs came up. Mainline's default knob value
    // is 2 and the deployment host reports 4, so this is not a hardened-host
    // exception — it is the ordinary case the least-privilege block has to cover.
    let text = read("systemd/warden.service");
    let svc = assignments(&text, "Service");
    let need = [
        "CAP_BPF",
        "CAP_PERFMON",
        "CAP_SYS_PTRACE",
        "CAP_KILL",
        "CAP_SYS_ADMIN",
    ];
    let mut seen = vec![];
    for key in ["AmbientCapabilities", "CapabilityBoundingSet"] {
        let line = svc
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| {
                panic!(
                    "{key} is not set: the unit claims a privilege ceiling it \
                                      does not define"
                )
            });
        seen.push(line.clone());
        for c in &need {
            assert!(
                line.split_whitespace().any(|w| w == *c),
                "{key} omits {c} — the sensors cannot attach without it on any host with \
                 perf_event_paranoid > 1: {line}"
            );
        }
    }
    assert_eq!(
        seen[0], seen[1],
        "AmbientCapabilities and CapabilityBoundingSet differ: whatever is in the bounding set \
         but not the ambient set is unavailable to the daemon, and whatever is ambient but not \
         bounding is silently dropped. Both lines must say the same set."
    );
}

#[test]
fn the_unit_declares_the_phase9_resource_envelope() {
    // A guardian with unbounded memory, CPU, tasks or descriptors is both a
    // single-host denial-of-service vector and an unreliable witness: the
    // process that is supposed to stay alive under load is the one the OOM
    // killer picks first. These are hard ceilings, duplicated in [resources]
    // and src/resources.rs; `--check` refuses a config that disagrees.
    let text = read("systemd/warden.service");
    let svc = assignments(&text, "Service");
    let get = |key: &str| {
        svc.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("warden.service sets no {key}"))
    };
    for (key, expected) in [
        ("MemoryMax", "768M"),
        ("CPUQuota", "200%"),
        ("TasksMax", "128"),
        ("LimitNOFILE", "4096"),
        ("IOWeight", "20"),
    ] {
        assert_eq!(
            get(key),
            expected,
            "{key} drifted from the Phase 9 envelope: --check would still print the shipped \
             values while the unit enforced something else"
        );
    }
    // The one deliberate exception to "cap everything" stays explicit: on the
    // lab's 6.12 kernel, BPF map charging hit memlock, so infinity is not an
    // oversight and must not be quietly tightened.
    assert_eq!(get("LimitMEMLOCK"), "infinity");
}

#[test]
fn the_unit_still_restarts_forever_within_the_limiter() {
    // Restart=always is what makes a takedown recoverable; the limiter bounds
    // how many times, it does not stop it. Assert both halves together so a
    // future edit cannot fix the silence by deleting the recovery.
    let text = read("systemd/warden.service");
    let svc = assignments(&text, "Service");
    assert_eq!(
        svc.iter()
            .find(|(k, _)| k == "Restart")
            .map(|(_, v)| v.clone())
            .as_deref(),
        Some("always"),
        "Restart must stay `always`: a security agent that does not come back after SIGKILL is \
         one signal away from permanent blindness."
    );
    assert_eq!(
        svc.iter()
            .find(|(k, _)| k == "Type")
            .map(|(_, v)| v.clone())
            .as_deref(),
        Some("simple"),
        "with ExecStartPre in the start path, Type=simple is what makes a pre-start refusal count \
         toward the limiter instead of hanging a unit that never reports ready."
    );
}
