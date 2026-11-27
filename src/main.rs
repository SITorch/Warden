//! main.rs — Warden: a host-level runtime security guardian.
//!
//! Pipeline: in-kernel eBPF sensors → ring buffer → decode → judge → (log +
//! optionally act + ship to Sentinel). A background heartbeat is the off-box
//! dead-man's-switch; SIGHUP reloads policy; SIGTERM/SIGINT exit cleanly.
//!
//! Run as root (or with CAP_BPF+CAP_PERFMON+CAP_SYS_PTRACE). Observe-only by
//! default — it never kills anything until an operator opts into enforce mode.

/// Deterministic arbitrary-input generator for the parser property tests
/// (W2K-17). Test-only: it exists so `cargo test` can feed the four parsers input
/// no hand-written case would think of, without pulling in a fuzzing crate that
/// an offline `--locked` build could not resolve.
#[cfg(test)]
mod arb;
mod bridge;
mod btf_compat;
mod c2;
mod config;
mod config_engine;
mod deliver;
mod detect;
mod doctor;
mod egress;
mod events;
mod explain;
mod guard;
mod health;
mod heartbeat;
mod hmac;
mod loader;
mod net_snap;
mod net_vol;
mod policy;
mod procscan;
mod resources;
mod respond;
mod telemetry;
mod tls;

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::config::{Config, Mode};
use crate::deliver::Deliverer;
use crate::detect::Detector;
use crate::events::RawEvent;
use crate::loader::Loaded;
use crate::respond::Responder;

/// How often we re-walk /proc to reconcile the protected-pid set. PIDs churn;
/// this keeps the kernel map honest without a per-event scan.
const PROTECT_REFRESH: Duration = Duration::from_secs(10);

// The volume tick is carried by the loop above, so the cadence the config report
// promises an operator is this period, not `interval_secs`. Live on the
// deployment host: `interval_secs = 5` produced ticks 10.0 s apart. Pinned at
// compile time so a change to the loop period fails the build rather than
// silently invalidating the claim in `net_vol::coverage_line`.
const _: () = assert!(
    PROTECT_REFRESH.as_secs() == crate::config::NET_VOLUME_TICK_GRANULARITY_SECS,
    "PROTECT_REFRESH must equal NET_VOLUME_TICK_GRANULARITY_SECS: the volume tick rides this loop, \
     and the journal line states the deliverable cadence in terms of it"
);

/// Coalescing window for duplicate journal lines (see `FindingLogThrottle`).
const LOG_THROTTLE_WINDOW: Duration = Duration::from_secs(10);

/// epoll_wait slice: short enough that shutdown + refresh + reload stay
/// responsive between events, long enough not to spin.
const POLL_SLICE_MS: i32 = 500;

fn main() -> anyhow::Result<()> {
    let args = Args::parse(std::env::args().skip(1))?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(if args.debug {
        "debug"
    } else {
        "info"
    }))
    .format_timestamp_millis()
    .init();

    // --version answers "which build am I looking at" — a question that has no
    // answer from a file's mtime or a package version alone on this tree. The
    // object digest is the half that identifies what the binary will actually load
    // (see `doctor::report` and §۵۱ of the report), and it is free to print, so it
    // goes here rather than only in `--doctor`. Needs no config file.
    if args.version {
        println!(
            "warden {} — eBPF object {} bytes (fnv-1a {:016x})",
            env!("CARGO_PKG_VERSION"),
            loader::obj_len(),
            loader::obj_fingerprint()
        );
        return Ok(());
    }

    // --health: what a RUNNING agent looks like from outside, read from /proc alone.
    // It is placed before the config load on purpose, for two reasons. First, the
    // question it answers is about the agent's config — the path its own argv names —
    // not about the file this command line points at, so loading ours would be a
    // second narrative (and a failure of our file would hide the answer). Second, it
    // must work on a host whose config is broken: an agent that was started with a
    // file that no longer parses is exactly the case this command exists to notice,
    // and a `--health` that died in `Config::load` would answer a question nobody
    // asked. It loads no kernel object and takes no privilege — see `health`'s module
    // doc for which claims that makes impossible, and the `cannot see/` lines it
    // prints instead of faking them.
    if args.health {
        if args.json {
            // One render pass, two formats: the JSON is parsed from the same
            // rendered lines the text view prints, so they cannot disagree.
            println!(
                "{}",
                serde_json::to_string_pretty(&health::report_json(args.config.as_ref()))?
            );
        } else {
            for line in health::report(args.config.as_ref()) {
                println!("{line}");
            }
        }
        return Ok(());
    }

    // ── M16 configuration engine operations ───────────────────────────────
    // Every branch below prints its answer and returns. They are placed before
    // the daemon's own Config::load because they answer questions *about* that
    // load (generate it, validate it, plan it, migrate it, watch it, restore
    // it) and must remain usable when the deployed file is broken.
    use config_engine::{
        drift, generate, migrate, plan, profile_docs, rollback, self_test, snapshot, validate_file,
        HostCapabilities, ProfileName,
    };

    if args.profile_list {
        let docs = profile_docs();
        if args.config_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": "warden.profile-catalog.v1",
                    "profiles": docs,
                }))?
            );
        } else {
            for doc in &docs {
                println!("warden: profile: {} — {}", doc.name, doc.summary);
                println!("  enabled: {}", doc.enabled_features.join(", "));
                println!("  disabled: {}", doc.disabled_features.join(", "));
                println!(
                    "  required capabilities: {}",
                    doc.required_capabilities.join(", ")
                );
                println!("  privileges: {}", doc.privilege_requirements);
                println!("  resources: {}", doc.resource_implications);
                println!("  risks: {}", doc.operational_risks);
                println!("  enforcement: {}", doc.enforcement_behavior);
                println!("  degradation: {}", doc.degradation_behavior);
                println!("  use cases: {}", doc.recommended_use_cases);
            }
        }
        return Ok(());
    }

    if let Some(requested) = &args.profile {
        let chosen = ProfileName::parse(requested)?;
        let caps = HostCapabilities::detect();
        if chosen == ProfileName::Custom {
            let path = args.config.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--profile custom validates an existing file: also pass --config PATH"
                )
            })?;
            let report = validate_file(Some(path), &caps, false);
            if args.config_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("warden: custom profile: {}", report.status);
                for d in &report.diagnostics {
                    println!(
                        "  {} {} — {}; fix: {}",
                        d.severity.word(),
                        d.field,
                        d.problem,
                        d.suggested_correction
                    );
                }
            }
            if report.status == "FAIL" {
                anyhow::bail!("custom profile validation failed");
            }
            return Ok(());
        }
        let generated = generate(chosen, &caps)?;
        if args.config_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": "warden.profile.v1",
                    "host_capabilities": caps,
                    "generated": generated,
                }))?
            );
        } else {
            println!("# warden profile: {}", generated.profile.word());
            for note in &generated.capability_notes {
                println!("# {note}");
            }
            println!(
                "# capability summary: {}",
                caps.capabilities
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.state.word()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "# Save this output to warden.toml, then: warden --check --strict --config PATH"
            );
            print!("{}", generated.toml);
        }
        return Ok(());
    }

    if args.config_validate {
        let caps = HostCapabilities::detect();
        let report = validate_file(args.config.as_deref(), &caps, args.strict);
        if args.config_json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("warden: config validation: {}", report.status);
            if let Some(path) = &report.config_path {
                println!("warden: config file: {path}");
            }
            for d in &report.diagnostics {
                println!(
                    "warden: {} {}: {} — security consequence: {}; correction: {}",
                    d.severity.word(),
                    d.field,
                    d.problem,
                    d.security_consequence,
                    d.suggested_correction
                );
            }
            for note in &report.capability_notes {
                println!("warden: note: {note}");
            }
        }
        if report.status == "FAIL" {
            anyhow::bail!("configuration validation failed");
        }
        return Ok(());
    }

    if args.config_plan {
        let caps = HostCapabilities::detect();
        let profile = ProfileName::Custom;
        let cfg = match &args.config {
            Some(p) => {
                Config::load(p).with_context(|| format!("loading config {}", p.display()))?
            }
            None => Config::safe_default(),
        };
        let report = validate_file(args.config.as_deref(), &caps, false);
        let simulation = plan(profile, &cfg, &report, &caps);
        if args.config_json {
            println!("{}", serde_json::to_string_pretty(&simulation)?);
        } else {
            println!("warden: config plan: {}", simulation.status);
            println!("warden: {}", simulation.simulation_notice);
            for section in [
                ("changes", &simulation.changes),
                ("enabled", &simulation.enabled_sensors),
                ("disabled", &simulation.disabled_sensors),
                ("privileges", &simulation.required_privileges),
                ("capabilities", &simulation.required_capabilities),
                ("risks", &simulation.operational_risks),
                ("service", &simulation.service_actions),
                ("policy", &simulation.policy_changes),
            ] {
                println!("warden: plan {}:", section.0);
                for item in section.1 {
                    println!("  - {item}");
                }
            }
        }
        return Ok(());
    }

    if args.config_migrate {
        let path = args
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--config-migrate needs --config PATH"))?;
        let report = migrate(
            path,
            args.target_version.expect("parser requires target version"),
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if let Some(path) = &args.config_baseline {
        let config_path = args
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--config-baseline needs --config PATH"))?;
        let state = snapshot(config_path)?;
        std::fs::write(path, serde_json::to_vec_pretty(&state)?)
            .with_context(|| format!("writing baseline {}", path.display()))?;
        println!(
            "warden: baseline written to {} (schema {})",
            path.display(),
            state.schema
        );
        println!("warden: secret-free: content fingerprint, mode, schema version, host capabilities and service state only");
        return Ok(());
    }

    if let Some(baseline) = &args.config_drift {
        let report = drift(baseline)?;
        if args.config_json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("warden: config drift report: {}", report.config_path);
            for row in &report.rows {
                println!(
                    "warden: {}: {} — desired={}, observed={}",
                    row.status, row.property, row.desired, row.configured_or_observed
                );
            }
            for item in &report.not_measured {
                println!("warden: NOT MEASURED: {item}");
            }
        }
        return Ok(());
    }

    if args.config_rollback {
        let target = args
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--config-rollback needs --config TARGET_PATH"))?;
        let backup = args.from.as_ref().expect("parser requires --from");
        let result = rollback(target, backup)?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        match std::env::current_exe() {
            Ok(exe) => {
                let check = std::process::Command::new(exe)
                    .args(["--check", "--strict", "--config"])
                    .arg(target)
                    .output();
                match check {
                    Ok(out) if out.status.success() => println!("warden: post-rollback health check: PASS (warden --check --strict)"),
                    Ok(out) => {
                        println!("warden: post-rollback health check: FAIL (warden --check --strict)");
                        eprint!("{}", String::from_utf8_lossy(&out.stderr));
                        anyhow::bail!("post-rollback health check failed; safety backup retained");
                    }
                    Err(e) => println!("warden: post-rollback health check: UNKNOWN ({e}); run `warden --check --strict --config {}`", target.display()),
                }
            }
            Err(e) => println!("warden: post-rollback health check: UNKNOWN ({e})"),
        }
        return Ok(());
    }

    if args.self_test {
        let report = self_test(args.config.as_deref());
        if args.config_json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            println!("warden: installation self-test (read-only)");
            for check in &report.checks {
                println!(
                    "warden: {}: {} — {}",
                    check.status, check.name, check.detail
                );
            }
        }
        if report.checks.iter().any(|c| c.status == "FAIL") {
            anyhow::bail!("installation self-test reported one or more failures");
        }
        return Ok(());
    }

    let cfg = match &args.config {
        Some(p) => Config::load(p).with_context(|| format!("loading config {}", p.display()))?,
        None => {
            log::warn!("no --config given; using safe observe-only defaults");
            Config::safe_default()
        }
    };
    // W2K-23: whatever the file contains that this binary cannot read must be in the
    // journal, not just in a `--check` the operator may never have run.
    log_unread_keys(&cfg);

    // Operator replay of refused findings. The dead-letter file is 0600 and
    // never silently truncated; the spool append is what makes the next start
    // deliver the original envelope with its original event id. Refuse to run
    // while the service is up — its sender holds the spool file handle and an
    // in-memory image of the file, which an external append would desync.
    if args.replay_quarantine {
        let Some(bridge) = cfg.bridge.as_ref() else {
            println!("warden: no [bridge] configured — there is nothing to replay");
            return Ok(());
        };
        let dead = deliver::quarantine_path(bridge);
        if !dead.exists() {
            println!(
                "warden: no dead-letter file at {} — nothing to replay",
                dead.display()
            );
            return Ok(());
        }
        if std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "warden"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            anyhow::bail!(
                "warden is running: stop it first (systemctl stop warden) — the sender holds \
                 the spool open and an external append would desync its in-memory image"
            );
        }
        let (replayed, skipped) = deliver::replay_quarantine(&bridge.spool_path, &dead)?;
        println!(
            "warden: replay queued {replayed} finding(s) for delivery on next start; \
             {skipped} skipped; dead-letter file archived with a .replayed.<ts> suffix"
        );
        return Ok(());
    }

    // --explain: the dry run. It needs the config (that is the whole question) and
    // nothing else: no kernel, no `/proc` of the actor it is asked about, no map,
    // no privilege. The answer comes from the same `Detector::judge` the event loop
    // calls, so this command cannot state a rule the agent does not follow.
    if let Some(kind) = &args.explain {
        let req = explain::Request::parse(kind, &args.event)
            .with_context(|| format!("explaining a {kind} event"))?;
        for line in explain::run(&cfg, &req)? {
            println!("{line}");
        }
        return Ok(());
    }

    // --socket-snapshot: run the pull path once and exit. This exists because the
    // pull path is the only part of Warden that needs no privilege at all — it
    // reads a world-readable file — so it is also the only part whose live
    // behaviour an operator can prove on a host without starting the agent,
    // loading a kernel object, or touching the running service. The report it
    // prints is byte-for-byte what the periodic tick would write to the journal.
    if args.socket_snapshot {
        let policy = &cfg.network_snapshot;
        println!("{}", net_snap::coverage_line(policy));
        if !policy.enabled {
            // Said explicitly, because the alternative is an operator reading a
            // one-off snapshot as evidence about a reconciler that never runs.
            println!("warden: this snapshot was taken on demand; the periodic reconciler is OFF");
        }
        let mut snap = net_snap::Reconciler::new(policy);
        let (report, notes) = snap.tick(policy, Instant::now());
        for note in notes {
            println!("warden: {note}");
        }
        for line in report.lines(policy) {
            println!("warden: {line}");
        }
        return Ok(());
    }

    // W2K-28: the transport gate that a host NAME could walk around. `validate()`
    // refuses cleartext HTTP to a publicly routable IP literal but cannot classify a
    // name without asking DNS, so this asks — once per configured uplink name, on a
    // helper thread with a 2 s deadline — and makes the same refusal about the
    // answer. It sits down here, after --health, --explain and --socket-snapshot have
    // returned, because those three promise to read nothing but the config file and
    // this does reach the resolver. The call is shared by the --check path and the
    // daemon path, so ExecStartPre and the process cannot disagree about whether this
    // uplink is allowed to start.
    let uplink_notes = config::resolve_uplink_names(&cfg, config::lookup_uplink_host)
        .with_context(|| "uplink identity")?;

    // --check: validate config + toolchain wiring and exit, without touching the
    // kernel. Useful in CI and as a systemd ExecStartPre sanity gate.
    // --doctor: everything --check prints, plus the host facts --check will not
    // claim. The split is deliberate: `--check` is safe to run anywhere because it
    // changes nothing — it reads the config file and, for a NAME uplink, one bounded
    // resolver answer (W2K-28) — and the lines it prints therefore hedge about the
    // kernel (`net_vol::coverage_line` says the hooks are "unknown here"). `--doctor`
    // reads /proc and /sys — world-readable files, no bpf() syscall, no load — to
    // answer the part `--check` cannot. The policy lines below are shared verbatim
    // so the two commands can never print different accounts of the same config.
    if args.check || args.doctor {
        println!("warden: config OK (mode={:?})", cfg.mode);
        // W2K-23 first, because it colours everything printed after it: a key Warden
        // never read means the policy below is what the agent RUNS on, which may not
        // be what the operator wrote. The typical live shape is a bridge key landing
        // under [respond] — the deploy script appends its own [bridge] table at the
        // end of the file, so the sample's commented block belongs to the previous
        // section as far as TOML is concerned.
        if !cfg.unread_keys.is_empty() {
            println!(
                "warden: WARNING: {} config key(s) in this file are not read by Warden: {}. \
                 A key that no field of its section declares is dropped in silence — the value \
                 in effect is Warden's default, not the one written. Check the section the key \
                 is really under (a table written by a deploy marker block can leave the \
                 sample's keys orphaned in the section before it).",
                cfg.unread_keys.len(),
                cfg.unread_keys.join(", ")
            );
        }
        // CI / deploy gate: make the same audit fatal. The warning above still
        // prints first so the operator sees the evidence in the log either way.
        if args.strict {
            enforce_strict_config(&cfg)?;
        }
        println!(
            "warden: embedded bpf object present ({} bytes)",
            loader::obj_len()
        );
        // W2K-13: the ring is a map-creation parameter, so `--check` — which never
        // touches the kernel — reports the arithmetic instead: what policy asks
        // for, and what this host's page size would make of it. `validate` has
        // already refused a request the kernel would resize.
        let page = config::page_size();
        println!(
            "warden: events ring: {} KiB requested, {} KiB on this host's {page}-byte pages",
            cfg.runtime.ring_size_kib,
            cfg.runtime.effective_ring_bytes(page) / 1024
        );
        // Phase 9: a declaration about the shipped unit, not a measurement.
        // `validate()` has already refused a value that disagrees with the unit,
        // and `--doctor` below reports the kernel's own cgroup controls instead.
        println!("{}", cfg.resources.check_line());
        // Coverage, from policy alone — the kernel is never touched here. Both
        // network axes judge only inside the app cgroup by default, so an empty
        // `[app].cgroup_contains` means the connect and listen sensors still emit
        // records and the detector still throws them away. "Quiet" and "off" look
        // identical from the journal, which is why the sanity gate has to say which
        // one it is before the service starts.
        let app_named = !cfg.app.cgroup_contains.is_empty();
        let egress_judged = app_named || !cfg.network_rules.app_egress_only;
        let listeners_judged = app_named || !cfg.listen_rules.app_listen_only;
        println!(
            "warden: network coverage: egress={}, listeners={} (app cgroup matchers: {})",
            if egress_judged { "judged" } else { "OFF" },
            if listeners_judged { "judged" } else { "OFF" },
            cfg.app.cgroup_contains.len()
        );
        if !egress_judged || !listeners_judged {
            println!(
                "warden: WARNING: {} judge only the app cgroup and `[app].cgroup_contains` is \
                 empty, so every CONNECT/LISTEN record is dropped after being read. Name the \
                 app cgroup, or set the flag to false to police the whole host.",
                if !egress_judged && !listeners_judged {
                    "[network_rules].app_egress_only and [listen_rules].app_listen_only"
                } else if !egress_judged {
                    "[network_rules].app_egress_only"
                } else {
                    "[listen_rules].app_listen_only"
                }
            );
        }
        // W2K-18: a comm is settable from inside any process with
        // prctl(PR_SET_NAME), so it can no longer authorize an implant-capable eBPF
        // load. What `allow_loader_exes` empty means is that NOTHING on this host is
        // authorized by identity — every load whose executable could be read is a
        // finding, and only the exited-loader case falls back to the name list. An
        // operator who expects a sanctioned tracer must pin its path, so the gate says
        // which side of that line the config is on.
        if cfg.bpf_rules.allow_loader_exes.is_empty() && !cfg.bpf_rules.allow_loaders.is_empty() {
            println!(
                "warden: bpf loader authorization: allow_loader_exes is empty, so no loader is \
                 authorized by executable identity; a readable-exe implant-capable load always \
                 fires, and [bpf_rules].allow_loaders ({:?}) only carries loads whose \
                 /proc/<pid>/exe could not be read (the loader already exited). Pin the \
                 sanctioned paths to authorize by identity.",
                cfg.bpf_rules.allow_loaders
            );
        }
        // W2K-30: the two suppressors that still have a name in the decision. A comm
        // is settable from inside any process with prctl(PR_SET_NAME), so since this
        // stage a name clears a finding only when the executable Warden read is the
        // binary that name belongs to — which leaves exactly one case where these
        // lists carry weight by themselves: `/proc/<pid>/exe` could not be read. Say
        // which lists those are, because an operator leaning on a name is holding a
        // hole open and should know its size.
        if !cfg.cred_rules.expected_privilege_comms.is_empty()
            || !cfg.ptrace_rules.benign_reader_comms.is_empty()
        {
            println!(
                "warden: name-only suppression: [cred_rules].expected_privilege_comms {:?} and \
                 [ptrace_rules].benign_reader_comms {:?} clear a privilege raise or a READ-mode \
                 ptrace only when /proc/<pid>/exe agrees with the name or could not be read; pin \
                 [cred_rules].expected_privilege_exes / [ptrace_rules].benign_reader_exes to \
                 authorize by identity.",
                cfg.cred_rules.expected_privilege_comms, cfg.ptrace_rules.benign_reader_comms
            );
        }
        // The verdict sensor's coverage is not a policy question — it is a property of
        // how clients dial, measured on the deployment kernel. In a 60-second live
        // sample, 116 of 128 stream connects returned -EINPROGRESS: a non-blocking dial
        // still in flight, which has no outcome to report. The other legitimate absence
        // is structural: the verdict probe sits on __inet_stream_connect, so a datagram
        // dial — CONNECT-recorded, since security_socket_connect sees both — never
        // reaches it at all. An operator who then sees fewer verdicts than dials must be
        // able to tell "expected shape" from "sensor lost records", so the gate names the
        // rule before the service starts.
        println!(
            "warden: egress verdicts: emitted only for a TERMINAL stream connect(); a \
             non-blocking dial (what every connect-with-a-timeout client does) has no outcome \
             yet and a datagram dial never reaches the verdict probe, so fewer verdicts than \
             dials is the normal shape, not a lost sensor"
        );
        // The accept sensor's coverage has the same shape: three absences that are
        // properties of the hook, not losses. Measured on the deployment kernel, 157
        // of 4008 inet_accept() returns in sampled production traffic were -EAGAIN —
        // a non-blocking accept with nothing queued, which took no connection and so
        // has no flow to report. A datagram socket has no accept at all, and the
        // record is a transition: it says a flow existed at an instant and names its
        // actor, never how long it lasted or how much it moved. Saying so at the gate
        // is what stops "no flow records" from reading as "no connections".
        println!(
            "warden: inbound flows: emitted only for an accept() that returned 0; an -EAGAIN \
             poll with nothing queued, and any datagram socket (there is no accept on one), \
             produce no record — and a FLOW record covers the moment of acceptance only, \
             never the close, so it cannot report a flow's duration or volume"
        );
        // The other silent posture switch: an empty destination allowlist is the
        // strictest one (any app egress is a finding), which is right for a worker
        // that should never dial out — but an operator who meant "allow the
        // datastores" and left it blank will get a finding per backing-service
        // connection, so name the count rather than let it be discovered by volume.
        if cfg.network_rules.egress_allow.is_empty() && cfg.network_rules.allow_ports.is_empty() {
            println!(
                "warden: egress policy: no `[network_rules].egress_allow` entries and no \
                 `allow_ports`, so any app dial-out{} is a finding",
                if cfg.network_rules.allow_loopback {
                    " outside loopback"
                } else {
                    ", loopback included"
                }
            );
        }
        // The pull path's own coverage line, from policy only — `--check` does not
        // read /proc/net, and does not need to: the fact worth printing before the
        // service starts is that a pull-less Warden cannot see a socket that was
        // already open when it attached. N-03/N-11 in the report.
        println!("{}", net_snap::coverage_line(&cfg.network_snapshot));
        // N-05: the cumulative counters' line, from policy only, and explicitly
        // without hook status. `--check` never touches the kernel, so it cannot
        // know whether `fexit/tcp_cleanup_rbuf` attached — and `coverage_line`
        // says exactly that instead of implying the totals would be kept. Passing
        // `None` is the whole point: a pre-start check that claimed "3 hooks
        // attached" would be a fabricated reading of a map it never opened.
        println!("{}", net_vol::coverage_line(&cfg.net_volume, None));
        // W2K-19: the transport's trusted-path claim, printed from policy. Validating
        // has already refused a publicly routable IP literal unless the operator
        // attested the path, so what remains to say is which side of the line each
        // configured uplink is on. W2K-28 adds the answer for the case that could
        // only be hedged before: a host NAME now gets exactly one lookup above,
        // before this block, and the lines below are what it said — refused if the
        // address is publicly routable, reported with its class if it answered.
        println!("{}", config::uplink_constraint_line(&cfg));
        for note in &uplink_notes {
            println!("{note}");
        }
        // The bridge is validated here too, and not only its URL: `--check` runs
        // as systemd's ExecStartPre, and the point of it is to fail before the
        // service starts rather than after. An unopenable spool is exactly the
        // kind of misconfiguration that would otherwise only be discovered by a
        // finding that could not be stored.
        match cfg.bridge.as_ref() {
            Some(b) => println!("warden: bridge OK — {}", deliver::check(b)?),
            None => println!("warden: bridge not configured (findings go to the journal only)"),
        }
        if args.doctor {
            // Printed after the policy lines because they are the hedged ones: the
            // operator reads "the hooks are unknown here" and then the host answer.
            for line in doctor::report() {
                println!("{line}");
            }
        }
        return Ok(());
    }

    // W2K-28: what the uplink's address actually is, in the journal rather than
    // only in a `--check` the operator may never have run — the same reason
    // W2K-23 logs unread keys here. Empty for an uplink written as an IP literal,
    // which `validate()` already judged without needing a resolver.
    for note in &uplink_notes {
        log::warn!("{note}");
    }

    log::info!(
        "warden starting: mode={:?}, protect_self={}, bridge={}, heartbeat={}",
        cfg.mode,
        cfg.protect.protect_self,
        cfg.bridge.is_some(),
        cfg.heartbeat.is_some(),
    );
    if cfg.mode == Mode::Enforce {
        log::warn!(
            "ENFORCE mode: kill_reverse_shell={}, kill_takedown_attacker={}, kill_privilege_escalation={}, kill_ransomware={}, require_anchored_identity={} ({})",
            cfg.respond.kill_reverse_shell,
            cfg.respond.kill_takedown_attacker,
            cfg.respond.kill_privilege_escalation,
            cfg.respond.kill_ransomware,
            cfg.respond.require_anchored_identity,
            if cfg.respond.require_anchored_identity {
                "a kill whose target the event cannot anchor is WITHHELD"
            } else {
                "W2K-25 opt-in: an unanchored target is still signalled, by choice"
            }
        );
    }
    // Phase 3: state the network policy posture out loud at startup. A deny
    // rule is a decision in this build, not a firewall: the summary says so
    // even when mode=enforce, so no reader can mistake a rule for protection.
    log::info!(
        "{}",
        policy::PolicyPosture::new(cfg.mode, cfg.network_rules.deny_destinations.len()).summary()
    );
    warn_if_peer_instance();

    run(cfg, args).context("warden event loop")
}

/// W2K-43: another Warden already on this host is the one producer of findings
/// that needs no attacker. Both agents enrich their signal/ptrace records from
/// /proc, both protect themselves, so each one's reads arrive at the other as
/// activity at a protected pid — measured on the lab VM at ~166 records/s with
/// 26.5% of the kernel ring dropped. Say it at startup, before the records
/// start arriving, rather than leaving it to be inferred from a flood.
///
/// This only says. Which of the two instances folds, stands down, or is refused
/// is the operator's call, and nothing here changes either agent's policy. The
/// observer's own kind is measured rather than assumed, in
/// [`procscan::peer_warning`]: by the time this runs the ask-and-exit modes have
/// all returned, so it answers `true` here — and it keeps answering correctly
/// for any mode added later that reaches `run()`.
fn warn_if_peer_instance() {
    if let Some(notice) = procscan::peer_warning(&procscan::peer_instances()) {
        log::warn!("{notice}");
    }
}

/// With no app cgroup there is no way to tell "the application" from an admin
/// session, so every app-attributed detector stays silent by design. That is a
/// safe default on a dev box and a blind default on a server: the install looks
/// healthy while shell, egress, privilege-change, listener and file-burst
/// findings can never fire. Say so at startup instead of leaving it to be
/// inferred from an empty sample config.
fn warn_if_no_app_cgroup(cfg: &Config) {
    if cfg.app.cgroup_contains.iter().any(|n| !n.trim().is_empty()) {
        return;
    }
    log::warn!(
        "[app].cgroup_contains is empty — shell-in-app, egress, privilege-change, \
         listener and file-burst findings cannot be attributed to the application and \
         will NOT fire. Active detections are limited to deleted-exe executions, \
         signal/ptrace at protected pids, module/BPF loads, watched mounts, and \
         persistence creation. Set [app].cgroup_contains (e.g. [\"app.service\"]) to \
         enable the app-scoped detectors."
    );
}

fn run(cfg: Config, args: Args) -> anyhow::Result<()> {
    // Raise the memlock rlimit — older kernels charge BPF maps against it.
    bump_memlock();

    // Signals: SIGTERM/SIGINT → shutdown; SIGHUP → policy reload.
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, reload.clone())?;

    // Load + attach the kernel sensors. The ring's capacity is a map-creation
    // parameter, so policy has exactly one moment to name it: here.
    let egress_attach = cfg
        .egress
        .cgroup_path
        .as_deref()
        .filter(|_| cfg.egress.enabled)
        .map(|p| (p, cfg.egress.arm));
    let mut loaded = Loaded::attach(cfg.runtime.ring_bytes(), egress_attach)
        .context("attaching eBPF sensors")?;
    // W2K-13: report the capacity the kernel actually built, because every drop
    // number below is a fraction of it. A size that disagrees with policy means
    // the request was rounded — validation is supposed to make that impossible,
    // so it is a warning rather than a footnote.
    match loaded.ring_capacity_bytes {
        Some(actual) if actual != cfg.runtime.ring_bytes() => log::warn!(
            "events ring is {} bytes although [runtime].ring_size_kib = {} asks for {}; the \
             drop counters are measured against the ring the kernel built, not the one \
             policy named.",
            actual,
            cfg.runtime.ring_size_kib,
            cfg.runtime.ring_bytes()
        ),
        Some(actual) => log::info!("events ring buffer: {} KiB", actual / 1024),
        None => log::info!(
            "events ring buffer: {} KiB requested (kernel capacity unreadable)",
            cfg.runtime.ring_bytes() / 1024
        ),
    }
    log::info!("eBPF sensors attached (exec, task_kill, ptrace, connect, connect_result, accept_flow, commit_creds, module_load, inode_rename, inode_unlink, inode_create, socket_listen, bpf, sb_mount)");
    if loaded.lsm_attached {
        log::info!("BPF-LSM enforcing programs attached (file_open, file_permission, mmap_file, inode_unlink, inode_rename, inode_setattr)");
    } else {
        log::warn!(
            "BPF-LSM enforcing programs NOT attached — running detection-only. \
             The guarded-files policy will be resolved and logged but nothing is \
             denied in-kernel. Enable the `bpf` LSM (add it to the boot `lsm=` list \
             and reboot) to arm enforcement."
        );
    }

    // Seed the sensor emit gates and the protected set from policy.
    loaded.set_exec_emit(true)?;
    loaded.set_connect_emit(true)?;
    // The dial's VERDICT (N-02), gated separately from the dial itself. Its coverage
    // is deliberately narrower than CONNECT's and the reason is measured, not
    // assumed: in a 60-second production sample on the deployment kernel, 116 of 128
    // stream connects returned -EINPROGRESS — the non-blocking shape every
    // "connect with a timeout" client uses (Python's `settimeout` among them). An
    // in-flight dial has no outcome yet, so the kernel emits a record only for a
    // terminal return. Most egress therefore has a where without a what-happened, and
    // the periodic `ringbuf: clean` line prints the verdict/dial ratio so the gap is
    // declared rather than papered over. See docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md §42 for the probe
    // and its tables.
    loaded.set_connect_result_emit(true)?;
    // The INBOUND half of the flow picture (N-03 accept, N-04, N-12): who accepted
    // whom. On by default even though it is the highest-volume sensor in the set —
    // ≈3.9 accepts/s measured on the deployment host in a quiet window, roughly 30×
    // the dial rate — because that rate is the point of the record, and the two
    // things that make it safe are already in place: it produces no finding at all
    // (`Detector::judge` returns None for `Kind::Flow`, so it cannot flood the
    // spool), and the kernel's per-sensor submit/drop counters report what it cost
    // and what the ring refused. An operator who wants it quiet during a busy
    // deploy flips one map slot via `Loaded::set_flow_emit`, no detach.
    loaded.set_flow_emit(true)?;
    // The CUMULATIVE network counters (N-05). Seeded from policy rather than
    // forced on like every gate above, because these three programs sit on the
    // send and receive path of every socket on the host: whether the box pays that
    // cost for totals nobody has asked to read yet is an operator's decision, not
    // Warden's. When it is off the programs stay attached and return immediately,
    // and the coverage line says the volume question is unanswerable — off is a
    // stated state here, not a silence.
    loaded.set_net_volume_emit(cfg.net_volume.enabled)?;
    // W2K-31: the value this write left in `CFG_NET_VOLUME_EMIT`. The reload path
    // compares against THIS and not against `cfg.net_volume.enabled`, because `cfg`
    // is deliberately never replaced (it keeps holding what the threads at boot were
    // started with — see the reload block). An operator who flips the gate off and
    // back on across two reloads would otherwise be told "unchanged" on the second
    // one while the kernel stayed muted and the tick reported totals that had
    // stopped moving.
    let mut volume_emit = cfg.net_volume.enabled;
    loaded.set_module_emit(true)?;
    loaded.set_file_emit(true)?;
    loaded.set_service_emit(true)?;
    loaded.set_listen_emit(true)?;
    loaded.set_bpf_emit(true)?;
    loaded.set_mount_emit(true)?;
    // The enforcing layer's two gates. Access records always emit (the shadow
    // stream is the whole point pre-arming); the arm gate follows policy and fails
    // CLOSED to shadow in the kernel, so `enforce.arm=false` (the default) logs
    // would-denies without blocking. Arming is the deliberate, config-driven flip.
    loaded.set_access_emit(true)?;
    loaded.set_enforce_arm(cfg.enforce.arm)?;

    // Phase 7: seed the egress arm gate and install the exact deny rules. Both
    // are gated on `[egress].enabled`: with it off, no hook is attached, the arm
    // slot stays 0 and no rule is written. The arm write is read back from the
    // kernel before the state is reported, so a failed write cannot leave a
    // config that says "armed" while the map says SHADOW.
    if cfg.egress.enabled {
        loaded.set_egress_arm(cfg.egress.arm)?;
        let confirmed = loaded.egress_armed()?;
        loaded.egress_runtime.armed = confirmed;
        if confirmed != cfg.egress.arm {
            log::warn!(
                "egress arm read back {} after writing {}; the kernel's value is authoritative",
                confirmed,
                cfg.egress.arm
            );
        }
        let installed = loaded.sync_egress_policy(&cfg.egress.deny)?;
        log::info!("egress: installed {installed} exact deny rule(s)");
    }
    log::info!("{}", loaded.egress_runtime().summary());
    // The posture is rebuilt from the kernel-verified facts above, not from
    // the config that requested them. With egress disabled this is exactly the
    // shipped observe-only posture; with it enabled but hooks missing or the
    // map degraded it says DEGRADED/UNAVAILABLE rather than claiming ENFORCE.
    let egress_startup_preflight = loaded.egress_runtime().preflight();
    log::info!(
        "{}",
        policy::PolicyPosture::with_preflight(
            cfg.mode,
            cfg.egress.deny.len(),
            egress_startup_preflight,
        )
        .summary()
    );
    log::debug!(
        "egress policy generation at startup: {}",
        loaded.egress_runtime().policy().generation()
    );

    // Resolve the guarded-files policy to (dev, ino) → guard policy and push it
    // into the kernel map. Best-effort per path (a missing file is skipped with a
    // warning inside resolve). A no-op when the LSM layer isn't attached.
    let guarded = guard::resolve(&cfg.enforce.guarded_files);
    let g = loaded.sync_guarded_inodes(&guarded)?;
    if loaded.lsm_attached {
        log::info!(
            "enforce: guarding {} inode(s); arm={} ({})",
            g,
            cfg.enforce.arm,
            if cfg.enforce.arm {
                "ARMED — denials return -EPERM"
            } else {
                "SHADOW — would-denies logged, allowed through"
            }
        );
    }

    let resolution = procscan::resolve_protected(&cfg.protect);
    let n = loaded.sync_protected(&resolution.all_pids())?;
    let kernel_identity = resolution.kernel_identity();
    log_protect_policy(&cfg.protect, &resolution);
    log::info!(
        "protecting {} immune pid(s), {} tripwire-only pid(s) ({} pushed to kernel)",
        resolution.protected.len(),
        resolution.tripwire_only_pids().len(),
        n
    );
    let mut protected = resolution.protected;
    // Seed the "already reported" marker so the first refresh tick does not
    // repeat what startup just said.
    let mut last_unmatched = resolution.unmatched_targets;

    // Heartbeat (off-box dead-man's-switch).
    let host = cfg
        .bridge
        .as_ref()
        .map(|b| b.host.clone())
        .unwrap_or_else(config::hostname);
    let mut hb = heartbeat::spawn(cfg.heartbeat.clone(), host)?;
    if hb.is_some() {
        log::info!("heartbeat thread running");
    }

    // Delivery to Sentinel (optional). A bad URL — or an unopenable spool — is
    // fatal here, not silently per-event: this process is the only place a
    // finding exists, and a bridge that cannot keep one should not come up
    // looking healthy. `Deliverer` owns the queue, the retry loop and the
    // on-disk spool, so the drain loop below never touches the network (W-05,
    // W-R6). On the healthy path `enqueue` is a bounded, non-blocking send; when
    // the queue is full it fsyncs the record to the spool on this thread, so a
    // long outage with a full queue can delay the drain loop by disk latency.
    let mut deliverer = match cfg.bridge.clone() {
        Some(b) => Some(Deliverer::start(b).context("starting Sentinel delivery")?),
        None => None,
    };

    let mut detector = Detector::new(cfg.clone());
    // Phase 7: hand the judge only kernel-verified capability facts. With
    // egress disabled it gets `None` — every DENY rule stays observe-only —
    // so a config toggle alone can never upgrade a finding's claim.
    detector.set_egress_preflight(cfg.egress.enabled.then_some(egress_startup_preflight));
    // W2K-10 / F09: the kernel's protected map is pid-keyed, so the judges need
    // the start times this map was written from — including tripwire-only pids —
    // to tell a takedown from a recycled pid. The responder still receives only
    // `protected`, never this broader table.
    detector.set_protected(kernel_identity);
    warn_if_no_app_cgroup(&cfg);
    // The pull path. Its state is the previous snapshot plus everything the
    // sensors named, because the report is a comparison of those two and not a
    // dump of /proc.
    let mut snap = net_snap::Reconciler::new(&cfg.network_snapshot);
    // One readlink at start-up, not one per accepted flow: FLOW records carry the
    // namespace inode the kernel saw, and this is the only number it can be
    // compared against to say "this accept happened here" vs "…in a namespace
    // whose sockets this process cannot enumerate". `None` if the link is
    // unreadable, and the journal line then declines to classify rather than
    // defaulting to host.
    let own_netns = net_snap::self_netns_ino();
    if cfg.network_snapshot.enabled {
        log::info!(
            "socket snapshot (pull path) ON: every {}s, attribution {} — it sees only Warden's \
             own network namespace, so container sockets are out of scope, and it writes to the \
             journal only.",
            cfg.network_snapshot.interval_secs,
            if cfg.network_snapshot.attribute {
                "on"
            } else {
                "off"
            }
        );
    }
    let mut log_throttle = FindingLogThrottle::new(LOG_THROTTLE_WINDOW);
    // Rebuilt on reload when the mode or the anchoring policy changes — see the
    // SIGHUP block below. The policy is read from config here, not defaulted, so
    // `--check` and the running process cannot disagree about what would be
    // refused (W2K-25).
    let mut responder = Responder::new(cfg.mode, cfg.respond.require_anchored_identity);
    // The cumulative network counters (N-05). Their state is the previous
    // absolute read per cgroup, because the kernel only ever reports totals and
    // the number an operator acts on is the movement between two of them. The
    // first tick lands one full interval after start rather than immediately: at
    // t=0 the map is legitimately empty, and a "0 cgroup(s) tracked" line in the
    // same second as the coverage line would read as a contradiction.
    let mut volume_sampler = net_vol::VolumeSampler::default();
    let mut last_volume = Instant::now();
    // Said once here, and again by `--check`, because the six fexit programs may
    // have attached only partially and a half-counted total is not a measurement.
    log::info!(
        "{}",
        net_vol::coverage_line(&cfg.net_volume, Some(&loaded.volume_hooks))
    );

    // epoll on the ring-buffer fd so we block efficiently between events.
    let epfd = Epoll::new()?;
    epfd.add(loaded.events.as_raw_fd())?;

    let mut last_refresh = Instant::now();
    let mut stats = Stats::default();
    // W-02 sampling state. The kernel's drop counter is monotonic, so the report
    // below is built from deltas over one window; seeding both at 0 makes the
    // first tick cover everything since load, which is the honest first reading.
    let mut last_drops = 0u64;
    let mut last_received = 0u64;
    // W-05: the delivery-loss counter is cumulative for the same reason, so the
    // tick reports the delta and the lifetime total separately rather than
    // repeating one cumulative number until it stops meaning anything.
    // Self-observability: the previous delivery snapshot, so a self-finding
    // reports what CHANGED rather than a cumulative total every tick.
    let mut last_delivery: Option<deliver::DeliveryStats> = None;
    let mut last_suppressed = 0u64;

    log::info!("entering event loop");
    while !shutdown.load(Ordering::Relaxed) {
        // Policy reload on SIGHUP.
        if reload.swap(false, Ordering::Relaxed) {
            match args.config.as_ref().map(|p| Config::load(p)) {
                Some(Ok(fresh)) => {
                    // W2K-23 on reload too: an edit that introduces an unread key is
                    // exactly the edit whose effect the operator is checking for.
                    log_unread_keys(&fresh);
                    // W-04: read the mode out before `fresh` is moved into the
                    // detector, so the responder below can be rebuilt from it.
                    let fresh_mode = fresh.mode;
                    // Likewise the arm flag: `fresh` is moved into the detector
                    // before the "applied" summary below is logged.
                    let fresh_arm = fresh.enforce.arm;
                    // Phase 7: capture the egress fields before `fresh` moves.
                    let fresh_egress_enabled = fresh.egress.enabled;
                    let fresh_egress_arm = fresh.egress.arm;
                    let fresh_egress_denies = fresh.egress.deny.clone();
                    let fresh_egress_cgroup_path = fresh.egress.cgroup_path.clone();
                    // …and the W2K-13 cache window, for the same reason.
                    let fresh_enrich_cache_ms = fresh.runtime.enrich_cache_ms;
                    // W2K-25: the anchoring policy lives on the responder, which
                    // is rebuilt further down — capture it before `fresh` is
                    // moved into the new Detector.
                    let fresh_require_anchored = fresh.respond.require_anchored_identity;
                    // W-R7: work out what will NOT take effect while `fresh` is
                    // still borrowed — it is moved into the Detector below. This
                    // is compared against `cfg`, which deliberately keeps holding
                    // the values the running threads were started with, so the
                    // warning repeats on every reload until the restart happens
                    // rather than going quiet after one report.
                    let unapplied = unapplied_reload_changes(&cfg, &fresh);
                    let protect_resolution = procscan::resolve_protected(&fresh.protect);
                    loaded.sync_protected(&protect_resolution.all_pids())?;
                    let reload_kernel_identity = protect_resolution.kernel_identity();
                    log_protect_policy(&fresh.protect, &protect_resolution);
                    protected = protect_resolution.protected;
                    last_unmatched = protect_resolution.unmatched_targets;
                    // Re-arm and re-resolve the guarded set from the fresh policy.
                    // Re-stat on reload is also how a guarded file rewritten in
                    // place (new inode) gets re-pinned to its current inode.
                    loaded.set_enforce_arm(fresh_arm)?;
                    // Phase 7: classify the reload against the CONFIG THIS
                    // PROCESS BOOTED WITH. Hook attachment is a load-time fact,
                    // so a new cgroup_path or a disabled→enabled flip must be
                    // reported as restart-required, never silently armed.
                    let egress_transition = egress::EgressReloadTransition::classify(
                        cfg.egress.enabled,
                        fresh_egress_enabled,
                        cfg.egress.cgroup_path != fresh_egress_cgroup_path,
                    );
                    match loaded.apply_egress_reload(
                        egress_transition,
                        fresh_egress_arm,
                        &fresh_egress_denies,
                    ) {
                        Ok(report) => {
                            log::info!(
                                "SIGHUP: egress reload {}: {}; {}",
                                egress_transition.label(),
                                if report.applied {
                                    "applied from kernel-verified writes"
                                } else {
                                    "no kernel state changed"
                                },
                                report.summary
                            );
                            if !report.restart_required.is_empty() {
                                log::warn!(
                                    "SIGHUP: egress restart required: {}",
                                    report.restart_required.join("; ")
                                );
                            }
                        }
                        Err(e) => {
                            // E: an aborted reload must not take the daemon down
                            // or leave a half-written policy presented as live.
                            log::error!(
                                "SIGHUP: egress reload {} FAILED; old runtime preserved: {e}; {}",
                                egress_transition.label(),
                                loaded.egress_runtime().summary()
                            );
                        }
                    }
                    let guarded = guard::resolve(&fresh.enforce.guarded_files);
                    let g = loaded.sync_guarded_inodes(&guarded)?;
                    if loaded.lsm_attached {
                        log::info!("SIGHUP: guarding {} inode(s); arm={}", g, fresh_arm);
                    }
                    // W2K-31: the volume gate is one map slot, so — unlike `[bridge]`
                    // — a reload can apply it completely. It has to be WRITTEN, though:
                    // the tick further down already reads the FRESH policy out of the
                    // new detector, so a gate left at its boot value is the half of the
                    // pair that does not move. Measured on the deployment host: an
                    // enabled → disabled reload kept counting in the kernel for a report
                    // that had gone quiet, and disabled → enabled printed a tick whose
                    // totals could not have moved.
                    if fresh.net_volume.enabled != volume_emit {
                        loaded.set_net_volume_emit(fresh.net_volume.enabled)?;
                        log::warn!(
                            "SIGHUP: net_volume emit gate {} → {}, applied now",
                            yes_no(volume_emit),
                            yes_no(fresh.net_volume.enabled)
                        );
                        volume_emit = fresh.net_volume.enabled;
                        // The coverage line is the sentence that says what the gate costs
                        // and what question it answers. It was stated once at boot, about
                        // the posture that has now changed, so state it again about this
                        // one — with the hooks this process really attached.
                        log::info!(
                            "{}",
                            net_vol::coverage_line(&fresh.net_volume, Some(&loaded.volume_hooks))
                        );
                    }
                    // Phase 7: rebuild the judge's capability proof from the
                    // arm/policy state just confirmed against the kernel. A
                    // reload that only edits `[egress]` cannot attach hooks, so
                    // the hook bits stay whatever the kernel verified at load.
                    let fresh_egress_proof = loaded.egress_runtime().preflight();
                    detector = Detector::new(fresh);
                    detector
                        .set_egress_preflight(fresh_egress_enabled.then_some(fresh_egress_proof));
                    // A fresh detector means a fresh identity table too — the new
                    // policy's full kernel set was pushed above. Tripwire-only pids
                    // are included for the judges but never for the responder.
                    detector.set_protected(reload_kernel_identity);
                    warn_if_no_app_cgroup(detector.config());
                    // The pull path is the opposite of `[bridge]`: it holds no thread and
                    // no kernel object, so a reload applies it completely. Say what moved,
                    // because a bare "reloaded config" would also be claiming the sections
                    // below that did NOT apply.
                    if let Some(note) = snap.sync_policy(&detector.config().network_snapshot) {
                        log::info!("SIGHUP: socket snapshot policy applied — {note}");
                    }

                    // The responder was previously built once at startup and never
                    // replaced, while this branch still logged "reloaded config
                    // (mode=…)". The log therefore claimed a mode the process had
                    // not adopted: after `enforce → observe`, the old Responder
                    // stayed in Enforce and kept killing, and after
                    // `observe → enforce` it stayed in Observe and killed nothing.
                    // Rebuilding is safe — it holds only `mode` and one bool,
                    // `new()` has no side effects, and it is owned by this
                    // single-threaded loop; the old one is dropped by the
                    // assignment.
                    let current = (responder.mode(), responder.requires_anchored_identity());
                    let wanted = (fresh_mode, fresh_require_anchored);
                    // Read the OLD values before the rebuild below, not after:
                    // `responder.mode()` would already be the fresh mode there, and
                    // the line would read "Enforce → Enforce" for an observe→enforce
                    // reload — the same kind of log that says something the process
                    // did not do.
                    if responder_needs_rebuild(current, wanted) {
                        responder = Responder::new(wanted.0, wanted.1);
                        if current.0 != wanted.0 {
                            log::warn!(
                                "SIGHUP: responder mode {:?} → {:?}, applied now",
                                current.0,
                                wanted.0
                            );
                        }
                        if current.1 != wanted.1 {
                            log::warn!(
                                "SIGHUP: responder anchoring policy (W2K-25) \
                                 require_anchored_identity {} → {}, applied now",
                                yes_no(current.1),
                                yes_no(wanted.1)
                            );
                        }
                    }
                    // W-R7: name what took effect instead of a bare "reloaded
                    // config". That line read as though the whole file were now
                    // live, which it never was: `[bridge]` and `[heartbeat]` are
                    // fixed for the life of the process.
                    log::info!(
                        "SIGHUP: applied mode={:?}, protect ({} pid(s)), enforce (arm={}, \
                         {} guarded inode(s)), runtime (enrich cache = {} ms), net_volume \
                         (kernel gate = {}, interval = {} s)",
                        fresh_mode,
                        protected.len(),
                        fresh_arm,
                        g,
                        fresh_enrich_cache_ms,
                        yes_no(volume_emit),
                        detector.config().net_volume.interval_secs
                    );
                    if !unapplied.is_empty() {
                        log::warn!(
                            "SIGHUP: NOT applied (restart required): {}. [bridge] and \
                             [heartbeat] are read once at startup and their threads cannot \
                             take a new configuration mid-flight, and the events ring is \
                             allocated when its map is created. Restart warden to apply them; \
                             this warning repeats on every reload until you do.",
                            unapplied.join("; ")
                        );
                    }
                }
                Some(Err(e)) => {
                    log::error!("SIGHUP: config reload failed, keeping old: {e}");
                    let preserved = egress::EgressReloadReport::preserved(
                        egress::EgressReloadTransition::FailedConfig,
                        loaded.egress_runtime(),
                    );
                    log::warn!(
                        "SIGHUP: {}; old runtime preserved: {}",
                        preserved.transition.label(),
                        preserved.summary
                    );
                }
                None => log::warn!("SIGHUP: no config path to reload from"),
            }
        }

        // Periodic protected-set reconciliation.
        if last_refresh.elapsed() >= PROTECT_REFRESH {
            let fresh = procscan::resolve_protected(&detector.config().protect);
            let pids = fresh.all_pids();
            // Reconcile unconditionally. `sync_protected` diffs against the
            // kernel map itself, so an unchanged set costs no writes; comparing
            // against the userspace *immunity* set here would silently leave a
            // removed tripwire-only pid in the kernel map (F09).
            let added = loaded.sync_protected(&pids)?;
            if added > 0 {
                log::debug!(
                    "protected set reconciled: {} pid(s), {} newly pushed",
                    pids.len(),
                    added
                );
            }
            // W-R4: adopt the new resolution even when the pid set is identical.
            // A pid recycled by a new process has a later start time, and
            // kill-immunity is bound to that start time — skipping the
            // assignment would keep the dead process's value and could shield
            // the very process that reused the number. Report a change in the
            // unmatched-target list only when it actually changes, so a policy
            // that matches nothing is not re-warned every tick.
            if fresh.unmatched_targets != last_unmatched {
                log_protect_policy(&detector.config().protect, &fresh);
                last_unmatched = fresh.unmatched_targets.clone();
            }
            // W2K-10 / F09: keep the judges' view in step with the whole map
            // the kernel holds, tripwire-only pids included. The responder's
            // `protected` below stays immunity-only.
            detector.set_protected(fresh.kernel_identity());
            protected = fresh.protected;
            // Re-resolve the guarded set on the same tick. A guarded file rewritten
            // in place gets a NEW inode; without this re-stat the kernel map would
            // keep pointing at the old, now-unlinked inode and silently guard
            // nothing. Re-running resolve() each tick is what makes protection track
            // the file's CURRENT inode within one PROTECT_REFRESH of it changing.
            let guarded = guard::resolve(&detector.config().enforce.guarded_files);
            loaded.sync_guarded_inodes(&guarded)?;
            last_refresh = Instant::now();

            // Journal-side coalescing: repeat findings from the same actor and
            // type are counted, not re-logged. Report the count at the tick so
            // the journal states what it omitted instead of implying the burst
            // was one event. Delivery is unaffected — every finding still went
            // to the bridge or spool above.
            log_throttle.prune(Instant::now());
            let suppressed = stats.suppressed_logs.saturating_sub(last_suppressed);
            last_suppressed = stats.suppressed_logs;
            if suppressed > 0 {
                log::warn!(
                    "journal: {suppressed} repeated finding line(s) suppressed in the last {}s — \
                     only the first of each (type, pid) was logged. Every finding was still \
                     judged and delivered; this throttle is on the journal line, not on \
                     detection.",
                    PROTECT_REFRESH.as_secs(),
                );
            }

            // W-02: report ring-buffer loss. The kernel counter is monotonic, so
            // the delta over this tick is what happened during it; a non-zero
            // delta means the sensors produced more than the ring could hold and
            // the surplus is gone — not queued, not retried, gone. Logged at warn,
            // because under flood this is the entire difference between a quiet
            // host and a deaf one, and the whole point of the counter is that the
            // second must never look like the first.
            match loaded.sensor_counters() {
                Ok(counters) => {
                    let total = counters.drops.iter().sum::<u64>();
                    let dropped = total.saturating_sub(last_drops);
                    let received = stats.received.saturating_sub(last_received);
                    last_drops = total;
                    last_received = stats.received;
                    if dropped > 0 {
                        // Drops are counted in the kernel at reserve time and
                        // `received` in userspace at drain time, so this ratio is
                        // an estimate over the window rather than per-event
                        // accounting. It is the right order of magnitude for "how
                        // much am I losing", which is the question; the absolute
                        // counts on either side are exact. Both the rate and the
                        // dropped/received ratio are reported, because they answer
                        // different questions: the rate says how bad it is now, the
                        // ratio says what fraction of the host's activity this
                        // process is blind to.
                        //
                        // W2K-14 names the sensor. The advice below is "mute the
                        // noisiest sensor" — which a bare total cannot act on — so
                        // the largest per-kind loss rides on the same line.
                        let window = PROTECT_REFRESH.as_secs_f64();
                        let attempted = dropped + received;
                        // Phase 4 ← Phase 1: the beaconing detector must weaken
                        // its confidence when this window lost events. A window
                        // with no events at all is None, never 0.0 — the same
                        // discipline as the health JSON, so a quiet host cannot
                        // claim clean data.
                        let loss_ratio =
                            (attempted > 0).then_some(dropped as f64 / attempted as f64);
                        detector.set_ring_loss_ratio(loss_ratio);
                        // W2K-13: quote the capacity this loss is a fraction of,
                        // and name the knob that changes it. The advice used to be
                        // "raise `events` in bpf/warden.bpf.c" — accurate about the
                        // source, and unusable by anyone running the shipped binary.
                        let ring_note = match loaded.ring_capacity_bytes {
                            Some(bytes) => format!("{} KiB ring", bytes / 1024),
                            None => format!(
                                "{} KiB ring (requested; capacity unreadable)",
                                cfg.runtime.ring_size_kib
                            ),
                        };
                        let worst = counters
                            .worst_drop()
                            .map(|(kind, n)| {
                                format!("worst: {} ({} since start)", kind.as_str(), n)
                            })
                            .unwrap_or_else(|| "worst: unknown".to_string());
                        log::warn!(
                            "ringbuf: {dropped} event(s) DROPPED in the last {window:.0}s — \
                             {received} of {attempted} reached userspace: {rate:.0}/s lost, \
                             ratio {dropped} dropped : {received} received ({pct:.1}%), {total} \
                             dropped since start ({worst}). The {ring_note} is too small for this \
                             event rate: raise `[runtime] ring_size_kib` and restart (the ring is \
                             sized when its map is created, so SIGHUP cannot apply it), or mute \
                             the noisiest sensor.",
                            rate = dropped as f64 / window,
                            pct = (dropped as f64 / attempted as f64) * 100.0,
                        );
                        // Phase 1: the journal line above is invisible to
                        // Sentinel. Ship the same loss as a self-degraded
                        // finding so a sensor that went deaf never looks like
                        // a quiet host on the platform. It takes the ordinary
                        // enqueue path (spools if the bridge is the broken
                        // thing) and carries no kill intent or credential.
                        if let Some(d) = &deliverer {
                            let f = telemetry::ring_loss_finding(
                                dropped,
                                received,
                                total,
                                worst.as_str(),
                                &ring_note,
                            );
                            d.enqueue(&f, crate::respond::Action::Observed);
                        }
                    } else {
                        // N-02: the verdict sensor's coverage is the one thing the drop
                        // counters cannot say. A dial with no CONNECT_RESULT record is the
                        // EXPECTED shape in two cases — a stream connect still in flight
                        // (-EINPROGRESS, what every connect-with-a-timeout client does) and
                        // a datagram dial, which the verdict probe cannot see because it
                        // sits on __inet_stream_connect. So "fewer verdicts than dials" is
                        // either normal or a dead kretprobe, and only the pair of submit
                        // counters side by side distinguishes them. Put on the debug line
                        // because it is a diagnostic, not an alert: this number cannot be
                        // compared to a threshold — it moves with how the apps on this host
                        // choose to dial, and with how much of their traffic is UDP.
                        let dials = counters.submitted[crate::events::Kind::Connect as usize];
                        let verdicts =
                            counters.submitted[crate::events::Kind::ConnectResult as usize];
                        let verdict_note = if dials == 0 {
                            String::new()
                        } else {
                            format!("; {verdicts} of {dials} dial(s) had a terminal verdict")
                        };
                        log::debug!(
                            "ringbuf: clean — {received} received, 0 dropped in the last {}s \
                             ({total} dropped since start; {} record(s) submitted by the kernel \
                             since start){verdict_note})",
                            PROTECT_REFRESH.as_secs(),
                            counters.submitted.iter().sum::<u64>(),
                        );
                    }
                    // Phase 1: one structured trust state for this tick, from
                    // the same counters the prose above just reported. The
                    // declared blind spots are included, so a clean ring never
                    // reads as full coverage. Debug level: the journal already
                    // has the actionable lines; this is the machine summary.
                    let live = telemetry::TelemetryReport::live(
                        telemetry::RingLoss::observed(
                            total,
                            counters.submitted.iter().sum::<u64>(),
                        ),
                        telemetry::PipelineCounters::unknown(),
                        last_delivery.is_some_and(|p| p.dropped > 0),
                        false,
                    );
                    log::debug!("warden telemetry state: {}", live.state.word());
                    // Phase 5: the same reading travels with every finding
                    // enqueued from here on. A clean ring still reports the
                    // declared blind spots, so the platform never reads a
                    // healthy counter as full host coverage.
                    if let Some(d) = &deliverer {
                        d.set_sensor_health(&live);
                    }
                }
                // Deliberately loud, and deliberately NOT folded into "zero
                // loss". "I could not read the counter" and "nothing was
                // dropped" are different facts, and zero is the reassuring one,
                // so it is the one an unreadable counter must never report. The
                // cursors are left unadvanced on purpose: the next successful
                // read then covers this blind window too, instead of skipping it.
                Err(e) => {
                    log::warn!(
                        "ringbuf: drop counter unreadable ({e}); loss for this window is UNKNOWN, \
                         not zero."
                    );
                    // Phase 5: an unreadable counter also invalidates the last
                    // health snapshot — a stale HEALTHY on the wire would be a
                    // false claim about the current window.
                    if let Some(d) = &deliverer {
                        d.set_sensor_health_unknown();
                    }
                }
            }

            // Phase 7: sample the egress counters on the same cadence as the
            // ring counters. The four numbers answer four different questions:
            // "a rule matched and allowed" (an explicit ALLOW entry), "a DENY
            // matched but SHADOW let it through", "an ARMED DENY really refused
            // an operation", and "a rule insert was refused so coverage is
            // incomplete". Only the third is a block, and the first two are
            // reported separately so a shadow hit can never be misread as a
            // denial. With egress disabled these counters stay at zero and
            // nothing is logged — a disabled feature must not look active.
            if loaded.egress_runtime().enabled {
                match loaded.egress_stats() {
                    Ok(s) => {
                        let verdict = if s.has_verified_denial() {
                            "VERIFIED DENIAL(S) — an armed rule returned -EPERM"
                        } else if s.hit_deny > 0 {
                            "SHADOW would-deny hit(s) — traffic was allowed through"
                        } else {
                            "no DENY match in this window"
                        };
                        log::debug!(
                            "egress: allow_hit={} shadow_deny={} armed_denied={} map_full={} \
                             ({verdict})",
                            s.hit_allow,
                            s.hit_deny,
                            s.denied,
                            s.map_full,
                        );
                        if s.map_full > 0 {
                            log::warn!(
                                "egress: {} rule insert(s) were refused by the kernel map — \
                                 the exact-policy coverage is INCOMPLETE, not fully enforced",
                                s.map_full
                            );
                        }
                    }
                    Err(e) => {
                        // An unreadable counter is unknown, never zero — the
                        // same discipline as the ring-drop counter above.
                        log::warn!("egress: counters unreadable ({e}); disposition UNKNOWN");
                    }
                }
            }

            // W-05: delivery health, on the same tick and for the same reason as
            // the ring-drop report — the failure this exists to break is silence.
            // A non-empty spool means findings exist that Sentinel has not seen;
            // a non-zero `lost` means some never will. Both are stated plainly
            // rather than folded into one "bridge: ok".
            if let Some(d) = &deliverer {
                let s = d.stats();
                let lost_now = s
                    .dropped
                    .saturating_sub(last_delivery.map_or(0, |p| p.dropped));
                if lost_now > 0 {
                    log::error!(
                        "bridge: {lost_now} finding(s) LOST in the last {}s — never accepted by \
                         Sentinel and not on disk ({total} lost since start). The spool is full, \
                         or cannot be written; see the preceding spool error. The platform's \
                         record of this host now has gaps.",
                        PROTECT_REFRESH.as_secs(),
                        total = s.dropped,
                    );
                }
                // Self-observability: the same degradation the journal reports
                // is also shipped to Sentinel as a finding, so a sensor whose
                // uplink is failing does not look like a healthy quiet host.
                // Only on a tick where something actually changed — a healthy
                // steady state mints no row. The finding takes the ordinary
                // enqueue path: if the bridge is what is broken, it spools and
                // waits exactly like any other finding.
                if let Some(prev) = last_delivery {
                    if let Some(f) = s.self_finding(&prev) {
                        d.enqueue(&f, crate::respond::Action::Observed);
                    }
                }
                last_delivery = Some(s);
                if s.pending_on_disk > 0 {
                    log::warn!(
                        "bridge: Sentinel has not accepted {} finding(s) — {} bytes buffered on \
                         disk, {} waiting in memory. Retrying with backoff; nothing is lost \
                         unless the spool fills.",
                        s.pending_on_disk,
                        s.spool_bytes,
                        s.queue_depth,
                    );
                } else {
                    log::debug!("bridge: uplink healthy — {}", s.summary());
                }
            }

            // The pull path, on the same tick and for the same reason as the two
            // reports above: the failure it exists to break is a quiet one. A
            // listener that predates this process, or one whose record was lost to
            // a full ring, produces no journal line ever — and the journal cannot
            // tell "nothing is listening" from "nothing was listening while I was
            // watching". Its own interval gates it, so a 10s tick loop can carry a
            // 5-minute snapshot without either number moving the other.
            let snap_policy = &detector.config().network_snapshot;
            let now = Instant::now();
            if snap.due(snap_policy, now) {
                let (report, notes) = snap.tick(snap_policy, now);
                for note in notes {
                    log::warn!("{note}");
                }
                for line in report.lines(snap_policy) {
                    // `info`, not `debug`: these lines are the evidence that the
                    // pull path ran and what it found. A coverage report nobody can
                    // see at a default log level is the silence N-11 describes.
                    log::info!("{line}");
                }
            }

            // The cumulative counters (N-05) ride the same refresh loop and gate
            // on their own interval, exactly as the pull path above does — the
            // failure they exist to break is the same silence. A cgroup that moved
            // 4 GB while nobody read the map is indistinguishable from one that
            // moved nothing unless the read happens on a cadence and says which of
            // the two it was. Skipped entirely when policy has them off, so an
            // intentionally uncounted host never prints an empty report.
            let vol_policy = &detector.config().net_volume;
            if vol_policy.enabled
                && last_volume.elapsed() >= Duration::from_secs(vol_policy.interval_secs)
            {
                last_volume = Instant::now();
                // One walk per tick, bounded by policy: it names the ids, it does
                // not decide whether they were counted.
                let paths =
                    net_vol::cgroup_paths(&vol_policy.cgroup_root, vol_policy.cgroup_walk_max);
                match loaded.net_volume_totals(&paths) {
                    Ok(totals) => {
                        let (rows, gone) =
                            volume_sampler.tick(&totals, vol_policy.report_min_bytes);
                        let moved = rows.len();
                        let mut shown = rows;
                        shown.truncate(vol_policy.max_rows_per_tick);
                        // `info`, like the snapshot lines: this is the evidence the
                        // counter ran and what it saw, and a report nobody reads at
                        // the default level is the thing the whole sensor replaced.
                        log::info!("{}", net_vol::tick_line(&shown, moved, &totals, &gone));
                        // The one state this sensor must never leave ambiguous.
                        // An empty map and a host that moved nothing print the same
                        // quiet tick, so when NO bump has ever landed the two are
                        // distinguished by the only evidence available: whether the
                        // programs are attached at all. Attached-but-silent is an
                        // idle host; not-attached is a counter that will read zero
                        // for as long as this process lives, which an operator who
                        // just enabled it needs told in those words.
                        if totals.bumps == 0 && totals.rows.is_empty() {
                            if totals.hooks.all_attached() {
                                log::warn!(
                                    "net_volume: enabled and all 3 hooks attached, but 0 bumps \
                                     since start — nothing has sent or received a byte through \
                                     tcp_sendmsg/tcp_cleanup_rbuf/udp_sendmsg since this agent \
                                     started. Trusting this as an idle host depends on the \
                                     hooks being real; a host that moves traffic and still \
                                     shows this line is a kernel the fexit attach did not take."
                                );
                            } else {
                                log::warn!(
                                    "net_volume: enabled but NO cgroup has ever been counted \
                                     ({} hook(s) attached) — the totals will stay empty this \
                                     run regardless of traffic.",
                                    totals.hooks.attached_count()
                                );
                            }
                        }
                        if let Some(missing) = totals.hooks.missing_claim() {
                            // Repeated on purpose. The startup line states it once
                            // and scrolls away; a total read weeks later has to
                            // carry its own caveat or it becomes a measurement.
                            log::warn!(
                                "net_volume: this report is INCOMPLETE — {missing} did not \
                                 attach, so those directions contributed nothing above."
                            );
                        }
                        if totals.refused > 0 {
                            log::warn!(
                                "net_volume: {} bump(s) refused for want of a map slot \
                                 (max {} cgroups) — bytes moved on this host that are in NO \
                                 total above. The map is a bound, not a census.",
                                totals.refused,
                                loader::NET_VOLUME_MAX
                            );
                        }
                    }
                    Err(e) => log::warn!(
                        "net_volume: totals unreadable ({e}); the volume moved in this window is \
                         UNKNOWN, not zero."
                    ),
                }
            }
        }

        // Block for events (or wake on the slice to re-check flags/refresh).
        epfd.wait(POLL_SLICE_MS)?;

        // Drain everything currently in the ring buffer.
        while let Some(item) = loaded.events.next() {
            stats.received += 1;
            let Some(event) = RawEvent::decode(&item) else {
                stats.undecodable += 1;
                continue;
            };
            // The pull path keeps its own account of what the sensors said, so the
            // next snapshot can name the sockets they never explained. Fed for
            // every decoded record, judged or not — see `Reconciler::note`.
            snap.note(&event);
            // The verdict sensor (N-02) has one consumer in this build: the journal.
            // That is a statement about the build, not an oversight — `judge` raises no
            // finding for this record because the dial-time CONNECT record already owns
            // the egress finding, and the path that would take `conn_state` is the
            // platform's flow ingest, which is not wired here. Until it is, this line is
            // how a live host shows the kretprobe pair fired and paired at all. Debug
            // level: a completed dial is routine, and a routine line per dial on a 2-CPU
            // box is the log flood this pipeline was tuned to avoid.
            if let Some(outcome) = event.connect_outcome {
                log::debug!(
                    "egress verdict: pid {} ({}) dialed {} -> {}{}",
                    event.actor_pid,
                    event.comm,
                    event.dest.as_deref().unwrap_or("(endpoint not decodable)"),
                    outcome.as_str(),
                    match outcome.conn_state_hint() {
                        Some(state) => format!(" (conn_state={state})"),
                        None => String::new(),
                    }
                );
            }
            // The accept sensor (N-03's inbound half) has the same single consumer in
            // this build: the journal, and again that is a statement about the build.
            // `judge` returns None for FLOW because an accepted connection on a host
            // whose job is serving them is routine — the deployment host measured ≈3.9
            // accepts/s in a quiet window, so a finding per accept is the flood this
            // pipeline was tuned away from, and the judgement worth making ("this peer
            // is not one of that listener's sanctioned peers") needs the platform's
            // allowlist. Debug level for the same volume reason. The line is what
            // proves on a live host that the pair fired, paired, and decoded.
            if let Some(flow) = event.flow {
                let netns = match (flow.netns_ino, own_netns) {
                    (0, _) => "netns unreadable in-kernel".to_string(),
                    (ino, Some(mine)) if ino == mine => format!("{ino} (this namespace)"),
                    (ino, Some(_)) => format!("{ino} (NOT enumerable from /proc/net here)"),
                    (ino, None) => format!("{ino} (agent namespace unknown)"),
                };
                log::debug!(
                    "inbound flow: pid {} ({}) accepted {} on port {}{} via {}",
                    event.actor_pid,
                    event.comm,
                    event.dest.as_deref().unwrap_or("(endpoint not decodable)"),
                    flow.local_port,
                    match event.protocol {
                        Some(p) => format!("/{}", p.as_str()),
                        None => String::new(),
                    },
                    netns
                );
            }
            let Some(finding) = detector.judge(&event) else {
                continue;
            };
            stats.findings += 1;

            let action = responder.act(&finding, &protected);
            if log_throttle.admit(
                finding.process.pid,
                finding.event_type_str(),
                Instant::now(),
            ) {
                log::warn!(
                    "[{}] {} — {} (action={})",
                    finding.severity_str(),
                    finding.event_type_str(),
                    finding.summary,
                    action.as_str()
                );
            } else {
                stats.suppressed_logs += 1;
            }

            if let Some(d) = &deliverer {
                d.enqueue(&finding, action);
            }
        }
    }

    // W-05: stop the sender and flush what is still in memory BEFORE reporting.
    // `shutdown` joins the thread, and the thread writes its in-memory tail to
    // the spool on the way out, so the numbers below describe the state on disk
    // with nothing still in flight. Reporting first would be the same kind of
    // lie the ring-drop counter exists to prevent: a "0 waiting" that really
    // meant "0 written yet".
    if let Some(d) = deliverer.as_mut() {
        d.shutdown();
    }
    let delivery = deliverer.as_ref().map(|d| d.stats());

    // W-02: the lifetime drop total belongs in the shutdown line — it is the one
    // number that says whether this process's view of the host was complete.
    // Read while `loaded` is still alive. Reported as unknown rather than as zero
    // when the counter cannot be read, the same distinction the periodic report
    // makes: a shutdown summary that says "0 dropped" when it means "not
    // measured" would launder the invisible loss the counter exists to expose.
    let dropped_total = match loaded.dropped() {
        Ok(n) => n.to_string(),
        Err(e) => format!("unknown ({e})"),
    };
    log::info!(
        "shutting down: {} events, {} findings ({} repeated journal line(s) suppressed), \
         {} undecodable, {} dropped in-kernel",
        stats.received,
        stats.findings,
        stats.suppressed_logs,
        stats.undecodable,
        dropped_total,
    );
    match &delivery {
        Some(s) => log::info!("bridge: {}", s.summary()),
        None => log::info!("bridge: not configured — findings went to the journal only"),
    }
    if let Some(s) = &delivery {
        if s.dropped > 0 {
            log::error!(
                "bridge: {} finding(s) were LOST during this run — Sentinel never accepted them \
                 and they are not on disk. The platform's record of this host has permanent gaps; \
                 raise bridge.spool_max_bytes or fix the spool's writability.",
                s.dropped
            );
        }
        if s.pending_on_disk > 0 {
            log::warn!(
                "bridge: {} finding(s) ({} bytes) are in {} and will be delivered on the next \
                 start — Sentinel has not seen them yet. They are not lost.",
                s.pending_on_disk,
                s.spool_bytes,
                cfg.bridge
                    .as_ref()
                    .map(|b| b.spool_path.display().to_string())
                    .unwrap_or_default(),
            );
        }
    }
    if let Some(h) = hb.as_mut() {
        h.stop();
    }
    // Dropping `loaded` detaches the programs; the kernel restores normal
    // behaviour. Nothing we attached persists past our exit.
    Ok(())
}

/// `[bridge]` settings a SIGHUP could not apply, as field names — empty when the
/// fresh section matches the running one.
///
/// W-R7: `[bridge]` is read once at startup, by the `Deliverer`'s sender thread.
/// It cannot be handed a new configuration mid-flight: changing the destination
/// or the credentials means tearing down a thread that is holding findings in
/// its queue and on its spool, and there is no safe point in the drain loop to
/// do that from. So the reload path applies what it can — mode, protect, enforce,
/// and the rest of the detector's policy — and must say plainly what it did not:
/// otherwise "reloaded config" reads as "everything is now in effect", and an
/// operator who repointed `url` at a new collector believes findings land there
/// while they keep arriving at the old one, which looks exactly like a healthy
/// bridge.
///
/// Only field NAMES are reported, never values: `api_key` is in here, and a diff
/// that printed it would put a credential in the journal.
fn unapplied_bridge_changes(
    running: Option<&config::Bridge>,
    fresh: Option<&config::Bridge>,
) -> Vec<String> {
    match (running, fresh) {
        // Enabling or disabling the uplink is itself restart-required: there is
        // no way to start a sender thread on a loop that is already draining, or
        // to stop one without discarding what it is holding.
        (None, Some(_)) => vec!["[bridge] was added (not started)".to_string()],
        (Some(_), None) => vec!["[bridge] was removed (still sending)".to_string()],
        (Some(a), Some(b)) => {
            let mut fields = Vec::new();
            if a.url != b.url {
                fields.push("url");
            }
            if a.api_key != b.api_key {
                fields.push("api_key");
            }
            if a.host != b.host {
                fields.push("host");
            }
            if a.timeout_ms != b.timeout_ms {
                fields.push("timeout_ms");
            }
            if a.queue_max != b.queue_max {
                fields.push("queue_max");
            }
            if a.spool_path != b.spool_path {
                fields.push("spool_path");
            }
            if a.spool_max_bytes != b.spool_max_bytes {
                fields.push("spool_max_bytes");
            }
            if a.backoff_ms != b.backoff_ms {
                fields.push("backoff_ms");
            }
            if a.max_backoff_ms != b.max_backoff_ms {
                fields.push("max_backoff_ms");
            }
            if a.allow_public_plaintext != b.allow_public_plaintext {
                fields.push("allow_public_plaintext");
            }
            // Phase 8: names only. A changed key PATH is safe to print, but a
            // changed key VALUE is not; this diff never reads file contents.
            if a.tls_ca_file != b.tls_ca_file {
                fields.push("tls_ca_file");
            }
            if a.tls_cert_file != b.tls_cert_file {
                fields.push("tls_cert_file");
            }
            if a.tls_key_file != b.tls_key_file {
                fields.push("tls_key_file");
            }
            if a.tls_sni != b.tls_sni {
                fields.push("tls_sni");
            }
            if fields.is_empty() {
                Vec::new()
            } else {
                vec![format!("[bridge] {}", fields.join(", "))]
            }
        }
        (None, None) => Vec::new(),
    }
}

/// `[heartbeat]` settings a SIGHUP could not apply. Same contract as
/// [`unapplied_bridge_changes`], and the same reason: the beat runs on a thread
/// spawned once with its configuration, so `url`, `interval_secs`, `secret` and
/// `seq_file` are fixed for the life of the process. A changed `secret` is
/// reported by name only — never its value, which is the whole point of it.
fn unapplied_heartbeat_changes(
    running: Option<&config::Heartbeat>,
    fresh: Option<&config::Heartbeat>,
) -> Vec<String> {
    match (running, fresh) {
        (None, Some(_)) => vec!["[heartbeat] was added (not beating)".to_string()],
        (Some(_), None) => vec!["[heartbeat] was removed (still beating)".to_string()],
        (Some(a), Some(b)) => {
            let mut fields = Vec::new();
            if a.url != b.url {
                fields.push("url");
            }
            if a.interval_secs != b.interval_secs {
                fields.push("interval_secs");
            }
            if a.secret != b.secret {
                fields.push("secret");
            }
            if a.seq_file != b.seq_file {
                fields.push("seq_file");
            }
            if fields.is_empty() {
                Vec::new()
            } else {
                vec![format!("[heartbeat] {}", fields.join(", "))]
            }
        }
        (None, None) => Vec::new(),
    }
}

/// Everything a SIGHUP re-read but could not put into effect. See
/// [`unapplied_bridge_changes`] for why any of this is reported at all.
/// W2K-23: name every key in the loaded file that no field of its section reads.
///
/// Deliberately a warning and never a refusal. A sensor that will not start because
/// of a typo is a coverage gap — the host goes blind and the dead-man's switch is the
/// only thing that notices — whereas an ignored key is already silent today. This
/// makes the silence audible at the three places an operator actually looks: `--check`
/// before start, the journal at start, and every SIGHUP reload after that.
fn log_unread_keys(cfg: &Config) {
    for key in &cfg.unread_keys {
        log::warn!(
            "config key {key} is not read by Warden: no field of that section declares it, so \
             the value in effect is Warden's default. Check which section the key is really under."
        );
    }
}

/// `--check --strict` turns the unread-key warning into a hard failure.
///
/// Normal startup stays deliberately loud-but-non-fatal (see `log_unread_keys`):
/// a sensor that refuses to start over a typo is a blind host. But CI and the
/// deploy gate are exactly the places where "the file says X, Warden runs Y"
/// must be a red build, so the same audit is offered in a strict form. Only key
/// NAMES are reported — never values, so an api_key landing in an orphaned
/// section cannot leak through this error path.
fn enforce_strict_config(cfg: &Config) -> anyhow::Result<()> {
    if cfg.unread_keys.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "--check --strict: {} config key(s) are not read by Warden: {}. No field of those \
         sections declares them, so the values in effect are Warden's defaults — the file does \
         not mean what it appears to. Check the section each key is really under (a deploy \
         marker block can leave keys orphaned in the section before it).",
        cfg.unread_keys.len(),
        cfg.unread_keys.join(", ")
    )
}

/// `true`/`false` as the operator reads them, for log lines that compare two
/// settings. Rust's `{:?}` on a bool would do this, but the sentence is about the
/// policy name, not the type.
fn yes_no(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

/// Whether the running responder has to be rebuilt after a reload.
///
/// Its own function because the answer is two comparisons and the bug this exists
/// to prevent is "one of them was left out": W-04 rebuilt only on a mode change,
/// and W2K-25 put a second policy on the same struct — a reload that changed only
/// that policy would keep enforcing the old one while the SIGHUP log announced the
/// config as applied. That shape cannot be pinned by reading this file's source
/// text from a test: the assertion's own string is in the same file, so the
/// anchor matches the test rather than the code (measured — it stayed green with
/// the term deleted). A table can be mutated, so the decision lives here.
fn responder_needs_rebuild(current: (Mode, bool), wanted: (Mode, bool)) -> bool {
    current.0 != wanted.0 || current.1 != wanted.1
}

fn unapplied_reload_changes(running: &Config, fresh: &Config) -> Vec<String> {
    let mut changes = unapplied_bridge_changes(running.bridge.as_ref(), fresh.bridge.as_ref());
    changes.extend(unapplied_heartbeat_changes(
        running.heartbeat.as_ref(),
        fresh.heartbeat.as_ref(),
    ));
    // W2K-13: the new ring size is real policy, but the ring itself is allocated
    // when its map is created, so a SIGHUP can only record the intention. Say so
    // the way [bridge] is said, rather than let the reload log imply the running
    // host has the larger ring. (`[runtime] enrich_cache_ms` is the opposite case
    // — the fresh detector picks it up immediately — so it is not listed here.)
    if running.runtime.ring_size_kib != fresh.runtime.ring_size_kib {
        changes.push(format!(
            "[runtime] ring_size_kib {} → {} (still {} KiB: the ring is sized at map creation)",
            running.runtime.ring_size_kib,
            fresh.runtime.ring_size_kib,
            running.runtime.ring_size_kib
        ));
    }
    // Phase 7: hook attachment is a load-time fact. A reload can flip the arm
    // slot and replace the rules, but it cannot attach to a different cgroup —
    // saying so prevents a new cgroup_path from reading as applied protection.
    if running.egress.enabled != fresh.egress.enabled
        || running.egress.cgroup_path != fresh.egress.cgroup_path
    {
        changes.push(format!(
            "[egress] enabled/cgroup_path changed (running enabled={}, path={:?}); hook \
             attachment happens at load, so restart Warden to move the cgroup hooks",
            running.egress.enabled, running.egress.cgroup_path
        ));
    }
    changes
}

/// Say once per policy load which `[protect]` selectors are weak and which
/// targets matched nothing.
///
/// F09: `comms` and comm-only targets are tripwire-only and are reported as
/// such. They cannot produce `Action::Refused`; kill immunity requires either
/// `protect_self`, a `cgroup_contains` match (pre-existing behavior), or an
/// anchored `[[protect.targets]]`. W-R4: a target that matches no live process
/// — an `exe` under `hidepid=`, a 15-byte-truncated comm, a uid nobody runs as —
/// protects nothing, and silence there reads as protection that does not exist.
fn log_protect_policy(protect: &config::Protect, resolved: &procscan::Resolution) {
    for (class, notice) in protect.selector_notices() {
        match class {
            config::ProtectSelectorClass::TripwireOnly => {
                log::warn!("[protect] {notice} — tripwire only; it cannot grant SIGKILL immunity")
            }
            config::ProtectSelectorClass::Ignored => log::warn!("[protect] {notice}"),
            config::ProtectSelectorClass::LooseImmunity => {
                // F09 deliberately leaves cgroup_contains immunizing. Calling
                // it tripwire-only would tell operators the wrong thing about
                // a real enforcement exemption.
                log::warn!(
                    "[protect] {notice} — loose but still immunizing; prefer an anchored target"
                )
            }
        }
    }
    if resolved.protected.is_empty() {
        log::warn!(
            "[protect] the immunity set is empty — nothing on this host may refuse a kill, \
             including Warden itself (protect_self=false, no cgroup_contains match and no \
             anchored selector matched). {} pid(s) remain in the tripwire-only alert set",
            resolved.tripwire_only_pids().len()
        );
    }
    if !resolved.unmatched_targets.is_empty() {
        log::warn!(
            "[protect] {} target(s) matched no live process, so they protect nobody: {}. \
             Every field a target names must match, and `uid` is the real uid.",
            resolved.unmatched_targets.len(),
            resolved.unmatched_targets.join("; ")
        );
    }
}

#[derive(Default)]
struct Stats {
    received: u64,
    undecodable: u64,
    findings: u64,
    /// Findings whose journal line was coalesced by `FindingLogThrottle`. The
    /// finding itself was still judged, responded to and delivered; only the
    /// duplicate log line was dropped.
    suppressed_logs: u64,
    // `shipped`/`ship_errors` used to live here, incremented synchronously around
    // the send. Delivery is asynchronous now, so a per-event result no longer
    // exists to count — the authoritative numbers come from `Deliverer::stats()`,
    // which can also say what is on disk, which these two never could.
}

/// Log the first finding of each `(actor, type)` per window, count the rest.
///
/// This is a journal-side throttle only: every finding is still judged,
/// answered by the responder and delivered to the bridge/spool. The reason to
/// have it is that journald rate-limits by service, so a storm of identical
/// lines can make systemd drop the *whole unit's* output — including findings
/// the operator has not seen yet and lines from other services. Coalescing at
/// the source keeps one representative line per burst and reports the count at
/// the next tick, so the journal never implies the repeats did not happen.
struct FindingLogThrottle {
    window: Duration,
    seen: HashMap<(u32, &'static str), Instant>,
}

/// Prune the throttle map once it holds more than this many actors. Above it,
/// stale entries are dropped on the periodic tick; below it, admission is one
/// hash lookup per finding.
const LOG_THROTTLE_PRUNE_AT: usize = 4096;

impl FindingLogThrottle {
    fn new(window: Duration) -> Self {
        Self {
            window,
            seen: HashMap::new(),
        }
    }

    fn admit(&mut self, actor: u32, kind: &'static str, now: Instant) -> bool {
        match self.seen.get(&(actor, kind)) {
            Some(&last) if now.duration_since(last) < self.window => false,
            _ => {
                self.seen.insert((actor, kind), now);
                true
            }
        }
    }

    fn prune(&mut self, now: Instant) {
        if self.seen.len() > LOG_THROTTLE_PRUNE_AT {
            let window = self.window;
            self.seen
                .retain(|_, last| now.duration_since(*last) < window);
        }
    }
}

/// Best-effort RLIMIT_MEMLOCK bump. Harmless if it fails (modern kernels with
/// memcg-accounted BPF don't need it); logged at debug.
fn bump_memlock() {
    let lim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit with a valid resource id and initialized struct.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
    if rc != 0 {
        log::debug!(
            "RLIMIT_MEMLOCK bump failed (usually fine): {}",
            std::io::Error::last_os_error()
        );
    }
}

/// A tiny epoll wrapper — just enough to block on the ring-buffer fd with a
/// timeout. We depend on libc already (for kill/signals), so no extra crate.
struct Epoll {
    fd: i32,
}

impl Epoll {
    fn new() -> anyhow::Result<Self> {
        // SAFETY: epoll_create1 with a valid flag; return value checked.
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { fd })
    }

    fn add(&self, target: i32) -> anyhow::Result<()> {
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: target as u64,
        };
        // SAFETY: valid epoll fd, valid target fd, initialized event struct.
        let rc = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, target, &mut ev) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Wait up to `timeout_ms`. EINTR (a delivered signal) returns Ok — the
    /// caller re-checks its flags on the next loop turn.
    fn wait(&self, timeout_ms: i32) -> anyhow::Result<()> {
        let mut evs = [libc::epoll_event { events: 0, u64: 0 }; 8];
        // SAFETY: valid epoll fd, buffer sized by evs.len().
        let rc =
            unsafe { libc::epoll_wait(self.fd, evs.as_mut_ptr(), evs.len() as i32, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(());
            }
            return Err(err.into());
        }
        Ok(())
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        // SAFETY: fd owned by us, closed exactly once at drop.
        unsafe { libc::close(self.fd) };
    }
}

/// Minimal argument parser — no clap, keeping the dependency tree tiny for a
/// privileged daemon.
/// `warden [--config PATH] [--check] [--doctor] [--health] [--explain KIND] [--event K=V] [--version] [--debug] [--socket-snapshot]`.
struct Args {
    config: Option<PathBuf>,
    check: bool,
    doctor: bool,
    /// The running agent's own state, read from `/proc` — see [`health`].
    health: bool,
    explain: Option<String>,
    /// The `--event key=value` fields, kept in order for the error messages and
    /// validated by [`explain::Request::parse`] — not here — because which keys
    /// exist is the detector's business, not the CLI's.
    event: Vec<String>,
    version: bool,
    debug: bool,
    socket_snapshot: bool,
    /// Turn `--check`'s unread-key WARNING into a hard failure. Off by default
    /// so a sensor never refuses to start over a typo; on for CI and the deploy
    /// gate, where an unread key means the file says one thing and Warden runs
    /// another. Never read without `--check`/`--doctor` (the parser refuses it).
    strict: bool,
    /// Machine-readable form of `--health`. Modifier only; a scraper can parse
    /// the same evidence-word claims the human view prints.
    json: bool,
    /// Replay 0600-dead-lettered findings into the spool after the Sentinel
    /// contract is fixed. Warden must be stopped first; see `deliver::replay_quarantine`.
    replay_quarantine: bool,

    // ── M16 configuration engine operations ───────────────────────────────
    /// Generate one of the five validated, capability-aware profiles.
    profile: Option<String>,
    /// Print the five profile contracts without generating a file.
    profile_list: bool,
    /// Dedicated configuration validator (human or `--config-json` output).
    config_validate: bool,
    /// Simulation of the policy that would be applied; never touches the kernel.
    config_plan: bool,
    /// Versioned migration of the TOML document, with backup and revalidation.
    config_migrate: bool,
    /// Write a secret-free state baseline for later drift comparison.
    config_baseline: Option<PathBuf>,
    /// Compare the current config/host state against a stored baseline.
    config_drift: Option<PathBuf>,
    /// Restore a verified configuration backup (paired with `--from`).
    config_rollback: bool,
    /// Source backup for `--config-rollback`.
    from: Option<PathBuf>,
    /// Target schema version for `--config-migrate`.
    target_version: Option<u32>,
    /// Read-only installation self-test with explicit statuses.
    self_test: bool,
    /// Machine-readable output for the read-only config-engine operations.
    config_json: bool,
}

/// The usage text, kept as a constant instead of inline in the match arm so a test
/// can assert that every mode the parser accepts is also documented here. A flag
/// that parses but is missing from `--help` is a flag no operator on a live host
/// will find — and `--health` is the one whose whole point is being reachable when
/// the daemon's own logs are not.
const HELP: &str = "\
warden [--config PATH] [--check] [--doctor] [--health] [--explain KIND] [--event KEY=VALUE] [--version] [--debug] [--socket-snapshot] [--replay-quarantine] [--strict] [--json] [--profile NAME] [--profile-list] [--config-validate] [--config-plan] [--config-migrate] [--config-baseline PATH] [--config-drift PATH] [--config-rollback --from BACKUP] [--target-version N] [--self-test] [--config-json]
\x20 --check: validate the config and print what policy would cover; writes nothing, never touches the kernel, and asks the resolver once only if an uplink is a NAME.
\x20 --strict: only with --check/--doctor/--config-validate — fail instead of warning when the file names a key this binary never reads (a silent policy mismatch). Off by default so a typo never blinds a live sensor; use it in CI.
\x20 --json: only with --health — print the same claims as JSON (schema warden.health.v1), including the UNVERIFIED `cannot see/` lines. Secret-free: a config parse error quoting an api_key line is redacted.
\x20 --doctor: the same lines, plus this host — kernel release, BTF, cgroup v2, and whether each volume fexit target exists here. Reads /proc and /sys, loads nothing.
\x20 --health: what a RUNNING agent can be seen to be from /proc — its pid, its comm and argv, its threads, whether its config file still parses, its signal handlers, its exe link. Cap-less: no bpf() syscall, no map read, nothing attached, no privilege taken. Every line carries one evidence word, and the things a /proc-only view CANNOT see (attach state, ring-buffer counters, the agent's in-memory policy) are printed as `cannot see/…` lines instead of estimated.
\x20 --explain KIND: ask what THIS config would say about an event that is not happening (exec, connect, listen, module, bpfload, mount, creds, signal, ptrace, file, service, access). Calls the same detector the agent calls, loads nothing, and names the knob that decided the answer. Feed the record with repeated --event key=value; --event without --explain is refused rather than dropped.
\x20 --version: the version and the digest of the embedded eBPF object, which is what identifies the object rather than its size.
\x20 --socket-snapshot: take one /proc/net snapshot, attribute it per policy, print the report and exit. Reads a world-readable file, loads no kernel object, needs no privilege.
\x20 --replay-quarantine: STOP warden first, then append findings Sentinel refused with a named HTTP 400 back to the spool for delivery on the next start. The dead-letter file is archived, never truncated. Do not run while warden is active — the sender holds the spool open.
\x20 --profile NAME: generate one canonical, validated configuration from essential|balanced|advanced|hardened (custom validates an existing file). Capability-aware: unsupported optional sensors stay off with a reason. No kill/denial is armed.
\x20 --profile-list: print the five profile contracts (features, prerequisites, risks, enforcement and degradation behavior) as JSON.
\x20 --config-validate: dedicated validator for the file named by --config. Reports exact fields, consequences and corrections; checks permissions, schema version, unread keys, capability mismatches and unsafe combinations. Use --config-json for machine-readable output.
\x20 --config-plan: SIMULATION of the config named by --config: enabled/disabled sensors, privileges, capabilities, risks and service actions. Makes no bpf() call and claims no attach.
\x20 --config-migrate --target-version 1: back up, validate, version and revalidate a config document. Idempotent; ambiguous versions are refused.
\x20 --config-baseline PATH: write a secret-free state baseline (content fingerprint, mode, schema, host capabilities, service state). Use --config-json for JSON.
\x20 --config-drift PATH: compare the current config and measured host facts against that baseline, naming unmeasured runtime state instead of guessing.
\x20 --config-rollback --from BACKUP: restore a validated configuration backup atomically. Refuses backups that arm kill/denial behavior; keeps a safety backup of the current file.
\x20 --self-test: read-only installation self-test with explicit PASS/FAIL/UNKNOWN/NOT_RUN/NOT_APPLICABLE statuses. Never loads BPF, starts services or contacts SENTINEL.
\x20 --config-json: machine-readable output for --profile, --profile-list, --config-validate, --config-plan, --config-drift and --self-test. It does not change --health's --json schema.";

impl Args {
    fn parse(mut it: impl Iterator<Item = String>) -> anyhow::Result<Self> {
        let mut config = None;
        let mut check = false;
        let mut doctor = false;
        let mut health = false;
        let mut explain = None;
        let mut event: Vec<String> = Vec::new();
        let mut version = false;
        let mut debug = false;
        let mut socket_snapshot = false;
        let mut strict = false;
        let mut json = false;
        let mut replay_quarantine = false;
        let mut profile = None;
        let mut profile_list = false;
        let mut config_validate = false;
        let mut config_plan = false;
        let mut config_migrate = false;
        let mut config_baseline = None;
        let mut config_drift = None;
        let mut config_rollback = false;
        let mut from = None;
        let mut target_version = None;
        let mut self_test = false;
        let mut config_json = false;
        while let Some(a) = it.next() {
            match a.as_str() {
                "--config" | "-c" => {
                    config = Some(PathBuf::from(
                        it.next()
                            .ok_or_else(|| anyhow::anyhow!("--config needs a path"))?,
                    ));
                }
                "--check" => check = true,
                "--doctor" => doctor = true,
                "--health" => health = true,
                "--explain" => {
                    explain = Some(
                        it.next()
                            .ok_or_else(|| anyhow::anyhow!("--explain needs an event kind"))?,
                    );
                }
                "--event" => {
                    event.push(
                        it.next()
                            .ok_or_else(|| anyhow::anyhow!("--event needs key=value"))?,
                    );
                }
                "--version" => version = true,
                "--debug" => debug = true,
                "--socket-snapshot" => socket_snapshot = true,
                "--strict" => strict = true,
                "--json" => json = true,
                "--replay-quarantine" => replay_quarantine = true,
                "--profile" => {
                    profile = Some(
                        it.next()
                            .ok_or_else(|| anyhow::anyhow!("--profile needs a profile name"))?,
                    );
                }
                "--profile-list" => profile_list = true,
                "--config-validate" => config_validate = true,
                "--config-plan" => config_plan = true,
                "--config-migrate" => config_migrate = true,
                "--config-baseline" => {
                    config_baseline =
                        Some(PathBuf::from(it.next().ok_or_else(|| {
                            anyhow::anyhow!("--config-baseline needs a path")
                        })?));
                }
                "--config-drift" => {
                    config_drift =
                        Some(PathBuf::from(it.next().ok_or_else(|| {
                            anyhow::anyhow!("--config-drift needs a baseline path")
                        })?));
                }
                "--config-rollback" => config_rollback = true,
                "--from" => {
                    from =
                        Some(PathBuf::from(it.next().ok_or_else(|| {
                            anyhow::anyhow!("--from needs a backup path")
                        })?));
                }
                "--target-version" => {
                    let raw = it
                        .next()
                        .ok_or_else(|| anyhow::anyhow!("--target-version needs a number"))?;
                    target_version = Some(raw.parse::<u32>().map_err(|_| {
                        anyhow::anyhow!("--target-version must be an integer, got {raw:?}")
                    })?);
                }
                "--self-test" => self_test = true,
                "--config-json" => config_json = true,
                "--help" | "-h" => {
                    println!("{HELP}");
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }
        // One question per run. `--check`, `--doctor` and `--socket-snapshot` all
        // print and return, so an `--explain` beside them would be dropped in
        // silence — the exact failure W2K-23 is about, in the argument parser
        // instead of the config file.
        if explain.is_some() && (check || doctor || health || socket_snapshot) {
            anyhow::bail!(
                "--explain cannot be combined with --check, --doctor, --health or \
                 --socket-snapshot: the others print and exit before it runs, so the answer you \
                 asked for would be the one you did not. Run them as separate commands."
            );
        }
        // The same rule on the other axis, and for the same reason: the four
        // print-and-return commands answer four DIFFERENT questions — the file
        // (`--check`), this kernel (`--doctor`), a process that is up right now
        // (`--health`), this netns's sockets (`--socket-snapshot`) — and `main` runs
        // them in a fixed order, so a combination silently reports only the first.
        if health && (check || doctor || socket_snapshot) {
            anyhow::bail!(
                "--health cannot be combined with --check, --doctor or --socket-snapshot: each \
                 answers a different question — the config file, this kernel, a running process, \
                 this namespace's sockets — and the first of them exits before the others run. \
                 Run them as separate commands."
            );
        }
        // `--strict` is a modifier on `--check`/`--doctor`, never a question of
        // its own. Typed alone or beside a mode that does not print the unread-key
        // audit, it would be silently ignored — the W2K-23 failure shape again.
        if strict && !(check || doctor || config_validate) {
            anyhow::bail!(
                "--strict only modifies --check, --doctor and --config-validate: without them there is no \
                 unread-key audit to make strict. Write `warden --check --strict`."
            );
        }
        if strict
            && (health || socket_snapshot || version || explain.is_some() || replay_quarantine)
        {
            anyhow::bail!(
                "--strict cannot be combined with --health, --socket-snapshot, --version, \
                 --explain or --replay-quarantine: only --check/--doctor/--config-validate run \
                 the unread-key audit it tightens."
            );
        }
        // `--json` only formats `--health`. Typed alone or beside another mode
        // it would be ignored, and a monitoring consumer would receive prose
        // where it expected JSON.
        if json && !health {
            anyhow::bail!(
                "--json only modifies --health: write `warden --health --json`. No other command \
                 has a JSON view, and silently ignoring the flag would feed a scraper prose."
            );
        }
        // Replay writes to the spool, so it must be the only question asked: a
        // combination with any print-and-exit mode would silently do one and skip
        // the other, the same class of bug W2K-23 names in the config parser.
        if replay_quarantine
            && (check
                || doctor
                || health
                || socket_snapshot
                || version
                || explain.is_some()
                || json)
        {
            anyhow::bail!(
                "--replay-quarantine cannot be combined with --check, --doctor, --health, \
                 --explain, --socket-snapshot, --version or --json: it mutates the spool and the \
                 others print and exit. Run them as separate commands."
            );
        }
        // W2K-23's shape again, one level down: `--event` is the record `--explain`
        // judges. Given beside anything else it would be read, kept in `Args`, and
        // never looked at — the silence this repo treats as a bug.
        if !event.is_empty() && explain.is_none() {
            anyhow::bail!(
                "--event feeds --explain, and no --explain was given: the fields would be read \
                 and then dropped in silence. Ask `--explain KIND --event key=value …`."
            );
        }
        // M16 config-engine operations answer one question per run. Without
        // this, a mistyped combination would print the first answer and drop
        // the rest — the same silent-loss rule the earlier flags enforce.
        let engine_ops = u8::from(profile.is_some())
            + u8::from(profile_list)
            + u8::from(config_validate)
            + u8::from(config_plan)
            + u8::from(config_migrate)
            + u8::from(config_baseline.is_some())
            + u8::from(config_drift.is_some())
            + u8::from(config_rollback)
            + u8::from(self_test);
        if engine_ops > 1 {
            anyhow::bail!(
                "only one configuration-engine operation may be given per run: use separate \
                 commands for --profile, --profile-list, --config-validate, --config-plan, \
                 --config-migrate, --config-baseline, --config-drift, --config-rollback and --self-test"
            );
        }
        if engine_ops > 0
            && (check
                || doctor
                || health
                || socket_snapshot
                || version
                || explain.is_some()
                || replay_quarantine)
        {
            anyhow::bail!(
                "configuration-engine operations cannot be combined with --check, --doctor, \
                 --health, --explain, --socket-snapshot, --version or --replay-quarantine: each \
                 answers a different question and the first would exit before the other ran"
            );
        }
        if config_json
            && !(profile.is_some()
                || profile_list
                || config_validate
                || config_plan
                || config_drift.is_some()
                || self_test)
        {
            anyhow::bail!(
                "--config-json formats --profile, --profile-list, --config-validate, --config-plan, \
                 --config-drift and --self-test only; --health uses --json, and mutating \
                 migration/rollback/baseline operations print an audit trail as text"
            );
        }
        if config_migrate && target_version.is_none() {
            anyhow::bail!("--config-migrate needs --target-version (this build supports 1)");
        }
        if config_rollback && from.is_none() {
            anyhow::bail!("--config-rollback needs --from BACKUP");
        }
        if from.is_some() && !config_rollback {
            anyhow::bail!("--from only modifies --config-rollback");
        }
        if target_version.is_some() && !config_migrate {
            anyhow::bail!("--target-version only modifies --config-migrate");
        }

        Ok(Args {
            config,
            check,
            doctor,
            health,
            explain,
            event,
            version,
            debug,
            socket_snapshot,
            strict,
            json,
            replay_quarantine,
            profile,
            profile_list,
            config_validate,
            config_plan,
            config_migrate,
            config_baseline,
            config_drift,
            config_rollback,
            from,
            target_version,
            self_test,
            config_json,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bridge(toml_src: &str) -> config::Bridge {
        toml::from_str(toml_src).unwrap()
    }

    fn heartbeat(toml_src: &str) -> config::Heartbeat {
        toml::from_str(toml_src).unwrap()
    }

    /// The table behind the SIGHUP rebuild. Written after the source-text anchor
    /// for the same rule was measured to be vacuous — it stayed green with
    /// `|| fresh_require_anchored != old_require_anchored` deleted, because the
    /// needle it searched for is itself a string in this file.
    #[test]
    fn the_responder_is_rebuilt_when_either_setting_moves() {
        // (mode, require_anchored_identity)
        let anchored_enforce = (Mode::Enforce, true);
        assert!(
            !responder_needs_rebuild(anchored_enforce, anchored_enforce),
            "nothing moved: no rebuild, and no reload line claiming one"
        );
        assert!(
            responder_needs_rebuild(anchored_enforce, (Mode::Observe, true)),
            "a mode change alone must rebuild — the W-04 case"
        );
        assert!(
            responder_needs_rebuild(anchored_enforce, (Mode::Enforce, false)),
            "the anchoring policy alone must rebuild — the W2K-25 case, which W-04 \
             would have logged as applied while keeping the old responder"
        );
        assert!(
            responder_needs_rebuild(anchored_enforce, (Mode::Observe, false)),
            "both moved at once"
        );
        assert!(
            responder_needs_rebuild((Mode::Observe, false), (Mode::Observe, true)),
            "opting back into the safe policy from the permissive one is also a change"
        );
    }

    #[test]
    fn the_policy_log_words_a_bool_the_way_the_config_file_does() {
        // The SIGHUP line prints `require_anchored_identity {} → {}`; if it printed
        // Rust's Debug for a bool the operator would read a different vocabulary
        // than the one they type into warden.toml.
        assert_eq!(yes_no(true), "true");
        assert_eq!(yes_no(false), "false");
    }

    /// The CLI is a contract with the operator, and `--socket-snapshot` is the one
    /// flag that runs Warden's userspace-only path: it must parse, and an argument
    /// that does not exist must still be refused rather than silently ignored.
    #[test]
    fn the_socket_snapshot_flag_parses_and_an_unknown_one_still_bails() {
        let a = Args::parse(vec!["--socket-snapshot".to_string()].into_iter()).unwrap();
        assert!(a.socket_snapshot);
        assert!(!a.check, "the snapshot gate is not --check");
        assert!(!a.debug);

        let a = Args::parse(
            vec![
                "-c".to_string(),
                "/tmp/w.toml".to_string(),
                "--debug".to_string(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(!a.socket_snapshot, "off unless asked for");
        assert_eq!(
            a.config.as_deref(),
            Some(std::path::Path::new("/tmp/w.toml"))
        );

        let err = Args::parse(vec!["--socket-snapshots".to_string()].into_iter())
            .err()
            .map(|e| e.to_string())
            .expect("a misspelled flag must be refused, not ignored");
        assert!(err.contains("unknown argument"), "{err}");
    }

    /// `--doctor` and `--version` are the two flags an operator reaches for when
    /// something does not add up, so they have to exist in the parser, and
    /// `--doctor` must not silently mean `--check`: the host section is the whole
    /// reason it is a different flag.
    #[test]
    fn the_doctor_and_version_flags_parse_and_are_distinct() {
        let a = Args::parse(vec!["--doctor".to_string()].into_iter()).unwrap();
        assert!(a.doctor);
        assert!(!a.check, "--doctor is not --check");
        assert!(!a.version);
        assert!(!a.socket_snapshot, "the doctor loads nothing itself");

        let a = Args::parse(vec!["--version".to_string()].into_iter()).unwrap();
        assert!(a.version);
        assert!(!a.doctor);

        // Both at once is the shape a script gets wrong; it must still parse, and
        // the run order (version, then check-or-doctor) is what decides output.
        let a =
            Args::parse(vec!["--version".to_string(), "--doctor".to_string()].into_iter()).unwrap();
        assert!(a.version && a.doctor);

        for misspelled in ["--doctorr", "--versions", "--docto"] {
            let err = Args::parse(vec![misspelled.to_string()].into_iter())
                .err()
                .map(|e| e.to_string())
                .expect("a misspelled doctor/version flag must be refused, not ignored");
            assert!(err.contains("unknown argument"), "{err}");
        }
    }

    /// `--health` is the fourth print-and-return question, and the only one about a
    /// process that is up right now. Three things have to hold: it parses and stays
    /// distinct from the other modes; a misspelling is refused rather than quietly
    /// starting the daemon (the worst possible outcome of a typo in a flag name, and
    /// the reason `other => bail!` exists); and it refuses the company of the other
    /// print-and-return commands exactly like `--explain` does, so no answer is ever
    /// dropped in silence. The `--version` + `--health` pair is allowed to parse
    /// because the run order — version first, then health — decides, same as the
    /// 20a case above.
    #[test]
    fn the_health_flag_parses_stays_distinct_and_refuses_company() {
        let a = Args::parse(vec!["--health".to_string()].into_iter()).unwrap();
        assert!(a.health);
        assert!(!a.check, "--health is not --check");
        assert!(!a.doctor, "--health is not --doctor");
        assert!(!a.socket_snapshot, "--health takes no snapshot");
        assert!(!a.version);
        assert!(a.explain.is_none(), "--health explains no hypothetical");
        assert!(a.config.is_none(), "no --config means the agent's own path");

        // The path is kept, not dropped: the report names a --config that this
        // command does not use, instead of pretending the flag was never typed.
        let a = Args::parse(
            vec![
                "--config".to_string(),
                "/tmp/other.toml".to_string(),
                "--health".to_string(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert!(a.health);
        assert_eq!(
            a.config.as_deref(),
            Some(std::path::Path::new("/tmp/other.toml"))
        );

        let a =
            Args::parse(vec!["--version".to_string(), "--health".to_string()].into_iter()).unwrap();
        assert!(a.version && a.health);

        for other in ["--check", "--doctor", "--socket-snapshot"] {
            let err = Args::parse(vec!["--health".to_string(), other.to_string()].into_iter())
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| panic!("--health beside {other} must be refused, not ignored"));
            assert!(err.contains("--health cannot be combined"), "{err}");
        }

        // And from the other side: a dry run beside --health must not be the answer
        // that gets dropped.
        let err = Args::parse(
            vec![
                "--explain".to_string(),
                "exec".to_string(),
                "--health".to_string(),
            ]
            .into_iter(),
        )
        .err()
        .map(|e| e.to_string())
        .expect("--explain beside --health must be refused");
        assert!(err.contains("--explain cannot be combined"), "{err}");

        for misspelled in ["--healthh", "--healt", "--health-check", "--running"] {
            let err = Args::parse(vec![misspelled.to_string()].into_iter())
                .err()
                .map(|e| e.to_string())
                .expect("a misspelled health flag must be refused, not ignored");
            assert!(err.contains("unknown argument"), "{err}");
        }
    }

    #[test]
    fn strict_is_a_modifier_of_check_and_doctor_only() {
        let a =
            Args::parse(vec!["--check".to_string(), "--strict".to_string()].into_iter()).unwrap();
        assert!(a.check && a.strict);
        assert!(HELP.contains("--strict"));

        let a =
            Args::parse(vec!["--doctor".to_string(), "--strict".to_string()].into_iter()).unwrap();
        assert!(a.doctor && a.strict);

        // A modifier with no question to modify, or beside a mode that never
        // runs the unread-key audit, would be read and dropped in silence.
        for args in [
            vec!["--strict"],
            vec!["--strict", "--health"],
            vec!["--strict", "--socket-snapshot"],
            vec!["--strict", "--version"],
            vec!["--strict", "--replay-quarantine"],
        ] {
            let err = Args::parse(args.iter().map(|s| s.to_string()))
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| panic!("{args:?} must refuse --strict"));
            assert!(err.contains("--strict"), "{err}");
        }
    }

    #[test]
    fn strict_check_fails_on_unread_keys_and_passes_on_a_clean_file() {
        let dir = std::env::temp_dir().join(format!("warden-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("warden.toml");

        // Clean: every key is read -> strict passes.
        std::fs::write(&path, "mode = \"observe\"\n").unwrap();
        let clean = config::Config::load(&path).unwrap();
        assert!(clean.unread_keys.is_empty());
        enforce_strict_config(&clean).expect("a fully-read config must pass --check --strict");

        // One orphaned key -> strict fails, and the error names the KEY, never
        // any value (an api_key in an orphaned table must not leak).
        std::fs::write(
            &path,
            "[respond]\nkill_reverse_shell = false\nspool_path = \"/tmp/moved.jsonl\"\n\
             api_key = \"SUPER-SECRET-MUST-NOT-LEAK\"\n",
        )
        .unwrap();
        let dirty = config::Config::load(&path).unwrap();
        assert!(!dirty.unread_keys.is_empty());
        let err = enforce_strict_config(&dirty)
            .err()
            .map(|e| e.to_string())
            .expect("an unread key must fail --check --strict");
        assert!(err.contains("spool_path"), "{err}");
        assert!(err.contains("api_key"), "{err}");
        assert!(
            !err.contains("SUPER-SECRET-MUST-NOT-LEAK"),
            "the error leaked a value: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_is_a_modifier_of_health_only() {
        let a =
            Args::parse(vec!["--health".to_string(), "--json".to_string()].into_iter()).unwrap();
        assert!(a.health && a.json);
        assert!(HELP.contains("--json"));

        for args in [
            vec!["--json"],
            vec!["--check", "--json"],
            vec!["--json", "--doctor"],
            vec!["--json", "--socket-snapshot"],
            vec!["--json", "--version"],
        ] {
            let err = Args::parse(args.iter().map(|s| s.to_string()))
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| panic!("{args:?} must refuse --json"));
            assert!(err.contains("--json"), "{err}");
        }
    }

    #[test]
    fn replay_quarantine_is_a_flag_of_its_own() {
        let a = Args::parse(vec!["--replay-quarantine".to_string()].into_iter()).unwrap();
        assert!(a.replay_quarantine);
        assert!(!a.check && !a.doctor && !a.health && !a.socket_snapshot);
        assert!(HELP.contains("--replay-quarantine"));

        // It mutates the spool; pairing it with a print-and-exit mode would
        // silently do one and skip the other.
        for other in [
            "--check",
            "--doctor",
            "--health",
            "--socket-snapshot",
            "--version",
        ] {
            let err =
                Args::parse(vec!["--replay-quarantine".to_string(), other.to_string()].into_iter())
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| panic!("replay beside {other} must be refused"));
            assert!(
                err.contains("--replay-quarantine cannot be combined"),
                "{err}"
            );
        }
    }

    /// W2K-23's rule applied to the parser: a flag whose only consumer is another
    /// flag must not be silently accepted when that other flag is absent. `--event`
    /// feeds `--explain`, so alone it would be read, stored, and never looked at.
    #[test]
    fn an_event_record_without_the_question_it_belongs_to_is_refused() {
        let err = Args::parse(
            vec![
                "--event".to_string(),
                "path=/bin/bash".to_string(),
                "--check".to_string(),
            ]
            .into_iter(),
        )
        .err()
        .map(|e| e.to_string())
        .expect("--event without --explain must be refused, not dropped");
        assert!(err.contains("--event feeds --explain"), "{err}");

        // Same with --health, where the temptation is to think the fields describe a
        // live process: they describe a hypothetical, and --health reads /proc.
        let err = Args::parse(
            vec![
                "--health".to_string(),
                "--event".to_string(),
                "pid=1".to_string(),
            ]
            .into_iter(),
        )
        .err()
        .map(|e| e.to_string())
        .expect("--event beside --health must be refused too");
        assert!(err.contains("--event feeds --explain"), "{err}");

        // The pair the refusal exists to protect still works.
        let a = Args::parse(
            vec![
                "--explain".to_string(),
                "exec".to_string(),
                "--event".to_string(),
                "path=/bin/bash".to_string(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(a.event, vec!["path=/bin/bash".to_string()]);
    }

    /// Every mode the parser accepts must also be in the usage text: a flag that
    /// parses but is undocumented is a flag nobody on a live host will find, and a
    /// documented flag that was renamed away is a lie about the CLI.
    #[test]
    fn the_usage_text_names_every_flag_the_parser_accepts() {
        for flag in [
            "--config",
            "--check",
            "--doctor",
            "--health",
            "--explain",
            "--event",
            "--version",
            "--debug",
            "--socket-snapshot",
        ] {
            assert!(HELP.contains(flag), "`{flag}` parses but is not in --help");
        }
        // `--health`'s own promise, in the place an operator reads it before the
        // output exists: the cap-less claim and the declared blind spots.
        let health_line = HELP
            .lines()
            .find(|l| l.trim_start().starts_with("--health"))
            .expect("--health documented");
        assert!(health_line.contains("no bpf() syscall"), "{health_line}");
        assert!(health_line.contains("cannot see/"), "{health_line}");
        assert!(health_line.contains("RUNNING"), "{health_line}");
    }

    /// `--explain` takes a kind and any number of `--event key=value` pairs, and
    /// it is the one command whose answer depends on the config being loaded — so
    /// the parser must keep the pairs and must refuse being paired with a command
    /// that prints and returns (`--check`, `--doctor`, `--health`,
    /// `--socket-snapshot`), which would otherwise drop the dry run silently.
    #[test]
    fn explain_takes_a_kind_and_its_event_pairs_and_refuses_to_be_second() {
        let a = Args::parse(
            vec![
                "--explain".to_string(),
                "connect".to_string(),
                "--event".to_string(),
                "dest=203.0.113.7:443".to_string(),
                "--event".to_string(),
                "proto=tcp".to_string(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(a.explain.as_deref(), Some("connect"));
        assert_eq!(a.event.len(), 2, "repeated --event accumulates");
        assert_eq!(a.event[0], "dest=203.0.113.7:443");
        assert!(!a.check && !a.doctor && !a.socket_snapshot);

        // A kind is not optional: an empty dry run has no answer to give.
        let err = Args::parse(vec!["--explain".to_string()].into_iter())
            .err()
            .map(|e| e.to_string())
            .expect("--explain without a kind must be refused");
        assert!(err.contains("needs an event kind"), "{err}");

        // The value is required too, or `--event` would swallow the next flag.
        let err = Args::parse(
            vec![
                "--explain".to_string(),
                "exec".to_string(),
                "--event".to_string(),
            ]
            .into_iter(),
        )
        .err()
        .map(|e| e.to_string())
        .expect("--event without key=value must be refused");
        assert!(err.contains("--event needs"), "{err}");

        // One question per run: beside a print-and-return command the dry run
        // would never be reached.
        for other in ["--check", "--doctor", "--health", "--socket-snapshot"] {
            let err = Args::parse(
                vec![
                    "--explain".to_string(),
                    "exec".to_string(),
                    other.to_string(),
                ]
                .into_iter(),
            )
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| panic!("--explain beside {other} must be refused, not ignored"));
            assert!(err.contains("--explain cannot be combined"), "{err}");
        }

        // The kind token itself is not validated here — `explain::Request::parse`
        // owns that, because the list of kinds and their keys is one table.
        let a =
            Args::parse(vec!["--explain".to_string(), "nonsense".to_string()].into_iter()).unwrap();
        assert_eq!(a.explain.as_deref(), Some("nonsense"));
    }

    #[test]
    fn an_unchanged_restart_required_section_reports_nothing() {
        // The warning has to stay silent when there is nothing to warn about, or
        // it becomes the noise an operator learns to skip.
        let b = bridge("url = \"http://c:9000/x\"\napi_key = \"k\"\n");
        let h = heartbeat("url = \"http://hb:9000/b\"\n");
        assert!(unapplied_bridge_changes(Some(&b), Some(&b)).is_empty());
        assert!(unapplied_heartbeat_changes(Some(&h), Some(&h)).is_empty());
        assert!(unapplied_bridge_changes(None, None).is_empty());
        assert!(unapplied_heartbeat_changes(None, None).is_empty());
    }

    #[test]
    fn a_repointed_bridge_url_is_named() {
        // W-R7: the expensive misreading is "SIGHUP said reloaded, so findings go
        // to the new collector now". Naming the field is what prevents it.
        let a = bridge("url = \"http://old:9000/x\"\napi_key = \"k\"\n");
        let b = bridge("url = \"http://new:9000/x\"\napi_key = \"k\"\n");
        assert_eq!(
            unapplied_bridge_changes(Some(&a), Some(&b)),
            vec!["[bridge] url".to_string()]
        );
    }

    #[test]
    fn several_changed_bridge_fields_are_reported_together() {
        let a = bridge("url = \"http://c:9000/x\"\napi_key = \"k\"\ntimeout_ms = 5000\n");
        let b = bridge("url = \"http://d:9000/x\"\napi_key = \"k\"\ntimeout_ms = 1000\n");
        assert_eq!(
            unapplied_bridge_changes(Some(&a), Some(&b)),
            vec!["[bridge] url, timeout_ms".to_string()]
        );
    }

    #[test]
    fn a_changed_api_key_is_named_but_never_printed() {
        // The value must not reach the journal — naming it is the whole fix, and
        // printing it would make the warning a credential leak.
        let a = bridge("url = \"http://c:9000/x\"\napi_key = \"OLD-CREDENTIAL\"\n");
        let b = bridge("url = \"http://c:9000/x\"\napi_key = \"NEW-CREDENTIAL\"\n");
        let changes = unapplied_bridge_changes(Some(&a), Some(&b));
        assert_eq!(changes, vec!["[bridge] api_key".to_string()]);
        assert!(
            !changes[0].contains("CREDENTIAL"),
            "value leaked: {changes:?}"
        );
    }

    #[test]
    fn a_changed_heartbeat_secret_is_named_but_never_printed() {
        let a = heartbeat("url = \"http://hb:9000/b\"\nsecret = \"OLD-SHARED\"\n");
        let b = heartbeat("url = \"http://hb:9000/b\"\nsecret = \"NEW-SHARED\"\n");
        let changes = unapplied_heartbeat_changes(Some(&a), Some(&b));
        assert_eq!(changes, vec!["[heartbeat] secret".to_string()]);
        assert!(!changes[0].contains("SHARED"), "value leaked: {changes:?}");
    }

    #[test]
    fn adding_or_removing_a_consumer_needs_a_restart_too() {
        // Enable-then-reload is the case an operator is most likely to try: the
        // uplink they just configured is exactly the one that will not start.
        let b = bridge("url = \"http://c:9000/x\"\napi_key = \"k\"\n");
        let h = heartbeat("url = \"http://hb:9000/b\"\n");
        assert_eq!(unapplied_bridge_changes(None, Some(&b)).len(), 1);
        assert_eq!(unapplied_bridge_changes(Some(&b), None).len(), 1);
        assert_eq!(unapplied_heartbeat_changes(None, Some(&h)).len(), 1);
        assert_eq!(unapplied_heartbeat_changes(Some(&h), None).len(), 1);
    }

    #[test]
    fn duplicate_findings_are_logged_once_per_window() {
        let mut t = FindingLogThrottle::new(Duration::from_secs(10));
        let t0 = Instant::now();
        assert!(t.admit(7, "endpoint:file_tamper", t0));
        assert!(!t.admit(7, "endpoint:file_tamper", t0 + Duration::from_secs(1)));
        // A different actor or a different finding type is still its own line.
        assert!(t.admit(8, "endpoint:file_tamper", t0 + Duration::from_secs(1)));
        assert!(t.admit(7, "endpoint:mount", t0 + Duration::from_secs(1)));
        // The window is exclusive at its end: the first line may reappear.
        assert!(t.admit(7, "endpoint:file_tamper", t0 + Duration::from_secs(10)));
    }

    #[test]
    fn the_log_throttle_forgets_stale_actors_when_it_grows() {
        // Same failure mode the file-burst map had: one entry per pid forever.
        // The tick's prune must clear actors whose last line is outside the
        // window once the map is large enough to justify the walk.
        let mut t = FindingLogThrottle::new(Duration::from_secs(1));
        let t0 = Instant::now();
        for pid in 0..LOG_THROTTLE_PRUNE_AT as u32 + 512 {
            assert!(t.admit(pid, "endpoint:file_tamper", t0));
        }
        assert!(t.seen.len() > LOG_THROTTLE_PRUNE_AT);
        t.prune(t0 + Duration::from_secs(5));
        assert!(t.seen.is_empty());
    }
}
