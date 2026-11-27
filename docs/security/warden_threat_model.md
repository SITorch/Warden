# WARDEN threat model and security-coverage reconciliation (M02)

Status of this document: **IMPLEMENTED (analysis), VALIDATED against source, NOT live-validated in this pass**.

This is a source-driven threat model of the tree in `Warden/`, reconciled on
2026-11-22. Every "existing coverage" entry names the actual hook, rule or test
that was read. Statements about what an attached hook does on a running kernel
remain historical unless the current pass executed the privileged test suite;
this pass is unprivileged (`EUID=1000`, `CapEff=0x0`). The machine-checkable
coverage contract is `docs/security/warden_coverage_matrix.md`; this document
explains *adversaries, trust boundaries and the meaning of that coverage*.

## 1. Security objective and non-objectives

WARDEN is a **host detection agent with a narrow in-kernel denial primitive**.
It is not a firewall, not an anti-virus product, not a kernel integrity system,
and not a tamper-proof guard against an attacker who already owns ring 0.

What it can do, when correctly deployed:

1. Observe kernel-scheduled events (exec, signal, ptrace, socket operations,
   accepted flows, module/BPF/mount activity, destructive file operations) with
   process and cgroup attribution from the kernel hook context.
2. Correlate those events into explainable findings with bounded behavioral
   state (per-actor bursts, local beaconing) and no automated kill by default.
3. Optionally deny a small, explicitly enumerated set of file accesses by
   `(dev, ino)` via BPF-LSM, and optionally deny exact egress destinations for
   one validated, isolated cgroup via cgroup socket-address programs.
4. Report findings durably to SENTINEL and report *its own* sensor degradation
   rather than appearing healthy while blind.

What it explicitly cannot do: inspect packet payloads, see DNS queries, read TLS
SNI/ALPN, see QUIC metadata, guarantee C2 detection, protect against arbitrary
kernel compromise, or observe sockets inside every container network namespace.

## 2. Adversaries and assumptions

| # | Adversary | Assumed capabilities | What WARDEN can do | Limit |
|---|---|---|---|---|
| A1 | Remote attacker with code execution inside the application | App UID, app cgroup, ordinary syscalls | Detect shell/interpreter chains (`judge_exec`, `shell_comms` checked against exe **and** filename, never comm alone), unsanctioned dials (`judge_connect`, C2 tracker), destructive file bursts (`judge_file`), persistence creates (`judge_service`) | A process that never triggers a hooked operation is invisible; app-UID-only rules cannot distinguish a malicious sibling if the app cgroup is unset |
| A2 | Compromised web worker | A1 + legitimate request context | Same as A1; cgroup-scoped rules suppress normal peers; `PROTECT_TARGET` identities bind pid to start time | In-process compromise without child processes or dials produces no host event |
| A3 | Compromised database worker | A1 + legitimate DB traffic | Same telemetry; egress allowlist narrows what is "expected" | DB-initiated network noise can dominate the finding stream; port alone is not protocol evidence |
| A4 | Unprivileged local user | Own UID, no root | Detect file-create/ransom extensions/bursts by any actor for watched names, fileless exec, listens | File modification hooks observe rename/unlink/create; **not** a full write-integrity system; user systemd paths require the configured directories |
| A5 | Malicious process sharing the app UID | Can forge `comm`, can rename itself | Identity checks use `/proc/<pid>/exe`, resolved filename, `(dev,ino)`, cgroup and start time; comm is consulted last and recorded as `matched_by` | If exe is unreadable and cgroup is unconfigured, identity confidence is reduced and reported as such, never upgraded |
| A6 | Privileged attacker with partial capabilities (e.g. CAP_SYS_PTRACE) | Ptrace/inspect protected process | `WARDEN_PTRACE` reports ATTACH as High regardless of reader identity; metadata READ by outsiders is Medium | READs by a sanctioned reader can be demoted only when the kernel-resolved exe/cgroup prove it; an ATTACH is never silenced |
| A7 | Root-level userspace attacker | UID 0, can kill userspace, edit config | File guard denies selected intents on pinned inodes even for root when `allow_root=false`; file/permission/immutable-style operations are reported; heartbeat absence is detectable off-box | Root can unload BPF if LSM lockdown is absent, disable the daemon, replace the config, or reboot. Kernel tamper is **reported, not prevented** |
| A8 | Container escape attempt | Container UID, access to mounts | `security_sb_mount` sensor with source allowlist, exemption carve-outs keyed on resolved exe, and non-bypassable raw-device/docker-sock sources | Mount sensor is observe-only; no container runtime metadata; no host-network completeness for container netns |
| A9 | Attacker disabling monitoring | Signals, ptrace, config edits, service edits | Signal/ptrace sensors keyed to `ProtectTarget`, persistence-create monitoring of systemd paths, integrity of config load (transactional reload), heartbeat gap alarm off-box | Local watchdog alone is insufficient; an attacker with full root can stop both. No self-reported health is accepted as proof of safety |
| A10 | Attacker modifying security policy | Edit config, flip egress arm | `[[enforce.guarded_files]]` can protect the config/unit/binary; egress reload is disarm→verify→clear→re-arm with rollback; `--check` reports live state | Protection requires operator to configure guards and arm them; defaults are shadow/observe |
| A11 | Identity manipulator (pid/name/path reuse) | Rename, fork-bomb, exec deleted images | Kernel-stamped exe `(dev,ino)`, pid+starttime cache keys, pidfd liveness checks, deleted-exe detection, restriction of kill to anchored identities | PID namespace transitions and pid reuse outside the cached window are only partially observable; `/proc` can be hidden |
| A12 | Namespace concealer | Enter mount/net/user namespaces | FLOW records socket netns inode; cgroup id is monotone and comes from the hook; exe identity is kernel-stamped | `/proc/net` pull path is host-namespace only; no Docker API dependency by design; veth attribution unknown |
| A13 | Kernel-level attacker (loadable module/eBPF rootkit) | Ring 0 | `module_load` and `security_bpf` sensors emit findings; BPF program type gate distinguishes implant-capable loads; guarded inodes still deny some file operations | **No prevention.** A kernel attacker can hide events, detach links, replay or drop records. Documentation must never claim tamper-proofness |

## 3. Trust boundaries

1. **Kernel → agent.** The ring-buffer record is evidence from the hook context.
   The kernel timestamp (`ts_ns`) is monotonic; userspace must label it as such
   and never replace it with its own processing clock. The kernel's `(dev,ino)`
   of the executable is stronger than a `/proc` path read milliseconds later.
   Because the ring is per-CPU, record order is not timestamp order: the C2
   tracker rejects a zero stamp or a sample older than that actor's last one
   rather than subtracting intervals backwards (`src/c2.rs`).
2. **Agent → enforcement maps.** Configuration is *not* policy truth. Truth is
   what was written to, and read back from, the BPF map plus the verified attach
   state. A missing cgroup identity never authorizes enforcement.
3. **Agent → SENTINEL.** The bridge is an authenticated delivery hop (shared key
   or optional mTLS), not an identity authority. An `agent_id` field is a label
   until a unique per-agent credential is verified by the collector. The clock
   lineage in the envelope (`observed_at_unix_ms`, `kernel_event_ts_ns`,
   `kernel_event_unix_ms` and the two clock labels) is stored in the sealed
   backend record; ingest refuses a label that contradicts those fields, but
   this is contract validation, not proof that the agent's clock was correct.
4. **Host network namespace → container netns.** Push sensors are global; the
   `/proc/net` snapshot is not. Absence from the snapshot is not evidence of
   absence of traffic.
5. **Process name → process identity.** `comm` is user-controlled. Trust order
   is kernel-stamped exe inode > resolved exe path > exec filename > comm.
6. **File path → inode.** Guards match `(dev,ino)`, not paths. Renames, hardlinks
   and namespace-relative paths cannot change which inode is protected. A
   replacement file is a new inode and must be re-pinned by the refresh loop.
7. **Local health → remote confirmation.** A heartbeat generated by the process
   under attack is weak evidence; the alarm is the *absence* observed off-box.
8. **Observed fact → heuristic conclusion.** A TCP dial to port 443 is a dial to
   port 443. It is not evidence of HTTPS, SNI or payload contents. Findings keep
   observed facts and heuristic labels in separate, versioned fields.

## 4. Attack coverage matrix (MITRE ATT&CK Linux)

Status labels follow the mission's shared vocabulary. `VALIDATED` here means a
structural/focused test in this tree, **not** a privileged live attack test.

| Technique | Existing coverage (source evidence) | Evidence / test | Limitation | Improvement | Prevention | Validation |
|---|---|---|---|---|---|---|
| T1059.004 Unix Shell | `detect.rs::judge_exec` + `shell_comms` matched against exe, filename and comm in that order; staged-exec rule | `src/detect.rs` (`shell_identity`, `staged_in_untrusted_dir`), shell tests in `detect.rs` | Only fires on execve; a shell that never execs an external command is not seen. `comm` fallback is spoofable but labelled `matched_by` | Correlate shell exec with subsequent dial/persistence events in the temporal engine | None (observe only) | Spawn `sh -c` from an app-cgroup worker in a VM → High `endpoint:process_creation` with kernel `source_ts_ns` |
| T1562.001 Impair Defenses | `WARDEN_SIGNAL`/`WARDEN_PTRACE` sensors on protected targets; `WARDEN_BPFLOAD` and `WARDEN_MODULE`; file-guard on binary/unit/config; heartbeat gap | `bpf/warden.bpf.c` `security_task_kill`, `security_ptrace_access_check`, `security_bpf`, `module_load`; `src/detect.rs` `judge_signal/judge_ptrace/judge_bpf` | Local kill/unload by root cannot be denied; self-reported health is not proof; heartbeat requires external collector | BPF link/map integrity verification and external health status in the envelope | Only for protected files when armed; signal/modules are report-only | Send SIGTERM to protected pid in VM → `endpoint:self_tamper`; stop agent → off-box missed-heartbeat alert |
| T1543.002 Systemd Service | `WARDEN_SERVICE` from `security_inode_create` with a 4-component path ladder; `[service_rules].persistence_dirs` | `bpf/warden.bpf.c` `security_inode_create`; `detect.rs::judge_service`; config shipped defaults | **Creation only**; modification of an existing unit is not covered by this sensor | Add inode-create *and* guarded modification coverage for unit paths | None (report only) | `touch /etc/systemd/system/evil.service` → `endpoint:new_service` |
| T1053.003 Cron | Same `WARDEN_SERVICE` path ladder matches `/cron`, `crontab` | `config/warden.toml` `[service_rules].persistence_dirs`; `detect.rs::judge_service` | crontab edits via temp-file rename can evade a create-only rule; user crontab directories vary by distro | Track rename/unlink into persistence dirs and correlate with later exec | None | Write a file under `/etc/cron.d/` → Critical `endpoint:new_service` |
| T1548.001 Setuid/Setgid | `commit_creds` sensor emits `WARDEN_CREDS` on euid→0 or capability gain; exe identity gates allowlisted privilege daemons | `bpf/warden.bpf.c` `kprobe/commit_creds`; `detect.rs::judge_creds` | Does **not** observe chmod/setuid bit changes themselves; only the resulting credential transition | Add setattr watch for mode changes on executable paths (guard hook exists, decoder carries intent) | None | `sudo -u app /bin/sh` from worker → `endpoint:privilege_change` with capability names |
| T1071 Application Layer Protocol | CONNECT destination/port + bounded beaconing assessment with explicit unsupported-input matrix | `src/c2.rs` `input_support_matrix()`; `detect.rs::judge_connect` | No payload, DNS, SNI, ALPN or QUIC. Port 443 is never called HTTPS. Confidence deliberately capped | Jitter-tolerant beacon analysis (this pass) | None | Synthetic periodic dials in lab → C2 finding with `input_support_matrix` showing DNS/TLS/FlowBytes unsupported |
| T1095 Non-Application Layer Protocol | CONNECT with family/protocol byte; beaconing labels T1095 for non-web ports and for port 53 | `src/c2.rs` technique mapping; `tests/network_coverage_matrix.rs` | Protocol byte is `sk_protocol`, not payload classification; port 53 evidence capped at 0.65 | Keep T1071.004 unsupported until a DNS transaction source exists | None | Regular dials to unusual TCP port → T1095 finding |
| T1571 Non-Standard Port | Destination port in CONNECT/LISTEN; egress allowlist and listen allowlist | `src/egress.rs`, `detect.rs::judge_listen` | A port number alone is not malicious; no service/protocol baseline exists | Add per-service destination/port baseline with minimum-observation threshold | Only via explicit egress policy in a validated cgroup | Listen on unexpected port in app cgroup → High `endpoint:listen` |
| T1059 / script chains (extension) | Exec filename including interpreters; staged executable location | `config/warden.toml` `shell_comms` includes perl/ruby; `detect.rs` | No argv capture, so `python -c` has no payload context | Correlate interpreter exec with file and network events in the temporal engine | None | `python3 /tmp/x.py` in app cgroup → exec finding |
| T1021 / T1072 lateral inbound (extension) | `inet_accept` kretprobe → FLOW with peer + netns inode | `bpf/warden.bpf.c` `inet_accept`; `tests/accept_flow_abi.rs` | No close, duration or bytes; journal-only in current detector to avoid ~4/s finding flood | Correlate FLOW with later egress/volume anomalies | None | Connect to a test listener → FLOW record with correct netns |
| T1486 Data Encrypted for Impact (extension) | Rename/unlink LSM sensors, per-actor burst window, ransom extension suffixes | `src/detect.rs::judge_file`, `[file_rules]` | Only rename/unlink/create; no generic write hook; burst threshold is app-scoped by default | Correlate bursts with persistence writes | None | 50 renames in 5 s by app actor in VM → High finding |
| T1547Boot/Logon Autostart (extension) | Same as T1543/T1053 with XDG autostart, init.d, rc.local, ld.so.preload patterns | `[service_rules]` defaults | Modification of an existing autostart file is out of scope of create-only telemetry | Guard selected persistent files by inode | None | Write `~/.config/autostart/x.desktop` → finding |

## 5. Reconciliation with current architecture

- **Prevention** exists only in two places: six BPF-LSM guards keyed by inode
  (`arm=false` by default, shadow-first) and four cgroup socket-address hooks
  (`enabled=false` by default, require a validated isolated cgroup v2 target).
- **Detection** is deterministic rules plus bounded behavioral counters. There
  is no trained model and no external ML dependency.
- **Reporting** covers every sensor's attach and drop state through
  `src/telemetry.rs`, with `UNKNOWN` instead of zero where a reading is absent.
- **Evidence status:** the structural claims above are checked by the tests in
  `Warden/tests/`; privileged attach/enforce outcomes require the isolated VM
  procedure in `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` and are not claimed here.

## 6. Mission 16 configuration/install boundary

The new surface is policy authoring and installation, not a new kernel capability.
The following additions apply to the trust boundaries above:

| Threat | M16 control | Residual / honesty note |
|---|---|---|
| Unprivileged user edits security policy because the config is group/world writable | `--config-validate` reports group/world write as an error when credentials are present and as a warning otherwise; `--self-test` fails it; installer writes new config as `0640` | The repository sample remains `0664` as historical user-owned work; operators must set `0640 root:warden` on deployed files. Validation never edits permissions silently. |
| Operator believes an unread key took effect | unread keys are reported with field names only; `--config-validate --strict` makes them fatal in CI; values are never printed in errors | Normal daemon startup remains non-fatal for unread keys so a typo does not blind a sensor. |
| Generated profile silently arms killing, LSM denial or cgroup egress denial | all four generated profiles are `mode=observe`, all responders off, `enforce.arm=false`, `egress.enabled=false`, `egress.arm=false`; no guarded path or uid is invented | Arming remains a separate, explicit operator action after reviewing shadow findings. |
| Planner overstates host capability | capability states are `VERIFIED`, `UNAVAILABLE`, `UNSUPPORTED` or `UNKNOWN`; `bpf_syscall` is always `UNKNOWN` because the planner does not call `bpf()`; volume requires every measured prerequisite to be verified | The planner reports for the process that runs it. A root daemon can have a stronger perf gate than an unprivileged operator; `M16_10` records exactly that split. Do not turn the planner's `UNKNOWN` into a pass. |
| Migration corrupts a live policy | validate before write, timestamped backup, atomic replace preserving mode, reload validation, restore on failure, idempotent when already at target | Back up the whole `/etc/warden` directory too; schema migration is not a backup of unrelated operator edits. |
| Rollback re-arms a dangerous policy | rollback validates the source and refuses backups with kill responders, `enforce.arm` or `egress.arm`; it writes a new safety backup of the current file | A safe-by-validation backup can still be outdated. Check content drift and health after restore. |
| Installer changes more than intended | preview by default; explicit `INSTALL`/`--yes`; `/tmp`-only `--test-mode`; existing config preserved on reinstall and uninstall; `systemctl` only with `--enable-service` | `--unattended` and `--replace-config` are operator authority; the script does not second-guess them beyond backups. |
| Drift report leaks secrets | baselines store a non-cryptographic content fingerprint, mode, schema and capability/service state; no config body or credential | The fingerprint answers “did it change?”, not authenticity; keep the baseline file itself writable only by the operator. |
| Two Warden instances interfere during privileged testing | the agent warns with pid, exe and identity strength; M16 tests used a throwaway config path and exact PID cleanup while the installed service stayed active | Co-residency is a known measurement perturbation and is stated wherever VM performance numbers are reported. Production should run one agent per host unless deliberately designed otherwise. |
