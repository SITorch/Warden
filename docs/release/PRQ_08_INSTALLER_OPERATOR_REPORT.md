# WARDEN-PRQ-01 — Phase 8 Installer & Operator Experience Report

status=`PASS_WITH_LIMITATIONS` for the packaged CLI/installer; `NOT_RUN` for a
real installation on a production or staging host.

## 1. Installation paths shipped

WARDEN keeps **one** installation mechanism (no second config engine, no
rewritten installer). Two entry points exist on top of the same binary, sample
config, and systemd units:

| Entry point | Behaviour | Default posture |
|---|---|---|
| `make install` | Installs `target/release/warden` to `/usr/local/sbin/warden`, sample policy to `/etc/warden/warden.toml` (mode `0640`; existing policy preserved as `warden.toml.sample`), two systemd units to `/etc/systemd/system`, and README + the two machine-checked docs to `/usr/local/share/doc/warden`. Does not enable or start the service. | Observe-only sample; no bridge, no denial, no kill |
| `make install-wizard PROFILE=balanced` → `scripts/install_wizard.sh` | Guided, idempotent preview-first installer. Without `--yes`/`--unattended` it writes nothing. Supports `--prefix`, `--config-dir`, `--unit-dir`, `--doc-dir`, `--replace-config`, `--enable-service`, `--self-test`, `--uninstall`, and `--test-mode`. | Preview-first; existing config preserved; no secret printed |
| `scripts/test-privileged.sh` | Explicit 0=PASS / 1=FAIL / 77=SKIP runner for the ignored in-kernel BPF-LSM case. Disposable VMs only. | `SKIP` unless root + `CAP_BPF` + `bpf` LSM + object all present |

`--test-mode` refuses any target outside `/tmp` (`warden-install: ERROR:
--test-mode targets must all be under /tmp: /usr/local` when invoked without
explicit temp targets) — a deliberate guard against accidental writes.

## 2. Operator CLI surface (read-only by default)

| Command | What it actually does | Boundary it states |
|---|---|---|
| `--check [--strict]` | Validates config, prints what policy would cover; writes nothing, loads no BPF, one resolver lookup at most. | Never claims an attach |
| `--doctor` | Adds this host's kernel release, BTF, cgroup v2, perf gate, and per-fexit-hook presence. | Hook *presence* is not attach; three evidence levels are named |
| `--health [--json]` | `/proc`-only view of a running agent; one evidence word per claim; `cannot see/…` lines for kernel state. | No `bpf()` call, no map read, no privilege |
| `--version` | Version + FNV-1a of the object compiled into **this** binary. | Not the object a running agent loaded |
| `--self-test [--json]` | Read-only installation report with `PASS`/`FAIL`/`UNKNOWN`/`NOT_RUN`/`NOT_APPLICABLE`. | Never loads BPF, starts services, or contacts SENTINEL |
| `--profile NAME` / `--profile-list` | Generates or describes one of `essential|balanced|advanced|hardened|custom`. | No kill/denial armed by any profile |
| `--config-validate` / `--config-plan` | Strict field/consequence validator; simulation of sensor/privilege/service actions. | Plan makes no `bpf()` call and claims no attach |
| `--config-baseline` / `--config-drift` / `--config-rollback` | Secret-free state baseline, honest drift comparison, atomic restore of a validated backup. | Rollback refuses backups that arm kill/denial |
| `--explain KIND --event k=v` | Asks what this config *would* say about an event that is not happening. | Names the deciding knob; loads nothing |
| `--socket-snapshot` | One `/proc/net` snapshot attributed per policy. | World-readable file; no privilege; samples, not a stream |
| `--replay-quarantine` | Re-appends SENTINEL-refused findings from the archived dead-letter file. | Refuses to run while the service is active |

## 3. Self-test results on this host

Two runs were captured, both from the current checkout:

| Run | Result |
|---|---|
| `warden --self-test` with no `--config` (uses `/etc/warden/warden.toml`) | **exit 1** — `configuration FAIL`: the operational sample does not validate on this host; every other check passes/skips honestly |
| `warden --self-test --config config/warden.example.toml` | **exit 0** — `configuration PASS_WITH_WARNINGS` (empty app cgroup), `configuration_permissions PASS` (mode `0640`) |

Both runs report `artifact_integrity PASS` for the public Alpha object (1,243,656
bytes, FNV-1a `0xbc288747047b4edb`), `NOT_RUN` for kernel sensor load, runtime
startup, and local event pipeline, and `NOT_APPLICABLE` for SENTINEL
connectivity (no bridge configured). This is a useful honesty property: an
unconfigured host is not reported as a healthy deployment.

Note for operators: the historical in-repository `config/warden.toml` is an
operational sample, not a safe starting policy. Its permissions were corrected
from `0664` to `0640` in PRQ, but its contents are host-specific. The public
example is `config/warden.example.toml`.

## 4. Shipped service units

| Unit | Role | Notable property |
|---|---|---|
| `systemd/warden.service` | Main agent | Drops privileges, seccomp filter, `AmbientCapabilities`, resource limits; `Documentation=` points at shipped docs |
| `systemd/warden-deadman@.service` | Optional watchdog | Operators must understand its restart contract before use; not enabled by the installer |

`make install` installs both units with mode `0644` but does **not** run
`systemctl enable`/`start`. Enabling is an explicit operator action
(`--enable-service` on the wizard, or manual `systemctl`).

## 5. Evidence

| Evidence | Result |
|---|---|
| `scripts/tests/test_config_engine_cli.sh` | exit 0 `PASS` (gate evidence `PRQ_03_BUILD_GATES.txt`) |
| `scripts/tests/test_install_wizard.sh` | exit 0 `PASS` (same gate evidence) |
| `warden --config-validate --strict` on both configs | exit 0 `PASS_WITH_WARNINGS` |
| `--self-test` with public example | exit 0, statuses shown above |
| `--self-test` with default operational sample | exit 1, `configuration FAIL` — truthful, not hidden |

## 6. Limitations

| Limitation | Status |
|---|---|
| No installation to a clean/staging system was performed | `NOT_RUN` |
| Service enable/start, SIGHUP reload, and deadman restart behaviour were not exercised live | `NOT_RUN` |
| Uninstall was exercised only in the script's own tests, not on a host | `PARTIAL` |
| Privileged runtime qualification via the shipped runner | `SKIP` (exit 77) on this host |
| `--self-test` cannot see attach state, ring counters, or in-memory policy | `PASS` (it says so explicitly) |

## 7. Decision

The installer and operator CLI are contributor- and operator-ready for a public
Alpha: safe defaults, preview-first writes, no invented success states, and
honest `NOT_RUN`/`SKIP` statuses. Live deployment qualification is a separate,
still-open activity.
