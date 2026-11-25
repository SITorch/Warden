# WARDEN-PRQ-FINAL-02 — Final Enforcement Proof

status=`PARTIAL`. Representative armed cases now have disposable-VM proof on the
exact FINAL-02 candidate: one BPF-LSM pre-opened-fd case, armed cgroup egress
TCP4/UDP4/TCP6 denial with a non-match control, and one armed kill-takedown
case. The full hook matrices, additional kernels, forced E-09 insert refusal and
production qualification remain open. Prepared 2026-11-24.

## 1. Isolation and recovery prerequisites

| Prerequisite | Observed status |
|---|---|
| Disposable VM identity | `debian13`, UUID `1118cc9f-c1bf-4a94-bd6e-dec23a1884ab`, hostname `debian` |
| Console / out-of-band access | libvirt serial/console PTY defined; SSH verified with passwordless sudo |
| Kernel / LSM | Debian 13, `6.12.107+deb13-amd64`; active LSM list includes `bpf`; `CAP_BPF` present under sudo |
| Exact candidate | Source synced to the VM; shipped BPF object SHA-256 `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`; release binary built there |
| Fresh FINAL-02 snapshot | `PASS` — `prq_final2_baseline` created after cleaning superseded VM copies; reverted with `--running --force` before the armed runs |
| Recovery verification | `PASS` — after revert the VM was `running`, SSH worked, kernel release was unchanged, BPF SHA matched and the release binary was present |
| Earlier snapshot failure | Historical, superseded: initial `prq_final2_baseline` save failed with `Input/output error` at 97% guest disk use; the disk was cleaned and a new snapshot was created and verified |
| Host exposure | No armed program, test process, cgroup or netns was created on the active development host; only the disposable VM was used |
| Service/config rollback | Pre-existing observe-mode service was stopped for the LSM run; VM snapshot is the rollback path. No host or production config was changed |

Raw prerequisite, snapshot and post-revert captures are listed as private raw
evidence in `PRQ_FINAL_EVIDENCE_INDEX.md`; they are not published.

## 2. BPF-LSM — current candidate

`scripts/test-privileged.sh` was run as root in the VM with `RUSTUP_HOME` and
`CARGO_HOME` set so the privileged ignored test could execute. It returned
`0` (`PASS`), not `77` (`SKIP`).

| Check | Current-source result |
|---|---|
| Preconditions | `PASS` — root, `CAP_BPF`, active `bpf` LSM and shipped object all present |
| Privileged test | `a_preopened_fd_loses_write_access_when_the_guard_is_armed ... ok` |
| Observed denial | `read(2)`, `write(2)`, `ftruncate(2)` and `fchmod(2)` through a descriptor opened *before* arming all returned `-EPERM` after `runtime_cfg` was armed and guarded inodes were installed |
| Attach evidence | Two LSM programs loaded and attached (`file_permission`, `inode_setattr`) |
| Other four hooks (`file_open`, `mmap_file`, `inode_unlink`, `inode_rename`) | Implemented and structurally frozen by `tests/capability_matrix.rs`; individual armed cases remain `NOT_RUN` |
| Allowed action, event content, unrelated-file control, reload, disarm, writable mapping | `NOT_RUN` |

An earlier attempt failed only because root had no rustup default toolchain
(`cargo exit 1`, script `exit 1`). It is recorded as an environment failure and
not counted as an enforcement result. The successful rerun is the evidence.

## 3. Four cgroup egress hooks — current candidate

`scripts/phase6_privileged_validation.sh` ran as root in a throwaway network
namespace and cgroup v2 leaf. No host egress path or production service was
used.

| Check | Current-source result |
|---|---|
| Hook attach / arm read-back | `PASS` — `egress enforcement: ARMED, hooks 4/4 attached (cgroup/connect4, cgroup/connect6, cgroup/sendmsg4, cgroup/sendmsg6), policy generation 2 (3 rule(s), ready=true)` |
| `traffic.shadow_allows` | `PASS` — `CONNECT_OK`; `shadow_deny=1` recorded in `egress_stats` |
| `traffic.armed_denies_tcp4` | `PASS` — `CONNECT_ERR:1` (`EPERM`) |
| `traffic.armed_denies_udp4_sendmsg` | `PASS` — `SEND_ERR:1` (`EPERM`) |
| `traffic.armed_denies_tcp6` | `PASS` — `CONNECT_ERR:1` (`EPERM`) |
| `traffic.armed_allows_other_port` | `PASS` — `CONNECT_OK`; exact-rule negative control |
| `counter.armed_denial` | `PASS` — `armed_denied=1` in the agent log |
| Config guardrails | `PASS` — `arm=true` with `enabled=false` refused; root cgroup refused; empty config accepted |
| Direct UDP6 datagram (`cgroup/sendmsg6`) | `NOT_RUN` — hook attached, but no direct UDP6 send case was executed |
| Forced E-09 insert refusal / `map_full` | `NOT_RUN` — regressions pass; no live refused insert was produced |

Two harness classifications are recorded explicitly and are **not** counted as
passes:

- `traffic.baseline_no_agent` reported `EXECUTED AND FAILED` with
  `CONNECT_ERR:111` because the throwaway listener had not bound at the fixed
  1-second sleep. Later traffic to the same listener succeeded in shadow and
  armed modes.
- `traffic.armed_attach` reported `BLOCKED BY ENVIRONMENT` because the harness
  greps for the stale literal `SIGHUP: egress arm=true`. The current binary logs
  `SIGHUP: egress reload B enabled→enabled: ... egress enforcement: ARMED`.
  The kernel-verified ARMED state is present in the separate log read-back.

Egress enforcement remains scoped to the attached cgroup, not a host firewall.
UDP counters are per operation, not per packet, and IPv6 socket-path numbers are
not wire traffic.

## 4. Kill responder — current candidate

A throwaway Warden instance ran with `mode=Enforce`,
`kill_takedown_attacker=true`, `require_anchored_identity=true`, all other
`kill_*` flags false and `[enforce] arm=false`. A throwaway `sleep` victim was
allowed to enter Warden's protected set before a Python actor sent it `SIGTERM`.

| Check | Current-source result |
|---|---|
| Protected-set refresh | `PASS` — victim pid pushed before the signal |
| Takedown | `PASS` — victim died and the exact actor pid was killed by Warden via `pidfd_send_signal` |
| Log evidence | `PASS` — `ENFORCED: SIGKILL → pid 97457 (python3) via pidfd_send_signal [takedown attempt: ... sent SIGTERM to protected pid 97147 via kill]` and `[critical] endpoint:self_tamper ... (action=killed)` |
| PID reuse / exclusions / other `kill_*` flags / repeated events / disarm | `NOT_RUN` |
| `kill(2)` fallback TOCTOU (R-09) | `NOT_RUN` specifically; pidfd path is the one proven here |

The first probe was inconclusive because the signal preceded the protected-set
refresh; it is preserved as provenance and not counted. No real SSH, database,
Wallet, signer or systemd process was targeted.

## 5. Default-safety regression

Static and config-validation checks still establish: `mode = observe`,
`enforce.arm = false`, kill off, egress disabled/unarmed and no bridge in the
public example. The egress VM run additionally observed a live SIGHUP reload
from SHADOW to ARMED with policy generation 2 and verified kernel writes.

No stale armed policy was created on the host: no armed test ran there.
Post-arm disarm, reboot persistence and clean-host service recovery remain
`NOT_RUN`.

## 6. Unexecuted tests

- Remaining BPF-LSM hooks and their allowed/denied/event/unrelated/reload/disarm
  cases — `NOT_RUN` for the current source.
- Writable mappings created before arming — `NOT_RUN`.
- Direct UDP6 egress, exhaustive cgroup scope, repeated reload/disarm and forced
  E-09 insert refusal — `NOT_RUN` for the current source.
- Kill identity reuse, exclusions, other responder flags, repeated attempts and
  disarm — `NOT_RUN`.
- Default safety after armed reload/reboot/disarm — `NOT_RUN`.
- Any kernel or distribution other than Debian 13 `6.12.107+deb13-amd64` —
  `UNKNOWN`.

## 7. Decision

The FINAL-02 candidate has **representative lab proof**, not full enforcement
qualification. The successful VM cases are `PASS` for what they executed; the
unexecuted cases above stay `NOT_RUN` or `UNKNOWN`. Historical Phase 6 armed
egress evidence is retained with its provenance and does not replace the new
current-source run. Production remains `NOT QUALIFIED` / `BLOCKED`; nothing here
authorizes deployment, SENTINEL integration or publication.
