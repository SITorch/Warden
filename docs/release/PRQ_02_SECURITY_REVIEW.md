# WARDEN-PRQ-01 — Phase 2 Security Review

status=`PASS_WITH_LIMITATIONS` — four confirmed defects were fixed and verified;
hardening items remain documented, not fixed. Static review only: no hostile
input fuzzing, no privileged enforcement test, and no external penetration test.

## 1. Method and scope

Read-only static review of the Rust agent and eBPF C source at PRQ HEAD
`e4d5f7adea0f957d37c70dbc162782583a0ce01c`, plus documentation claim
verification against M15/M16 evidence. Four parallel audits were performed:
Rust security, eBPF/kernel, documentation contradictions, and
supply-chain/license. No files were modified by the auditors; fixes were applied
afterwards by PRQ.

## 2. Confirmed defects and fixes

| # | Severity | Defect | Fix | Verification |
|---|---|---|---|---|
| 1 | Medium | `health.rs::redact_secrets()` masked only double-quoted `api_key` values; literal/multiline TOML strings and the human-readable health output could carry a credential quoted by a parse error. | Replaced with a line-oriented redactor covering eight credential-key names and all string forms; applied to **both** human and JSON output at the single `report()` entry point. | 2 new unit tests; full suite green |
| 2 | Medium | `loader.rs::set_enforce_arm()` warned but still wrote `CFG_ENFORCE_ARM=1` and returned `Ok(())` when no BPF-LSM program was attached — `arm=true` could be reported while nothing would deny. | Fail closed: arm now bails out unless `enforce_arm_effective()` (LSM attached **and** guarded-inode map handle live). Disarming remains allowed for recovery. Added `enforce_arm_effective()` for telemetry. | Build/clippy/full suite green |
| 3 | Medium | `loader.rs::sync_guarded_inodes()` ignored stale-key removal errors with `let _ = …` and returned `want.len()` regardless of actual kernel state. | Removal errors are collected and returned as an error; success count is read back from the live map rather than the desired set. | Build/clippy/full suite green |
| 4 | Low | `tls.rs::last_error()` matched the raw `SSL_read`/`SSL_write` return against `SSL_ERROR_*` codes instead of calling `SSL_get_error(ssl, ret)`, making clean-close/want-read/want-write branches unreachable. | Added the `SSL_get_error` FFI binding and classify properly; preserve `WouldBlock`/`TimedOut`. | Build/clippy/full suite green |

A fifth defect ( privileged test `SKIP` counted as `ok` ) was a test-integrity
issue rather than a runtime security bug; see `PRQ_02_TEST_SEMANTICS_FIX.txt`
and `PRQ_03_BUILD_REPRODUCIBILITY_REPORT.md`.

## 3. Hardening items — documented, not fixed

These require a deployment/attacker precondition not established by source
alone. They are tracked in `PRQ_02_RUST_RISK_REGISTER.md` and
`WARDEN_KNOWN_LIMITATIONS.md` and are **not** claimed as remediated.

| Priority | Item | Why not fixed in PRQ |
|---|---|---|
| High (conditional) | Daemon `Config::load()` does not enforce the validator's own config permission/ownership check; symlinked config paths are not rejected | Needs a security decision on deployment ownership model; changing load behaviour could break existing installs |
| Medium | Spool open/parent dirs follow symlinks; `set_permissions` follows symlinks | Requires a storage-layout change and migration testing |
| Medium | Spool compaction uses predictable `<spool>.tmp` without `O_EXCL` | Requires a compaction rewrite and crash-consistency tests |
| Medium | `kill(2)` fallback when pidfd is unavailable leaves a check-to-signal TOCTOU window | Needs a kernel-version policy decision (fail closed vs operate) |
| Medium | CRLF/control characters not rejected in bridge/heartbeat host, path, and `api_key` header interpolation | Requires a request-builder refactor and regression tests |
| Medium | Inode-keyed guarding: atomic replacement changes the inode until `PROTECT_REFRESH` re-stats | Bounded, documented gap; closing it needs filesystem-event driven re-resolution |
| Low | DNS resolution in the delivery worker has no deadline | Needs a timeout helper integration and tests |
| Low | `bump_memlock()` logs failure only at debug | Cosmetic/operational; no security boundary crossed |

## 4. eBPF-side findings (summary; full register in `PRQ_02_EBPF_RISK_REGISTER.md`)

- Live BPF-LSM/cgroup denial on `7.0.0-15-generic` was claimed without evidence;
  the claim was downgraded to capability/readiness only.
- Ring-loss ratio was never reset on a clean/unreadable tick, so one lossy
  window could degrade C2 confidence indefinitely. (Documented; not fixed —
  requires detector state-machine change.)
- BPF-LSM attachment is all-or-nothing in userspace, but partial links stay
  live while the guarded-inode map handle is dropped. (Documented; not fixed.)
- cgroup/sock_addr return-convention **prose** was inverted (code is correct).
  (Documented; not fixed — comment-only.)
- UDP accounting is per `sendmsg`/`recvmsg` operation, not per packet/datagram.
  Docs now say so.
- IPv6 volume status reconciled to `LIVE_VALIDATED_M15` with the
  socket-path-not-wire boundary.
- Ring-buffer drop counter measures reserve failures only, not end-to-end loss.
- Internal kprobe targets (`__inet_stream_connect`, `inet_accept`) fail closed,
  limiting CO-RE portability.

## 5. Misleading-success states — before vs after

| State | Before | After |
|---|---|---|
| `enforce.arm=true` with no LSM | Warn + write slot + `Ok(())` | Hard error; slot stays shadow |
| Guarded-inode reconcile with stale removals failing | Desired count reported | Error returned; live count read back |
| Health JSON secret-free claim | Only double-quoted `api_key` masked | All credential forms masked in human + JSON |
| Privileged test unexecuted | Printed `SKIP`, counted as `ok` | `#[ignore]`d; explicit `SKIP`/exit 77 runner |
| TLS clean close / want-read | Misclassified as generic OpenSSL error | Correctly classified via `SSL_get_error` |

## 6. Capability boundaries that must remain in docs

- Observational `kprobe`/`kretprobe`/`tracepoint`/`fexit` programs **never deny**,
  including the one named `kprobe/security_socket_connect`.
- Only six `lsm/*` programs can deny file/inode access, and only when the `bpf`
  LSM is active, the program attached, `guarded_inodes` populated, and
  `CFG_ENFORCE_ARM=1`.
- Only four `cgroup/sock_addr` programs can deny egress, and only when attached,
  armed, and matched by an exact rule. Their convention is `1=allow, 0=deny`;
  syscall-visible `-EPERM` comes from the kernel after a `0` return.
- Detection findings, including C2 cadence, never block traffic and never set
  `wants_kill`.
- IPv6 volume is IPv6-**socket-path** accounting, not all IPv6 wire traffic.

## 7. Status summary

| Area | Status |
|---|---|
| Confirmed defect remediation | `PASS` |
| Regression tests for fixes | `PASS` |
| Hardening queue documented | `PASS` |
| Live enforcement security proof | `NOT_RUN` (disposable VM required) |
| External penetration test | `NOT_RUN` |
| Overall security review | `PASS_WITH_LIMITATIONS` |
