# WARDEN-PRQ-FINAL-02 — Final Security Verification

status=`PASS_WITH_LIMITATIONS` for static verification and defect closure;
representative armed VM cases now `PASS` for the current candidate, with the
full runtime matrix still `NOT_RUN` / `PARTIAL`. Prepared 2026-11-24.

## 1. Method

Three independent read-only audits were performed against the current working
tree (no files modified by the auditors, no privileged tests executed during
those audits). Later disposable-VM armed cases are documented separately in
`docs/release/PRQ_FINAL_ENFORCEMENT_PROOF.md`.

| Audit | Scope | Result |
|---|---|---|
| Rust / runtime security | `events.rs`, `respond.rs`, `loader.rs`, `tls.rs`, `hmac.rs`, `deliver.rs`, `bridge.rs`, `health.rs`, `guard.rs`, `main.rs` | No new undocumented defect; documented residuals R-06…R-13 re-verified |
| eBPF implementation | `bpf/warden.bpf.c`, `bpf/warden.h`, `loader.rs`, `egress.rs`, `guard.rs`, `events.rs` | One new observability defect (E-09) found and fixed; other findings already documented |
| Documentation truth | `README.md`, `DESIGN.md`, `SECURITY.md`, PRQ decision reports, M16 evidence | Seven real inaccuracies found and corrected |

PRQ-01/02 fixes were independently re-verified as present: health secret
redaction, BPF-LSM arm fail-closed, guarded-inode reconciliation, TLS
`SSL_get_error` classification, and privileged-test skip semantics.

## 2. Confirmed defect fixed — E-09

| Field | Record |
|---|---|
| Problem | `WARDEN_EGRESS_MAP_FULL` (slot 3 of `egress_stats`) was defined, read, and used to gate an operator warning, but never written. A refused deny-rule insert could not appear in telemetry; `map_full=0` was indistinguishable from "failures are not counted". |
| Source | `bpf/warden.h:545-550`; `bpf/warden.bpf.c:1989-2005`; `src/egress.rs:47,492-506`; `src/main.rs:1494-1506` |
| Explanation | Kernel paths increment slots 0–2; userspace insert failures returned an error without recording it. Enforcement still failed safe (rollback, `ready=false`, degraded preflight); the defect was false reassurance in monitoring, not a fail-open. |
| Correction | Added `EgressStatsWriter` for `Array<MapData,u64>` with checked increment and read-back of slot 3; added `sync_with_stats()` and `apply_egress_reload_with_stats()`; production callers in `src/loader.rs` pass the real map handle. The count is incremented exactly once at the refused insert, before rollback. No new dependency, hook, map or subsystem. |
| Regression | `refused_insert_records_a_single_map_full_counter`, `refused_insert_during_reload_records_a_single_map_full_counter`, `successful_sync_does_not_record_a_map_full_counter`; existing rollback tests unchanged. |
| Result | `cargo test --offline --locked --bin warden egress::tests` → 22 passed / 0 failed / 637 filtered out, exit 0. `cargo clippy --all-targets --all-features --offline --locked -- -D warnings` → exit 0. `cargo check --all-targets --offline --locked` → no code warnings. |
| Residual risk | Userspace counter can be tampered with by an attacker already able to manipulate the agent; no live armed insert-refusal was produced. |

## 3. Confirmed coverage gap fixed — redirect classification

`classify()` already refused 3xx, but the table-driven test did not assert
301/302/307/308. Added them to the `Refused` set in
`src/bridge.rs::status_classification_matches_the_retry_contract`. Targeted
test: 1 passed / 0 failed / 658 filtered out, exit 0. No runtime logic changed.
Residual risk: a future redirect-following client must re-run the test.

## 4. Documentation corrections

Seven inaccuracies were fixed: conditional/default-local Sentinel bridge
(`README.md`, `DESIGN.md`); kill and fd-effect code-only with live `NOT_RUN`;
privileged runner scoped to pre-opened-fd LSM; `[enforce]` one of two denial
axes; historical `DESIGN.md` status header; `0640` sample permissions; M16 VM
work was observe-only, armed egress proof belongs to earlier Phase 6 VM
(`SECURITY.md`, `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md`,
`WARDEN_KNOWN_LIMITATIONS.md`, `WARDEN_PRODUCTION_QUALIFICATION.md`,
`PRQ_06_ENFORCEMENT_QUALIFICATION.md`).

Those seven corrections were accurate when recorded; the later VM run has
since exercised one pre-opened-fd LSM case, representative armed egress cases
and one kill-takedown case. Those narrow results do not upgrade the full
matrices or the production decision.

All six mandatory limitations remain preserved and machine-checked in
`docs/security/`: IPv6 socket-path ≠ wire traffic; C2 cadence ≠ malice; egress
denial ≠ host firewall; guarded files are explicit-policy only; temporary
observer ≠ all installs; local collector self-test ≠ real backend delivery.

## 5. Verified capability truth and defaults

`--check` does not claim attach; `--self-test` does not contact SENTINEL;
`--doctor` reports presence, not attach; `--health` is `/proc`-only with
`cannot see/…` for kernel state. Defaults: `mode = observe`,
`enforce.arm = false`, kill off, `[egress] enabled = false, arm = false`, no
bridge in the public example, config mode `0640`.

## 6. Risk register

| Risk | Severity | Implementation evidence | Test evidence | Residual risk | Decision |
|---|---|---|---|---|---|
| Config load skips validator mode/symlink checks (R-06) | High, conditional | `src/config.rs:2282-2292` vs `config_engine.rs:780-803` | Not functionally tested | Local actor can alter policy | Documented Alpha limitation |
| Spool open/permission repair follows symlinks (R-07) | Medium | `src/deliver.rs:285-310` | Not functionally tested | Spool redirection/exposure | Documented |
| Predictable `.tmp` without `O_EXCL` (R-08) | Medium | `src/deliver.rs:442-480` | Not functionally tested | Local race can lose spool state | Documented |
| `kill(2)` fallback TOCTOU (R-09) | Medium, conditional | `src/respond.rs:503-515` | pidfd takedown `PASS` in VM; fallback, PID reuse and exclusions `NOT_RUN` | Wrong-process SIGKILL | Documented; representative pass only |
| CR/LF in request headers (R-10) | Medium | `src/bridge.rs:785-797` | Not injected | Header injection via config | Config permission boundary |
| Inode-key guard lag (R-11) | Medium, bounded | `src/guard.rs:110-161`, `loader.rs:1347-1400` | Not functionally tested | One refresh window | Documented bound |
| Resolver has no deadline (R-12) | Low | `src/bridge.rs:633-643` | Not functionally tested | Delivery stall / spool growth | Documented |
| RLIMIT_MEMLOCK only debug-logged (R-13) | Low | `src/main.rs:2133-2145` | Not injected | Poor diagnosability | Documented |
| Egress insert-refusal telemetry (E-09, fixed) | Low, closed for code | `src/egress.rs`, `loader.rs` | 3 new tests pass; clippy clean | No live armed refusal | `PASS` (code), live `NOT_RUN` |
| 3xx regression gap (fixed) | Low, closed for code | `src/bridge.rs` | 1 targeted test passes | Future refactor | `PASS` (code) |
| Full armed LSM/cgroup/kill matrix for current source | High | Architecture present, defaults off | Representative VM cases `PASS`; remaining cases `NOT_RUN` | Full semantics, other kernels and recovery unproven | Production blocker |
| Local root attacker | High | No claim against unrestricted root | Not tested | Root can unload/reconfigure BPF | Out of trust boundary |

Zero risk is not claimed.

## 7. Gate summary

Static review `PASS`; defects fixed with regression evidence `PASS`; safe
defaults `PASS`; documentation truth `PASS` after corrections; representative
armed VM proof `PASS`; full armed matrix `NOT_RUN` / `PARTIAL`; hostile-input
fuzzing `NOT_RUN`. Overall `PASS_WITH_LIMITATIONS`.
