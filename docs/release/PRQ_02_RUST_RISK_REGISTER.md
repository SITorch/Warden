# WARDEN-PRQ-01 — Phase 2 Rust Security Risk Register

status=`PASS` (register complete); remediation status is per-row.

## 1. Confirmed defects (all fixed in PRQ)

| ID | Severity | Location | Risk | Fix | Status |
|---|---|---|---|---|---|
| R-01 | Medium | `src/health.rs` `redact_secrets()` + `report()` | Credential quoted by a TOML parse error could leak into `--health --json` (literal/multiline strings uncovered) and human output was unredacted | Line-oriented redactor for 8 key names, all string forms, applied to both outputs | `FIXED`, 2 regression tests |
| R-02 | Medium | `src/loader.rs` `set_enforce_arm()` | `arm=true` reported as applied with no LSM attached — misleading security state | Fail closed unless `enforce_arm_effective()`; added effective-state helper | `FIXED` |
| R-03 | Medium | `src/loader.rs` `sync_guarded_inodes()` | Stale guarded inode could remain live while desired count was reported | Removal errors are fatal; live map count returned | `FIXED` |
| R-04 | Low | `src/tls.rs` `last_error()` | Raw return value misclassified against `SSL_ERROR_*`, hiding clean close/timeouts | Added `SSL_get_error` FFI; correct mapping | `FIXED` |
| R-05 | Medium (test integrity) | `tests/preopened_fd_guard.rs` | Privileged test printed `SKIP` and returned normally; Cargo counted it as `ok`, inflating pass counts | `#[ignore]` on runtime case; preconditions now hard-fail; regression guard; `scripts/test-privileged.sh` with exit 77 for SKIP | `FIXED`, evidence in `PRQ_02_TEST_SEMANTICS_FIX.txt` |

## 2. Conditional / hardening items (not fixed)

| ID | Priority | Location | Risk | Precondition | Recommended action | Status |
|---|---|---|---|---|---|---|
| R-06 | High (conditional) | `src/config.rs:2282-2293`, `src/config_engine.rs:780-803` | Daemon load does not enforce config mode/ownership; symlinked config accepted | Group/world-writable config or attacker-controlled symlink | Enforce ownership/mode at load+reload; `O_NOFOLLOW` | `DOCUMENTED` |
| R-07 | Medium | `src/deliver.rs:282-310` | Spool open and `set_permissions` follow symlinks; existing parent dirs not tightened | Local attacker with write access to spool parent | `O_NOFOLLOW`/`O_DIRECTORY`, fchmod via fd, verify parent each open | `DOCUMENTED` |
| R-08 | Medium | `src/deliver.rs:442-480` | Predictable `<spool>.tmp` created without `O_EXCL` | Local attacker races compaction | Unique temp file, `O_CREAT\|O_EXCL\|O_NOFOLLOW`, mode 0600, atomic rename | `DOCUMENTED` |
| R-09 | Medium | `src/respond.rs:478-516` | `kill(2)` fallback TOCTOU after identity validation | pidfd unavailable (older kernel) | Prefer fail-closed or require pidfd in enforce mode | `DOCUMENTED`; enforcement `NOT_RUN` anyway |
| R-10 | Medium | `src/bridge.rs:785-798`, `src/heartbeat.rs:312-326` | CRLF/control chars in host/path/api_key interpolate into raw headers | Attacker-controlled config values (requires config write) | Reject control chars; URL-encode; canonicalize host/path | `DOCUMENTED` |
| R-11 | Medium | `src/guard.rs:110-162`, `src/main.rs:1293-1299` | Inode-keyed guard follows old inode after atomic replacement until refresh | Attacker can atomically replace a guarded file | Shorten refresh window or event-driven re-resolution | `DOCUMENTED` (bounded gap) |
| R-12 | Low | `src/bridge.rs:633-640` | `to_socket_addrs()` has no deadline; can block the drain loop | DNS resolver failure or hostile resolver | Bounded DNS helper as in heartbeat | `DOCUMENTED` |
| R-13 | Low | `src/main.rs:2131-2145` | `bump_memlock()` logs at debug on failure | BPF setup depends on memlock | Bounded limit, preserve hard limit, warn on failure | `DOCUMENTED` |

## 3. Ring-buffer / detector state (eBPF-side, tracked here for C2 impact)

| ID | Risk | Status |
|---|---|---|
| R-14 | `detector.set_ring_loss_ratio()` is only called on lossy ticks; one lossy window can degrade C2 confidence indefinitely | `DOCUMENTED` (needs loss → clean and loss → unreadable regression tests) |
| R-15 | `ringbuf_drops` counts reserve failures only; not end-to-end loss | `DOCUMENTED` (bounded semantics) |

## 4. Areas reviewed with no high-severity confirmed finding

`c2.rs` (bounded heuristic, no block intent), `telemetry.rs`, `net_vol.rs`,
and the ring-buffer decode paths. This is a statement about the static review,
not a proof of absence of vulnerabilities.

## 5. Verification of fixes

All fixed items are covered by the full gate: `cargo test --offline --locked`
= **718 passed, 0 failed, 2 ignored**; `cargo clippy --all-targets --all-features
--offline --locked -- -D warnings` exit 0. Evidence:
`evidence/prq/PRQ_03_BUILD_GATES.txt`, `evidence/prq/PRQ_03_FULL_TEST_SUITE.txt`.
