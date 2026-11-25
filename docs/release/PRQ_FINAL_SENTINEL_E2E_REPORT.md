# WARDEN-PRQ-FINAL-02 — SENTINEL End-to-End Qualification

status=`LOCAL_CONTRACT_VALIDATED`; live integration `BLOCKED`. Prepared
2026-11-24. Raw evidence: `Warden/evidence/prq/final/PRQ_FINAL_SENTINEL_E2E.txt`
and `evidence/prq/final/sentinel_e2e/local_collector_selftest.txt`.

## 1. Authorization boundary

No authorized staging SENTINEL endpoint, tenant, API key, HMAC secret, client
certificate, egress authorization or permission to create test data exists in
this environment. PRQ-01 reached the same conclusion. Per mission rules, none
was invented and no unrelated file was searched for credentials to use against
an external service. No external service was contacted.

| Requirement | Status |
|---|---|
| Authorized staging endpoint | `BLOCKED` |
| Tenant / project identifier | `BLOCKED` |
| Authentication material | `BLOCKED` (none invented) |
| Network / egress authorization | `BLOCKED` |
| Permission to create Backend test data | `BLOCKED` |
| Live WARDEN → SENTINEL event delivery | `NOT_RUN` / `BLOCKED` |

`LIVE_INTEGRATION_VALIDATED` is therefore **not** awarded. A local mock is not
substituted for real proof.

## 2. What was actually executed

| Test | Command / source | Result | Boundary |
|---|---|---|---|
| Local collector self-test | `python3 scripts/live_bridge_check.py selftest` | exit 0, `SELFTEST PASS` | loopback collector + synthetic requests; no kernel sensor, no real backend |
| Backend route verification (read-only) | `<parent-project>/sentinel/urls.py:460`, `<parent-project>/sentinel/tests/test_host_ingest.py:30`, `<parent-project>/api_module/authentication.py:101-112` | `/api/v1/sentinel/host/` confirmed present in current private backend | source inspection only |
| In-process delivery contract tests | 75 `#[test]` attributes in `src/bridge.rs`, `src/deliver.rs`, `src/heartbeat.rs`, `tests/uplink_identity_gate.rs`; PRQ-01 whole suite 718 passed / 0 failed / 2 ignored; FINAL-02 clean-export suite 721 passed / 0 failed / 2 ignored | `PASS` | in-process mock servers |
| Redirect classification regression (new) | `cargo test --offline --locked --bin warden status_classification_matches_the_retry_contract` | exit 0; 1 passed | table assertion, no runtime change |

The local collector self-test exercised refusal, duplicate `event_id`,
HMAC rejection, heartbeat sequence acceptance, replay rejection and
out-of-order rejection, and reported `posts_attempted=4`, `posts_accepted=2`,
`posts_refused=2`, `posts_invalid=1`, `duplicate_deliveries=1`.

## 3. Redirect and rejection safety

The delivery client is hand-rolled HTTP/1.1 over a raw socket; it does not
follow redirects. `classify()` in `src/bridge.rs` accepts only 2xx, retries a
small explicit set (408, 425, 429, 5xx), and refuses everything else. Therefore
a 301/302/307/308 is **not** a delivery acknowledgement and cannot cause an
authentication header to be replayed to a redirect target.

Verified defect coverage gap: although the runtime behaviour was already safe,
the table-driven regression test did not explicitly cover 3xx. This mission
added 301, 302, 307 and 308 to the `Refused` set with a rationale comment. The
targeted test passed. No runtime logic changed; no new dependency; no
architecture change.

Status classification table (verified by test):

| Status class | Codes | Verdict |
|---|---|---|
| Success | 200, 201, 202, 204, 299 | accepted |
| Retry | 408, 425, 429, 500, 502, 503, 504, 599 | retried |
| Refused | 301, 302, 307, 308, 400, 401, 403, 404, 409, 413, 422, 499 | refused, not retried |

Related in-process coverage includes strict status-line parsing (a non-HTTP
banner can no longer be read as success), whole-batch handling, 503 backlog
drain without loss, spool permissions, restart recovery, and HMAC heartbeat
replay rejection.

## 4. Unexecuted lifecycle phases

The complete lifecycle `Sensor → Parsing → Detection → Queue → Delivery →
Authentication → HTTP Ingest → Backend Processing → Durable Storage →
Acknowledgment` was **not** demonstrated end to end. Specifically:

| Phase | Status | Reason |
|---|---|---|
| DNS resolution against authorized collector | `NOT_RUN` | no authorized endpoint |
| TLS validation against real certificate | `NOT_RUN` | no authorized endpoint / CA material |
| Real authentication | `NOT_RUN` | no issued credentials |
| HTTP method/path/headers against live backend | `NOT_RUN` | no authorized endpoint |
| Backend processing and durable storage | `NOT_RUN` | no test-data permission |
| Acknowledgment semantics | `NOT_RUN` | no real ingester |
| Real outage / spool-growth / recovery reconciliation | `NOT_RUN` | no controlled live collector |
| Real 3xx through a load balancer | `NOT_RUN` | no authorized staging infrastructure |
| Event-count reconciliation with Backend rows | `NOT_RUN` | no Backend access |

A successful HTTP response is not treated as durable-ingestion proof, and the
in-process collector is not represented as a real SENTINEL deployment.

## 5. Historical issue reconciliation

The historical HTTP 301 observation on the host-ingest path and the rejected-
finding handling are not claimed resolved by this mission. The local contract
test shows the current client would classify 301 as refused (not acknowledged),
and the new regression locks that behaviour in. Whether the real staging
load balancer still returns 301 for the documented path can only be answered
when an authorized staging environment is provided.

## 6. Residual risk and required external action

| Risk | Residual |
|---|---|
| Real backend may reject the payload schema despite local contract tests | unverified |
| Durable storage may not match acknowledged deliveries | unverified |
| Real authentication / mTLS may be misconfigured | unverified |
| Collector outage behaviour under real traffic | unverified |
| Clock lineage across real hosts | unverified |

External maintainer action (`BLOCKED_EXTERNAL_MAINTAINER_ACTION`): provide an
authorized staging endpoint, tenant, credentials/CA, egress authorization and
test-data permission; then execute the full lifecycle with a canary event set
and reconcile generated / accepted / transmitted / acknowledged / persisted
counts.

## 7. Gate summary

| Gate | Status |
|---|---|
| Local contract behaviour | `PASS` |
| Endpoint path present in current backend source | `PASS` (source-level) |
| Redirect not treated as acknowledgement | `PASS` |
| Live SENTINEL delivery | `BLOCKED` / `NOT_RUN` |
| SENTINEL integration readiness | `LOCAL_CONTRACT_VALIDATED` |
