# WARDEN-PRQ-01 — Phase 5 SENTINEL Integration Report

status=`BLOCKED` — no authorized live staging endpoint, tenant, or credentials
were provided. No integration test was fabricated.

## 1. What WARDEN's integration actually is

WARDEN is a host agent that can optionally:

1. **Report events** to a SENTINEL collector over a cleartext HTTP bridge with
   HMAC-signed envelopes (`src/bridge.rs`, `src/hmac.rs`), with a placeholder
   `X-API-Key` header field.
2. **Report heartbeat/status** to a SENTINEL endpoint (`src/heartbeat.rs`).
3. Use **optional mTLS** (`src/tls.rs`) with mandatory peer verification, pinned
   host/IP, and client certificate — no "verification off" option.
4. **Spool to disk** when the bridge is unavailable (`src/deliver.rs`) and
   retry with a bounded attempt budget.

The public Alpha defaults are local-only: `[bridge]` is not configured,
`mode = "observe"`, no kill responder armed, and the example config has no
endpoint. Nothing is sent anywhere by default.

## 2. Evidence available (historical, bounded)

| Evidence | What it proves | What it does not prove |
|---|---|---|
| M16 final gate local collector bridge self-test (`SELFTEST PASS`) | WARDEN can sign and POST a synthetic event to a **local** collector and handle duplicate/replay/sequence cases | No real SENTINEL endpoint was contacted |
| M16 backend clock-lineage stored-event tests (68 passed) | The SENTINEL-side ingest contract for signed host events exists and passes in the monorepo test suite | Not a live WARDEN→SENTINEL deployment test |
| `scripts/live_bridge_check.py` and config-engine CLI regressions | CLI/transport plumbing is present and testable offline | Not a production integration |

Those are contract/self-test results, not live integration proof.

## 3. Blockers

| Blocker | Status |
|---|---|
| Authorized staging SENTINEL endpoint | `BLOCKED` — none provided |
| Tenant / project identifier | `BLOCKED` — none provided |
| API key / HMAC shared secret / client certificate | `BLOCKED` — none provided; **none invented** |
| Network reachability / egress authorization from a test host | `BLOCKED` |
| Permission to create test data in SENTINEL | `BLOCKED` |

The mission rules explicitly forbid inventing endpoints, credentials, or
reporting channels. No such values appear in the public snapshot: the example
config has no bridge target, and the only addresses in source are generic unit
test fixtures.

## 4. Safety properties that were verified without a live endpoint

- Config validation rejects enabled egress/arm without the required gates and
  flags safe defaults (`--config-validate --strict` on both configs, exit 0).
- The secret is confined to the bridge layer and is not serialized by Phase 7
  egress code (`docs/security/warden_phase7_egress_enforcement.md` §6).
- Health output redaction now masks credential assignments in both human and
  JSON views (`PRQ_02_SECURITY_REVIEW.md`).
- CRLF/control-character validation in header interpolation remains a
  documented hardening item (`PRQ_02_RUST_RISK_REGISTER.md` R-10).

## 5. What a future live test must record

To move this from `BLOCKED` to `PASS`, a future authorized test must capture:

- exact endpoint host, tenant, and time window (sanitized in public evidence);
- WARDEN build digest and config (with secrets redacted);
- events POSTed, accepted (2xx), rejected, duplicated, and retried;
- heartbeat accepted/rejected status;
- spool depth before/after and behaviour under a forced bridge outage;
- HMAC verification result on the SENTINEL side;
- for mTLS: certificate chain, pinned identity, and peer-verification failure
  cases.

## 6. Decision

Real live SENTINEL integration: `BLOCKED`. It is a **public Alpha release
limitation**, documented in `WARDEN_KNOWN_LIMITATIONS.md`, and a **production
qualification blocker** in `WARDEN_PRODUCTION_QUALIFICATION.md`.
