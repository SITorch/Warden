# WARDEN-PRQ-01 — Phase 1 Public Sanitization Report

status=`PASS` for the prepared snapshot; publication is a separate, external action.

## 1. Snapshot identity

| Item | Value |
|---|---|
| Public candidate path | `/tmp/opencode/prq/public_snapshot/WARDEN` |
| File count | Final count recorded in `PRQ_10_PUBLIC_REPOSITORY_CONTENTS.md` |
| Approximate size | ~7.4 MiB (dominated by the prebuilt eBPF object and `Cargo.lock` metadata) |
| Preparation method | Explicit inclusion manifest (allow-list), not "copy then delete" |
| Raw evidence | `evidence/prq/PRQ_01_PUBLIC_SNAPSHOT_RESCAN.txt` (private) |

The snapshot is built from the **current checkout**, not from either ZIP
archive. At scan time, `warden.zip` was a deleted tracked user change and
`warden2.zip` was a stale untracked snapshot containing raw evidence and
unredacted docs; both were excluded. `warden2.zip` was subsequently found
absent at the FINAL-02 final recheck; the cause is `UNKNOWN` and it was not
reconstructed from the export.

## 2. Sanitization actions applied

| # | Action | Evidence |
|---|---|---|
| 1 | Rewrote `SECURITY.md` as a public coordinated-disclosure policy. No invented reporting address or PGP key; GitHub Private Vulnerability Reporting is designated and flagged as an external gate. | `SECURITY.md` |
| 2 | Redacted private infrastructure references in public docs: 13 internal-IP occurrences, 2 home-path occurrences, 2 private-URL occurrences (aggregate counts from the first export). | `PRQ_01_PUBLIC_SNAPSHOT_RESCAN.txt` |
| 3 | Replaced the lab-VM address `192.168.122.3` in `src/config.rs` and `src/bridge.rs` **test fixtures** with the generic `192.168.100.10`. 89 config/bridge unit tests still pass. | `PRQ_01_PUBLIC_SNAPSHOT_RESCAN.txt` final rescan |
| 4 | Rebuilt `bpf/warden.bpf.o` with `-fdebug-prefix-map=$(CURDIR)=.` so DWARF and BTF line info contain no builder home path. The Makefile now applies the flag on every rebuild. | See §3 below |
| 5 | Reconciled public-facing status claims with M15/M16 evidence (IPv6 `LIVE_VALIDATED_M15`, two denial axes, no unverified live `-EPERM` claim). | `README.md`, `DESIGN.md`, `SECURITY.md` |
| 6 | Added a safe, strictly validating public config example (`config/warden.example.toml`, mode `0640`) and made it the public install default. The operational `config/warden.toml` is retained only as a sanitized **compile-time test fixture** (required by `src/config.rs::include_str!`); install targets are export-rewritten to the example. | `PRQ_02_CONFIG_PERMISSION_FIX.txt` |
| 7 | Excluded raw evidence, scratch outputs, M15/M16 reports, operator guide, raw live-validation log, ZIPs, `target/`, and parent SENTINEL source. | `PRQ_01_EXCLUDED_CONTENT_MANIFEST.md` |
| 8 | Added public repository infrastructure: `.gitignore`, `.gitattributes`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/workflows/ci.yml`, issue/PR templates. | Public snapshot tree |

## 3. BPF object path sanitization (the highest-risk item)

The shipped prebuilt object originally contained three `/home/...` strings in
DWARF/BTF line info. This was resolved by **rebuilding from the same source**
with a debug-prefix map, not by hand-editing binary bytes.

Verification performed on a copy before adopting the rebuild:

| Check | Result |
|---|---|
| Fresh rebuild with the *original* Makefile flags | Byte-identical to shipped object (SHA-256 `5e0508c0…e7e4a`) — build is deterministic with local clang 21.1.8 |
| `.text` (eBPF program instructions) original vs prefix-map rebuild | **Byte-identical** |
| BTF type dump original vs prefix-map rebuild (path prefix normalized) | **Identical** (1,927 types, zero diff lines) |
| `bpftool btf dump file …` on rebuilt object | `PASS` (exit 0) |
| `/home/` strings remaining | **0** |
| Rebuild reproducibility with the updated Makefile flag | Byte-identical (SHA-256 `2461fbc…5b3a`) |

| Artifact | M15/M16 historical | Public Alpha object |
|---|---|---|
| Size | 1,243,776 bytes | 1,243,656 bytes |
| SHA-256 | `5e0508c09746ff3e96234fca65a5cc658efc3c8c266e1006ef0c720bbf0e7e4a` | `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a` |
| FNV-1a | `0x12b9ea8166db40df` | `0xbc288747047b4edb` |

`bpf/.built-from`, the SBOM, `README.md`, the health-test identity canary, and
the PRQ build-gate evidence were updated to the new values. M15/M16 reports and
raw evidence were **left unchanged**: they describe the historical object they
actually tested. Both objects are treated as functionally identical for the
purposes of the historical privileged evidence because program text and BTF
types are unchanged; only debug path strings were relativised. This lineage
statement is a bounded technical claim, not a new privileged test result.

## 4. Redaction policy

- Over-redaction is preferred. Private IPs, home paths, usernames, repository
  owner names, internal service names, and credential values are removed even
  where they appear only in test data.
- Generic documentation ranges (`203.0.113.9`, `192.168.100.10`) and RFC1918
  values used solely for private-range *classification* unit tests are retained
  because they carry no deployment information.
- Raw evidence is never "sanitized in place and published"; it is excluded and
  replaced by sanitized summaries in `docs/release/`.

## 5. Residual risks

| Risk | Status |
|---|---|
| Dedicated secret scanners unavailable locally | `BLOCKED` — see `PRQ_01_SECRET_SCAN_REPORT.md` |
| Private vulnerability reporting channel not yet enabled | `BLOCKED` — external action |
| Canonical Git history contains historical private paths/identifiers; not rewritten | `PARTIAL` — mitigated by sanitized export |
| Broken doc references in the mirrored phase-7 doc (parent mirror must stay identical) | `PARTIAL` — fixed at export time, documented in `PRQ_02_DOCUMENTATION_CONTRADICTIONS.md` |

## 6. Decision

The prepared snapshot is `PASS` for local public-release content readiness on
the criteria this mission can verify. It is **not published**. Publication
requires the external actions in `WARDEN_ALPHA_RELEASE_CHECKLIST.md`.


## OSR-FINAL-03 reconciliation — 2026-11-25

This section was added after FINAL-02. It does not alter the historical record
above. The user has explicitly confirmed that `Warden/warden2.zip` was
intentionally deleted by the user. Current status for present-day readiness:

```text
status      = ABSENT
cause       = USER_CONFIRMED_INTENTIONAL_DELETION
recovery    = NOT_REQUIRED
replacement = NOT_CREATED
```

The earlier FINAL-02 `UNKNOWN` classification is superseded for
WARDEN-OSR-FINAL-03 readiness purposes only. This mission did not restore,
reconstruct, search indefinitely for, or substitute the archive. The deletion
is not classified as accidental data loss.
