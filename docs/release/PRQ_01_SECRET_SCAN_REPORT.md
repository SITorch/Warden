# WARDEN-PRQ-01 — Phase 1 Secret / Credential Scan Report

status=`PARTIAL` — current tree scanned with fallback tooling; history scanned
path-only; dedicated secret scanners unavailable. **No confirmed active secret
was found, but the result is not equivalent to a full gitleaks/trufflehog run.**

## 1. Scope and tooling

| Item | Value |
|---|---|
| Scan date | 2026-11-23 |
| Canonical source root | `Warden/` subtree of the parent SENTINEL monorepo |
| Parent branch / HEAD | `main` / `e4d5f7adea0f957d37c70dbc162782583a0ce01c` |
| Raw evidence (private) | `evidence/prq/PRQ_01_secret_scan_fallback.txt`, `evidence/prq/PRQ_01_git_history_scan.txt` |
| Dedicated scanners | `gitleaks` — **NOT AVAILABLE**; `trufflehog` — **NOT AVAILABLE** |
| Fallback | `grep -rInE` pattern scan over the current worktree, plus `git log`/`git rev-list` path-only history enumeration |

The absence of dedicated scanners is a real evidence limitation and is **not**
reported as a pass. The public CI workflow adds `gitleaks/gitleaks-action@v2`
with `fetch-depth: 0` so the published repository gets a real history scan after
publication.

## 2. Current-tree fallback scan — results

Patterns searched (case-insensitive): `api[_-]?key`, `apikey`, `bearer`,
`authorization:`, `secret`, `token`, `password`, `passwd`, `private[_-]?key`,
`BEGIN [A-Z ]*PRIVATE KEY`, `hmac`, `root[_-]?token`, plus file-extension checks
for `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx`, `.env*`, `credentials.json`.

| Category | Finding | Classification |
|---|---|---|
| Credential-assignment patterns in Rust/Python source | Matches are **variable names, test fixtures, and redaction code** (e.g. `api_key` field names, placeholder test values such as `"test-secret"` in unit tests, the new `redact_secrets()` regression cases). No live credential value found. | `PASS` with manual review |
| PEM / private key / certificate files in Warden tree | None found in the canonical tracked source set. (Historical M16 evidence recorded a `.pem` in the *parent* deployment, which is outside WARDEN's public scope.) | `PASS` |
| `.env` / `.env.*` files in Warden tree | None in the release candidate. Generic `*.env` handling appears only as guarded-file *examples* in documentation and a test fixture name. | `PASS` |
| Home-directory / private IP strings in documentation and source | Found and remediated — see `PRQ_01_PUBLIC_SANITIZATION_REPORT.md`. | `PASS` after fix |
| `Warden/warden2.zip` (untracked user archive, present at scan time) | Contained stale, unredacted documentation and raw evidence. Excluded from the public snapshot. It was recorded present in earlier FINAL-02 integrity checks but is absent at the final recheck; cause `UNKNOWN`, not reconstructed. | `NOT_APPLICABLE` to public release; preservation `PARTIAL` |
| Parent SENTINEL backend/frontend/ML source trees | Present in the monorepo but outside WARDEN's public scope. Verified absent from the public snapshot. | `PASS` (scope boundary) |

## 3. Git history scan — results

`git log --all --name-only` / path enumeration was run with values excluded from
the report (path-only evidence retained privately).

| Observation | Classification |
|---|---|
| No path in WARDEN history is named like a private key, certificate, or `.env` credential store. | `PASS` (path-level only) |
| Secret-pattern **classifications in historical commit contents** were not resolved because no dedicated history-capable scanner is installed. | `UNKNOWN` |
| Canonical Git history is **not rewritten** — per the mission constraint. Instead a sanitized export/mirror is prepared. | `PASS` (strategy) |
| A full `gitleaks` history scan is a **public-release gate**: it must run against the published repository with full history before the repository is declared clean. | `BLOCKED` (tooling) |

## 4. Confirmed no-secret assertions (bounded)

The following can be asserted truthfully:

- No file in the public snapshot is a PEM, private key, certificate, or
  credentials file. (Evidence: final rescan in `PRQ_FINAL_EVIDENCE_INDEX.md`.)
- No live deployment network address, host account name, private repository
  owner/URL, or parent-platform module directory is present as an
  **addressable value** in the public snapshot after the fixture fix. Generic
  documentation ranges and redaction placeholders are not deployment data.
- No file from the parent SENTINEL backend, frontend, or ML trees is present in
  the public snapshot; historical path names appear only in explanatory prose
  about scope.
- Credential-like tokens in source are field names, synthetic test values, or
  the redactor's own regression fixtures — not live credentials.

## 5. Remaining risk and required external action

1. **Run `gitleaks` (or equivalent) with full history** on the public repository
   after publication; treat any finding as a release-blocking incident until
   triaged. Status: `BLOCKED` locally.
2. **Enable GitHub secret scanning / push protection** (or the platform's
   equivalent) on the published repository. Status: `NOT_RUN` — external action.
3. Re-run the fallback pattern scan on every future export before publishing.
   Status: `PASS` (process, this pass).

## 6. Status summary

| Check | Status |
|---|---|
| Current-tree fallback scan | `PASS` (with documented tooling limitation) |
| Key/cert/env-file check | `PASS` |
| Git history path-only scan | `PASS` (path-level) |
| Git history content scan (dedicated scanner) | `BLOCKED` — tool unavailable |
| Public snapshot rescan after sanitization | `PASS` |
| No confirmed active secret | `PASS` (bounded by above limitations) |

A `PASS` here means "no secret found by the scans that actually ran"; it does
**not** mean "cryptographically proven secret-free".


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
