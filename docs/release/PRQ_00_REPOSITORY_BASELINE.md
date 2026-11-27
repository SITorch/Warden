# WARDEN-PRQ-01 — Phase 0 Repository Baseline

captured=2026-11-23T16:29:36Z
status=`PASS` (baseline established; no destructive operations performed)

## 1. Authority and scope

- Canonical WARDEN root: `<home>/Desktop/Project/Warden` — a **subtree** of the
  parent SENTINEL monorepo, whose Git root is `<home>/Desktop/Project`.
- Parent branch: `main`.
- Parent HEAD at PRQ start: `e4d5f7adea0f957d37c70dbc162782583a0ce01c`.
- M16 reported HEAD: `8c813d5910c4c705ea4131baa8aeb922bd1d3e85`.
- The parent repository advanced after M16 by the user commit
  `chore: sync local workspace changes`. M15/M16 reports and evidence remain present.
  **PRQ treats the current checkout as authoritative** and does not assume M16 claims
  still hold without re-verification.
- M16 is closed (`COMPLETED_WITH_LIMITATIONS`, readiness `LAB_VALIDATED`). PRQ does not
  reopen or repeat M16 as a general engineering mission; its reports/evidence are
  historical baseline inputs only.
- Evidence: `evidence/prq/PRQ_00_baseline_raw.txt`.

## 2. Working tree state (preserved, not modified)

At baseline, `git status --short` showed two WARDEN-specific user changes plus
several unrelated modified/untracked files elsewhere in the parent monorepo.
The detailed paths are recorded in the **private** baseline evidence; they are
deliberately not reproduced in the public report.

| Category | State | PRQ handling |
|---|---|---|
| Tracked WARDEN ZIP | deleted in worktree | user change — preserved, not restored |
| Untracked WARDEN ZIP | stale snapshot | user change — present at baseline and excluded from public release; absent at final recheck (see FINAL-02 records) |
| WARDEN PRQ evidence directory | untracked | created by PRQ; excluded from export |
| Unrelated parent-monorepo work | modified / untracked | preserved untouched; not part of the public scope |

`git diff --check` exit 0 at baseline. No submodules. Git LFS unavailable/not in use.
Remotes are private (host/user redacted in evidence).

At baseline, `warden2.zip` (2,481,554 bytes) was identified as a **stale,
non-canonical snapshot**: it contains 29 `src/`, 8 `scripts/`, 3 `systemd/`
files versus the current 26 / 6 / 2, plus raw evidence, scratch output and
`.pyc` files. It is not a release source. It was recorded present in earlier
FINAL-02 integrity checks but was absent at the final recheck; the cause is
`UNKNOWN` and it was not reconstructed from the sanitized export.

## 3. Current architecture (unchanged)

- Single Rust daemon (`src/main.rs`, 26 source files), `aya` 0.13 pure-Rust BPF loader.
- eBPF C object `bpf/warden.bpf.o` with source `.built-from` provenance stamp and a
  runtime test asserting the embedded bytes equal the shipped object
  (`tests/embedded_object_is_the_shipped_object.rs`, 32 programs expected).
- Direct OpenSSL 3 FFI for optional mTLS (`src/tls.rs`); otherwise cleartext HTTP bridge
  or local-log-only. Binary dynamically links `libssl.so.3`, `libcrypto.so.3`, `libc`,
  `libgcc_s`, `libz`, `libzstd`.
- Existing configuration engine (`src/config.rs`, `src/config_engine.rs`) — no second
  engine will be introduced.
- systemd units: `warden.service`, `warden-deadman@.service`.
- Installer: preview-first `scripts/install_wizard.sh` with regression tests under
  `scripts/tests/`.

## 4. Existing capabilities and evidence

M16 authoritative gate (`evidence/m16/M16_13_final_gate.txt`):

| Check | M16 reported result |
|---|---|
| `git diff --check` | PASS (exit 0) |
| `cargo fmt --check` | PASS |
| `cargo check --all-targets --offline` | PASS |
| `cargo test --offline` | 716 passed, 0 failed, 1 ignored |
| `cargo clippy --all-targets --offline -D warnings` | PASS |
| `cargo build --release --offline` | PASS |
| config-engine CLI regression | PASS |
| installer CLI regression | PASS |
| `--config-validate --strict` (repo sample) | PASS |
| legacy `--check --strict` (repo sample) | PASS |
| shipped BPF object SHA-256 (M16 historical) | `5e0508c09746ff3e96234fca65a5cc658efc3c8c266e1006ef0c720bbf0e7e4a` |

> PRQ-01 note: the public-release object was subsequently rebuilt from the same
> source with `-fdebug-prefix-map` to remove builder home paths from debug/BTF
> line info (see `PRQ_01_PUBLIC_SANITIZATION_REPORT.md`). Its new SHA-256 is
> `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`
> (1,243,656 bytes, FNV-1a `0xbc288747047b4edb`). The M15/M16 value above is
> retained only as the historical baseline it describes.
| self-test with safe 0640 temp copy | PASS |
| local collector bridge self-test | PASS (`SELFTEST PASS`) |
| backend clock-lineage stored-event tests | 68 passed |
| privileged VM validation | completed on disposable Debian 13, kernel `6.12.107+deb13-amd64` |

M16 final verdict `COMPLETED_WITH_LIMITATIONS`; readiness `LAB_VALIDATED`; **not
production-ready**. These are historical claims; PRQ re-runs build/test gates on the
current checkout before making any current-state assertion.

## 5. Existing blockers (must remain visible)

| Qualification | Baseline status |
|---|---|
| Real live SENTINEL delivery | `BLOCKED` — no authorized staging endpoint/tenant/key |
| Additional kernel/distribution compatibility | `BLOCKED` — only Debian 13 evidenced |
| Long-duration soak | `UNKNOWN` — only M16 60 s measured workload |
| Armed kill enforcement | `NOT_RUN` |
| Armed BPF-LSM denial qualification | `NOT_RUN` |
| Armed cgroup egress qualification | `NOT_RUN` |

Privileged/enforcement tests are **never** run on the active host; they require a
disposable isolated VM with recovery.

## 6. Missing public-release infrastructure

- No `Warden/.github/` — effective CI lives in parent `.github/workflows/ci.yml`.
- No `Warden/.gitignore`, `.gitattributes`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `CHANGELOG.md`, `config/warden.example.toml`, or `docs/release/` (created by PRQ).
- `SECURITY.md` describes a private-only Forgejo/LAN deployment — not a public policy.
- No SBOM, no local SBOM/audit/deny tooling (`cargo-audit`, `cargo-deny`, `syft`,
  `spdx`, `sbom4rust`, `markdown-link-check`, `shellcheck`, `gitleaks`, `trufflehog`
  all unavailable). Fallback scans are documented in PRQ_01.

## 7. Files requiring sanitization / exclusion from public mirror

- **Redact in place for public docs:** `SECURITY.md`, `DESIGN.md`, `README.md`,
  `docs/security/WARDEN_MISSION_16_OPERATOR_GUIDE.md`, `scripts/LIVE_VALIDATION.md`.
- **Current public replacements:** `docs/release/WARDEN_FINAL_OPERATOR_HANDOFF.md` and
  `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` replace the excluded operator guide and raw runbook.
- **Never publish raw:** `evidence/m15/`, `evidence/m16/`, `evidence/prq/` raw scans,
  `scratch/`, both ZIPs, `target/`, `.pyc`, local paths/IPs/usernames, and any parent
  SENTINEL source. Public evidence will be sanitized summaries only.
- Canonical private Git history is **never rewritten**; a sanitized export/mirror is
  prepared instead (PRQ_01).

## 8. Known defects to fix (tracked, not yet fixed at baseline)

1. `tests/preopened_fd_guard.rs`: a privileged path prints `SKIP` and returns normally,
   so the Rust harness counts it as `ok` — inflating pass counts. Must be restructured.
2. `config/warden.toml` mode `0664` where operational config should be `0640`.
3. `Makefile` build/test commands are not consistently `--locked --offline`; CI rebuilds
   BPF without byte-equality verification against the committed object.
4. Public-facing docs contain private infrastructure details and an outdated IPv6
   `IMPLEMENTED_NOT_VALIDATED_LIVE` claim versus M15/M16 evidence.

## 9. Work excluded from repetition

M15/M16 architecture, sensor implementation, config engine, installer, and their full
test matrices are complete and will not be rebuilt. PRQ re-verifies integrity and
statuses only, fixes the specific defects above, and adds release infrastructure.

## 10. Toolchain observed

`rustc 1.95.0`, `cargo 1.95`, `clang 21.1.8`, `bpftool 7.7.0`. Exact versions recorded
in `evidence/prq/PRQ_00_baseline_raw.txt` and re-captured in build evidence.


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
