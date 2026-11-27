# WARDEN-PRQ-01 — Phase 2 Documentation Contradiction Report

status=`PARTIAL` — all public-facing contradictions material to the security
posture were corrected; two mirrored-document reference issues are handled at
export time because the canonical mirrors must remain byte-identical.

## 1. Corrections applied in place

| # | File | Problem | Correction |
|---|---|---|---|
| 1 | `README.md` | "Six further programs are the **only** ones that can deny anything" — contradicted the four cgroup egress deny hooks | Now names both denial axes and states observational hooks never deny |
| 2 | `README.md` architecture diagram | Only LSM block marked deny-capable | Now labels LSM file denial and four cgroup egress hooks (off by default) |
| 3 | `README.md` | IPv6 datagram hooks `IMPLEMENTED_NOT_VALIDATED_LIVE` despite M15 evidence | `LIVE_VALIDATED_M15` with verifier/attach/`[::1]` +4/+4, 2800 B, and socket-path boundary |
| 4 | `README.md` | Guarded-file denial "verified on kernel `7.0.0-15`" | Downgraded to readiness only; live denial `NOT_RUN`; `SKIP` ≠ pass |
| 5 | `README.md` | Already-open-fd revocation "tested in-kernel" | "Implemented in code; live qualification `NOT_RUN`"; mapping gap retained |
| 6 | `README.md` | "17 listeners and 15 connections" | Corrected to 19 connections (36 udp-bound, 8 TIME_WAIT) per `LIVE_VALIDATION.md` §22 |
| 7 | `README.md` | Object length `1 211 600` / stale FNV | Updated to the public Alpha object; M15/M16 values labelled historical |
| 8 | `DESIGN.md` hook table + note | IPv6 `IMPLEMENTED_NOT_VALIDATED_LIVE` | `LIVE_VALIDATED_M15` + socket-path boundary |
| 9 | `DESIGN.md:707` | "Armed denial is verified in-kernel" on `7.0.0-15` | Readiness only; runtime test `#[ignore]`d; only VM runner is evidence |
| 10 | `DESIGN.md` checklist | `[x]` LSM inline-deny verified on dev host | `[ ]` NOT qualified; explains "3 passed" is not 3 denials |
| 11 | `DESIGN.md` | Private guarded-asset filenames, TLS key filenames, internal backend address | Replaced with explicit guarded-file pattern description |
| 12 | `SECURITY.md` | Private Forgejo/LAN reporting policy | Rewritten as public private-vulnerability-reporting policy |
| 13 | `config/warden.toml` permission | Sample mode `0664` vs "root-only" text | Mode fixed to `0640`; self-test now reports `configuration_permissions PASS` |
| 14 | `README.md` | Broken refs `EVALUATION-AND-FIXES.md`, `warden_phase6_live_validation.md` | Replaced with existing `docs/security/warden_coverage_matrix.md` and `scripts/LIVE_VALIDATION.md` §§15/17 |
| 15 | Public docs and one code comment | Excluded raw runbook pointers remained in the shipped tree | Added `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` and reconciled current pointers; historical rows 6 and 14 are unchanged |

## 2. Export-time corrections (canonical mirrors intentionally unchanged)

`docs/security/warden_phase7_egress_enforcement.md` and
`docs/security/warden_coverage_matrix.md` have byte-identical mirrors in the
parent SENTINEL repository. A repository test
(`tests/network_coverage_matrix.rs::vendored_docs_match_the_repository_mirrors_when_present`)
fails if the canonical copies drift. Because modifying parent SENTINEL files is
out of scope for this mission, the canonical copies were restored, and the
public snapshot rewrites only the dead reference targets:

| Canonical target | Public target |
|---|---|
| `warden_phase6_live_validation.md` | `docs/release/PRQ_06_ENFORCEMENT_QUALIFICATION.md` |
| `warden_kernel_compatibility_matrix.md` | `docs/release/PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md` |

Both replacement files are part of the public snapshot, so the exported docs
have no dead links.

## 3. Remaining documented contradictions (not corrected)

| Item | Reason |
|---|---|
| Mission 15/16 reports contain historical object digests, BTF IDs, and private deployment details | They are historical artifacts, excluded from the public snapshot; altering them would falsify the historical record |
| `scripts/LIVE_VALIDATION.md` raw log | Excluded from public snapshot |
| M16 final report says the isolated cgroup cleanup returned to 4 programs/2 maps | Historical and accurate for `M16_10`; the first `M16_09` attempt left the pid alive — both facts are in raw evidence, both excluded from public |
| `systemd/warden-deadman@.service` duplicates one `Documentation=` line | Cosmetic, no security impact |

## 4. Verification

- `git diff --check` exit 0.
- `cargo test --offline --locked` 718 passed / 0 failed / 2 ignored, including
  the mirror-equality test after the canonical restore.
- Public snapshot rescan confirmed no private identifiers or dead-reference
  targets in the exported docs (final index).
