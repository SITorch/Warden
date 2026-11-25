# WARDEN — FINAL-02 Final Evidence Index

This index separates **private raw evidence** (not published) from **sanitized
public reports** (included in the export). It also serves as the public
replacement for references to the excluded raw live-validation log and raw
mission evidence; section numbers below refer to the private raw log where the
original documents say so.

## 1. Authoritative baseline

| Item | Value |
|---|---|
| Mission | WARDEN-PRQ-01 plus WARDEN-PRQ-FINAL-02 — public-source preparation, final qualification and release decision |
| Parent HEAD | `e4d5f7adea0f957d37c70dbc162782583a0ce01c` (branch `main`) |
| M16 reported HEAD (historical) | `8c813d5910c4c705ea4131baa8aeb922bd1d3e85` |
| M16 final verdict (unchanged) | `COMPLETED_WITH_LIMITATIONS`; readiness `LAB_VALIDATED` |
| Public Alpha BPF object | 1,243,656 bytes; SHA-256 `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`; FNV-1a `0xbc288747047b4edb` |
| Historical M15/M16 object | 1,243,776 bytes; SHA-256 `5e0508c09746ff3e96234fca65a5cc658efc3c8c266e1006ef0c720bbf0e7e4a`; FNV-1a `0x12b9ea8166db40df` |

## 2. Public sanitized reports (included in export)

| File | Subject | Status |
|---|---|---|
| `PRQ_00_REPOSITORY_BASELINE.md` | Authoritative tree, user work, tool availability, baseline digests | informational |
| `PRQ_01_SECRET_SCAN_REPORT.md` | Fallback scan, history path scan, scanner gaps | `PARTIAL` |
| `PRQ_01_PUBLIC_SANITIZATION_REPORT.md` | Redactions, BPF path rebuild, export policy | `PASS` |
| `PRQ_01_EXCLUDED_CONTENT_MANIFEST.md` | Allow-list / exclusion categories / export rewrites | `PASS` |
| `PRQ_02_SECURITY_REVIEW.md` | Four confirmed defect fixes, hardening queue | `PASS_WITH_LIMITATIONS` |
| `PRQ_02_RUST_RISK_REGISTER.md` | R-01…R-15 register | `PASS` (register) |
| `PRQ_02_EBPF_RISK_REGISTER.md` | E-01…E-08 register, capability boundaries | `PASS` (register) |
| `PRQ_02_DOCUMENTATION_CONTRADICTIONS.md` | 14 corrections + export-only fixes | `PARTIAL` |
| `PRQ_03_BUILD_REPRODUCIBILITY_REPORT.md` | All local gates, test-count delta, object lineage | `PASS` |
| `PRQ_04_SUPPLY_CHAIN_REPORT.md` | Dependencies, fallback SBOM, advisory tool gaps | `PARTIAL` |
| `PRQ_05_SENTINEL_INTEGRATION_REPORT.md` | Integration contract, blockers, future protocol | `BLOCKED` |
| `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md` | One historical VM; everything else `UNKNOWN` | `PARTIAL` |
| `PRQ_06_ENFORCEMENT_QUALIFICATION.md` | Three enforcement axes, test-integrity fix | `NOT_RUN` |
| `PRQ_07_TEST_AND_PERFORMANCE_REPORT.md` | 718 tests; soak `UNKNOWN` | `PASS` / `UNKNOWN` |
| `PRQ_08_INSTALLER_OPERATOR_REPORT.md` | Installer, CLI, self-test results | `PASS_WITH_LIMITATIONS` |
| `PRQ_09_LICENSE_ATTRIBUTION_REPORT.md` | GPL-2.0-only, SPDX, dependency licenses | `PASS` / `PARTIAL` |
| `PRQ_10_PUBLIC_REPOSITORY_CONTENTS.md` | Snapshot manifest, link check, clean-export gates | `PASS` (local export only; publication `BLOCKED`) |
| `WARDEN_PUBLIC_RELEASE_READINESS.md` | Release decision | `BLOCKED` (local content `PASS`) |
| `WARDEN_PRODUCTION_QUALIFICATION.md` | Production decision | `NOT QUALIFIED` / `BLOCKED` |
| `WARDEN_KNOWN_LIMITATIONS.md` | Authoritative limits and forbidden claims | informational |
| `WARDEN_ALPHA_RELEASE_CHECKLIST.md` | Done locally vs external actions | informational |
| `warden_alpha1.spdx.json` | SPDX 2.3 fallback SBOM, 79 packages / 78 relationships | valid JSON |
| `PRQ_FINAL_BASELINE_AND_FREEZE.md` | FINAL-02 baseline and final candidate freeze | informational |
| `PRQ_FINAL_SECRET_AND_HISTORY_AUDIT.md` | gitleaks, fallback scan, history strategy | `PASS` / tool coverage `PARTIAL` |
| `PRQ_FINAL_SENTINEL_E2E_REPORT.md` | Local collector contract, live integration blocker | `LOCAL_CONTRACT_VALIDATED` / `BLOCKED` |
| `PRQ_FINAL_SECURITY_DISCLOSURE_READINESS.md` | Private reporting channel gate | `BLOCKED` external |
| `PRQ_FINAL_LICENSE_AND_ATTRIBUTION.md` | License, SBOM and attribution review | `PASS` / `PARTIAL` |
| `PRQ_FINAL_SECURITY_VERIFICATION.md` | Rust/eBPF/doc audits, E-09 fix, risk register | `PASS_WITH_LIMITATIONS` |
| `PRQ_FINAL_KERNEL_COMPATIBILITY.md` | Historical VM vs final candidate | `PARTIAL` |
| `PRQ_FINAL_ENFORCEMENT_PROOF.md` | Representative LSM / egress / kill VM proof; full matrix gaps | `PARTIAL` (executed cases `PASS`) |
| `PRQ_FINAL_PERFORMANCE_AND_SOAK.md` | Bounded observation vs soak gap | `PARTIAL` / `UNKNOWN` |
| `PRQ_FINAL_INSTALLER_AND_RECOVERY.md` | Packaged CLI vs clean-host install | `PASS_WITH_LIMITATIONS` / `NOT_RUN` |
| `PRQ_FINAL_CI_QUALIFICATION.md` | Workflow inspection and local replay | `LOCAL_CI_REPLAY` |
| `PRQ_FINAL_SUPPLY_CHAIN_REPORT.md` | Advisory audit PASS, license policy gap | `PARTIAL` |
| `WARDEN_FINAL_PRODUCTION_QUALIFICATION.md` | Final production authority | `NOT QUALIFIED` / `BLOCKED` |
| `WARDEN_FINAL_RELEASE_DECISION.md` | Final public release authority | `RELEASE_BLOCKED` |
| `WARDEN_FINAL_KNOWN_LIMITATIONS.md` | Consolidated capability and proof limits | informational |
| `WARDEN_ALPHA_RELEASE_NOTES.md` | Candidate release-note content | informational |
| `WARDEN_FINAL_OPERATOR_HANDOFF.md` | Lab operator handoff and status semantics | informational |

## 3. Private raw evidence (excluded from export)

| Path | Contents |
|---|---|
| `evidence/prq/PRQ_00_baseline_raw.txt` | Raw baseline captures |
| `evidence/prq/PRQ_01_secret_scan_fallback.txt` | Raw fallback pattern matches |
| `evidence/prq/PRQ_01_git_history_scan.txt` | Path-only history enumeration |
| `evidence/prq/PRQ_01_PUBLIC_SNAPSHOT_RESCAN.txt` | Raw snapshot rescans |
| `evidence/prq/PRQ_02_CONFIG_PERMISSION_FIX.txt` | Config mode fix + self-test before/after |
| `evidence/prq/PRQ_02_TEST_SEMANTICS_FIX.txt` | Privileged-test runner exit codes |
| `evidence/prq/PRQ_03_BUILD_GATES.txt` | All gate commands and exit codes |
| `evidence/prq/PRQ_03_FULL_TEST_SUITE.txt` | Complete 718-test output |
| `evidence/prq/PRQ_10_CLEAN_EXPORT_GATES.txt` | Clean-export gate commands, exit codes, honest `SKIP` |
| `evidence/prq/PRQ_10_LINK_CHECK.txt` | Fallback Markdown link check (0 hard broken, 32 soft/intentional) |
| `evidence/prq/PRQ_10_EXPORT_FULL_TEST_SUITE.txt` | Full 718-test output from the clean export |
| `evidence/prq/final/vm_armed/**` | Raw FINAL-02 VM preflight, snapshot, LSM/egress/kill armed outputs, log read-back and summary |
| `evidence/prq/PRQ_10_FINAL_VERIFICATION.txt` | Final rebuild, rescan, digests, worktree preservation |
| `evidence/m15/**`, `evidence/m16/**` | Raw privileged VM evidence (host details, PIDs, BTF IDs) |
| `scripts/LIVE_VALIDATION` (private raw runbook; not published) | Raw operational runbook (§§15–24 referenced by older docs) |
| `docs/security/WARDEN_MISSION_1[56]_*.md` | Historical mission reports |

### Cross-reference: raw runbook sections → public sanitized counterpart

| Raw section (private) | Topic | Public counterpart |
|---|---|---|
| §15 | BTF/CO-RE preflight, cgroup/LSM capability boundary | `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md`, `PRQ_05_SENTINEL_INTEGRATION_REPORT.md` |
| §16 | Connect verdict ABI, internal kprobe limits | `PRQ_02_EBPF_RISK_REGISTER.md` E-08, `PRQ_07_TEST_AND_PERFORMANCE_REPORT.md` |
| §17 | cgroup egress shadow/armed semantics | `PRQ_06_ENFORCEMENT_QUALIFICATION.md` |
| §18 | Inbound accept, netns boundary | `PRQ_02_EBPF_RISK_REGISTER.md` |
| §22 | Socket inventory, connection counts, ring drain | `PRQ_07_TEST_AND_PERFORMANCE_REPORT.md` |
| §23 | IPv4/IPv6 family gap and six hook prototypes | `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md`, `PRQ_02_EBPF_RISK_REGISTER.md` E-06 |
| §24 | Privileged runbook / cleanup | `PRQ_06_ENFORCEMENT_QUALIFICATION.md` |

The raw log is **not** reproduced in the public repository; the table above is
the sanctioned pointer for readers of older documents.

## 4. Test tally

| Run | Passed | Failed | Ignored |
|---|---|---|---|
| M16 historical | 716 | 0 | 1 |
| PRQ-01 current checkout | 718 | 0 | 2 |
| PRQ-01 clean public export | 718 | 0 | 2 |
| FINAL-02 clean public export | 721 | 0 | 2 |
| FINAL-02 disposable-VM armed LSM runner | 1 | 0 | 0 |

The two ignored tests are the deliberately `#[ignore]`d privileged BPF-LSM case
and one pre-existing ignored test. The privileged runner returned `SKIP` with
exit 77 on the development host: `SKIP` is **not** a pass. The separately
recorded VM run of that ignored case returned exit 0 and is evidence only for
the case it executed.

## 5. Final verification

Recorded after the final rebuild; raw output is in
`evidence/prq/PRQ_10_FINAL_VERIFICATION.txt` and the other `PRQ_10_*` files
listed in section 3. Detailed interpretation is in
`PRQ_10_PUBLIC_REPOSITORY_CONTENTS.md`.

| Check | Result |
|---|---|
| Snapshot rebuilt from final tree | `PASS` — 112 files, no `target/` or `.git`, modes preserved |
| Redacted rescan (private IPs / home paths / private URLs / key files) | `PASS` — no matches, no key/cert/env/ZIP/raw-runbook files |
| BPF object digest and absent `/home/` strings | `PASS` — SHA-256 `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`, 0 `/home/` strings, `make bpf` reports current |
| Documentation link check | `PASS` (local targets) — 50 Markdown files, 0 hard broken; 33 intentional soft references to excluded private evidence/historical docs/kernel source; external URL reachability `NOT_RUN` |
| Clean-export build/test/clippy gates | `PASS` — all gates exit 0; full suite 721 passed / 0 failed / 2 ignored; `scripts/test-privileged.sh` exit 77 `SKIP` (not a `PASS`) |
| gitleaks 8.30.1 public export + canonical tree | `PASS` — re-run after the armed-evidence doc updates; 0 findings each; checksum verified; no private history in export |
| cargo-audit 0.23.0 final lockfile | `PASS` — 1566 advisories, 72 deps, exit 0; RustSec DB `1d328b6bb9f2f350bf65c1c81ab68781cb9e018a` |
| FINAL-02 VM recovery snapshot | `PASS` — fresh `prq_final2_baseline` created, reverted and verified `running` with SSH, exact BPF SHA and release binary |
| Representative armed VM proof | `PASS` for executed cases — pre-opened-fd `-EPERM`; armed egress TCP4/UDP4/TCP6 `-EPERM`, non-match allow, 4/4 hooks ARMED read-back; kill takedown via `pidfd_send_signal` with `action=killed`. Full matrices remain `PARTIAL` / `NOT_RUN`; egress harness timing and stale-grep artifacts are recorded |
| `cargo deny` / hosted CI | `NOT_RUN` — tool/runner unavailable locally |
| `git diff --check` | `PASS` — exit 0 |
| User work preserved / parent mirrors unchanged | `PARTIAL` — deleted tracked `Warden/warden.zip` still deleted, unrelated monorepo work present, both parent mirrors byte-identical; untracked `Warden/warden2.zip` was recorded present in earlier FINAL-02 integrity logs but is absent at final recheck, cause `UNKNOWN`, no copy found in targeted host paths or the VM, not reconstructed |
| No commit / push / tag / publish / history rewrite / remote change | `PASS` (none performed) |

The `SKIP` result for privileged qualification on the host is deliberately not
counted as a pass. The VM `PASS` results are narrow lab evidence, not a full
enforcement matrix. Neither local export readiness nor those VM proofs change
the release or production decisions: public release remains `RELEASE_BLOCKED`
and production remains `NOT QUALIFIED` / `BLOCKED`.


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
