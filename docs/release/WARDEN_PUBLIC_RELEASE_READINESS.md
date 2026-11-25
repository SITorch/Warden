# WARDEN — Public Alpha Release Readiness Decision

**Public release: `RELEASE_BLOCKED`. Local content readiness: `PASS`.**
FINAL-02 closes the local secret/advisory gaps without creating any external
channel or publication. Nothing in this decision authorizes a release.

This document states what PRQ-01 verified and what remains outside this
mission's authority. It is a decision record, not a publishing action. No
commit, tag, push, remote change, or repository publication was performed.

## 1. Readiness gates

| Gate | Requirement | Observed | Status |
|---|---|---|---|
| Sanitized public snapshot | Allow-list export, redacted, no raw evidence/ZIPs/parent source | Final 112-file export, rebuilt and rescanned after all FINAL-02 fixes; see `PRQ_10_PUBLIC_REPOSITORY_CONTENTS.md` | `PASS` |
| BPF object free of builder paths | No `/home/` strings, reproducible, provenance recorded | Rebuilt with `-fdebug-prefix-map`; 0 private paths; SHA-256 `2461fbc…5b3a`; byte-identical rebuild | `PASS` |
| Correct license & attribution | Unmodified GPL-2.0 text, SPDX IDs, dependency inventory | `LICENSE` verbatim v2, SPDX headers on eBPF C/H, 79-package SPDX SBOM | `PASS` / `PARTIAL` for native libs |
| Genuine private vulnerability reporting channel | Real, monitored, reachable by reporters | **Not configured**; no email, PGP key, or third-party channel invented | `BLOCKED` |
| Clean-clone build & tests | Public snapshot builds and tests without private context | All clean-export gates exit 0; 721 passed / 0 failed / 2 ignored; privileged runner `SKIP`; see `PRQ_10_PUBLIC_REPOSITORY_CONTENTS.md` | `PASS` |
| Reliable test statuses | SKIP never counted as pass; honest ignores | 721 passed / 0 failed / 2 ignored; privileged runner 0/1/77 with `77=SKIP` | `PASS` |
| Honest documentation | No live-denial or production claims; limits stated | PRQ-02 corrections plus seven FINAL-02 corrections; `WARDEN_FINAL_KNOWN_LIMITATIONS.md` | `PASS` |
| Safe defaults | Observe-only, no bridge, no denial, no kill, config mode `0640` | Public example validates `PASS_WITH_WARNINGS`; self-test exit 0 | `PASS` |
| Contributor-ready structure | `.gitignore`, `.gitattributes`, CI, CONTRIBUTING, CoC, CHANGELOG, templates | Present in snapshot | `PASS` |
| Secret scanning | Dedicated scanner with full history | gitleaks 8.30.1 and fallback scan pass locally; no private history in export; hosted CI `NOT_RUN` | `PASS` locally / `NOT_RUN` hosted |
| Advisory audit | cargo-audit 0.23.0, RustSec DB `1d328b6bb9f2f350bf65c1c81ab68781cb9e018a`, 72 deps, exit 0; hosted CI not yet run | `PASS` locally / `NOT_RUN` hosted |
| Canonical history handling | No rewrite, no private history in public repo | Fresh export strategy; no rewrite performed | `PASS` (strategy) |

## 2. Why the decision is `BLOCKED`, not `PASS_WITH_LIMITATIONS`

A public security project without a **real, monitored private vulnerability
reporting channel** would invite public disclosure of vulnerabilities. The
mission rules forbid inventing an address, PGP key, or third-party account.
`SECURITY.md` therefore names GitHub Private Vulnerability Reporting as the
intended mechanism and marks enabling it as an external gate. Until a
maintainer actually enables and tests it, the release gate is `BLOCKED`.

Two additional external gates are not satisfied: the maintainer must create the
public repository from the sanitized export (with a fresh single initial
commit) and let CI run `gitleaks`, `cargo audit`, and `cargo deny`. Those are
listed in `WARDEN_ALPHA_RELEASE_CHECKLIST.md`.

## 3. What is true now (bounded claims)

- The local snapshot contains only WARDEN material, sanitized, with safe
  defaults and no raw evidence.
- The eBPF object is reproducible and contains no private build paths; its
  program text and BTF types are unchanged from the M15/M16 object.
- The current checkout builds, formats, lints, and tests cleanly with
  `--offline --locked`; all unprivileged gates exit 0.
- No production, kernel-enforcement, soak, or real SENTINEL integration claim
  is made. See `WARDEN_PRODUCTION_QUALIFICATION.md`.

## 4. Explicit non-actions

The following were **not** done and remain maintainer decisions: creating the
public repository, changing its visibility, creating commits/tags, pushing,
rewriting history, modifying the parent SENTINEL repository, or contacting any
external party.

## 5. Re-evaluation criteria

Re-evaluate this decision to `PASS` only when all of the following are recorded:

1. Private vulnerability reporting enabled and a test report submitted through
   it successfully (channel proven real, not assumed).
2. Sanitized snapshot re-exported from the final tree and rescanned clean.
3. Clean-export build/test gates green (recorded in final evidence index).
4. `gitleaks` full-history scan, `cargo audit`, and `cargo deny` green in the
   published repository's CI.
5. Documentation link check clean and the final worktree/user-work verification
   complete.
