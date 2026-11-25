# WARDEN — FINAL-02 Public Release Decision

**Public release: `RELEASE_BLOCKED`. Local content readiness: `PASS`.
Publication: `NOT_PERFORMED`.** Prepared 2026-11-24. This is a decision record,
not a publishing action.

No commit, tag, push, remote change, repository visibility change, or parent
SENTINEL modification was performed. The sanitized snapshot is a local staging
directory only.

## 1. Alpha criteria

| Requirement | Status | Evidence |
|---|---|---|
| Sanitized snapshot from a fresh export, no inherited private Git history | `PASS` | Allow-list export; `.git` absent; exact manifest in `PRQ_FINAL_EVIDENCE_INDEX.md` |
| License and attribution | `PASS` / `PARTIAL` | Unmodified GPL-2.0 text, SPDX headers, SBOM; native-library binary distribution unresolved |
| Real, monitored private vulnerability reporting channel | `BLOCKED` | Not configured; no email, PGP key, team identity or third-party account invented |
| Clean-clone build and reliable statuses | `PASS` locally / `NOT_RUN` hosted | Clean-export gates green; host `SKIP` exit 77 is not a pass; VM privileged exit 0 is recorded separately; hosted CI unavailable |
| Honest documentation | `PASS` | FINAL-02 corrections, six mandatory limitations preserved, representative VM proof caveats stated, no production claim |
| Safe defaults | `PASS` | `mode = observe`, `enforce.arm = false`, kill off, egress disabled/unarmed, no bridge in public example, config `0640` |
| Contributor-ready structure | `PASS` | CI workflow, issue/PR templates, CONTRIBUTING, CoC, CHANGELOG, `.gitignore`, `.gitattributes` |
| Secret / history / advisory gates | `PASS` locally / `NOT_RUN` hosted | gitleaks 8.30.1 and cargo-audit 0.23.0 verified locally; hosted CI not run, `cargo deny` unavailable |

## 2. Why the decision remains blocked

A public security project must give reporters a real, monitored private channel
before release. The mission rules forbid inventing an address, PGP key or
account. `SECURITY.md` names GitHub Private Vulnerability Reporting as the
intended mechanism and marks enabling it as an external gate. Until a maintainer
enables it and submits a harmless test report through the real channel, this
gate cannot be called complete. No `PASS_WITH_LIMITATIONS` substitute is used.

Creating the public repository from the sanitized export is also an external
maintainer action. The canonical private history must not be pushed or rewritten
to satisfy this gate.

## 3. Completed locally vs external actions

| Item | Locally completed | External / still open |
|---|---|---|
| Fresh sanitized export and manifest | `PASS` | Create the public repository from it (`NOT_RUN`) |
| Secret and history audit | `PASS` local tools | Hosted full-history gitleaks (`NOT_RUN`) |
| Advisory audit | `PASS` for exact lockfile | Re-run in hosted CI (`NOT_RUN`) |
| License/SBOM review | `PASS` / `PARTIAL` | `cargo deny` policy + native-license decision (`NOT_RUN`) |
| Clean-export build and tests | `PASS` | Hosted CI four jobs (`NOT_RUN`) |
| Documentation truth and safe defaults | `PASS` | Final public docs review by maintainer (`NOT_RUN`) |
| Private vulnerability reporting | not possible locally | Enable and test channel (`BLOCKED`) |
| SENTINEL live integration | local collector contract only | Authorized endpoint/tenant/credentials (`BLOCKED`) |
| Production qualification | representative armed VM proofs `PASS`; full matrix open | `NOT QUALIFIED` / `BLOCKED` |

## 4. Required sequence when unblocked

1. Enable the real private reporting channel and prove it with a harmless test
   report; record the result privately.
2. Create the public repository from the final sanitized export with a fresh
   initial commit. Do not rewrite or expose canonical history.
3. Set description, topics, GPL-2.0-only license selection, branch protection
   and the verified reporting channel.
4. Run all four CI jobs; triage findings; confirm the privileged job reports
   `SKIP` on unprivileged runners, not `PASS`.
5. Re-export from the final tree and re-run the local gates if any file changed
   after this decision.

Only after those steps is a new release decision warranted. Nothing in this
document authorizes publication by itself.
