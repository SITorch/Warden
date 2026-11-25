# WARDEN-PRQ-FINAL-02 — Final CI Qualification

status=`LOCAL_CI_REPLAY`. No hosted or self-hosted CI execution was performed.
Prepared 2026-11-24.

## 1. Workflow inspection

`.github/workflows/ci.yml` parses successfully (PyYAML) and defines four jobs:

| Job | Runner | Steps | Purpose |
|---|---|---:|---|
| `build-and-test` | `ubuntu-latest` | 16 | toolchain, native BPF tools, cache, locked/offline build, format, check, tests, clippy, release build, BPF rebuild check, object integrity, config validation, two CLI regressions, privileged-test structural check |
| `supply-chain` | `ubuntu-latest` | 4 | install `cargo-audit` + `cargo-deny`, advisory audit, license/bans check |
| `secret-scan` | `ubuntu-latest` | 2 | full-history checkout, gitleaks action |
| `docs` | `ubuntu-latest` | 2 | lychee offline Markdown link check |

Triggers: push to `main`, pull request, `workflow_dispatch`. Permissions:
`contents: read` only. Actions are pinned to moving major tags
(`actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`,
`gitleaks/gitleaks-action@v2`, `lycheeverse/lychee-action@v2`), not commit SHAs:
a supply-chain hardening item for the maintainer.

## 2. Failure semantics

- Every gate is a separate `run` step; a non-zero step fails the job.
- Clippy uses `-D warnings`.
- The privileged test is checked structurally and via
  `bash scripts/test-privileged.sh`; CI explicitly requires exit 77 (`SKIP`)
  on unprivileged runners. It cannot silently report a functional PASS.
- No privileged BPF/LSM/egress/kill test runs in ordinary CI.

## 3. Local replay evidence

PRQ-01 clean-export gates (byte-identical snapshot at that time) all exited 0:
format, check, tests, clippy, release build, both config validations, self-test,
two CLI regressions, three integration suites, `make bpf`. Full suite: 718
passed / 0 failed / 2 ignored; `test-privileged.sh` exit 77 `SKIP`.

FINAL-02 changes (redirect regression coverage, egress map-full counter fix,
documentation corrections) were validated locally with targeted tests:
egress 22 passed, redirect 1 passed, clippy `-D warnings` exit 0, check no code
warnings. Final full-candidate gate is recorded in the evidence index.

## 4. Not executed

| Item | Status | Reason |
|---|---|---|
| Hosted CI | `NOT_RUN` | no authorized staging repository / hosted runner |
| Self-hosted CI | `NOT_RUN` | none configured |
| `cargo audit` in CI | `NOT_RUN` locally | install attempt interrupted by server restart; record as unavailable unless final local binary exists |
| `cargo deny check licenses bans` | `NOT_RUN` | tool not installed locally |
| gitleaks action | `BLOCKED` externally; locally reproduced | local gitleaks 8.30.1 with verified checksum |
| lychee link action | `BLOCKED` externally; local fallback used | offline fallback checker |
| Failed-gate propagation in a real runner | `NOT_RUN` | reviewed statically only |

No remote was changed and no candidate was pushed to test the workflow.

## 5. Required external action

Create the public repository, then run `workflow_dispatch` on a sanitized
branch or open a pull request; confirm four jobs pass, confirm a deliberately
failing gate fails the pipeline, and confirm the privileged job reports `SKIP`
rather than `PASS`. Optionally pin actions to immutable commit SHAs before the
first hosted run.

## 6. Decision

`LOCAL_CI_REPLAY` only. A local replay must not be presented as hosted CI.
