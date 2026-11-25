# WARDEN-PRQ-FINAL-02 — Final Baseline and Candidate Freeze

status=`PASS` — baseline verified and final candidate frozen. Prepared
2026-11-24 on Ubuntu 26.04.1 LTS, Linux `7.0.0-15-generic` (x86_64),
unprivileged UID 1000. This is a private release-engineering record; only
sanitized conclusions are intended for eventual public disclosure.

## 1. Authoritative starting point

PRQ-01 records were read before modification. Historical M16 closure
(`COMPLETED_WITH_LIMITATIONS`, `LAB_VALIDATED`) was not reopened. The volatile
`/tmp/opencode/prq` working area was empty at mission start after a server
restart; canonical reports and evidence in `Warden/` had survived. The export
builder, link checker and gate runner were recreated and then used against the
canonical tree.

## 2. Git and repository state

| Item | Actual value |
|---|---|
| Git root | `<home>/Desktop/Project` |
| HEAD | `e4d5f7adea0f957d37c70dbc162782583a0ce01c` |
| Branch | `main` |
| Tags | `w-r4-closed-d45097d` (unchanged) |
| Remotes | one `origin` (unchanged; value not reproduced here) |
| `git diff --check` | exit 0 |
| Parent mirrors | `warden_phase7_egress_enforcement.md` and `warden_coverage_matrix.md` byte-identical |
| Deleted tracked `Warden/warden.zip` | still deleted — preserved |
| Untracked `Warden/warden2.zip` | `ABSENT` at final recheck — earlier FINAL-02 integrity logs recorded it present (2,481,554 bytes); cause `UNKNOWN`, no copy found in targeted host paths or the disposable VM, not reconstructed |
| Unrelated `<parent-project>/` changes | present (13 paths measured: 1 modified + 12 untracked) |
| Unrelated `<parent-project>/`, `<parent-project>/` work | preserved |
| Release branch | none existed; none created |

The PRQ-01 count of 12 `<parent-project>/` paths differs from the 13 observed here. No
`<parent-project>/` file was touched by this mission; the discrepancy is recorded, not
treated as a defect. The final absence of `warden2.zip` downgrades the
user-work preservation gate to `PARTIAL`; the other preserved items above are
unchanged.

## 3. Final candidate freeze

| Property | Value |
|---|---|
| Candidate root | local staging `public_snapshot/WARDEN` — never published |
| Included files | 112 |
| Exact size and per-file digests | `evidence/prq/final/PRQ_FINAL_CANDIDATE_MANIFEST.sha256` |
| Build output | no `target/` in the export; no `.git` directory |
| Config modes | `config/warden.toml` `0640`, `config/warden.example.toml` `0640` |
| Script modes | installer `0775`, phase6 validator `0775`, privileged runner `0755`, two `scripts/tests/` regressions `0775` |
| BPF object | `bpf/warden.bpf.o`; SHA-256 `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`; 1,243,656 bytes; 0 `/home/` strings; `make bpf` reports current |
| `Cargo.lock` SHA-256 | `509d60d0d324a152ea174ed68da2bf79dca2dd8716266bc46d8d692946f51a8f` |
| `LICENSE` SHA-256 | `edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6` |

The initial FINAL-02 export was byte-identical to PRQ-01 (95 files). Later
FINAL-02 work added one security report, six qualification reports, five final
authority documents and a bare parent-path sanitization rule. Every count and
digest in this record therefore refers to the regenerated 112-file candidate,
not the initial 95-file baseline. Any later source, config or doc change
requires regenerating the manifest.

## 4. Test baseline

The final clean-export suite reports **721 passed, 0 failed, 2 ignored**. All
clean-export gates exit 0; `scripts/test-privileged.sh` exits 77 `SKIP`, which
is not a pass. Historical M16 reported 716 passed / 0 failed / 1 ignored and
PRQ-01 reported 718 / 0 / 2. Full raw output is in the FINAL-02 evidence index.

## 5. Outstanding changes and blockers

| Item | Status |
|---|---|
| Dedicated secret scanning | `PASS` locally with gitleaks 8.30.1; hosted CI `NOT_RUN` |
| Advisory audit | `PASS` locally with cargo-audit 0.23.0; `cargo deny` `NOT_RUN` |
| Real SENTINEL live delivery | `BLOCKED` / `NOT_RUN` |
| Armed LSM / cgroup egress / kill proof on final source | `PARTIAL` — representative VM cases `PASS`, full matrices `NOT_RUN` |
| Additional kernel/distribution matrix | `UNKNOWN` |
| Long-duration soak | `UNKNOWN` |
| Hosted CI execution | `NOT_RUN` |
| Private vulnerability reporting channel | `BLOCKED` (external maintainer action) |

## 6. Scope of this final qualification

- No architecture rewrite, second config engine, new detection subsystem or
  duplicate installer.
- No commit, push, tag, publish, reset, clean, destructive checkout, history
  rewrite, force push, branch/tag deletion or remote visibility change.
- No privileged or armed destructive test on the active development host.
- No external service credentials used or invented.
- All remaining work operates on the frozen candidate and canonical tree; any
  change requires regenerating the manifest and re-running applicable gates.


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
