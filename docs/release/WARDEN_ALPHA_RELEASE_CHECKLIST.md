# WARDEN — Public Alpha Release Checklist

This checklist separates **done locally** from **external maintainer actions**.
Nothing here publishes anything by itself.

## A. Completed locally (PRQ-01 and FINAL-02)

- [x] Baseline captured; authoritative tree and HEAD recorded (`PRQ_00_…`).
- [x] Current-tree fallback secret scan and path-only history scan (`PRQ_01_SECRET_SCAN_REPORT.md`).
- [x] Sanitized allow-list snapshot prepared; raw evidence, ZIPs, parent source, and operational config excluded (`PRQ_01_EXCLUDED_CONTENT_MANIFEST.md`).
- [x] BPF object rebuilt with `-fdebug-prefix-map`; 0 builder paths; reproducible; digest/provenance updated (`PRQ_01_PUBLIC_SANITIZATION_REPORT.md`).
- [x] Three confirmed code defects + misleading-success/test-integrity issues fixed with regressions (`PRQ_02_SECURITY_REVIEW.md`).
- [x] Documentation contradictions corrected; export-only reference rewrites for mirrored docs (`PRQ_02_DOCUMENTATION_CONTRADICTIONS.md`).
- [x] Safe public config example added (`0640`, observe-only, strict validation exit 0).
- [x] PRQ-01 local gates green: 718 passed / 0 failed / 2 ignored; clippy `-D warnings`; release build; CLI regressions (`PRQ_03_…`).
- [x] SPDX 2.3 fallback SBOM regenerated with correct root package and public object digest (`PRQ_04_…`).
- [x] Honest enforcement, kernel, test/performance, integration, installer, and license reports written.
- [x] Final snapshot rebuilt/rescanned, link-checked, clean-export gates run, and worktree verified (results in `PRQ_FINAL_EVIDENCE_INDEX.md`).
- [x] Dedicated gitleaks 8.30.1 scan of the 112-file export and canonical tree: 0 findings; checksum verified (`PRQ_FINAL_SECRET_AND_HISTORY_AUDIT.md`).
- [x] cargo-audit 0.23.0 advisory audit of the final lockfile: exit 0, 72 deps, RustSec DB `1d328b6bb9f2f350bf65c1c81ab68781cb9e018a` (`PRQ_FINAL_SUPPLY_CHAIN_REPORT.md`).
- [x] E-09 egress telemetry defect fixed with three regressions; 3xx redirect regression coverage added (`PRQ_FINAL_SECURITY_VERIFICATION.md`).
- [x] Seven documentation inaccuracies corrected; final authority docs and evidence index written.
- [x] FINAL-02 clean-export suite: 721 passed / 0 failed / 2 ignored; privileged runner `SKIP` (77).

## B. Blocking external actions (must be done by the maintainer)

1. **Enable a genuine private vulnerability reporting channel.** Preferred:
   GitHub Private Vulnerability Reporting on the target repository. Verify it
   by submitting a harmless test report through the real channel; record the
   result privately. Do not invent an email address, PGP key, or third-party
   account. Status: `BLOCKED`.
2. **Create the public repository from the sanitized export**, not from the
   parent monorepo. Use the current OSR-FINAL-03 sanitized candidate identified
   by the private final manifest, with a single fresh initial commit. Do
   **not** rewrite, push, or expose the canonical private history. Status:
   `NOT_RUN`.
3. **Set repository metadata:** description, topics, GPL-2.0-only license
   selection matching `LICENSE`/`Cargo.toml`, branch protection, and the
   reporting channel from step 1. Status: `NOT_RUN`.
4. **Let CI run on the published repository** and confirm green: unprivileged
   build/test/clippy, `gitleaks` full-history scan, `cargo audit`, `cargo deny`,
   and the BPF reproducibility check. Triage every finding before tagging.
   Status: `NOT_RUN`.
5. **Review the public docs one final time** for any deployment-specific detail
   introduced after the export. Status: `NOT_RUN`.

## C. Post-release, before any production claim

- [ ] Disposable-VM privileged qualification for all three enforcement axes,
      with verbatim 0/1/77 results.
- [ ] Additional kernel/distribution matrix entries.
- [ ] Defined soak with acceptance criteria and measured resource behaviour.
- [ ] Authorized live SENTINEL integration test with redacted evidence.
- [ ] Clean-host install/service-start/reload/deadman exercise.
- [ ] Formal acceptance or closure of each item in `WARDEN_KNOWN_LIMITATIONS.md`.

## D. Do-not-do list

- No `git reset --hard`, `git clean -fd`, destructive checkout, history rewrite,
  force push, branch/tag deletion, commit, push, tag, or remote visibility
  change as part of this checklist's local preparation.
- No deletion or modification of user work (the deleted tracked ZIP, the stale
  untracked ZIP, unrelated monorepo changes, or parent SENTINEL mirrors).
- No privileged test on the active host.
- No invented endpoint, credential, reporting channel, benchmark threshold, or
  production claim.

## E. Final public statement to use until section C is complete

> WARDEN public Alpha: observe-first, safe defaults, narrow armed lab proofs on
> one kernel, no full enforcement qualification, no production claim,
> publication `RELEASE_BLOCKED`. See `WARDEN_FINAL_KNOWN_LIMITATIONS.md`.
