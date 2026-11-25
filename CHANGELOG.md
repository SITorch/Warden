# Changelog

All notable changes to WARDEN are documented here. WARDEN has **no prior public
releases**; this file records the first prepared public Alpha and unreleased
changes. The format is based on [Keep a Changelog](https://keepachangelog.com/)
and the project intends to follow Semantic Versioning once it leaves Alpha.

## [Unreleased] — prepared `v0.1.0-alpha.1`

> Proposed pre-release designation. No tag, package, binary, or public release
> has been created. See `docs/release/WARDEN_ALPHA_RELEASE_CHECKLIST.md`.

### Added

- Public repository infrastructure: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md` (public policy), `CHANGELOG.md`, `SUPPORT.md`,
  `THIRD_PARTY_NOTICES.md`, `.gitignore`, `.gitattributes`, a pinned and
  least-privilege GitHub Actions workflow, issue/PR templates, a private
  vulnerability reporting form, Dependabot configuration, and a safe
  `config/warden.example.toml`.
- OSR-FINAL-03 candidate preparation: hardened CI pins, truthful support and
  disclosure gates, and a dated reconciliation of the intentional
  `warden2.zip` deletion. No publication or tag was created.
- Sanitized public evidence summaries and the PRQ-01/02/03/09 reports under
  `docs/release/` and `docs/security/`.
- `scripts/test-privileged.sh`: dedicated privileged qualification runner with an
  explicit `SKIP` (exit 77) convention.

### Changed

- Privileged BPF-LSM runtime test is now `#[ignore]`d in the default Rust suite;
  a skipped qualification can no longer be counted as a passing test.
- `config/warden.toml` sample permission corrected from `0664` to `0640`.
- Makefile build/test targets made lockfile-consistent (`--locked`).
- Public-facing documentation reconciled with M15/M16 evidence: IPv6 UDP volume
  `LIVE_VALIDATED_M15`, denial-axis terminology, and evidence boundaries.

### Fixed

- Misleading-success state where arming file enforcement reported `arm=true`
  while no BPF-LSM program was attached (see `docs/release/PRQ_02_SECURITY_REVIEW.md`).
- Incomplete secret redaction in health output (see same report).

### Known limitations (not fixed — see `docs/release/WARDEN_KNOWN_LIMITATIONS.md`)

- Live SENTINEL delivery: `BLOCKED` (no authorized staging environment).
- Additional kernels/distributions: `UNKNOWN`.
- Long-duration soak: `UNKNOWN`.
- Full armed kill, BPF-LSM and cgroup egress matrices: `NOT_RUN` / `PARTIAL`
  (representative disposable-VM cases passed on one kernel; see
  `docs/release/PRQ_FINAL_ENFORCEMENT_PROOF.md`).
- Not production-ready.
