# WARDEN-PRQ-01 — Phase 4 Supply-Chain & Dependency Report

status=`PARTIAL` — lockfile and licenses inventoried with fallback tooling;
advisory scanning and SBOM generation by dedicated tools are `BLOCKED` locally
and delegated to public CI.

## 1. Dependency inventory

- `Cargo.lock` is committed and checked with `--locked` in every build/test gate.
- 72 resolved packages (71 third-party + the `warden` root crate).
- 9 direct runtime dependencies with a deliberately small tree: `aya 0.13`,
  `anyhow`, `libc`, `serde`, `serde_json`, `toml`, `signal-hook`, `log`,
  `env_logger`. One dev dependency: `aya-obj 0.2`.
- No Rust TLS crate: `src/tls.rs` binds directly to the system OpenSSL 3 API, so
  the binary dynamically links `libssl.so.3`, `libcrypto.so.3`, `libc`,
  `libgcc_s`, `libz`, `libzstd` (verified by `ldd`). **The binary is not fully
  static** and the host OpenSSL runtime is part of the deployment contract.

## 2. SBOM

`docs/release/warden_alpha1.spdx.json` — SPDX 2.3 JSON, valid, 79 packages and
78 relationships. It was produced by a **documented fallback** (cargo metadata +
Cargo.lock checksums + `ldd` + BPF object hash) because `syft`, `spdx`, and
`sbom4rust` are unavailable. Its `documentNamespace` is an explicit
`https://example.invalid/…` placeholder — not a published or resolvable URI.

The SBOM includes the public Alpha BPF object digest and records the
`-fdebug-prefix-map` rebuild in its creation info. Native libraries are listed
with `licenseDeclared: NOASSERTION` because local tooling cannot resolve their
versioned license metadata; this is an honest gap, not a claim of license
clarity.

## 3. License mix (declared by cargo metadata)

| Declared license | Count |
|---|---|
| MIT OR Apache-2.0 | 51 |
| Apache-2.0 OR MIT | 6 |
| Unlicense OR MIT | 5 |
| MIT/Apache-2.0 | 3 |
| MIT | 3 |
| Zlib | 1 |
| Apache-2.0/MIT | 1 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |

No package in the resolved set has an empty license field. Full per-package
declared licenses and `purl` references are in the SBOM. See
`PRQ_09_LICENSE_ATTRIBUTION_REPORT.md` for the project license and attribution
conclusions.

## 4. Advisory / policy scanning

| Tool | Local status | Public CI | Result |
|---|---|---|---|
| `cargo audit` | NOT AVAILABLE | `cargo install cargo-audit --locked` then `cargo audit` | `BLOCKED` / `NOT_RUN` |
| `cargo deny` | NOT AVAILABLE | `cargo install cargo-deny --locked` then `cargo deny check licenses bans` | `BLOCKED` / `NOT_RUN` |
| `gitleaks` history scan | NOT AVAILABLE | `gitleaks/gitleaks-action@v2`, full history | `BLOCKED` / `NOT_RUN` |

No advisory result is claimed. A public release must not claim "no known
vulnerabilities" until `cargo audit` has run green in CI.

## 5. Git history strategy

- Parent monorepo history contains 47 commits touching `Warden/`, plus all
  SENTINEL backend/frontend/deploy history, private remotes, and one private tag
  (`w-r4-closed-d45097d`).
- **Canonical private history is not rewritten.** No `git filter-repo`,
  `filter-branch`, history rewrite, force push, tag deletion, or branch changes
  were performed.
- Public repository must be a **fresh sanitized export/mirror** with a single
  initial commit created from `/tmp/opencode/prq/public_snapshot/WARDEN` by the
  user. No commit was created in this mission.
- The private remote URL and repository owner/path are redacted from all public
  artifacts.

## 6. Status summary

| Check | Status |
|---|---|
| Lockfile present and enforced (`--locked`) | `PASS` |
| SBOM generated and valid | `PASS` (fallback) |
| Dependency licenses inventoried | `PASS` |
| Vulnerability advisory scan | `BLOCKED` locally |
| License/ban policy scan | `BLOCKED` locally |
| Git history exposed to public | `BLOCKED` (export strategy required) |
| Overall | `PARTIAL` |
