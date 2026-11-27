# WARDEN-PRQ-FINAL-02 — Final License and Attribution Review

status=`PASS` for WARDEN-authored material, declared Rust dependency licenses
and the fallback SBOM; `PARTIAL` for exact system-native library license
resolution. No formal legal opinion is offered. Prepared 2026-11-24.

## 1. Project license and version

| Item | Value |
|---|---|
| Package | `warden` `0.1.0` (`Cargo.toml`) |
| Proposed release designation | `v0.1.0-alpha.1` (pre-release metadata only; no tag created) |
| Project license | **GPL-2.0-only** |
| `LICENSE` | verbatim GNU GPL v2 text; SHA-256 `edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6` |
| `Cargo.toml` | `license = "GPL-2.0-only"` |
| eBPF sources | `SPDX-License-Identifier: GPL-2.0` in `bpf/warden.bpf.c` and `bpf/warden.h` (kernel-project spelling; normalization is an owner decision) |
| SBOM | `docs/release/warden_alpha1.spdx.json`; SPDX 2.3; 79 packages; 78 relationships; SHA-256 `8ce721ef5682bee00616de315227634b790b1389417b088170b1e76ede18b1f6` |
| `Cargo.lock` | 72 packages, 71 with registry checksums, 1 local package; SHA-256 `509d60d0d324a152ea174ed68da2bf79dca2dd8716266bc46d8d692946f51a8f` |

The `v0.1.0-alpha.1` designation fits the current crate version `0.1.0` and
the changelog's "prepared" wording. It has not been applied as a tag, package
or binary release.

## 2. Attribution inventory

| Category | Evidence | Status |
|---|---|---|
| WARDEN Rust source | single project `LICENSE` + crate license metadata | `PASS` |
| WARDEN eBPF C sources and shared header | SPDX identifiers; LICENSE applies | `PASS` |
| Generated `bpf/vmlinux.h` | generated from kernel headers; no invented license string | `PARTIAL` (upstream provenance should be documented by a maintainer) |
| Rust dependencies | 71 registry checksums in `Cargo.lock`; declared licenses inventoried in PRQ-09 and the SPDX SBOM | `PASS` |
| System-native libraries (libc, OpenSSL, kernel headers, clang output) | exact versioned license strings not resolved locally | `PARTIAL` |
| GPL-2.0 / OpenSSL interaction | documented explicitly in PRQ-09 §4; no claim that the final binary is unambiguously compatible | `PARTIAL` |
| Automated license policy gate | `cargo deny` not installed locally; CI job configured but not executed | `BLOCKED` locally / `NOT_RUN` externally |

PRQ-09 remains the authoritative detailed license report; this document adds
only the final candidate facts and does not contradict it.

## 3. Binary distribution implications

- The eBPF object is shipped as source-adjacent build output with debug info.
  It is GPL-2.0-only material under the project license.
- Binary redistribution would require satisfying GPL-2.0 obligations and
  resolving the native-library license question above. This mission prepares
  **source only** and publishes no binary, package or release asset.
- No third-party code was copied into the export without attribution; the
  export allow-list contains only WARDEN paths and project infrastructure.

## 4. External actions before publication

1. The public repository settings report `GPL-2.0` (GitHub's versionless
   GPLv2-only identifier), consistent with `Cargo.toml` `GPL-2.0-only`; the
   `LICENSE` file is unchanged.
2. Have a maintainer document the provenance/license of the generated
   `vmlinux.h` rather than guessing.
3. Run the CI `cargo deny check licenses bans` job in hosted CI and review any
   findings.
4. Obtain a legal determination before any binary distribution; not required
   for a source-only Alpha.

## 5. Gate summary

| Requirement | Status |
|---|---|
| Project license present and unmodified | `PASS` |
| SPDX identifiers on eBPF sources | `PASS` |
| Dependency licenses inventoried | `PASS` |
| SPDX SBOM valid and checksummed | `PASS` (fallback generator) |
| Native library license resolution | `PARTIAL` |
| Ownership / licensing ambiguity that blocks publication | none identified |
| Binary distribution | `NOT_PERFORMED` |
