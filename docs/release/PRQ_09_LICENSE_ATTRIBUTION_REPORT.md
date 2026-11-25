# WARDEN-PRQ-01 — Phase 9 License & Attribution Report

status=`PASS` for the WARDEN-authored material and declared Rust dependency
licenses; `PARTIAL` for system-native libraries, whose exact versioned licenses
could not be resolved with locally available tooling.

## 1. Project license

| Item | Value |
|---|---|
| Project license | **GPL-2.0-only** |
| `Cargo.toml` | `license = "GPL-2.0"` |
| `LICENSE` | Complete, verbatim GNU General Public License v2, June 1991 (338 lines), including the "How to Apply These Terms" section |
| `bpf/warden.bpf.c` | `SPDX-License-Identifier: GPL-2.0` |
| `bpf/warden.h` | `SPDX-License-Identifier: GPL-2.0` |
| Public SBOM | `licenseDeclared: GPL-2.0` / `licenseConcluded: GPL-2.0-only` for the root `warden` package and the eBPF object |

The license text was **not** edited or replaced with a summary. No `COPYING`,
`NOTICE`, or third-party attribution file exists in the canonical tree; the
attribution record is the SPDX SBOM plus the `Cargo.lock` checksums.

## 2. Attribution gaps that are honest, not fatal

| Gap | Treatment |
|---|---|
| No per-file copyright headers on Rust sources | Not added in PRQ (would be a large mechanical diff). The single project LICENSE and SPDX identifiers on eBPF sources establish the project-level licence. |
| No `NOTICE` file | Not invented. If a future contributor adds one, it must be reviewed for accuracy before publication. |
| Generated `bpf/vmlinux.h` has no SPDX header | It is generated from kernel headers, not WARDEN-authored code. Its upstream provenance should be documented by a future maintainer; PRQ did not guess a licence string. |
| Native runtime libraries | `libssl.so.3`, `libcrypto.so.3`, `libc`, `libgcc_s`, `libz`, `libzstd` are listed in the SBOM with `licenseDeclared: NOASSERTION` because no local tool resolved their versioned licence. Operators must satisfy themselves about the host OpenSSL/runtime licences in their deployment. |

## 3. Declared licenses in the resolved Cargo graph

All 71 third-party packages in `Cargo.lock` have a non-empty declared license
in `cargo metadata`. Distribution (as declared, not re-licensed by WARDEN):

| Declared string | Packages |
|---|---|
| MIT OR Apache-2.0 | 51 |
| Apache-2.0 OR MIT | 6 |
| Unlicense OR MIT | 5 |
| MIT/Apache-2.0 | 3 |
| MIT | 3 |
| Zlib | 1 |
| Apache-2.0/MIT | 1 |
| (MIT OR Apache-2.0) AND Unicode-3.0 | 1 |

Full per-package declared licenses and `pkg:cargo/…` purls are in
`docs/release/warden_alpha1.spdx.json`. `licenseConcluded` for third-party
packages is `NOASSERTION`: PRQ did not perform legal review of each crate.

## 4. GPL-2.0 and the OpenSSL runtime

`src/tls.rs` binds directly to the system OpenSSL 3 API via `extern "C"`; no
Rust TLS crate is used and no `Cargo.lock` entry changes. The release binary
dynamically links the host's `libssl.so.3` / `libcrypto.so.3`. This is a
**deployment dependency**, not vendored source. PRQ makes no legal conclusion
about GPL-2.0/OpenSSL compatibility and does not claim the binary is fully
static; both facts are documented in `PRQ_04_SUPPLY_CHAIN_REPORT.md`.

## 5. Tooling limitations

| Tool | Local status | Consequence |
|---|---|---|
| `cargo deny check licenses bans` | NOT AVAILABLE | No automated license-policy gate locally; configured in public CI |
| `syft` / `spdx` / `sbom4rust` | NOT AVAILABLE | SPDX SBOM produced by a documented fallback generator |
| SPDX license-list validation | NOT AVAILABLE | License identifiers recorded as declared; not validated against the SPDX list |

No license string is invented and no package is relabelled to make a gate pass.

## 6. External action before publication

1. Confirm that the public repository's stated license is **GPL-2.0-only** and
   that `LICENSE` is the unmodified v2 text.
2. Decide whether to add a `NOTICE` file; do not add one speculatively.
3. Let public CI run `cargo deny check licenses bans` and triage any finding.
4. Confirm the repository host's license picker matches `Cargo.toml` (external,
   not performed by PRQ).

## 7. Status

| Check | Status |
|---|---|
| Root project license present and verbatim | `PASS` |
| SPDX identifiers on eBPF sources | `PASS` |
| Dependency licenses inventoried | `PASS` |
| SBOM present and valid | `PASS` (fallback) |
| Native library license resolution | `PARTIAL` |
| Automated license policy gate | `BLOCKED` locally / `NOT_RUN` externally |
