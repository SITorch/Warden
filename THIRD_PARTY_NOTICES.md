# Third-party notices

This file summarizes licensing information for the public WARDEN Alpha source
candidate. It is not a legal opinion.

## WARDEN project material

WARDEN is licensed under **GPL-2.0-only**. The root `LICENSE` contains the
verbatim GNU General Public License version 2 text. The eBPF sources carry
`SPDX-License-Identifier: GPL-2.0`; the userspace package declares
`license = "GPL-2.0-only"` in `Cargo.toml`. The two eBPF SPDX headers retain
the kernel-project `GPL-2.0` spelling; changing them is an owner decision and
this document does not infer `or-later` terms from that spelling.

## Rust dependencies

The locked dependency set is recorded in `Cargo.lock` and the generated
`docs/release/warden_alpha1.spdx.json` SBOM (SPDX 2.3, 79 packages, 78
relationships). The observed license distribution in that SBOM is:

- 51 packages under `MIT OR Apache-2.0`.
- 6 under `Apache-2.0 OR MIT`.
- 3 under `MIT/Apache-2.0` and 1 under `Apache-2.0/MIT`.
- 5 under `Unlicense OR MIT`.
- 3 MIT-only packages.
- 1 package under `(MIT OR Apache-2.0) AND Unicode-3.0`.
- 1 Zlib-licensed package.
- 2 WARDEN entries under GPL-2.0-only.
- 6 native runtime library entries with `NOASSERTION`.

`cargo metadata --locked` reports 72 Rust packages; the SBOM has 79 entries
because it also records the WARDEN root package and six native runtime
libraries.

The exact package-by-package inventory, versions, evidence sources, and
redistribution status are retained in the private OSR license inventory and
legal-uncertainty report; raw private evidence is not part of this public
candidate.

## Native and build-time components

- The optional direct mTLS bridge binds to the host OpenSSL 3 API through
  `extern "C"` in `src/tls.rs`. A binary built with that feature links the
  host's `libssl.so.3` and `libcrypto.so.3` dynamically. Those libraries are not
  bundled in this public source candidate.
- The default bridge uses cleartext HTTP over `std::net`; TLS is expected to be
  terminated at a trusted edge where applicable.
- `clang`, `llvm`, and `libbpf-dev` are build-time tools. They are not vendored
  or redistributed in this candidate.
- The shipped `bpf/warden.bpf.o` is generated from WARDEN's own GPL-2.0 eBPF
  source using the recorded toolchain. No third-party binary is bundled.

## Redistribution boundary

The public source candidate contains source, configuration, documentation and
the WARDEN-built BPF object. It does **not** contain a userspace release binary,
private ZIP archives, VM snapshots, raw evidence, or vendored native libraries.
Exact redistribution conditions for a future binary distribution, including the
dynamically linked native libraries and the six `NOASSERTION` SBOM entries,
remain `LEGAL_REVIEW_REQUIRED`. Do not publish or ship a binary until that
review is complete.
