# WARDEN-PRQ-01 — Phase 3 Build & Gate Reproducibility Report

status=`PASS` for the current checkout; clean-snapshot verification is covered in
`PRQ_10_PUBLIC_REPOSITORY_CONTENTS.md` and the final evidence index.

## 1. Environment

| Tool | Version |
|---|---|
| rustc | 1.95.0 (59807616e 2026-04-14) |
| cargo | 1.95.0 (f2d3ce0bd 2026-03-21) |
| clang | Ubuntu clang 21.1.8 (6ubuntu1) |
| bpftool | 7.7.0 |
| git HEAD | `e4d5f7adea0f957d37c70dbc162782583a0ce01c` (branch `main`) |

`cargo-audit`, `cargo-deny`, `syft`, `spdx`, `sbom4rust`, `markdown-link-check`,
`shellcheck`, `gitleaks`, `trufflehog`, `rg`, and `git-lfs` are **unavailable**
locally. Fallbacks are documented in the relevant reports.

All Cargo commands used `--offline --locked` after dependencies were cached;
`Cargo.lock` has 72 resolved packages including the root crate.

## 2. Gate results

Evidence: `evidence/prq/PRQ_03_BUILD_GATES.txt` and
`evidence/prq/PRQ_03_FULL_TEST_SUITE.txt`.

| Gate | Command | Result |
|---|---|---|
| Whitespace | `git diff --check` | exit 0 `PASS` |
| BPF stamp | `make bpf` | exit 0 — object current, all input+object hashes match `.built-from` `PASS` |
| Format | `cargo fmt --all -- --check` | exit 0 `PASS` |
| Check | `cargo check --all-targets --offline --locked` | exit 0 `PASS` |
| Tests | `cargo test --offline --locked` | exit 0 — **718 passed, 0 failed, 2 ignored** `PASS` |
| Clippy | `cargo clippy --all-targets --all-features --offline --locked -- -D warnings` | exit 0 `PASS` |
| Release | `cargo build --release --offline --locked` | exit 0 `PASS` |
| Public config validation | `warden --config-validate --strict --config config/warden.example.toml` | exit 0 `PASS_WITH_WARNINGS` (expected empty-app-cgroup warning) |
| Sample config validation | `warden --config-validate --strict --config config/warden.toml` | exit 0 `PASS_WITH_WARNINGS` |
| Config-engine CLI | `scripts/tests/test_config_engine_cli.sh` | exit 0 `PASS` |
| Installer CLI | `scripts/tests/test_install_wizard.sh` | exit 0 `PASS` |
| BPF integrity | `cargo test --test embedded_object_is_the_shipped_object --test capability_matrix` | exit 0 `PASS` |
| Privileged qualification | `bash scripts/test-privileged.sh` (unprivileged host) | exit 77 `SKIP` — **not a pass** |

## 3. Test-count delta from M16

| Run | Passed | Failed | Ignored |
|---|---|---|---|
| M16 historical gate | 716 | 0 | 1 |
| PRQ current | 718 | 0 | 2 |

The +2 passed / +1 ignored delta is fully accounted for:

- +1 ignored: the privileged BPF-LSM runtime case is now `#[ignore]`d so it can
  never inflate the default pass count.
- +1 passed: regression guard asserting that the runtime case stays `#[ignore]`d.
- +1 passed: new secret-redaction regression test.
- (the second redaction test is counted inside the same binary's total)

## 4. BPF object integrity and lineage

| Property | Value |
|---|---|
| Size | 1,243,656 bytes |
| SHA-256 | `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a` |
| FNV-1a | `0xbc288747047b4edb` |
| `.built-from` | `80a6eeeb…b039 2461fbcd…5b3a` |
| Program count | 32 expected (embedded-object test) |
| BTF types | 1,927 (`bpftool btf dump` exit 0) |
| Private `/home/` strings | 0 |

Determinism evidence: rebuilding with the original flags reproduced the M16
object byte-for-byte; rebuilding with `-fdebug-prefix-map` reproduced the public
object byte-for-byte. `.text` is byte-identical between the two; BTF dumps are
identical after normalizing the path prefix. Therefore this is a metadata-only
change, not a new sensor implementation.

## 5. Known gate limitations

- `make bpf` skips recompilation when hashes match; this is by design and the
  stamp covers `warden.bpf.c`, `warden.h`, `vmlinux.h`, and the object.
- The CI workflow rebuilds BPF and asserts `git diff --exit-code` on the object;
  with the new prefix map this is reproducible only if the builder's `CURDIR`
  differs — the flag maps the *absolute* cwd to `.`, so the output is independent
  of the checkout path. (Verified by two identical rebuilds.)
- Advisory/license tool gates are in public CI (`cargo audit`, `cargo deny`),
  not locally verifiable. Status: `BLOCKED` locally, `NOT_RUN` externally.

## 6. Decision

Build and test reproducibility for the current checkout: `PASS`. This does not
imply kernel-load, enforcement, or production readiness.
