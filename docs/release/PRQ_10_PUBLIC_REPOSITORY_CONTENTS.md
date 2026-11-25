# WARDEN-PRQ-FINAL-02 — Public Repository Contents and Final Export Gates

status=`PASS` for local snapshot preparation. This report describes what is in
the final sanitized export, what was transformed, and the checks run against
that exact tree. It does **not** authorize publication; see
`WARDEN_FINAL_RELEASE_DECISION.md` (`RELEASE_BLOCKED`) and
`WARDEN_ALPHA_RELEASE_CHECKLIST.md`.

All raw outputs referenced here live in private `evidence/prq/` and are excluded
from the export. The snapshot path below is a local staging directory; nothing
was pushed, tagged or published.

## 1. Snapshot manifest

| Item | Value |
|---|---|
| Public snapshot root | local staging directory `public_snapshot/WARDEN` |
| Included files | **112** |
| Exact size and per-file SHA-256 | `evidence/prq/final/PRQ_FINAL_CANDIDATE_MANIFEST.sha256` |
| Build inputs | `Cargo.toml`, `Cargo.lock`, `Makefile`, `LICENSE` |
| BPF object | `bpf/warden.bpf.o` — 1,243,656 bytes; SHA-256 `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`; FNV-1a `0xbc288747047b4edb`; 0 `/home/` strings |
| `target/` in snapshot | `NO` — all build output kept outside the export |
| `.git` in snapshot | `NO` — no inherited private history |

File distribution (112 total):

| Area | Files | Contents |
|---|---:|---|
| Root | 12 | `Cargo.toml`, `Cargo.lock`, `LICENSE`, `Makefile`, `README.md`, `DESIGN.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `.gitignore`, `.gitattributes` |
| `src/` | 26 | Canonical Rust implementation — no second config engine or duplicate subsystem |
| `bpf/` | 5 | `.built-from`, `vmlinux.h`, `warden.bpf.c`, `warden.bpf.o`, `warden.h` |
| `tests/` | 13 | Integration / ABI / capability / coverage tests |
| `config/` | 2 | `warden.example.toml` (install default) and sanitized `warden.toml` (compile-time test fixture only) |
| `scripts/` | 6 | Installer, bridge check, privileged validator, honest privileged runner, two CLI regressions |
| `systemd/` | 2 | `warden.service`, `warden-deadman@.service` |
| `.github/` | 3 | Unprivileged CI workflow, bug report template, PR template |
| `docs/security/` | 4 | Coverage matrix, threat model, phase-7 egress enforcement, FINAL-02 security verification |
| `docs/release/` | 39 | Sanitized PRQ / FINAL-02 / final authority reports plus `warden_alpha1.spdx.json` |

The full file-by-file allow-list is implemented by the export builder and its
addition/removal rationale is recorded in `PRQ_01_EXCLUDED_CONTENT_MANIFEST.md`.

### File modes and special files

- Config files: mode `0640` in the export, same as canonical.
- Script modes are preserved from the canonical tree; a rebuild initially
  dropped executable bits and the builder now restores them explicitly.
- No `.pem`, `.key`, `.crt`, `.env*`, `warden.zip`, `warden2.zip`, raw
  `LIVE_VALIDATION.md`, xattrs or symlinks are present.

## 2. Export-only transformations

The canonical tree is not rewritten. These changes are applied by the export
builder only, so the parent SENTINEL byte-identical doc checks remain green.
Counts are captured in the final export-build evidence
(`evidence/prq/final/PRQ_FINAL_EXPORT_BUILD.txt`).

| Transformation | Purpose |
|---|---|
| Private IP literals → `<internal-ip>` | Remove host/network identities while retaining synthetic test literals |
| `/home/<user>` paths → `<home>` | Remove local account paths |
| Private URL literals → `<redacted-private-url>` | Remove private Git/forge URL |
| Credential-like assignments → `<redacted>` | Remove plausible secrets |
| Dead raw-doc references → sanitized PRQ counterparts | Keep public docs self-consistent after evidence exclusion |
| Private platform/source paths → neutral descriptions | Remove parent-monorepo file paths, including bare `<parent-project>/`, `<parent-project>/` and `<parent-project>/` area names |

Notes and boundaries:

- WARDEN's own bridge path `/api/v1/sentinel/host/` is a real source literal and
  test fixture; it is deliberately not rewritten.
- Source and test files are copied verbatim except for path-only rewrites;
  generic redaction would corrupt synthetic IP literals used by tests.
- The BPF object was rebuilt with `-fdebug-prefix-map` in PRQ-01; `.text` and
  BTF types match the historical object after path normalization.
- `config/warden.toml` remains only because `src/config.rs` uses `include_str!`;
  public install prose points at `config/warden.example.toml`.

## 3. Documentation link check

`markdown-link-check` is unavailable locally; a fallback checker inspected every
exported Markdown file:

| Check | Result |
|---|---:|
| Markdown files scanned | 50 |
| Hard broken inline links (local targets) | **0** |
| Unresolved backticked repo-relative paths | **33** (soft/intentional) |

The soft findings are references to excluded private evidence, historical
mission reports or a kernel source path outside this repository. External URL
reachability is `NOT_RUN`; no availability claim is made. Raw output:
`evidence/prq/final/PRQ_FINAL_LINK_CHECK.txt`.

## 4. Clean-export gates

Gates were executed from the fresh export with `CARGO_TARGET_DIR` outside the
snapshot and outside `/tmp`. This matters: under `/tmp`, two tests derive
expectations from the target device/path and fail. Full raw output:
`evidence/prq/final/PRQ_FINAL_CLEAN_EXPORT_GATES.txt`.

| Gate | Exit | Result |
|---|---:|---|
| `cargo fmt --all -- --check` | 0 | `PASS` |
| `cargo check --all-targets --offline --locked` | 0 | `PASS` |
| `cargo test --offline --locked` | 0 | `PASS` — 721 passed / 0 failed / 2 ignored |
| `cargo clippy --all-targets --all-features --offline --locked -- -D warnings` | 0 | `PASS` |
| `cargo build --release --offline --locked` | 0 | `PASS` |
| Both strict config validations | 0 | `PASS_WITH_WARNINGS` (documented empty app cgroup matchers) |
| `warden --self-test --config config/warden.example.toml` | 0 | `PASS` with `NOT_RUN` / `NOT_APPLICABLE` stated |
| Config-engine and installer CLI regressions | 0 | `PASS` |
| Embedded-object, capability and network-coverage integration tests | 0 | `PASS` (12 tests in the targeted replay) |
| `make bpf` | 0 | `PASS` — rebuild byte-identical |
| `scripts/test-privileged.sh` | 77 | `SKIP` — privileged qualification **NOT** executed; not a `PASS` |

No privileged or enforcement test was run on the active host. The two ignored
tests are the deliberately `#[ignore]`d privileged BPF-LSM case and one
pre-existing ignored test.

## 5. Limitations of this verification

- Hosted CI was not run; no authorized staging repository or runner existed.
- `cargo deny`, TruffleHog, syft, grype, shellcheck and markdown-link-check were
  unavailable locally. gitleaks 8.30.1 and cargo-audit 0.23.0 were verified
  locally; their raw evidence is private.
- Secret-pattern findings were reviewed by path/context; no history rewrite was
  performed or permitted.
- Link checks covered local targets only.
- Creating the public repository, choosing its metadata, enabling a monitored
  private vulnerability reporting channel and publishing remain external
  maintainer actions. Public release remains `RELEASE_BLOCKED`.

## 6. Status summary

| Check | Status |
|---|---|
| 112-file allow-list snapshot from final tree | `PASS` |
| Redaction rescan | `PASS` |
| BPF digest / no private path strings / rebuild current | `PASS` |
| Local Markdown link targets | `PASS` — 0 hard broken; 33 intentional soft references |
| Clean-export build/test/clippy/config/CLI gates | `PASS` |
| Full exported test suite | `PASS` — 721 / 0 / 2 |
| Privileged qualification on this host | `SKIP` — not a pass |
| Public release decision | `RELEASE_BLOCKED` |
| Production qualification | `NOT QUALIFIED` / `BLOCKED` |
| Publication / tagging / remote changes | `NOT_PERFORMED` |
