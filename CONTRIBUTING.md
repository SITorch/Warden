# Contributing to WARDEN

WARDEN is experimental Alpha software. Contributions are welcome, but this is a host-security agent that runs with elevated privileges: changes are reviewed for security impact, not just correctness.

## Development setup

Obtain the source from the official public repository or your own fork:

`https://github.com/SITorch/Warden`

Do not copy private parent repositories, private history, internal evidence, unpublished branches, or maintainer-only development artifacts into contributions.

Ordinary Rust work needs:

- Rust toolchain (edition 2021; `rustc`/`cargo` — `Cargo.toml` does not declare a separate MSRV; recorded verification used `rustc`/`cargo` 1.95.0).
- `clang` with the BPF target and `bpftool` only when rebuilding `bpf/warden.bpf.o` or regenerating `vmlinux.h`.
- `libssl-dev` / OpenSSL 3 headers for the optional direct mTLS transport; the default bridge is cleartext HTTP and needs no Rust TLS crate.
- Linux with BTF (`/sys/kernel/btf/vmlinux`) only for runtime/loader work.

```sh
make                    # clang BPF object + locked debug build
make check              # configuration and toolchain wiring; no kernel needed
make config-check       # dedicated strict config validation
make self-test          # read-only installation self-test
make test-cli           # config-engine + installer CLI regressions
make test               # locked unit + integration tests (privileged case ignored)
make fmt
make clippy
```

The default `cargo test` deliberately **ignores** the privileged BPF-LSM qualification. A skipped test is never a passing test.

Documentation work should check local Markdown links and verify that commands match the CLI and configuration schema. External URL reachability is not part of the offline check. Do not edit generated BPF objects by hand; rebuild and record the resulting digest.

## Fork-based contribution workflow

Contributors without write access to the upstream repository should use a GitHub fork.

### 1. Fork the repository

Create a fork of:

`https://github.com/SITorch/Warden`

Clone your fork locally:

```sh
git clone https://github.com/YOUR_USERNAME/Warden.git
cd Warden
```

Replace `YOUR_USERNAME` with your GitHub account name.

### 2. Configure the upstream remote

Add the official WARDEN repository as the upstream remote:

```sh
git remote add upstream https://github.com/SITorch/Warden.git
git fetch upstream
git remote -v
```

Keep:

- `origin` pointing to your personal fork.
- `upstream` pointing to `SITorch/Warden`.

Push contribution branches to your fork, not directly to the upstream repository.

### 3. Start from the latest main branch

Update your local main branch from upstream:

```sh
git switch main
git merge --ff-only upstream/main
```

Create a dedicated branch for your contribution:

```sh
git switch -c docs/short-description
```

Use a descriptive branch name appropriate to the change, for example:

- `docs/improve-installation-guide`
- `fix/config-validation`
- `test/network-policy-regression`

Do not develop directly on your local `main` branch.

### 4. Make and validate your changes

Keep the contribution focused.

Before committing:

```sh
git status --short
git diff --check
git diff
```

Run the relevant checks for the files and components you changed.

For documentation changes, verify local Markdown links and ensure documented commands match the current CLI and configuration schema.

For Rust or security-sensitive code changes, follow the applicable build, formatting, Clippy, and regression-test requirements below.

Do not include unrelated changes, generated artifacts, private evidence, credentials, or local development files.

### 5. Commit and push your branch

Use a descriptive commit message:

```sh
git add <changed-files>
git commit -m "docs: improve installation guide"
git push -u origin docs/short-description
```

Replace the example branch and commit message with values appropriate to your contribution.

### 6. Open a Pull Request

Open a Pull Request from your fork to the official repository:

- **Base repository:** `SITorch/Warden`
- **Base branch:** `main`
- **Head repository:** your fork
- **Compare branch:** your contribution branch

Describe:

- The problem or motivation.
- The exact changes.
- Affected components.
- Tests performed.
- Tests not performed.
- Security and compatibility implications.

All contributions are subject to maintainer review and the repository's security and contribution policies.

## Build requirements and reproducibility

- `Cargo.lock` is committed with checksums. Use `--locked`; release verification additionally uses `cargo fetch --locked` followed by `--offline --locked`.
- The shipped `bpf/warden.bpf.o` is prebuilt. Editing `bpf/*.c` alone does not change runtime behaviour until `make bpf` rebuilds the object and refreshes `bpf/.built-from`. `tests/embedded_object_is_the_shipped_object.rs` asserts the embedded bytes equal the shipped object.
- Do not change the object without a corresponding integrity/test update.

## BPF-specific requirements

- Keep ABI structs in `bpf/warden.h` and their Rust mirrors in `src/events.rs` / tests in sync. ABI drift is guarded by `tests/*abi*.rs`.
- The six `lsm/*` programs are deny-capable only when the `bpf` LSM is active, the program is attached, `guarded_inodes` is populated, and `CFG_ENFORCE_ARM` is set. The four `cgroup/sock_addr` programs are a separate denial axis. Neither may be described as "always on" or as full-host protection.

## Privileged test requirements

`make test-privileged` runs the BPF-LSM pre-opened-fd qualification through `scripts/test-privileged.sh`, which reports `SKIP` (exit 77) when preconditions are absent. It requires root, `CAP_BPF`, and `bpf` in the boot `lsm=` list.

> Run privileged tests ONLY in a disposable, isolated VM with console/out-of-band recovery. Never on a production host, the primary development host, or the only SSH-accessible machine.

Ordinary CI cannot grant these capabilities; it runs the structural tests and reports the privileged case as explicitly skipped, never as passed.

## Code style and review

- `cargo fmt` and `cargo clippy -D warnings` must pass.
- No unsafe block without a documented `// SAFETY:` justification.
- Security-sensitive changes (loader, guard, egress, deliver, bridge, HMAC/TLS, config) require an explicit threat-model note and regression tests.
- Do not introduce a second configuration engine or duplicate a subsystem.

## Pull request process

1. Describe the problem, current limitation, why the change is necessary, affected components, compatibility impact, and tests added.
2. Include exact commands and evidence for any behavioural claim.
3. State tests performed **and tests not performed**, with kernel/distribution and privilege context where relevant. Ordinary CI is unprivileged.
4. Describe security implications, configuration changes, and documentation changes explicitly.
5. Never include real credentials, private hostnames/IPs, or local absolute paths in code, tests, fixtures, or evidence.
6. State clearly which checks ran, which were skipped, and which were blocked. Use `PASS`, `FAIL`, `SKIP`, `BLOCKED`, `UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE` or `PARTIAL`; do not turn `SKIP` into `PASS`.

## Evidence requirements

Classify every result as `PASS`, `FAIL`, `SKIP`, `BLOCKED`, `UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE`, or `PARTIAL`.

Do not report a skip as a pass, or an unavailable service as a success.

By contributing you agree that your contribution is licensed under the project license (`GPL-2.0-only`) and that you have the right to submit it.
