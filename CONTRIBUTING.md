# Contributing to WARDEN

WARDEN is experimental Alpha software. Contributions are welcome, but this is a
host-security agent that runs with elevated privileges: changes are reviewed for
security impact, not just correctness.

## Development setup

Obtain the source from the maintainer-provided sanitized repository; do not copy
the private parent history. Ordinary Rust work needs:

- Rust toolchain (edition 2021; `rustc`/`cargo` — `Cargo.toml` does not declare a
  separate MSRV; recorded verification used `rustc`/`cargo` 1.95.0).
- `clang` with the BPF target and `bpftool` only when rebuilding
  `bpf/warden.bpf.o` or regenerating `vmlinux.h`.
- `libssl-dev` / OpenSSL 3 headers for the optional direct mTLS transport; the
  default bridge is cleartext HTTP and needs no Rust TLS crate.
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

The default `cargo test` deliberately **ignores** the privileged BPF-LSM
qualification. A skipped test is never a passing test.

Documentation work should check local Markdown links and verify that commands
match the CLI and configuration schema. External URL reachability is not part of
the offline check. Do not edit generated BPF objects by hand; rebuild and
record the resulting digest.

## Build requirements and reproducibility

- `Cargo.lock` is committed with checksums. Use `--locked`; release verification
  additionally uses `cargo fetch --locked` followed by `--offline --locked`.
- The shipped `bpf/warden.bpf.o` is prebuilt. Editing `bpf/*.c` alone does not
  change runtime behaviour until `make bpf` rebuilds the object and refreshes
  `bpf/.built-from`. `tests/embedded_object_is_the_shipped_object.rs` asserts
  the embedded bytes equal the shipped object.
- Do not change the object without a corresponding integrity/test update.

## BPF-specific requirements

- Keep ABI structs in `bpf/warden.h` and their Rust mirrors in `src/events.rs`
  / tests in sync. ABI drift is guarded by `tests/*abi*.rs`.
- The six `lsm/*` programs are deny-capable only when the `bpf` LSM is active,
  the program is attached, `guarded_inodes` is populated, and `CFG_ENFORCE_ARM`
  is set. The four `cgroup/sock_addr` programs are a separate denial axis.
  Neither may be described as "always on" or as full-host protection.

## Privileged test requirements

`make test-privileged` runs the BPF-LSM pre-opened-fd qualification through
`scripts/test-privileged.sh`, which reports `SKIP` (exit 77) when preconditions
are absent. It requires root, `CAP_BPF`, and `bpf` in the boot `lsm=` list.

> Run privileged tests ONLY in a disposable, isolated VM with console/out-of-band
> recovery. Never on a production host, the primary development host, or the only
> SSH-accessible machine.

Ordinary CI cannot grant these capabilities; it runs the structural tests and
reports the privileged case as explicitly skipped, never as passed.

## Code style and review

- `cargo fmt` and `cargo clippy -D warnings` must pass.
- No unsafe block without a documented `// SAFETY:` justification.
- Security-sensitive changes (loader, guard, egress, deliver, bridge, HMAC/TLS,
  config) require an explicit threat-model note and regression tests.
- Do not introduce a second configuration engine or duplicate a subsystem.

## Pull request process

1. Describe the problem, current limitation, why the change is necessary,
   affected components, compatibility impact, and tests added.
2. Include exact commands and evidence for any behavioural claim.
3. State tests performed **and tests not performed**, with kernel/distribution
   and privilege context where relevant. Ordinary CI is unprivileged.
4. Describe security implications, configuration changes, and documentation
   changes explicitly.
5. Never include real credentials, private hostnames/IPs, or local absolute
   paths in code, tests, fixtures, or evidence.
6. State clearly which checks ran, which were skipped, and which were blocked.
   Use `PASS`, `FAIL`, `SKIP`, `BLOCKED`, `UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE`
   or `PARTIAL`; do not turn `SKIP` into `PASS`.

## Evidence requirements

Classify every result as `PASS`, `FAIL`, `SKIP`, `BLOCKED`, `UNKNOWN`, `NOT_RUN`,
`NOT_APPLICABLE`, or `PARTIAL`. Do not report a skip as a pass, or an
unavailable service as a success.

By contributing you agree that your contribution is licensed under the project
license (GPL-2.0-only) and that you have the right to submit it.
