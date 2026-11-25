## What problem does this solve?

Describe the current implementation, its limitation, and why this change is
necessary. Do not introduce a second configuration engine or duplicate
subsystem.

## Scope of changes

List source files, eBPF programs, tests, configuration, docs, and CI files
touched. Note ABI, kernel, config-schema, or behavioural impact.

## Tests performed

List exact commands, environments, and statuses using `PASS`, `FAIL`, `SKIP`,
`BLOCKED`, `UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE`, or `PARTIAL`.

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo check --all-targets --locked --offline`
- [ ] `cargo test --locked --offline`
- [ ] `cargo clippy --all-targets --all-features --locked --offline -- -D warnings`
- [ ] `cargo build --release --locked --offline`
- [ ] Strict config validation
- [ ] CLI / installer regressions
- [ ] BPF object rebuild and integrity check
- [ ] Regression test added for the change

## Tests not performed

Explicitly list checks that were skipped, blocked, or not run, with the reason.
Never report a skipped privileged test as passing.

## Environment

- Distribution / kernel release (`uname -r`):
- Architecture:
- BTF and `bpf` LSM availability:
- Privileges / runner type:

## Security implications

For loader, guard, egress, delivery, bridge, HMAC/TLS, config, installer, or
responder changes: describe the threat-model impact and how a security-sensitive
failure cannot become a misleading success state.

## Configuration and documentation

- [ ] No configuration schema change, or it is documented and validated
- [ ] Public docs updated where behaviour or defaults changed
- [ ] No private evidence, host paths, credentials, or customer data included

## Evidence

Provide the minimum source or command evidence needed to review behavioural
claims. Do not paste unredacted logs. A skipped check is never a pass.
