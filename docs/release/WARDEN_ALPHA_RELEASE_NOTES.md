# WARDEN — Public Alpha Release Notes (candidate)

These notes describe the OSR-FINAL-03 sanitized candidate, prepared from the
FINAL-02 engineering baseline without changing code or dependencies. They are
**release-note content, not a publication notice**: publication remains
`RELEASE_BLOCKED` until the maintainer enables a real private vulnerability
reporting channel, verifies notifications, runs hosted CI, and completes the
external actions in `WARDEN_ALPHA_RELEASE_CHECKLIST.md` and the private
maintainer handoff.

## What WARDEN is

WARDEN is an experimental, observe-first eBPF sensor with optional,
off-by-default enforcement. It is one Rust binary plus one eBPF object and one
configuration model. There is no second config engine, duplicate subsystem or
rewritten installer.

## What is included

- Rust daemon, eBPF C/source, shipped BPF object and tests.
- Systemd units, safe public example config and preview-first install wizard.
- Unprivileged CI workflow pinned to verified Action SHAs, contributor
  documents, support boundaries, third-party notices, GPL-2.0 license and SBOM.
- Sanitized decision, security, kernel, enforcement, installer and supply-chain
  reports with explicit limitations. Raw private evidence is excluded.

## Safe defaults

- `mode = observe`
- `enforce.arm = false`
- kill responders off
- `[egress] enabled = false`, `arm = false`
- no SENTINEL bridge configured in the public example
- config mode `0640`

## Build and verify

A contributor can reproduce the local gates from a clean clone:

```sh
cargo fmt --all -- --check
cargo check --all-targets --offline --locked
cargo test --offline --locked
cargo clippy --all-targets --all-features --offline --locked -- -D warnings
cargo build --release --offline --locked
```

`scripts/test-privileged.sh` returns `0` pass, `1` fail or `77` skip. It is for
disposable VMs with verified recovery. `77` is `SKIP`, not a pass.

## Honest status

- Local build/test/content readiness: `PASS`.
- Public release: `RELEASE_BLOCKED`; nothing has been published.
- Production: `NOT QUALIFIED` / `BLOCKED`.
- Representative armed VM proofs on one Debian 13 kernel: `PASS` — one
  pre-opened-fd LSM case, armed egress TCP4/UDP4/TCP6 denial with non-match
  control, and one kill-takedown case. Full enforcement matrices: `PARTIAL` /
  `NOT_RUN`.
- Real SENTINEL delivery: `BLOCKED` / `NOT_RUN`.
- Additional kernels and long-duration soak: `UNKNOWN`.
- Private vulnerability reporting: `NOT_CONFIGURED` / `NOT_TESTED`;
  `BLOCKED_EXTERNAL_MAINTAINER_ACTION`.

Read `WARDEN_FINAL_KNOWN_LIMITATIONS.md` before deploying. Only the narrow VM
cases above are claimed; no host-wide containment, full-matrix denial,
production stability, real backend delivery or zero-risk claim is made.

## License and reporting

WARDEN is GPL-2.0-only. Do not publish until a monitored private vulnerability
reporting channel has been enabled on the actual repository and tested with a
harmless report. No address, PGP key, team identity or third-party account is
supplied by this candidate.
