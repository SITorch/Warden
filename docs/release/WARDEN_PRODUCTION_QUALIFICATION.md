# WARDEN — Production Qualification Decision

**Decision: `NOT QUALIFIED`. Status: `BLOCKED`.**

This is the historical PRQ-01 decision. For the FINAL-02 candidate,
`WARDEN_FINAL_PRODUCTION_QUALIFICATION.md` is the authority; the statuses below
are not silently upgraded by later VM evidence.

M16 remains `COMPLETED_WITH_LIMITATIONS` with readiness `LAB_VALIDATED`.
PRQ-01 does not reopen M16, does not repeat it, and does not upgrade that
verdict. Nothing in this pass establishes production readiness.

## 1. Gate-by-gate decision

| Gate | Status | Evidence / blocker |
|---|---|---|
| Current-tree build, format, lint, unprivileged tests | `PASS` | `PRQ_03_BUILD_GATES.txt`, `PRQ_03_FULL_TEST_SUITE.txt` — 718 passed / 0 failed / 2 ignored |
| Sanitized, reproducible BPF object | `PASS` | `PRQ_01_PUBLIC_SANITIZATION_REPORT.md` §3 |
| Live BPF-LSM file denial | `NOT_RUN` | Disposable VM required; runner returns `SKIP` (77) here |
| cgroup egress armed denial (current source) | `NOT_RUN` | Historical Phase 6 isolated-VM evidence only; M16 VM work was observe-only volume accounting |
| Armed kill responder | `NOT_RUN` | All flags off; throwaway-process VM test required |
| Kernel/distribution matrix beyond one historical VM | `UNKNOWN` | `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md` |
| Long-duration soak / resource stability | `UNKNOWN` | `PRQ_07_TEST_AND_PERFORMANCE_REPORT.md` |
| Real SENTINEL integration | `BLOCKED` | No endpoint, tenant, credentials, permission, or network authorization; none invented |
| Secret/advisory/license gates in CI | `NOT_RUN` | Local tools unavailable; public CI configured only |
| Private vulnerability reporting channel | `BLOCKED` | External maintainer action |
| Clean-host install, service start, SIGHUP reload, deadman | `NOT_RUN` | `PRQ_08_INSTALLER_OPERATOR_REPORT.md` |
| Open hardening items (R-06 … R-12, E-02/E-03) | `DOCUMENTED` | `PRQ_02_RUST_RISK_REGISTER.md`, `PRQ_02_EBPF_RISK_REGISTER.md` |

Any single `NOT_RUN`/`BLOCKED`/`UNKNOWN` row is sufficient to withhold
production qualification; several remain.

## 2. What the strongest current evidence actually supports

- Kernel/enforcement: **capability and readiness** only, on
  `7.0.0-15-generic`; no live denial on that kernel. Historical functional
  evidence exists for `6.12.107+deb13-amd64` with the M15/M16 object in a
  disposable VM and a 60 s bounded workload.
- Public Alpha object lineage: `.text` and BTF types identical to the
  historically validated object; only debug path prefixes changed. This makes
  the historical evidence *substantively relevant*, but it is not a new
  privileged test of the public object.
- Detection: implemented and unit/structurally tested; analytic findings only,
  never blocking and never carrying kill intent.

## 3. Required before re-evaluation

1. Run `scripts/test-privileged.sh` in a disposable VM with recovery for each
   enforcement axis; record 0/1/77 verbatim and never fold `77` into a pass.
2. Capture attach IDs, armed state read back from the kernel, map contents,
   positive and negative denial results, and cleanup verification.
3. Expand the kernel/distribution matrix with the same evidence protocol.
4. Define and execute a soak with stated workload, duration, and acceptance
   limits; report CPU, memory, spool depth, and ring behaviour.
5. Complete an authorized live SENTINEL integration test with redacted
   evidence.
6. Close or formally accept each documented hardening item in
   `WARDEN_KNOWN_LIMITATIONS.md`.
7. Complete the public release gates in
   `WARDEN_PUBLIC_RELEASE_READINESS.md`.

## 4. Safety rules for that work

- Privileged tests **only** in disposable isolated VMs with out-of-band
  recovery; never on the active host.
- Kill-responder tests use throwaway processes only.
- No endpoint, credential, threshold, benchmark result, or production claim is
  invented to make a gate green.

## 5. Statement for public documentation

> WARDEN is an experimental public Alpha. It ships as an observe-first eBPF
> sensor with optional, off-by-default enforcement. It is **not production
> qualified**. Live enforcement denial, multi-kernel compatibility, soak
> stability, and real SENTINEL integration remain unverified in this release.
