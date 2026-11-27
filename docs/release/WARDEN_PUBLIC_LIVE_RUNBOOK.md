# WARDEN Public Alpha — sanitized live-validation runbook

This runbook is the public-facing replacement for excluded raw validation logs
(`scripts/LIVE_VALIDATION.md`) and superseded operator guides. It describes how
to reproduce only the read-only checks and the narrowly scoped, disposable-VM
checks whose sanitized results are summarized in the PRQ reports below. It does
not contain a raw host log, credential, hostname, account, PID, or private IP.

> **Status boundary:** WARDEN is an Experimental Open-Source Alpha, not a
> production-qualified EDR/XDR replacement. A skipped or unavailable check is
> reported as `SKIP`, `BLOCKED`, or `NOT_RUN`; it is never a `PASS`.

## 15. Preflight and kernel compatibility

1. Record the exact commit, distribution, kernel release (`uname -r`),
   architecture, and whether `/sys/kernel/btf/vmlinux` and a `bpf` entry in
   `/sys/kernel/security/lsm` are present.
2. Build with `make check` and `make` on a non-production machine. The shipped
   eBPF object is prebuilt; `make bpf` is only needed after changing BPF C
   source.
3. Verify the object and embedded bytes with:
   `cargo test --locked --offline --test embedded_object_is_the_shipped_object --test capability_matrix`.
4. Treat every kernel other than the representative lab kernel as unqualified
   until the verifier accepts, the programs attach, and the counters move. See
   `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md` and `PRQ_FINAL_KERNEL_COMPATIBILITY.md`.

## 16. Connect-outcome probes

The `__inet_stream_connect` pair is a kernel-internal probe pair. On a
disposable VM, use a loopback-only TCP client to generate both successful and
refused dials, then confirm that a terminal return produces a connect-result
journal line and that an in-flight `-EINPROGRESS` dial produces none. Do not
infer a connection verdict from a missing line. The measured sample and its
limits are in `PRQ_FINAL_ENFORCEMENT_PROOF.md`.

## 17. Optional cgroup egress qualification

Run only inside an isolated cgroup on a disposable VM. Keep `arm = false` for
shadow counting first; only then set `arm = true` with an exact
`(family, protocol, address, port)` rule. Confirm a matching operation is
refused with `-EPERM`, a non-matching operation is allowed, and the cgroup
`egress_stats` counter moves. This is not a full-host firewall and is disabled
by default. See `PRQ_06_ENFORCEMENT_QUALIFICATION.md` and
`docs/security/warden_phase7_egress_enforcement.md`.

## 18. Inbound-flow probes

Use a loopback-only listener and client. Confirm the accept pair records a
record only when `accept(2)` returns `0`; an `-EAGAIN` call took nothing. Verify
the local port and network-namespace fields against `ss`/`/proc/net` where
readable. The namespace field is important because container netnamespaces are
not visible to a host-only pull path. See `docs/security/warden_coverage_matrix.md`.

## 22. Baseline and listener measurements

Capture a quiet-window baseline before injecting test traffic. Record listener
counts, accepted connections, and measurement windows without copying private
host details. Findings are analytic leads; egress detection does not block
traffic. The sanitized historical measurements are in
`PRQ_02_DOCUMENTATION_CONTRADICTIONS.md` and `PRQ_07_TEST_AND_PERFORMANCE_REPORT.md`.

## 23. Network-volume probes

For each protocol family under test, transfer a known byte count over
loopback, then confirm the corresponding `net_volume` map row and periodic
journal line move. UDP counts are per `sendmsg`/`recvmsg` payload operation,
not packets or wire bytes. IPv6 volume accounting is socket-path accounting,
not all IPv6 wire traffic. See `PRQ_FINAL_ENFORCEMENT_PROOF.md` and
`WARDEN_FINAL_KNOWN_LIMITATIONS.md`.

## 24. Read-only diagnostics

Use `warden --health`, `warden --doctor --check`, and `warden --explain KIND`
to observe what the current process can actually see. These commands do not
attach BPF programs and report `cannot see/…` for attach state, ring-buffer
counters, and the daemon's in-memory policy. See `DESIGN.md` and
`WARDEN_FINAL_OPERATOR_HANDOFF.md`.

## Outage, spool, and recovery checks

Stop the agent before using `--replay-quarantine`. The dead-letter file is
0600 and is archived with a `.replayed.<timestamp>` suffix; it is never
truncated in place. A spool rewrite failure rolls back and preserves surviving
findings. For installation, uninstall, configuration rollback, and health
checks after rollback, use `WARDEN_FINAL_OPERATOR_HANDOFF.md`.

## Evidence references

- `PRQ_00_REPOSITORY_BASELINE.md`
- `PRQ_02_DOCUMENTATION_CONTRADICTIONS.md`
- `PRQ_06_ENFORCEMENT_QUALIFICATION.md`
- `PRQ_FINAL_ENFORCEMENT_PROOF.md`
- `PRQ_FINAL_PERFORMANCE_AND_SOAK.md`
- `PRQ_FINAL_SECRET_AND_HISTORY_AUDIT.md`
- `WARDEN_FINAL_KNOWN_LIMITATIONS.md`
- `WARDEN_FINAL_OPERATOR_HANDOFF.md`
