# WARDEN-PRQ-01 — Phase 6 Enforcement Qualification Status

status=`NOT_RUN` for the public Alpha object. All privileged enforcement paths
require a disposable isolated VM with recovery and were never run on the active
host.

## 1. The three enforcement axes

| Axis | Mechanism | Default | Current status |
|---|---|---|---|
| File/inode denial | Six `lsm/*` programs; needs active `bpf` LSM, attach, populated `guarded_inodes`, `CFG_ENFORCE_ARM=1` | `[enforce] arm = false` | `NOT_RUN` live; code ships; readiness observed on `7.0.0-15` only |
| Egress denial | Four `cgroup/sock_addr` programs; needs `[egress] enabled=true`, attach to isolated cgroup, `arm=true`, exact rule | `[egress] enabled=false, arm=false` | `NOT_RUN` for current source; historical armed `-EPERM` evidence is from an earlier **Phase 6** isolated VM (13/13 executed), not from M16 (observe-only volume accounting), and predates reload/cgroup-fd changes |
| Kill responder | Userspace signal to a judged process; multiple `kill_*` flags | All false; `mode="observe"` | `NOT_RUN` |

Detection findings, including C2 cadence, **never** acquire kill intent and
never block traffic (`wants_kill: false`, `traffic_blocked: false`).

## 2. Test-integrity fix (the PRQ enforcement-adjacent change)

The old `tests/preopened_fd_guard.rs` printed `SKIP` and returned normally when
root/`CAP_BPF`/`bpf` LSM were absent; Cargo counted that as `ok`, so an
unprivileged run could appear to prove in-kernel `-EPERM`. PRQ changed this:

- the runtime case is `#[ignore]`d — default `cargo test` reports it as
  `ignored`, never `ok`;
- any unmet precondition **when the test is explicitly invoked** is a hard
  failure (`assert_eq!(geteuid(), 0)`, `unwrap_or_else(panic!)` for object load
  and BTF);
- a regression test asserts the `#[ignore]` annotation stays after `#[test]`;
- `scripts/test-privileged.sh` checks root, `CAP_BPF` (bit 39), active `bpf`
  LSM, and object presence, then runs the ignored test with `--ignored`.

Exit convention: **0 = PASS, 1 = FAIL, 77 = SKIP**. On the unprivileged dev host
the runner returned `SKIP ... exit 77` — explicitly **not** a pass.

Evidence: `evidence/prq/PRQ_02_TEST_SEMANTICS_FIX.txt`.

## 3. Misleading-success fix in arming

Before PRQ, `set_enforce_arm(true)` with no LSM attached logged a warning but
still wrote `CFG_ENFORCE_ARM=1` and returned `Ok(())`, so telemetry could say
`arm=true` while nothing would deny. It now fails closed (see
`PRQ_02_SECURITY_REVIEW.md` §2). This makes it harder for an operator to believe
enforcement is active when it is not — but it does not itself qualify
enforcement.

## 4. What a real qualification must capture

For each axis, in a fresh disposable VM:

1. kernel release, active `lsm=` list, capability set, BTF availability;
2. build digest / SHA-256 of the exact object loaded;
3. program attach IDs and per-hook attachment success/failure;
4. arm state read back from the kernel (not the requested value);
5. policy/map contents actually installed;
6. a positive test (denial occurs, syscall returns `-EPERM`) and a negative test
   (non-matching operation allowed);
7. shadow-mode behaviour (would-deny counted, operation allowed);
8. reload transitions A–E and rollback on injected failures;
9. cleanup verification (no leftover programs, maps, cgroups, or processes);
10. explicit final status from `scripts/test-privileged.sh` (0/1/77) — a `77`
    is recorded as `SKIP`, never folded into a passing count.

## 5. Safety rules

- Never run on the active host or a production system.
- Always use a disposable VM with console/out-of-band recovery.
- Kill-responder tests use throwaway processes only.
- Capture rollback evidence before declaring any enforcement test complete.

## 6. Decision

| Axis | Status |
|---|---|
| File/inode LSM denial | `NOT_RUN` |
| cgroup egress denial | `NOT_RUN` (historical evidence only) |
| Kill responder | `NOT_RUN` |
| Privileged test harness honesty | `PASS` |
| Overall enforcement qualification | `NOT_RUN` → production blocker |
