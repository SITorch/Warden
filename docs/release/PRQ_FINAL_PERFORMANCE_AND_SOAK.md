# WARDEN-PRQ-FINAL-02 — Final Performance & Soak Report

status=`PARTIAL` for bounded historical observation; `UNKNOWN` for
long-duration reliability. Prepared 2026-11-24.

## 1. What was measured previously

| Measurement | Source | Bounded meaning |
|---|---|---|
| 60 s privileged VM workload: 32,797 ring submissions, 0 reserve failures | M16 historical evidence | Bounded window only; **not** a soak result and not proof of no end-to-end loss |
| `[::1]` v6 transfer: 2800 B / 4 ops each way | M15 historical evidence | Functional counter delta, not throughput characterisation |
| PRQ-01 full unprivileged suite: 718 passed / 0 failed / 2 ignored; FINAL-02 721 / 0 / 2 | PRQ-01 and FINAL-02 clean exports | Correctness evidence, not performance evidence |
| No CPU/RSS/latency benchmark harness in tree | Source review | No capacity or overhead claim is made |

## 2. This mission

- The disposable VM was started and confirmed accessible (`6.12.107+deb13-amd64`,
  2 vCPU, 3.5 GiB, 97% disk use).
- The current candidate source and BPF object were copied into the VM and the
  object digest was verified there.
- A long-running unprivileged gate script was launched over SSH, but the SSH
  session timed out during compilation; no completed CPU/RSS/event-rate data
  was captured. Result: new VM performance measurement `NOT_RUN`.
- No 24-hour or 48–72-hour soak was started. Nothing is reported as completed
  on the basis of a future expected finish.

## 3. Acceptance criteria

No arbitrary threshold was invented. Any future run must define workload,
duration, resource bounds and acceptance limits in advance and investigate:
unexplained event loss, unreported ring loss, unbounded memory/queue/spool
growth, restart loops, deadlock, sensor failure, uncontrolled retry,
unrecoverable state or incorrect enforcement.

## 4. Telemetry caveats

- `ringbuf_drops` counts `bpf_ringbuf_reserve()` failures only, not userspace,
  spool or bridge loss.
- `set_ring_loss_ratio()` is not reset on clean or unreadable ticks; C2
  confidence can stay degraded after one bad window (R-14).
- Therefore "0 drops" never means "no events lost end to end".

## 5. Status table

| Dimension | Status |
|---|---|
| Idle baseline comparison | `NOT_RUN` |
| Typical activity / process churn | `NOT_RUN` |
| TCP/UDP IPv4/IPv6 high-rate workload | `NOT_RUN` (M15/M16 bounded deltas only) |
| Ring pressure / loss visibility | historical bounded evidence only |
| SENTINEL outage / spool growth | in-process tests only; live `NOT_RUN` |
| Memory/RSS/peak/FD/thread metrics | `NOT_RUN` |
| Restart / config reload / repeated attach-detach | `NOT_RUN` live |
| 24-hour or longer soak | `UNKNOWN` |

## 6. Decision

Long-duration performance and soak qualification remains `UNKNOWN`, a
production blocker. No performance superiority, capacity or stability claim is
made for the Alpha beyond the bounded historical observations above.
