# WARDEN-PRQ-01 — Phase 7 Test Coverage & Performance / Soak Report

status=`PASS` for unprivileged test execution; `UNKNOWN` for long-duration
performance and soak qualification.

## 1. Test coverage (unprivileged)

Full evidence: `evidence/prq/PRQ_03_FULL_TEST_SUITE.txt`.

| Suite group | Result |
|---|---|
| Main unit tests (`src/main.rs`) | 655 passed, 0 failed, 1 ignored |
| Config-engine CLI regression | 7 passed |
| Installer wizard CLI regression | 4 passed |
| Additional integration suites (network, egress, health, ABI, object integrity, etc.) | 52 passed across 12 binaries |
| **Total** | **718 passed, 0 failed, 2 ignored** |

What the ignored tests are:

1. the privileged BPF-LSM runtime case (deliberately `#[ignore]`d, run only via
   `scripts/test-privileged.sh`);
2. one pre-existing ignored test from the M16 baseline.

Structural/ABI coverage includes: accept-flow ABI, connect-outcome ABI,
network ABI, net-volume ABI, ring-size override, ring-buffer drop counter,
shipped-unit failure path, uplink identity gate, capability matrix, embedded
object equals shipped object, and the repository doc-mirror equality check.

## 2. Performance evidence available

| Measurement | Source | Bounded meaning |
|---|---|---|
| 60 s measured workload with 32,797 ring submissions and 0 reserve failures | M16 privileged VM evidence (historical) | Bounded-window observation; **not** a soak result and not a universal loss proof |
| `[::1]` transfer 2800 B / 4 ops each way on v6 UDP hooks | M15 evidence (historical) | Functional counter delta, not throughput characterisation |
| No CPU/memory/latency benchmark harness in the tree | Source review | No benchmark claim is made |

## 3. Soak status

| Dimension | Status |
|---|---|
| Long-duration (hours/days) stability | `UNKNOWN` |
| Memory growth over time | `UNKNOWN` |
| Spool growth and compaction under sustained bridge outage | `UNKNOWN` |
| Ring drain behaviour under sustained high event rate | `UNKNOWN` |
| Reconnect/backoff behaviour over extended outage | `UNKNOWN` |
| Watchdog/deadman unit behaviour over time | `UNKNOWN` |

There is no benchmark threshold in this mission and none is invented. Any
future soak must define its own workload, duration, acceptance criteria, and
resource bounds before it can produce a `PASS`.

## 4. Ring-loss and telemetry caveats affecting performance claims

- `set_ring_loss_ratio()` is only called on lossy ticks; clean/unreadable ticks
  do not reset it, so C2 confidence can stay degraded after one bad window
  (`PRQ_02_EBPF_RISK_REGISTER.md` E-02).
- The drop counter counts `bpf_ringbuf_reserve()` failures only, not
  userspace/spool/bridge loss (E-07).
- Therefore "0 drops" means "0 reserve failures in that bounded window", not
  "no events lost end to end".

## 5. Decision

Unprivileged test execution: `PASS`. Long-duration performance/soak
qualification: `UNKNOWN` — a production qualification blocker. No performance
superiority or capacity claim is made.
