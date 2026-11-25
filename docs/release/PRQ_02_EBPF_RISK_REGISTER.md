# WARDEN-PRQ-01 — Phase 2 eBPF / Kernel Risk Register

status=`PASS` (register complete); no new privileged kernel test was run in PRQ.

## 1. Reviewed material

`bpf/warden.bpf.c`, `bpf/warden.h`, `bpf/vmlinux.h`, `src/loader.rs` lifecycle,
detectors, structural tests, and M15/M16/coverage documentation. No obvious
verifier-breaking memory-safety defect or ABI drift was found in the shipped
object. Program text and BTF types are unchanged by the PRQ path-sanitization
rebuild (see `PRQ_01_PUBLIC_SANITIZATION_REPORT.md` §3).

## 2. Findings

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| E-01 | High (evidence) | `DESIGN.md`, mission reports | Live BPF-LSM/cgroup denial on `7.0.0-15-generic` claimed without supporting evidence. `bpf_lsm=VERIFIED` is only an active-LSM-list read (`src/config_engine.rs:335-359`), not an attach/denial proof. | `DOC_FIXED` — downgraded to capability/readiness; live denial `NOT_RUN` |
| E-02 | Medium | `src/main.rs`, `src/detect.rs`, `src/c2.rs` | Ring-loss ratio only set on lossy ticks; one lossy window can degrade C2 confidence indefinitely; unreadable counters don't clear it. | `DOCUMENTED` — not fixed (needs detector state-machine change + tests) |
| E-03 | Medium | `src/loader.rs:793-823,936-953,1311-1320` | Six LSM programs attach sequentially; first failure leaves earlier links live but drops the guarded-inode map handle, so live programs get no policy. All failures are reported as "bpf LSM not active". | `DOCUMENTED` — not fixed (needs per-hook state or rollback) |
| E-04 | Medium | `bpf/warden.bpf.c:2034-2051`, `src/main.rs:1486-1488` | cgroup/sock_addr return-convention **prose** inverted. Code is correct: shadow DENY returns `1` (allow), armed DENY returns `0` (deny), syscall sees `-EPERM` from the kernel. | `DOCUMENTED` — not fixed (comment-only; parent-mirror constraint) |
| E-05 | Medium | `bpf/warden.bpf.c:1170-1256`, coverage docs | "Every UDP transmission" claims unsupported. Hooks are fexit `sendmsg`/`recvmsg`, one operation per completed call; `MSG_PEEK` can double-count; no wire/`skb->protocol` view. | `DOCUMENTED` — docs corrected to per-operation wording |
| E-06 | Medium | IPv6 volume status labels | Source comments/tests said `IMPLEMENTED_NOT_VALIDATED_LIVE` while M15 evidence says `LIVE_VALIDATED_M15` (verifier accept, 6 attaches, `[::1]` +4/+4, 2800 B each way on `6.12.107+deb13-amd64`). | `DOC_FIXED` — reconciled with socket-path boundary |
| E-07 | Low | `bpf/warden.bpf.c:105-180` | `ringbuf_drops` counts `bpf_ringbuf_reserve()` failures only; `ringbuf_events` counts submissions. No userspace/spool/bridge loss measurement. | `DOCUMENTED` — bounded semantics stated |
| E-08 | Low | `src/loader.rs:497-692` | Internal kprobe targets (`__inet_stream_connect`, `inet_accept`) are fail-closed; a kernel lacking/blacklisting them cannot run Warden even in detect-only mode. | `DOCUMENTED` — CO-RE portability is about compiled accesses, not internal-symbol availability |

## 3. Capability boundaries (must remain in all public claims)

### Observational vs denial hooks

- `kprobe`, `kretprobe`, `tracepoint`, `fexit` programs return `0` and only emit
  records or bump counters. This includes `kprobe/security_socket_connect` —
  the `security_*` name does **not** make it an LSM denial hook.
- Six `lsm/*` programs can return `-EPERM` for guarded-file denial only when:
  `bpf` LSM active, program attached, `guarded_inodes` populated, and
  `CFG_ENFORCE_ARM=1`.
- Four `cgroup/sock_addr` programs can deny egress only when attached to the
  configured cgroup, armed, and matched by an exact rule (`1=allow`, `0=deny`).
- Detection findings (including C2) never block traffic and never set
  `wants_kill`.

### IPv6 volume boundary

IPv6 UDP volume hooks `udpv6_sendmsg`/`udpv6_recvmsg`. An AF_INET6 socket can
carry IPv4-mapped datagrams and the hook cannot inspect `skb->protocol`.
Correct claim: **IPv6-socket-path accounting**, not all IPv6 wire traffic.

### C2 boundary

`src/c2.rs` implements a bounded heuristic over CONNECT timing, destination
novelty, cadence, and confidence caps; DNS/TLS metadata and per-flow bytes are
unsupported. Ring loss reduces confidence. Findings are analytic leads, not
proof of command-and-control.

### Ring-buffer boundary

`32,797` submissions / `0` drops in an M16 bounded workload is neither a soak
result nor a universal loss proof.

## 4. Evidence boundary for live LSM denial on `7.0.0-15-generic`

Establishable from existing evidence: BTF/CO-RE prototype checks reported
compatible; `bpf` present in the active LSM list; source contains capable
programs; capability summaries exist.

**Not** establishable: successful BPF-LSM attach on that host; `guarded_inodes`
population; `enforce.arm=1` applied and read back; any `-EPERM` from a guarded
syscall; cgroup egress attach/arm/exercise on that host.

Strongest supportable claim: **BPF-LSM readiness/capability was reported on
`7.0.0-15-generic`, but live enforcement denial on that kernel is unverified.**

## 5. Required future qualification

All live enforcement claims need a reproducible run in a **disposable isolated
VM with recovery** recording: active LSM list, program attach IDs, arm state,
guarded-inode map contents, and an actual refused syscall — via
`scripts/test-privileged.sh`. Status: `NOT_RUN` for the public Alpha object.
