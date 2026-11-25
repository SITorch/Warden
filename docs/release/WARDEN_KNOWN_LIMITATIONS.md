# WARDEN — Known Limitations (Public Alpha)

This is the honest list of things WARDEN does **not** do, has **not** proved, or
cannot see. It is authoritative for public Alpha claims: if a README, a doc, or
a CI line implies otherwise, this list wins.

Statuses use the mission vocabulary. `SKIP` is never a pass. This is the
historical PRQ-01 list; `WARDEN_FINAL_KNOWN_LIMITATIONS.md` is authoritative for
FINAL-02 and records the later, narrowly scoped VM evidence.

## 1. Enforcement is not qualified

| Limitation | Status | Notes |
|---|---|---|
| Live BPF-LSM file/inode denial on any kernel in this pass | `NOT_RUN` | Requires a disposable isolated VM; the kernel case is `#[ignore]`d and the runner returns `77=SKIP` on this host |
| Live cgroup egress denial for the current source | `NOT_RUN` | Historical armed `-EPERM` evidence is from an earlier **Phase 6** isolated VM, not M16: M16 used an observe-only, no-egress config. Phase 6 evidence predates later reload/cgroup-fd changes |
| Armed kill responder | `NOT_RUN` | All `kill_*` flags default false; only throwaway processes may ever be used |
| BPF-LSM on `7.0.0-15-generic` | `UNKNOWN` (readiness only) | `bpf_lsm=VERIFIED` is an active-LSM-list read, not an attach or denial |
| Rollback under injected partial-attach failure | `NOT_RUN` | A partial LSM attach can leave live programs with no policy map handle (E-03) |

## 2. Platform coverage is narrow

| Limitation | Status |
|---|---|
| Privileged evidence exists for exactly one kernel | Debian 13, `6.12.107+deb13-amd64`, historical M15/M16 object |
| All other kernels/distributions | `UNKNOWN` |
| Internal kprobe targets `__inet_stream_connect` / `inet_accept` | Fail closed on kernels lacking or blacklisting them — CO-RE compatibility does not guarantee availability |
| BPF object path independence | Verified for two rebuilds on this toolchain; other clang/BTF toolchains are `UNKNOWN` |

## 3. Detection and telemetry boundaries

- Observational programs (`kprobe`, `kretprobe`, `tracepoint`, `fexit`) **never
  deny**, including the one named `kprobe/security_socket_connect`.
- Detection findings, including C2 cadence, never block traffic and never set
  `wants_kill`. They are analytic leads, not proof of compromise.
- C2 detection uses bounded connect-interval heuristics only: no DNS, SNI, TLS
  metadata, or payload inspection; confidence is capped at 0.72.
- IPv6 volume is IPv6-**socket-path** accounting (`udpv6_sendmsg`/`recvmsg`),
  not all IPv6 wire traffic; IPv4-mapped datagrams are included.
- UDP counts are per `sendmsg`/`recvmsg` operation, not per packet or datagram;
  `MSG_PEEK` can inflate ingress.
- `ringbuf_drops` counts `bpf_ringbuf_reserve()` failures only — not
  userspace, spool, or bridge loss.
- One lossy tick can leave C2 confidence degraded indefinitely because the
  ring-loss ratio is not reset on clean or unreadable ticks (E-02).
- `--health` is `/proc`-only: attach state, ring counters, net-volume totals,
  the protected-PID map, in-memory policy after reload, and unit state are
  printed as `cannot see/…`, never estimated.
- `--version` reports the digest of the object compiled into *that* binary,
  not the object a running agent loaded.
- Socket inventory is off by default, samples only, covers Warden's own network
  namespace, and emits no finding.

## 4. Storage, config, and request-hardening gaps

| ID | Limitation | Status |
|---|---|---|
| R-06 | Daemon config load does not enforce the validator's own permission/ownership check; symlinked config paths are not rejected | `DOCUMENTED` |
| R-07 | Spool open/parent dirs and `set_permissions` follow symlinks | `DOCUMENTED` |
| R-08 | Spool compaction uses a predictable `<spool>.tmp` without `O_EXCL` | `DOCUMENTED` |
| R-09 | `kill(2)` fallback (when pidfd is unavailable) has a check-to-signal TOCTOU window | `DOCUMENTED` |
| R-10 | CRLF/control characters are not rejected in bridge/heartbeat host, path, and `api_key` header interpolation | `DOCUMENTED` |
| R-11 | Inode-keyed guarding follows the old inode after atomic replacement until `PROTECT_REFRESH` re-stats | `DOCUMENTED` (bounded) |
| R-12 | Bridge DNS resolution has no deadline | `DOCUMENTED` |

## 5. Integration and operations

| Limitation | Status |
|---|---|
| Real SENTINEL staging integration (endpoint, tenant, credentials, network authorization) | `BLOCKED` — nothing invented |
| Spool behaviour under sustained outage, reconnect/backoff over extended time | `UNKNOWN` |
| Long-duration soak (hours/days), memory growth, resource stability | `UNKNOWN` |
| Installation/service start/reload/deadman on a clean host | `NOT_RUN` |
| Live installation self-test with the operational sample config | `FAIL` on this host; use the public example config |

## 6. Supply chain and release process

| Limitation | Status |
|---|---|
| `cargo audit`, `cargo deny`, `gitleaks`, `trufflehog`, `syft`, `shellcheck`, `markdown-link-check` locally | `BLOCKED` (unavailable); CI configured, not run |
| Secret-pattern classification in canonical Git history | `UNKNOWN` (path-only scan done; dedicated scanner unavailable) |
| Private Git history | Not rewritten; public release uses a fresh sanitized export |
| Private vulnerability reporting channel | `BLOCKED` — must be a real, monitored channel configured by the maintainer |
| Publication, commit, tag, push | `NOT_RUN` — external maintainer action |

## 7. Claims that must never be made

- "Production ready" or "production qualified".
- "BPF-LSM denial verified on `7.0.0-15-generic`".
- "All tests passed, including privileged tests" (two are ignored; the runner
  returned `SKIP`/77).
- "No known vulnerabilities" (no advisory scan ran locally).
- "No secrets anywhere in history" (only a path-level scan ran locally).
- "Soak tested" or "0 drops means no events lost".
- "Full IPv6 wire visibility" or "traffic was blocked by a detection finding".
