# WARDEN

**WARDEN — Adaptive Linux Host Security Agent**

Observe. Understand. Respond. Protect.

> **PUBLIC ALPHA — EXPERIMENTAL — NOT PRODUCTION QUALIFIED**
>
> `PROJECT_STATUS=EXPERIMENTAL_ALPHA` · `PRODUCTION_READY=NO`
>
> WARDEN is an observe-first eBPF host agent with optional, off-by-default
> response. It is not a production-ready EDR/XDR replacement. A representative
> lab kernel has narrowly qualified local behaviour; full matrix, soak,
> live-platform integration and production qualification remain open. See
> [Known limitations](docs/release/WARDEN_FINAL_KNOWN_LIMITATIONS.md) and
> [Alpha release notes](docs/release/WARDEN_ALPHA_RELEASE_NOTES.md).

WARDEN watches a Linux host from the kernel boundary: process execution,
signals and ptrace against protected processes, connect/listen activity,
credential changes, module and BPF-program loads, container mounts, persistence
writes, destructive file operations, and optional cgroup egress. The kernel
programs emit compact records; all judgement lives in the Rust userspace agent.
[Local-only reporting is the default](#sentinel-bridge). No external platform
contact is required for the supported local checks.

WARDEN is separate from SENTINEL. SENTINEL is a different platform; WARDEN can
optionally ship findings to a SENTINEL-compatible ingest endpoint when a bridge
is configured. **Live SENTINEL delivery is not qualified in this Alpha** and is
reported as `BLOCKED / NOT_RUN`.

## Start here

- [What it detects today](#what-it-detects-today) and [capability status](#capability-status)
- [Build](#build), [run without installing](#run-without-installing), and [configuration](#configuration)
- [Install, uninstall, and recovery](docs/release/WARDEN_FINAL_OPERATOR_HANDOFF.md)
- [Security policy and private reporting gate](SECURITY.md)
- [Contributing](CONTRIBUTING.md) · [Support boundaries](SUPPORT.md) · [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Report a bug](.github/ISSUE_TEMPLATE/bug_report.md) · [Report a vulnerability privately](SECURITY.md#where-to-report-private-channel)

The detailed operational reference follows below; the short Alpha summary above
is the authoritative status boundary for this release candidate.

## What it detects today

Thirty-two programs ship in the embedded object: the original twenty-six
(observational sensors, including the first four volume counters), the four Phase 7
cgroup egress hooks, and two new IPv6 datagram volume hooks below. The cgroup hooks
are **disabled by default** — they are
compiled in but attach only when `[egress] enabled = true` names an isolated cgroup,
and deny only when `arm = true` and an exact rule matches. Program names are the
ELF section names they attach under:

| Sensor (eBPF program)                 | Catches                                              | Finding                     |
|---------------------------------------|------------------------------------------------------|-----------------------------|
| `tp/sched/sched_process_exec`         | shell spawned inside the app cgroup; a renamed binary staged in a world-writable directory; deleted-on-disk (fileless) binary | `endpoint:process_creation` |
| `kprobe/security_task_kill`           | a signal aimed at a **protected** pid (Sentinel/Warden/app) | `endpoint:self_tamper`      |
| `kprobe/security_ptrace_access_check` | a ptrace aimed at a **protected** pid                | `endpoint:self_tamper`      |
| `kprobe/security_socket_connect`      | egress from the app cgroup outside the allowlist (C2/exfil), carrying the destination **and the socket's transport** (`tcp`/`udp`/`icmp`/`other`; no claim on a record from an older object). **Observes the connect — it does not stop it**; see [Capability status](#capability-status) | `endpoint:network_connect`  |
| `kprobe/security_socket_listen`       | a bind shell / reverse-shell listener on a non-allowlisted port, with the bound endpoint and its transport | `endpoint:listen`           |
| `kprobe/__inet_stream_connect`        | the **attempt** half of the connect-outcome pair: it stashes where the dial was aimed (family, transport, port, address) so the verdict below can name the same endpoint byte-for-byte. Emits no record itself | (feeds `connect_result`)    |
| `kretprobe/__inet_stream_connect`     | the **verdict** for that dial: established / refused / timed out / unreachable / blocked / aborted / interrupted / would-block / already-connected / failed-other. Only a terminal return produces a record | `egress verdict:` journal line (no `endpoint:*` finding — see below) |
| `kprobe/inet_accept`                  | the **stash** half of the accept pair: `accept(2)` has no child socket at entry, so it catches the pointer to the one being filled and emits nothing itself | (feeds `flow`)              |
| `kretprobe/inet_accept`               | an INBOUND connection that was actually taken: the accepting task, the peer endpoint and transport, which local port accepted it, and which network namespace the socket lives in (so a container's flow is not mistaken for a host flow). Only an `rc == 0` accept produces a record — a call that returned `-EAGAIN` took nothing | journal line only (no `endpoint:*` finding — see below) |
| `fexit/tcp_sendmsg`                   | bytes a cgroup handed to a TCP send queue, and the calls that returned (N-05). Accumulates into the `net_volume` map keyed by **cgroup id**, never into the ring — so it is not subject to ring loss. Off unless `[net_volume].enabled = true` | periodic `network volume` journal line |
| `fexit/tcp_cleanup_rbuf`              | bytes copied to a cgroup's userspace on TCP receive, and the receive completions — the stream ingress half. A receive that only `MSG_PEEK`s counts, because the copy into userspace really happened | periodic `network volume` journal line |
| `fexit/udp_sendmsg`                   | IPv4 datagram egress. Counts **payload at the send/recv call**, not wire bytes: kernel IP/TCP headers and retransmits are outside the totals, a userspace TLS library's record framing is inside them, and loopback is included. Not packets either — see `ops` | periodic `network volume` journal line |
| `fexit/udp_recvmsg`                   | IPv4 datagram ingress, measured on the deployment kernel in §23: `out 102400B/100 ops, in 95232B/93 ops` for a known IPv4 transfer, where §22 had read `in 0B/0 ops`. A `MSG_PEEK` copy is counted | periodic `network volume` journal line |
| `fexit/udpv6_sendmsg`, `fexit/udpv6_recvmsg` | IPv6 datagram egress/ingress, added to close the §23 family gap (`udpv6_*` dispatch, not `udp_*`). **LIVE_VALIDATED_M15**: on an isolated `6.12.107+deb13-amd64` host all six prototypes passed target-BTF preflight, the verifier accepted and attached six programs, and a known `[::1]` transfer moved `udp6_out`/`udp6_in` +4/+4 with 2800 B each way (`M15_09`/`M15_11`). This is IPv6-**socket-path** accounting, not all IPv6 wire traffic. Not revalidated in the current pass | periodic `network volume` journal line |
| `cgroup/connect4`                      | Phase 7 optional egress gate for IPv4 TCP connects from **one named cgroup**; with `arm = false` (the default) it only counts "would deny" in shadow; with `arm = true` a matching exact rule returns `-EPERM`. Not attached unless `[egress] enabled = true` | journal line + kernel `egress_stats` (no `endpoint:*` finding) |
| `cgroup/connect6`                      | the IPv6 half of the optional connect gate; same two switches, same counting/shadow semantics | journal line + kernel `egress_stats` |
| `cgroup/sendmsg4`                      | the IPv4 unconnected-UDP destination gate — the only way this build sees a datagram's *destination* before it is sent; still cgroup-scoped and opt-in | journal line + kernel `egress_stats` |
| `cgroup/sendmsg6`                      | the IPv6 unconnected-UDP destination half; completes the four-hook set so a partial IPv6/IPv4 attach is reported DEGRADED rather than full coverage | journal line + kernel `egress_stats` |
| `kprobe/commit_creds`                 | an app process raising to root or gaining capabilities | `endpoint:privilege_change` |
| `tp/module/module_load`               | a non-allowlisted kernel module loaded at runtime (LKM rootkit) | `endpoint:module_load`      |
| `kprobe/security_bpf`                 | a BPF program loaded by a loader whose executable is not authorized (in-kernel eBPF implant) | `endpoint:bpf_load`         |
| `kprobe/security_sb_mount`            | a bind mount grafting a watched host path (container escape) | `endpoint:mount`            |
| `kprobe/security_inode_create`        | a file created in a boot/login-survival location (persistence) | `endpoint:new_service`      |
| `kprobe/security_inode_rename`        | rename into a ransom extension, watched-name tamper, modification burst | `endpoint:file_tamper`      |
| `kprobe/security_inode_unlink`        | unlink of a watched-name file, or a burst of destructive ops | `endpoint:file_tamper`      |
| `lsm/file_permission` (+ the other five `lsm/*` guards) | an actor touching a guarded inode — either denied in-kernel (`arm=true`) or, in the shipped `arm=false` posture, the attempt it **would** have denied | `endpoint:access_denied`    |
| (periodic delivery tick)              | Warden's own uplink degraded — findings LOST, dead-lettered, or isolated. A delta, not a steady-state heartbeat; no kill intent | `endpoint:self_degraded`   |

Those two `endpoint:self_tamper` rows share one Sentinel slot, so the verdict is
carried inside the record rather than in a new event type. `detail.reason` names
the class and `detail.authorization` says who was believed and how:

| reason | tier | what it means |
|--------|------|---------------|
| `unauthorized_signal` | Critical | an outside actor sent a number whose default action terminates or freezes the target |
| `inert_signal` | Info | SIGCONT / SIGWINCH / SIGCHLD / SIGURG — the kernel would not act on it, so it is control traffic, not a blow |
| `service_control` | Low | the sender's pid was 1 — the service manager stopping or reloading a unit; never armed |
| `own_reload_path` | Low | SIGHUP at Warden's own pid, whose handler reloads the config; never armed |
| `self_termination` | Medium | the protected process aimed the signal at itself (a panic, `abort()`, `kill(getpid(), …)`); never armed |
| `ptrace_attach` | High | a real attach/inject request (`PTRACE_MODE_ATTACH`) |
| `verified_external_reader` | Info | a `/proc` read by a process whose executable *and* cgroup resolved and that is provably outside `[app] cgroup_contains` |
| `unverified_reader` / `in_app_reader` / `app_cgroup_unconfigured` | Medium | the same read, with the one fact that would have demoted it named as missing |

Two invariants hold across all of them: a `comm` alone never earns a demotion
(`prctl(PR_SET_NAME)` is available to every process), and none of this changes
what enforcement may do — `kill_takedown_attacker` still fires only for SIGKILL,
SIGTERM, SIGSTOP, SIGQUIT and SIGABRT from an unauthorized actor.

Two sets of programs can deny: the six `lsm/*` file guards (below) deny
**file/inode** access when `[enforce]` is armed and `bpf` is in the kernel's boot
`lsm=` list; four optional `cgroup/sock_addr` programs deny **egress** when
`[egress] enabled = true`, `arm = true`, and an exact rule matches (disabled by
default). Observational kprobes/tracepoints/fexit programs never deny.

| Guarded-file program (`lsm/*`) | Denies                                              |
|--------------------------------|-----------------------------------------------------|
| `lsm/file_open`                | a new open of a guarded file by a disallowed actor   |
| `lsm/mmap_file`                | a new mapping of a guarded file                      |
| `lsm/inode_unlink`             | an unlink of a guarded file                          |
| `lsm/inode_rename`             | a rename of a guarded file                           |
| `lsm/inode_setattr`            | chmod/chown on a guarded file                        |
| `lsm/file_permission`          | a read/write through an fd, even one opened before arming |

The kernel side is deliberately dumb: it observes, does one map lookup (e.g. "is
the victim protected?" / "is this sensor emitting?"), stamps a fixed 344-byte
record, and hands it to userspace over a BPF ring buffer. **All judgement lives
in Rust** — the shell/egress/ransom allowlists, the app-cgroup attribution, and
the burst window are all userspace policy. A policy change never touches kernel
code, and the kernel programs stay well inside the verifier's complexity budget.

## Capability status

Warden is a **detection-and-limited-response** system, not an egress firewall and
not a full inline LSM. That distinction is easy to lose when design notes describe
what a *host* can do as though it were what this *build* does, so every capability
is labelled here as something a test or a source file can be checked against.

`Implemented` — ships and works.  `Partial` — ships, with a boundary named below.
`Planned` — designed, not in this build.  `Not supported` — deliberately absent;
do not expect it.

| Capability | Status | Where it stands |
|---|---|---|
| Exec / shell-spawn detection | Implemented | `tp/sched/sched_process_exec`, matched on the exec's *identity* (`/proc/<pid>/exe`, the execve path, comm) — not comm alone, which a process rewrites at will |
| Renamed-copy / staged-binary exec detection | Implemented | same sensor, `exec_rules.untrusted_exe_prefixes`: a world-writable staging area handing out the executable. Medium, and never arms the responder |
| Fileless (deleted-exe) detection | Implemented | same sensor, `exec_rules.flag_deleted_exe` |
| Signal-against-protected detection | Implemented | `kprobe/security_task_kill`, and it records *which call* aimed the signal (`kill`/`tkill`/`sigqueue`, plus `timer_claimed`/`mqueue_claimed`/`sigio_claimed`/`aio_or_usb` — read from `si_code` at the hook). A signal the victim aimed at itself is a Medium self-termination and never arms the responder. Kernel-generated signals — a SIGSEGV of its own, the OOM killer's `SIGKILL` — do not reach this hook at all: the kernel approves them before calling the LSM, so there is nothing here to tell apart. The three `*_claimed` classes name a number a sender chose, not a timer that fired, because those mechanisms queue past the permission check too (W2K-04) |
| ptrace-against-protected detection | Implemented | `kprobe/security_ptrace_access_check` |
| Listener / bind-shell detection | Implemented | `kprobe/security_socket_listen`; the record names the bound endpoint and the socket's transport, read from the kernel rather than assumed from `listen(2)`'s contract |
| Privilege-raise detection | Implemented | `kprobe/commit_creds` |
| Module-load detection | Implemented | `tp/module/module_load` |
| BPF-load detection | Implemented | `kprobe/security_bpf` |
| Mount / container-escape detection | Implemented | `kprobe/security_sb_mount` |
| **Egress detection** | Implemented | `kprobe/security_socket_connect` — sees the connect, its destination, and the socket's transport (`tcp`/`udp`/`icmp`/`other`) and judges it. A record written before the field existed decodes with **no** transport (`null` in the finding), never a guessed one. The `sk_protocol` read was checked against the BTF of the build host (`7.0.0-15-generic`) and the deployment host (`6.12.107+deb13-amd64`) only; on any other kernel the object may fail to load and Warden exits rather than run partially — see `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §15 before deploying (N-14) |
| **Jittered beacon / C2 cadence detection** | Implemented (offline-validated) | `src/c2.rs` (v2) judges one destination's connect intervals from the **kernel** `ts_ns` on the ring record: median + MAD, 6+ dials inside 900 s, 10–600 s interval band, capped confidence 0.72, and one cooldown per destination. A zero or backwards timestamp is discarded rather than counted. No DNS/SNI/payload claim and no privileged live run in this pass; see `SECURITY.md` and the threat model |
| **Cross-event attack-chain correlation** | Implemented (structural + synthetic tests) | `src/correlate.rs` joins two **already-judged** kernel observations from the same pid within a bounded window (default 10 s), requiring the `/proc` start time to agree when both halves carry one so a recycled pid cannot inherit a chain: suspicious exec → unsanctioned egress (`suspicious_exec_then_egress`), privilege raise → persistence write / module / BPF load (`privilege_then_persistence`), suspicious listener → an accepted flow on that exact port (`suspicious_listener_accepted`), and unsanctioned dial → the kernel's `Established` verdict (`unsanctioned_dial_established`). It is the consumer that makes the verdict and accept sensors useful without flooding the spool: a routine accept or a completed dial stays journal-only unless its earlier half was already a finding. Emits `endpoint:attack_chain` (Medium/High, `wants_kill = false`). Hard bounds: 8 anchors/actor, 4096 actors, configurable via `[correlation]`. No new eBPF program, no payload/DNS/TLS claim, and no privileged live validation in this pass |
| **Egress verdict (what the connect did)** | Partial — sensor ships and is measured; no standalone host finding, but consumed by correlation | `kprobe/__inet_stream_connect` + `kretprobe/__inet_stream_connect` stamp the transport's answer into `aux2` bits 24..31, beside the family and transport the dial record already carried. It emits **only for a terminal return**: measured on the deployment kernel (`6.12.107+deb13-amd64`), 116 of 128 live stream connects (91%) returned `-EINPROGRESS` — a non-blocking dial still in flight, which is what every "connect with a timeout" client does, and has no outcome yet. So a CONNECT record with no matching CONNECT_RESULT record is the expected shape, not a lost record. `ConnectOutcome::conn_state_hint()` maps exactly three verdicts to the platform's Zeek-shaped `conn_state` (`S1`/`REJ`/`S0`) and claims nothing for the other seven. It raises no **standalone** `endpoint:*` finding: the dial-time egress finding already owns that connection. Its `Established` verdict can complete an `endpoint:attack_chain` (`unsanctioned_dial_established`) when it matches a judged unsanctioned dial to the same endpoint; the platform's `conn_state` flow ingest is still not wired from here. The attach target is a kernel *internal* symbol, not a `security_*` hook, so it was measured before shipping — see N-14 and `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §16 |
| **Inbound flow (who was accepted)** | Partial — sensor ships and is measured live; journal-only, no standalone finding, but consumed by correlation | `kprobe/inet_accept` + `kretprobe/inet_accept` record an inbound connection the kernel actually took: the accepting task, the peer endpoint (`daddr`/`aux`, same packing as a dial, so the one formatter renders both), the transport, **which local port accepted it** (`target_pid`) and **which network namespace** the socket lives in (`cap_old` = `net->ns.inum`). It emits only on `rc == 0`: sampled production accepts on the deployment kernel returned `-EAGAIN` 157 times in 4008 calls (3.9%) and those took nothing. The namespace field matters because the two paths see different worlds — the kprobe is global, so it records accepts inside container netnamespaces that `/proc/net` (the pull path above) cannot see at all. It raises **no standalone finding**: the host's own job is accepting connections (≈3.9 accepts/s measured in a quiet window), so an allowlist decision belongs to the platform, not here. A flow on the exact port of a judged suspicious listener now completes an `endpoint:attack_chain` (`suspicious_listener_accepted`); ordinary accepts still stay journal-only. Not hooked on `security_socket_accept` — measured there, `newsock->sk` was NULL in 2021/2021 entry and 2184/2184 return probes, so the stable hook has no peer to report. `inet_accept` is a kernel-internal symbol and the `ns.inum` read is a new CO-RE relocation, both verified only on `6.12.107+deb13-amd64` (plus `inet_accept`'s signature on the build host): on another kernel the load fails and Warden exits rather than run partially (N-14). See `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §18 and `docs/security/warden_coverage_matrix.md` §1 |
| **Socket inventory (the pull path)** | Partial — implemented, off by default, journal-only | Every `kprobe`/`lsm` sensor above reports a *transition*, so none can see what was already true before Warden attached. `[network_snapshot]` reconciles `/proc/net/{tcp,tcp6,udp,udp6}` — kernel *state* — against the previous tick and against the sensors' own account, and names any listener or connection no sensor reported: pre-start sockets, records lost to a full ring, sockets whose sensor is muted. It needs no capability the unit does not already grant, attaches nothing, and cannot enforce anything. Boundaries, all stated in its own journal line: **off by default** (the walk runs inside the loop that drains the ring — release build, build host at load 3.33, seven samples each: **0–2 ms to read all four tables**, **21–71 ms with inode→pid attribution** (median 25 ms); the `/proc/<pid>/fd` walk is the cost, not the tables, and `attribute_max_pids` bounds it), **Warden's own network namespace only** (container sockets are not in this file), **it samples** (a socket that opens and closes between ticks is in no snapshot), and **no finding** — the bridge's batch contract is an open decision, so a coverage statement does not get to make it. Prove it on any host without privileges: `warden --socket-snapshot` |
| **Egress blocking** | Optional — **disabled by default**, shadow until armed | Phase 7 ships four `cgroup/sock_addr` programs (`cgroup/connect4`, `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6`), but they are not attached unless `[egress] enabled = true` names an **isolated cgroup** (never the host root). Attaching with `arm = false` (the default) is **shadow only**: a matching DENY is counted, not refused. Denial needs `arm = true` **and** an exact `(family, protocol, address, port)` rule; a denied operation returns `-EPERM` from the kernel hook. A DENY rule in `[network_rules].deny_destinations` remains an observe-only policy decision and never becomes a traffic claim. In a disposable VM, armed TCP4/UDP4/TCP6 operations were refused with `-EPERM` while a non-matching port was allowed; direct UDP6 and the full matrix remain untested. See `docs/release/PRQ_FINAL_ENFORCEMENT_PROOF.md`, `docs/security/warden_phase7_egress_enforcement.md` and `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §15/§17 |
| Persistence **creation** detection | Implemented | `kprobe/security_inode_create` in watched dirs |
| Persistence **modification** detection | **Not supported** | The persistence directories are not `guarded_files`, and `lsm/file_permission` only acts on operator-enumerated guarded inodes, so overwriting an existing file in a watched location (`~/.bashrc`, a systemd unit, `authorized_keys`) is invisible |
| Ransom-extension / rename-storm detection | Implemented | `kprobe/security_inode_rename` + the burst window |
| Destructive-op burst detection | Implemented | `kprobe/security_inode_unlink` + the burst window |
| Content-entropy ransomware detection | **Not supported** | No entropy is computed anywhere. `lsm/file_permission` learns *that* a guarded inode is being written, but it carries no written bytes and covers only `[[enforce.guarded_files]]`, so it cannot feed an entropy heuristic. `DESIGN.md` T4 names it as a criterion; only the rename/unlink-storm half is real |
| `kallsyms` / `/dev/mem` open detection | **Not supported** | `DESIGN.md` T6 names them; no hook covers them |
| Guarded-file open/mmap/permission **denial** | Partial — one armed VM case passed; full matrix not qualified | Six `lsm/*` programs need `bpf` in the boot `lsm=` list **and** an armed `[enforce]`; unarmed they observe. In a disposable VM on `6.12.107+deb13-amd64`, `scripts/test-privileged.sh` returned `0` and proved `-EPERM` for the pre-opened-fd case with `file_permission`/`inode_setattr` attached. Other hooks, allowed/event/disarm cases and other kernels remain untested; a default `cargo test` pass is not evidence of denial |
| Retracting access through an fd opened *before* arming | **Lab-proven on one kernel** for descriptors; writable mappings still not revoked | `lsm/file_permission` re-checks every read/write (including `O_APPEND`) once armed. The privileged VM runner proved `read`, `write`, `ftruncate` and `fchmod` through a pre-armed fd all returned `-EPERM`. A writable **mapping** created before arming is still not revoked — page faults bypass the hook |
| Kill a confirmed offender | One armed takedown case `PASS` in a disposable VM; full matrix not qualified | `src/respond.rs`, opt-in per rule; signals through a `pidfd` where the kernel has one, `kill(2)` otherwise. The VM run killed the exact throwaway signalling actor via `pidfd_send_signal` and logged `action=killed`; PID reuse, exclusions, other flags and fallback remain untested. See `docs/release/PRQ_FINAL_ENFORCEMENT_PROOF.md` |
| Kill identity check (pid reuse) | Implemented | The process start time is captured at enrichment and re-verified against a `pidfd` before anything is signalled, so a recycled pid is **refused** rather than killed (W-R3) |
| Protected-set identity | Partial | `[[protect.targets]]` with `exe`/real `uid`/exact `cgroup` grants immunity (all named fields must hold); F09 excludes `comms` and comm-only targets from immunity while keeping them in the PID-keyed tripwire. Kill-immunity is bound to the pid's start time (W-R4), and the takedown/inspection judges check that same binding before reporting, so a recycled pid no longer produces a false `endpoint:self_tamper` (W2K-10). The kernel's `protected_pids` map is still keyed by pid alone — the record is still emitted for the stale number and is dropped in userspace, with a `debug` line naming why |
| Kill from inside the kernel | **Planned** | `bpf_send_signal` is not called. `src/config.rs` says so in as many words; `DESIGN.md` §4/§6 describe the host probe |
| Ring-buffer drop counter | Implemented | `ringbuf_drops` + `ringbuf_events`, one slot per event kind (W2K-14), reported per sensor by `src/main.rs` |
| Ring size and per-event `/proc` cost | Implemented, load path unverified on a non-root host | `[runtime] ring_size_kib` sizes the events ring when its map is created, so the shipped object no longer fixes the capacity; `[runtime] enrich_cache_ms` collapses the four `/proc` reads per event into one, keyed on `(pid, start time)` and always bypassed for `execve` (W2K-13). `tests/ring_size_override.rs` checks the capacity the kernel actually creates, and prints SKIPPED instead of passing when it cannot load |
| Durable finding spool + retry | Implemented | `src/deliver.rs` (W-05) |
| Heartbeat HMAC authentication | Implemented | `src/hmac.rs` |
| Transport encryption | Optional mTLS; cleartext is the default | Direct mutual TLS is supported when `[bridge]` has `tls_ca_file`, `tls_cert_file` and `tls_key_file` and `url` is `https://`. Verification is mandatory, hostname/IP matching is per connection, IP literals send no SNI, and a failed handshake sends no findings. Without that explicit triple, the shipped cleartext HTTP path applies and must be a trusted local path — see [Sentinel bridge](#sentinel-bridge) |

`tests/capability_matrix.rs` freezes the shipped hook list against this table, so
a program added or removed in `bpf/warden.bpf.c` cannot leave the two disagreeing.

Two consequences worth stating plainly, because the original design notes read
more capable than the build:

- **A finding that says `endpoint:network_connect` is not a blocked connection.**
  It is an observed one. If you need the connection refused, that is a firewall
  rule, not Warden. The sensor sees `connect(2)` for `AF_INET`/`AF_INET6` (TCP
  and connected UDP); it does **not** see unconnected UDP (`sendto`), `AF_UNIX`,
  raw sockets, or any payload — so a DNS-tunneled or unconnected-UDP C2 path
  produces no `endpoint:network_connect` finding at all.
- **A connect's verdict is only as complete as the kernel's answer.** The outcome
  pair reports a verdict for a dial that *finished*: a non-blocking connect in
  flight — the shape 91% of the dials measured on the deployment host turn out to
  be — produces a CONNECT record and no CONNECT_RESULT record, because at that
  moment nothing has answered yet. The periodic `ringbuf: clean` debug line prints
  the ratio — `N of M dial(s) had a terminal verdict` — and
  `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §16 shows how to read the same counters from
  `bpftool` on a live host. The absence of a verdict is not evidence of a failure,
  and the sensor never writes one to fill the space.
- **Quiet is not the same as empty, and only the pull path can tell them apart.**
  Every sensor is a transition, so a journal with no `endpoint:listen` line proves
  only that no listener opened *while Warden was watching with a ring that was not
  full*. `[network_snapshot]` (off by default) is the answer to that question, and
  `warden --socket-snapshot` runs it once against the live kernel tables to show
  what the push path missed — on the build host, 17 listeners and 19 connections
  were open (with 36 udp-bound sockets and 8 `TIME_WAIT` entries in the same tick,
  per `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §22) before any record ever arrived. Without the
  section enabled, Warden's silence about pre-existing sockets is structural, and
  `--check` says so in one line rather than letting it be discovered in an incident.
- **The file guard protects the files you guard, from new opens and from I/O
  through already-open descriptors.** `lsm/file_open` gates acquisition and
  `lsm/file_permission` re-checks each read/write, so the code intends that
  opening a key before arming does not preserve access to it — implemented in
  code and **lab-proven for descriptors in one disposable VM** (`-EPERM` on a
  pre-opened fd). It is still not "every `.env` on the box": only enumerated
  guarded inodes are checked, a writable memory mapping established before
  arming is not revoked, and the full hook matrix is untested.
- **A pid is not an identity.** The kernel reuses pid numbers, so "pid 4711" at
  event time is not necessarily "pid 4711" when enforcement runs. The kill
  responder therefore opens the pidfd first, reads the start time of the process
  that handle pins, and proves the two still agree before signalling; if they do
  not, it refuses and says `action=identity-changed`. It will let an offender live
  rather than kill the wrong process.
- **`/proc` saying "no such file" is not proof that a process exited.** On a host
  whose `/proc` is mounted `hidepid=2`, another user's `/proc/<pid>` answers
  `ENOENT` while that process is running — the same answer a real exit gives. The
  responder tells them apart with the handle, which no mount option can hide: it
  asks signal 0, and `ESRCH` means the pinned process is gone while `EPERM` means
  it is alive and merely not ours. A live-but-unnamed target is
  `action=unverifiable` and an `ENFORCEMENT NOT DELIVERED` line, never
  "already exited": a coverage gap an operator has to close, not luck.
- **An unanchored kill is withheld by default.** If the event recorded no start
  time — `/proc` was unreadable when the finding was built, and became readable
  only afterwards — there is nothing to compare the live process against. The
  responder used to signal anyway; now it returns `action=unproven` and logs
  `ENFORCEMENT WITHHELD`, because a SIGKILL that cannot be proven to reach the
  process the finding named is the mistake this whole path exists to avoid.
  `respond.require_anchored_identity = false` opts back into the old behaviour,
  and the startup line in enforce mode prints which policy is live (W2K-25).
- **A second Warden on this host is named at startup.** Two agents enriching
  their records from `/proc` read each other, and each read is a finding for the
  other: measured on the lab VM at ~166 records/s with 26.5% of the kernel ring
  dropped, with no attacker involved (W2K-43). The agent walks `/proc` **once at
  startup** — never on the event path, because a detector of self-amplification
  that amplifies is not a fix — and logs every instance that shares its identity,
  tiered by what the evidence proves: a matching `(dev, ino)` from
  `/proc/<pid>/exe` is *the same executable file*, while a matching `comm` or exe
  basename is *the same name only; identity NOT verified*. `--doctor` answers the
  same question as seen by that run, and an inspection mode never counts as a
  peer: one daemon beside `--doctor` is the healthy case, not a collision. This
  only says. Folding one instance in, standing one down, or refusing a second
  start is the operator's call, and nothing here changes either agent's policy.
- **Protection is an identity too.** The guarded set records each protected
  pid's start time, so a pid recycled by a new process is no longer immune from
  the responder, and a `[[protect.targets]]` entry that matches nothing is
  reported at load rather than silently protecting nobody. The *alert* side
  stays pid-keyed in the kernel, so a recycled number can still produce a false
  takedown finding for up to one refresh interval (10 s) — a false alarm, never
  a missed kill (W-R4).
- **A crash is not an attacker.** A protected process that aims a lethal signal at
  *itself* — `abort()` and a Rust panic both `tgkill` the victim's own thread group,
  and `kill(getpid(), SIGTERM)` is just as legal — is reported as a Medium
  self-termination naming the call that did it, and it never asks the responder to
  kill anything: the pid is already going, and a kill aimed at a number that gets
  recycled hits whatever lives there next. The finding is not silenced, because
  whatever made the guardian abort is exactly what an operator wants to see. No
  outside process can produce the shape — `actor_pid` is the sender's own tgid, read
  by the kernel at the hook — with one exception the kernel itself creates: a record
  whose class is `aio_or_usb` is aimed from a completion context, where the pid beside
  it may name no sender, so that class never gets the self-termination pass (W2K-04).
- **Durability has a latency edge.** The healthy delivery path is a bounded,
  non-blocking hand-off to the sender thread. When the in-memory queue is full
  during a Sentinel outage, the event-loop thread appends **and fsyncs** the
  finding to the spool itself, so a long outage at high event rate can delay
  ring draining by disk latency. Size `queue_max`, the ring buffer, and the
  spool's storage for the burst you must absorb. A full spool and a hard kill
  can still lose findings; both are counted and logged, never silent.
- **A refused finding is dead-lettered, not dropped.** Sentinel's `400` now names
  the offending entries in `errors[].index`; Warden removes only those from the
  batch and retries the rest (one bad finding can no longer cost the up to 63
  good ones beside it). The named findings go to a sibling
  `bridge_quarantine.jsonl`, mode `0600`, one JSON line each with the exact
  envelope and the reason; a refusal without usable indices dead-letters the
  whole batch. The file is capped (8 MiB) and never silently truncated.

### Replaying dead-lettered findings

After the Warden/Sentinel contract is fixed, an operator can put the refused
findings back in the delivery queue:

```
systemctl stop warden
warden --replay-quarantine --config /etc/warden/warden.toml
systemctl start warden
```

Replay appends each original envelope to the spool (keeping its `event_id`, so
Sentinel's redelivery dedupe still recognises it), then renames the dead-letter
file to `bridge_quarantine.jsonl.replayed.<ts>` — the original is **archived,
never erased**, so a second invocation cannot replay the same rows twice. The
command refuses to run while `warden.service` is active: the sender holds the
spool and an in-memory image of it, which an external append would desync.
If no `[bridge]` is configured there is nothing to replay.


## Architecture

```
        ┌─────────────────────── kernel ───────────────────────┐
        │  tp/sched/sched_process_exec  kprobe/security_task_kill│
        │  kprobe/security_ptrace_access_check                  │
        │  kprobe/security_socket_connect  …_socket_listen      │
        │  kprobe/commit_creds  tp/module/module_load  …_bpf    │
        │  kprobe/security_sb_mount   kprobe/security_inode_create │
        │  kprobe/security_inode_rename  …_inode_unlink         │
        │  lsm/{file_open,file_permission,mmap_file,          │
        │       inode_unlink,inode_rename,inode_setattr}      │
        │  ← deny file/inode when armed; 4 cgroup hooks deny egress (off by default) │
        │        │            │              │                  │
        │        └────────────┴───── ring buffer ───────────────┼──┐
        │   protected_pids (hash)   runtime_cfg (array)         │  │
        └───────────────────────────────────────────────────────┘  │
                                                                    │ 344-byte
        ┌────────────────────── userspace (Rust) ──────────────────┘ records
        │  loader (aya)  →  decode  →  detect  →  ┬─ log (journald)
        │                                          ├─ respond (kill, opt-in)
        │                                          └─ bridge → Sentinel host-ingest
        │  heartbeat thread ─────────────────────────→ off-box collector
        └───────────────────────────────────────────────────────────┘
```

- **eBPF in C, loaded by Rust/aya.** CO-RE (Compile Once, Run Everywhere) via
  BTF, so one compiled object is portable across kernels. The object is
  *embedded into the binary* at build time — there is no external `.o` to lose
  or tamper with. The userspace binary is a single Rust executable, but it is
  **not fully static**: the optional Phase 8 bridge transport links against the
  host's runtime `libssl.so` and `libcrypto.so` (OpenSSL 3 API). A build without
  those shared libraries is not supported by the shipped configuration.
- **Tamper-evident, not tamper-proof.** Warden can't guarantee it survives a
  determined root attacker. What it guarantees is that its death is *loud*:
  self-protection sensors + an off-box heartbeat + systemd `Restart=always`.

## Posture: observe first

Warden ships **observe-only**, on both enforcement axes. It watches, judges,
logs, and (if a bridge is configured) reports — but:

- it never **kills** until an operator sets `mode = "enforce"` **and** opts into a
  specific responder. The kill responder refuses obviously-suicidal targets
  (pid 1, Warden itself, any protected pid) no matter what policy says.
- it never **denies a file open** until `[enforce]` is armed and the file is one
  the operator has guarded — and even then only if the kernel was booted with
  `bpf` in its `lsm=` list, because an unattachable LSM hook cannot refuse a
  syscall. See [`[enforce]`](#configuration).
- it never **denies egress** until `[egress] enabled = true` names an isolated
  cgroup, `arm = true` is read back from the kernel, and an exact
  `(family, protocol, address, port)` rule matches. All three default off.

Unarmed, the LSM programs do exactly what the kprobes do: observe and report.
The four optional cgroup hooks are not attached at all in the default posture.

## Build

Requires `clang` (with a bpf target), `bpftool` (only to regenerate
`vmlinux.h`), and a Rust toolchain.

```sh
make            # clang builds bpf/warden.bpf.o, cargo builds the agent
make check      # validate config + toolchain wiring, no kernel needed
make config-check  # M16: dedicated config validation (no kernel, no service change)
make self-test  # M16: read-only installation self-test with explicit statuses
make test-cli   # M16: config-engine + guided-installer regressions
make test       # unit tests; privileged cases self-skip
sudo env "PATH=$PATH" make test-privileged   # disposable VM only: BPF-LSM pre-opened-fd denial; kill/egress NOT exercised
sudo make install
```

For a guided, preview-first installation use
`make install-wizard PROFILE=balanced` (add `--yes`/`--unattended` only when you
intend to write files). The full operator Q&A is in
[`docs/release/WARDEN_FINAL_OPERATOR_HANDOFF.md`](docs/release/WARDEN_FINAL_OPERATOR_HANDOFF.md).

A green `make test` is not evidence for the enforce paths: the tests that load
BPF or signal real processes self-skip without privileges, and the target above
fails loudly instead of reporting a skip as a pass. Run it on a disposable VM
whose kernel has `bpf` in the boot `lsm=` list — see
`docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` for the live runbook.

`make install` places the binary at `/usr/local/sbin/warden`, a sample policy
at `/etc/warden/warden.toml`, and the systemd unit. Then:

```sh
sudo systemctl daemon-reload
sudo $EDITOR /etc/warden/warden.toml     # set protect/app/bridge for this host
sudo systemctl enable --now warden
```

## Run without installing

```sh
sudo ./target/release/warden --config config/warden.toml --debug
```

Needs `CAP_BPF` to load programs and create maps; `CAP_SYS_ADMIN` **or**
`kernel.perf_event_paranoid <= 1` to attach the tracepoints and kprobes;
`CAP_SYS_PTRACE` for /proc enrichment; `CAP_KILL` for enforce mode. The second
one is the one that bites: `perf_event_open(2)` for a tracepoint or kprobe is
gated on `CAP_SYS_ADMIN` while `perf_event_paranoid` is above 1, and `CAP_PERFMON`
does **not** satisfy it — while the mainline default is 2, Debian 13 ships 3 and
this dev host ships 4. A unit granting only `CAP_BPF CAP_PERFMON CAP_SYS_PTRACE
CAP_KILL` therefore loads the object, then fails to attach anything with an
anonymous `EACCES`, on most kernels. The shipped unit grants `CAP_SYS_ADMIN` as
well and drops it again at the seccomp layer for the dangerous calls; see
`systemd/warden.service` for what that costs and `warden --doctor` for the
measurement on the host you are on.

### When it will not start

A guardian that is down looks, by default, like a guardian that is fine. The unit
is configured so that a start failure is bounded and announced instead:

- `ExecStartPre=/usr/local/sbin/warden --check --config …` rejects a contradictory
  policy **before** any `bpf()` syscall, so a config error never churns the kernel.
- `StartLimitIntervalSec=300` + `StartLimitBurst=8` bound the loop. `Restart=always`
  still restarts a crashed daemon forever *within* the window; what it no longer
  does is restart a never-starts daemon forever.
- `OnFailure=warden-deadman@%n.service` writes a `daemon.crit` journal line on each
  failed start, from a unit that lives outside the process being reported — because
  the in-process heartbeat cannot report a process that never began. Measured: a
  failing start produces an alert about three seconds later, and eight of them trip
  the limiter into `failed`.

Check the three things it will tell you, in this order:

```sh
systemctl status warden                 # ActiveState + why the last start died
journalctl -u warden -n 100             # the first lines are the real error
/usr/local/sbin/warden --check --config /etc/warden/warden.toml   # config only
/usr/local/sbin/warden --doctor         # kernel only: BTF, cgroup v2, perf gate, kill delivery
```

`--check` and `--doctor` are deliberately separate: one reads only the file, the
other only `/proc` and `/sys`. Neither loads anything, neither needs privilege, and
`--doctor` reports the perf gate — `kernel.perf_event_paranoid` against this
process's `CAP_SYS_ADMIN` — so "the sensors will be refused" is visible before you
start the service rather than after. It also reports **kill delivery**: two
`pidfd_send_signal(…, 0, …)` probes, one against this process's own pid and one
against pid 1. Signal 0 is the kernel's permission check with the delivery
suppressed, so nothing is signalled — but the pair of answers is what separates
"a seccomp filter refuses the syscall, so enforce mode can never deliver" from
"this uid simply may not signal a process it does not own", which no single errno
can tell you. It is a measurement of the user running the command, never of the
daemon; the line says so.

### Commands that load nothing

| Command | What it answers | What it does NOT answer |
|---|---|---|
| `warden --version` | Which build this is, and the FNV-1a digest of the eBPF object compiled into it. The digest is the part that identifies the object: its **length** does not — a comment-only edit to `bpf/warden.bpf.c` changes the bytes. The public Alpha object is 1,243,656 bytes, SHA-256 `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`, FNV-1a `0xbc288747047b4edb`. It is rebuilt from the same source/ABI/BTF as the M15/M16 object (1,243,776 bytes, SHA-256 `5e0508c0…e7e4a`, FNV `0x12b9ea8166db40df`) with only debug path prefixes relativised via `-fdebug-prefix-map`, so no builder home path is published. The eBPF program text (`.text`) and BTF type data are byte-identical to the M15/M16 object; see `docs/release/PRQ_01_PUBLIC_SANITIZATION_REPORT.md`. `make bpf` refreshes the digest after any source change. | Whether the object loads. |
| `warden --check` | What the **config** would cover: every coverage sentence the agent will run on, plus the warnings it refuses to keep to itself (unread keys, empty loader allowlist, a plaintext uplink, an empty app cgroup). Reads the file only — safe as `ExecStartPre`, safe in CI, safe unprivileged. | Anything about the kernel. `net_vol`'s line deliberately ends "the hooks and their totals are unknown here". |
| `warden --check --strict` | The same config audit, but unread keys become a hard failure instead of a warning — for CI and the deploy gate. Names only key names, never values. Refused beside any mode other than `--check`/`--doctor`. | Anything about the kernel; normal startup still uses the non-fatal audit. |
| `warden --profile-list --config-json` | M16: the five profile contracts (features, prerequisites, risks, enforcement and degradation behavior), machine-readable. | Whether a profile can attach on this kernel; that needs the privileged VM gate. |
| `warden --profile NAME [--config-json]` | M16: generate a complete, validated, capability-aware TOML document from `essential`, `balanced`, `advanced` or `hardened`; `custom` validates an existing file. No kill/denial is armed. | A runtime claim: the output is a plan, not an attached agent. |
| `warden --config-validate --strict --config PATH [--config-json]` | M16: exact diagnostics with field, security consequence and correction; checks schema, permissions, unread keys, capability mismatches and unsafe combinations. | Kernel attach, service state or live SENTINEL delivery. |
| `warden --config-plan --config PATH [--config-json]` | M16: explicit simulation of sensors, privileges, risks and service actions. | Any bpf() call; the output says `SIMULATION ONLY`. |
| `warden --config-baseline PATH` / `warden --config-drift PATH` | M16: write/compare a secret-free state snapshot (content fingerprint, mode, schema, measured host facts, service state); unmeasured runtime state is named, not guessed. | In-memory policy after SIGHUP, ring counters and spool contents. |
| `warden --self-test --config PATH` | M16: read-only installation report using `PASS`, `FAIL`, `UNKNOWN`, `NOT_RUN` and `NOT_APPLICABLE`. | Kernel load, service start or SENTINEL connectivity; those are explicitly `NOT_RUN`/`NOT_APPLICABLE`. |
| `warden --doctor` | `--check`'s lines **plus this host**: kernel release, page size, BTF, cgroup v2, the perf gate, whether this process may deliver a signal at all, and per fexit target one of `present` / `ABSENT` / `CANNOT TELL` — read from `/sys/kernel/tracing/available_filter_functions` when it can (the list ftrace itself accepts) and from `/proc/kallsyms` when it cannot. It also answers one question the running agent answered only in its own startup journal: how many other Warden instances are live on this host, each named by pid, exe and `comm`, and each marked `the same executable file (dev/ino match)` or `the same name only; identity NOT verified` according to what this reader could actually read (W2K-43). | Whether a hook attached. Presence is one of three levels — clang accepts the C, the verifier accepts the bytecode and its BTF relocations, attach plus a bump in the right map row — and only the last is a measurement. `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §22/§23 is the live record for the deployment kernel. Nor is the delivery probe a verdict on the daemon: it answers for the uid that ran `--doctor`, and the service runs under its own `User=` and `AmbientCapabilities`. Nor is the co-residency count a claim that no others exist: an instance whose exe and command line are both unreadable — another user's on a `hidepid=` host — cannot be proved and is not listed. |
| `warden --health` | What a **running agent** can be seen to be from outside, right now: its pid, uid, cgroup and `comm`; its argv, and the config path that argv names (never this command's `--config`, which is reported as unused if it differs); whether that file still parses for this binary and whether it is newer than the process; its threads from `/proc/<pid>/task`, compared after the kernel's 15-byte `TASK_COMM_LEN` cut, so `warden-heartbea` is what a live heartbeat thread is actually called; `SigCgt:`, i.e. whether the SIGHUP reload path really reaches it; its age from `/proc/uptime` minus field 22 of `stat`; and the FNV-1a digest of the object compiled into **this** binary. Cap-less and `/proc`-only: no `bpf()` syscall, no map read, nothing attached, no capability taken, no signal sent, no subprocess. One line per claim, one evidence word per line. | Anything inside the kernel: the attach set, the ring buffer's capacity and drop/submitted counters, the net-volume totals and their deltas, the `protected_pids` map — all of them map reads that need `CAP_BPF`/`CAP_PERFMON`. Also the policy the agent holds in memory after a reload (there is no status path), what it logged (journald's file, and this command spawns no `journalctl`), and the unit's `ActiveState`/`NRestarts` (the bus, a second control channel). On a root-owned agent its `exe` link and `fd` table need `PTRACE_MODE_READ` too, so identity drops to `PARTIAL` and the log sink to `CANNOT TELL`. Each of these is printed as a `cannot see/…` line naming the privilege it would take — never a reassuring count. |
| `warden --health --json` | The **same** claims as `--health`, as `warden.health.v1` JSON: an ordered `claims` array of `{claim, status, detail}` plus a `by_status` tally. Derived from the rendered lines, so text and JSON cannot disagree; `cannot see/…` lines keep their `UNVERIFIED` status rather than being dropped to look healthier. A config parse error quoting an `api_key` line is redacted. | Any claim the cap-less text view cannot make — JSON does not invent evidence. Refused without `--health`. |
| `warden --explain KIND --event k=v …` | What **this config** would have said about an event that is not happening: it hands a hypothetical record to the same `Detector::judge` the running agent calls, so the answer cannot be a rule the agent does not follow. Then it changes **one knob at a time** and re-asks, printing only what moved the answer — `GATE` (silence → finding), `SILENCED`, `SEVERITY`, `RESPONSE`. Kinds: `exec signal ptrace connect connect_result creds module file service listen bpfload mount access flow`; `ops=N` replays one record N times so the file-burst rule is explainable. | Whether the kernel emitted the record (`--doctor`/`--check`), whether the responder would have killed (it re-checks live identity through a pidfd), and whether the journal would have printed another line (repeats are coalesced for 10 s). The probes cover the knobs they were written for, not every key in `Config` — the last lines of every answer say all of this. |

`--explain` never signals: `Responder::act()` is not called on this path, only
`cfg.mode` and the finding's own `wants_kill` are read. It also never reads the
actor's `/proc` — `exe`, `cmdline` and `cgroup` are supplied with `--event`, which
is why an answer about a process that does not exist is honest: the footer names
every default the command invented (`pid=0`, `exe absent`, `cgroup absent ≠ outside
the app`). Example — the question an operator actually asks after a quiet week:

```
$ warden --config /etc/warden/warden.toml --explain exec \
    --event path=/bin/bash --event comm=bash --event uid=1000 \
    --event exe=/usr/local/bin/python3.11 --event cgroup=/system.slice/docker-27f0b80….scope
warden: explain: verdict: NO FINDING from this config
warden: explain: GATE: add "docker-27f0b80….scope" to [app].cgroup_contains →
    endpoint:process_creation at high — app-context shell spawn: …
```

`CANNOT TELL` is a state of its own and never counts as `ABSENT`. On the
deployment host `available_filter_functions` is mode 0440 `root:root`, and reading
its `Permission denied` as "the function is not there" would have published four
working hooks as missing (§23 step 1). Run `--doctor` as root for the authoritative
source; unprivileged it still answers, from the weaker list, and says which it used.

`--health` is the only one of the five that is about a process that is up **right
now**, and it is the reason that paragraph is a rule and not a style: it runs before
the config loads, so a host whose `/etc/warden/warden.toml` no longer parses still
gets an answer instead of a load error, and the agent's unreadable `exe` link comes
out as `PARTIAL` with the errno printed rather than as a green line. Its own last
line lists what it did not do, and the seven `cannot see/…` lines above it are the
map-backed claims it deliberately does not fake. Like `--explain`, it refuses the
company of the other print-and-return modes — `warden --health --check` is an error,
not a report that silently dropped one of the two. Example, on the deployment host
as an ordinary user:

```
$ warden --health | sed 's/ — .*//'
warden: health: build: VERIFIED
warden: health: process: present
warden: health: identity: PARTIAL
warden: health: control: VERIFIED
warden: health: threads: PARTIAL
warden: health: config/path: present
warden: health: config/parse: CANNOT TELL
warden: health: log sink: CANNOT TELL
warden: health: age: VERIFIED
warden: health: cannot see/attached programs: UNVERIFIED
warden: health: cannot see/ring buffer: UNVERIFIED
warden: health: cannot see/volume totals: UNVERIFIED
warden: health: cannot see/protected pid set: UNVERIFIED
warden: health: cannot see/the policy in the agent's memory: UNVERIFIED
warden: health: cannot see/what the agent logged: UNVERIFIED
warden: health: cannot see/the unit's own state: UNSUPPORTED
warden: health: cannot see/another uid's process: UNAVAILABLE
warden: health: cannot see/sockets outside Warden's namespace: UNAVAILABLE
warden: health: what this did NOT do: VERIFIED
```

Every line is `warden: health: <claim>: <STATUS> — <why>`, one claim per line and
one status word per claim, so the `sed` above is the whole index; the detail each
line carries after the em dash is the errno, the `/proc` file it came from, and the
privilege that would have answered the question. Unprivileged, `identity` is
`PARTIAL` because `/proc/<pid>/exe` needs `PTRACE_MODE_READ`, `config/parse` and
`log sink` are `CANNOT TELL`, and `threads` is `PARTIAL` because the config file
that would say which threads to expect is one of the unreadable ones — so the
expectation falls back to this build's minimum and says so in the line.

## Configuration

Everything an operator tunes lives in `warden.toml`. Most of it takes effect on
a reload; `[bridge]`, `[heartbeat]` and `[runtime] ring_size_kib` need a restart —
see [Reloading](#reloading).

### One configuration engine, two levels of UX (M16)

`schema_version = 1` is now written in the sample and understood by the loader;
a missing key is accepted as legacy version 0 so existing deployments keep
starting. The same `Config` structure is used by the daemon and by the new
read-only operations:

```sh
warden --profile-list --config-json
warden --profile balanced                      # prints a complete TOML document
warden --config-validate --strict --config warden.toml
warden --config-plan --config warden.toml --config-json
warden --config-migrate --target-version 1 --config /etc/warden/warden.toml
warden --config-baseline /var/lib/warden/baseline.json --config /etc/warden/warden.toml
warden --config-drift /var/lib/warden/baseline.json --config-json
warden --config-rollback --config /etc/warden/warden.toml --from /path/to/backup
warden --self-test --config /etc/warden/warden.toml
```

Profiles are capability-aware and all generated profiles are **observe-only**:
no kill responder, BPF-LSM arm, cgroup egress denial or guessed guarded-file
path. A capability that was not measured stays `UNKNOWN`; a plan is labelled
`SIMULATION ONLY` and never claims an eBPF attach. Operations answer one
question per run and are dispatched before daemon config load, so a broken
deployed file cannot block validation or recovery. See the
[operator guide](docs/release/WARDEN_FINAL_OPERATOR_HANDOFF.md) for exact
semantics, backup behavior and safe VM procedures.

- `[runtime]` — the two costs Warden pays per event and per burst.
  `ring_size_kib` sizes the kernel→userspace events ring (default `256`, the
  capacity baked into `bpf/warden.bpf.c`; range 64–16384 KiB, and only values the
  kernel honours verbatim — a page-power-of-two — are accepted, so `200` is
  refused with the number to use instead of silently becoming 256). **Restart
  required**: the ring's size is fixed when its map is created. The ring is lossy
  by contract; the drop counters say which sensor is bleeding, and the answer to
  a sensor that overruns even a large ring is to mute it, not to keep growing the
  buffer. `enrich_cache_ms` (default `100`, `0` disables, above `5000` refused)
  is how long Warden reuses one `/proc` read set for a process instead of taking
  four reads for every event it produces — measured on this host, 51 events from
  one process went from 204 `/proc` operations to 54. Its cost is honesty about
  staleness: `execve` always re-reads (a new image under the same pid must never
  be judged on the old one), and the window is the maximum lag an attribution
  field can carry. A misspelled key inside `[runtime]` is ignored, because
  `warden.toml` as a whole does not deny unknown keys — so after editing this
  section, read `warden --check`'s `events ring:` line: it echoes both the size
  policy asked for and the size this host's page granularity would build.
- `[protect]` — which processes are guarded. `protect_self` keeps Warden's own
  pid in the immunity set, and `[[protect.targets]]` grants immunity through an
  AND over `comm`/`exe`/`uid`/exact `cgroup` **only when the target also names
  `exe`, real `uid`, or exact `cgroup`** (W-R4/F09). `[protect].comms` and
  comm-only targets are **tripwire-only**: a signal or ptrace at a matching pid
  still alerts, but the kill responder never returns `action=refused` for them.
  This matters because any process can take a protected name with
  `prctl(PR_SET_NAME)`; a name by itself is not an identity. `cgroup_contains`
  retains its previous behavior and is the loosest immunizing selector, so an
  anchored target is preferred. Immunity is bound to the process's start time,
  so a recycled pid does not inherit it. An omitted `[protect]` table defaults
  `protect_self` to `true`.
- `[app]` — what counts as "the application" for exec/egress/privesc/file
  attribution. A shell (or dial-out, or root-escalation) in the app cgroup is an
  incident; the same in an admin session is routine. An empty `cgroup_contains`
  silently disables every app-scoped detector, so Warden warns about it at
  startup; the any-actor sensors (deleted-exe, protected-pid signal/ptrace,
  module/BPF, mount, persistence creation) still fire. `exe_allowlist` names the
  app's own runtimes by their resolved `/proc/<pid>/exe` path (never comm); that
  is what stands the staging rule below down for a declared binary, and nothing
  else.
- `[exec_rules]` — the shell list, matched against the exec's identity (resolved
  exe, the path the execve tracepoint saw, comm) rather than comm alone; the
  deleted-exe (fileless) flag; and `untrusted_exe_prefixes`, the world-writable
  staging areas whose contents the app has no business executing. The last one is
  what catches `cp /bin/bash /tmp/svc-agent`, where no shell name appears anywhere
  in the event. It reports Medium and never arms the responder; `[]` disables it,
  and an entry that is not an absolute path below `/` is refused at load.
- `[network_rules]` — the egress allowlist (destinations, ports, loopback) and
  whether to judge only the app cgroup.
- `[cred_rules]` — privilege-raise detection: the expected setuid plumbing to
  suppress, and whether a pure capability gain also counts. Since W2K-30 the
  suppression is identity-aware: `expected_privilege_comms` clears a raise only
  when the readable `/proc/<pid>/exe` is that name's binary (or when no exe could
  be read at all), so `prctl(PR_SET_NAME)`-ing a payload into "sudo" no longer
  hides the escalation. `expected_privilege_exes` is the absolute-path list that
  authorizes a raise whatever the process calls itself; it ships empty, which
  means nothing is authorized by identity, and `warden --check` names that posture
  on every run.
- `[ptrace_rules]` — which readers of a protected pid's `/proc` metadata are
  routine plumbing. Same W2K-30 rule as above: `benign_reader_comms` silences a
  `PTRACE_MODE_READ` only when the executable Warden read belongs to that name
  (`systemd` ← `/usr/lib/systemd/systemd`, tolerating the kernel's 15-byte
  truncation and a `runc:[1:CHILD]` re-title) or could not be read at all; a
  process that calls itself `systemd` from `/tmp/.cache/systemd-scan` is credential
  recon and reports as such. `benign_reader_exes` is the path list that clears a
  read whatever the process is called, and it is consulted first. An ATTACH is
  never silenced by either list.
- `[module_rules]` — the runtime kernel-module allowlist and its severity ceiling.
- `[bpf_rules]` — which eBPF program loads are worth surfacing (`watch_prog_types`,
  the implant-capable kinds) and **who may load them**. Since W2K-18 that second
  question is answered by `allow_loader_exes`: absolute executable paths, matched
  against the loader's resolved `/proc/<pid>/exe`. `allow_loaders` is a list of
  comms, and a comm is a string the process chose for itself with one
  `prctl(PR_SET_NAME)` call, so it no longer authorizes anything on its own — it
  only decides a load whose executable could not be read because the loader had
  already exited, and since W2K-29 "had already exited" is the kernel's answer
  rather than a guess: `pidfd_open` on that pid must not say `ALIVE`, so a live
  loader hiding behind an unreadable `/proc/<pid>/exe` (a `hidepid=` mount, a
  cross-uid read) is a finding whatever it calls itself. Since Stage 13 that fallback
  has a fact underneath it: the hook stamps the loader's executable file —
  `(dev, ino)` of `mm->exe_file`, read inside the hook while the task is alive by
  construction — into the record, so when `/proc/<pid>/exe` cannot be read the agent
  still knows *which file ran*. `allow_loader_exes` is then compared against the
  inodes its paths resolve to, and a name no longer clears a load whose file the
  kernel named and whose file is not on that list; the finding quotes
  `loader_exe_dev`/`loader_exe_ino` and tells the operator to resolve it with
  `find / -xdev -inum <ino>`. Three answers, and the third is not a verdict: with an
  empty list — or with no entry that can be `stat()`ed — there is nothing to compare,
  and the weaker name-only posture is exactly what it was. A readable exe still
  decides first. The shipped default is an
  empty exe list, which means **no loader is authorized by identity**: every
  implant-capable load with a readable executable is a finding. `warden --check`
  says so on every run; pin your sanctioned loaders to make it stop. Entries must
  be absolute paths to a file (a relative or blank entry can never match, and
  would read as an armed rule authorizing nothing).
- `[file_rules]` — watched names (any actor), ransom extensions, and the
  modification-burst threshold/window (app-attributed).
- `[enforce]` — the guarded-file axis, **one of two denial axes** (the other is
  `[egress]`, disabled by default). `arm = false` is shadow mode: the LSM hooks run and emit
  `endpoint:access_denied` records for what they *would* have refused, but allow
  the operation through. Each `[[enforce.guarded_files]]` names a `path`, the one
  `authorized_uid` allowed the denied intents, which `deny` intents
  (`read`/`write`/`exec`) are forbidden to anyone else, and whether `allow_root`
  exempts uid 0 — it does not, by default, so a stolen root shell cannot read a
  guarded key. Requires `bpf` in the kernel boot `lsm=` list to arm at all.
- `[respond]` — the opt-in kill responders (all default off).
- `[bridge]` — the Sentinel uplink (optional; omit for local-log-only).
  **Restart required.** A cleartext `http://` URL is **refused at load** when its
  host is a publicly routable IP literal (W2K-19) or a name whose one startup
  lookup answers publicly (W2K-28); see
  [Sentinel bridge](#sentinel-bridge) for the classification table and the
  `allow_public_plaintext` attestation.
- `[heartbeat]` — the off-box dead-man's-switch (optional). **Restart required.**
  Same transport rule as the bridge, with its own refusal text — a readable beat
  leaks the moment this host went quiet.
  Hostname lookups are bounded (≤5 s, at most two lookups stuck in libc at once);
  an IP-literal collector URL never touches DNS. A hung resolver costs one late
  beat and a warning, not a silent switch.

See `config/warden.toml` for the fully-commented sample.

### Keys Warden never reads (W2K-23)

A TOML key that no field of its section declares used to be dropped in complete
silence. That is not hypothetical: the deploy script rewrites `[bridge]` between its
markers and appends that table at the **end** of the file, which leaves the sample's
commented bridge block — and any key uncommented from it — structurally inside
`[respond]`. Uncomment `spool_path` there and the config parses, loads, and ignores
it; the durable queue keeps writing where the systemd unit expects it, while the
operator believes they moved it.

`warden` now names every such key, in the file's own dotted form, at three places an
operator actually looks: `warden --check`, the journal at startup, and every SIGHUP
reload.

```
warden: WARNING: 1 config key(s) in this file are not read by Warden:
respond.spool_path. A key that no field of its section declares is dropped in
silence — the value in effect is Warden's default, not the one written. …
```

Array-of-tables entries carry their index (`enforce.guarded_files[2].allow_rooot`),
so a typo inside one of eight guard blocks names the block. Misspelled section names
are reported whole (`mount_rulezz`).

This is a warning, never a refusal — deliberately. A sensor that will not start
because of a typo is a coverage gap on a live host, and the dead-man's switch paging
because somebody typed `timout_ms` is a worse outcome than the misconfiguration
itself. The audit is derived from the structs rather than hand-listed: a loaded config
is re-serialised through serde, so the schema is serde's own field list and cannot
drift from the code. The shipped sample is a test fixture for that property
(`the_shipped_sample_config_leaves_nothing_unread`), and the 38 KB config on the
deployment host — with all eight guarded files and both marker blocks — reports zero
unread keys.

**Strict mode for CI.** `warden --check --strict` promotes the same audit from a
warning to a hard failure (exit non-zero). The deploy gate and CI should use it:
an unread key there means the file says one thing and the agent runs another.
Normal startup stays non-fatal — a typo must never blind a live sensor — and the
error names only key NAMES, never values, so an `api_key` orphaned into the wrong
section cannot leak through it.

### Reloading

`systemctl reload warden` (SIGHUP) re-reads `warden.toml`. What it applies and
what it does not:

| Section | On SIGHUP |
| --- | --- |
| `mode` | **applied** — the responder is rebuilt, so `observe → enforce` starts killing and `enforce → observe` stops |
| `[protect]` | **applied** — the pid set is re-walked, re-pushed, and re-bound to each process's current start time |
| `[app]`, `[exec_rules]`, `[network_rules]`, `[cred_rules]`, `[ptrace_rules]`, `[module_rules]`, `[file_rules]`, `[service_rules]`, `[listen_rules]`, `[bpf_rules]`, `[mount_rules]` | **applied** — the detector is rebuilt from the fresh policy |
| `[respond]` | **applied** — the detector reads these flags per finding |
| `[enforce]` | **applied** — the arm gate is re-pushed and every guarded file is re-resolved to its current (device, inode) |
| `[runtime] enrich_cache_ms` | **applied** — the detector is rebuilt, and the cache window is read per event |
| `[runtime] ring_size_kib` | **restart required** — the ring is sized when its map is created; the reload logs the requested and live values so the gap is visible |
| `[net_volume]` | **applied** — the tick settings come from the rebuilt detector, and the in-kernel gate is a slot of `runtime_cfg`, so a flip of `enabled` writes it and says `net_volume emit gate true → false, applied now` (W2K-31). The attach set is the part that needs a restart, and it does not change here |
| `[bridge]` | **restart required** |
| `[heartbeat]` | **restart required** |

`[bridge]` and `[heartbeat]` are exceptions because each is owned by a
thread started once at boot: the bridge thread holds an in-flight queue and the
on-disk spool, and the heartbeat thread holds the monotonic `seq` counter. There
is no safe point at which to swap either mid-flight, so a reload does **not**
apply them. `ring_size_kib` is a third, different kind of exception: nothing in
userspace holds the size, the kernel does, at the moment the map is created.

A reload never silently pretends otherwise. When a restart-required field has
changed, Warden logs at `warn` the exact fields that differ and says a restart is
required — the fields are *named*, never printed, so `[bridge] api_key` and
`[heartbeat] secret` appear as their key and not their value. The warning repeats
on every reload until the restart actually happens.

A reload that changes nothing restart-required logs only the applied summary, and
the summary names the kernel gate rather than the config value, because those two
are what a reload can pull apart:

```
SIGHUP: applied mode=Observe, protect (3 pid(s)), enforce (arm=false, 2 guarded inode(s)), runtime (enrich cache = 250 ms), net_volume (kernel gate = false, interval = 60 s)
```

so a partially-applied reload is distinguishable from a clean one at a glance.

## Sentinel bridge

When `[bridge]` is set, every finding is POSTed to
`POST /api/v1/sentinel/host/`. The default authentication is an `X-API-Key`
(a Sentinel client key whose service is `sentinel`); an explicitly configured
mTLS transport additionally authenticates the agent with its own certificate.
Findings arrive marked `source: "warden"` and stamped with the host id, and
Sentinel records them as first-party `endpoint:*` events.

Each envelope also carries **what this box did about the finding**: `action` is
the responder's verdict — one of `observed`, `killed`, `refused`,
`identity-changed`, `failed`, `unverifiable`, `unproven` — and
`enforcement_requested` is whether the class was lethal at all. The journal line
and the wire print the same word from the same mapping, so the two cannot drift.
Read the pair together: `killed` says a SIGKILL was delivered, `refused` says the
pid was protected or was this daemon or init, `unproven` says enforcement was
withheld because the event could not anchor its target (see
`respond.require_anchored_identity`), and `observed` with
`enforcement_requested: true` says this host is in observe mode while a lethal
class was firing. Without the word, all of that reached the platform as one
identical row (W2K-27).

Each envelope also carries its **clock lineage**: `event_time_unix_ms` comes from
the kernel `bpf_ktime_get_coarse_ns()` stamp on the ring record (converted with
the boot-time offset), while `observed_at_unix_ms` is the agent's wall clock at
judgement. The raw `kernel_event_ts_ns`, its converted `kernel_event_unix_ms`,
and the `kernel_event_clock` / `event_time_clock` labels ship beside them; a
record with no usable kernel stamp says `event_time_source = "agent_observed_at"`
instead of inventing one. Sentinel stores the lineage and **rejects a batch** that
claims a kernel clock without its raw stamp, or whose claimed wall time and raw
stamp disagree with the boot-time conversion. Legacy envelopes without the new
fields still ingest. This is provenance, not synchronisation: the host's clock can
still be wrong, and no NTP or cross-host ordering guarantee is implied.

Two transport shapes are supported, and neither is silently changed at runtime:

1. **Cleartext HTTP (the default).** TLS terminates at the deployment edge, as
   elsewhere in this platform, and that makes the Warden→edge hop part of the
   trust boundary. `X-API-Key` travels in a request header in cleartext, and
   heartbeat beats are authenticated but not encrypted. Keep that hop on
   loopback, a private/management network, or an encrypted tunnel (WireGuard,
   SSH, an internal service mesh). If Warden and the edge are separated by an
   untrusted network, either run a TLS-terminating proxy on the Warden host and
   point `bridge.url` at its local `http://` listener, or use the mTLS shape
   below.
2. **Direct mutual TLS (Phase 8, opt-in).** Set `bridge.url` to `https://` and
   configure all three of `tls_ca_file`, `tls_cert_file` and `tls_key_file`
   together. The agent verifies the server against the explicit CA and presents
   its own certificate. DNS names are pinned with
   `X509_VERIFY_PARAM_set1_host` and sent as SNI; IP literals are pinned with
   `X509_VERIFY_PARAM_set1_ip_asc` and send no SNI. `tls_sni` is optional and is
   ignored for an IP literal target. Verification parameters are per connection,
   so concurrent uplinks cannot contaminate each other. A partial material set,
   `http://` plus material, `https://` without material, a non-`0600` key, or a
   failed handshake is a hard refusal — there is no TLS downgrade or cleartext
   fallback. The binary links to the host's `libssl.so`/`libcrypto.so`; it is not
   a fully static binary.

The "keep a cleartext hop on loopback/private" rule is checked, not just stated.
`warden --check` and startup classify the host of `bridge.url` / `heartbeat.url`
by the address it really is, and **refuse to load** a cleartext `http://` pointing
at a publicly routable address — whether the URL spelled it as an IP literal
(W2K-19) or as a name whose record answers publicly (W2K-28). A verified mTLS
uplink is not subject to the cleartext gate.

| What the URL's host is | At load | `--check` says |
| --- | --- | --- |
| `127.0.0.1`, `::1` | allowed | "no wire, no exposure" |
| RFC1918, link-local, CGNAT `100.64.0.0/10` | allowed | "trusted only if THAT network is yours; a shared VPC is not a tunnel" |
| publicly routable IP over `http://` | **refused** | the config error names the URL and the payload at risk |
| host name that answers with a routable address over `http://` | **refused** | the error lists every address the name resolved to |
| host name that answers loopback/private | allowed | one line per name: the address and its class |
| host name that does not answer (dead resolver, NXDOMAIN, >2 s) | allowed | "could not be classified" — Warden still starts, and says so |
| `https://` with the complete mTLS triple | allowed | "MUTUAL TLS", the verified identity and the CA/cert paths (never the key) |
| `https://` without the complete mTLS triple | **refused** | names the missing material; no downgrade |
| `http://` with mTLS material | **refused** | sending a client certificate in cleartext is not allowed |

A name is resolved **once per process at startup**, on a helper thread with a
2-second deadline, so the check cannot hang a boot: an unanswerable name is a
report, not a refusal. That answer is an advisory, because records move. The
guarantee is at the address the request would actually use: the delivery path
classifies the socket address it just resolved (including the one it re-resolved
after a connect failure) and refuses to send an unattested public one — the
finding stays queued, then spooled, and the journal says why. `--check` cannot
show that second gate; a running Warden can.

The refusal is escapable only by attestation: `bridge.allow_public_plaintext =
true` (and the same key under `[heartbeat]`) lets the config load, and `--check`
then prints that it was allowed *because you attested the path*, not because the
path is safe. A beat anyone on path can read tells an attacker when this host
stopped sending them — the exact takedown the dead-man's switch exists to notice
— which is why `[heartbeat]` gets its own refusal text rather than reusing the
bridge's, and why the beat gets the startup refusal but **not** the delivery
refusal: a beat that stops because a collector's address changed is read off-box
as the host itself going quiet.

### Verifying the bridge and heartbeat locally

`scripts/live_bridge_check.py` is a stdlib-only collector that speaks both
protocols above. It verifies the heartbeat HMAC and rejects a `seq` that does
not strictly climb for its host, and it can refuse bridge POSTs with `503` so
the durable spool and the reconnect path are exercised rather than assumed:

```sh
# refuse the first two findings, then accept; check MACs and the API key
python3 scripts/live_bridge_check.py serve --port 9099 \
    --api-key test-key --secret shared-secret \
    --fail-first 2 --log /tmp/warden-live.jsonl

# ... run Warden with bridge.url/heartbeat.url pointed at 127.0.0.1:9099,
# generate findings, then stop Warden and read the log:
python3 scripts/live_bridge_check.py summarize --log /tmp/warden-live.jsonl
```

`summarize` exits non-zero if a beat was rejected or a host's accepted `seq`
values are not strictly increasing. Duplicate `event_id`s are reported but do
not fail the run: delivery is at-least-once by design, and the id is what makes
a redelivery idempotent on the Sentinel side.

The collector can check itself before it is trusted with a live run:

```sh
python3 scripts/live_bridge_check.py selftest
```

It starts a loopback server, drives the same handler threads with synthetic
requests, and asserts the 401/503/200 verdicts, duplicate-id detection, MAC
verification and seq-replay rejection.

`docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` is the full operational runbook: outage and spool
growth, reconnect and drain order, restart replay, the spool cap, SIGHUP field
handling, and the heartbeat sequence across a restart. It is a procedure, not a
claim — each scenario lists the exact log lines and the pass condition.

## Layout

```
bpf/warden.h         kernel↔userspace ABI (the 344-byte record)
bpf/warden.bpf.c     the observational CO-RE sensors, six fexit volume
                     counters (incl. the IPv6 datagram pair), six LSM
                     guarded-file programs and four OPTIONAL cgroup egress hooks
bpf/vmlinux.h        generated from this host's BTF
src/events.rs        ABI mirror + /proc enrichment
src/config.rs        warden.toml policy + cgroup/mTLS validation + schema version
src/config_engine.rs M16: one canonical engine for profiles, validation, plans,
                     migration, drift, rollback and read-only self-test
src/procscan.rs      resolve protect policy → concrete tgids
src/loader.rs        aya: load object, attach programs, own the maps
src/detect.rs        events → judged Findings
src/respond.rs       the opt-in kill responder
src/bridge.rs        the Sentinel uplink (cleartext or optional mTLS)
src/tls.rs           per-connection OpenSSL verification for direct mTLS
src/egress.rs        cgroup egress policy, A–E reload state machine, rollback
src/resources.rs     resource budget + honest --doctor reporting
src/heartbeat.rs     the off-box dead-man's-switch
src/arb.rs           test-only deterministic input generator for the parser property tests
src/main.rs          arg/config, signals, the ring-buffer event loop
scripts/install_wizard.sh  M16: guided, preview-first installer/uninstaller
scripts/tests/       M16: config-engine and installer CLI regressions
docs/security/       canonical, machine-checked coverage + Phase 7 contracts
                     + Mission 16 operator guide and final report
```

Those two `docs/security/` files are part of the standalone source tree because
`tests/network_coverage_matrix.rs` compiles them into the structural contract.
A release archive that omits them is incomplete even when other paths happen to
make the tests compile in a fuller checkout.

## License

GPL-2.0-only (the eBPF programs link against GPL-only kernel helpers).

## Reporting a security issue

See [SECURITY.md](SECURITY.md): where to file, what a report needs, and — just
as important — the documented capability boundaries that are design decisions
rather than vulnerabilities.
