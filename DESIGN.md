# Warden — Host-Level Runtime Security Guardian

> **Historical status note (original design session 2026-09-26; build
> 2026-09-27):** at that time the full suite was 195 unit + 8 integration tests
> and the sudo/root deployment was still pending. This header is retained for
> provenance only. The current authoritative test count, kernel evidence and
> release decisions are in `docs/release/PRQ_FINAL_EVIDENCE_INDEX.md`,
> `PRQ_07_TEST_AND_PERFORMANCE_REPORT.md`, `PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md`
> and `WARDEN_FINAL_RELEASE_DECISION.md`.

---

## خلاصه اجرایی (Persian executive summary)

**مسئله:** Sentinel به‌طور کامل در لایه‌ی اپلیکیشن کار می‌کند — login، برداشت،
دستگاه، درخواست API. هیچ دیدی نسبت به سیستم‌عامل ندارد: اجرای پروسه، syscall،
اتصال شبکه‌ی خام، دستکاری فایل، بارگذاری ماژول کرنل، یا تلاش برای کشتن خودِ
Sentinel. یک RCE، باج‌افزار، تروجان، backdoor، یا تهدید داخلی (insider) روی همان
سرور، خارج از میدان دید Sentinel رخ می‌دهد.

**راه‌حل — Warden:** یک نگهبانِ سطح-هاست، **کاملاً مجزا از Sentinel**، مبتنی بر
**eBPF**. در دامنه‌ی دسترسیِ جدا (root/CAP_BPF) اجرا می‌شود؛ اپ جنگو هرگز کد کرنل
بار نمی‌کند. رفتار را می‌بیند نه امضا را: بازنویسیِ انبوهِ پرآنتروپیِ فایل‌ها
(باج‌افزار)، پروسه‌ی وب که شل spawn می‌کند (RCE)، اتصال خروجیِ خارج از allowlist
(exfiltration)، سوکت گوش‌دهنده‌ی جدید (backdoor)، خواندن `.env`/`.pem` توسط
غیرِ-اپ (سرقت اعتبارنامه)، بارگذاری ماژول/BPF غیرمنتظره (rootkit)، و ptrace/signal
به Sentinel یا Warden (خودمحافظت).

**سه تصحیح صادقانه‌ی مهندسی:**
1. این آنتی‌ویروسِ امضا-محور **نیست**. تشخیصِ رفتاری + سیاستِ allowlist است — که
   دورزدنش سخت‌تر و ارزشش بالاتر است.
2. **CO-RE eBPF، نه ماژول کرنل.** ماژول out-of-tree (`.ko`) می‌تواند کرنل را
   panic کند و با هر ارتقای کرنل می‌شکند. eBPF توسط verifier تضمینِ پایان‌پذیری
   می‌گیرد و با BTF/CO-RE روی کرنل‌های مختلف portable است. امن‌تر و حرفه‌ای‌تر.
3. **مشاهده در برابر مسدودسازی.** بخش عمده‌ی ارزش، مشاهده‌ی high-signal است.
   مسدودسازیِ بدونِ-reboot را برای «خروجی شبکه» و «کشتن پروسه» می‌دهیم؛
   enforcementِ کاملِ inline (BPF-LSM) گزینه‌ای opt-in است که یک reboot می‌خواهد.
   هیچ چیزی روی همان هاست در برابر root محلی تضمینِ ۱۰۰٪ نمی‌دهد — بنابراین
   Warden **tamper-evident** است (آژیر + dead-man's-switch + ری‌استارت خودکار)،
   نه tamper-proof.

<!-- WARDEN-DESIGN-APPEND -->

---

## 1. Threat model — what Warden defends against

The wallet backend runs Django/Granian + Celery workers + Postgres + Redis on a
Linux host. Sentinel scores *application* actions. Warden owns everything below
the app boundary. Concrete adversary scenarios, each mapped to a sensor:

| # | Threat | Host-level signature Warden detects | Hook that ships | Status |
|---|--------|-------------------------------------|-----------------|--------|
| T1 | **RCE / reverse shell** (web proc popped) | a process inside the app cgroup `execve`s `sh -i`/`bash -i`/`nc`/`socat`/`python -c`/`perl -e`, matched on the exec's **identity** — the resolved `/proc/<pid>/exe`, the path the tracepoint saw, then comm — because comm is a 15-byte label the process sets itself; plus a renamed copy executed out of a world-writable staging directory (`exec_rules.untrusted_exe_prefixes`) | `tp/sched/sched_process_exec` | **Implemented** — the staging half reports Medium and never arms the responder. Residual: a copy renamed to a non-shell name and placed outside the listed prefixes (say `/usr/local/bin/svc-agent`) is still missed; the rule narrows the evasion, it does not close it |
| T2 | **Data exfiltration / C2** | egress connect from the app cgroup to an IP:port **outside** the allowlist (only Postgres, Redis, price-API egress, DNS are sanctioned) | `kprobe/security_socket_connect`, the dial's outcome from `kprobe`+`kretprobe/__inet_stream_connect`, and — since Phase 7 — four optional `cgroup/sock_addr` programs | **Detection Implemented; blocking Optional (Phase 7, off by default)** — the kprobe still only observes; the four cgroup hooks deny only when enabled, armed and matched (§4). The outcome pair sees only a *terminal* return: measured, 91% of live dials on the deployment host are non-blocking and emit no verdict record. `src/c2.rs` v2 adds local cadence detection over the kernel `ts_ns` of CONNECT records (median/MAD, 6+ dials, 900 s window, capped 0.72 confidence); it is **offline-validated only** in this pass, with no privileged live evidence |
| T3 | **Backdoor / implant** | a new listening socket bound by any proc that isn't the known server; a process whose backing executable was **unlinked from disk** but is still running (fileless); and — since the accept pair — **who actually connected to a listener**, with the accepting task, the peer endpoint, the local port and the socket's network namespace | `kprobe/security_socket_listen`, `kprobe`+`kretprobe/inet_accept`, `tp/sched/sched_process_exec` | Implemented — the listen half judges and finds; the accept half is **journal-only, by policy**: this host's job is accepting connections (≈3.9 accepts/s measured in a quiet window on the deployment host), so a finding per accept would bury the detector. Deciding "this peer is not one of this listener's sanctioned peers" is the platform's allowlist, not a host rule. It sees what the `/proc/net` pull path cannot: accepts inside container network namespaces (the kprobe is global; the pull path reads only Warden's own netns) |
| T4 | **Ransomware** | one process rewriting many files fast, rename-to-new-extension storms, or deleting shadow/backup dirs | `kprobe/security_inode_rename`, `kprobe/security_inode_unlink` (+ burst window) | **Partial** — rename/unlink storms ship; **"high Shannon entropy of written bytes" does Not: no entropy is computed, and `lsm/file_permission` carries no written bytes** (it sees I/O on guarded inodes only) |
| T5 | **Credential theft** | a **non-app** process (uid, cgroup, or exe path not on the allowlist) opening `.env`, `*.pem`, `*.key`, Postgres/Redis creds, Django `SECRET_KEY` | `lsm/file_open`, `lsm/mmap_file`, `lsm/file_permission` (guarded inodes only) | **Partial** — reads and writes are denied only for files the operator enumerates in `[[enforce.guarded_files]]` and only when armed; **no `.env`/`*.pem` pattern matching exists**. `lsm/file_permission` re-checks I/O through an fd opened before arming, so "already open" no longer keeps access (W-R2); a writable mapping created before arming is still not revoked |
| T6 | **Rootkit / kernel tamper** | `finit_module`/`init_module`/`bpf(BPF_PROG_LOAD)` from anything but the package manager or Warden itself | `tp/module/module_load`, `kprobe/security_bpf` | **Partial** — both ship; **`kallsyms` / `/dev/mem` opens are Not supported** (no hook) |
| T7 | **Insider / privilege abuse** | unexpected `setuid(0)`, `sudo`/`su` outside a maintenance window, `ptrace` across users | `kprobe/commit_creds`, `tp/sched/sched_process_exec`, `kprobe/security_ptrace_access_check` | **Partial** — `commit_creds` ships; `sudo`/`su` ride the exec shell-list; **`ptrace` fires only when the target is a protected pid**, so cross-user ptrace of an unprotected process is invisible |
| T8 | **Sentinel/Warden takedown** (the "خاموش‌بشه" case) | `SIGKILL/SIGTERM/SIGSTOP` or `ptrace` targeting the Sentinel (Granian/Celery) or Warden PIDs; Warden heartbeat gap | `kprobe/security_task_kill` + `kprobe/security_ptrace_access_check` + dead-man's-switch. The kill sensor records the `si_code` class — which call aimed it (`kill`/`tkill`/`sigqueue`/posix timer/…) — and treats a signal the victim aimed at its own pid as a Medium self-termination rather than a responder trigger (W2K-04). Since W2K-36/41 the tier follows the number's **kernel disposition** and the sender's **verified identity**, and the basis travels in the record (`detail.reason` + `detail.authorization`): terminate/freeze from an outside actor is Critical `unauthorized_signal`, a number the kernel would ignore (SIGCONT/SIGWINCH/SIGCHLD/SIGURG) is Info `inert_signal`, a send from pid 1 is Low `service_control` (the service manager stopping its own unit — the shape the parent exemption cannot cover), SIGHUP at Warden's own pid is Low `own_reload_path`, and a `/proc` READ is demoted to Info `verified_external_reader` only when the reader's executable *and* cgroup resolved and it is provably outside `[app] cgroup_contains`. No demotion is ever earned by a `comm`, and none of it moves the responder's arm list, which stays the same five numbers (W2K-42). Bounded honestly: the kernel does not call `security_task_kill` for signals it generates itself (`si_fromuser()` gates it on `si_code <= 0`), so a process killed by its own SIGSEGV or by the OOM killer produces **no** kill record — that case belongs to the heartbeat gap, not to this sensor |
| T9 | **Persistence** | a file **created** in `~/.bashrc`'s dir, `/etc/cron*`, systemd unit dirs, `/etc/ld.so.preload`, `authorized_keys` by a non-package process | `kprobe/security_inode_create` | **Partial** — creation ships; **overwriting an existing file there is Not supported**: the persistence watch list is not `guarded_files`, so `lsm/file_permission` does not cover it |

**Explicit non-goals (honesty):**
- Not a signature AV. No hash/YARA malware DB (bypassable, low-signal). Behaviour + allowlist only.
- Not tamper-*proof* against local root — that is physically impossible on the
  same host. Warden is tamper-*evident*: it screams and auto-restarts.
- Not an IDS for the network fabric — the NDR sensor already owns IP-to-IP flow
  analytics (subagent confirmed `sentinel/ndr/`). Warden owns **process↔socket
  attribution** the network layer can't see (which PID/exe/cgroup opened a flow).

---

## 2. Why separate, why eBPF, why not a kernel module

**Separate from Sentinel (your instinct, and it's correct):**
- **Privilege isolation.** Loading BPF needs `CAP_BPF`+`CAP_PERFMON` (effectively
  root). Probed this host: the dev shell is `uid=1000`, `CapEff=0000000000000000`;
  the Dockerfile runs non-root. The Django app must **never** gain the capability
  to load kernel code. Warden lives in its own privilege domain (a dedicated
  systemd unit / its own minimal container with `CAP_BPF` only).
  Corrected after measurement: attaching the tracepoints and kprobes is a separate
  gate from loading — `perf_event_open(2)` needs `CAP_SYS_ADMIN` unless
  `kernel.perf_event_paranoid <= 1`, so the minimal set for the shipped sensor mix
  is larger than "CAP_BPF only". See `warden --doctor`, which prints both facts.
- **Blast-radius isolation.** If Warden were a module inside Sentinel, an attacker
  who RCE'd and killed the web process would blind the guard in the same stroke —
  precisely the "turns itself off" failure. Separation means killing the app does
  not kill the watcher; and Warden watching the app's liveness is the tripwire.
- **Fault isolation.** A bug in kernel-attached code can stall every syscall on
  the box. That belongs in a small, audited Rust binary — not bolted onto a
  391-dependency Django app.

**eBPF over a kernel module (`.ko`):**
- The verifier **statically proves** the program terminates and can't wild-write
  kernel memory — a `.ko` has neither guarantee and can panic the box.
- **CO-RE + BTF** → one binary is portable across kernels. Probed: this host has
  `/sys/kernel/btf/vmlinux` (7 MB) and `CONFIG_DEBUG_INFO_BTF=y`. No per-kernel
  recompile, no DKMS fragility.
- Attach/detach is live — no reboot to load or update a probe.

**Language split (low-level + high-level, as you asked):**
- **eBPF programs: C**, compiled by **clang** (probed: clang 21.1.8) to BPF
  bytecode, using CO-RE relocations against the kernel BTF. This is the only
  thing that runs in kernel space.
- **Userspace agent: Rust** (probed: rustc 1.95, cargo), using the **`aya`**
  crate — a pure-Rust eBPF loader (no libbcc/LLVM runtime dependency, one Rust
  executable). It is embedded-object portable but **not fully static**: the
  optional Phase 8 mTLS transport links against the host's `libssl.so` /
  `libcrypto.so`. Rust because this is privileged, long-running, must never leak
  or crash: memory-safe, fearless-concurrency, and `aya` gives us loader +
  perf/ring-buffer consumer in one toolchain that we already use for the
  perf-phase Rust work. Fast (low-level) where it touches the kernel, safe
  (high-level) where it reasons about policy.

> **Build tooling — you mentioned Makefile + compile-and-install:** yes. A
> top-level `Makefile` drives `clang -target bpf -g -O2 … -c bpf/*.bpf.c`, then
> `cargo build --release`, then `make install` lays down the binary + a
> **systemd unit** (`warden.service`, `Restart=always`, `AmbientCapabilities=
> CAP_BPF CAP_PERFMON CAP_SYS_PTRACE`, hardening `ProtectSystem=strict`,
> `NoNewPrivileges=yes`). Not a kernel-module install — a hardened service that
> loads CO-RE eBPF at start. Optionally a distroless container with the same caps.

---

## 3. Architecture

```
  ┌─────────────────────── KERNEL SPACE ───────────────────────┐
  │  eBPF programs (C, CO-RE, verifier-checked)                 │
  │   exec         → tracepoint/sched_process_exec              │
  │   connect      → kprobe/security_socket_connect             │
  │   verdict      → kprobe+kretprobe __inet_stream_connect     │
  │   listen       → kprobe/security_socket_listen  (backdoor)  │
  │   accept       → kprobe+kretprobe inet_accept    (inbound)  │
  │   volume       → fexit sendmsg/recvmsg/cleanup_rbuf (map)   │
  │   file         → kprobe security_inode_rename + _unlink     │
  │   service      → kprobe/security_inode_create   (persist)   │
  │   module/bpf   → tracepoint finit_module + kprobe/security_bpf│
  │   mount        → kprobe/security_sb_mount    (cont. escape) │
  │   creds        → kprobe/commit_creds         (privesc)      │
  │   selfprotect  → kprobe/security_task_kill + ptrace         │
  │        │  emit structured events via BPF ring buffer         │
  │        │  (allowlist maps looked up IN-KERNEL for T2/T5)     │
  └────────┼────────────────────────────────────────────────────┘
           │ ring buffer (bounded, lossy-by-design, never blocks kernel)
  ┌────────▼──────────── USERSPACE (Rust, aya) ─────────────────┐
  │  loader → attaches programs, populates policy maps          │
  │  event consumer → decode, enrich (pid→exe→cgroup→container)  │
  │  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐  │
  │  │ Detectors    │→ │ Policy engine │→ │ Responder        │  │
  │  │ (behavioural)│  │ (allowlist +  │  │  local: kill /   │  │
  │  │  entropy,    │  │  anomaly,     │  │  connect-block;  │  │
  │  │  rate, graph)│  │  severity)    │  │  remote: bridge  │  │
  │  └──────────────┘  └───────────────┘  └────────┬─────────┘  │
  │  self-heartbeat (dead-man's-switch) ───────────┼─────────►  │
  └────────────────────────────────────────────────┼───────────┘
                                                     │ HTTP / mTLS + X-API-Key
                                    ┌────────────────▼───────────────┐
                                    │ Sentinel  POST /api/v1/sentinel │
                                    │   (host-finding ingest — §5)    │
                                    └─────────────────────────────────┘
```

**The diagram above is the design TARGET, not the shipped build.** Several of
its labels are unbuilt or optional, and reading them as always-on features is
the W-R1 finding:

| Diagram label | Shipped? |
|---|---|
| Responder "local: kill" | ✅ yes — userspace, `src/respond.rs`: `pidfd_send_signal` where the kernel has it, `kill(2)` otherwise, and the target's identity (pid + start time) is re-verified first (W-R3) |
| Responder "connect-block" | ⚠️ **optional since Phase 7** — four `cgroup/sock_addr` programs ship but are disabled by default; they require `[egress] enabled = true` on an isolated cgroup and `arm = true` plus an exact rule to deny (§4). Not part of the always-on shipped posture |
| Detector "entropy" | ❌ **no** — no entropy is computed anywhere; T4's entropy half is unbuilt |
| Detector "rate" / "graph" | ⚠️ partial — a per-actor burst *window* ships for rename/unlink; no cross-process graph |
| Transport "HTTPS X-API-Key" | ⚠️ **optional since Phase 8** — the default bridge is cleartext HTTP with `X-API-Key` and a trusted-path rule; direct mutual TLS is supported only when `tls_ca_file` + `tls_cert_file` + `tls_key_file` and an `https://` URL are all configured. Verification is mandatory and per connection, DNS names are matched as DNS SANs and sent as SNI, IP literals are matched as IP SANs with no SNI, and no downgrade exists. The cleartext gate (W2K-19/W2K-28) still classifies the address a cleartext request would use and refuses a public one; it does not apply to a verified mTLS transport |

Design rules the implementation must hold:
- **Kernel code stays minimal and dumb.** Filtering that can be a map lookup
  (is this dest IP allowlisted? is this uid the app?) happens in-kernel to cut
  event volume; all *judgement* is userspace. The verifier limits complexity
  anyway.
- **Ring buffer is bounded and lossy by contract.** Under flood the kernel drops
  events rather than blocking a syscall. That trade is only acceptable because a
  per-CPU counter charges every failed `bpf_ringbuf_reserve`, `src/loader.rs` sums
  it across CPUs, and `src/main.rs` reports the dropped/received delta on every
  refresh tick — at `warn` when non-zero, since a silent counter reads as "quiet
  host" and that is the failure the counter exists to prevent. A drop is a signal
  only if somebody is looking at it. Both counters are indexed by event kind
  (W2K-14): `ringbuf_drops` says how much was lost, `ringbuf_events` says how much
  each sensor actually handed to the ring, so the warning can name the noisiest
  sensor and a sensor that never fired is distinguishable from a quiet host.
- **Delivery is durable, and loss is counted too (W-05).** A finding Sentinel
  does not accept is not dropped: `src/deliver.rs` retries it with capped
  exponential backoff, buffers it to a bounded 0600 append-only spool
  (`/var/lib/warden/bridge_spool.jsonl`, one JSON envelope per line), and
  delivers the backlog oldest-first on the next start. Only two things are ever
  lost, and both are loud: a spool that has hit `spool_max_bytes`, and a finding
  that had been accepted but not yet persisted when the process was killed hard.
  The counters (`pending_on_disk`, `dropped`, `queue_depth`) are reported on the
  same refresh tick as the ring drops, for the same reason — the failure mode
  this exists to break is silence. The network also moved off the ring-drain
  path entirely (W-R6): the drain loop only ever does a non-blocking hand-off to
  the sender thread, so a slow resolver or a trickle response can no longer stall
  the consumer and turn a Sentinel problem into ring loss. The one exception is
  the spool overflow path: when the in-memory queue is full, the drain thread
  appends **and fsyncs** the record to disk, deliberately trading disk latency
  and ring headroom for durability during a long outage. `queue_max`, the ring
  size and the spool's disk are the levers for that burst.
- **A refused finding is dead-lettered, never dropped (§130 F-130-4).** When
  Sentinel answers `400` and names the offending array indices in `errors[]`,
  Warden pulls out only those entries, writes each one's exact envelope to a
  sibling `bridge_quarantine.jsonl` (mode `0600`, one JSON line per finding),
  and retries the surviving findings instead of discarding the whole batch. A
  refusal with no usable indices dead-letters the entire batch. The file is
  bounded (8 MiB) and never silently truncated. `warden --replay-quarantine`
  appends those envelopes back to the spool (preserving `event_id` so Sentinel's
  dedupe still recognises them) and archives the dead-letter file to
  `.replayed.<ts>`; it refuses to run while `warden.service` is active, because
  the sender holds an in-memory image of the spool that an external append would
  desync. A degradation of this path (loss, dead-letter, isolation) is itself
  shipped to Sentinel as `endpoint:self_degraded` so a failing sensor never
  looks like a healthy quiet host.
- **Everything degrades to observe-only.** If a policy map is missing or a
  responder can't act, Warden logs+alerts and never wedges the host.

### 3a. State vs. transition — why there is a pull path at all

Every kernel sensor above reports a **transition**: `security_socket_connect`
fires when a socket is dialed, `security_socket_listen` when one is bound, the
verdict pair when a dial returns. Nothing in that set can see what was already
true when Warden attached, because the transition happened before there was
anyone listening. Three concrete holes follow, and they are not hypothetical —
all three were observed on the dev host while building this:

| Hole | Why the push path cannot see it |
|---|---|
| A listener that predates Warden | `bind`/`listen` already returned; no future hook fires for it |
| A socket opened while the ring was full | `bpf_ringbuf_reserve` failed and the kernel dropped the event by design (§3, W2K-14) |
| A socket whose sensor is muted | the per-sensor emit gate is off, so the transition is real and unreported |

The pull path (`src/net_snap.rs`, `[network_snapshot]`, stage ۱۵) closes the
first two by reading the kernel's **state** — `/proc/net/{tcp,tcp6,udp,udp6}` —
and reconciling it against (a) the previous tick, which turns state into
transitions Warden *did* observe, and (b) the sensors' own account of this run,
which names a listener or a connection no `LISTEN`/`CONNECT` record reported.
Design constraints it is built to:

- **No new capability, nothing attached, nothing enforced.** It reads files any
  local user can read, so it cannot widen the attack surface, and it deliberately
  produces **no Finding** — the bridge's all-or-nothing batch contract is an
  open owner decision (§5, N-06), and a coverage statement does not get to make
  it. Journal only.
- **The same formatter on both sides.** A snapshot endpoint and a sensor endpoint
  are rendered by one function (`crate::events::dest_of`), because the
  cross-check is a string comparison; if either side re-renders the tuple
  independently, one of them is permanently wrong and the report becomes noise.
- **Every shortfall is a stated reason, never an absence.** Four tables are
  tracked individually (missing ≠ unreadable ≠ empty), the `/proc/<pid>/fd` walk
  separates "stopped at its pid budget" from "a pid whose fds this process may not
  open (not root, `hidepid=`, or gone mid-walk)" from "no owner exists", and unparsed rows keep their rejection reason, and unknown TCP
  states stay visible as `Other(state)` with a count. The failure mode this
  exists to prevent is a report that reads like a healthy quiet host.
- **It samples.** A socket that opens and closes between two ticks is in neither
  snapshot. That is said in the line itself, not only here.
- **Off by default, and `--socket-snapshot` proves it anywhere.** Because it
  needs no privilege, its live behaviour is checkable on a host without starting
  the agent, loading a kernel object, or touching the running service.

What it does **not** close: the other network namespaces of the host (container
sockets are not in `/proc/net` as Warden sees them), and any *root cause* — an
unexplained listener is a question, not a finding. The byte/packet gap it used to
name — "a flow still has no byte or packet counter" — is partly closed by §3b:
there is now a per-cgroup byte and operation counter, but it is per **cgroup**,
not per flow, and it counts payload at the send/recv boundary rather than packets.

### 3b. Cumulative volume per cgroup (N-05, stages ۱۶b and ۱۶f)

The ring buffer can carry a flow's *existence* but not its *size*: `WARDEN_FLOW`
records the moment of acceptance and never the close, and a byte counter would
emit one record per threshold crossed on every socket — the exact traffic that
overflowed the ring in stage ۱۶'s measurement. So volume does not go through the
ring at all. Six `fexit` programs keep totals in a map:

| fexit section            | kernel function it returns from          | direction it measures |
|--------------------------|------------------------------------------|-----------------------|
| `fexit/tcp_sendmsg`      | `tcp_sendmsg(struct sock *, msghdr *, size_t) → int` | egress: bytes the kernel accepted into the send queue (`ret`), and the call |
| `fexit/udp_sendmsg`      | `udp_sendmsg(struct sock *, msghdr *, size_t len) → int` | egress: the same pair for datagrams |
| `fexit/tcp_cleanup_rbuf` | `tcp_cleanup_rbuf(struct sock *, int copied) → void`   | ingress: bytes copied to userspace, and the completion |
| `fexit/udp_recvmsg`      | `udp_recvmsg(struct sock *, msghdr *, size_t, int flags, int *addr_len) → int` — the five-argument `struct proto::recvmsg` shape, **not** the four-argument `struct proto_ops::recvmsg` | ingress: the same pair for IPv4 datagrams (stage ۱۶f; **REALISTICALLY_TESTED** — loaded, attached and counted on the deployment kernel, §23 of `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md`) |
| `fexit/udpv6_sendmsg`    | `udpv6_sendmsg(struct sock *, msghdr *, size_t) → int`, the `struct proto::sendmsg` shape | IPv6 datagram egress — **LIVE_VALIDATED_M15** (socket-path accounting; see below) |
| `fexit/udpv6_recvmsg`    | `udpv6_recvmsg(struct sock *, msghdr *, size_t, int flags, int *addr_len) → int`, the same `struct proto::recvmsg` shape | IPv6 datagram ingress — **LIVE_VALIDATED_M15** (socket-path accounting; see below) |

Design decisions that are not visible in the code and should not be re-derived:

- **The key is a cgroup id, not a flow and not a pid.** `bpf_get_current_cgroup_id()`
  returns the kernfs node id, which is the cgroup directory's `st_ino`: monotone,
  never recycled. A flow key (the 4-tuple) and a pid key were both rejected because
  there is no close hook — no `fexit/tcp_close` in this set — so nothing would ever
  remove the entry, and a recycled port or pid would inherit a dead tenant's running
  total and report it as its own. That is the same identity failure W2K-10 and W-R3
  were about, reached from the other side. A stale *cgroup* entry cannot lie that
  way: ids do not come back, and `last_ns` on every row says when it last moved.
- **`ops` is counted alongside `bytes`, and that is the honest unit.** One
  `sendmsg` becomes 0..hundreds of segments depending on MSS, window and retransmit,
  so a hook at this layer cannot prove packets. The pair is what is defensible, and
  ops-high-with-bytes-flat is itself a signal (a ping-pong or a scan) that neither
  number shows alone. The roadmap word was "پکت"; the shipped thing is
  bytes-and-operations, deliberately.
- **Both sides of the denominator.** `net_volume_stats` is a `PERCPU_ARRAY` counting
  successful bumps and map-full refusals, because "no rows" otherwise means an idle
  host, a dead hook, or a full map — three different situations an operator would
  resolve differently. The same lesson came from W2K-14 on the telemetry path.
- **Each hook attaches independently and a missing one is named.** An observational
  feature must never be able to stop the agent (N-14), so a `Btf::from_sys_fs()`
  failure or one rejected program downgrades that direction and keeps the others.
  `coverage_line()` then writes the gap into the report instead of letting a
  one-sided total read as a volume.
- **Stage ۱۶f closed the direction §22 measured as missing, and this revision adds
  the family half that §23 exposed.** §22 step 4 was not a guess: 137 KiB reached a
  cgroup's userspace over UDP while its `bytes_in` stayed at `0`, because the only
  ingress hook was a TCP one. `fexit/udp_recvmsg` is the datagram half, with its
  argument list taken from this tree's `bpf/vmlinux.h` (`struct proto::recvmsg`, five
  arguments — the four-argument `struct proto_ops::recvmsg` is a different function and
  the ABI test pins both texts so nobody confuses them). `MSG_PEEK` is counted rather
  than filtered, because `tcp_cleanup_rbuf` has no flags argument to filter on and the
  two ingress hooks must mean the same thing. §23 then showed an IPv6 datagram reaches
  neither `udp_sendmsg` nor `udp_recvmsg` — it dispatches through
  `udpv6_sendmsg`/`udpv6_recvmsg` — so v6 datagram volume was absent in both
  directions. This build adds those two hooks and attempts all six at startup.
  M15 subsequently proved a verifier accept, six attachments and a landed `[::1]`
  bump on an isolated `6.12.107+deb13-amd64` host (`M15_09`/`M15_11`); status is
  **LIVE_VALIDATED_M15** for this object, not revalidated in the current pass.
  This is IPv6-**socket-path** accounting, not `skb->protocol` wire evidence.
  The stage ۱۶f claim itself
  remains `REALISTICALLY_TESTED` (§23 step 4: `out 102400B/100 ops, in 95232B/93 ops`
  against a test that printed exactly those numbers); the cost half is still
  `UNVERIFIED`.
- **It is OFF by default**, unlike the other sensor gates. Those are always-on and
  only *muted* per event; this one is a per-`sendmsg` map write, and on a busy host
  that is a cost the operator buys knowingly. `sensor_emitting()` fails open, so the
  slot is seeded explicitly at startup from `[net_volume].enabled`.
- **A byte at this hook is payload at the call boundary, and the gap to the wire
  runs both ways.** IP and TCP headers and retransmitted segments are added below
  `tcp_sendmsg`, so they are **outside** the totals; a userspace TLS library's own
  record framing is handed *to* `sendmsg`, so it is **inside** them. That means
  `wire > these totals` for a plain flow and `these totals > plaintext` for a TLS
  flow — both correct, neither a bug, and the reason a volume line must never be
  reconciled against an interface counter. An earlier draft of the caveat claimed
  TLS overhead was excluded; the live run in `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §۲۲ is
  what falsified it. Kernel TLS (kTLS) is not characterised: this host does not
  enable it and nothing here measured which path its records take.
- **The read side is a bounded, self-caveating tick.** A `--net-volume` one-shot
  flag was rejected: the map only accumulates while the agent holds it attached, so
  a CLI run would report zeroes for a host that was busy an hour ago. Instead the
  event loop samples at `effective_interval_secs(requested)` — the request rounded
  up to the 10 s protect-refresh period that actually carries the tick — names the
  top `max_rows_per_tick` by combined movement above `report_min_bytes`, resolves
  ids to paths by walking `cgroup_root` within `cgroup_walk_max`, and prints how
  many cgroups moved *at all* versus how many it printed.
- **The cadence the report states is the cadence the agent can run.** `interval_secs
  = 5` was live-measured at ticks 10.0 s apart (18:12:11.678 → 21.695 → 31.728),
  because the volume tick is carried by the same loop that re-walks `/proc` for the
  protected set. Printing the requested number would have described a cadence that
  does not exist, so `cadence_phrase()` names both values, and a `const` assertion
  in `src/main.rs` pins `NET_VOLUME_TICK_GRANULARITY_SECS` against `PROTECT_REFRESH`
  so a future change to the loop period breaks the build instead of staling the
  claim. `network_snapshot` shares the floor and predates the finding; it is
  recorded in `src/config.rs`, not silently re-tuned.

---

## 4. Response — local enforcement vs. remote escalation

Two independent response paths; each sensor's finding declares which it wants.

Every bullet below carries the status of the **shipped build**, not of the host's
theoretical capability. `DESIGN.md` §6 is a *host* probe (what the kernel would
permit); this section is what `bpf/warden.bpf.c` and `src/` actually do. The two
were conflated in earlier drafts, and the difference is the whole point of W-R1.

**Local, in-Warden (immediate, no round-trip):**
- **Egress block — Phase 7 OPTIONAL, shadow by default, DISABLED unless
  explicitly configured.** The embedded object now contains four
  `SEC("cgroup/sock_addr")` programs: `cgroup/connect4`, `cgroup/connect6`,
  `cgroup/sendmsg4` and `cgroup/sendmsg6`. Their mere presence is *not* an
  enforcement claim, which is exactly the mistake W-R1 existed to prevent:
  1. `src/loader.rs` attaches them **only** when `[egress] enabled = true` names
     an absolute, non-root cgroup path (a test/tenant cgroup, never the host
     root). With no config, no hook is loaded and `policy::Preflight` reports
     the shipped observe-only posture.
  2. `CFG_EGRESS_ARM` is 0 in every default map. Attaching with `arm = false`
     counts would-denies in `egress_stats` but returns 0 (allow) to the kernel.
     Denial requires `arm = true`, which is rejected by `Config::validate`
     unless `enabled = true` as well.
  3. A matching exact `(family, protocol, address, port)` DENY rule must be in
     `egress_policy`. There is no hostname, CIDR or process-name wildcard;
     `port = 0` is the only wildcard and is consulted after exact-port misses.
  Only the conjunction of all three (plus a `Preflight` built from verified
  kernel facts) may produce a `traffic_blocked: true` finding. The old
  `kprobe/security_socket_connect` remains an observer and the old
  `[network_rules].deny_destinations` list remains an observe-only decision;
  neither gained kill intent or a traffic claim. See
  `docs/security/warden_phase7_egress_enforcement.md` for the contract and
  `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` and `docs/security/warden_coverage_matrix.md` for the privileged-evidence boundary.
- **Process kill — IMPLEMENTED (userspace); the in-kernel path is PLANNED.**
  A confirmed T1/T3 (reverse shell, fileless exec) can be killed via userspace
  signalling in `src/respond.rs`, gated on `mode = "enforce"` and an opt-in
  `[respond]` flag per rule. Default is **alert-only**. `bpf_send_signal` is
  **not called anywhere** — `src/config.rs` says so at the flag's definition.
  The signal goes through a `pidfd` where the kernel provides one
  (`pidfd_open`/`pidfd_send_signal`, Linux ≥ 5.3), which binds the handle to the
  *process* rather than the number; `kill(2)` is the fallback. W-R3's pid-reuse
  race is closed by recording the target's start time at enrichment and
  re-verifying it against the pidfd immediately before signalling — a pid that
  now names a different process is **refused** (`action=identity-changed`) rather
  than signalled, so the response prefers a missed kill to a wrong one. A target
  whose identity **cannot be read** is `action=unverifiable`, and that answer is
  corroborated by the handle rather than by `/proc`: a `hidepid=2` mount makes
  another user's live `/proc/<pid>` answer `ENOENT`, exactly what an exit answers,
  so signal 0 on the pidfd (`ESRCH` = gone, `EPERM` = alive and not ours) is what
  decides whether enforcement says "it exited" or "I could not name it, and I did
  not kill it" (W2K-37, W2K-39). The remaining case — `/proc` readable **now** but
  unreadable **at event time**, so no start time was ever recorded — is
  `action=unproven`: the kill is withheld under spec 4.2 item 7 ("no unproven
  signal") and `respond.require_anchored_identity = false` is the only way back to
  signalling an unnameable target (W2K-25).
  The residual window (a recycle in the instant between the kernel event and
  enrichment) needs the pidfd to be captured kernel-side to close fully; that
  belongs with the `bpf_send_signal` work, not here.
- **Protected-set selection — IMPLEMENTED (userspace); the kernel tripwire stays
  pid-keyed.** `[protect]` membership decides two different things: which pids
  the kernel tripwire reports a signal/ptrace against, and which pids the
  responder refuses to kill. Both used to be selected by exact `comm` — a
  15-byte name any process sets with `prctl(PR_SET_NAME)` — so a spoofed name
  bought both a false takedown finding and kill immunity (F09). The tripwire is
  preserved for `comms` and comm-only targets, but F09 excludes them from the
  userspace immunity set: only `protect_self`, `cgroup_contains` (pre-existing
  behavior) and `[[protect.targets]]` entries that name `exe`, the **real** uid
  or the exact cgroup path can produce `Action::Refused`. A target that matches
  no live process is reported at load, because silence there would read as
  protection that does not exist.
  Kill-immunity is bound to the `(pid, starttime)` identity
  (`src/procscan.rs`), so a recycled pid does not inherit it. The same binding now
  guards the *reporting* path too (W2K-10): `judge_signal`/`judge_ptrace` compare
  the target's live start time against the `Protected` entry the kernel map was
  written from, and drop the finding only when that comparison *proves* the number
  changed hands and the new occupant does not match the protect policy itself. A
  target whose start time cannot be read — gone, or `hidepid=` — is never silenced,
  because a killed victim disappearing from `/proc` is the sound of the attack
  succeeding. The residual is kernel-side and stated rather than hidden:
  `protected_pids` is a `__u32 → __u8` hash and `pid_is_protected()` tests key
  presence only, so for up to one `PROTECT_REFRESH` (10 s) the record is still
  *emitted* for a recycled pid and discarded in userspace with a `debug` line.
  Closing the emission itself needs an identity-valued map key and a relink of the
  shipped object; the alarm it used to raise was a false one, never a wrong kill.
  The hand-written `Default for Protect` also fixes a silent one: an omitted
  `[protect]` table used to derive `protect_self = false`.
- **A signal finding says who aimed it, and at whom (W2K-04).** The kill hook reads
  `si_code` through CO-RE — the only place that siginfo still exists — and ships a
  4-bit class in `aux2`: `kill`, `tkill`, `sigqueue`, and then `timer_claimed`,
  `mqueue_claimed`, `sigio_claimed`, `aio_or_usb`. The last four are named for what
  they prove: -2/-3/-5 are not reserved to the kernel, and the mechanisms that would
  set them (posix-timer expiry via `posixtimer_send_sigqueue()`, fasync via
  `send_sigio_to_task()` → `do_send_sig_info()`) queue past
  `check_kill_permission()` and so never reach this hook — a record naming one of
  them was written by a *sender* that chose that number, which makes it a lead, not a
  mechanism. `judge_signal` uses the class as evidence only. The judgement turns on
  `actor_pid == target_pid`, for the classes whose kernel path runs in the sender's
  own context: a protected process that aimed a lethal signal at *itself*
  (`abort()` and a Rust panic both `tgkill` their own thread group) is a Medium
  self-termination carrying `reason: "self_termination"` and no kill request — the
  victim is already going, and a kill aimed at a number about to be recycled hits
  whatever lives there next. It is still never silenced. The one class excluded from
  that pass is `aio_or_usb`: `kill_pid_usb_asyncio()` calls the hook from the
  completion path, where `current` is whatever task that CPU was running, so there
  `actor == target` proves nothing about who aimed the signal and the record keeps the
  attack tier. Kernel-**generated** signals
  are a bound rather than a gap we closed: `check_kill_permission()` calls the LSM hook
  only when `si_fromuser(info)` holds, i.e. `si_code <= 0`, so a SIGSEGV the process
  took itself or the OOM killer's `SIGKILL` produce no kill record at all — that death
  belongs to the heartbeat / dead-man's-switch path. An `si_code` that cannot be read
  decodes to `kill`, the attack class: Warden does not trade a false negative for a
  quieter log.
- **Guarded-file denial — PARTIAL, opt-in, needs one reboot to arm.** Six LSM
  programs ship (`lsm/file_open`, `lsm/file_permission`, `lsm/mmap_file`,
  `lsm/inode_unlink`, `lsm/inode_rename`, `lsm/inode_setattr` in
  `bpf/warden.bpf.c`). They deny only files the operator has explicitly guarded,
  only for the `deny` intents named per file, and only after `[enforce] arm =
  true`. Until then they run in **shadow** mode: they emit
  `endpoint:access_denied` for what they *would* have refused and let the
  operation through. Arming is impossible without `bpf` in the boot `lsm=` list
  (see §6), so the enforcement upgrade costs one reboot. `lsm/file_permission`
  is the per-I/O check: it re-evaluates read/write (including `O_APPEND`) on an
  fd that was opened before arming, closing the "pre-existing descriptor keeps
  working" half of W-R2. A writable **mapping** created before arming is still
  not revoked — page faults do not pass through an LSM hook.
  Not shipped: `bprm_check` (exec denial) — the six above are the whole set.

**Remote — the Sentinel bridge (§5).** When a bridge is configured, findings can
be shipped to Sentinel so host events can land in the same case/notification/SOAR
fabric as app events, giving one correlated timeline (e.g. `login_success` from a VPN → 30s later
`endpoint:process_creation` of a shell → `ndr`-style egress = one incident).

---

## 5. The Sentinel bridge — exact seam

The map came back precise. Sentinel is **entirely app-layer + externally-fed NDR
network telemetry**, with **zero** host/kernel visibility — and it has already
**reserved the exact slots** for a host sensor:
- `EntityKind.PROCESS / SERVICE / ASSET` exist with the comment *"no sensor ships
  it yet — the kinds exist so the graph and the mapping table are ready when one
  does"* (`sentinel/models.py:731-733`).
- Kill-chain stages reserve `endpoint:process_creation`, `endpoint:new_service`,
  `endpoint:privilege_change` — *"no sensor ships yet"* (`sentinel/correlation/stages.py:75-78`).

**Warden is that sensor.** Two candidate seams, and a recommendation:

**Seam A — in-process (rejected for Warden).** `sentinel.ingest.record_event(...)`
(`sentinel/ingest.py:248`) is *"the only way an observation enters the security
layer,"* never raises, and accepts a custom ≤32-char `event_type` (the enum is
not DB-enforced). But calling it means running **inside** the Django process —
which violates the privilege/blast-radius isolation that is Warden's whole point.
**Rejected** for the guard; it would only make sense for an in-app shim.

**Seam B — authenticated HTTP (chosen).** Warden is a separate OS process, so it
must speak over the network like any external sensor. Today the only authenticated
external ingest is `POST /api/v1/sentinel/ndr/` (`X-API-Key`, tenant-scoped) —
but that schema is IP-to-IP flow/DNS records and would **lose process/syscall
semantics** (which PID, which exe, which cgroup). And `/api/v1/sentinel/assess/`
restricts `event_type` to a customer allowlist `SUBMITTABLE_EVENT_TYPES`
(`sentinel/api.py:67-75`) that host types are **not** in.

→ **The clean design is a new authenticated ingest view mirroring
`SentinelNdrIngestAPI`**, accepting the reserved `endpoint:*` event shape:

```
POST /api/v1/sentinel/host/          (NEW — SentinelHostIngestAPI)
  auth:   X-API-Key  (ClientAPIKey.ServiceType.SENTINEL, tenant-scoped)
          or a verified first-party agent certificate over mutual TLS (Phase 8)
  body:   one envelope object, OR {"findings": [ … ]} with at most 64
          {"event_id":   "<stable id, unique per finding>",   # idempotency key
             "source":    "warden",
             "host":       "<hostname/asset id>",
             "event_type": "endpoint:process_creation" | "endpoint:self_tamper"
                          | "endpoint:network_connect" | "endpoint:listen"
                          | "endpoint:privilege_change" | "endpoint:module_load"
                          | "endpoint:bpf_load" | "endpoint:mount"
                          | "endpoint:new_service" | "endpoint:file_tamper"
                          | "endpoint:access_denied"    # guarded-file attempt denied in-kernel, or shadow-mode "would have denied"
                           | "endpoint:self_degraded",   # Warden's own uplink degraded — first-party operational signal, NOT an attacker step
                             # 12 types (src/detect.rs); there is no endpoint:egress_block.
                             # self_degraded carries wants_kill=false and is deliberately absent from stages.MAPPING.
             "severity":   "info|low|medium|high|critical",
             "summary":    "<one line, human-readable>",
             "process":    {"pid":…, "ppid":…, "uid":…, "comm":…, "exe":…,
                            "cmdline":…, "cgroup":…, "starttime":…},
                            # `starttime` = /proc/<pid>/stat field 22, clock ticks
                            # since boot. Present when /proc was readable. It is
                            # what the kill responder re-checks before signalling
                            # (W-R3); omitting it is not an error, it means the
                            # identity could not be pinned.
             "target_pid": <pid or null>,
             "action":     "observed" | "killed" | "refused"
                          | "identity-changed" | "failed" | "unverifiable"
                          | "unproven",   # `Action::as_str` (src/respond.rs:62-72),
                            # the SAME string the journal line prints: one verdict,
                            # one vocabulary, so the two surfaces cannot drift.
                            # Absent only from a build older than W2K-27.
             "enforcement_requested": <true|false>,
                            # `Finding.wants_kill`, shipped under another name.
                            # It is what makes the word above readable:
                            # requested+observed = the class is lethal and the mode
                            # was observe; not requested = the finding was
                            # report-only and no mode change would kill anything.
                            # That is why the daemon's mode need not travel.
             "observed_at_unix_ms":       <agent wall clock at envelope build>,
             "event_time_unix_ms":        <kernel event time when available,
                                            else observed_at_unix_ms>,
             "event_time_source":         "kernel_monotonic" | "agent_observed_at",
             "kernel_event_ts_ns":        <raw CLOCK_MONOTONIC from the ring, or null>,
             "kernel_event_unix_ms":      <that stamp converted with boot time, or null>,
             "kernel_event_clock":        "CLOCK_MONOTONIC",
             "event_time_clock":          "realtime_unix_ms",
                            # F-009: two clocks, both shipped with their lineage.
                            # `sentinel/api.py` stores them and refuses a whole
                            # batch whose labels contradict the raw stamp or the
                            # boot-time conversion; envelopes from older agents
                            # without these keys are still accepted.
             "detail":     { … sensor-specific, e.g. dest_ip/port,
                            files_touched, target_pid … }   # no `entropy`: no sensor computes it
          }
  effect: validate (the event_type/severity vocabularies are closed sets and a
          wrong value is refused; an unknown *body key* is not refused, it is
          dropped — the far side builds its stored dict from the fields it knows,
          so a key that is not added to `sentinel/api.py::_validate_finding` never
          reaches the store. This is why a new envelope key and a backend change
          ship in one stage) → for each,
          record_event(event_type=…, request=None,
                       metadata={"source":"warden", "host":…, "process":…, …})
          → optionally decisions.assess(event) for high/critical so the
            existing response.executor.consider(...) / SOAR runner.process(...)
            fabric can open a case, notify, or demand step-up.
  retry:  a repeated event_id is NOT a second row. Warden retries a finding it
          could not confirm, and the redelivery is byte-identical, so the far
          side has to be the one that recognises it — otherwise a timeout on a
          request Sentinel actually stored would duplicate the event.
```

**Single vs. batch.** Warden batches. `src/deliver.rs:731` starts the window at
`BATCH_MAX` (64) and coalesces whatever is already queued (`deliver.rs:750`),
because under a storm one request per finding cannot drain the spool faster than it
fills; the endpoint's own latency then shrinks the window and a run of successes
grows it back.

This paragraph used to claim the opposite — "Warden deliberately sends one envelope
per request" — and it was the reason the coupling below was believed to be
impossible. It is not (finding N-06 in §39 of the evaluation report):
`SentinelIngestAPI` validates the batch as a unit and answers **400 for the whole
request** if any single finding is malformed. Historically Warden classified any
4xx other than 408/425/429 as `Permanent` and discarded the whole batch — one
unaccepted finding silently destroyed up to 63 good ones. **Fixed in §130
(F-130-4):** a `400` that names `errors[].index` is now `Outcome::Isolated` — Warden
dead-letters exactly the named envelopes to `bridge_quarantine.jsonl` (0600) and
retries the survivors, so a refusal without usable indices is the only case that
dead-letters the whole batch. Nothing permanent is silent any more: every refused
envelope is on disk and replayable with `warden --replay-quarantine`.

The far side's allowlist is still a coupled seam — this is exactly why
`endpoint:access_denied` was added to `SUBMITTABLE_HOST_EVENT_TYPES` in the same
change that taught Warden to emit it. The difference is that a future mismatch can
no longer destroy good findings: the worst case is a dead-letter file an operator
sees, fixes, and replays, plus an `endpoint:self_degraded` finding saying the
uplink is unhappy.

**A timeout is not a failure (W-05).** The case this whole design exists for is
the one where Sentinel stored the row and its response never arrived. From
Warden's side that is indistinguishable from "nothing happened", so it retries —
and the `event_id` is what stops the retry from becoming a duplicate. Warden
generates the id once, at enqueue, and carries it through every attempt
unchanged; a spooled record on disk is byte-identical to the one it replaces.

**The verdict ships with the finding (W2K-27).** `Responder::act` answers one of
seven words, and for every build before this stage that answer went to the journal
and nowhere else, while `respond.rs`'s own header promised it was "shipped in the
finding's action trail". The promise was the design; the wire never carried it. So
on the platform side a SIGKILL that landed, a kill withheld because the event could
not name its target (`unproven`), a kill refused because the pid is protected, and
an observe-mode no-op were one indistinguishable row — which is precisely the
question a cross-host investigation asks at the worst moment: did the box fight
back, or did it only watch?

The fix is one argument. `Deliverer::enqueue(finding, action)` takes the verdict
rather than reading it off `Finding`, because the verdict only exists after `act`
and a field a caller can forget to set is a field that will be forgotten; with the
argument required, a call site cannot deliver a record with no outcome attached, so
the guarantee is the compiler's and not a test's. The word is `Action::as_str()` —
the same mapping the log line prints, so the journal and the store cannot disagree
about what happened. `enforcement_requested` rides along because `observed` alone
does not say whether enforcement was ever possible.

The far side stores both inside `SecurityEvent.metadata`, which is inside the
sealed digest, so the verdict a box reported is tamper-evident afterwards the same
way the finding is. The backend accepts any string there rather than checking it
against its own copy of the vocabulary, and that is the one place in this contract
where tolerance is the safe direction: a closed set would have answered 400 to
`unproven` the day stage 8 shipped it, and a 400 is `Permanent` here — batch and
all, discarded.

Why a new view rather than reusing NDR: host findings are **process events, not
flows** — forcing them into the flow schema throws away the attribution that
makes them valuable, and the reserved `endpoint:*` taxonomy already exists to
receive them properly. This is ~1 view + 1 validator + 1 URL, mirroring an
existing, tested pattern (`SentinelNdrIngestAPI` at `sentinel/api.py:363`).

**Origin labelling:** SecurityEvent has no `source` column; the app-vs-external
boundary is `tenant` (NULL = first-party). Warden's events are first-party
(tenant NULL), distinguished by convention via `metadata["source"] = "warden"`
— exactly how the map says a host producer should tag itself.

**Response reuse:** because findings flow through `record_event`→`assess`, a
critical host finding reaches users through Sentinel's existing seams —
`response/executor.py:60 consider(...)`, SOAR `runner.py:68 process(...)`
(`_step_open_case`/`_step_notify`). No new response mechanism needed on the
Sentinel side; note there is still no account-freeze/session-kill enactor there
(tier-3 is structurally absent), so containment of the *host* stays Warden-local
(kill, guarded-file deny), while Sentinel handles case + notification + app-side
step-up/hold. The optional cgroup2 egress gate is Warden-local and exact-rule
based (§4); it is not handed to Sentinel, is disabled by default, and is not a
full-host firewall. Traffic outside that cgroup still needs a firewall rule.

---

## 6. What the environment supports (probed, not assumed)

**Read this table as a probe of the HOST, not a feature list.** Every ✅ below
means *this kernel permits it*; it does **not** mean Warden ships it. Two rows in
earlier drafts read as though a host capability were a shipped responder, and
that misreading is exactly what the W-R1 audit finding is about. What ships is in
README.md's capability matrix; §4 restates the response paths with their status.

| Capability | This host | Consequence |
|---|---|---|
| BTF / CO-RE | ✅ `/sys/kernel/btf/vmlinux`, `CONFIG_DEBUG_INFO_BTF=y` | portable eBPF, no per-kernel build — **used** |
| `CONFIG_BPF_SYSCALL` | ✅ `=y` | can load programs — **used** |
| clang / rustc / cargo / bpftool | ✅ clang 21, rustc 1.95, cargo 1.95, bpftool 7.7 | full Rust+aya toolchain present now |
| cgroup v2 | ✅ `cgroup2fs` | the kernel accepts the four Phase 7 `cgroup/sock_addr` programs; they ship but are **disabled by default**, attach only to a named isolated cgroup, and deny only when armed (§4) |
| `bpf_send_signal` | ✅ (kernel 7.0) | a probe *could* kill in-kernel — **Warden does not call it**; the kill is userspace `kill(2)` (§4) |
| `CONFIG_BPF_LSM` | ✅ `=y` compiled; `bpf` active in the boot `lsm=` list on `7.0.0-15` (capability read only) | 6 `lsm/*` guarded-file programs ship. BPF-LSM readiness was observed, but live attach and in-kernel `-EPERM` denial are **NOT verified** on `7.0.0-15`; the runtime test is `#[ignore]`d and requires root/`CAP_BPF` in a disposable VM. A deployment host needs `lsm=…,bpf` + reboot before deny (not shadow) can work |
| kernel | `7.0.0-15-generic` (very recent) | ring buffer, LSM progs, CO-RE all available — **used** |
| privilege | dev shell `uid=1000 CapEff=0` | Warden needs its own root/CAP_BPF unit; app stays unprivileged |
| container | bare host (not docker) | systemd unit is the natural deploy; container path documented as alt |

**Critical assets Warden can guard (example pattern, not a deployment inventory):**
operators enumerate explicit guarded files under `[[enforce.guarded_files]]` —
for example an application `.env`, a TLS private key, or a configuration file
holding a Django `SECRET_KEY` / DB / Redis credentials. Warden resolves each
listed path to a `(device, inode)` and denies the configured intents to
unauthorised actors only when enforcement is armed. There is no automatic
detection of `.env`, `*.pem`, or `*.key` files: matching is explicit, by the
paths the operator lists. The example configuration shows safe placeholders;
no private deployment paths or filenames are reproduced here.

### 6a. Diagnostics and the observe-only gate (§130)

Three read-only surfaces were added or tightened in §130; none of them loads a
kernel object, takes a privilege, or touches the running service.

- **`warden --check --strict`** (C-130-6 / F-130-6). `--check` already named every
  config key this binary does not read (the W2K-23 drift that can leave an
  operator believing `spool_path` moved when it did not). `--strict` promotes that
  same audit to a hard, non-zero exit for CI and the deploy gate. Normal startup
  stays deliberately non-fatal — a sensor that refuses to boot over a typo is a
  blind host — and the error names only key **names**, never values, so an
  `api_key` orphaned into the wrong table cannot leak through the error path.
- **`warden --health --json`** (C-130-1). The machine-readable form of `--health`,
  schema `warden.health.v1`: an ordered `claims` array of
  `{claim, status, detail}` and a `by_status` tally. It is parsed from the **same
  rendered lines** the text view prints, so the two surfaces cannot disagree about
  what was seen. The `cannot see/…` lines keep their `UNVERIFIED` status in JSON
  too — dropping them would make the machine view look healthier than the text.
  A config parse error that quotes an `api_key` line is redacted. `--json` is a
  modifier of `--health` alone and is refused beside any other mode.
- **The observe-only invariant gate** (`deploy/steps/70_verify.sh`, §130 F-130-1).
  The verify step now parses the live config and refuses a posture change:
  `mode="observe"`, `arm=false`, and all four `kill_*` flags false are hard
  requirements, as is `bridge.timeout_ms >= 15000` (the value the fixed
  `wire-bridge.sh` writes). An explicit `WARDEN_ALLOW_ENFORCE=1` is the only
  documented opt-out — it is for a future, separately-approved posture change and
  is **not** set live. A matcher that cannot read the config fails closed rather
  than passing by silence.

Note on reload: `[bridge]` and `[heartbeat]` are read once at startup, so changes
to them need a **restart**, not a SIGHUP (SIGHUP only reloads the enforcement
policy). The startup and shutdown path already drains the sender and fsyncs the
spool before exit, so a restart is safe; the earlier docs claiming SIGHUP applied
these tables were wrong and are corrected (F-130-5).

---

## 7. Layout & build (as built)

The original proposal here was "one `.bpf.c` per sensor" in a `bpf/` of six files
plus a `src/detect/` module tree and a `policy.rs`. **That is not what shipped**,
and the tree below is the real one — a single C object and flat Rust modules.
Kept as the proposal it was for the record; a reader should not go looking for
`fsmon.bpf.c` or `policy.rs`.

```
Project/Warden/
  Makefile                     # clang bpf → cargo build → install unit
  bpf/
    warden.bpf.c               # the ONE object: 14 observational programs (13 sensor
                               #   sites — the connect verdict is a kprobe+kretprobe pair)
                               #   + 6 LSM guarded-file programs
    warden.h                   # kernel↔userspace ABI (the 344-byte record)
    vmlinux.h                  # bpftool-generated from this host's BTF
    warden.bpf.o               # built from warden.bpf.c, embedded at compile time
  src/                         # Rust (aya) userspace agent, flat modules
    main.rs                    # arg/config, signals, the ring-buffer event loop
    loader.rs                  # aya: load object, attach programs, own the maps
    events.rs                  # ABI mirror + /proc enrichment (pid→exe/cgroup)
    config.rs                  # warden.toml policy
    net_snap.rs                # the pull path: /proc/net reconcile + attribution (§3a)
    procscan.rs                # resolve protect policy → pids + (pid, starttime)
    detect.rs                  # events → judged Findings (all allowlists/anomaly)
    arb.rs                     # fixed-seed property-test corpora (`#[cfg(test)]` only)
    guard.rs                   # guarded-file paths → (device, inode) pins
    respond.rs                 # the opt-in kill responder
    deliver.rs                 # durable finding spool + retry + 0600 dead-letter/quarantine + replay + self-degraded finding
    hmac.rs                    # HMAC-SHA256 for the heartbeat
    bridge.rs                  # the Sentinel uplink (cleartext HTTP or optional mTLS)
    tls.rs                     # per-connection OpenSSL verification for mTLS
    egress.rs                  # exact deny rules + A–E reload state machine
    resources.rs               # resource budget + honest --doctor reporting
    heartbeat.rs               # dead-man's-switch emitter
  config/warden.toml           # allowlists, protected paths, [enforce]/[egress] guards, mode
  systemd/warden.service       # Restart=always, CAP_BPF/PERFMON/PTRACE, hardened
  tests/                       # ringbuf_drop_counter.rs, capability_matrix.rs,
                               # network_coverage_matrix.rs (reads vendored docs)
  docs/security/               # canonical machine-checked coverage + Phase 7 contract
  README.md  DESIGN.md  SECURITY.md
```

There is no separate `detect/` directory, no `policy.rs` (policy lives in
`config.rs` + `detect.rs`), and no per-sensor `.bpf.c` files: everything the
kernel runs is in the one `warden.bpf.c`.

**Sentinel side (small, mirrors existing pattern):** new
`SentinelHostIngestAPI` + validator + `endpoint:*` additions to the submittable
set, in `sentinel/api.py` / `sentinel/urls.py` / a `sentinel/host/` validator,
with tests — applied to **both** `panel.settings` and `settings_exercise`
(separate DBs). No SecurityEvent schema change is required (custom `event_type`
persists; `metadata` carries the process detail), so **likely no migration** —
to be confirmed when built.

---

## 8. Honest risks & limits

- **Local root can still win eventually.** A determined root can `bpftool prog
  detach` Warden's programs. Mitigations are evidence, not prevention:
  `selfprotect` fires on ptrace/kill of Warden, the dead-man's-switch alarms on
  heartbeat gap to an off-box collector, and (with the LSM reboot) we can deny
  `bpf()`/`bpftool` to non-Warden uids. Tamper-*evident*, not tamper-proof — I
  will not claim otherwise.
- **Inline file deny needs a reboot** (LSM boot flag). The kill responder does
  not — it is userspace `kill(2)`. Egress deny needs no reboot but is opt-in,
  cgroup-scoped and exact-rule based (§4); it is not a full-host firewall rule.
- **False positives** on exec/egress will happen; that's why default is
  observe-mode with an allowlist-learning period before any rule is set to
  enforce. Ransomware/exfil rules are the safest to auto-enforce; exec-kill is
  the riskiest (self-DoS) and stays opt-in.
- **`comm` is not an identity.** Any process can rename it with
  `prctl(PR_SET_NAME)`, it is capped at 15 bytes, and after an `execve` the
  kernel simply fills it with the invoked file's name — measured on this host,
  `cp /bin/bash /tmp/w2k15-probe` reports `comm=w2k15-probe`, and
  `ln -s /bin/dash deploy-task` reports `comm=deploy-task` while the readlink
  resolves to `/usr/bin/dash`. The exec rule therefore matches the resolved
  `/proc/<pid>/exe` first, then the path the tracepoint reported, then comm, and
  a renamed copy is caught by *where it came from*
  (`exec_rules.untrusted_exe_prefixes`) when no name says shell. What that still
  cannot see: a copy renamed to an innocent name and placed outside the listed
  prefixes. The staging rule reports Medium and never arms the responder, because
  "a binary came out of `/tmp`" is unexplained, not proven.
  The same lesson had to be applied to the rules that *suppress*, which is where a
  forged name pays best (W2K-30, W2K-29). Three of them took a comm as the whole
  answer: `cred_rules.expected_privilege_comms` discarded a privilege raise
  outright, `ptrace_rules.benign_reader_comms` discarded a `/proc` read of a
  protected pid, and `bpf_rules.allow_loaders` discarded an implant-capable eBPF
  load when the loader's executable could not be read. Renaming a payload to
  `sudo`, `systemd` or `warden` therefore made the corresponding attack invisible.
  The rule now has three tiers, strongest first: a pinned executable path
  (`expected_privilege_exes`, `benign_reader_exes`, `allow_loader_exes`) authorizes
  whatever the name says; otherwise a name authorizes only where the readable
  `/proc/<pid>/exe` **is** that name's binary (basename equality, case-insensitive,
  tolerating the kernel's truncation at `TASK_COMM_LEN-1` and a `runc:[1:CHILD]`
  re-title); otherwise — when no executable could be read at all — the name still
  carries the record, because "the process exited before userspace looked" is the
  routine shape of a short-lived loader and the alternative is to re-arm the noise
  the benign lists exist to damp — the `/proc` readers alone once filled the live
  journal with 192 benign High "inspection attempt" lines. That last, weakest tier
  is what `warden --check` prints every run, and it is the only place a bare comm
  decides anything. The BPF arm adds one more question, because "the exe was
  unreadable" has two very different causes: `pidfd_open` asks the kernel's pid
  table whether the loader is still there (a `hidepid=` mount cannot fake it —
  measured on Debian 13 / 6.12.107, uid 1000 with no capabilities got `ALIVE` for
  three root-owned processes whose `/proc/<pid>/exe` answered `ENOENT` in the same
  breath), and a loader that is **still running** behind an unreadable exe is a
  finding rather than a pass. An answer the probe could not give (`ENOSYS`,
  `EPERM`) is deliberately treated like "exited": an unanswered question is not
  evidence of a live implant, and refusing a name over a kernel-capability gap
  would invent Critical findings on locked-down hosts.
  Stage 13 put a fourth tier underneath the weakest one, in the kernel. Every tier
  above reads `/proc/<pid>/exe` from userspace, and for the shape this rule exists to
  catch — a short-lived loader — that read is usually already too late: measured on
  the lab VM with the loader deliberately left as a zombie (`exit_mm()` drops
  `mm->exe_file` on the way out, so `readlink` answers `ENOENT` while the pid is still
  occupied), the exe was still readable for only 6 of 15 such loads — and those 6
  were decided by the path, which is why the invariant is stated over the unreadable
  subset. So the `security_bpf` kprobe now stamps `(dev, ino)` of `mm->exe_file` into
  the record it writes, by CO-RE read, where the task is alive by construction. When
  the path is unreadable the agent compares that pair against the inodes
  `allow_loader_exes` resolves to, which makes the exited-loader case an identity
  question instead of a name question: a match authorises, a resolved-but-different
  file convicts (and an allowlisted comm can no longer clear it), and — the part that
  keeps this from becoming a new false-positive engine — an empty list or a list
  whose entries cannot be `stat()`ed yields *no basis*, not a deny. `ino == 0` is the
  no-claim encoding for both cases that produce it (a task with no address space, and
  an object built before the stamp existed), and `dev` is the kernel's `kdev_t`
  packing, so the userspace side re-encodes `st_dev` through the same helper the
  guarded-inode keys use; compared raw, the two numbers describe one filesystem and
  never match.
- **Overhead.** Per-syscall probes cost. The real mitigations, as built: narrow
  tracepoints, an in-kernel cgroup/map lookup to drop what userspace would only
  discard anyway, a per-actor burst *window* so rename/unlink storms report once
  rather than per-event, and the `ringbuf_drops` counter so any events the kernel
  *did* drop under load are visible rather than silent (W-02). W2K-13 added the
  two knobs this list was missing. `[runtime] ring_size_kib` sizes the events ring
  when its map is created (`src/loader.rs::attach` via aya's `set_max_entries`),
  so 256 KiB is the default rather than a compile-time ceiling, and validation
  accepts only sizes the kernel keeps verbatim — the run logs the capacity it
  actually got, so a drop ratio is never quoted against a number nobody chose.
  `[runtime] enrich_cache_ms` bounds the per-event userspace cost: enrichment used
  to take four `/proc` reads (`stat`, `cmdline`, `cgroup`, `exe`) for *every*
  record, which on a ransomware-style storm is thousands of proc-filesystem walks
  for information that barely changes. The cache is keyed on `(pid, start time)` —
  the pair that makes pid reuse a miss instead of a wrong attribution — always
  bypassed for `execve` (a new image under the same pid must not inherit the old
  one's identity), and bounded by the window, so the worst lag is the number the
  operator set. On this host, 51 events from one process went from 204 `/proc`
  operations to 54 (`strace`-counted). There is no
  `vfs_write` payload hook and no sampling of one: `lsm/file_permission` sees
  the *permission* decision for guarded inodes, never the bytes written, so no
  write path can be sampled for entropy.
- **Untrusted-input parsers are a real surface, and they are tested as
  properties, not as examples.** Four places take bytes this process did not
  author: the ring-buffer record decode (`src/events.rs`), the spool line reader
  after a crash (`src/deliver.rs`), the two HTTP status-line parsers
  (`src/bridge.rs`, `src/heartbeat.rs`), and the TOML policy file
  (`src/config.rs`). Each is driven by a deterministic generator
  (`src/arb.rs`, 2–4k seeded iterations per parser) over both raw noise and
  grammar-shaped input, asserting the invariants that actually matter: no panic,
  a per-kind fold never leaking across kinds, `body` bytes surviving verbatim,
  an empty `event_id` refused, `deny` words never widening past the three
  `WARDEN_INTENT_*` bits, and — the finding this harness exposed, not an
  example anyone wrote on purpose — **no non-HTTP, non-`HTTP/… <3 digits>` reply
  counting as a delivery or a beat**.
  An accepted reply drops the record from the spool, so the lenient spelling was
  a silent-loss path, and the fix errs toward retry (Sentinel dedupes on the
  event id). This is *not* `cargo-fuzz`: the deployment and CI build run
  `cargo test --locked --offline`, so a libfuzzer harness would not run there;
  reproducibility and offline execution were worth more than coverage. The
  kernel-side C programs have no fuzz harness at all.
- **This is a real build, not a weekend script.** Realistic first milestone is
  **M1** below; the full sensor set is several milestones.

---

## 9. Original milestones (the design-time plan — §9a is what actually shipped)

Kept as the plan of record. **All of these have since been built**; the status
marker on each says how faithfully, and §9a is authoritative. The one place the
plan and the build diverged in *capability* (not just ordering) is M3's
"observe then block" and M4's entropy — see the markers.

- **M0 — skeleton:** Makefile, `vmlinux.h` gen, one trivial `exec` tracepoint
  loading via aya, printing enriched exec events. Proves the toolchain end-to-end.
  → **Shipped.**
- **M1 — self-protection + dead-man's-switch (highest value first):** kill/ptrace
  of Sentinel+Warden PIDs (`kprobe/security_task_kill`,
  `kprobe/security_ptrace_access_check`) + heartbeat to an off-box endpoint +
  systemd `Restart=always`. Directly answers "protect against Sentinel being
  turned off." → **Shipped** (with HMAC on the heartbeat).
- **M2 — Sentinel bridge:** `SentinelHostIngestAPI` + `endpoint:*` types + the
  Rust `bridge.rs` client; M1 findings now appear in Sentinel cases. → **Shipped**
  (cleartext HTTP by default or optional per-agent mTLS, durable spool + retry;
  since W2K-19 the cleartext "trusted path" premise is a load-time rule —
  cleartext to a publicly routable IP literal is refused unless
  `allow_public_plaintext` attests it, see `classify_uplink` in `src/config.rs`).
- **M3 — RCE + exfil:** shell-spawn-from-app-cgroup + an exact-destination
  cgroup deny, "observe then block". → **Partial → Optional with Phase 7.**
  Detection always ships; the four cgroup deny hooks are off by default and
  shadow-by-default, and only an explicitly enabled + armed isolated-cgroup
  deployment denies (§4). The original kprobe remains observe-only.
- **M4 — ransomware + credential-theft:** entropy/rate + protected-path reads. →
  **Partial.** The rename/unlink-storm *rate* half shipped; **entropy did not**,
  and protected-path reads ship only as the `[[enforce.guarded_files]]` LSM deny
  (§4), not as pattern-matched `.env`/`*.pem` reads.
- **M5 — rootkit/persistence + optional LSM inline-deny** (documents the reboot).
  → **Shipped**, with six `lsm/*` guarded-file programs; inline deny arms only
  with `bpf` in the boot `lsm=` list + reboot.

---

## 9a. Delivery status (2026-09-27)

What actually shipped differs slightly from the milestone *ordering* above (the
sensors were built in one sustained pass rather than strictly M-by-M), but every
buildable milestone's substance is present. The single ABI carries all sensors;
`assert_abi_size` pins it at **344 bytes**.

**Done — builds green, unit-tested, no root required:**

- [x] **Toolchain (M0).** `make bpf` compiles the CO-RE object (clang `-target
  bpf`, `vmlinux.h`); Rust `aya` loader embeds it via `include_bytes_aligned!`
  into one Rust executable with dynamic `libssl`/`libcrypto` for optional mTLS.
  `warden --check` reports config OK + embedded object size.
- [x] **Self-protection + heartbeat (M1).** `signal` (kprobe
  `security_task_kill`) and `ptrace` (kprobe `security_ptrace_access_check`)
  sensors → `endpoint:self_tamper`; protected-PID set (Granian/Celery/Warden,
  `protect_self`); dead-man's-switch heartbeat emitter; `systemd/warden.service`
  with `Restart=always`.
- [x] **Sentinel bridge (M2).** `SentinelHostIngestAPI` at `POST
  /api/v1/sentinel/host/`, `IsWardenSensor` (sentinel-service **and**
  superuser-owned key) → findings stored **first-party** (`tenant=None`),
  store-only; `bridge.rs` hand-rolled HTTP/1.1 client. 19 host-ingest tests;
  `manage.py check` clean on **both** settings; no migration.
- [x] **RCE + exfil (M3).** `exec` (tp `sched_process_exec`) →
  `endpoint:process_creation` (shell-in-app-cgroup / deleted-exe fileless);
  `connect` sensor → `endpoint:network_connect` (egress outside
  allowlist/ports/loopback, app-attributed). The record carries the socket's
  transport (`tcp`/`udp`/`icmp`/`other`, or no claim at all for an object predating
  the field) because a UDP dial and a TCP one to the same endpoint are different
  incidents and the flow contract has no column without it.
- [x] **Ransomware + tamper (M4, file half).** `file` sensor as two LSM-hook
  kprobes — `security_inode_rename` + `security_inode_unlink` →
  `endpoint:file_tamper`, with three rules: watched-name (any actor),
  ransom-extension (app-attributed), and per-actor modification-burst.
- [x] **Privilege escalation.** `creds` (kprobe `commit_creds`) →
  `endpoint:privilege_change` (uid→root or capability gain, app-attributed,
  suppressing the expected setuid plumbing).
- [x] **Rootkit / module load (M5, detection half).** `module` sensor →
  `endpoint:module_load` (runtime load of a non-allowlisted kernel module).
- [x] **Persistence / new service (M5, persistence half).** `service` sensor
  (kprobe `security_inode_create`) → `endpoint:new_service`: a file created in a
  boot/login-survival location (rogue systemd unit, cron entry, XDG autostart,
  `init.d`/`rc.local`, `ld.so.preload`, extra `authorized_keys`, `sudoers.d`
  drop — T1543). Allowlist-over-watchlist model (`persistence_dirs` watched,
  `allow_paths` sanctioned), fires for **any** actor, report-only (the artifact
  is already on disk). The kernel captures the created leaf plus three ancestor
  directory names as a **fixed ladder** (four constant-offset reads, no verifier
  loop) packed into the shared `filename` buffer; userspace rebuilds the
  root-first path. ABI unchanged at 344 bytes. Fed end to end
  (`api.SUBMITTABLE_HOST_EVENT_TYPES`, `stages.py` T1543 row now live rather
  than reserved).
- [x] **Backdoor listener, eBPF implant, container escape (advanced set).**
  Three more programs close the last host gaps, no ABI growth (they reuse the
  `daddr`/`aux`/`aux2`/`filename` fields) and no cfg-slot growth at the time
  (slots 5/6/7 were free; `CFG_SLOT_COUNT` was 8 and full). Two later gates —
  the LSM access-emit slot (8) and the enforce-arm slot (9) — grew the array to
  10; all ten slots are now assigned:
  - `listen` sensor (kprobe `security_socket_listen`) → `endpoint:listen`: a
    process in the app begins listening on a socket that is not an allowlisted
    service port — a planted bind shell / reverse-shell listener. Inbound C2, so
    it shares the command-and-control stage (T1071) with the outbound
    `connect`. App-attributed, loopback- and port-allowlisted.
  - `bpf` sensor (kprobe `security_bpf`, gated to `BPF_PROG_LOAD`) →
    `endpoint:bpf_load`: a BPF program of an implant-capable type loaded at runtime by
    a loader that is not authorized — the modern in-kernel rootkit that hides
    processes and rewrites syscall returns without a module (T1014 Rootkit, Defense
    Evasion). Host-global, report-only. Authorization is by executable identity
    (`[bpf_rules].allow_loader_exes` matched against `/proc/<pid>/exe`), NOT by comm:
    since W2K-18 the comm list only decides a load whose exe could not be read
    because the loader had already exited, and an empty exe list — the shipped
    default — authorizes nothing by identity. Since Stage 13 the same hook also
    writes the loader's `(dev, ino)` into the record, so an unreadable exe is no
    longer an unidentified actor: the pair is compared against the inodes those same
    paths resolve to, and a pinned loader is authorised — or refused — by the file
    that actually ran.
  - `mount` sensor (kprobe `security_sb_mount`) → `endpoint:mount`: a **bind**
    mount grafting a watched host path (the Docker/containerd socket, `/`,
    `/proc`, `/etc`, `/root`) — the classic escape-to-host move (T1611, Privilege
    Escalation). `bind_only` by default (a plain block-device mount is routine
    admin work); report-only.

  **Twelfth** program; ABI still 344 bytes. Fed end to end
  (`api.SUBMITTABLE_HOST_EVENT_TYPES` now 10 kinds, 23 host-ingest tests,
  `stages.py` rows citing T1071/T1014/T1611 handles live).
- [x] **Host-observation correlation adapter.** All ten `endpoint:*` findings
  feed the kill-chain correlator: `from_host_events` anchors each on its host as
  an `('asset', host)` entity so a multi-stage host attack chains into one
  Attack Story, and `network_connect` additionally anchors on its destination IP
  so a host-observed egress joins an NDR-observed beacon to the same address.
  Mappings in `stages.py` (`killchain-2`), techniques in `ndr/attack.py`
  (`attack-16`); the grep test keeps T-literals out of everything but the
  registry.

**Deferred — needs sudo/root, held for the operator:**

- [ ] Live **kernel-load smoke test** of all twenty programs (14 observational + 6
  LSM guarded-file programs) against the running kernel (CAP_BPF) — the one thing
  unit tests cannot cover. (`tests/capability_matrix.rs` pins the *shipped set*
  structurally, but it parses the object without loading it.) On the dev host the
  privileged `tests/preopened_fd_guard.rs` now loads `file_permission` +
  `inode_setattr` and observes `-EPERM`; the other eighteen are still not
  load-smoked. What IS measured on the deployment kernel is that the object
  *loads* at all: `bpftool prog loadall … autoattach` returned 0 for the
  stage-13 object on `6.12.107+deb13-amd64`, and a *throwaway* kprobe/kretprobe
  pair on `__inet_stream_connect` attached and fired there — Warden's own pair has
  not (`docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §16).
- [ ] **Confirm the network transport byte on a live host**
  (`docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §15). The packed `aux2` is tested against synthetic
  records only: unit tests prove the decoder, not that the kernel wrote them. What a
  run has to show is (a) a `connect` to a UDP socket arrives with `udp` and not
  `null`, (b) a record from the previous object still decodes with no claim — the
  append-only rule in `bpf/warden.h`, and (c) the object *loads at all* on the
  deployment kernel, because `sk->sk_protocol` is a CO-RE relocation and Warden
  refuses to start rather than run half-attached (N-14: an observational field
  should not be able to take the agent down; making that true is a separate,
  owner-approved change).
- [ ] **Confirm the connect verdict on a live host**
  (`docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §16). The pair was measured with a throwaway probe on
  the deployment kernel — attach, fire, terminal codes, the 91% in-flight share — but
  the shipped programs have not been run against a real dial through Warden's own ring
  buffer. What a run has to show: (a) a blocking connect that succeeds yields a
  `connect_result` of `established` (hint `S1`), (b) a refused one yields `refused`
  (`REJ`), (c) a timeout-style non-blocking client yields a `connect` record and **no**
  verdict record, with the debug line's `N of M dial(s)` ratio reflecting that, and
  (d) `__inet_stream_connect` resolves on the running kernel — the same fail-closed
  exposure as N-14, now on an internal symbol rather than a `security_*` hook.
- [ ] **Run the pull path on the deployment host** (`warden --socket-snapshot`,
  then `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §17). What it has to show is not a detection:
  (a) the four tables parse with **0 rows rejected** on that kernel's spelling,
  (b) the *pre-existing* listeners are named once on the baseline tick, which is
  the whole reason the path exists — every one of them is invisible to the push
  sensors, (c) as root the attribution line resolves most inodes — where the same
  walk as an ordinary user resolved **1 of 11** and named the ~170 denied pids
  as the reason, because another user's `/proc/<pid>/fd` is `0700` and an
  unprivileged walk simply cannot open it (not `hidepid=`, though a `hidepid=`
  mount produces the same line and the wording covers both), and (d) `cost N ms`
  on that box, since 0–2 ms for the tables and 21–71 ms with attribution are
  **build-host release-build numbers at load 3.33** and no figure here is a VPS
  benchmark. What stays UNVERIFIED after it: a periodic tick *inside a running
  agent* (the flag runs one tick and exits), and every socket in another network
  namespace.
- [ ] `make install` + `systemctl enable --now warden.service`.
- [ ] **BPF-LSM inline-deny: NOT qualified on the dev host** (kernel `7.0.0-15`):
  `bpf` presence in the active LSM list and six shipped `lsm/*` programs establish
  readiness only. The runtime `preopened_fd_guard` case is `#[ignore]`d and reports
  `SKIP` without root/`CAP_BPF`; a default `cargo test` "3 passed" counts two
  structural tests plus a regression guard, not an in-kernel `-EPERM`. Only
  `scripts/test-privileged.sh` in a disposable VM is evidence of denial, and it
  has not been run successfully for this object. This hardens the
  **file** axis only: there is no exec hook (`bprm_check`) to deny. The Phase 7
  `cgroup/connect4|6/sendmsg4|6` programs do not need the `bpf` LSM or a reboot:
  they attach to a named cgroup via `bpf_link_create`, are disabled by default and
  deny only when explicitly enabled and armed against an exact destination. The
  process-kill responder needs no reboot — it is userspace `kill(2)`.
- [ ] Optional: point `config/warden.toml [bridge]` at a real superuser Sentinel
  key for a live end-to-end finding.

**Not built (deliberate, would need approval):** the credential-theft *pattern*
half of M4 — matching `.env`/`*.pem`/`*.key` by name and denying a non-app read.
What ships instead is narrower: the `lsm/file_open` + `lsm/mmap_file` +
`lsm/file_permission` programs deny reads/writes of files the operator has
**explicitly enumerated** in `[[enforce.guarded_files]]` and pinned to an inode,
and only when armed. There is no glob matching, and the rename/unlink sensors
watch destructive ops, not reads; an fd opened before arming is re-checked per
read/write, but a writable mapping established before arming is not revoked
(W-R2).

---

## 10. Open decisions for you

1. **Deploy unit:** hardened **systemd service** on the bare host (my
   recommendation — matches probed reality), or a distroless **container** with
   `CAP_BPF`? 
2. **Enforcement appetite:** ship **observe-only** first everywhere (safest), or
   arm the responders that exist — **guarded-file deny**, **shell-kill**, and the
   **cgroup-scoped exact-rule egress deny** — from the start for the app cgroup?
   The egress hook must first be enabled for a validated isolated cgroup, and a
   reload cannot attach it (§4); observe-only remains the safe starting posture.
3. **Bridge shape:** add the **new `POST /api/v1/sentinel/host/`** endpoint (my
   recommendation), or keep Warden fully standalone (its own alert channel) and
   bridge to Sentinel later?
4. **LSM reboot:** in scope now (adds inline *file* deny for guarded files), or
   defer — keep the guarded-file **shadow** findings plus the userspace kill,
   which need no reboot?
5. **Start at M0/M1?** M1 (self-protection + dead-man's-switch) is the most
   direct answer to your "protect against it being shut down" ask.

---

## 11. Mission 16 — one configuration engine, honest UX

Mission 16 did not add a second configuration, health or telemetry system.
`src/config_engine.rs` serializes and re-parses the same `Config` that
`src/main.rs` loads at startup. Five named profiles give Simple/Advanced UX
without hiding policy:

| Profile | Detective surface | Enforcement | Intended use |
|---|---|---|---|
| `essential` | core sensors only; C2, snapshot and volume off | observe-only | first deployment / unfamiliar host |
| `balanced` | C2 + bounded `/proc` socket snapshot; volume only if every measured prerequisite is `VERIFIED` | observe-only | ordinary servers |
| `advanced` | all rule knobs explicit; shorter snapshot cadence | observe-only | operators tuning a file by hand |
| `hardened` | full detective surface + BPF-LSM readiness reporting | observe-only; no path or uid invented; no arm | high-value hosts awaiting deliberate arming |
| `custom` | validates an existing document byte-for-byte | whatever the file says | review and migration |

Every generated profile writes `schema_version = 1`, leaves all kill responders
off, leaves `enforce.arm = false` and `egress.enabled = false`, and refuses to
enable six-hook volume accounting unless BTF, cgroup v2, the perf gate and all
six raw BTF prototypes are verified for the process that asks. An unprivileged
planner therefore reports `perf_gate=UNAVAILABLE` and leaves volume off even if a
root daemon could attach it; that is deliberate. It never calls `bpf()`, never
touches a service, never contacts SENTINEL, and labels its output `SIMULATION
ONLY` where it describes future actions.

Operations are one question per run, are dispatched before daemon config load,
and use the truth categories from the mission: `PASS`, `FAIL`, `BLOCKED`,
`UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE` and `PARTIAL`. Migration writes a
timestamped backup, validates before and after, and is idempotent. Rollback
validates the source and refuses a backup that arms kill or denial behavior.
Drift reports measured changes and explicitly lists in-memory policy, ring
counters, spool and bridge delivery as `NOT MEASURED`. The guided installer
extends `make install` rather than replacing it: preview by default, explicit
`--yes`/`--unattended`, `/tmp`-only unprivileged `--test-mode`, config preserved
on reinstall and uninstall, and no `systemctl` call unless `--enable-service`
is given.

The live boundary remains unchanged: privileged attach and counters were
measured only in the disposable Debian 13 VM, the M15 BPF object was not
recompiled, and live SENTINEL platform delivery remains external and `BLOCKED`.
The operator guide and final report in `docs/security/` carry the commands,
measured values and residual limitations.

