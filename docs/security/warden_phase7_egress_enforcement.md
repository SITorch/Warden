# Warden Phase 7 — Genuine Kernel Egress Enforcement

**Status:** implemented in the tree; **disabled by default**; live verification is
recorded in `warden_phase6_live_validation.md` and classified per test. This
document is the contract for the *code*, not a claim that any production host is
protected.

---

## 1. What changed, and what did not

Phase 0–5 shipped a complete observe-only agent. Two separate mechanisms used to
describe "deny":

* `network_rules.deny_destinations` — a **policy decision** evaluated in
  `src/detect.rs`. It produced a Critical observe-only finding whose JSON said
  `traffic_blocked: false`. It could not alter a syscall.
* `enforce.guarded_files` — six BPF-LSM programs that can genuinely return
  `-EPERM` for a file operation, but only on the **file** axis.

Phase 7 adds a third mechanism: four cgroup socket-address programs that can
genuinely refuse an outbound `connect(2)` or unconnected `sendmsg(2)`. It does
**not** repurpose either of the first two:

* `deny_destinations` is still observe-only. Its finding now carries a
  `DenyDecision` built through the honesty layer (`policy.rs`), which requires
  positive kernel proof before it will set `traffic_blocked: true`. A config
  rule is never such proof.
* The LSM file guard is untouched. Its arm flag (`enforce.arm`) remains separate
  from `egress.arm` so arming one axis cannot silently arm the other.
* No `kill_*` flag changed, `mode` still defaults to `observe`, WireGuard stays
  off, and `BACKUP_REQUIRE_OFFSITE=1` is untouched.

---

## 2. The three independent gates

A matching DENY refuses traffic **only when all three hold**. There is no fourth
implicit path and no config-only shortcut.

### Gate 1 — attachment (`[egress] enabled = true` + a cgroup path)

`src/config.rs::Config::validate` refuses any enabled egress configuration that
does not name an absolute, non-root cgroup directory. `loader::open_validated_cgroup`
then performs the authoritative check in the kernel: it opens each component with
`O_NOFOLLOW` (rejecting `.`, `..`, prefix components and symlink aliases),
requires `fstatfs` on the opened fd to report the cgroup2 super-magic, reads
`/proc/self/mountinfo` for the cgroup2 roots visible in this process's mount
namespace, compares the target's `(dev,ino)` with the owning root, refuses the
root or an alias of it, and fails closed when more than one cgroup2 mount could
own the path. The loader attaches with
`CgroupSockAddr::attach(fd, CgroupAttachMode::Single)` from that **same validated
fd**, so a path swapped between validation and attach cannot redirect the hooks.
`/sys/fs/cgroup` and `/` are explicitly rejected: the default path is an
**isolated test/tenant cgroup**, never the host root. No test in this tree
attaches hooks to the host root.

With `[egress]` omitted (the shipped default):

* `enabled = false`, `arm = false`, `cgroup_path = None`, `deny = []`;
* **no cgroup program is loaded and no link is attached**;
* the embedded object still contains the programs and maps (so `--check` and
  structural tests can see them), but the runtime reports `EgressHooks::default()`
  — all four bits false.

### Gate 2 — arming (`CFG_EGRESS_ARM` slot 13)

`warden.h` defines `CFG_EGRESS_ARM = 13` with default value 0. The kernel's
`egress_decide()` reads that slot on every DENY match:

```c
if (!(armed && *armed == 1)) {
    egress_count(WARDEN_EGRESS_HIT_DENY);   /* shadow: count, allow */
    return 1;                               /* cgroup/sock_addr: 1 = ALLOW */
}
egress_count(WARDEN_EGRESS_DENIED);
return 0;                                   /* 0 = DENY -> syscall sees -EPERM */
```

For `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` the verifier restricts R0 to `[0, 1]`, and
the convention is the reverse of the file-LSM programs: **1 allows, 0 denies**.
Returning `-EPERM` from the BPF program was measured to fail `BPF_PROG_LOAD` on
`6.12.107+deb13-amd64`; the syscall-visible `EPERM` is produced by returning 0.
The live proof and the correction history are in
`warden_phase6_live_validation.md` §5 and
`warden_kernel_compatibility_matrix.md` §3.

`Config::validate` rejects `arm = true` while `enabled = false`, so a dormant
config cannot read as protection. The reload state machine writes the slot and
reads it back before it reports ARMED; the reported bit is the kernel's answer,
never the requested value. Attachment with `arm = false` is **shadow by default**:
a would-deny is counted, never refused. A failed write or a read-back
mismatch rolls back the old policy and arm bit; on an unconfirmed rollback the
runtime is marked DEGRADED.

### Gate 3 — an exact rule in `egress_policy`

A `[[egress.deny]]` entry is:

```toml
[[egress.deny]]
address = "203.0.113.9"   # IPv4 or IPv6 literal; no names, no CIDR
port    = 4444            # 0 = any port for this address+protocol
protocol = "tcp"          # "tcp" (default) or "udp"
```

The userspace compiler (`egress::EgressDeny::to_key`) writes the 28-byte
`warden_egress_key` ABI. The kernel key is `(family, protocol, addr, port)`:

* `family` — `AF_INET = 2` or `AF_INET6 = 10`;
* `protocol` — `IPPROTO_TCP = 6` or `IPPROTO_UDP = 17`;
* `addr` — 4 or 16 raw octets in the leading bytes, rest zero;
* `port` — **network byte order**, because `bpf_sock_addr.user_port` is a direct
  load of `sockaddr_in.sin_port` (confirmed from `net/core/filter.c`:
  `sock_addr_convert_ctx_access` maps `user_port` to the nested `sin_port` field
  with no conversion). Rust writes `port.to_be()`, so the integer value stored is
  exactly what the kernel sees on either endianness.

A `port = 0` rule is the **only** wildcard. The kernel looks up the exact port
first and only then the zero-port key, so a specific rule always wins. An
invalid address is a hard config error, never a silently-looser rule: an
unparseable name must not become `0.0.0.0` and block far more than intended.

---

## 3. Hook set and coverage honesty

| Section | Hook | What it sees | Gap |
|---|---|---|---|
| `cgroup/connect4` | `BPF_CGROUP_INET4_CONNECT` | IPv4 connect destination before routing | Does not see a hostname, only the resolved address |
| `cgroup/connect6` | `BPF_CGROUP_INET6_CONNECT` | IPv6 connect destination | Same |
| `cgroup/sendmsg4` | `BPF_CGROUP_UDP4_SENDMSG` | IPv4 unconnected-UDP destination | Connected UDP uses the connect hook instead |
| `cgroup/sendmsg6` | `BPF_CGROUP_UDP6_SENDMSG` | IPv6 unconnected-UDP destination | Same |

`EgressHooks::all()` requires **all four** attach calls to have succeeded. A
partial attach is reported as `DEGRADED` by `policy::Preflight`, never as full
coverage. `Loaded::egress_stats()` reads the four monotonic kernel counters:

| Slot | Constant | Meaning |
|---|---|---|
| 0 | `WARDEN_EGRESS_HIT_ALLOW` | an explicit ALLOW-shaped rule matched (allows) |
| 1 | `WARDEN_EGRESS_HIT_DENY` | a DENY matched in shadow; traffic was allowed |
| 2 | `WARDEN_EGRESS_DENIED` | an armed DENY returned `-EPERM` |
| 3 | `WARDEN_EGRESS_MAP_FULL` | a userspace rule insert was refused; coverage incomplete |

Only slot 2 is a verified block. A nonzero slot 1 is reported as "SHADOW
would-deny hit(s) — traffic was allowed through", and slot 3 raises a warning
that coverage is incomplete. The journal reports these on the same cadence as
the ring-drop counters; an unreadable counter is UNKNOWN, never zero.

---

## 4. Transactional policy updates and the A–E reload contract

`egress::EgressPolicy::sync` snapshots the live map, then writes the desired
generation. On any kernel write failure it removes every touched key and
re-installs the snapshot. A post-write read-back compares every key and rule;
only then is the arm slot touched. If rollback cannot be confirmed it sets
`ready = false`, which `EgressRuntime::preflight()` feeds into
`policy::Preflight` so the agent reports DEGRADED instead of silently presenting
a partial rule set as complete.

`SIGHUP` can flip `arm` and replace the rules (both are map writes). It **cannot**
move hook attachment, which is a load-time fact. The transition is classified
against the config the process booted with, not the last requested config:

| State | Transition | Kernel action | Reported truth |
|---|---|---|---|
| A | enabled → disabled | disarm, read back 0, clear and read back the map | hooks remain attached from startup but are disarmed and empty; restart to detach |
| B | enabled → enabled | disarm, sync, verify, re-arm only on full success, read back | rules and generation come from the verified map, not the config |
| C | `cgroup_path` changed | same disarm/clear as A | new path is explicitly NOT covered; startup hooks are on the OLD cgroup; restart required |
| D | disabled → enabled | no arm write and no rule write | restart required; a reload cannot manufacture startup attachment |
| E | config load failed | no kernel write at all | old arm bit, map and generation are preserved and reported |

Insert, remove, enumeration and arm-write failures restore the previous map and
arm bit. A failed re-arm leaves the runtime SHADOW rather than reporting the old
ARMED state. A failed rollback is not silently labelled recovered: the summary
says DEGRADED and asks for a restart. Failed reloads do not kill the daemon.

---

## 5. What this primitive cannot do (stated, not guessed)

* **No DNS names.** The hook sees an IP and a port. A hostname resolved to a
  different address is a different rule. Phase 10 adds DNS *metadata* from a
  separate source; it does not make the kernel hook name-aware.
* **No TLS/SNI/HTTP inspection.** An encrypted connection is just a TCP dial to
  an IP:port. There is no default TLS interception anywhere in this mission.
* **No QUIC semantics.** UDP sends are seen per datagram destination; no
  handshake or ALPN is parsed.
* **No per-process identity in the kernel key.** Attachment is cgroup-scoped:
  every process in the chosen cgroup shares the rule set. That is why the config
  requires an isolated cgroup.
* **No packet filtering.** `cgroup/sock_addr` is not XDP/TC/sockops and cannot
  inspect or rewrite packets; no such hook ships (pinned by
  `tests/network_coverage_matrix.rs`).
* **No egress → process-kill coupling.** A denied dial never acquires kill
  intent. All `kill_*` flags stay false in the shipped posture.

---

## 6. Honest reporting contract

`policy::DenyDecision` has two constructors:

* `observe_only(mode)` — the shipped default; `traffic_blocked: false`; note says
  the connection was **NOT** blocked.
* `verified(mode, preflight, kernel_denied)` — sets `traffic_blocked: true` only
  when `kernel_denied` is true **and** the preflight resolves to
  `EnforcementState::Enforce`. The detector passes `kernel_denied = false` for
  its connect observation because that record is not a kernel denial record.

No `api_key` appears in any egress config, map, journal line, report, or finding
envelope. The secret stays in the bridge layer and is never serialized by any
Phase 7 code path.

---

## 7. Verification status

Historical privileged evidence lives in `docs/security/warden_phase6_live_validation.md`
outside the standalone `Warden/` tree. An earlier isolated-VM run recorded
13/13 `EXECUTED AND PASSED`, including shadow allow, shadow counter, armed IPv4
TCP `EPERM`, armed UDP `sendmsg4` `EPERM`, armed IPv6 TCP `EPERM`, and
non-matching-port allow. That run predates the current reload and cgroup-fd
validation changes; it is history, **not** a current-source live proof. No
privileged BPF attach was re-executed in the current audit pass: this host has
`CapEff=0x0`, and no VM or production host was touched.

Current unprivileged gates for this phase are recorded in the final audit report
and include:

* `cargo fmt --check`;
* `cargo clippy --offline --all-targets -- -D warnings`;
* `cargo test --offline --all-targets`, including the A–E reload matrix, rollback
  injection tests, cgroup validation tests and the four transport/key/hook cases;
* `cargo build --release --locked --offline` when the vendored dependency set is
  complete.

The shipped object must still contain exactly the four cgroup sections and the
`egress_policy` / `egress_stats` maps; `tests/network_coverage_matrix.rs` and
`tests/capability_matrix.rs` enforce that structurally. The eBPF C source was
not changed by the current audit pass.

---

## 8. Mission 16 configuration boundary

M16 did not change the egress hook set, the A–E reload state machine or the
plain-language denial contract. It added a configuration engine that makes the
existing safe defaults explicit:

* every generated profile writes `schema_version = 1` and leaves
  `egress.enabled = false` and `egress.arm = false`;
* no profile invents a cgroup path, guard path, UID or bridge credential;
* `--config-validate` flags cgroup egress enabled without verified cgroup v2,
  and flags `egress.arm = true` with the note that traffic will be denied and
  the target must be an isolated test cgroup;
* `--config-plan` lists cgroup egress as enabled/disabled in a document explicitly
  labelled `SIMULATION ONLY`; it never attaches a program;
* rollback refuses a backup with `egress.arm` (or kill responders / LSM arm),
  keeping the existing safety-backup behavior.

The VM work in `M16_09` used a schema-v1 observe-only config with
`net_volume.enabled = true` and no egress section. It is evidence for volume
accounting and the unchanged installed service, not an armed egress test.
Armed egress evidence remains historical and environment-specific; no new
firewall, service or host network change was authorised in M16.
