// SPDX-License-Identifier: GPL-2.0
/*
 * warden.bpf.c — Warden's in-kernel sensors (CO-RE eBPF).
 *
 * Twelve observational sensors, one ring buffer (the enforcing BPF-LSM layer
 * below adds six deny-capable guards, and the network volume block after sensor
 * 12 adds six fexit programs that write a counter map instead of a record):
 *   1. tp/sched/sched_process_exec  — every execve on the box (RCE/shell tripwire, T1)
 *   2. kprobe/security_task_kill    — a signal aimed at a PROTECTED pid    (takedown, T8)
 *   3. kprobe/security_ptrace_access_check — ptrace aimed at a PROTECTED pid (inject, T7/T8)
 *   4. kprobe/security_socket_connect — an outbound connect (C2/reverse-shell dial-out, T1/T4)
 *   5. kprobe/commit_creds          — a credential change that raises privilege (privesc, T5)
 *   6. tp/module/module_load        — a kernel module was loaded            (rootkit/LKM, T6)
 *   7. kprobe/security_inode_rename — a destructive rename                  (ransomware/tamper, T2/T9)
 *   8. kprobe/security_inode_unlink — a destructive unlink                  (ransomware/tamper, T2/T9)
 *   9. kprobe/security_inode_create — a file dropped in a persistence dir   (boot/login survival, T3)
 *  10. kprobe/security_socket_listen — a socket entered LISTEN              (bind-shell/backdoor, T4)
 *  11. kprobe/security_bpf          — a BPF program was loaded              (eBPF rootkit/stealth, T6)
 *  12. kprobe/security_sb_mount     — a filesystem was mounted              (container escape, T10)
 *
 * The kernel side is deliberately dumb: it observes, does one map lookup to
 * decide "is the victim protected?", stamps a fixed-size record, and hands it
 * to userspace over a BPF ring buffer. All judgement lives in Rust. This keeps
 * us safely inside the verifier's complexity budget and means a policy change
 * never touches kernel code.
 *
 * CO-RE: we read kernel structs through bpf_core_read / BPF_CORE_READ so one
 * compiled object is portable across kernels via BTF relocation. Built against
 * the vmlinux.h generated from THIS host's /sys/kernel/btf/vmlinux, but the
 * relocations make it portable.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "warden.h"

char LICENSE[] SEC("license") = "GPL";

/* Address families. vmlinux.h gives us the sockaddr structs but not these
 * constants; they are ABI-stable on Linux, so we name them here rather than
 * carry a magic 2/10 at the comparison site. */
#define AF_INET  2
#define AF_INET6 10

/* File-access constants the enforcing (BPF-LSM) programs need. vmlinux.h gives
 * us the structs but not these UAPI/VFS constants; they are ABI-stable, so we
 * name them here rather than carry magic numbers at the test site.
 *   f_mode bits (fmode_t)         — how a file was opened
 *   PROT_* (mmap prot)            — happen to share bit positions with FMODE_*
 *   errno EPERM                   — returned negated to DENY an LSM hook       */
#define FMODE_READ   0x0000001u
#define FMODE_WRITE  0x0000002u
#define FMODE_EXEC   0x0000020u
#define PROT_READ    0x1u
#define PROT_WRITE   0x2u
#define PROT_EXEC    0x4u
/* mmap flags (UAPI): whether a writable mapping can reach the file's contents.
 * MAP_PRIVATE writes are copy-on-write and never touch the inode; MAP_SHARED
 * writes do. Every executable's loader makes a private PROT_WRITE mapping of
 * its own data segment — treating that as a write to the file denied the
 * loader its own memory and killed the process at startup (seen live: a
 * guarded binary SIGSEGVs on exec while armed). */
#define MAP_SHARED   0x01u
#define MAP_PRIVATE  0x02u
/* MAY_* bits passed to security_file_permission. Note the different bit order
 * from PROT_*: MAY_EXEC is 1, MAY_WRITE is 2, MAY_READ is 4. */
#define MAY_EXEC     0x1
#define MAY_WRITE    0x2
#define MAY_READ     0x4
#define MAY_APPEND   0x8
#define EPERM        1
/* The connect-outcome codes the return probe classifies. UAPI errno numbers are
 * ABI-stable on Linux (they are the userspace contract), so — like AF_INET and
 * MAP_SHARED above — they are named here instead of carried as magic at the
 * test site. Only the ones a `connect(2)` can actually return appear; the two
 * "still in flight" codes (EINPROGRESS/EALREADY) are matched explicitly because
 * they are the ones this sensor must NOT report. */
#define ECONNREFUSED 111
#define ETIMEDOUT    110
#define EHOSTUNREACH 113
#define ENETUNREACH  101
#define EACCES       13
#define ECONNRESET   104
#define ECONNABORTED 103
#define EPIPE        32
#define EINTR        4
#define EAGAIN       11
#define EISCONN      106
#define EINPROGRESS  115
#define EALREADY     116

/* ── maps ──────────────────────────────────────────────────────────────── */

/* The event channel to userspace. 256 KiB is plenty for our event rate; the
 * ring buffer is lossy by contract — under flood the kernel drops rather than
 * blocking a syscall. That trade is only safe if the loss is VISIBLE, which is
 * what the `ringbuf_drops` map below is for. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* W-02: the ring-buffer drop counter.
 *
 * A lossy ring is indistinguishable from a quiet host unless somebody counts the
 * losses: "zero events" reads as "nothing happened" when it may mean "nothing got
 * through". Every `bpf_ringbuf_reserve` below records its own failure here, so a
 * flood that overruns the ring leaves a number behind instead of a silence.
 *
 * PERCPU_ARRAY, one slot PER EVENT KIND (index = `enum warden_event_kind`, slot 0
 * unused): one counter per CPU per sensor, so the hot path is a lock-free bump of
 * this CPU's private u64 and emitting an event never contends with another CPU
 * doing the same. `src/loader.rs` samples the copies and sums them; `src/main.rs`
 * reports the dropped/drained ratio on a timer, loudly, because a quiet log is
 * exactly the failure this counter exists to break.
 *
 * W2K-14: the index used to be 0 for everything, which made the report say "N
 * events lost" and nothing about WHERE. The operator-facing advice in that warning
 * is "mute the noisiest sensor" — unactionable without per-sensor numbers. Slot
 * count is now `WARDEN_KIND_SLOTS`, and the bound is deliberate: adding a kind is
 * a change in `warden.h`, this map's size, and the reader together.
 *
 * This map is embedded in `bpf/warden.bpf.o` and must ship with it — see the
 * Makefile's `bpf` target and `include_bytes_aligned!` in src/loader.rs. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, WARDEN_KIND_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_drops SEC(".maps");

/* W2K-14: the mirror of `ringbuf_drops` for events that DID get through.
 *
 * Drops alone cannot tell a quiet host from a dead sensor: zero drops with zero
 * events is either "nothing happened" or "the program stopped firing" (a hook that
 * failed to attach on one kernel, a gate left muted, an ABI the verifier rejected).
 * Counting successful submits per kind makes that distinction visible from the
 * same two maps, and gives the drop ratio a per-sensor denominator instead of a
 * process-wide one. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, WARDEN_KIND_SLOTS);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_events SEC(".maps");

/* Charge one dropped event to this CPU's counter for `kind`.
 *
 * `__sync_fetch_and_add` rather than `*n += 1`: a BPF program on this CPU can be
 * interrupted by an NMI running another Warden program that reaches the same
 * counter, so the read-modify-write has to be atomic even against the private
 * per-CPU copy. Best-effort by contract — if the lookup itself fails there is no
 * counter to charge the loss to, and the reserve that brought us here has already
 * failed, so there is nothing left to do but return.
 *
 * The bounds test is for the verifier (a variable array index must be proven in
 * range) and doubles as the ABI guard: a kind outside `WARDEN_KIND_SLOTS` is a
 * counter that silently never moves, which is the invisibility this whole map
 * exists to remove. */
static __always_inline void count_drop(__u32 kind)
{
	if (kind == 0 || kind >= WARDEN_KIND_SLOTS)
		return;
	__u64 *n = bpf_map_lookup_elem(&ringbuf_drops, &kind);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* Record one successfully reserved-and-submitted event for `kind`. Called right
 * before `bpf_ringbuf_submit`, so the counter tracks records handed to the ring,
 * not records the sensor decided to build. */
static __always_inline void count_submit(__u32 kind)
{
	if (kind == 0 || kind >= WARDEN_KIND_SLOTS)
		return;
	__u64 *n = bpf_map_lookup_elem(&ringbuf_events, &kind);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* PIDs Warden must guard: the Sentinel workers, and Warden's own agent.
 * Userspace populates this at startup and refreshes it as PIDs change. Key is
 * tgid, value is a nonzero tag byte. A signal/ptrace whose TARGET is in here is
 * what we care about — not who sends it (that's userspace's call). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} protected_pids SEC(".maps");

/* A small config array so userspace can flip per-sensor behaviour without a
 * reload. Slots are named in `enum warden_cfg_slot` (warden.h): index 0 gates
 * the exec sensor, 1 the connect sensor, 2 the module-load sensor, 3 the file
 * rename/unlink sensor, 4 the persistence-create sensor, 5 the listen sensor,
 * 6 the bpf-load sensor, 7 the mount sensor. Sized to CFG_SLOT_COUNT so a new
 * sensor's gate is a new enum value, not a map resize. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_SLOT_COUNT);
	__type(key, __u32);
	__type(value, __u32);
} runtime_cfg SEC(".maps");

/* Is the sensor at config slot `slot` currently emitting? Absent slot ⇒ treat
 * as emitting (fail open to observability): a config we failed to seed must not
 * silently blind a sensor. */
static __always_inline bool sensor_emitting(__u32 slot)
{
	__u32 *on = bpf_map_lookup_elem(&runtime_cfg, &slot);
	return !(on && *on == 0);
}

/* The enforcing gate. Unlike sensor_emitting (which fails OPEN so a misconfigured
 * gate never blinds a detector), the enforce arm fails CLOSED to observe-only: an
 * absent or zero slot means SHADOW (log the would-deny, allow the operation). Only
 * an explicit 1 arms real -EPERM denial. Denial is the one irreversible thing a
 * guard does — a wrong deny can lock the box out of its own files — so the safe
 * default whenever we are unsure is "do not deny", exactly inverse to emission. */
static __always_inline bool enforce_armed(void)
{
	__u32 slot = CFG_ENFORCE_ARM;
	__u32 *on = bpf_map_lookup_elem(&runtime_cfg, &slot);
	return on && *on == 1;
}

/* ── the enforcing guard map ─────────────────────────────────────────────────
 *
 * The inode identities Warden is guarding, keyed (device, inode) → policy. This
 * is the ONE map the BPF-LSM programs consult to decide deny-or-allow. Userspace
 * stat()s each configured guarded file, resolves it to (dev, ino), and installs a
 * warden_guard_policy. A hash map keyed on the resolved inode (not a path string)
 * is both cheap in-kernel and unspoofable: a symlink, hardlink, bind mount, or
 * `..` trick still lands on the same inode, and a path walk in the verifier's
 * budget is exactly what we avoid. 4096 guarded files is far more than any real
 * secret set. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct warden_inode_key);
	__type(value, struct warden_guard_policy);
} guarded_inodes SEC(".maps");

/* What the entry half of the connect-outcome pair keeps while the dial runs.
 *
 * The endpoint must be read at ENTRY: `address` is the caller's sockaddr, and by
 * the time a kretprobe fires a blocking connect has already slept through a SYN
 * timeout, during which the task can have been moved, the buffer reused, or the
 * syscall argument frame unwound. The kernel's own copy lives on the syscall
 * stack so it is very likely still valid — "likely" is not good enough for a
 * field that ends up in an egress decision, so it is copied here instead, once,
 * while it is certainly readable.
 *
 * Keyed by tid (not pid): a connect belongs to one thread, and the return probe
 * runs on the same thread. 4096 slots is far above the concurrency this sees —
 * measured live on the deployment host, a 60 s window held 128 connects with the
 * entry and exit counters never more than one apart, i.e. nothing piled up. When
 * a store *does* fail the dial simply gets no outcome record; the CONNECT and
 * CONNECT_RESULT submit counts are what make that gap visible to the operator,
 * which is why no separate counter map is needed here. */
struct warden_connect_stash {
	__u32 family;                     /* AF_INET / AF_INET6, already validated */
	__u32 proto;                      /* sk_protocol as read at entry (0 = no claim) */
	__u32 port;                       /* destination port, host byte order */
	__u8  daddr[WARDEN_ADDR_LEN];     /* destination address, network byte order */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct warden_connect_stash);
} connect_pending SEC(".maps");

/* ── the accept pair's stash (stage 16) ──────────────────────────────────────
 * One field, because the accept is the opposite shape from the dial: a dial's
 * destination exists on the way in and its verdict only on the way out, but an
 * accept's ENTIRE flow identity — peer address, peer port, local port, transport,
 * namespace — exists only on the way out, in the child socket the protocol layer
 * has just filled. So the entry half carries nothing but the pointer to that
 * child, and the return half reads everything from it.
 *
 * Same key discipline as connect_pending: the full pid_tgid word, so two hosts of
 * the same tid in different PID namespaces cannot collide, drained by the return
 * probe even when it is about to emit nothing (see warden_on_flow). 4096 entries
 * against a measured peak of 3 outstanding accepts on the deployment host is the
 * same generous margin, for the same reason — a full map costs a record, not a
 * connection. */
struct warden_accept_stash {
	struct socket *newsock; /* the socket accept(2) is filling — set by the caller of inet_accept */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct warden_accept_stash);
} accept_pending SEC(".maps");

/* ── the network volume totals (N-05, stage 16b) ───────────────────────────
 *
 * Keyed by the cgroup id the sending/receiving task was in at that instant —
 * monotone, never recycled, and already the identity a containerised deployment
 * is managed by. `struct warden_net_volume` in warden.h carries the full argument
 * for why neither a flow key nor a pid key was used; both were rejected because
 * nothing in this hook set sees a close, so a stale total would be inherited by
 * whoever got the identity next.
 *
 * A plain hash, not a per-CPU one: the entry has to be shared for the total to
 * mean anything, and the update path is a handful of atomic adds against one
 * 40-byte value. On the deployment host's measured traffic (≈1 active connect
 * per 107 s, ≈3.9 accepts per second on a busy listener) that is not a contended
 * lock, and the live stage of this runbook measures the difference rather than
 * assuming it.
 *
 * max_entries is the coverage bound: past 512 distinct cgroups the oldest
 * tenants keep their frozen totals while new ones are refused, and every refusal
 * is charged to WARDEN_NETVOLUME_FULL below so the reader says "incomplete"
 * instead of printing a smaller number. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, WARDEN_NET_VOLUME_MAX);
	__type(key, __u64);
	__type(value, struct warden_net_volume);
} net_volume SEC(".maps");

/* Health of the map itself: [0] bumps refused for want of a slot, [1] bumps that
 * landed. Without [1], "no cgroups have totals" is ambiguous between a host that
 * moved nothing and six fexit programs that never attached — the same
 * dead-versus-quiet ambiguity W2K-14 removed for the ring, removed here for the
 * counter path. Per-CPU so reporting health never costs the data path a lock. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, WARDEN_NETVOLUME_STATS);
	__type(key, __u32);
	__type(value, __u64);
} net_volume_stats SEC(".maps");

/* ── helpers ───────────────────────────────────────────────────────────── */

/* Fill the actor identity block that every event carries. Reads the current
 * task via CO-RE so it survives struct layout changes across kernels. */
static __always_inline void fill_actor(struct warden_event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid  = bpf_get_current_uid_gid();

	e->actor_pid = pid_tgid >> 32;
	e->actor_tid = (__u32)pid_tgid;
	e->actor_uid = (__u32)uid_gid;
	e->actor_ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->ts_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* Stamp the actor's executable FILE, not its name, into the record's two spare
 * __u64 slots (cap_old = super_block dev, cap_new = inode number).
 *
 * Why in the kernel: `/proc/<pid>/exe` is read by userspace some milliseconds
 * after the event, and a short-lived actor is gone by then — which is the normal
 * shape of a loader, not an anomaly (W2K-29). At that point the only identity
 * left on the record is `comm`, a string the process chose for itself with
 * prctl(PR_SET_NAME). Here, inside the hook, the task is alive by construction
 * and its `mm->exe_file` is the file the kernel is actually running, so the
 * (dev,ino) pair names that file even after the task exits and even when a
 * `hidepid=` mount denies /proc. Userspace matches it against the inode of each
 * authorized path — a claim that survives the death of the process it describes.
 *
 * Nothing is claimed when there is nothing to read: a kernel thread has no mm,
 * and an ino of 0 is what `guard_inode` already treats as "no identity" (anon /
 * pseudo-fs inodes). Leaving BOTH slots zero is the no-claim encoding, so a
 * record from an older object — which never stamped them — decodes as unknown
 * and the caller keeps its previous, weaker evidence rather than reading a
 * fabricated inode 0. These two slots are free for the kinds that call this;
 * see the per-kind field map in warden.h. */
static __always_inline void fill_exe_inode(struct warden_event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct mm_struct *mm = BPF_CORE_READ(task, mm);

	if (!mm)
		return;

	struct file *exe = BPF_CORE_READ(mm, exe_file);

	if (!exe)
		return;

	__u64 ino = BPF_CORE_READ(exe, f_inode, i_ino);

	if (ino == 0)
		return;

	e->cap_old = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	e->cap_new = ino;
}

static __always_inline bool pid_is_protected(__u32 tgid)
{
	return bpf_map_lookup_elem(&protected_pids, &tgid) != NULL;
}

/* Pack a network record's aux2: address family in bits 0..15, transport in bits
 * 16..23, and (for the connect-outcome kind only) the outcome in bits 24..31.
 * One helper for all three producers so they cannot drift apart from each other
 * or from the decoder's masks — the family is masked on the way in for exactly
 * that reason, so a producer cannot spill into the transport field by accident.
 *
 * `sk_protocol` is a u16 in the kernels this object is built for (the field was
 * widened from u8), while the transport field on the wire is 8 bits because every
 * real IPPROTO_* number fits there. A value that does not fit is stamped as 0 —
 * "no claim" — rather than truncated into a different transport: `other` would be
 * an assertion about a protocol the record cannot carry. */
static __always_inline __u32 warden_net_aux2_ex(__u32 family, __u16 proto, __u8 outcome)
{
	if (proto > 0xFFu)
		return (family & WARDEN_NET_FAMILY_MASK) |
		       ((__u32)outcome << WARDEN_NET_RESULT_SHIFT);
	return (family & WARDEN_NET_FAMILY_MASK) |
	       ((__u32)proto << WARDEN_NET_PROTO_SHIFT) |
	       ((__u32)outcome << WARDEN_NET_RESULT_SHIFT);
}

static __always_inline __u32 warden_net_aux2(__u32 family, __u16 proto)
{
	return warden_net_aux2_ex(family, proto, WARDEN_CONNECT_NO_CLAIM);
}

/* The transport the socket carries, read off the socket rather than off the
 * syscall: `connect(2)` says nothing about it. A missing `sk` gives 0, which this
 * ABI means as "no claim", never as a protocol. */
static __always_inline __u16 warden_sock_proto(struct socket *sock)
{
	struct sock *sk = BPF_CORE_READ(sock, sk);

	if (!sk)
		return 0;
	return BPF_CORE_READ(sk, sk_protocol);
}

/* Copy a dial's destination endpoint out of a sockaddr: the port in host order,
 * the address verbatim in network order (so userspace's big-endian
 * `Ipv4Addr::from`/`Ipv6Addr::from` read them right). Shared by the two sensors
 * that see the same destination at two different moments — the attempt and its
 * result — because those two records must agree byte-for-byte or the correlation
 * in userspace is a guess. `family` is the caller's already-checked AF_INET /
 * AF_INET6; anything else never reaches here. */
static __always_inline void warden_read_dst(struct sockaddr *address, __u32 family,
					   __u32 *port, __u8 *daddr)
{
	if (family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)address;
		__be32 be_addr = BPF_CORE_READ(in, sin_addr.s_addr);

		*port = bpf_ntohs(BPF_CORE_READ(in, sin_port));
		__builtin_memset(daddr, 0, WARDEN_ADDR_LEN);
		__builtin_memcpy(daddr, &be_addr, sizeof(be_addr));
	} else { /* AF_INET6 */
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)address;

		*port = bpf_ntohs(BPF_CORE_READ(in6, sin6_port));
		BPF_CORE_READ_INTO(daddr, in6, sin6_addr.in6_u.u6_addr8);
	}
}

/* ── 1. exec: the RCE / reverse-shell tripwire (T1) ──────────────────────── */

SEC("tp/sched/sched_process_exec")
int warden_on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	if (!sensor_emitting(CFG_EXEC_EMIT))
		return 0; /* exec sensor muted (learning window) */

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_EXEC); /* ring full: drop, don't block. */
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_EXEC;
	fill_actor(e);

	/* The executed path lives in the tracepoint's __data area at the offset
	 * packed into the low 16 bits of __data_loc_filename. Read it best-effort;
	 * a truncated/failed read just leaves filename[] zeroed. */
	unsigned short off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
				  (void *)ctx + off);

	count_submit(WARDEN_EXEC);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 2. signal to a protected pid: the takedown tripwire (T8) ────────────── */
/*
 * security_task_kill(struct task_struct *p, struct kernel_siginfo *info,
 *                    int sig, const struct cred *cred)
 * Fires for signals delivered via the LSM path. We only emit when the TARGET
 * is one of our protected pids — a SIGKILL/STOP/TERM at Sentinel or Warden.
 */
SEC("kprobe/security_task_kill")
int BPF_KPROBE(warden_on_task_kill, struct task_struct *p, void *info, int sig)
{
	__u32 target = BPF_CORE_READ(p, tgid);
	if (!pid_is_protected(target))
		return 0;

	/* Not every signal that reaches this hook is a takedown attempt.
	 * kill(pid, 0) is the standard "may I signal you?" probe and arrives here
	 * with sig == 0; kernel-generated signals (the OOM killer, force_sig) pass
	 * the SEND_SIG_NOINFO / SEND_SIG_PRIV sentinels — NULL or (void *)1 —
	 * instead of a userspace siginfo. Report neither: a protected process
	 * killed by the kernel's own OOM path is the host defending itself, and a
	 * zero-signal permission probe must never look like an attack.
	 *
	 * What IS left is user-aimed traffic, and the siginfo says which call aimed
	 * it — kill(2) against a process, tkill(2)/abort() inside one, sigqueue(3)
	 * with a payload, a posix timer armed to fire later. That distinction is
	 * evidence userspace cannot rebuild afterwards, so read si_code HERE, at the
	 * hook, where the pointer is still valid (W2K-04; see the define in warden.h
	 * for why a kernel-GENERATED signal never reaches this hook at all). */
	if (sig <= 0 || (unsigned long)info < 4096UL)
		return 0;

	/* BPF_CORE_READ takes the offset from BTF rather than trusting a hardcoded
	 * +8, and it yields 0 when the read fails — 0 is SI_USER, i.e. the attack
	 * class. Guessing anything gentler would hide a real takedown. */
	int si_code = BPF_CORE_READ((struct kernel_siginfo *)info, si_code);
	__u32 delivery = WARDEN_SIGDELIV_USER;
	if (si_code == WARDEN_SI_TKILL)
		delivery = WARDEN_SIGDELIV_TKILL;
	else if (si_code == WARDEN_SI_QUEUE)
		delivery = WARDEN_SIGDELIV_QUEUE;
	else if (si_code == WARDEN_SI_TIMER)
		delivery = WARDEN_SIGDELIV_TIMER;
	else if (si_code == WARDEN_SI_MESGQ)
		delivery = WARDEN_SIGDELIV_MESGQ;
	else if (si_code == WARDEN_SI_ASYNCIO)
		delivery = WARDEN_SIGDELIV_ASYNCIO;
	else if (si_code == WARDEN_SI_SIGIO)
		delivery = WARDEN_SIGDELIV_SIGIO;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_SIGNAL);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_SIGNAL;
	fill_actor(e);
	e->target_pid = target;
	e->aux = sig;
	/* Tell userspace the one thing only the hook can still see: whether the
	 * sender parents the victim. By the time this record is read, a SIGKILLed
	 * target may be gone and its ppid unknowable. */
	if (BPF_CORE_READ(p, real_parent, tgid) == (__u32)(bpf_get_current_pid_tgid() >> 32))
		e->aux2 |= WARDEN_SIGNAL_FROM_PARENT;
	/* Which call aimed the signal, in the bits above the parent flag. Userspace
	 * reads this together with actor vs target: SI_TKILL from the victim's own pid
	 * is abort()/raise() — a crash — while SI_USER from another pid is a kill. */
	e->aux2 |= (delivery << WARDEN_SIGNAL_DELIVERY_SHIFT) & WARDEN_SIGNAL_DELIVERY_MASK;

	count_submit(WARDEN_SIGNAL);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 3. ptrace of a protected pid: inspect/inject tripwire (T7/T8) ───────── */
/*
 * security_ptrace_access_check(struct task_struct *child, unsigned int mode)
 * The would-be tracer is `current` (the actor); `child` is the target.
 */
SEC("kprobe/security_ptrace_access_check")
int BPF_KPROBE(warden_on_ptrace, struct task_struct *child, unsigned int mode)
{
	__u32 target = BPF_CORE_READ(child, tgid);
	if (!pid_is_protected(target))
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_PTRACE);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_PTRACE;
	fill_actor(e);
	e->target_pid = target;
	e->aux = mode;

	count_submit(WARDEN_PTRACE);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 4. outbound connect: the C2 / reverse-shell dial-out tripwire (T1/T4) ── */
/*
 * security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
 * The LSM hook fires on every connect(2) before it leaves the box, for the
 * connecting task (`current` = the actor). We record the destination for TCP/UDP
 * over IPv4/IPv6 and leave the verdict — is this egress sanctioned? — entirely to
 * userspace, which holds the allowlist. The kernel side stays a dumb recorder.
 *
 * Unlike signal/ptrace we do NOT filter on a protected set here: the interesting
 * actor is the app reaching *out*, not a victim being reached. Emitting every
 * connect would be noisy, so this sensor is gated by CFG_CONNECT_EMIT and the
 * app-cgroup attribution in userspace narrows it to app-initiated egress.
 */
SEC("kprobe/security_socket_connect")
int BPF_KPROBE(warden_on_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	if (!sensor_emitting(CFG_CONNECT_EMIT))
		return 0;

	/* Only inet families carry a routable destination worth judging; unix
	 * sockets, netlink, etc. are local plumbing. Read the family first and
	 * bail cheaply on everything else so the common case adds ~one read. */
	sa_family_t family = BPF_CORE_READ(address, sa_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	/* The dial's protocol is what makes this record usable as a flow: without it
	 * a UDP dial to 8.8.8.8:53 and a TCP one to the same endpoint arrive
	 * byte-identical. Read it off the socket, not off the syscall — `connect(2)`
	 * says nothing about transport. A missing sk stamps 0, which this ABI means
	 * as "no claim", never as a protocol.
	 *
	 * `sk_protocol` is a real BTF member of struct sock on both kernels this
	 * stage was verified against (see the header's note on the accessor). */
	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_CONNECT);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_CONNECT;
	fill_actor(e);
	e->aux2 = warden_net_aux2(family, warden_sock_proto(sock));
	warden_read_dst(address, family, &e->aux, e->daddr);

	count_submit(WARDEN_CONNECT);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 4b. the dial's RESULT: what the network actually did (N-02) ─────────── */
/*
 * __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len,
 *                       int flags, int is3) is where a TCP connect learns its
 * verdict: `sk_stream_wait_connect()` has returned and the errno is the
 * transport's answer. This is the ONLY place in the current sensor set that can
 * distinguish "the C2 dial connected" from "it was refused", so it is worth a
 * second pair of programs — and only a pair, because the endpoint has to be read
 * on the way in and the verdict only exists on the way out.
 *
 * Why this function and not `security_socket_connect`'s return: that hook returns
 * the *LSM verdict*, not the transport outcome — a kretprobe there would report
 * success for a dial that never left the box. Why not `inet_stream_connect`
 * (its caller, also measured): both were probed on the deployment kernel and both
 * carry the same retval, so the inner one is chosen for being closer to the
 * transport and further from any future wrapper. Why not fexit: a BTF-type attach
 * takes its argument list from the target's BTF, which is precisely the N-14
 * hazard on a kernel that has not been surveyed; kprobe/kretprobe read registers
 * positionally and the retval is register-only.
 *
 * What this CANNOT see, and what the design therefore refuses to claim (all of it
 * measured with a throwaway kretprobe on the deployment kernel; see the header
 * note on enum warden_connect_outcome):
 *   - a non-blocking dial in flight. It returns -EINPROGRESS here, and 91% of the
 *     live production connects in a 60 s sample were exactly that shape — because
 *     "connect with a timeout" is implemented as non-blocking + poll by the
 *     stacks this box actually runs. No record is emitted: the outcome is not yet
 *     known, and "unknown" recorded as "refused" would be the fabrication this ABI
 *     is built to prevent.
 *   - UDP. `connect(2)` on a datagram socket only sets a tuple and returns 0, so
 *     this stream-only path never sees it; the transport byte from stage 13 is
 *     what keeps a UDP dial from being read as a TCP one.
 *   - a dial that never returns (a task killed while blocked in connect). Its
 *     stash entry is not reaped on task exit — there is no hook here for one — so
 *     it stays until a recycled pid_tgid overwrites it (the entry probe updates
 *     with BPF_ANY) or the map fills. A full map makes the update fail, and the
 *     dial then produces no verdict record: 4096 live dials in flight at once is
 *     the bound, and losing the verdict is not losing the dial, which CONNECT
 *     still reported.
 */
SEC("kprobe/__inet_stream_connect")
int BPF_KPROBE(warden_on_connect_start, struct socket *sock, struct sockaddr *address,
	       int addrlen)
{
	if (!sensor_emitting(CFG_CONNECT_RESULT_EMIT))
		return 0; /* outcome sensor muted: stash nothing */

	sa_family_t family = BPF_CORE_READ(address, sa_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct warden_connect_stash st = {};

	st.family = family;
	st.proto = warden_sock_proto(sock);
	warden_read_dst(address, family, &st.port, st.daddr);

	/* The full pid_tgid word, not just the tid: two hosts of the same tid in
	 * different PID namespaces cannot collide on it, and the return probe reads
	 * the same word from the same task. */
	__u64 key = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&connect_pending, &key, &st, BPF_ANY);
	return 0;
}

/* Classify a terminal retval. Numbers come from the codes this hook was measured
 * returning, plus the ones a blocking connect can reach on timeout or teardown.
 * Anything still in flight, or any shape this hook does not produce, is
 * NO_CLAIM — which the caller treats as "emit nothing", never as a category. */
static __always_inline __u8 warden_connect_outcome(long rc)
{
	switch (rc) {
	case 0:                return WARDEN_CONNECT_ESTABLISHED;
	case -ECONNREFUSED:    return WARDEN_CONNECT_REFUSED;
	case -ETIMEDOUT:       return WARDEN_CONNECT_TIMEOUT;
	case -EHOSTUNREACH:
	case -ENETUNREACH:     return WARDEN_CONNECT_UNREACHABLE;
	case -EACCES:
	case -EPERM:           return WARDEN_CONNECT_BLOCKED;
	case -ECONNRESET:
	case -ECONNABORTED:
	case -EPIPE:           return WARDEN_CONNECT_ABORTED;
	case -EINTR:           return WARDEN_CONNECT_INTERRUPTED;
	case -EAGAIN:          return WARDEN_CONNECT_WOULD_BLOCK;
	case -EISCONN:         return WARDEN_CONNECT_ALREADY;
	case -EINPROGRESS:     /* in flight — no verdict yet */
	case -EALREADY:        /* in flight, and a second non-blocking connect on it */
		return WARDEN_CONNECT_NO_CLAIM;
	default:
		/* A positive retval is not a shape this hook produces; reporting it as
		 * a failure would be a claim about a value we cannot interpret. */
		if (rc < 0)
			return WARDEN_CONNECT_FAILED_OTHER;
		return WARDEN_CONNECT_NO_CLAIM;
	}
}

SEC("kretprobe/__inet_stream_connect")
int BPF_KRETPROBE(warden_on_connect_result, long rc)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct warden_connect_stash *st = bpf_map_lookup_elem(&connect_pending, &key);

	if (!st)
		return 0; /* entry half never stashed: muted, or not an inet dial */

	/* Take the copy and retire the entry BEFORE any early return. Draining even
	 * when the sensor has been muted in-flight is what keeps a recycled tid from
	 * later being handed someone else's destination. */
	struct warden_connect_stash dialed = *st;

	bpf_map_delete_elem(&connect_pending, &key);

	if (!sensor_emitting(CFG_CONNECT_RESULT_EMIT))
		return 0;

	/* The kernel returns an `int`; the kretprobe hands back the whole 64-bit
	 * register, so -ECONNREFUSED arrives as 0xFFFFFF93 and every failure would
	 * classify as NO_CLAIM — a sensor that silently reports nothing. Measured
	 * directly: the raw word for a non-blocking dial on the deployment kernel is
	 * 4294967181, i.e. 0x100000000 − 115 for -EINPROGRESS, so the value is
	 * ZERO-extended there rather than sign-extended. Truncating to 32 bits and
	 * letting the compiler sign-extend is correct for both shapes, which matters
	 * because which shape a kernel gives is not something this object verifies. */
	rc = (int)rc;

	__u8 outcome = warden_connect_outcome(rc);

	if (outcome == WARDEN_CONNECT_NO_CLAIM)
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_CONNECT_RESULT);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_CONNECT_RESULT;
	fill_actor(e);
	e->aux2 = warden_net_aux2_ex(dialed.family, (__u16)dialed.proto, outcome);
	e->aux = dialed.port;
	__builtin_memcpy(e->daddr, dialed.daddr, sizeof(dialed.daddr));

	count_submit(WARDEN_CONNECT_RESULT);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 4c. the inbound ACCEPT: who was let in (N-03 accept half, N-04, N-12) ─── */
/*
 * inet_accept(struct socket *sock, struct socket *newsock, int arg) is where a
 * TCP accept stops being a syscall and becomes a socket: by the time it returns,
 * the protocol layer has installed the child `sk` and filled its 4-tuple, and
 * `current` is still the task that called accept(2). That combination is exactly
 * what no other program in this object sees — LISTEN knows the door exists and
 * CONNECT only ever looks outward — so this is the sensor that turns "something
 * is listening on 8200" into "postgres accepted 10.0.0.7:51344 on 8200".
 *
 * Why not the obvious hook. `security_socket_accept(sock, newsock)` is the LSM
 * chokepoint, stable across kernels, and already the attach target of two other
 * sensors here. Measured with a throwaway kprobe/kretprobe pair on the deployment
 * kernel (6.12.107+deb13-amd64), it cannot answer the question: the hook runs
 * BEFORE `sock->ops->accept()`, so the child carries no socket at all — 2021 of
 * 2021 entry calls and 2184 of 2184 return calls read `newsock->sk == NULL`. A
 * FLOW record from there would have no peer address, no port, no namespace: the
 * stable hook is the one with nothing to say. `inet_accept` is one layer down and
 * returns the truth. Its signature (vlen=3) and its presence in kallsyms were
 * verified on both kernels this stage was checked against, and it is non-
 * blacklisted (a kprobe attached and fired).
 *
 * Why a pair at all, when everything readable is readable at the return: the
 * kretprobe is handed only the return register and the task, never the arguments,
 * so the child pointer must be caught on the way in. The stash is a pointer
 * across a function boundary, which is the part of this design worth stating
 * plainly: `newsock` is allocated by the syscall wrapper before the call and
 * released by it afterwards, so it is live at the return for every observed
 * shape — including the -EAGAIN returns, where following the pointer yielded
 * `sk == NULL` (the probe's child-null counter tracked the -EAGAIN count exactly,
 * 32 and 32 at the end of the run) rather than a fault. The read is a bounded
 * probe-read (see the comment at the dereference), so a kernel that proved the
 * pointer wrong gets silence rather than a record — and that path was not
 * theoretical: the FIRST version of this program was rejected at load on the
 * deployment kernel, because it relocated through the stash's own struct instead of
 * through `struct socket`. `bpftool prog loadall` found it; LIVE_VALIDATION.md §18
 * step 1 is how to reproduce that check.
 *
 * What this CANNOT see, so the platform never infers it from a missing record:
 *   - UDP "flows". inet_accept is stream-only; a datagram socket has no accept.
 *     The transport byte from the record is what keeps the two apart downstream.
 *   - the close, and therefore duration or bytes. This is a transition sensor: it
 *     reports the moment a flow exists, and stage 15's pull path is what reports
 *     which flows still exist. Neither one alone is a connection table.
 *   - a socket accepted by a family other than inet, and an accept from a task
 *     that returned before we could drain — the entry probe stashes and the return
 *     probe deletes, always, in that order.
 */
SEC("kprobe/inet_accept")
int BPF_KPROBE(warden_on_accept_start, struct socket *sock, struct socket *newsock, int arg)
{
	if (!sensor_emitting(CFG_FLOW_EMIT))
		return 0; /* flow sensor muted: stash nothing, and the return half emits nothing */

	/* Filter on the LISTENER's family, not the child's: at entry the child has no
	 * socket yet (that is the whole reason for the pair). This is a correctness
	 * guard, not a cost saving — measured on the deployment host, 798 of 798 entry
	 * calls passed it, because `inet_accept` IS the inet accept op and a unix or
	 * netlink listener never reaches it (they have their own accept functions). So
	 * the claim "this filter avoids a map update per unix-socket handshake" would be
	 * false, and it is left out deliberately; what the check does is refuse to
	 * stash a child whose address bytes this program cannot interpret. */
	sa_family_t family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct warden_accept_stash st = { .newsock = newsock };
	__u64 key = bpf_get_current_pid_tgid();

	bpf_map_update_elem(&accept_pending, &key, &st, BPF_ANY);
	return 0;
}

SEC("kretprobe/inet_accept")
int BPF_KRETPROBE(warden_on_flow, long rc_in)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct warden_accept_stash *st = bpf_map_lookup_elem(&accept_pending, &key);

	if (!st)
		return 0; /* entry half never stashed: muted, or not an inet accept */

	/* Copy and retire BEFORE any early return — the rule the dial's return probe
	 * runs on too: a drained map cannot later hand a recycled tid someone else's
	 * socket pointer. */
	struct warden_accept_stash taken = *st;

	bpf_map_delete_elem(&accept_pending, &key);

	if (!sensor_emitting(CFG_FLOW_EMIT))
		return 0;

	/* `(int)` for the same reason warden_on_connect_result truncates: the kretprobe
	 * hands back the whole 64-bit register and the deployment kernel zero-extends
	 * the errno there, so -EAGAIN arrives as 0xFFFFFF93. Only the comparison to
	 * zero matters here — a non-zero register is a non-zero int in either
	 * extension — and an accept that failed produced no flow, so it must produce
	 * no record. In the sampled production traffic on the deployment kernel that
	 * was 157 of 4008 inet_accept() returns (3.9%, all -EAGAIN). */
	if ((int)rc_in != 0)
		return 0;

	/* The child socket, read WITHOUT BPF_CORE_READ over the stash field.
	 *
	 * `BPF_CORE_READ(taken.newsock, sk)` does not load: the access-index builtin
	 * emits a relocation for the WHOLE chain, and its first link is
	 * `struct warden_accept_stash.newsock` — a type that exists only in this
	 * object, never in kernel BTF, so libbpf cannot resolve it and the kernel
	 * rejects the program with -EINVAL ("failed to resolve CO-RE relocation
	 * <byte_off> struct warden_accept_stash.newsock", measured on
	 * 6.12.107+deb13-amd64 with `bpftool prog loadall`). That is a load-time
	 * failure, not a missing field: the loader is fail-closed (N-14), so the whole
	 * agent would refuse to start over one relocation.
	 *
	 * The stash member is therefore taken as a plain 8-byte load — it is the
	 * program's own map value, no relocation needed — and only `struct socket.sk`,
	 * which IS a kernel type, is relocated, through bpf_core_read() so a bad
	 * pointer returns an error the probe can refuse rather than a fault. */
	struct socket *newsock = taken.newsock;
	struct sock *sk = NULL;

	if (bpf_core_read(&sk, sizeof(sk), &newsock->sk))
		return 0; /* the stashed pointer is not readable at the return: say nothing */

	if (!sk)
		return 0; /* accepted with no child: a shape this kernel did not produce */

	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family != AF_INET && family != AF_INET6)
		return 0;

	/* The peer, in the byte order the kernel holds it: `skc_dport` is network
	 * order (unlike `skc_num`, which is already host order) and the address is
	 * copied verbatim so userspace's big-endian constructors read it right. Both
	 * were verified against a real loopback dial where the client knew its own
	 * source port — the record's port matched byte for byte. */
	__u32 peer_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	__u16 proto = BPF_CORE_READ(sk, sk_protocol);
	__u32 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);

	/* The namespace identity, by CO-RE: `bpf_get_netns_cookie()` is rejected for
	 * kprobe-type programs ("program of this type cannot use helper
	 * bpf_get_netns_cookie") and `struct net` has no `proc_inum` on this kernel,
	 * so `net->ns.inum` is the way to read it. This is the field that makes the
	 * sensor's extra reach legible: the kprobe is global, so accepts inside a
	 * container's netns are recorded here even though the /proc/net pull path
	 * reads only Warden's own namespace. Measured live on the deployment host
	 * with a counters-only copy of this program: the per-namespace counters of one
	 * run split 963 accepted flows over FIVE inodes — 753, 131, 56, 15, 8 — and the
	 * host's own (`/proc/self/ns/net` there: 4026531840, init_net) held only the
	 * 131, i.e. 86.4% of the accepts on that host happened on sockets whose
	 * namespace the pull path cannot enumerate. The counts are per-inode, not
	 * per-container: which inode belongs to which workload is a userspace mapping
	 * this sensor does not guess. Without this field, those flows would arrive as
	 * host flows no host process owns. */
	__u32 net_inum = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e) {
		count_drop(WARDEN_FLOW);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_FLOW;
	fill_actor(e);
	/* Same three fields a dial uses, so `dest` renders with the one formatter both
	 * the push and the pull path compare. Outcome bits stay 0 — an accepted flow
	 * is not a verdict about a SYN. */
	e->aux2 = warden_net_aux2(family, proto);
	e->aux = peer_port;
	e->target_pid = local_port;
	e->cap_old = net_inum;

	if (family == AF_INET) {
		__be32 be_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

		__builtin_memcpy(e->daddr, &be_addr, sizeof(be_addr));
	} else { /* AF_INET6 */
		BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}

	count_submit(WARDEN_FLOW);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── network volume counters (N-05, stage 16b) ─────────────────────────────
 *
 * Not a sensor in the ring sense: nothing here reserves or submits. The fexit
 * programs add to a bounded hash of per-cgroup totals, and userspace reads the
 * totals on a timer. The reason is cost shape — see the long comment on `struct
 * warden_net_volume` in warden.h: an operator who wants byte volume cannot get it
 * from a lossy ring at 344 bytes per ~10-byte fact, and a map write on the data
 * path does not touch userspace at all.
 *
 * The hook set and each function's shape were MEASURED on the deployment kernel
 * (6.12.107+deb13-amd64), not taken from the design note that named them, and
 * the note was wrong in a way that would have failed the verifier: it described
 * `tcp_sendmsg` as taking the socket's `struct socket *`. BTF says
 * `int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)`, and every
 * target takes `struct sock *` first:
 *   tcp_sendmsg       ret = bytes queued into the send buffer, or -errno
 *   tcp_cleanup_rbuf  void; arg `copied` = bytes handed to the reader
 *   udp_sendmsg       ret = bytes handed to the datagram path, or -errno
 *   udp_recvmsg       ret = bytes copied out of ONE datagram, or -errno
 *   udpv6_sendmsg     the AF_INET6 twin of udp_sendmsg (same proto op shape)
 *   udpv6_recvmsg     the AF_INET6 twin of udp_recvmsg (same proto op shape)
 * The first four were present in /sys/kernel/tracing/available_filter_functions
 * on the deployment kernel (the list that decides whether a trampoline can be
 * installed at all), and §24 of LIVE_VALIDATION.md recorded the two `udpv6_*`
 * names there too; all six are global in /proc/kallsyms. BTF records them with
 * `linkage=static`, which is not an obstacle — the attach is by BTF func id and
 * the ftrace location exists — but it is why "is it a real symbol" was not the
 * question worth answering, and "is it filter-able" was.
 *
 * WHAT IS NOT COVERED, so the reader can say it out loud instead of letting a
 * small number read as a measurement:
 *   - IPv6 datagrams bypassed BOTH original datagram hooks, which §23 measured
 *     rather than assumed: 102400 B sent and 95232 B received over `[::1]` produced
 *     no `net_volume` line in two independent runs, while the byte-for-byte IPv4
 *     twin produced `out 102400B/100 ops, in 95232B/93 ops`. This revision adds
 *     `fexit/udpv6_sendmsg` and `fexit/udpv6_recvmsg` to close that family gap.
 *     ATTACHMENT AND COUNTING OF THE NEW PROGRAMS ARE NOT ESTABLISHED by this
 *     source change: no privileged host test was run here, so the honest status is
 *     `IMPLEMENTED_NOT_VALIDATED_LIVE`, not "covered". Stream traffic had no such
 *     gap — 1 MiB over `tcp6` was counted both ways in §23, because
 *     `tcp_sendmsg`/`tcp_cleanup_rbuf` are address-family agnostic.
 *   - A `recvmsg` that PEEKs counts, and §23 measured how much: 1024 bytes
 *     delivered by peek-then-read were recorded as `in 2048B/2 ops`. Both ingress
 *     hooks use the same rule ("bytes copied to userspace by a receive call"); a
 *     poller that peeks at one datagram repeatedly inflates `bytes_in` accordingly.
 *   - Anything that does not pass through these six functions: retransmits
 *     (accounted lower, where the sk_buff is queued to the device), zero-copy
 *     readers, AF_PACKET capture, XDP redirect.
 *   - Wire bytes, and the gap runs in BOTH directions. IP/TCP headers and
 *     retransmitted segments are added below these functions and are not in the
 *     totals; a userspace TLS library's record framing is handed to sendmsg() as
 *     payload and so IS in them. A total is therefore neither an interface
 *     counter nor a count of plaintext — warden.h gives both inequalities.
 *   - Kernel TLS (kTLS) is NOT characterised by this build: whether its send
 *     path reaches an fexit on tcp_sendmsg depends on the in-kernel record layer
 *     calling the tcp path directly rather than through the proto op, and no
 *     measurement here settles it. This deployment does not enable kTLS, so the
 *     question is recorded rather than answered. UNVERIFIED.
 *   - Per-flow and per-pid attribution, rejected on identity grounds (key
 *     recycling with no close hook) rather than on cost — warden.h explains both
 *     rejections.
 */

/* Refuse to track more cgroups than the map holds, and say so in a counter
 * rather than in a smaller total. A hash map write can fail for two reasons at
 * this site — the map really is full, or another CPU inserted this same cgroup
 * between our lookup and our update — and only the first is a coverage loss, so
 * the bump path re-looks-up before charging. */
static __always_inline void net_volume_stat(__u32 slot)
{
	if (slot >= WARDEN_NETVOLUME_STATS)
		return;
	__u64 *n = bpf_map_lookup_elem(&net_volume_stats, &slot);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* A completed fexit invocation is an observation even when the emit gate is
 * off or the cgroup map is full. Counting it here, before either condition, is
 * what separates "the probe ran and saw traffic" from "a total happened to
 * land". The six slots follow VolumeHook::ALL in net_vol.rs. */
static __always_inline void net_volume_invoke(__u32 slot)
{
	net_volume_stat(slot);
}

/* UDP receive returns the copied byte count EXCEPT under MSG_TRUNC, where
 * Linux v6.12 returns the original datagram length (`ulen`). Charging that
 * value would claim more bytes were copied than the caller's buffer could
 * hold. Capping every positive return at `len` makes the invariant true on
 * every kernel that uses either convention, and costs one compare. */
static __always_inline __u64 net_volume_recv_bytes(int ret, size_t len)
{
	if (ret <= 0)
		return 0;
	__u64 charged = (__u64)ret;
	__u64 capacity = (__u64)len;
	return charged < capacity ? charged : capacity;
}

/* Add `bytes` to this cgroup's total for one direction and count the operation.
 *
 * `bytes` is what the kernel actually accepted, never what the caller asked for:
 * a send that returned -EPIPE moves 0 bytes but is still one operation, and the
 * pair (ops high, bytes flat) is itself the tell for a process hammering a
 * closed socket. A negative return is charged as zero bytes, never as a huge
 * unsigned number — `__u64` would turn -ECONNRESET into an astronomically large
 * total, which is the kind of bug a counter map is supposed to make impossible.
 *
 * The gate is `sensor_emitting`, which fails OPEN: a runtime_cfg array that was
 * never seeded lets the counting continue. For this sensor that is the right
 * direction — an unseeded gate means Warden forgot to say "off", and a volume
 * total that exists but was not asked for costs a map write, while a total that
 * is missing is a coverage hole nobody can see. */
static __always_inline void net_volume_bump(int egress, __u64 bytes)
{
	if (!sensor_emitting(CFG_NET_VOLUME_EMIT))
		return;

	__u64 cg = bpf_get_current_cgroup_id();
	struct warden_net_volume *v = bpf_map_lookup_elem(&net_volume, &cg);

	if (!v) {
		struct warden_net_volume fresh = {};

		fresh.last_ns = bpf_ktime_get_ns();
		/* Ignore the return: the re-lookup below is the only question that
		 * matters. Either our insert won, or another CPU on this same cgroup
		 * beat us and its zeroed entry is just as good as ours — in which
		 * case BPF_NOEXIST failed with -EEXIST and we must not read that as
		 * "the map is full". Only a lookup that still returns NULL means the
		 * cgroup could not be tracked at all. */
		bpf_map_update_elem(&net_volume, &cg, &fresh, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&net_volume, &cg);
	}
	if (!v) {
		net_volume_stat(WARDEN_NETVOLUME_FULL);
		return;
	}

	if (egress) {
		__sync_fetch_and_add(&v->bytes_out, bytes);
		__sync_fetch_and_add(&v->ops_out, 1);
	} else {
		__sync_fetch_and_add(&v->bytes_in, bytes);
		__sync_fetch_and_add(&v->ops_in, 1);
	}
	/* A plain store, not an atomic add: two CPUs racing here produce either
	 * timestamp, and the reader only asks "is this cgroup still moving", for
	 * which any recent value is the right answer. */
	v->last_ns = bpf_ktime_get_ns();
	net_volume_stat(WARDEN_NETVOLUME_BUMP);
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(warden_vol_tcp_out, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
	net_volume_invoke(WARDEN_NETVOLUME_TCP_OUT);
	net_volume_bump(1, ret > 0 ? (__u64)ret : 0);
	return 0;
}

/* Ingress for a stream. `tcp_cleanup_rbuf` runs on the receive path once the
 * data has been copied out to the reader, and its `copied` argument is that
 * amount; this hook is deliberately the one Warden already knows exists as a
 * global symbol on this kernel. The guard on `copied` is ours, not a restating
 * of the kernel's: whatever the caller does, a completion that moved no bytes
 * adds no bytes here — but it still counts as an operation, because "was asked
 * and delivered nothing" is a fact about the path, not a measurement of zero. */
SEC("fexit/tcp_cleanup_rbuf")
int BPF_PROG(warden_vol_tcp_in, struct sock *sk, int copied)
{
	net_volume_invoke(WARDEN_NETVOLUME_TCP_IN);
	net_volume_bump(0, copied > 0 ? (__u64)copied : 0);
	return 0;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(warden_vol_udp_out, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
	net_volume_invoke(WARDEN_NETVOLUME_UDP_OUT);
	net_volume_bump(1, ret > 0 ? (__u64)ret : 0);
	return 0;
}

/* The third direction, and the reason `ops_in` is now a pair rather than a
 * stream-only count. Signature taken from the target kernel's own BTF: `struct
 * proto`'s `recvmsg` member is `int (*)(struct sock *, struct msghdr *, size_t,
 * int, int *)` (vmlinux.h:123350, generated from that kernel), and `udp_recvmsg`
 * is what the UDP proto assigns there — so five arguments plus the return value.
 * The older six-argument form (with `nonblock`) was folded away upstream; writing
 * this from memory of an older kernel is exactly the mistake §۳۹ made about
 * `tcp_sendmsg`, so the type came from the host's BTF, not from recollection.
 *
 * `ret` is the bytes copied into the reader's userspace for ONE datagram, UNLESS
 * the caller passed MSG_TRUNC: Linux v6.12 then returns the original datagram
 * length. `net_volume_recv_bytes(ret, len)` caps the charge at the caller's
 * buffer size, so a truncated read adds `len`, not `ulen`. A 1 MiB `readv` over
 * a queue of small datagrams still produces one bump per `recvmsg(2)` — the
 * same "operations, not packets" rule as the send side, reached from the other
 * end.
 *
 * MSG_PEEK IS NOT FILTERED, and that costs something an operator should know:
 * `flags` is right here, so a peek could be skipped, but then datagram ingress
 * would be counted by a different rule than stream ingress (`tcp_cleanup_rbuf`
 * has no flags argument at all, so filtering there is not available). The
 * definition shipped is the one both ingress hooks can share — bytes copied to
 * userspace by a receive call, peek included, because the copy really happened —
 * and the consequence is stated instead of hidden: a poller that peeks at the
 * same datagram twenty times has had those bytes copied twenty times, and this
 * counter says twenty — and §23 measured exactly that shape: a 1024-byte
 * datagram peeked and then read landed as `in 2048B/2 ops`.
 *
 * ATTACHED AND COUNTED on the deployment kernel (§23, 2026-11-02): the verifier
 * accepted this five-argument fexit, `bpftool prog list` showed four `warden_vol_*`
 * programs at the time, and a known IPv4 datagram transfer produced
 * `out 102400B/100 ops, in 95232B/93 ops` for its cgroup — the §22 reading of the
 * same test was `in 0B/0 ops`. It never sees an IPv6 datagram: that family's
 * sockets call `udpv6_recvmsg`, which is why the v6 twin follows below. */
SEC("fexit/udp_recvmsg")
int BPF_PROG(warden_vol_udp_in, struct sock *sk, struct msghdr *msg, size_t len, int flags,
	     int *addr_len, int ret)
{
	net_volume_invoke(WARDEN_NETVOLUME_UDP_IN);
	net_volume_bump(0, net_volume_recv_bytes(ret, len));
	return 0;
}

/* IPv6 datagram egress. §23 measured that an AF_INET6 datagram socket dispatches
 * through `udpv6_sendmsg`, not `udp_sendmsg`, and §24 confirmed the function is in
 * the kernel's ftrace attach list. The arguments restate the `struct proto::sendmsg`
 * prototype pinned in net_volume_abi.rs, the same shape as `udp_sendmsg`; the
 * verifier, not this comment, is the final authority on the deployed kernel.
 *
 * Same accounting rule as the v4 twin: `ret` is what the kernel accepted as this
 * call's payload, a negative return is charged as zero bytes but still one op,
 * and no event record is submitted. */
SEC("fexit/udpv6_sendmsg")
int BPF_PROG(warden_vol_udp6_out, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
	net_volume_invoke(WARDEN_NETVOLUME_UDP6_OUT);
	net_volume_bump(1, ret > 0 ? (__u64)ret : 0);
	return 0;
}

/* IPv6-socket-path datagram ingress. Same five-argument `struct proto::recvmsg`
 * shape as `udp_recvmsg` above, and the same rule: positive `ret` is capped at
 * `len` (MSG_TRUNC returns `ulen`), MSG_PEEK is deliberately not filtered (see
 * the v4 comment), and a completion that moved no bytes still counts as an
 * operation. An AF_INET6 socket may receive an IPv4-mapped datagram and this
 * hook cannot see skb->protocol at this point, so the honest claim is
 * IPv6-socket-path accounting, not pure IPv6 wire traffic.
 *
 * STATUS: IMPLEMENTED, NOT LIVE-VALIDATED. This build adds the program; it does
 * not add a measurement. A privileged lab run must confirm the verifier accepts
 * it, the hook attaches, and a known `[::1]` datagram lands in `net_volume`
 * before anyone calls this path "covered". */
SEC("fexit/udpv6_recvmsg")
int BPF_PROG(warden_vol_udp6_in, struct sock *sk, struct msghdr *msg, size_t len, int flags,
	     int *addr_len, int ret)
{
	net_volume_invoke(WARDEN_NETVOLUME_UDP6_IN);
	net_volume_bump(0, net_volume_recv_bytes(ret, len));
	return 0;
}

/* ── 5. commit_creds: the privilege-escalation tripwire (T5) ─────────────── */
/*
 * commit_creds(struct cred *new) is the single chokepoint every credential
 * change flows through — setuid, capset, a successful sudo, or an exploit that
 * overwrote a task's creds all land here to install `new` onto `current`. At the
 * probe entry the swap has not happened yet, so `current->real_cred` still holds
 * the OLD credentials and `new` holds what is about to take effect. Comparing the
 * two is how we catch "this task just became root" or "this task just gained
 * capabilities it didn't have."
 *
 * We emit only on a genuine RAISE — euid crossing to 0, or new effective caps —
 * never on a drop (root shedding privilege is normal and safe). Like connect,
 * there is no protected-set filter: the actor IS the subject, and every
 * privilege gain on the box is worth surfacing; userspace attributes it.
 */
SEC("kprobe/commit_creds")
int BPF_KPROBE(warden_on_commit_creds, struct cred *new)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	/* Old credentials: current->real_cred, still in place at probe entry. */
	__u32 old_euid = BPF_CORE_READ(task, real_cred, euid.val);
	__u64 cap_old  = BPF_CORE_READ(task, real_cred, cap_effective.val);

	/* New credentials about to be committed. */
	__u32 new_euid = BPF_CORE_READ(new, euid.val);
	__u64 cap_new  = BPF_CORE_READ(new, cap_effective.val);

	/* A raise is euid crossing INTO root, or effective caps we didn't hold
	 * before. Anything else (dropping privilege, unchanged creds) is not a
	 * tripwire — bail before touching the ring buffer to keep this cheap on the
	 * hot path commit_creds sits on. */
	bool became_root = (new_euid == 0 && old_euid != 0);
	bool gained_caps = (cap_new & ~cap_old) != 0;
	if (!became_root && !gained_caps)
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_CREDS);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_CREDS;
	fill_actor(e);
	e->aux     = new_euid;   /* new euid */
	e->aux2    = old_euid;   /* old euid */
	e->cap_old = cap_old;
	e->cap_new = cap_new;

	count_submit(WARDEN_CREDS);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 6. module_load: the rootkit / LKM-implant tripwire (T6) ─────────────── */
/*
 * tp/module/module_load fires after a kernel module is successfully loaded,
 * whichever path brought it in (init_module / finit_module / request_module).
 * A loaded module runs in ring 0 with total authority — the classic rootkit
 * vector — so on a locked-down production host, where the module set is fixed
 * at boot, ANY runtime load is worth surfacing. We record the module name and
 * the kernel's taint flags and, exactly like exec/connect/creds, leave the
 * verdict (is THIS module expected?) to userspace's allowlist. The kernel side
 * stays a dumb recorder.
 *
 * The module name lives in the tracepoint's __data area at the offset packed
 * into the low 16 bits of __data_loc_name, same shape as exec's filename.
 */
SEC("tp/module/module_load")
int warden_on_module_load(struct trace_event_raw_module_load *ctx)
{
	if (!sensor_emitting(CFG_MODULE_EMIT))
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_MODULE);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_MODULE;
	fill_actor(e);
	e->aux = ctx->taints; /* kernel taint flags carried by this module */

	unsigned short off = ctx->__data_loc_name & 0xFFFF;
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename),
				  (void *)ctx + off);

	count_submit(WARDEN_MODULE);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 7. file rename/unlink: the ransomware / tamper tripwire (T2/T9) ──────── */
/*
 * Ransomware, whatever else it does, has to commit its work to disk, and it does
 * that through one of two LSM chokepoints: it renames the ciphertext over the
 * victim file (…/report.docx → …/report.docx.locked), or it unlinks the original
 * after writing an encrypted copy. Both flow through security_inode_rename /
 * security_inode_unlink regardless of which syscall or libc wrapper was used, so
 * hooking here — rather than the far hotter per-write path — catches the
 * destructive step cheaply. We also catch a targeted tamper: an unlink/rename of
 * a file an operator marked sensitive (a keystore, an audit log).
 *
 * As everywhere, the kernel stays a dumb recorder: it captures the affected leaf
 * name and which op it was, and leaves every verdict — is this a ransom
 * extension? a sensitive path? a burst? — to userspace. The dentry's d_name is
 * the leaf only; the LSM hook doesn't hand us a cheap full path, and the leaf
 * carries the two signals we need (the new extension on a rename, the identity of
 * the removed file on an unlink).
 *
 * security_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
 *                       struct inode *new_dir, struct dentry *new_dentry, ...)
 * The NEW name is the tell (the attacker chose it), so we read new_dentry.
 */
SEC("kprobe/security_inode_rename")
int BPF_KPROBE(warden_on_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	       struct inode *new_dir, struct dentry *new_dentry)
{
	if (!sensor_emitting(CFG_FILE_EMIT))
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_FILE);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_FILE;
	fill_actor(e);
	e->aux = WARDEN_FILE_RENAME;

	/* d_name.name is a pointer to the leaf bytes; read the string it points at. */
	const unsigned char *name = BPF_CORE_READ(new_dentry, d_name.name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);

	count_submit(WARDEN_FILE);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * security_inode_unlink(struct inode *dir, struct dentry *dentry)
 * The removed file's name is what matters — that's the victim.
 */
SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(warden_on_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!sensor_emitting(CFG_FILE_EMIT))
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_FILE);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_FILE;
	fill_actor(e);
	e->aux = WARDEN_FILE_UNLINK;

	const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);

	count_submit(WARDEN_FILE);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 9. inode create: the persistence / boot-survival tripwire (T3) ───────── */
/*
 * Every durable foothold an attacker plants — a rogue systemd unit, a cron
 * entry, an XDG autostart .desktop, an init.d script, an ld.so.preload, an
 * extra key in authorized_keys — is ultimately a FILE that appears in a
 * well-known persistence directory. security_inode_create is the LSM chokepoint
 * every fresh regular file passes through (open(O_CREAT), creat, mknod of a
 * regular file), whatever syscall or tool created it, so hooking here catches
 * the drop itself rather than chasing each tool.
 *
 * The verdict — is THIS directory a persistence location, is THIS file
 * sanctioned? — is entirely userspace's, exactly like every sibling sensor. But
 * that verdict needs directory context, and the LSM hands us only the leaf
 * dentry. Rather than reconstruct a variable-length absolute path in the kernel
 * (a bounded d_parent loop the verifier merely tolerates), we capture a FIXED
 * ladder: the created leaf plus its three nearest ancestor directory names, one
 * per WARDEN_SVC_SLOT-byte cell of filename[]. That is a handful of
 * constant-offset CO-RE reads — no loop at all — and three ancestors is enough
 * depth to recognise every persistence dir that matters (…/systemd/system/x,
 * …/cron.d/x, …/autostart/x). Userspace joins the non-empty cells leaf-last.
 *
 * security_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
 * `dentry` is the new leaf; dir is its parent inode (we walk d_parent for names).
 */
SEC("kprobe/security_inode_create")
int BPF_KPROBE(warden_on_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	if (!sensor_emitting(CFG_SERVICE_EMIT))
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_SERVICE);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_SERVICE;
	fill_actor(e);
	e->aux = WARDEN_SERVICE_CREATE;

	/* Walk up a fixed, unrolled ladder of dentries. Each BPF_CORE_READ chain is
	 * a constant number of dereferences the verifier fully unrolls; a NULL or
	 * self-referential root just yields an empty/repeated cell userspace ignores.
	 * Cell 0 = leaf, 1 = parent, 2 = grandparent, 3 = great-grandparent. */
	struct dentry *d0 = dentry;
	struct dentry *d1 = BPF_CORE_READ(d0, d_parent);
	struct dentry *d2 = BPF_CORE_READ(d1, d_parent);
	struct dentry *d3 = BPF_CORE_READ(d2, d_parent);

	const unsigned char *n0 = BPF_CORE_READ(d0, d_name.name);
	const unsigned char *n1 = BPF_CORE_READ(d1, d_name.name);
	const unsigned char *n2 = BPF_CORE_READ(d2, d_name.name);
	const unsigned char *n3 = BPF_CORE_READ(d3, d_name.name);

	bpf_probe_read_kernel_str(&e->filename[0 * WARDEN_SVC_SLOT], WARDEN_SVC_SLOT, n0);
	bpf_probe_read_kernel_str(&e->filename[1 * WARDEN_SVC_SLOT], WARDEN_SVC_SLOT, n1);
	bpf_probe_read_kernel_str(&e->filename[2 * WARDEN_SVC_SLOT], WARDEN_SVC_SLOT, n2);
	bpf_probe_read_kernel_str(&e->filename[3 * WARDEN_SVC_SLOT], WARDEN_SVC_SLOT, n3);

	count_submit(WARDEN_SERVICE);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 10. socket listen: the bind-shell / backdoor-listener tripwire (T4) ───── */
/*
 * A reverse shell dials out (sensor 4 catches that); a *bind* shell does the
 * opposite — it opens a port and waits for the attacker to connect in. Whatever
 * the implant (a netcat listener, a planted sshd on an odd port, a webshell's
 * helper), it must put a socket into the LISTEN state, and every listen(2) flows
 * through security_socket_listen. Hooking listen rather than bind is deliberate:
 * a bind with no listen is ordinary client-socket source-port selection and pure
 * noise, whereas entering LISTEN is exactly the backdoor behaviour, and by the
 * time this LSM hook fires an explicit bind() has already populated the local
 * address/port we want to report.
 *
 * security_socket_listen(struct socket *sock, int backlog)
 * We read the bound local endpoint off the sock_common and, as everywhere, leave
 * the verdict — is THIS listener sanctioned? — to userspace's allowlist.
 */
SEC("kprobe/security_socket_listen")
int BPF_KPROBE(warden_on_listen, struct socket *sock, int backlog)
{
	if (!sensor_emitting(CFG_LISTEN_EMIT))
		return 0;

	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	/* Only inet listeners expose a routable service; unix/netlink listeners are
	 * local plumbing. Read the family first and bail cheaply on the rest. */
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	/* `listen(2)` means SOCK_STREAM, so this is TCP in practice — and it is still
	 * read from the socket rather than hardcoded: the record should say what the
	 * kernel holds, not what the syscall's contract implies. */
	__u16 proto = BPF_CORE_READ(sk, sk_protocol);

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_LISTEN);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_LISTEN;
	fill_actor(e);
	e->aux2 = warden_net_aux2(family, proto);
	/* skc_num is the local bound port already in host byte order (0 only in the
	 * rare autobind-at-listen case a real bind-shell never uses). */
	e->aux = BPF_CORE_READ(sk, __sk_common.skc_num);

	if (family == AF_INET) {
		__be32 be_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		__builtin_memcpy(e->daddr, &be_addr, sizeof(be_addr));
	} else { /* AF_INET6 */
		BPF_CORE_READ_INTO(&e->daddr, sk,
				   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
	}

	count_submit(WARDEN_LISTEN);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 11. bpf prog load: the eBPF-rootkit / stealth-hook tripwire (T6) ──────── */
/*
 * eBPF is now itself an implant vector: a program loaded into the kernel can
 * hide processes, tamper with syscall returns, sniff traffic, and mask its own
 * presence — all in ring 0, and all without a kernel module (so sensor 6 never
 * sees it). Every load flows through the bpf(2) syscall and its LSM gate
 * security_bpf. On a locked-down host the set of legitimate BPF loaders is tiny
 * and known, so surfacing each PROG_LOAD (with the loader attributed by
 * userspace) turns "someone just installed in-kernel code" into an event.
 *
 * Warden loads its own programs at startup BEFORE this probe is attached, so it
 * never trips itself; a later self-load would be attributed to comm="warden" and
 * can be allowlisted like any other loader.
 *
 * security_bpf(int cmd, union bpf_attr *attr, unsigned int size)
 * Only BPF_PROG_LOAD installs new code; map ops (lookup/update/…) are ordinary
 * and far too hot to surface, so we bail on them before the ring buffer.
 *
 * We also read attr->prog_type (the kind of program being loaded) into aux2, so
 * userspace can tell a stealth-capable implant (kprobe / tracepoint / xdp / lsm)
 * apart from the benign resource filters the init system loads all the time
 * (cgroup_skb / cgroup_device …). Distinguishing THOSE from a rootkit is the
 * whole point of the sensor — a bare "someone loaded a BPF program" fires on
 * every systemd service start. attr is the kernel-side copy the bpf(2) syscall
 * already populated, so a kernel read is correct.
 */
SEC("kprobe/security_bpf")
int BPF_KPROBE(warden_on_bpf, int cmd, union bpf_attr *attr)
{
	if (!sensor_emitting(CFG_BPF_EMIT))
		return 0;

	if (cmd != BPF_PROG_LOAD)
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_BPFLOAD);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_BPFLOAD;
	fill_actor(e);
	/* W2K-29's residual, closed at the only point it can be: the loader's
	 * executable identity is taken here, while the task is guaranteed alive, so
	 * a loader that exits before userspace enriches the record is still named by
	 * a file rather than by a name it picked for itself. */
	fill_exe_inode(e);
	e->aux = cmd; /* enum bpf_cmd; always BPF_PROG_LOAD here, carried for userspace */
	/* enum bpf_prog_type of the program being installed. On the PROG_LOAD path
	 * attr is non-NULL; a failed read degrades to 0 (UNSPEC), which userspace
	 * treats as "unknown type" and does NOT suppress — fail toward surfacing. */
	e->aux2 = BPF_CORE_READ(attr, prog_type);

	count_submit(WARDEN_BPFLOAD);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ── 12. mount: the container-escape / host-fs-exposure tripwire (T10) ─────── */
/*
 * A mount is how a contained attacker breaks containment: bind-mounting the host
 * root or /proc into the container, mounting the host's block device, or
 * over-mounting a sensitive path. Every mount(2) — whatever the flags or fs type
 * — passes through security_sb_mount. On a running production host mounts are
 * rare and almost always administrative, so surfacing each one (with the source
 * and flags) and letting userspace judge which are suspicious (a bind mount of a
 * host path, a mount landing inside an app/container cgroup) is cheap and high
 * signal.
 *
 * security_sb_mount(const char *dev_name, const struct path *path,
 *                   const char *type, unsigned long flags, void *data)
 * By this hook the syscall has copied dev_name/type into KERNEL memory, so we
 * read them with the kernel accessor. dev_name is the mount SOURCE — for a bind
 * mount, the host path being grafted in. That source is the tell userspace judges:
 * a bind of a watched host path (/dev, /etc, the container-runtime sockets) is the
 * escape shape, while a sandbox's own sub-mounts (under /oldroot, /proc/self/fd,
 * a systemd namespace staging dir) are rejected by prefix. We do NOT capture the
 * destination: a hardened systemd unit binds real host /dev nodes to the SAME
 * target path (/dev/null → /dev/null inside its private namespace), so the target
 * is not a reliable sandbox-vs-escape discriminator; the source allowlist is.
 */
SEC("kprobe/security_sb_mount")
int BPF_KPROBE(warden_on_sb_mount, const char *dev_name, const struct path *path,
	       const char *type, unsigned long flags)
{
	if (!sensor_emitting(CFG_MOUNT_EMIT))
		return 0;

	struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop(WARDEN_MOUNT);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = WARDEN_MOUNT;
	fill_actor(e);
	e->aux = (__u32)flags; /* low 32 bits of the MS_* mount flags (MS_BIND, …) */

	/* dev_name can be NULL (e.g. a remount or a virtual fs); leave filename empty
	 * in that case. It's a kernel string here, copied in by the mount syscall. */
	if (dev_name)
		bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), dev_name);

	count_submit(WARDEN_MOUNT);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ══ ENFORCING LAYER: BPF-LSM guards that can return -EPERM ══════════════════
 *
 * Everything above this line OBSERVES: a kprobe/tracepoint fires during or after
 * an operation and can only report it. The programs below are different in kind.
 * They are SEC("lsm/<hook>") — they attach to the kernel's LSM MAC layer, run as
 * part of the access-control decision itself, and their RETURN VALUE is honoured:
 * a nonzero (negative errno) return DENIES the operation before it happens. This
 * is the difference between "the wallet key was read, and we logged it" and "the
 * read was refused." It is real prevention, and it works even against root,
 * because the LSM hook runs regardless of uid.
 *
 * With that power comes the failure mode: a wrong deny can lock the machine out
 * of its own files. So the whole layer is SHADOW-FIRST. Each guard does the full
 * lookup and decision, emits a WARDEN_ACCESS record either way, but only actually
 * returns -EPERM when enforce_armed() (CFG_ENFORCE_ARM == 1). Unarmed — the
 * default — it logs a "would-deny" and returns 0 (allow). An operator watches the
 * shadow findings until they trust them, THEN arms denial with a single flip.
 *
 * REQUIREMENT: these attach only when the kernel's active LSM list includes "bpf"
 * (needs CONFIG_BPF_LSM=y AND `lsm=...,bpf` on the kernel command line). Where bpf
 * is not an active LSM the loader logs a loud warning and Warden runs as before —
 * all 12 observational sensors, no enforcement. The guards never trip Warden's own
 * accesses: the agent runs as the authorized uid for the files it manages, and in
 * any case reads config before these attach.
 */

/* Decide and record one guarded-inode access. Shared by all six LSM programs.
 * Returns the value the LSM hook should propagate: 0 (allow) always in shadow, or
 * -EPERM when armed AND the actor is unauthorised for a denied intent. `inode` is
 * the file's inode; `intent` is the WARDEN_INTENT_* bits this operation carries.
 *
 * The decision is deliberately tiny and branch-cheap — it runs on the open/mmap/
 * unlink/rename/setattr hot path for EVERY file, so the common case (inode not
 * guarded) is a single hash lookup that misses and returns 0 immediately. */
static __always_inline int guard_inode(struct inode *inode, __u32 intent, __u32 hook)
{
	if (!inode)
		return 0;

	/* Resolve the (dev, ino) identity via CO-RE. dev rides on the super_block. */
	struct warden_inode_key key = {};
	key.ino = BPF_CORE_READ(inode, i_ino);
	key.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	if (key.ino == 0)
		return 0; /* anon/pipe/socket inode — never a guarded file */

	struct warden_guard_policy *pol = bpf_map_lookup_elem(&guarded_inodes, &key);
	if (!pol)
		return 0; /* not a file we guard — the overwhelmingly common path */

	/* Does this operation's intent intersect what we deny for this inode? A key
	 * file denies READ|WRITE; an append-only log might deny only WRITE. No overlap
	 * ⇒ allow (e.g. a plain getattr on a WRITE-only-denied file). */
	if ((intent & pol->deny_intents) == 0)
		return 0;

	/* The authorised actor is always allowed. Attribution is by real uid: the app's
	 * own service account may touch its key; anyone else is the incident. Root is
	 * NOT implicitly allowed — that is the whole point (a stolen root shell must not
	 * read the wallet key) — unless the policy explicitly opts in via ALLOW_ROOT. */
	__u32 uid = (__u32)bpf_get_current_uid_gid();
	if (uid == pol->authorized_uid)
		return 0;
	if ((pol->flags & WARDEN_GUARD_ALLOW_ROOT) && uid == 0)
		return 0;

	/* Unauthorised touch of a guarded inode with a denied intent. Decide the
	 * verdict FIRST (armed ⇒ deny), so we can stamp it into the record we emit.
	 * The verdict is kept in a volatile slot: with the shipped clang, the folded
	 * `armed ? -EPERM : 0` form is rejected by the BPF verifier, so the two
	 * constants are materialised on separate paths and re-checked on return. */
	bool armed = enforce_armed();
	volatile int verdict = 0;
	if (armed)
		verdict = -EPERM;

	/* Emit a WARDEN_ACCESS record if the access sensor is emitting. We still
	 * enforce the verdict even if emission is muted — denial must not depend on a
	 * log channel — but muting lets an operator quiet a noisy shadow window. */
	if (sensor_emitting(CFG_ACCESS_EMIT)) {
		struct warden_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			__builtin_memset(e, 0, sizeof(*e));
			e->kind = WARDEN_ACCESS;
			fill_actor(e);
			e->aux = hook; /* enum warden_access_hook — which chokepoint fired */
			e->aux2 = (intent & 0xF) | (armed ? WARDEN_ACCESS_DENIED : 0);
			e->cap_old = key.dev;
			e->cap_new = key.ino;
			e->target_pid = pol->authorized_uid; /* who WAS authorised (reused slot) */
			count_submit(WARDEN_ACCESS);
			bpf_ringbuf_submit(e, 0);
		} else {
			/* Ring full ⇒ drop the record, but still return the verdict
			 * below: denial must never depend on the log channel. The
			 * drop is counted, so a muted access stream under flood
			 * shows up as loss rather than as a quiet box. */
			count_drop(WARDEN_ACCESS);
		}
	}

	if (verdict < 0)
		return -EPERM;
	return 0;
}

/* ── 13. lsm/file_open: deny an unauthorised OPEN of a guarded file (T2/T9) ─── */
/*
 * int file_open(struct file *file)
 * The MAC gate every open(2)/openat(2) passes through, AFTER the path has been
 * resolved to a struct file (so no symlink/`..` games) but BEFORE the fd is
 * usable. f_mode tells us read vs write intent. Returning -EPERM here is a clean
 * EACCES/EPERM to the caller — the file is never handed over. This is the primary
 * secret-file guard: it turns "root read your wallet key" into "permission denied".
 */
SEC("lsm/file_open")
int BPF_PROG(warden_guard_file_open, struct file *file)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	fmode_t mode = BPF_CORE_READ(file, f_mode);

	__u32 intent = 0;
	if (mode & FMODE_READ)
		intent |= WARDEN_INTENT_READ;
	if (mode & FMODE_WRITE)
		intent |= WARDEN_INTENT_WRITE;
	if (mode & FMODE_EXEC)
		intent |= WARDEN_INTENT_EXEC;
	if (intent == 0)
		intent = WARDEN_INTENT_READ; /* an open with no mode bits still reads metadata */

	int ret = guard_inode(inode, intent, WARDEN_ACCESS_OPEN);
	return ret;
}

/* ── 14. lsm/mmap_file: deny an unauthorised memory-map of a guarded file ───── */
/*
 * int mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
 *               unsigned long flags)
 * mmap is the second read path: a file can be mapped PROT_READ and its bytes
 * pulled out without ever calling read(2). file is NULL for an anonymous mapping
 * (guard_inode handles NULL). prot carries the intended access.
 *
 * WRITE intent only applies to a SHARED mapping: MAP_SHARED|PROT_WRITE writes
 * land in the page cache and therefore in the file, which is the tamper this
 * guard exists to stop. MAP_PRIVATE|PROT_WRITE is copy-on-write and changes
 * nothing on disk — and it is what the loader requests for every binary's data
 * segment. Denying private writable maps made a guarded executable die with
 * SIGSEGV on exec (the live failure this fix comes from), which would have
 * turned "protect the guardian" into "the guardian can never restart".
 */
SEC("lsm/mmap_file")
int BPF_PROG(warden_guard_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	if (!file)
		return 0; /* anonymous mapping — no inode to guard */
	struct inode *inode = BPF_CORE_READ(file, f_inode);

	__u32 intent = 0;
	if (prot & PROT_READ)
		intent |= WARDEN_INTENT_READ;
	if ((prot & PROT_WRITE) && (flags & MAP_SHARED))
		intent |= WARDEN_INTENT_WRITE;
	if (prot & PROT_EXEC)
		intent |= WARDEN_INTENT_EXEC;
	if (intent == 0)
		intent = WARDEN_INTENT_READ;

	return guard_inode(inode, intent, WARDEN_ACCESS_MMAP);
}

/* ── 15. lsm/inode_unlink: deny an unauthorised DELETE of a guarded file ────── */
/*
 * int inode_unlink(struct inode *dir, struct dentry *dentry)
 * dentry->d_inode is the inode being unlinked. Deleting a guarded file is a WRITE-
 * class tamper (removing the audit log, the key, the allowlist). We guard the
 * target inode, not the directory.
 */
SEC("lsm/inode_unlink")
int BPF_PROG(warden_guard_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	return guard_inode(inode, WARDEN_INTENT_WRITE, WARDEN_ACCESS_UNLINK);
}

/* ── 16. lsm/inode_rename: deny an unauthorised RENAME over/of a guarded file ─ */
/*
 * int inode_rename(struct inode *old_dir, struct dentry *old_dentry,
 *                  struct inode *new_dir, struct dentry *new_dentry)
 * Two inodes matter: renaming the guarded file AWAY (old_dentry's inode) and
 * renaming something OVER the guarded file (new_dentry's inode, if it exists —
 * the classic "swap a trojan in over the real binary/key" move). We guard both;
 * either being a denied guarded inode is refused. Ransomware's rename-to-.locked
 * over the victim is exactly the second shape.
 */
SEC("lsm/inode_rename")
int BPF_PROG(warden_guard_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
	int ret = guard_inode(old_inode, WARDEN_INTENT_WRITE, WARDEN_ACCESS_RENAME);
	if (ret)
		return ret;
	struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
	return guard_inode(new_inode, WARDEN_INTENT_WRITE, WARDEN_ACCESS_RENAME);
}

/* ── 17. lsm/inode_setattr: deny unauthorised chmod/chown/truncate of a guard ─ */
/*
 * int inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
 * chmod, chown, and truncate all flow through setattr. An attacker who can't read
 * a key might still try to chmod it world-readable, chown it to themselves, or
 * truncate an append-only log to zero — all WRITE-class tampers on the inode.
 */
SEC("lsm/inode_setattr")
int BPF_PROG(warden_guard_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr)
{
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	return guard_inode(inode, WARDEN_INTENT_WRITE, WARDEN_ACCESS_SETATTR);
}

/* ── 18. lsm/file_permission: revoke I/O through a pre-existing fd (W-R2) ───── */
/*
 * int file_permission(struct file *file, int mask)
 *
 * The five hooks above gate ACQUISITION: open(2), mmap(2), unlink, rename and
 * setattr. They cannot see a descriptor that was already open when the guard was
 * armed — the open happened before there was a policy to check, and every later
 * write(2)/read(2) on that fd is a fresh operation on an already-granted file.
 * That was the W-R2 gap: a process that opened a guarded key before arming kept
 * reading and writing it while the guard reported the file as protected.
 *
 * file_permission is the kernel's per-I/O MAC chokepoint: vfs_read/vfs_write call
 * security_file_permission() on every operation, whatever the fd's age, and the
 * hook's return value is honoured. Checking (dev, ino) here therefore retracts
 * access through a descriptor opened before the policy existed. It is also the
 * only hook that sees a write through an fd the actor opened while it was still
 * authorised (e.g. it changed uid afterwards).
 *
 * `mask` is MAY_READ / MAY_WRITE / MAY_APPEND / MAY_EXEC. MAY_APPEND is a write;
 * O_APPEND writes must not slip past a WRITE denial. A zero mask means the kernel
 * asked nothing actionable, so return before the (cheap, but hot) map lookup.
 *
 * Residual gap, stated rather than papered over: a memory mapping CREATED BEFORE
 * arming is not revoked by this hook. Per-store page faults do not pass through
 * file_permission, and there is no per-write LSM hook for an established
 * writable mapping; denying one would require revoking the mapping itself
 * (mmap_file only fires at mmap time, and file_mprotect only at mprotect). An
 * attacker who mapped the key writable before arming can still write through
 * that mapping. This is the remaining half of W-R2 and is documented in README.
 *
 * This runs on every read/write of every file, so the common case must stay a
 * single hash miss. guard_inode does exactly one lookup for an unguarded inode.
 */
SEC("lsm/file_permission")
int BPF_PROG(warden_guard_file_permission, struct file *file, int mask)
{
	if (mask == 0)
		return 0;

	struct inode *inode = BPF_CORE_READ(file, f_inode);

	__u32 intent = 0;
	if (mask & MAY_READ)
		intent |= WARDEN_INTENT_READ;
	if (mask & (MAY_WRITE | MAY_APPEND))
		intent |= WARDEN_INTENT_WRITE;
	if (mask & MAY_EXEC)
		intent |= WARDEN_INTENT_EXEC;

	return guard_inode(inode, intent, WARDEN_ACCESS_PERMISSION);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Phase 7 — cgroup egress enforcement (EXACT DESTINATION, SHADOW BY DEFAULT)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is the first Warden primitive that can refuse an outbound operation.
 * Three independent switches all have to be on before anything is denied:
 *
 *   1. the cgroup program must be ATTACHED — userspace only attaches when
 *      `[egress] enabled = true` AND a test cgroup path was supplied. The
 *      shipped config leaves it off; a plain config knob cannot attach a hook.
 *   2. the `CFG_EGRESS_ARM` slot must be 1 — it is 0 (SHADOW) in every default
 *      map, so even an attached program only COUNTS would-denies, never denies.
 *   3. a matching exact `(family, protocol, addr, port)` DENY rule must be in
 *      `egress_policy`. No rule ⇒ allow, one hash miss on the hot path.
 *
 * Why cgroup/sock_addr and not a firewall or an LSM hook: this is the choke
 * point that sees the *intended destination* of connect(2)/sendmsg(2) before the
 * route is chosen, it is namespaced to one cgroup (so a test cgroup can be
 * denied without touching the host), and it is a genuine deny primitive — a
 * non-zero return makes the syscall fail with that errno. It is deliberately
 * NOT a packet filter: it cannot see DNS names, TLS SNI after encryption, or
 * QUIC, and those limits are stated in the Phase 10 docs rather than guessed at
 * from a port number.
 *
 * Byte order is a contract here. The verifier implements a read of
 * `ctx->user_port` as a direct load of `sockaddr_in.sin_port` and a read of
 * `ctx->user_ip4` as `sockaddr_in.sin_addr` (see net/core/filter.c,
 * sock_addr_is_accessible / sock_addr_convert_ctx_access) — i.e. NETWORK byte
 * order. We copy those bytes verbatim into `warden_egress_key`, and the Rust
 * userspace writer mirrors them with `IpAddr::octets()` and `u16::to_be()`.
 * No byte-order conversion happens in the kernel, so the two sides agree on
 * one encoding and a rule either matches exactly or does not match at all.
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, WARDEN_EGRESS_POLICY_MAX);
	__type(key, struct warden_egress_key);
	__type(value, struct warden_egress_rule);
} egress_policy SEC(".maps");

/* A plain ARRAY, not PERCPU: a DENY match is rare, and userspace must be able
 * to record a failed rule insert (WARDEN_EGRESS_MAP_FULL) into the same set of
 * counters the reader samples. __sync_fetch_and_add keeps the shared u64 exact
 * even when several CPUs match the same rule in the same instant. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, WARDEN_EGRESS_STATS);
	__type(key, __u32);
	__type(value, __u64);
} egress_stats SEC(".maps");

static __always_inline void egress_count(__u32 stat)
{
	__u64 *n = bpf_map_lookup_elem(&egress_stats, &stat);
	if (n)
		__sync_fetch_and_add(n, 1);
}

/* The single decision routine shared by TCP connect and UDP sendmsg, v4+v6.
 * `addr` points to 4 or 16 already-network-order bytes on the BPF stack.
 * A `port == 0` rule is the only wildcard: it is consulted only after an exact
 * port rule missed, so a specific port always wins over "any port". */
static __always_inline int egress_decide(__u32 family, __u32 protocol,
					 __u32 addr_len, const void *addr,
					 __u32 port)
{
	struct warden_egress_key key = {};
	key.family = family;
	key.protocol = protocol;
	key.port = (__u16)port;
	__builtin_memcpy(key.addr, addr, addr_len);

	struct warden_egress_rule *rule = bpf_map_lookup_elem(&egress_policy, &key);
	if (!rule && key.port != 0) {
		key.port = 0;
		rule = bpf_map_lookup_elem(&egress_policy, &key);
	}
	if (!rule)
		return 1; /* no policy for this destination: allow */

	if (rule->deny == 0) {
		egress_count(WARDEN_EGRESS_HIT_ALLOW);
		return 1;
	}

	/* A DENY rule matched. The arm gate is the difference between an audit
	 * record and a real refusal; default 0 means SHADOW (count, allow). */
	__u32 arm_slot = CFG_EGRESS_ARM;
	__u32 *armed = bpf_map_lookup_elem(&runtime_cfg, &arm_slot);
	if (!(armed && *armed == 1)) {
		egress_count(WARDEN_EGRESS_HIT_DENY);
		return 1;
	}
	egress_count(WARDEN_EGRESS_DENIED);
	/* cgroup/sock_addr programs return a BOOLEAN, not an errno: the verifier
	 * restricts R0 to [0,1] for BPF_PROG_TYPE_CGROUP_SOCK_ADDR. For this
	 * program type the kernel interprets 1 as ALLOW and 0 as DENY (the syscall
	 * then fails with -EPERM). This was measured directly on
	 * 6.12.107+deb13-amd64: a shadow DENY returning 0 produced EPERM while an
	 * armed DENY returning 1 connected successfully. Returning -EPERM is
	 * rejected by the verifier, so the syscall-visible errno must come from
	 * returning 0 here. */
	return 0;
}

/* ── 19. cgroup/connect4: TCP (and any AF_INET) outbound connect ─────────── */
/* Copy the four IPv6 words out of the context one at a time. A single 16-byte
 * memcpy off a cgroup_sock_addr field would make the verifier split the access
 * itself; doing it explicitly keeps the rewrite to `sin6_addr.s6_addr32[n]` a
 * plain 32-bit load and leaves no pointer-to-context for it to second-guess. */
static __always_inline int egress_decide_v6(struct bpf_sock_addr *ctx)
{
	__u32 w0 = ctx->user_ip6[0];
	__u32 w1 = ctx->user_ip6[1];
	__u32 w2 = ctx->user_ip6[2];
	__u32 w3 = ctx->user_ip6[3];
	__u8 addr[16];
	__builtin_memcpy(&addr[0], &w0, 4);
	__builtin_memcpy(&addr[4], &w1, 4);
	__builtin_memcpy(&addr[8], &w2, 4);
	__builtin_memcpy(&addr[12], &w3, 4);

	/* F06: an IPv4-mapped IPv6 endpoint is the same logical IPv4 endpoint an
	 * operator writes as `a.b.c.d`. Canonicalize the exact mapped prefix here,
	 * before the key is built, so an AF_INET deny cannot be bypassed by the v6
	 * hook. Bytes 0..9 zero and bytes 10..11 0xffff are the complete mapped
	 * prefix; every other IPv6 address keeps its AF_INET6 key. */
	if (addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0 &&
	    addr[4] == 0 && addr[5] == 0 && addr[6] == 0 && addr[7] == 0 &&
	    addr[8] == 0 && addr[9] == 0 && addr[10] == 0xff && addr[11] == 0xff)
		return egress_decide(AF_INET, ctx->protocol, 4, &addr[12],
				     ctx->user_port);

	return egress_decide(AF_INET6, ctx->protocol, 16, addr, ctx->user_port);
}

static __always_inline int egress_decide_v4(struct bpf_sock_addr *ctx)
{
	__u32 ip4 = ctx->user_ip4;
	return egress_decide(AF_INET, ctx->protocol, 4, &ip4, ctx->user_port);
}

/* ── 19. cgroup/connect4: TCP (and any AF_INET) outbound connect ─────────── */
SEC("cgroup/connect4")
int warden_egress_connect4(struct bpf_sock_addr *ctx)
{
	/* A mismatched family is not a policy deny: this program only judges
	 * AF_INET addresses, and cgroup/sock_addr uses 1=allow, 0=deny. */
	if (ctx->user_family != AF_INET)
		return 1;
	return egress_decide_v4(ctx);
}

/* ── 20. cgroup/connect6: AF_INET6 outbound connect ─────────────────────── */
SEC("cgroup/connect6")
int warden_egress_connect6(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET6)
		return 1;
	return egress_decide_v6(ctx);
}

/* ── 21. cgroup/sendmsg4: unconnected UDP datagram destination ──────────── */
SEC("cgroup/sendmsg4")
int warden_egress_sendmsg4(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET)
		return 1;
	return egress_decide_v4(ctx);
}

/* ── 22. cgroup/sendmsg6: unconnected IPv6 UDP datagram destination ─────── */
SEC("cgroup/sendmsg6")
int warden_egress_sendmsg6(struct bpf_sock_addr *ctx)
{
	if (ctx->user_family != AF_INET6)
		return 1;
	return egress_decide_v6(ctx);
}
/* freshness-probe */
