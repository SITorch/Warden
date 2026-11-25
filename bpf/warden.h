/* SPDX-License-Identifier: GPL-2.0 */
/*
 * warden.h — the ABI shared between the in-kernel eBPF programs and the
 * Rust userspace agent. This struct is written by the kernel into the ring
 * buffer and read byte-for-byte by userspace, so its layout is a contract:
 * change it here and you MUST change the Rust mirror in src/events.rs.
 *
 * Keep it flat, fixed-size, and naturally aligned — no pointers, no padding
 * surprises. The verifier and the ring buffer both prefer POD.
 */
#ifndef __WARDEN_H
#define __WARDEN_H

#define TASK_COMM_LEN   16
#define MAX_FILENAME    256
#define WARDEN_ADDR_LEN 16   /* holds a full IPv6 address; IPv4 uses the first 4 */

/* A WARDEN_SERVICE record reuses the 256-byte filename buffer as a fixed ladder
 * of path components — the created leaf plus its three nearest ancestor
 * directories — one per 64-byte slot. Capturing a bounded, fixed number of
 * ancestors (rather than reconstructing a variable-length absolute path in the
 * kernel) keeps the producer a handful of constant-offset reads with no loop:
 * trivially inside the verifier's budget, and enough context for userspace to
 * recognise every persistence directory that matters (systemd unit dirs,
 * cron.*, autostart, init.d, …). Userspace joins the non-empty slots
 * root-to-leaf to rebuild the trailing path. */
#define WARDEN_SVC_SLOT  64                        /* bytes per path component */
#define WARDEN_SVC_DEPTH (MAX_FILENAME / WARDEN_SVC_SLOT)  /* leaf + 3 ancestors */

/* What kind of host event this record describes. Numbered, never reordered:
 * new kinds only ever append, so an old userspace decoding a new record simply
 * rejects an unknown kind rather than misreading one. */
enum warden_event_kind {
	WARDEN_EXEC    = 1, /* a process called execve — the RCE/shell tripwire */
	WARDEN_SIGNAL  = 2, /* kill() aimed at a PROTECTED pid — takedown attempt */
	WARDEN_PTRACE  = 3, /* ptrace() aimed at a PROTECTED pid — inspection/inject */
	WARDEN_CONNECT = 4, /* outbound connect() — egress / C2 / reverse-shell dial-out */
	WARDEN_CREDS   = 5, /* commit_creds() raised privilege — euid→0 or new capabilities */
	WARDEN_MODULE  = 6, /* a kernel module was loaded — rootkit / LKM implant tripwire */
	WARDEN_FILE    = 7, /* a destructive file op (rename/unlink) — ransomware / tamper */
	WARDEN_SERVICE = 8, /* a file was created in a persistence location — boot/login survival */
	WARDEN_LISTEN  = 9, /* a socket entered LISTEN — a bind-shell / backdoor listener */
	WARDEN_BPFLOAD = 10,/* a BPF program was loaded — eBPF rootkit / stealth-hook implant */
	WARDEN_MOUNT   = 11,/* a filesystem was mounted — container escape / host-fs exposure */
	WARDEN_ACCESS  = 12,/* a BPF-LSM hook saw an UNAUTHORISED touch of a guarded inode — the
			     * one enforcing kind: this record is emitted from a program that can
			     * return -EPERM to actually DENY the operation in-kernel (shadow logs
			     * it, armed denies it), not merely observe after the fact */
	WARDEN_CONNECT_RESULT = 13,
			     /* a TCP connect() came back with a KNOWN outcome. CONNECT says the
			      * dial was aimed; this says what the transport decided. Emitted only
			      * when the return value is terminal — an in-flight non-blocking dial
			      * is not an outcome and produces no record here (see
			      * enum warden_connect_outcome for what the kernel can and cannot say
			      * at this hook, measured on the deployment kernel) */
	WARDEN_FLOW = 14,
		      /* an inbound connection was ACCEPTED — the only record that
		       * names who walked through a door: the accepting task, the peer
		       * it came from, the listener port it was taken on, and the
		       * network namespace the socket lives in. CONNECT aims an egress
		       * and LISTEN opens a door; neither can say anyone used it.
		       *
		       * Emitted only when the kernel's accept produced a connected
		       * child socket (rc == 0). A call that returned -EAGAIN took
		       * nothing and writes no record — measured, not assumed: in the
		       * sampled production traffic on the deployment kernel, 157 of
		       * 4008 inet_accept() returns (3.9%) were -EAGAIN, and every one
		       * of the 3851 that returned 0 held a full 4-tuple with
		       * skc_state == TCP_ESTABLISHED (the probe's per-state counters
		       * never showed another state). A FLOW record may therefore be
		       * read as "an established inbound flow existed at this
		       * instant", and no weaker claim is made for the flows it does
		       * not describe.
		       *
		       * Deliberately NOT hooked on security_socket_accept, the obvious
		       * place: measured there, 2021 of 2021 entry calls and 2184 of
		       * 2184 return calls had newsock->sk still NULL, because the LSM
		       * hook runs before the protocol family installs the child. The
		       * record would have had no peer address to report. */
};

/* W2K-14: the number of counter slots the kernel's per-sensor maps carry, indexed
 * directly by `enum warden_event_kind` (slot 0 is never used). Kinds append, so 16
 * leaves room for four more kinds without touching the maps; `src/loader.rs`
 * mirrors this bound and `tests/ringbuf_drop_counter.rs` asserts the shipped
 * object actually has the slots. */
#define WARDEN_KIND_SLOTS 16

/* Which BPF-LSM hook produced a WARDEN_ACCESS record. Carried in `aux`. These are
 * the file-access chokepoints Warden can DENY at (return -EPERM): opening a file,
 * mapping it, the three edit/tamper ops, and the per-I/O permission check that
 * also covers a descriptor opened before the guard was armed. Numbered
 * append-only like every other Warden enum. */
enum warden_access_hook {
	WARDEN_ACCESS_OPEN    = 1, /* lsm/file_open      — a process opened the guarded file */
	WARDEN_ACCESS_MMAP    = 2, /* lsm/mmap_file      — a process memory-mapped it */
	WARDEN_ACCESS_UNLINK  = 3, /* lsm/inode_unlink   — a process tried to delete it */
	WARDEN_ACCESS_RENAME  = 4, /* lsm/inode_rename   — a process tried to rename it */
	WARDEN_ACCESS_SETATTR = 5, /* lsm/inode_setattr  — a process tried to chmod/chown/truncate it */
	WARDEN_ACCESS_PERMISSION = 6, /* lsm/file_permission — a read/write through an fd, including
				       * one opened BEFORE the guard was armed (W-R2) */
};

/* WARDEN_ACCESS intent bits (carried in the low nibble of `aux2`) — what the
 * operation would DO to the file, so userspace and the in-kernel guard can match
 * it against the per-inode deny mask. A single open can be both read and write.
 * These deliberately share bit positions with the guard-policy deny flags below
 * so `intent & deny_flags` is the whole in-kernel decision. */
#define WARDEN_INTENT_READ  0x1u /* read the contents */
#define WARDEN_INTENT_WRITE 0x2u /* modify the contents (open-for-write, unlink, rename, setattr) */
#define WARDEN_INTENT_EXEC  0x4u /* execute / executable-map */

/* SIGNAL flag carried in `aux2` (above no nibble — that slot is otherwise
 * unused for this kind). Set when the sender is the target's real parent, i.e.
 * a supervisor terminating the process it spawned: systemd restarting a unit,
 * Docker reaping a timed-out healthcheck, a pool parent recycling a worker.
 * Decided at the hook, where both tasks are still alive — asking userspace to
 * read the target's ppid afterwards races the reaper and would sometimes flip a
 * routine restart into a "takedown attempt" that an armed responder could turn
 * into a kill of the supervisor itself. */
#define WARDEN_SIGNAL_FROM_PARENT 0x1u

/* W2K-04 — HOW the signal was aimed, carried in `aux2` bits 2..5 as a class
 * number: WARDEN_SIGNAL_DELIVERY_MASK after a >>WARDEN_SIGNAL_DELIVERY_SHIFT.
 *
 * First, what this hook cannot see, because it changes what the sensor may
 * promise: a kernel-GENERATED signal never reaches it. `check_kill_permission()`
 * in kernel/signal.c opens with `if (!si_fromuser(info)) return 0;`, and
 * `si_fromuser()` is `info == SEND_SIG_NOINFO || (!is_si_special(info) &&
 * SI_FROMUSER(info))`, where `SI_FROMUSER(x)` is `x->si_code <= 0`
 * (include/uapi/asm-generic/siginfo.h). SI_KERNEL (0x80) and every synchronous
 * fault code (SEGV_*, BUS_*, FPE_*, ILL_*, TRAP_* — all positive) therefore return
 * out of the permission check early and never call the LSM hook: a protected
 * process that segfaults produces no record here at all, and the OOM killer's
 * SEND_SIG_PRIV is both kernel-internal and filtered by the sentinel test in the
 * hook. What this sensor sees is only traffic a process aimed, which is exactly
 * what a takedown tripwire is for.
 *
 * So what is left to classify is which call aimed it — and the hook's reach
 * decides how much each number is worth, because the negative codes split into
 * three genuinely different kinds of evidence:
 *   kill(2)/sigsend(2)/       SI_USER   (0)  — sent in the caller's own context, so
 *   pidfd_send_signal(2)                       `actor_pid` IS the sender. The classic
 *                                              external takedown.
 *   tkill(2)/tgkill(2)        SI_TKILL  (-6) — also how raise()/abort() deliver, so a
 *                                              protected process dying on its own panic
 *                                              lands here as its own actor. The kernel
 *                                              sets this number itself and lets no one
 *                                              else: si_code_reserved_to_kernel() in
 *                                              kernel/signal.c treats SI_TKILL and every
 *                                              non-negative code as kernel-only, and the
 *                                              sigqueue syscalls honour it only when the
 *                                              target is not the sender.
 *   sigqueue(3)               SI_QUEUE  (-1) — caller context again, so the actor is the
 *                                              sender. Carries a payload; tooling, not a
 *                                              shell.
 *   timer_create(2)           SI_TIMER  (-2) — a record carrying -2, -3 or -5 is a LABEL,
 *   mq_notify(3)              SI_MESGQ  (-3)    not a proven mechanism: the kernel's own
 *   queued SIGIO              SI_SIGIO  (-5)    timer expiry (posixtimer_send_sigqueue)
 *                                              and its own fasync delivery
 *                                              (send_sigio_to_task -> do_send_sig_info)
 *                                              queue past check_kill_permission and never
 *                                              reach this hook. The only way one appears
 *                                              is a sender that NAMED it — none of -1..-5
 *                                              is reserved, so rt_sigqueueinfo can put any
 *                                              of them on the wire. (mq_notify's own
 *                                              delivery path was not read for this note;
 *                                              the unreserved number alone is enough to
 *                                              make -3 a claim.) Worth investigating as
 *                                              a disguise; never evidence of a timer.
 *   AIO/USB completion        SI_ASYNCIO(-4) — the one code the kernel aims here from
 *                                              outside process context:
 *                                              kill_pid_usb_asyncio() calls
 *                                              security_task_kill() on the completion
 *                                              path, so `current` is whatever that CPU was
 *                                              running and `actor_pid` names no sender.
 * Anything else — including a positive code, which cannot arrive here, and an
 * si_code the read failed on — maps to USER, the attack class. Guessing anything
 * gentler would let a forged or unreadable code downgrade a real takedown, and
 * Warden does not trade a false negative for a quieter log.
 *
 * Userspace pairs this class with `actor_pid == target_pid` to decide whether the
 * victim aimed the blow at ITSELF — the reachable half of W2K-04: a self-directed
 * SIGABRT is a crash, not an attacker, and must not arm the responder. That
 * inference holds only where the hook ran in the sender's context, so the ASYNCIO
 * shape is excluded from it: there, actor == target would say which CPU took the
 * completion, not who aimed the signal. */
#define WARDEN_SIGNAL_DELIVERY_SHIFT 2
#define WARDEN_SIGNAL_DELIVERY_MASK  0x3Cu /* bits 2..5; 0x2 stays spare */

/* The si_code numbers themselves are frozen uapi ABI; named WARDEN_SI_* so this
 * header stays self-contained (the BPF side is built against vmlinux.h, which
 * does not re-export them). */
#define WARDEN_SI_USER     0
#define WARDEN_SI_QUEUE    (-1)
#define WARDEN_SI_TIMER    (-2)
#define WARDEN_SI_MESGQ    (-3)
#define WARDEN_SI_ASYNCIO  (-4)
#define WARDEN_SI_SIGIO    (-5)
#define WARDEN_SI_TKILL    (-6)

/* The class WARDEN_SIGNAL_DELIVERY_* bits carry. Numbered append-only like every
 * other Warden enum; 0 is deliberately SI_USER so a record whose si_code could
 * not be read decodes to the attack class rather than to something milder. */
enum warden_signal_delivery {
	WARDEN_SIGDELIV_USER    = 0, /* SI_USER: kill(2)/sigsend(2), or unreadable */
	WARDEN_SIGDELIV_TKILL   = 1, /* SI_TKILL: tkill/tgkill — and abort()/raise() from inside */
	WARDEN_SIGDELIV_QUEUE   = 2, /* SI_QUEUE: sigqueue(3) with a payload */
	WARDEN_SIGDELIV_TIMER   = 3, /* SI_TIMER claimed — a sender-chosen label, see above */
	WARDEN_SIGDELIV_MESGQ   = 4, /* SI_MESGQ claimed — a sender-chosen label, see above */
	WARDEN_SIGDELIV_ASYNCIO = 5, /* SI_ASYNCIO: usbfs completion, or a sender claiming it */
	WARDEN_SIGDELIV_SIGIO   = 6, /* SI_SIGIO claimed — a sender-chosen label, see above */
};

/* WARDEN_ACCESS decision bit, also in `aux2` (above the intent nibble). Set when
 * the guard actually returned -EPERM (armed + unauthorised + guarded intent);
 * clear means this was a SHADOW would-deny (observed, allowed through). Lets one
 * event kind carry both "we blocked this" and "we would have blocked this". */
#define WARDEN_ACCESS_DENIED 0x100u

/* Which persistence-write operation a WARDEN_SERVICE record describes. Carried
 * in `aux`, numbered append-only like every other Warden enum. Today we watch
 * the dominant vector — a NEW file dropped into a persistence directory
 * (a systemd unit, a cron entry, an autostart .desktop, authorized_keys, an
 * rc/preload file). Renaming a staged file into such a directory is a planned
 * second op; the slot is reserved so userspace never has to guess. */
enum warden_service_op {
	WARDEN_SERVICE_CREATE = 1, /* security_inode_create — a new file in a persistence dir */
};

/* Which destructive file operation a WARDEN_FILE record describes. Carried in
 * `aux`. Numbered like the event kinds: append-only, never reused. We hook the
 * two LSM chokepoints ransomware cannot avoid — it must either rename the
 * ciphertext over the original or unlink the original after writing a copy — and
 * which are far cooler on the hot path than the per-write open hook. */
enum warden_file_op {
	WARDEN_FILE_RENAME = 1, /* security_inode_rename — new name captured (the extension tell) */
	WARDEN_FILE_UNLINK = 2, /* security_inode_unlink — the removed name captured */
};

/* ── the enforcing guard map ─────────────────────────────────────────────────
 *
 * The BPF-LSM programs decide "deny or allow" against a kernel map keyed by the
 * one inode identity that survives renames and hardlinks: (device, inode number).
 * Userspace stat()s each configured guarded file, resolves it to this key, and
 * installs the policy. Keying on the resolved inode — not a path string — is
 * deliberate: a path check in-kernel is both expensive (string walk) and
 * bypassable (symlink, hardlink, bind mount, `.`/`..`), whereas the inode is the
 * file itself. A guarded file rewritten in place (new inode) is re-resolved by
 * userspace on its refresh tick, so protection follows the current inode.
 */
struct warden_inode_key {
	__u64 dev; /* the file's super_block s_dev (new_encode_dev form, as CO-RE reads it) */
	__u64 ino; /* the file's i_ino */
};

/* Per-guarded-inode policy the kernel enforces. `authorized_uid` is the ONE uid
 * allowed to touch this inode (the app's own service account — e.g. the user the
 * wallet-signing process runs as); every other uid touching it with a denied
 * intent is the incident. `deny_intents` is a mask of WARDEN_INTENT_* bits: which
 * operations are forbidden for an unauthorised actor (a key file denies READ|WRITE;
 * an append-only audit log might deny only WRITE). `flags` carries guard options. */
struct warden_guard_policy {
	__u32 authorized_uid; /* the sole uid permitted the denied intents (root is NOT special here) */
	__u32 deny_intents;   /* WARDEN_INTENT_* bits an unauthorised actor is refused */
	__u32 flags;          /* WARDEN_GUARD_* option bits */
	__u32 _pad;           /* keep the value 8-byte aligned / size stable */
};

/* warden_guard_policy.flags bits. */
#define WARDEN_GUARD_ALLOW_ROOT 0x1u /* uid 0 is also allowed (for files the app runs as root must touch) */

/* ── the CONNECT/LISTEN `aux2` packing (append-only; the numbers are ABI) ────
 * The two network kinds used the whole of `aux2` for the address family, which
 * left the record unable to say what it dialed *with*: a UDP dial to 8.8.8.8:53
 * and a TCP one to the same endpoint arrived byte-identical. Nothing in the
 * platform's flow contract can be filled without that field — `FLOW_FIELDS`
 * names `protocol` — so the family sits in bits 0..15 and the socket's
 * `sk_protocol` takes bits 16..23.
 *
 * This is append-only in the way that matters: AF_INET (2) and AF_INET6 (10)
 * both fit in the low half, so a record written by an older object still decodes
 * its family — it just carries protocol 0. And 0 is reserved here to mean
 * "no claim", never a protocol: it is what an unstamped record says, and it is
 * also a legal `sk_protocol` for a raw socket opened with IPPROTO_IP. Userspace
 * must render that as absent, not as "other" — a fabricated protocol is worse
 * than a missing one, because the egress policy would then be matching a value
 * nobody observed. The producer keeps the same discipline for a transport too
 * wide for 8 bits (`sk_protocol` is a u16 now): it stamps 0 rather than
 * truncating.
 *
 * The accessor is `sk->sk_protocol`, a real BTF member of `struct sock` — not
 * `__sk_common.skc_protocol`, which this kernel's `struct sock_common` does not
 * have (an older spelling; the object fails to *compile* against a vmlinux.h
 * that lacks it, which is how the mismatch was caught). Verified as a CO-RE
 * member on the build host (7.0.0-15-generic) and the deployment host
 * (6.12.107+deb13-amd64). On any other kernel it is UNVERIFIED, and the failure
 * is not graceful: the loader propagates the first program-load error, so an
 * unmatched access relocation stops Warden from starting at all rather than
 * losing the transport byte. That asymmetry — an 8-bit observational field
 * able to take down the whole agent — is tracked as N-14 and needs its own
 * per-sensor degradation before this object ships to a kernel outside the two
 * named above. */
enum warden_net_aux2 {
	WARDEN_NET_FAMILY_SHIFT = 0,
	WARDEN_NET_PROTO_SHIFT  = 16,
};
#define WARDEN_NET_FAMILY_MASK 0x0000FFFFu
#define WARDEN_NET_PROTO_MASK  0x00FF0000u

/* ── the CONNECT_RESULT outcome (append-only; the numbers are ABI) ──────────
 * Bits 24..31 of `aux2`, next to the family and transport the two older network
 * kinds already use. A CONNECT record is an INTENT; this field is the only place
 * in the ABI where Warden reports what the network actually did, so it is
 * enumerated rather than raw, and every value is one the producer can prove.
 *
 * Why not just carry the errno: the classification IS the evidence, and the
 * errno it came from is not reproducible in userspace afterwards. It also keeps
 * one honest boundary — the codes the kernel uses for "still in flight" have no
 * slot here at all, because a record that claimed a state for a handshake that
 * had not finished would be exactly the fabricated value this ABI rejects.
 *
 * What this hook cannot say, measured rather than assumed on the deployment
 * kernel (6.12.107+deb13-amd64) with a throwaway kretprobe on
 * __inet_stream_connect:
 *   - a BLOCKING dial returns a terminal code: 0 when established, -ECONNREFUSED
 *     when a RST answered the SYN (500/500 of each observed live).
 *   - a NON-BLOCKING dial (O_NONBLOCK in the task's file flags — which is what
 *     every "connect with a timeout" client does, including Python's
 *     settimeout) returns -EINPROGRESS and the outcome is not yet known: at that
 *     instant the handshake is still running. In a 60 s window of real
 *     production traffic on the deployment host, 116 of 128 stream connects
 *     (91%) were that shape. They are NOT recorded, so an absent record never
 *     reads as a failed connect.
 *   - `retval` arrives as a 32-bit return widened into the 64-bit register the
 *     kretprobe reports, so -115 reads as 0xFFFFFF8D. The producer truncates to 32
 *     bits and lets the compiler sign-extend, which is right for both a
 *     zero-extended and a sign-extended register — which shape a given kernel
 *     produces is not something this object can verify, and the measurement here
 *     showed the zero-extended one. Without that step every failure decodes as
 *     "no claim".
 *
 * Closing the 91% needs a handshake-completion signal, not this hook. The same
 * survey found `sock:inet_sock_set_state` available on the deployment kernel
 * (and no connect-shaped `tcp:*` tracepoints at all), which is where a later
 * stage would look; a state change also runs in softirq context, so it carries
 * no trustworthy actor pid and would have to be keyed on the 4-tuple. */
enum warden_connect_outcome {
	WARDEN_CONNECT_NO_CLAIM       = 0,  /* never emitted; the zero of an unstamped record */
	WARDEN_CONNECT_ESTABLISHED    = 1,  /* rc == 0 — the transport completed the handshake */
	WARDEN_CONNECT_REFUSED        = 2,  /* -ECONNREFUSED (111) — a RST answered the SYN */
	WARDEN_CONNECT_TIMEOUT        = 3,  /* -ETIMEDOUT (110) — no answer within the connect timeout */
	WARDEN_CONNECT_UNREACHABLE    = 4,  /* -EHOSTUNREACH (113) | -ENETUNREACH (101) */
	WARDEN_CONNECT_BLOCKED        = 5,  /* -EACCES (13) | -EPERM (1) — policy refused it */
	WARDEN_CONNECT_ABORTED        = 6,  /* -ECONNRESET (104) | -ECONNABORTED (103) | -EPIPE (32) */
	WARDEN_CONNECT_INTERRUPTED    = 7,  /* -EINTR (4) — a signal ended the wait, not a network verdict */
	WARDEN_CONNECT_WOULD_BLOCK    = 8,  /* -EAGAIN (11) */
	WARDEN_CONNECT_ALREADY        = 9,  /* -EISCONN (106) — already connected; NOT a failure */
	WARDEN_CONNECT_FAILED_OTHER   = 10, /* any other negative rc: it failed, we cannot say how */
};
#define WARDEN_NET_RESULT_SHIFT 24
#define WARDEN_NET_RESULT_MASK  0xFF000000u

/*
 * One host observation. `actor_*` is always "who did it" (the current task).
 * The remaining fields are per-kind overloads, zeroed by the producer when a
 * kind does not use them:
 *
 *   SIGNAL   target_pid = victim tgid;  aux = signal number;
 *            aux2       = WARDEN_SIGNAL_FROM_PARENT (0x1) | the
 *                         WARDEN_SIGNAL_DELIVERY_* class at bits 2..5
 *   PTRACE   target_pid = victim tgid;  aux = ptrace mode
 *   EXEC     filename   = executed path (best-effort)
 *   CONNECT  daddr      = destination IP (v4 in [0..4], v6 full);
 *            aux        = destination port (host byte order);
 *            aux2       = WARDEN_NET_* packed: family at bits 0..15, the socket's
 *                         sk_protocol at bits 16..23
 *   CONNECT_RESULT
 *            daddr/aux/aux2 = exactly as CONNECT (same endpoint, same family and
 *                         transport packing) PLUS enum warden_connect_outcome at
 *                         bits 24..31. The record is emitted at the return of the
 *                         dial, so it shares a kind's field layout and adds one
 *                         fact: whether the network completed, refused or never
 *                         answered. No slot is redefined — which is why an old
 *                         decoder reads a new record as a CONNECT-shaped endpoint
 *                         with an unknown kind (rejected), not as a wrong endpoint.
 *   CREDS    aux        = new euid;   aux2 = old euid;
 *            cap_old    = prior effective capability mask;
 *            cap_new    = new effective capability mask
 *   MODULE   filename   = module name (best-effort);  aux = kernel taint flags
 *   FILE     filename   = affected leaf name (rename: the NEW name; unlink: the
 *                         removed name — the leaf, not the full path, which the
 *                         LSM hook doesn't cheaply give us);
 *            aux        = enum warden_file_op (RENAME / UNLINK)
 *   SERVICE  filename   = a ladder of up to WARDEN_SVC_DEPTH NUL-terminated
 *                         components, each in its own WARDEN_SVC_SLOT-byte cell:
 *                         cell 0 = created leaf, cell 1 = parent dir, cell 2 =
 *                         grandparent, cell 3 = great-grandparent (empty cells
 *                         zeroed). Userspace joins them leaf-last into the
 *                         trailing path it matches persistence dirs against;
 *            aux        = enum warden_service_op (CREATE)
 *   LISTEN   daddr      = local bound address (v4 in [0..4], v6 full);
 *            aux        = local bound port (host byte order);
 *            aux2       = WARDEN_NET_* packed: family at bits 0..15, sk_protocol
 *                         at bits 16..23
 *   FLOW     the INBOUND twin of CONNECT: the peer that was accepted, formatted
 *            with the same three fields so userspace renders and compares it with
 *            the one formatter the dial already uses — `daddr` = peer address (v4
 *            in [0..4], v6 full), `aux` = peer port (host byte order), `aux2` =
 *            the same family|protocol packing (bits 24..31 stay 0: an accepted
 *            flow has no dial verdict, and reading the outcome field here would
 *            call "no claim" a state).
 *            Two slots add what a dial record does not need:
 *            `target_pid` = the LOCAL port the peer was accepted on (host byte
 *            order) — which door, since one task can serve many listeners; and
 *            `cap_old` = the child socket's network-namespace inode number
 *            (`struct net::ns.inum`, read by CO-RE). That number is what makes an
 *            accepted flow inside a container readable as what it is: the kprobe
 *            is global, so this sensor sees netns the /proc/net pull path cannot
 *            (that path reads only Warden's own namespace), and without the inum
 *            those flows would be indistinguishable from host ones. `cap_new`
 *            stays 0 — the listener's socket inode is the obvious next identity
 *            and is NOT stamped here, because reading it needs a container_of
 *            through `struct socket_alloc` that has never been measured; a spare
 *            zero beats an unverified pointer walk.
 *   BPFLOAD  aux        = the bpf() command (enum bpf_cmd; we emit on PROG_LOAD);
 *            aux2       = enum bpf_prog_type of the program being loaded
 *                         (KPROBE/TRACEPOINT/XDP/LSM = stealth-capable implant;
 *                         CGROUP_SKB/… = the benign filters the init system loads);
 *            cap_old    = the LOADER's own executable: super_block dev (kernel
 *                         kdev_t, major<<20|minor) of `current->mm->exe_file`;
 *            cap_new    = ...and its inode number (i_ino).
 *                         These two are the reason this record can still name an
 *                         author after the author is gone. `/proc/<pid>/exe` is a
 *                         read userspace performs milliseconds late, and a loader
 *                         that exits first — the normal shape, not an evasion —
 *                         leaves `comm`, a string the process chose for itself, as
 *                         the only identity on the wire (W2K-29). Inside the hook
 *                         the task is alive by construction, so the file it runs is
 *                         readable here and nowhere else afterwards. Userspace
 *                         compares the pair against stat() of each configured
 *                         loader path. BOTH slots zero means NO CLAIM, which covers
 *                         both a kernel thread (no mm) and a record from an object
 *                         built before this was stamped: never read dev without a
 *                         non-zero ino. The dentry path is deliberately NOT walked
 *                         into filename[]: a path is a name, the pair above is an
 *                         identity, and the mount-root ambiguity a container's
 *                         dentry introduces would make the string less trustworthy
 *                         than the numbers, not more.
 *   MOUNT    filename   = mount source / device name (best-effort; for a bind
 *                         mount, the host path being exposed — the escape tell);
 *            aux        = low 32 bits of the mount flags (MS_* — MS_BIND, …)
 *   ACCESS   aux        = enum warden_access_hook (OPEN/MMAP/UNLINK/RENAME/SETATTR/PERMISSION);
 *            aux2       = WARDEN_INTENT_* bits (low nibble) OR'd with the
 *                         WARDEN_ACCESS_DENIED bit (0x100) when the guard actually
 *                         returned -EPERM (armed); no DENIED bit ⇒ a shadow would-deny;
 *            cap_old    = the guarded inode's device (s_dev);
 *            cap_new    = the guarded inode's number (i_ino);
 *            target_pid = the guarded inode's authorized uid (who WAS allowed) —
 *                         reusing the slot; the actor's own uid is actor_uid as always
 *
 * Keeping the record flat and fixed-size (no per-kind unions on the wire) is a
 * deliberate ABI choice: a single `size_of` assertion on each side pins the
 * whole contract, and the ring buffer copies one predictable extent every time.
 */
struct warden_event {
	__u32 kind;        /* enum warden_event_kind */
	__u32 actor_pid;   /* tgid of the doer (userspace "pid") */
	__u32 actor_tid;   /* kernel tid */
	__u32 actor_ppid;  /* parent tgid */
	__u32 actor_uid;   /* real uid */
	__u32 target_pid;  /* SIGNAL/PTRACE: the victim tgid; ACCESS: the guarded inode's authorized uid;
			    * FLOW: the LOCAL port the peer was accepted on (host byte order) */
	__u32 aux;         /* SIGNAL: signal number; PTRACE: mode; CONNECT/LISTEN/FLOW: port; CREDS: new euid; BPFLOAD: bpf cmd; MOUNT: flags */
	__u32 aux2;        /* CONNECT/LISTEN/FLOW: WARDEN_NET_* packed family|protocol;
			    * CONNECT_RESULT: the same packing plus the outcome at bits 24..31;
			    * CREDS: old euid; BPFLOAD: bpf_prog_type; SIGNAL: WARDEN_SIGNAL_* flags; ACCESS: intent|denied; reserved otherwise */
	__u64 ts_ns;       /* bpf_ktime_get_ns() at emission */
	__u64 cap_old;     /* CREDS: prior effective capability mask; ACCESS: guarded inode dev;
			    * FLOW: the socket's network-namespace inode number (ns.inum);
			    * BPFLOAD: the loader's own executable inode's device (0 = no claim) */
	__u64 cap_new;     /* CREDS: new effective capability mask; ACCESS: guarded inode ino;
			    * BPFLOAD: the loader's own executable inode number (0 = no claim) */
	__u8  daddr[WARDEN_ADDR_LEN];   /* CONNECT/LISTEN/FLOW: address (network order) */
	__u8  comm[TASK_COMM_LEN];      /* actor comm */
	__u8  filename[MAX_FILENAME];   /* EXEC: executed path (best-effort) */
};

/* runtime_cfg array slots — a single-flip per-sensor emit gate userspace toggles
 * without detaching a program (e.g. to mute a high-volume sensor during an
 * allowlist-learning window). Indices are an ABI too: numbered, never reused. */
enum warden_cfg_slot {
	CFG_EXEC_EMIT    = 0, /* 1 = emit exec events, 0 = mute */
	CFG_CONNECT_EMIT = 1, /* 1 = emit connect events, 0 = mute */
	CFG_MODULE_EMIT  = 2, /* 1 = emit module-load events, 0 = mute */
	CFG_FILE_EMIT    = 3, /* 1 = emit file rename/unlink events, 0 = mute */
	CFG_SERVICE_EMIT = 4, /* 1 = emit persistence-create events, 0 = mute */
	CFG_LISTEN_EMIT  = 5, /* 1 = emit listen-socket events, 0 = mute */
	CFG_BPF_EMIT     = 6, /* 1 = emit bpf-prog-load events, 0 = mute */
	CFG_MOUNT_EMIT   = 7, /* 1 = emit mount events, 0 = mute */
	CFG_ACCESS_EMIT  = 8, /* 1 = emit guarded-inode ACCESS events, 0 = mute the LSM sensors */
	CFG_ENFORCE_ARM  = 9, /* the ENFORCING gate: 0 = SHADOW (log a would-deny, allow through),
			       * 1 = ARMED (return -EPERM, actually deny). Default 0 — every LSM
			       * program is shadow-first; denial is a deliberate, separate flip. */
	CFG_CONNECT_RESULT_EMIT = 10, /* 1 = emit connect-outcome records, 0 = mute. Muting also
			       * stops the entry probe from stashing, and the return probe always
			       * drains whatever the entry probe stored, so a mute mid-flight can
			       * never leave a stale entry for a recycled tid. */
	CFG_FLOW_EMIT = 11, /* 1 = emit accepted-flow (WARDEN_FLOW) records, 0 = mute. Same
			       * stash-then-drain contract as CFG_CONNECT_RESULT_EMIT, which this
			       * sensor copies: an accept is a two-half hook, and the inbound
			       * mirror of a busy egress path is busy in its own way — the same
			       * 60 s window that measured 6301 inet_accept() calls measured only
			       * ~128 connects, so mute is the operator's knob for a chatty
			       * listener, not a rare escape hatch. */
	CFG_NET_VOLUME_EMIT = 12, /* 1 = bump the per-cgroup byte/operation counters (N-05, stage
			       * 16b/16f and the IPv6 datagram pair), 0 = the six volume fexit programs
			       * return without touching
			       * any map. This gate is the whole off switch for the sensor: nothing
			       * is emitted to the ring, so unlike every other slot here it mutes a
			       * counter rather than a record. Userspace seeds it from
			       * `[net_volume].enabled`, which defaults OFF. */
	CFG_EGRESS_ARM = 13, /* Phase 7. 1 = a programmed DENY rule may reject the operation.
			      * 0 (the default, and every absent slot) = SHADOW: rules are counted
			      * but every operation is allowed. This gate is deliberately separate
			      * from hook attachment: attaching a cgroup program is not permission
			      * to deny production traffic. */
	CFG_SLOT_COUNT   = 14, /* array capacity; slots 0..13 now all assigned */
};

/* ── Phase 7 cgroup egress enforcement ABI ──────────────────────────────────
 *
 * Exact-destination policy, deliberately smaller than a firewall. A key is an
 * (address family, L4 protocol, address, port) tuple; a rule is a decision plus
 * the generation that programmed it. There is no wildcard-by-name rule and no
 * mutable container-name matching: a deny must be attributable to an address an
 * operator can read. `port == 0` means "any port for this address", which is the
 * only wildcard the kernel side understands.
 *
 * The userspace writer is the ONLY producer of this map. A failed update never
 * replaces a generation that was previously valid — see src/egress.rs. */
#define WARDEN_EGRESS_POLICY_MAX 256
#define WARDEN_EGRESS_STATS      4

enum warden_egress_stat {
	WARDEN_EGRESS_HIT_ALLOW = 0, /* a rule said ALLOW and the operation proceeded */
	WARDEN_EGRESS_HIT_DENY  = 1, /* a rule said DENY; in SHADOW the operation still proceeded */
	WARDEN_EGRESS_DENIED    = 2, /* -EPERM returned because an ARMED DENY rule executed */
	WARDEN_EGRESS_MAP_FULL  = 3, /* a userspace rule insert was refused; coverage is incomplete */
};

struct warden_egress_key {
	__u32 family;      /* AF_INET / AF_INET6 */
	__u32 protocol;    /* IPPROTO_TCP / IPPROTO_UDP */
	__u8  addr[16];    /* network-byte order in the first 4 / 16 bytes */
	__u16 port;        /* network-byte order, 0 = any port */
	__u16 _pad;
};

struct warden_egress_rule {
	__u32 deny;        /* 0 = ALLOW, 1 = DENY */
	__u32 generation;  /* monotonically increasing policy generation */
};

/* ── the per-cgroup network volume counters (N-05, stage 16b) ───────────────
 *
 * WHY A MAP AND NOT RECORDS. The ring is lossy and a 344-byte record is a poor
 * container for a 10-byte fact: at the shipped 256 KiB default it holds ≈760
 * records in flight, and an operator who wants "how many bytes did this
 * container move while I was not looking" would need one record per send — the
 * exact event that floods the ring first and makes the answer unavailable. A
 * counter map is the other shape: the kernel adds four numbers per syscall and
 * userspace reads the totals once per interval. Cost is one hash lookup and a
 * few atomic adds; nothing crosses into userspace per byte.
 *
 * WHY KEYED BY CGROUP AND NOT BY FLOW OR PID. Both alternatives were rejected
 * on identity grounds, not cost:
 *   - Per-flow: the key would be the 4-tuple, and nothing here sees the close.
 *     Entries would therefore accumulate forever against a fixed map — and a
 *     reused (addr,port) pair would inherit the dead flow's byte total. A
 *     counter that can be inherited by the wrong flow is worse than no counter,
 *     because it is evidence that looks like history.
 *   - Per-pid: same recycling problem, one level up. tcp_sendmsg runs in the
 *     sender's context so the tgid is available and correct *at that instant*,
 *     but a process that exits leaves its totals behind and a new process with
 *     the recycled tgid reads as their continuation. Closing that needs a
 *     sched_process_exit drain and an event-time start clock — a stage of its
 *     own, not a field to add here.
 *   - cgroup: `bpf_get_current_cgroup_id()` returns the kernfs node id, which
 *     is allocated from a 64-bit monotone generator and is NOT reused when the
 *     cgroup goes away. So a stale total can never be mistaken for a new
 *     tenant's traffic; it can only be stale, and `last_ns` below is what lets
 *     the reader see that. On a systemd host every service is already its own
 *     cgroup, so this is per-service granularity without containers too.
 *
 * WHAT `ops` MEANS, AND WHAT IT DELIBERATELY DOES NOT. The roadmap word for
 * this sensor was "بایت/پکت" (bytes/packets). Packets are not what these hooks
 * can count: one tcp_sendmsg() can produce zero segments (queued, coalesced,
 * delayed by the congestion window) or hundreds (a large write GSO'd at a much
 * lower layer), and one tcp_cleanup_rbuf() follows a recvmsg() that drained
 * whatever had arrived. Stamping either number as "packets" would invent a
 * metric the kernel did not report. So the fields are OPERATIONS — completed
 * sendmsg/recvmsg-side calls — alongside the bytes, which are real:
 *   bytes_out: the return value of tcp_sendmsg/udp_sendmsg (bytes the kernel
 *              accepted into the send queue; a negative return is an error and
 *              adds nothing, so a failed send costs no bytes but is still one
 *              operation),
 *   bytes_in:  the `copied` argument of tcp_cleanup_rbuf (bytes handed to the
 *              reader's userspace), and `min(ret, len)` for a UDP receive. The
 *              cap is mandatory: Linux v6.12 returns the ORIGINAL datagram
 *              length when MSG_TRUNC is set, which is not the number of bytes
 *              copied. The bump path charges bytes only when the result is
 *              positive, so a completion that moved nothing never adds to a
 *              byte total.
 * Both are application payload measured at the send/recv call, not wire bytes.
 * The two differ in one direction each, and getting either backwards makes a
 * comparison against an interface counter look like a bug:
 *   OUTSIDE these totals: the IP and TCP headers the kernel adds below these
 *   functions, and retransmitted segments, which are accounted where the
 *   sk_buff is queued to the device, not where userspace handed the payload in.
 *   INSIDE these totals: a userspace TLS library's own record framing and
 *   handshake bytes. OpenSSL hands the finished TLS record to sendmsg() and the
 *   kernel sees it as payload; there is no hook here that could subtract it.
 *   Also invisible to any subtraction: traffic that never reached these
 *   functions at all (a UDP receive, an AF_PACKET capture, an XDP-redirected
 *   frame — see the reader's coverage line).
 * So: bytes_on_the_wire > these totals for a plain TCP flow (headers, retransmits),
 * and these totals > plaintext application bytes for a TLS flow (record framing).
 * Neither is a defect; both are consequences of measuring at the syscall boundary,
 * which is the only place these hooks can be.
 *
 * The two counters are read as a PAIR, and that is the point: operations high
 * while bytes stay flat describes a path that is being asked and delivering
 * nothing — repeated failed sends against a closed socket, say — which is a
 * different incident from the same volume moved in a handful of large writes.
 * A single number would have to pick which one it was evidence for.
 *
 * Loopback is NOT filtered out. `skc_bound_dev_if` says which device a socket is
 * *bound* to, not which one its packets take, so filtering on it would claim a
 * routing certainty the field does not carry; the totals therefore include the
 * localhost traffic a proxy or a sidecar moves, and any threshold built on them
 * must be read that way. */
struct warden_net_volume {
	__u64 bytes_out; /* bytes accepted into a send queue by this cgroup */
	__u64 ops_out;   /* send-side calls that returned, bytes or no bytes */
	__u64 bytes_in;  /* bytes copied to this cgroup's userspace on receive */
	__u64 ops_in;    /* receive-side completions, counted either way */
	__u64 last_ns;   /* bpf_ktime_get_ns() at the most recent bump; the reader
			 * uses it to tell a stopped tenant from a silent one */
};

/* How many cgroups the map can track. A hash, so an unused slot costs nothing;
 * the bound exists so that a host with ten thousand short-lived cgroups cannot
 * grow kernel memory without limit, and so the reader has a number to quote
 * when it says "the totals you are reading may be incomplete". Sized generously
 * against the deployment host, which measured a few hundred cgroups. */
#define WARDEN_NET_VOLUME_MAX 512

/* Health slots for the volume map, in a PERCPU_ARRAY so the data path never
 * takes a lock to report its own health. Same lesson as W2K-14: a counter with
 * no denominator is indistinguishable from a quiet host.
 *   [0] full — a bump for a NEW cgroup was refused because the map held
 *       WARDEN_NET_VOLUME_MAX keys. Bytes still moved; they are simply not in
 *       any total. The reader must say so rather than print a smaller number
 *       and let it look like a measurement.
 *   [1] bumps — every counter update that succeeded, including updates to an
 *       existing key. Zero with zero cgroups means the sensor never fired,
 *       which is a dead hook, not an idle host.
 *   [2..8) — lifetime fexit invocations, one slot per program in `VolumeHook::ALL`
 *       order. Incremented BEFORE the emit gate and before the map-full check:
 *       a disabled gate or a full map must not make an attached hook look silent.
 *       Invocation, bump and byte totals are three different claims; only the
 *       first proves that the probe ran on this kernel. */
enum warden_net_volume_stat {
	WARDEN_NETVOLUME_FULL = 0,
	WARDEN_NETVOLUME_BUMP = 1,
	WARDEN_NETVOLUME_TCP_OUT = 2,
	WARDEN_NETVOLUME_TCP_IN = 3,
	WARDEN_NETVOLUME_UDP_OUT = 4,
	WARDEN_NETVOLUME_UDP_IN = 5,
	WARDEN_NETVOLUME_UDP6_OUT = 6,
	WARDEN_NETVOLUME_UDP6_IN = 7,
	WARDEN_NETVOLUME_STATS = 8,
};

#endif /* __WARDEN_H */
