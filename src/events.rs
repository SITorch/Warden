//! events.rs — the Rust side of the kernel↔userspace ABI.
//!
//! This mirrors `bpf/warden.h` byte-for-byte. If you change one, change the
//! other; the `assert_abi_size` test pins the size so drift fails the build.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::linux::fs::MetadataExt;

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_FILENAME: usize = 256;
pub const WARDEN_ADDR_LEN: usize = 16;

/// SERVICE records pack a fixed ladder of path components into `filename`: the
/// created leaf in cell 0, then each successive ancestor directory in the next
/// cell, one per `WARDEN_SVC_SLOT` bytes. Mirror of the same names in warden.h;
/// `service_path` rebuilds the trailing path from the non-empty cells.
pub const WARDEN_SVC_SLOT: usize = 64;
pub const WARDEN_SVC_DEPTH: usize = MAX_FILENAME / WARDEN_SVC_SLOT;

/// Event kinds — must match `enum warden_event_kind` in warden.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Kind {
    Exec = 1,
    Signal = 2,
    Ptrace = 3,
    Connect = 4,
    Creds = 5,
    Module = 6,
    File = 7,
    Service = 8,
    Listen = 9,
    BpfLoad = 10,
    Mount = 11,
    Access = 12,
    ConnectResult = 13,
    Flow = 14,
}

impl Kind {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Kind::Exec),
            2 => Some(Kind::Signal),
            3 => Some(Kind::Ptrace),
            4 => Some(Kind::Connect),
            5 => Some(Kind::Creds),
            6 => Some(Kind::Module),
            7 => Some(Kind::File),
            8 => Some(Kind::Service),
            9 => Some(Kind::Listen),
            10 => Some(Kind::BpfLoad),
            11 => Some(Kind::Mount),
            12 => Some(Kind::Access),
            13 => Some(Kind::ConnectResult),
            14 => Some(Kind::Flow),
            _ => None,
        }
    }

    /// Every decodable kind, in wire order. The per-sensor kernel counters
    /// (W2K-14) are indexed by the discriminant, so this list is what lets the
    /// loader name a slot instead of printing an index — and what lets a test
    /// assert that every kind userspace can decode has a counter slot.
    pub const ALL: [Kind; 14] = [
        Kind::Exec,
        Kind::Signal,
        Kind::Ptrace,
        Kind::Connect,
        Kind::Creds,
        Kind::Module,
        Kind::File,
        Kind::Service,
        Kind::Listen,
        Kind::BpfLoad,
        Kind::Mount,
        Kind::Access,
        Kind::ConnectResult,
        Kind::Flow,
    ];

    /// Short stable name for journals and reports. Never derived from `Debug`, so
    /// a renamed variant cannot change what an operator's log filter matches.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Exec => "exec",
            Kind::Signal => "signal",
            Kind::Ptrace => "ptrace",
            Kind::Connect => "connect",
            Kind::Creds => "creds",
            Kind::Module => "module",
            Kind::File => "file",
            Kind::Service => "service",
            Kind::Listen => "listen",
            Kind::BpfLoad => "bpfload",
            Kind::Mount => "mount",
            Kind::Access => "access",
            Kind::ConnectResult => "connect_result",
            Kind::Flow => "flow",
        }
    }
}

/// Which persistence-write operation a `Service` event describes — mirrors
/// `enum warden_service_op` in warden.h. Carried on the wire in `aux`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceOp {
    Create = 1,
}

impl ServiceOp {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(ServiceOp::Create),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceOp::Create => "create",
        }
    }
}

/// Which destructive file operation a `File` event describes — mirrors
/// `enum warden_file_op` in warden.h. Carried on the wire in `aux`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Rename = 1,
    Unlink = 2,
}

impl FileOp {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(FileOp::Rename),
            2 => Some(FileOp::Unlink),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            FileOp::Rename => "rename",
            FileOp::Unlink => "unlink",
        }
    }
}

/// Which BPF-LSM chokepoint produced an `Access` event — mirrors
/// `enum warden_access_hook` in warden.h. Carried on the wire in `aux`. These are
/// the six file-access hooks the enforcing layer can DENY at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessHook {
    Open = 1,
    Mmap = 2,
    Unlink = 3,
    Rename = 4,
    Setattr = 5,
    /// `lsm/file_permission`: a read/write through an fd, including one opened
    /// before the guard was armed (W-R2).
    Permission = 6,
}

impl AccessHook {
    /// The six file-access chokepoints the enforcing layer can deny at, in wire
    /// order. See [`SignalDelivery::ALL`] for why the list is public.
    pub const ALL: [AccessHook; 6] = [
        AccessHook::Open,
        AccessHook::Mmap,
        AccessHook::Unlink,
        AccessHook::Rename,
        AccessHook::Setattr,
        AccessHook::Permission,
    ];

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(AccessHook::Open),
            2 => Some(AccessHook::Mmap),
            3 => Some(AccessHook::Unlink),
            4 => Some(AccessHook::Rename),
            5 => Some(AccessHook::Setattr),
            6 => Some(AccessHook::Permission),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            AccessHook::Open => "open",
            AccessHook::Mmap => "mmap",
            AccessHook::Unlink => "unlink",
            AccessHook::Rename => "rename",
            AccessHook::Setattr => "setattr",
            AccessHook::Permission => "permission",
        }
    }
}

/// WARDEN_ACCESS intent bits (low nibble of `aux2`) — must match the
/// `WARDEN_INTENT_*` defines in warden.h. What the operation would DO to the file.
pub const WARDEN_INTENT_READ: u32 = 0x1;
pub const WARDEN_INTENT_WRITE: u32 = 0x2;
pub const WARDEN_INTENT_EXEC: u32 = 0x4;

/// SIGNAL flag in `aux2` — must match `WARDEN_SIGNAL_FROM_PARENT` in warden.h.
/// The kernel sets it when the sender is the victim's real parent, so a
/// supervisor restarting its own child is not mistaken for an outside takedown.
pub const WARDEN_SIGNAL_FROM_PARENT: u32 = 0x1;

/// `aux2` placement of the SIGNAL delivery class — must match
/// `WARDEN_SIGNAL_DELIVERY_SHIFT` / `_MASK` in warden.h: a 4-bit class number
/// above the FROM_PARENT flag, decoded into `SignalDelivery`.
pub const WARDEN_SIGNAL_DELIVERY_SHIFT: u32 = 2;
pub const WARDEN_SIGNAL_DELIVERY_MASK: u32 = 0x3C;

/// How a signal was aimed at the victim — mirrors `enum warden_signal_delivery`
/// in warden.h, where the reasoning (including why a kernel-GENERATED signal
/// never reaches this sensor at all) is written out. Carried on the wire in
/// `aux2` bits 2..5 of a SIGNAL record; `User` is also what an unreadable
/// `si_code` decodes to, so the default stays the attack class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalDelivery {
    /// SI_USER (0): `kill(2)` / `sigsend(2)` — the classic external takedown.
    User = 0,
    /// SI_TKILL (-6): `tkill`/`tgkill` — also how `raise()`/`abort()` deliver, so
    /// a protected process dying on its own panic arrives as its own actor.
    Tkill = 1,
    /// SI_QUEUE (-1): `sigqueue(3)` with a payload — tooling, not a shell `kill`.
    /// -1 is not reserved to the kernel, so a sender can name it without calling
    /// sigqueue; the actor is still that sender either way.
    Queue = 2,
    /// SI_TIMER (-2): a label, never a mechanism. A real posix timer expiry is
    /// queued by `posixtimer_send_sigqueue()` past `check_kill_permission()`, so
    /// it never reaches this hook; a record saying -2 was written by a sender that
    /// named that number in `rt_sigqueueinfo`.
    Timer = 3,
    /// SI_MESGQ (-3): label only. -3 is not reserved to the kernel either, and the
    /// mqueue notification path was not read in this round, so a record naming it is
    /// treated the same way as `Timer`: a sender's claim, not a mechanism.
    Mesgq = 4,
    /// SI_ASYNCIO (-4): the one class the kernel itself aims here from outside
    /// process context (`kill_pid_usb_asyncio()` calls the hook on the completion
    /// path), or a sender naming -4. Its `actor_pid` may name no sender at all.
    Asyncio = 5,
    /// SI_SIGIO (-5): label only — `send_sigio_to_task()` uses `do_send_sig_info`,
    /// which skips the hook.
    Sigio = 6,
}

impl SignalDelivery {
    /// Every class the decoder can name, in `aux2` order. `--explain` prints this
    /// in its own error message so the accepted spellings can never drift from
    /// the labels a journal line carries.
    pub const ALL: [SignalDelivery; 7] = [
        SignalDelivery::User,
        SignalDelivery::Tkill,
        SignalDelivery::Queue,
        SignalDelivery::Timer,
        SignalDelivery::Mesgq,
        SignalDelivery::Asyncio,
        SignalDelivery::Sigio,
    ];

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(SignalDelivery::User),
            1 => Some(SignalDelivery::Tkill),
            2 => Some(SignalDelivery::Queue),
            3 => Some(SignalDelivery::Timer),
            4 => Some(SignalDelivery::Mesgq),
            5 => Some(SignalDelivery::Asyncio),
            6 => Some(SignalDelivery::Sigio),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            SignalDelivery::User => "kill",
            SignalDelivery::Tkill => "tkill",
            SignalDelivery::Queue => "sigqueue",
            SignalDelivery::Timer => "timer_claimed",
            SignalDelivery::Mesgq => "mqueue_claimed",
            SignalDelivery::Asyncio => "aio_or_usb",
            SignalDelivery::Sigio => "sigio_claimed",
        }
    }

    /// Whether `actor_pid` names the process that aimed the signal. True for every
    /// class the kernel reaches from a sender's own context, and for the label
    /// classes too — a sender that NAMED -2/-3/-5 in `rt_sigqueueinfo` is still the
    /// caller, so the actor beside the record is it. `Asyncio` is the exception: the
    /// usbfs completion calls the hook from whatever context took the completion, so
    /// there `actor_pid == target_pid` says which CPU ran, not who aimed it, and must
    /// not be read as self-termination.
    ///
    /// Written as an allow-list on purpose: a class appended to this enum later
    /// defaults to "the actor proves nothing", which errs toward keeping the attack
    /// tier. The reverse would let a new label quietly disarm the responder.
    pub fn actor_names_the_sender(self) -> bool {
        matches!(
            self,
            SignalDelivery::User
                | SignalDelivery::Tkill
                | SignalDelivery::Queue
                | SignalDelivery::Timer
                | SignalDelivery::Mesgq
                | SignalDelivery::Sigio
        )
    }
}

/// WARDEN_ACCESS decision bit (above the intent nibble in `aux2`) — must match
/// `WARDEN_ACCESS_DENIED` in warden.h. Set when the guard actually returned
/// -EPERM (armed + unauthorised + guarded intent); clear ⇒ a shadow would-deny.
pub const WARDEN_ACCESS_DENIED: u32 = 0x100;

/// The CONNECT/LISTEN `aux2` packing — must match `WARDEN_NET_*` in warden.h.
/// Family sits in bits 0..15, the socket's `sk_protocol` in bits 16..23, and for
/// CONNECT_RESULT only the outcome in bits 24..31.
pub const WARDEN_NET_FAMILY_MASK: u32 = 0x0000_FFFF;
pub const WARDEN_NET_PROTO_SHIFT: u32 = 16;
pub const WARDEN_NET_PROTO_MASK: u32 = 0x00FF_0000;
pub const WARDEN_NET_RESULT_SHIFT: u32 = 24;
pub const WARDEN_NET_RESULT_MASK: u32 = 0xFF00_0000;

/// What a network record was dialed *with*. Mirrors the platform's flow contract
/// vocabulary (`<parent-project>/sentinel/ndr/records.py` `KNOWN_PROTOCOLS` +
/// `DEFAULT_PROTOCOL`), so a label Warden emits today is one the far-side
/// detectors already name — inventing a private spelling here would just make the
/// flow row refuse itself later.
///
/// `None` (never this enum) is what an unstamped record means: the wire protocol
/// byte is 0, which is also a legal `sk_protocol` for a raw socket opened with
/// `IPPROTO_IP`. Nothing may be claimed from it, so decode yields no protocol and
/// the finding carries `null` — a fabricated "other" would let an egress rule
/// match a transport nobody observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl Protocol {
    /// Every transport label the finding can carry. `--explain` prints this as
    /// what it accepts, so the CLI's spelling and the wire's stay one list.
    pub const ALL: [Protocol; 4] = [
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Other,
    ];

    /// The kernel's `IPPROTO_*` numbers for the transports this sensor can
    /// actually see on a socket. Anything else is `Other` — a real observation of
    /// an unusual transport, not a gap in decoding.
    pub fn from_u8(v: u8) -> Self {
        match v {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            _ => Protocol::Other,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Icmp => "icmp",
            Protocol::Other => "other",
        }
    }
}

/// What a TCP connect's return value meant — mirrors
/// `enum warden_connect_outcome` in warden.h, where the measurements behind every
/// boundary (including the 91% of live dials this hook cannot classify) are
/// written out. Carried on the wire in `aux2` bits 24..31, CONNECT_RESULT only.
///
/// The producer never emits `NoClaim`: a dial whose outcome is not yet known
/// produces no record at all. A record that arrives with 0 in that field — or with
/// a number above this enum's range — is a record whose meaning the decoder does
/// not have, so `from_u32` rejects it and `decode` drops the whole event rather
/// than inventing a state for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    Established,
    Refused,
    Timeout,
    Unreachable,
    Blocked,
    Aborted,
    Interrupted,
    WouldBlock,
    AlreadyConnected,
    FailedOther,
}

impl ConnectOutcome {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(ConnectOutcome::Established),
            2 => Some(ConnectOutcome::Refused),
            3 => Some(ConnectOutcome::Timeout),
            4 => Some(ConnectOutcome::Unreachable),
            5 => Some(ConnectOutcome::Blocked),
            6 => Some(ConnectOutcome::Aborted),
            7 => Some(ConnectOutcome::Interrupted),
            8 => Some(ConnectOutcome::WouldBlock),
            9 => Some(ConnectOutcome::AlreadyConnected),
            10 => Some(ConnectOutcome::FailedOther),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ConnectOutcome::Established => "established",
            ConnectOutcome::Refused => "refused",
            ConnectOutcome::Timeout => "timeout",
            ConnectOutcome::Unreachable => "unreachable",
            ConnectOutcome::Blocked => "blocked",
            ConnectOutcome::Aborted => "aborted",
            ConnectOutcome::Interrupted => "interrupted",
            ConnectOutcome::WouldBlock => "would_block",
            ConnectOutcome::AlreadyConnected => "already_connected",
            ConnectOutcome::FailedOther => "failed_other",
        }
    }

    /// The Zeek `conn_state` this outcome corresponds to, in the vocabulary the
    /// platform ingests (`<parent-project>/sentinel/ndr/records.py` `KNOWN_CONN_STATES`),
    /// or `None` when that vocabulary has no honest word for it.
    ///
    /// Deliberately sparse. A kernel `connect(2)` verdict describes the originator's
    /// half of a handshake, while Zeek's states are seen from the wire and include
    /// teardown (`SF`, `RSTO`, `SH`…) that this record cannot know. Claiming one of
    /// those would be a fabricated state, and the platform treats `conn_state` as
    /// failure *evidence* — its scan detector counts `S0`/`REJ`/`RSTOS0`/`RSTRH` —
    /// so an over-eager mapping would inflate a scan finding out of ordinary
    /// connections. Only three states are asserted:
    ///   - `Established` → `S1` (open, not yet torn down; never `SF`, which needs a
    ///     close this sensor does not see)
    ///   - `Refused`     → `REJ` (a reply arrived and it was a refusal)
    ///   - `Timeout`     → `S0` (nothing answered the SYN within the connect timeout)
    ///
    /// `Unreachable` is NOT mapped to `S0` even though it looks the same from here:
    /// an `ENETUNREACH` can be produced by the local routing table without a single
    /// packet leaving, and `S0` specifically means "we sent a SYN and heard nothing".
    pub fn conn_state_hint(self) -> Option<&'static str> {
        match self {
            ConnectOutcome::Established => Some("S1"),
            ConnectOutcome::Refused => Some("REJ"),
            ConnectOutcome::Timeout => Some("S0"),
            _ => None,
        }
    }
}

/// Split a network record's packed `aux2` into (family, protocol). Shared by
/// CONNECT, LISTEN and CONNECT_RESULT, which stamp the same low 24 bits; a
/// protocol byte of 0 yields None, which is "no claim" and never `Other`.
fn net_aux2(aux2: u32) -> (u32, Option<Protocol>) {
    let family = aux2 & WARDEN_NET_FAMILY_MASK;
    let proto = match (aux2 & WARDEN_NET_PROTO_MASK) >> WARDEN_NET_PROTO_SHIFT {
        0 => None,
        v => Some(Protocol::from_u8(v as u8)),
    };
    (family, proto)
}

/// Render an intent mask as its bit names, for readable evidence ("read|write").
pub fn intent_names(intent: u32) -> String {
    let mut out: Vec<&str> = Vec::new();
    if intent & WARDEN_INTENT_READ != 0 {
        out.push("read");
    }
    if intent & WARDEN_INTENT_WRITE != 0 {
        out.push("write");
    }
    if intent & WARDEN_INTENT_EXEC != 0 {
        out.push("exec");
    }
    out.join("|")
}

/// Wire-identical to `struct warden_event`. `#[repr(C)]` + fixed arrays give it
/// the same layout the kernel wrote, so we can transmute the ring-buffer bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub kind: u32,
    pub actor_pid: u32,
    pub actor_tid: u32,
    pub actor_ppid: u32,
    pub actor_uid: u32,
    pub target_pid: u32,
    pub aux: u32,
    pub aux2: u32,
    pub ts_ns: u64,
    pub cap_old: u64,
    pub cap_new: u64,
    pub daddr: [u8; WARDEN_ADDR_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME],
}

/// CREDS only: the privilege transition `commit_creds` just applied. Folded out
/// of the raw `aux`/`aux2`/`cap_*` overloads during decode so the detector reasons
/// about a named change, not wire slots. `gained_caps` is the bits set in the new
/// effective mask that were not set in the old — the capabilities just acquired.
#[derive(Debug, Clone)]
pub struct CredChange {
    pub old_uid: u32,
    pub new_uid: u32,
    pub cap_old: u64,
    pub cap_new: u64,
}

impl CredChange {
    /// Capabilities present in the new effective set but absent from the old.
    pub fn gained_caps(&self) -> u64 {
        self.cap_new & !self.cap_old
    }
    /// Did this transition move the effective uid to root?
    pub fn to_root(&self) -> bool {
        self.new_uid == 0 && self.old_uid != 0
    }
}

/// ACCESS only: an unauthorised touch of a guarded inode, seen at a BPF-LSM hook.
/// Folded out of the raw `aux`/`aux2`/`cap_old`/`cap_new`/`target_pid` overloads
/// during decode so the detector reasons about a named access, not wire slots.
///
/// The record carries BOTH the identity of the guarded file (`dev`/`ino` — the
/// key the kernel matched) and the verdict the kernel reached: `denied` is true
/// only when the guard was armed AND actually returned -EPERM. A record with
/// `denied == false` is a SHADOW would-deny — the access was observed and allowed
/// through, and this is what it WOULD have blocked once armed. `authorized_uid`
/// is who the policy permits; the actor's own uid is `Event.actor_uid`.
#[derive(Debug, Clone)]
pub struct AccessInfo {
    pub hook: AccessHook,
    pub intent: u32,
    pub denied: bool,
    pub dev: u64,
    pub ino: u64,
    pub authorized_uid: u32,
}

impl AccessInfo {
    /// Human-readable intent ("read|write"). Thin wrapper over `intent_names`.
    pub fn intent_str(&self) -> String {
        intent_names(self.intent)
    }
}

/// FLOW only: what an accepted inbound connection says beyond the peer endpoint
/// `dest` already carries. Folded out of the `target_pid`/`cap_old` overloads
/// during decode, the way ACCESS folds its six.
///
/// `local_port` is WHICH listener took the connection. One accepting task usually
/// serves several, and the pull path's row for the same socket is keyed on
/// (local, remote) — so this is what lets a FLOW record be compared against a
/// `/proc/net` ESTABLISHED line rather than merely resembling one.
///
/// `netns_ino` is the inode number of the network namespace the child socket
/// lives in. The kprobe is global, so this sensor records accepts inside a
/// container's namespace — which the pull path cannot see at all, since it reads
/// only Warden's own `/proc/net`. Comparing the number against Warden's own
/// inode (`/proc/self/ns/net`) is what tells those two apart; a FLOW from another
/// namespace is not a host flow with an unattributed owner, it is a flow the host
/// socket table does not contain. `0` means the read did not succeed, and is
/// rendered as absent rather than as namespace zero — a real netns inode is never
/// 0, so the no-claim convention the network fields already use holds here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowInfo {
    pub local_port: u16,
    pub netns_ino: u64,
}

/// The actor's own executable, named as the kernel named it while the hook ran:
/// the `(super_block dev, inode number)` pair of `task->mm->exe_file`, folded out
/// of the `cap_old`/`cap_new` overloads.
///
/// An identity, not a name. `comm` is a string the process picked with
/// `prctl(PR_SET_NAME)` and `/proc/<pid>/exe` is a read that happens milliseconds
/// later, by which time a short-lived actor is gone; this pair is taken inside the
/// hook, where the task is alive by construction, so it still names the file after
/// the process exits and after a `hidepid=` mount makes `/proc` useless. Matching
/// it against `stat()` of an authorized path answers "was this the authorized
/// program" for an actor userspace can no longer see.
///
/// The number in `dev` is the kernel's `kdev_t` encoding (`major<<20 | minor`),
/// the same form `crate::guard::to_kernel_dev` produces from `st_dev` and the same
/// form the guarded-inode map keys use — one encoding, or the comparisons silently
/// never match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl ExeIdentity {
    /// The pair as a finding prints it, in the same words an operator pastes back
    /// into `--explain exe_dev=… exe_ino=…`.
    pub fn label(&self) -> String {
        format!("dev={} ino={}", self.dev, self.ino)
    }

    /// The identity of a path as the kernel would have stamped it for a process
    /// running it, or None when the path cannot be resolved.
    ///
    /// `st_dev` is the glibc packing and `s_dev` is the kernel's, so the conversion
    /// in `crate::guard::to_kernel_dev` is not decoration: compared raw, the two
    /// numbers describe the same filesystem and never match.
    pub fn of_path(path: &str) -> Option<ExeIdentity> {
        let meta = std::fs::metadata(path).ok()?;
        Some(ExeIdentity {
            dev: crate::guard::to_kernel_dev(meta.st_dev()),
            ino: meta.st_ino(),
        })
    }
}

/// A decoded, owned event — strings resolved, kind typed. What the rest of the
/// agent reasons about. This is a curated view, not a full mirror of `RawEvent`:
/// per-kind raw fields (the address family, the raw address bytes, the cred
/// overloads) are folded into higher-level fields like `dest`/`creds` during decode.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: Kind,
    pub actor_pid: u32,
    pub actor_ppid: u32,
    pub actor_uid: u32,
    pub target_pid: u32,
    pub aux: u32,
    pub ts_ns: u64,
    pub comm: String,
    pub filename: String,
    /// CONNECT: the resolved remote destination "ip:port" (e.g. "203.0.113.4:443").
    /// LISTEN: the resolved local bound endpoint "ip:port" (e.g. "0.0.0.0:4444").
    /// None for every other kind, and for a socket whose family we don't decode.
    pub dest: Option<String>,
    /// CONNECT/LISTEN only: the transport the socket carries, read from
    /// `sk_protocol` in the hook. None for every other kind, and for a record
    /// whose protocol byte was never stamped (see [`Protocol`]).
    pub protocol: Option<Protocol>,
    /// CONNECT_RESULT only: the verdict the transport returned. None for every
    /// other kind — and never `None` for a CONNECT_RESULT that decoded at all,
    /// because an unstamped outcome rejects the record (see [`ConnectOutcome`]).
    pub connect_outcome: Option<ConnectOutcome>,
    /// FLOW only: which listener took the connection and which network namespace
    /// the socket is in. Folded out of the `target_pid`/`cap_old` overloads; None
    /// for every other kind, because those two slots mean something else there
    /// (a victim tgid, a capability mask, an inode device). See [`FlowInfo`].
    pub flow: Option<FlowInfo>,
    /// CREDS only: the privilege transition. None for every other kind.
    pub creds: Option<CredChange>,
    /// BPFLOAD only: the `bpf_prog_type` of the program being loaded, folded out
    /// of `aux2`. Lets the detector separate a stealth-capable implant (kprobe /
    /// tracepoint / xdp / lsm) from the benign resource filters the init system
    /// loads routinely (cgroup_skb / cgroup_device …). None for every other kind.
    pub bpf_prog_type: Option<u32>,
    /// BPFLOAD only: the actor's own executable file, named by the kernel inside
    /// the hook (folded out of `cap_old`/`cap_new`). This is the one identity that
    /// outlives the process: `/proc/<pid>/exe` needs the task to still be there
    /// when userspace reads it, this does not. None for every other kind, and for a
    /// record whose slots were left zero — which covers both "no address space to
    /// read" and an object built before the kernel stamped it. See [`ExeIdentity`].
    pub actor_exe_file: Option<ExeIdentity>,
    /// ACCESS only: the guarded-inode access the BPF-LSM layer saw (and, when
    /// armed, denied). Folded out of the aux/aux2/cap_*/target_pid overloads.
    /// None for every other kind.
    pub access: Option<AccessInfo>,
    /// SIGNAL only: the sender is the victim's real parent, decided in the hook
    /// before either task can disappear. False for every other kind (and for a
    /// signal from anywhere but the parent).
    pub signal_from_parent: bool,
    /// SIGNAL only: which call aimed the signal, read from the siginfo in the hook
    /// (W2K-04). None for every other kind — `aux2` is a per-kind scratch slot, and
    /// the class field collides with an address family otherwise. `Detector::
    /// judge_signal` pairs it with `actor_pid == target_pid` to tell a process
    /// killing itself (a crash) from an outside takedown.
    pub signal_delivery: Option<SignalDelivery>,
}

fn cstr(bytes: &[u8]) -> String {
    // Bytes up to the first NUL; lossy so a mangled path can never panic us.
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Rebuild the trailing path from the fixed component ladder the kernel packed
/// into a 256-byte buffer (cell 0 = leaf, then each ancestor directory in the
/// next `WARDEN_SVC_SLOT`-byte cell). Empty cells and the "/" root cell (a dentry
/// that is its own parent, or a mount root) are dropped, the survivors are
/// ordered root-to-leaf, joined with "/", and given a leading "/". A path deeper
/// than `WARDEN_SVC_DEPTH` is truncated to its last components — enough to hold
/// the persistence-directory substrings userspace matches on
/// (".../systemd/system/x", ".../cron.d/x", ".../autostart/x"). Returns "" if the
/// ladder is entirely empty. Used by SERVICE for the created-file path the kernel
/// packs into `filename`.
fn service_path(bytes: &[u8; MAX_FILENAME]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(WARDEN_SVC_DEPTH);
    for i in 0..WARDEN_SVC_DEPTH {
        let cell = &bytes[i * WARDEN_SVC_SLOT..(i + 1) * WARDEN_SVC_SLOT];
        let name = cstr(cell);
        if name.is_empty() || name == "/" {
            continue; // empty ladder rung, or the root/mount dentry naming itself
        }
        parts.push(name);
    }
    if parts.is_empty() {
        return String::new();
    }
    parts.reverse(); // stored leaf-first; a filesystem path reads root-first
    format!("/{}", parts.join("/"))
}

/// Address families as the kernel numbers them (`AF_INET`/`AF_INET6`). The
/// connect sensor stamps one of these into `aux2`; anything else we decline to
/// decode rather than guess at the address bytes' meaning.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

/// The same two families, named for the pull path, so `net_snap` asks for a
/// family by name instead of repeating the kernel's numbers a second time.
pub(crate) fn family_tag(ip: &std::net::IpAddr) -> u32 {
    match ip {
        std::net::IpAddr::V4(_) => AF_INET,
        std::net::IpAddr::V6(_) => AF_INET6,
    }
}

/// Render a socket record's endpoint as "ip:port", or None when the family
/// isn't one we decode. Used for both CONNECT (the remote destination) and
/// LISTEN (the local bound address). The address bytes are in network order
/// exactly as the kernel holds them in the sockaddr / sock_common, so
/// `Ipv4Addr::from`/`Ipv6Addr::from` (both big-endian constructors) read them
/// directly.
///
/// `pub(crate)` because `net_snap` renders the same endpoints out of
/// `/proc/net/*` and the two sides are compared as strings: one formatter is
/// what makes that comparison mean anything.
pub(crate) fn dest_of(family: u32, addr: &[u8; WARDEN_ADDR_LEN], port: u16) -> Option<String> {
    match family {
        AF_INET => {
            let octets: [u8; 4] = addr[..4].try_into().ok()?;
            Some(format!("{}:{}", Ipv4Addr::from(octets), port))
        }
        AF_INET6 => {
            let octets: [u8; 16] = *addr;
            // Bracketed, per RFC 3986, so "[::1]:443" round-trips unambiguously.
            Some(format!("[{}]:{}", Ipv6Addr::from(octets), port))
        }
        _ => None,
    }
}

impl RawEvent {
    /// Decode a ring-buffer slice into an owned `Event`. Returns None if the
    /// slice is too short or the kind byte is unknown (defensive: never trust
    /// the length blindly even though the kernel writes a fixed size).
    pub fn decode(buf: &[u8]) -> Option<Event> {
        if buf.len() < std::mem::size_of::<RawEvent>() {
            return None;
        }
        // SAFETY: length checked above; RawEvent is repr(C) POD with no padding
        // invariants that a byte copy could violate. We copy out, never alias.
        let raw: RawEvent = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const RawEvent) };
        let kind = Kind::from_u32(raw.kind)?;
        // CONNECT, LISTEN, CONNECT_RESULT and FLOW all stamp an inet endpoint the same
        // way (address in daddr, port in aux, family+protocol packed in the low 24 bits
        // of aux2); resolve any of them into `dest`, and take the transport out of the
        // same word. That shared layout is the whole reason an attempt and its verdict
        // can be correlated in userspace at all — and why an ACCEPTED flow's peer is
        // comparable, string for string, with a dial's destination.
        let is_net = kind == Kind::Connect
            || kind == Kind::Listen
            || kind == Kind::ConnectResult
            || kind == Kind::Flow;
        let (family, protocol) = if is_net {
            net_aux2(raw.aux2)
        } else {
            (raw.aux2, None)
        };
        // CONNECT_RESULT only, and only from that kind: bits 24..31 are free for every
        // other network kind, and reading them there would see 0 (NoClaim) and call it
        // a verdict. An unknown number rejects the record like an unknown hook does.
        let connect_outcome = if kind == Kind::ConnectResult {
            Some(ConnectOutcome::from_u32(
                (raw.aux2 & WARDEN_NET_RESULT_MASK) >> WARDEN_NET_RESULT_SHIFT,
            )?)
        } else {
            None
        };
        let dest = if is_net {
            dest_of(family, &raw.daddr, raw.aux as u16)
        } else {
            None
        };
        let creds = if kind == Kind::Creds {
            Some(CredChange {
                new_uid: raw.aux,
                old_uid: raw.aux2,
                cap_old: raw.cap_old,
                cap_new: raw.cap_new,
            })
        } else {
            None
        };
        // BPFLOAD carries the program type in aux2 (see warden.h); fold it out so
        // the detector reasons about a named program kind, not a raw wire slot.
        let bpf_prog_type = if kind == Kind::BpfLoad {
            Some(raw.aux2)
        } else {
            None
        };
        // BPFLOAD also carries the actor's executable inode in cap_old/cap_new (see
        // `fill_exe_inode` and warden.h). `ino == 0` is the no-claim encoding, not a
        // file: it is what an object built before the kernel stamped these leaves
        // behind, and what a task with no address space gives, and the caller must
        // fall back to its weaker evidence rather than match against inode 0.
        let actor_exe_file = if kind == Kind::BpfLoad && raw.cap_new != 0 {
            Some(ExeIdentity {
                dev: raw.cap_old,
                ino: raw.cap_new,
            })
        } else {
            None
        };
        let signal_from_parent = kind == Kind::Signal && raw.aux2 & WARDEN_SIGNAL_FROM_PARENT != 0;
        // W2K-04: which call aimed the signal. Only the hook can say — the siginfo is
        // gone by the time this record is read. Decoded for SIGNAL alone, because
        // aux2 is a per-kind scratch slot (AF_INET is 2, which would otherwise read
        // as the sigqueue class), and an unknown class number rejects the record the
        // way an unknown ACCESS hook does.
        let signal_delivery = if kind == Kind::Signal {
            Some(SignalDelivery::from_u32(
                (raw.aux2 & WARDEN_SIGNAL_DELIVERY_MASK) >> WARDEN_SIGNAL_DELIVERY_SHIFT,
            )?)
        } else {
            None
        };
        // FLOW folds its two extra slots (see `FlowInfo` and the FLOW block in
        // warden.h). No rejection rule applies: both fields are plain numbers with
        // no unknown-value shape, and a `dest` the family check did not already
        // reject cannot exist here.
        let flow = if kind == Kind::Flow {
            Some(FlowInfo {
                local_port: raw.target_pid as u16,
                netns_ino: raw.cap_old,
            })
        } else {
            None
        };
        // ACCESS folds six overloaded slots into one AccessInfo: aux = which LSM
        // hook, aux2 = intent nibble OR'd with the DENIED bit, cap_old/cap_new =
        // the guarded inode's dev/ino, target_pid = the inode's authorized uid.
        // An unknown hook id makes the whole record undecodable (return None) —
        // same append-only discipline as an unknown kind.
        let access = if kind == Kind::Access {
            let hook = AccessHook::from_u32(raw.aux)?;
            Some(AccessInfo {
                hook,
                intent: raw.aux2 & 0xF,
                denied: raw.aux2 & WARDEN_ACCESS_DENIED != 0,
                dev: raw.cap_old,
                ino: raw.cap_new,
                authorized_uid: raw.target_pid,
            })
        } else {
            None
        };
        // SERVICE packs a component ladder into `filename`; every other kind
        // stores a plain string there. Rebuild the trailing path for SERVICE so
        // the detector reasons about "/etc/systemd/system/evil.service", not the
        // raw NUL-delimited cells.
        let filename = if kind == Kind::Service {
            service_path(&raw.filename)
        } else {
            cstr(&raw.filename)
        };
        Some(Event {
            kind,
            actor_pid: raw.actor_pid,
            actor_ppid: raw.actor_ppid,
            actor_uid: raw.actor_uid,
            target_pid: raw.target_pid,
            aux: raw.aux,
            ts_ns: raw.ts_ns,
            comm: cstr(&raw.comm),
            filename,
            dest,
            protocol,
            connect_outcome,
            flow,
            creds,
            bpf_prog_type,
            actor_exe_file,
            access,
            signal_from_parent,
            signal_delivery,
        })
    }
}

/// Read a process's current exe path from /proc, for enrichment. Best-effort:
/// a fileless (deleted-on-disk) process shows up as "<path> (deleted)", which
/// is itself a T3 signal the detector keys on.
pub fn exe_of(pid: u32) -> Option<String> {
    let link = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(link.to_string_lossy().into_owned())
}

/// Read a process's cgroup path from /proc, for app-cgroup attribution.
pub fn cgroup_of(pid: u32) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // cgroup v2 has a single "0::<path>" line.
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.trim().to_string());
        }
    }
    raw.lines().next().map(|l| l.to_string())
}

/// The three answers a read of `/proc/<pid>/stat` can give, kept apart because
/// they justify three different decisions.
///
/// Collapsing these into `Option<u64>` is what produced W2K-37: a host with
/// `/proc` mounted `hidepid=2` for the agent's uid and a process that genuinely
/// exited both read as `None`, so the journal said "the process had already
/// exited" about a live target and the enforcement gap looked like luck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcIdentity {
    /// There is a process at that number and it started at these ticks.
    Known(u64),
    /// No process has that number now, as far as `/proc` can say (`ENOENT`).
    /// NOT proof of an exit: a `hidepid=2` mount gives the same answer for a live
    /// process owned by another uid, so only `respond`'s pidfd corroboration may
    /// turn this into "it exited" (W2K-39).
    Gone,
    /// A process may well be there, but this user cannot read it — `EACCES` or
    /// `EPERM` from a `hidepid=` mount or a ptrace/yama rule. The errno is kept
    /// so the log can name the mechanism instead of guessing.
    Hidden(i32),
    /// The file was readable but field 22 was not parseable. Never treated as
    /// "gone": a truncated or racing read must not look like an exited process.
    Malformed,
}

impl ProcIdentity {
    /// The start time, when the read produced one. Used by the callers that only
    /// ever had `Option<u64>` — including [`Protected::immune`].
    pub fn as_starttime(&self) -> Option<u64> {
        match self {
            ProcIdentity::Known(t) => Some(*t),
            _ => None,
        }
    }

    /// One clause, for a log line: what the kernel actually said.
    pub fn explain(&self) -> String {
        match self {
            ProcIdentity::Known(t) => format!("a process that started at {t}"),
            ProcIdentity::Gone => "nothing at that pid (ENOENT)".to_string(),
            ProcIdentity::Hidden(errno) => format!(
                "/proc/{errno} — the pid may be live but this user cannot read it (a hidepid= \
                 mount or a ptrace rule), so its identity is unknown",
                errno = std::io::Error::from_raw_os_error(*errno)
            ),
            ProcIdentity::Malformed => {
                "/proc/<pid>/stat was readable but field 22 did not parse".to_string()
            }
        }
    }
}

/// Read the identity anchor of `pid` as a three-state answer. See
/// [`ProcIdentity`] — prefer this over [`starttime_of`] wherever the difference
/// between "exited", "hidden" and "unreadable" changes what gets logged.
pub fn identity_of(pid: u32) -> ProcIdentity {
    identity_from_read(std::fs::read_to_string(format!("/proc/{pid}/stat")))
}

/// The classification half of [`identity_of`], split out so all four answers are
/// testable — a real `/proc` will not hand an unprivileged test an `EACCES`, and
/// guessing "gone" instead of "hidden" is exactly the defect (W2K-37) this split
/// exists to make provable.
fn identity_from_read(read: Result<String, std::io::Error>) -> ProcIdentity {
    match read {
        Ok(raw) => match parse_starttime(&raw) {
            Some(ticks) => ProcIdentity::Known(ticks),
            None => ProcIdentity::Malformed,
        },
        Err(err) => match err.raw_os_error() {
            // ENOENT is the only errno that can mean "no process with that
            // number" — but it is not proof of it. A `hidepid=2` mount answers
            // ENOENT for another user's LIVE processes too (measured: report
            // §۷۰-۱۰ T7), which is why `respond` corroborates this answer with a
            // pidfd before calling anything exited (W2K-39). Nothing else in this
            // crate may treat `Gone` as liveness on its own.
            Some(libc::ENOENT) => ProcIdentity::Gone,
            Some(errno) => ProcIdentity::Hidden(errno),
            // A std error with no errno (only a virtual fs could do this): say
            // nothing about liveness.
            None => ProcIdentity::Malformed,
        },
    }
}

/// A process's start time, in clock ticks since boot — field 22 of
/// `/proc/<pid>/stat`. This is the identity anchor for W-R3: a pid is only a
/// number, and the kernel reuses it, so "pid 4711" does not name one process
/// for all time. (pid, starttime) does, because two processes cannot occupy the
/// same pid at the same instant and a recycled pid necessarily has a later
/// start time than the process it replaced.
///
/// `None` means "no start time", which covers both an exited process and a
/// `/proc` this user cannot read. Use [`identity_of`] when the log must say
/// which.
///
/// Parsing note: field 2 is the comm, wrapped in parentheses, and a process may
/// put anything in it — including spaces and parentheses (`(sd-pam)`, or a
/// process that renames itself to `) 0 0 0`). Splitting the line on whitespace
/// therefore mis-indexes every field after it. Everything before the *last*
/// `)` is the pid and comm; the fields we want start after it.
pub fn starttime_of(pid: u32) -> Option<u64> {
    identity_of(pid).as_starttime()
}

/// Is a pid number still occupied, asked of the kernel's pid table instead of
/// `/proc`?
///
/// `/proc` cannot answer this honestly on the hosts Warden is deployed to. A
/// `hidepid=2` mount answers `ENOENT` for another user's *live* process — measured
/// in report §۷۰-۱۰ — so "no such file" means both "it exited" and "you are not
/// allowed to see it", and conflating them is W2K-37/W2K-39. `pidfd_open` asks the
/// kernel's pid table instead of a mounted filesystem, and report §۷۷ measured the
/// consequence on Debian 13 / 6.12.107: as uid 1000 with an empty capability set,
/// behind `hidepid=invisible`, it answered `ALIVE` for three root-owned processes
/// whose `/proc/<pid>/exe` read `ENOENT` at the same instant. That is the answer
/// this type exists to get; the `Unknown` arm is what a kernel without pidfd or a
/// seccomp filter that refuses the syscall leaves behind, and §۷۷ records which
/// hosts are in which arm rather than assuming they all are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Something is at that number right now.
    Alive,
    /// Nothing is: the kernel said `ESRCH`.
    Gone,
    /// The kernel would not say (`ENOSYS` below 5.3, a seccomp filter, `EPERM`).
    /// Deliberately not collapsed with either of the others — an unknown answer
    /// must not be spent as evidence of an exit.
    Unknown(i32),
}

/// Ask [`Liveness`] of one pid. See the type: this is the question `/proc` cannot
/// answer on a `hidepid=` host.
pub fn pidfd_liveness(pid: u32) -> Liveness {
    // SAFETY: pidfd_open(2) takes (pid, flags); 0 is the only valid flags value.
    // Nothing is kept open on success — this asks only whether the number is
    // occupied, so the handle is closed immediately and no signal is ever sent
    // through it.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_long, 0) };
    if fd >= 0 {
        // SAFETY: `fd` is the pidfd just opened and is not used for anything else.
        unsafe { libc::close(fd as libc::c_int) };
        return Liveness::Alive;
    }
    // Same discipline as respond.rs and doctor.rs: errno belongs to the syscall
    // that set it, so it is read before anything else can clobber it.
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::ESRCH => Liveness::Gone,
        errno => Liveness::Unknown(errno),
    }
}

/// The parsing half of [`starttime_of`], split out so the awkward part is
/// testable with adversarial input instead of only through a real /proc.
///
/// Splitting the whole line on whitespace and taking index 21 (0-based) is the
/// obvious way to do this, and it is wrong: field 2 is the comm, and a process
/// may set its comm to anything at all via `prctl(PR_SET_NAME)` — including
/// spaces. `(sd-pam)` is ordinary; `) S 0 0` is legal and shifts every
/// subsequent field. Anchoring on the last `)` is what makes the index sound,
/// because everything before it is exactly "pid (comm" and the comm cannot
/// contain the final `)` that closes it... except when it can: the kernel
/// escapes `)` inside comm as `\)`, so the *last* `)` on the line is always the
/// real terminator.
fn parse_starttime(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // `after_comm` now begins with field 3 (state), so field 22 (starttime) is
    // at index 22 - 3 = 19 of the whitespace-split remainder.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// The full commandline (NUL-separated in /proc), for evidence.
pub fn cmdline_of(pid: u32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Signal number → name, for readable evidence.
///
/// The table covers every standard number rather than only the ones the responder is
/// armed for, because the record's severity now claims what the number *does* — a
/// summary that says "sent SIG?" cannot be checked against that claim by anyone reading
/// the journal. An unrecognised number, which on Linux means a real-time signal, is
/// rendered `SIG<n>` rather than dropped, exactly as `cap_names` keeps an unnamed bit.
pub fn signal_name(sig: u32) -> String {
    let named: &'static str = match sig as i32 {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGSTKFLT => "SIGSTKFLT",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGURG => "SIGURG",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGVTALRM => "SIGVTALRM",
        libc::SIGPROF => "SIGPROF",
        libc::SIGWINCH => "SIGWINCH",
        libc::SIGIO => "SIGIO",
        libc::SIGPWR => "SIGPWR",
        libc::SIGSYS => "SIGSYS",
        _ => return format!("SIG{sig}"),
    };
    named.to_string()
}

/// Render a capability bitmask as the names of the bits set, for readable
/// evidence ("CAP_SYS_ADMIN|CAP_NET_ADMIN"). Names track the kernel's
/// `linux/capability.h` bit positions; a bit we don't have a name for (a newer
/// kernel's capability) is rendered as "CAP_<n>" so nothing is silently dropped.
pub fn cap_names(mask: u64) -> String {
    // Indexed by capability number (bit position). Kept in sync with
    // include/uapi/linux/capability.h; index = the CAP_* value.
    const CAP_NAMES: [&str; 41] = [
        "CAP_CHOWN",              // 0
        "CAP_DAC_OVERRIDE",       // 1
        "CAP_DAC_READ_SEARCH",    // 2
        "CAP_FOWNER",             // 3
        "CAP_FSETID",             // 4
        "CAP_KILL",               // 5
        "CAP_SETGID",             // 6
        "CAP_SETUID",             // 7
        "CAP_SETPCAP",            // 8
        "CAP_LINUX_IMMUTABLE",    // 9
        "CAP_NET_BIND_SERVICE",   // 10
        "CAP_NET_BROADCAST",      // 11
        "CAP_NET_ADMIN",          // 12
        "CAP_NET_RAW",            // 13
        "CAP_IPC_LOCK",           // 14
        "CAP_IPC_OWNER",          // 15
        "CAP_SYS_MODULE",         // 16
        "CAP_SYS_RAWIO",          // 17
        "CAP_SYS_CHROOT",         // 18
        "CAP_SYS_PTRACE",         // 19
        "CAP_SYS_PACCT",          // 20
        "CAP_SYS_ADMIN",          // 21
        "CAP_SYS_BOOT",           // 22
        "CAP_SYS_NICE",           // 23
        "CAP_SYS_RESOURCE",       // 24
        "CAP_SYS_TIME",           // 25
        "CAP_SYS_TTY_CONFIG",     // 26
        "CAP_MKNOD",              // 27
        "CAP_LEASE",              // 28
        "CAP_AUDIT_WRITE",        // 29
        "CAP_AUDIT_CONTROL",      // 30
        "CAP_SETFCAP",            // 31
        "CAP_MAC_OVERRIDE",       // 32
        "CAP_MAC_ADMIN",          // 33
        "CAP_SYSLOG",             // 34
        "CAP_WAKE_ALARM",         // 35
        "CAP_BLOCK_SUSPEND",      // 36
        "CAP_AUDIT_READ",         // 37
        "CAP_PERFMON",            // 38
        "CAP_BPF",                // 39
        "CAP_CHECKPOINT_RESTORE", // 40
    ];
    if mask == 0 {
        return String::new();
    }
    let mut out: Vec<String> = Vec::new();
    for bit in 0..64u32 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        match CAP_NAMES.get(bit as usize) {
            Some(name) => out.push((*name).to_string()),
            None => out.push(format!("CAP_{bit}")),
        }
    }
    out.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── starttime parsing (W-R3) ────────────────────────────────────────────
    //
    // The responder's whole identity check rests on this parse, so it is worth
    // testing directly. A process may name itself anything at all via
    // prctl(PR_SET_NAME), which puts attacker-influenced text in the middle of
    // a whitespace-delimited line — the classic way to shift a field index.

    #[test]
    fn starttime_is_read_from_field_22() {
        // pid (comm) state, then fields 4..=21, then starttime as field 22.
        let line = "1234 (sleep) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20 21";
        assert_eq!(parse_starttime(line), Some(987654));
    }

    /// A comm containing spaces must not shift the index. Splitting the whole
    /// line on whitespace and taking token 21 — the obvious implementation —
    /// would read the wrong field here.
    #[test]
    fn a_comm_with_spaces_does_not_shift_the_starttime() {
        let line = "1234 (my comm) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
        assert_eq!(parse_starttime(line), Some(987654));
    }

    /// The kernel escapes `)` inside comm as `\)`, so the last `)` on the line
    /// is always the real terminator — even when the comm contains one. An
    /// implementation that split on the *first* `)` would stop early here.
    #[test]
    fn a_comm_containing_a_paren_does_not_end_the_parse_early() {
        let line = r"1234 (a\) b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
        assert_eq!(parse_starttime(line), Some(987654));
    }

    /// Too few fields must yield nothing, never a number scraped from the
    /// wrong position — a wrong start time is worse than none, because the
    /// responder would treat it as a verified identity.
    #[test]
    fn a_truncated_or_malformed_stat_line_yields_nothing() {
        assert_eq!(parse_starttime("1234 (sleep) S 1 2 3"), None);
        assert_eq!(parse_starttime("garbage with no paren"), None);
        assert_eq!(
            parse_starttime("1234 (sleep) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 xx"),
            None
        );
    }

    /// The real thing, against our own /proc: the value must be present and
    /// stable across two reads (a start time does not change).
    #[test]
    fn our_own_starttime_is_readable_and_stable() {
        let first = starttime_of(std::process::id()).expect("/proc/self/stat is readable");
        assert_eq!(starttime_of(std::process::id()), Some(first));
    }

    #[test]
    fn assert_abi_size() {
        // 8 * u32 = 32, + ts_ns u64 = 40, + cap_old u64 = 48, + cap_new u64 = 56,
        // + 16 daddr = 72, + 16 comm = 88, + 256 filename = 344. Every u64 sits at
        // an 8-aligned offset (32/40/48) and 344 is a multiple of 8, so there is no
        // hidden padding on either side. If this fails, the C struct and the Rust
        // mirror have drifted.
        assert_eq!(std::mem::size_of::<RawEvent>(), 344);
    }

    #[test]
    fn cstr_stops_at_nul() {
        let mut b = [0u8; 8];
        b[..3].copy_from_slice(b"sh\0");
        assert_eq!(cstr(&b), "sh");
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert!(RawEvent::decode(&[0u8; 4]).is_none());
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let mut buf = vec![0u8; std::mem::size_of::<RawEvent>()];
        buf[0] = 99; // kind = 99, unknown
        assert!(RawEvent::decode(&buf).is_none());
    }

    #[test]
    fn decodes_ipv4_connect_destination() {
        // A hand-built CONNECT record: family AF_INET in aux2, port 443 in aux,
        // 203.0.113.4 in the first four address bytes. The decoder must resolve
        // it to "203.0.113.4:443" and only then — connect is the one kind that
        // populates `dest`.
        let raw = RawEvent {
            kind: Kind::Connect as u32,
            actor_pid: 1000,
            actor_tid: 1000,
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 443,
            aux2: AF_INET,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr: [203, 0, 113, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        let ev = RawEvent::decode(bytes).unwrap();
        assert_eq!(ev.kind, Kind::Connect);
        assert_eq!(ev.dest.as_deref(), Some("203.0.113.4:443"));
    }

    #[test]
    fn decodes_ipv6_connect_destination() {
        let mut daddr = [0u8; WARDEN_ADDR_LEN];
        daddr[15] = 1; // ::1
        let raw = RawEvent {
            kind: Kind::Connect as u32,
            actor_pid: 1,
            actor_tid: 1,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 8443,
            aux2: AF_INET6,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        let ev = RawEvent::decode(bytes).unwrap();
        assert_eq!(ev.dest.as_deref(), Some("[::1]:8443"));
    }

    /// Build the wire bytes of a network record and decode them, so the packing
    /// tests read as "what `aux2` says → what the detector may claim" instead of
    /// twenty lines of struct literal each.
    fn decode_net(kind: Kind, port: u32, aux2: u32, daddr: [u8; WARDEN_ADDR_LEN]) -> Option<Event> {
        let raw = RawEvent {
            kind: kind as u32,
            actor_pid: 4242,
            actor_tid: 4242,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: port,
            aux2,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        RawEvent::decode(bytes)
    }

    const V4: [u8; WARDEN_ADDR_LEN] = [203, 0, 113, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// A FLOW record, i.e. a network record plus the two slots only the accept
    /// sensor fills: `target_pid` carries the LOCAL port and `cap_old` the socket's
    /// network-namespace inode.
    fn decode_flow(
        port: u32,
        aux2: u32,
        daddr: [u8; WARDEN_ADDR_LEN],
        local_port: u32,
        netns_ino: u64,
    ) -> Option<Event> {
        let raw = RawEvent {
            kind: Kind::Flow as u32,
            actor_pid: 933,
            actor_tid: 933,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: local_port,
            aux: port,
            aux2,
            ts_ns: 0,
            cap_old: netns_ino,
            cap_new: 0,
            daddr,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        RawEvent::decode(bytes)
    }

    #[test]
    fn a_flow_record_names_the_peer_the_door_and_the_namespace() {
        // The three facts the accept sensor exists for, each in the slot warden.h
        // assigns it. The peer port is in `aux` and renders through the same
        // formatter a dial uses — that shared rendering is what lets the pull path
        // compare the two — and the local port and netns are the two slots nothing
        // else in this kind reads.
        let v4 = [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let aux2 = AF_INET | (6 << WARDEN_NET_PROTO_SHIFT);
        let ev = decode_flow(41374, aux2, v4, 5432, 4_026_531_993).expect("a flow decodes");
        assert_eq!(ev.kind, Kind::Flow);
        assert_eq!(ev.dest.as_deref(), Some("127.0.0.1:41374"));
        assert_eq!(ev.protocol, Some(Protocol::Tcp));
        assert_eq!(
            ev.flow,
            Some(FlowInfo {
                local_port: 5432,
                netns_ino: 4_026_531_993
            })
        );
    }

    #[test]
    fn a_flow_record_never_borrows_a_dial_verdict() {
        // Bits 24..31 mean `enum warden_connect_outcome` for a CONNECT_RESULT and
        // nothing at all for a FLOW. A decoder that read them here would turn an
        // accepted connection into "refused" (2) purely because a stale or reused
        // byte happened to be set — the fabricated-network-fact class this ABI
        // refuses on purpose, so the read is gated on the kind, not on the value.
        let v4 = [10, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let aux2 = AF_INET | (6 << WARDEN_NET_PROTO_SHIFT) | (2 << WARDEN_NET_RESULT_SHIFT);
        let ev = decode_flow(51220, aux2, v4, 443, 1).expect("a flow decodes");
        assert_eq!(ev.connect_outcome, None);
        assert_eq!(
            ev.dest.as_deref(),
            Some("10.0.0.7:51220"),
            "the endpoint must still render — the outcome bits are not the family"
        );
    }

    #[test]
    fn a_flow_of_an_undecodable_family_keeps_its_port_and_loses_its_address() {
        // The family byte is what makes the address bytes mean anything; without it
        // the record keeps the two facts that need no interpretation (which port
        // accepted, which namespace) and declines the one it cannot render. An
        // address invented from bytes of unknown meaning would be worse than none.
        let ev = decode_flow(
            41374,
            0,
            [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            8200,
            9,
        )
        .expect("a flow with no family still decodes");
        assert_eq!(ev.dest, None);
        assert_eq!(ev.protocol, None);
        assert_eq!(ev.flow.map(|f| f.local_port), Some(8200));
        assert_eq!(ev.flow.map(|f| f.netns_ino), Some(9));
    }

    #[test]
    fn a_packed_aux2_gives_the_family_and_the_transport() {
        // The point of the stage: 17 (IPPROTO_UDP) in bits 16..23 beside AF_INET.
        // A dial to port 53 must be tellable from a TCP dial to the same endpoint.
        let ev = decode_net(
            Kind::Connect,
            53,
            AF_INET | (17 << WARDEN_NET_PROTO_SHIFT),
            V4,
        )
        .expect("a packed record decodes");
        assert_eq!(ev.dest.as_deref(), Some("203.0.113.4:53"));
        assert_eq!(ev.protocol, Some(Protocol::Udp));

        let tcp = decode_net(
            Kind::Listen,
            4444,
            AF_INET | (6 << WARDEN_NET_PROTO_SHIFT),
            V4,
        )
        .expect("a LISTEN record packs the same way");
        assert_eq!(tcp.dest.as_deref(), Some("203.0.113.4:4444"));
        assert_eq!(tcp.protocol, Some(Protocol::Tcp));
    }

    #[test]
    fn a_record_from_before_the_field_existed_keeps_its_family_and_claims_nothing() {
        // The append-only half, and the reason the family moved DOWN rather than the
        // protocol being XORed in somewhere: an old object wrote bare AF_INET (2) or
        // AF_INET6 (10) into aux2, both of which fit in bits 0..15. Such a record must
        // still resolve its destination, and must yield NO protocol — not "other",
        // not TCP-by-assumption. A policy that matched an invented transport would
        // report evidence nobody observed.
        let old = decode_net(Kind::Connect, 443, AF_INET, V4).expect("old record decodes");
        assert_eq!(old.dest.as_deref(), Some("203.0.113.4:443"));
        assert_eq!(old.protocol, None);

        let old6 = {
            let mut a = [0u8; WARDEN_ADDR_LEN];
            a[15] = 1;
            decode_net(Kind::Listen, 80, AF_INET6, a).expect("old v6 record decodes")
        };
        assert_eq!(old6.dest.as_deref(), Some("[::1]:80"));
        assert_eq!(old6.protocol, None);
    }

    #[test]
    fn a_protocol_byte_of_zero_is_absence_never_a_claim() {
        // 0 is both the unstamped value and a legal sk_protocol (a raw socket
        // opened with IPPROTO_IP). The two cases cannot be told apart on the wire,
        // so both must produce None: claiming "the transport is IP" from a byte
        // that may simply have never been written is the wrong direction to err.
        let ev = decode_net(
            Kind::Connect,
            53,
            AF_INET | (0 << WARDEN_NET_PROTO_SHIFT),
            V4,
        )
        .expect("family still decodes");
        assert_eq!(ev.protocol, None);
        // And the shift/mask pair must not let a protocol byte bleed into the family.
        assert_eq!(ev.dest.as_deref(), Some("203.0.113.4:53"));
    }

    #[test]
    fn an_unseen_transport_is_other_and_not_silently_dropped() {
        // 99 is a real observation of an unusual transport (SCTP-ish, IPPROTO_RAW on
        // a raw socket…): Other, still reported. Only the ABSENT case is None.
        assert_eq!(Protocol::from_u8(99), Protocol::Other);
        assert_eq!(Protocol::from_u8(1), Protocol::Icmp);
        let ev = decode_net(
            Kind::Connect,
            1,
            AF_INET | (99 << WARDEN_NET_PROTO_SHIFT),
            V4,
        )
        .expect("unusual transport decodes");
        assert_eq!(ev.protocol, Some(Protocol::Other));
    }

    #[test]
    fn the_protocol_labels_are_the_platform_flow_vocabulary() {
        // `<parent-project>/sentinel/ndr/records.py` allows exactly {tcp, udp, icmp} and
        // defaults the rest to 'other'. Warden's spelling has to be that spelling or
        // the flow row this feeds will refuse the value at ingest — loudly, by
        // design, which would look like a Warden bug and be a contract bug.
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
        assert_eq!(Protocol::Icmp.as_str(), "icmp");
        assert_eq!(Protocol::Other.as_str(), "other");
    }

    #[test]
    fn a_verdict_record_carries_the_endpoint_and_what_the_transport_decided() {
        // The whole point of stage 14: the dial and its outcome share a record
        // layout, so the same destination the CONNECT record reported still decodes
        // here — and the verdict comes out of the byte the kernel stamped last.
        let ev = decode_net(
            Kind::ConnectResult,
            4444,
            AF_INET | (6 << WARDEN_NET_PROTO_SHIFT) | (2 << WARDEN_NET_RESULT_SHIFT),
            V4,
        )
        .expect("a verdict record decodes");
        assert_eq!(ev.kind, Kind::ConnectResult);
        assert_eq!(
            ev.dest.as_deref(),
            Some("203.0.113.4:4444"),
            "the verdict record must resolve the endpoint the attempt did, or the two \
             halves describe different dials"
        );
        assert_eq!(ev.protocol, Some(Protocol::Tcp));
        assert_eq!(ev.connect_outcome, Some(ConnectOutcome::Refused));
        assert_eq!(
            ev.connect_outcome.and_then(|o| o.conn_state_hint()),
            Some("REJ")
        );
    }

    #[test]
    fn the_verdict_bits_mean_nothing_to_a_record_that_has_no_verdict() {
        // A CONNECT or LISTEN record's bits 24..31 are outside that kind's contract.
        // Reading them would turn every old object's unstamped high byte — or a stray
        // bit from a future kernel — into a verdict the sensor never made.
        let dial = decode_net(
            Kind::Connect,
            53,
            AF_INET | (17 << WARDEN_NET_PROTO_SHIFT) | (5 << WARDEN_NET_RESULT_SHIFT),
            V4,
        )
        .expect("the attempt still decodes");
        assert_eq!(dial.connect_outcome, None);
        assert_eq!(dial.protocol, Some(Protocol::Udp));
        assert_eq!(
            dial.dest.as_deref(),
            Some("203.0.113.4:53"),
            "the outcome byte must not bleed into the family read"
        );
    }

    #[test]
    fn a_verdict_number_the_kernel_does_not_stamp_rejects_the_record() {
        // 0 is "no claim" and 11 is nobody. Either arriving on a CONNECT_RESULT
        // record means producer and decoder disagree, and the honest answer to a
        // disagreement is no record — not the nearest category. Same rule as an
        // unknown kind, an unknown ACCESS hook and an unknown delivery class.
        for bad in [0u32, 11, 255] {
            let aux2 = AF_INET | (6 << WARDEN_NET_PROTO_SHIFT) | (bad << WARDEN_NET_RESULT_SHIFT);
            assert!(
                decode_net(Kind::ConnectResult, 443, aux2, V4).is_none(),
                "outcome {bad} is not a number the kernel stamps, and the record was \
                 accepted anyway"
            );
        }
        // Every number the kernel CAN stamp decodes, and to the right one.
        for (n, want) in [
            (1, ConnectOutcome::Established),
            (2, ConnectOutcome::Refused),
            (3, ConnectOutcome::Timeout),
            (4, ConnectOutcome::Unreachable),
            (5, ConnectOutcome::Blocked),
            (6, ConnectOutcome::Aborted),
            (7, ConnectOutcome::Interrupted),
            (8, ConnectOutcome::WouldBlock),
            (9, ConnectOutcome::AlreadyConnected),
            (10, ConnectOutcome::FailedOther),
        ] {
            let aux2 = AF_INET | (6 << WARDEN_NET_PROTO_SHIFT) | (n << WARDEN_NET_RESULT_SHIFT);
            let ev =
                decode_net(Kind::ConnectResult, 443, aux2, V4).expect("stamped outcome decodes");
            assert_eq!(
                ev.connect_outcome,
                Some(want),
                "outcome number {n} decoded as something else"
            );
        }
    }

    #[test]
    fn the_conn_state_hint_states_only_the_three_verdicts_a_connect_can_prove() {
        // A connect() verdict describes the originator's half of a handshake. Zeek's
        // vocabulary is seen from the wire and includes teardown; claiming one of
        // those, or S0 for a locally generated ENETUNREACH, would feed the platform's
        // scan detector a failure that never happened on the network.
        let all = [
            ConnectOutcome::Established,
            ConnectOutcome::Refused,
            ConnectOutcome::Timeout,
            ConnectOutcome::Unreachable,
            ConnectOutcome::Blocked,
            ConnectOutcome::Aborted,
            ConnectOutcome::Interrupted,
            ConnectOutcome::WouldBlock,
            ConnectOutcome::AlreadyConnected,
            ConnectOutcome::FailedOther,
        ];
        let stated: Vec<_> = all.iter().filter_map(|o| o.conn_state_hint()).collect();
        assert_eq!(
            stated,
            vec!["S1", "REJ", "S0"],
            "the hint set changed. Add a state only with the kernel code that proves it \
             written next to it, and never to make a null look complete."
        );
        // Unreachable in particular: ENETUNREACH can be raised by the local routing
        // table with no packet sent, and S0 specifically means "a SYN went out and
        // nothing answered".
        assert_eq!(ConnectOutcome::Unreachable.conn_state_hint(), None);
        assert_eq!(ConnectOutcome::Blocked.conn_state_hint(), None);
        assert_eq!(ConnectOutcome::FailedOther.conn_state_hint(), None);
    }

    #[test]
    fn the_outcome_labels_are_stable_and_unique() {
        // The label is what an operator greps for and what a journal filter matches,
        // so a rename is a breaking change to their tooling — and a duplicate is two
        // verdicts nobody can tell apart after the fact.
        let labels = [
            (ConnectOutcome::Established, "established"),
            (ConnectOutcome::Refused, "refused"),
            (ConnectOutcome::Timeout, "timeout"),
            (ConnectOutcome::Unreachable, "unreachable"),
            (ConnectOutcome::Blocked, "blocked"),
            (ConnectOutcome::Aborted, "aborted"),
            (ConnectOutcome::Interrupted, "interrupted"),
            (ConnectOutcome::WouldBlock, "would_block"),
            (ConnectOutcome::AlreadyConnected, "already_connected"),
            (ConnectOutcome::FailedOther, "failed_other"),
        ];
        let mut seen = std::collections::HashSet::new();
        for (o, want) in labels {
            assert_eq!(o.as_str(), want, "the journal label for {o:?} changed");
            assert!(seen.insert(o.as_str()), "{} named twice", o.as_str());
        }
        assert_eq!(Kind::ConnectResult.as_str(), "connect_result");
    }

    #[test]
    fn no_other_kind_leaks_a_protocol_or_a_family_read() {
        // Cross-kind discipline (the property tests fuzz this too, but pin the case
        // that matters here): a SIGNAL record's aux2 is a delivery class, so it must
        // never be read as family/protocol — AF_INET is 2, which IS a class number.
        for kind in [
            Kind::Signal,
            Kind::Exec,
            Kind::Ptrace,
            Kind::Creds,
            Kind::Access,
        ] {
            let ev = decode_net(kind, 2, 0, V4).expect("these kinds always decode");
            assert_eq!(
                ev.protocol, None,
                "{kind:?} must not claim a transport it never carried"
            );
            assert_eq!(ev.dest, None, "{kind:?} must not resolve an endpoint");
        }
    }

    #[test]
    fn unknown_family_yields_no_destination() {
        // A connect record whose family we don't decode must leave `dest` None
        // rather than misread the address bytes — the detector then treats it as
        // an un-attributable dial-out, not a false "0.0.0.0" destination.
        let raw = RawEvent {
            kind: Kind::Connect as u32,
            actor_pid: 1,
            actor_tid: 1,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 1,
            aux2: 99, // not AF_INET/AF_INET6
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr: [1u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        assert_eq!(RawEvent::decode(bytes).unwrap().dest, None);
    }

    #[test]
    fn decodes_a_creds_transition_to_root() {
        // A CREDS record: new euid 0 in aux, old euid 33 in aux2, and a capability
        // mask that gained CAP_SYS_ADMIN (bit 21). The decoder must fold the raw
        // slots into a CredChange that reports the root transition and the exact
        // capabilities gained — creds is the one kind that populates `creds`.
        let raw = RawEvent {
            kind: Kind::Creds as u32,
            actor_pid: 4242,
            actor_tid: 4242,
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: 0,   // new euid = root
            aux2: 33, // old euid = www-data
            ts_ns: 0,
            cap_old: 0,
            cap_new: 1 << 21, // CAP_SYS_ADMIN newly effective
            daddr: [0u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        let ev = RawEvent::decode(bytes).unwrap();
        assert_eq!(ev.kind, Kind::Creds);
        assert!(ev.dest.is_none());
        let c = ev.creds.expect("creds folded out");
        assert_eq!(c.old_uid, 33);
        assert_eq!(c.new_uid, 0);
        assert!(c.to_root());
        assert_eq!(c.gained_caps(), 1 << 21);
    }

    #[test]
    fn cap_names_renders_known_and_unknown_bits() {
        // CAP_SYS_ADMIN (21) alone.
        assert_eq!(cap_names(1 << 21), "CAP_SYS_ADMIN");
        // Two bits, rendered low-to-high and joined.
        assert_eq!(
            cap_names((1 << 12) | (1 << 21)),
            "CAP_NET_ADMIN|CAP_SYS_ADMIN"
        );
        // A bit past the named table degrades to CAP_<n> rather than vanishing.
        assert_eq!(cap_names(1 << 60), "CAP_60");
        // Empty mask is the empty string, never "CAP_?".
        assert_eq!(cap_names(0), "");
    }

    #[test]
    fn decodes_a_file_rename_with_its_leaf_name() {
        // A FILE record: op RENAME in aux, the new leaf name in filename. The
        // decoder carries both through untouched — the verdict (ransom extension?
        // watched name? burst?) is the detector's, not the decoder's.
        let mut filename = [0u8; MAX_FILENAME];
        let leaf = b"report.docx.locked";
        filename[..leaf.len()].copy_from_slice(leaf);
        let raw = RawEvent {
            kind: Kind::File as u32,
            actor_pid: 7777,
            actor_tid: 7777,
            actor_ppid: 1,
            actor_uid: 33,
            target_pid: 0,
            aux: FileOp::Rename as u32,
            aux2: 0,
            ts_ns: 123,
            cap_old: 0,
            cap_new: 0,
            daddr: [0u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        let ev = RawEvent::decode(bytes).unwrap();
        assert_eq!(ev.kind, Kind::File);
        assert_eq!(ev.filename, "report.docx.locked");
        assert_eq!(FileOp::from_u32(ev.aux), Some(FileOp::Rename));
        assert!(ev.creds.is_none() && ev.dest.is_none());
    }

    /// Pack a leaf-first component ladder into a SERVICE record's filename, the
    /// exact wire shape the kernel's four `bpf_probe_read_kernel_str` calls
    /// produce (cell 0 = leaf, cell 1 = parent, …).
    fn service_raw(components_leaf_first: &[&str]) -> RawEvent {
        let mut filename = [0u8; MAX_FILENAME];
        for (i, part) in components_leaf_first.iter().enumerate() {
            assert!(i < WARDEN_SVC_DEPTH, "ladder deeper than the wire allows");
            let cell = &mut filename[i * WARDEN_SVC_SLOT..(i + 1) * WARDEN_SVC_SLOT];
            let b = part.as_bytes();
            cell[..b.len()].copy_from_slice(b);
        }
        RawEvent {
            kind: Kind::Service as u32,
            actor_pid: 5150,
            actor_tid: 5150,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: ServiceOp::Create as u32,
            aux2: 0,
            ts_ns: 42,
            cap_old: 0,
            cap_new: 0,
            daddr: [0u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename,
        }
    }

    fn decode_raw(raw: &RawEvent) -> Event {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        RawEvent::decode(bytes).unwrap()
    }

    #[test]
    fn decodes_a_service_create_ladder_into_a_path() {
        // A rogue systemd unit dropped under /etc/systemd/system. The kernel
        // captured the leaf and its three ancestors; the decoder must rebuild the
        // trailing path root-first so the detector can match the persistence dir.
        let raw = service_raw(&["evil.service", "system", "systemd", "etc"]);
        let ev = decode_raw(&raw);
        assert_eq!(ev.kind, Kind::Service);
        assert_eq!(ev.filename, "/etc/systemd/system/evil.service");
        assert_eq!(ServiceOp::from_u32(ev.aux), Some(ServiceOp::Create));
        assert!(ev.creds.is_none() && ev.dest.is_none());
    }

    #[test]
    fn service_ladder_skips_empty_and_root_cells() {
        // A shallow path (a file created directly under "/") leaves upper cells
        // empty, and the mount-root dentry names itself "/"; both are dropped so
        // the rebuilt path has no doubled or trailing slashes.
        let raw = service_raw(&["rc.local", "etc", "/"]);
        assert_eq!(decode_raw(&raw).filename, "/etc/rc.local");

        let shallow = service_raw(&["passwd", "etc"]);
        assert_eq!(decode_raw(&shallow).filename, "/etc/passwd");
    }

    #[test]
    fn an_empty_service_ladder_decodes_to_empty() {
        // A fully-zeroed ladder (every read failed) must not fabricate a "/" — it
        // decodes to "", which the detector treats as an unattributable create.
        let raw = service_raw(&[]);
        assert_eq!(decode_raw(&raw).filename, "");
    }

    #[test]
    fn decodes_an_ipv4_listen_endpoint() {
        // A bind shell listening on 0.0.0.0:4444: family AF_INET in aux2, port in
        // aux, the wildcard local address in daddr. LISTEN resolves the same way
        // CONNECT does, into `dest` — the detector then judges the port/address.
        let raw = RawEvent {
            kind: Kind::Listen as u32,
            actor_pid: 6000,
            actor_tid: 6000,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 4444,
            aux2: AF_INET,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr: [0u8; WARDEN_ADDR_LEN], // 0.0.0.0 — listen on all interfaces
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let ev = decode_raw(&raw);
        assert_eq!(ev.kind, Kind::Listen);
        assert_eq!(ev.dest.as_deref(), Some("0.0.0.0:4444"));
        assert!(ev.creds.is_none());
    }

    #[test]
    fn decodes_an_ipv6_listen_endpoint() {
        let mut daddr = [0u8; WARDEN_ADDR_LEN];
        daddr[15] = 1; // ::1
        let raw = RawEvent {
            kind: Kind::Listen as u32,
            actor_pid: 6001,
            actor_tid: 6001,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 31337,
            aux2: AF_INET6,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        assert_eq!(decode_raw(&raw).dest.as_deref(), Some("[::1]:31337"));
    }

    #[test]
    fn decodes_a_bpf_prog_load() {
        // A BPFLOAD record carries the bpf() command in aux and nothing else; it
        // must decode to the Kind with no dest/creds and an empty filename.
        let raw = RawEvent {
            kind: Kind::BpfLoad as u32,
            actor_pid: 8000,
            actor_tid: 8000,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 5, // BPF_PROG_LOAD
            aux2: 0,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr: [0u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        };
        let ev = decode_raw(&raw);
        assert_eq!(ev.kind, Kind::BpfLoad);
        assert_eq!(ev.aux, 5);
        assert!(ev.dest.is_none() && ev.creds.is_none());
        assert_eq!(ev.filename, "");
    }

    /// A BPFLOAD record with the two `__u64` slots filled the way `fill_exe_inode`
    /// fills them: kernel `kdev_t` in `cap_old`, `i_ino` in `cap_new`.
    fn bpfload_raw_with_exe(dev: u64, ino: u64) -> RawEvent {
        let mut raw = zeroed_raw();
        raw.kind = Kind::BpfLoad as u32;
        raw.actor_pid = 8000;
        raw.aux = 5; // BPF_PROG_LOAD
        raw.aux2 = 2; // BPF_PROG_TYPE_KPROBE
        raw.cap_old = dev;
        raw.cap_new = ino;
        raw
    }

    #[test]
    fn a_bpfload_record_folds_the_exe_inode_the_kernel_stamped() {
        // 0x800_002 is major 8 / minor 2 in the kernel's own encoding. The decoder
        // passes the pair through untouched: `st_dev`'s glibc packing is converted
        // once, on the side that has to meet it (`ExeIdentity::of_path`), and a second
        // conversion here would be the bug — two halves of one comparison shifting
        // relative to each other is how an identity silently stops matching anything.
        let ev = decode_raw(&bpfload_raw_with_exe(0x800_002, 1234));
        assert_eq!(
            ev.actor_exe_file,
            Some(ExeIdentity {
                dev: 0x800_002,
                ino: 1234
            })
        );
        // The two facts share a record, not a slot: the program type still decodes.
        assert_eq!(ev.bpf_prog_type, Some(2));
    }

    #[test]
    fn an_unstamped_bpfload_record_claims_no_exe_inode() {
        // Zero in `cap_new` is the no-claim encoding, and it has to cover BOTH cases
        // that produce it: a task with no address space, and a record written by an
        // object built before this was stamped. Reading a device with no inode would
        // hand the detector an identity for inode 0 — a file that cannot exist, and so
        // a load that can never be authorised by anything.
        assert_eq!(
            decode_raw(&bpfload_raw_with_exe(0x800_002, 0)).actor_exe_file,
            None
        );
        assert_eq!(decode_raw(&bpfload_raw_with_exe(0, 0)).actor_exe_file, None);
    }

    #[test]
    fn only_a_kind_the_kernel_stamps_can_carry_an_exe_inode() {
        // `cap_old`/`cap_new` are per-kind scratch. On CREDS they are the capability
        // masks before and after a privilege change, and 1<<21 is CAP_SYS_ADMIN — not
        // inode 2097152. Folding them here would turn a root escalation into a claim
        // about an executable file.
        let mut creds = zeroed_raw();
        creds.kind = Kind::Creds as u32;
        creds.aux = 0;
        creds.aux2 = 1000;
        creds.cap_new = 1 << 21;
        let ev = decode_raw(&creds);
        assert!(ev.creds.is_some(), "the slots must still mean CREDS");
        assert_eq!(ev.actor_exe_file, None);

        // ACCESS uses the same two slots for a DIFFERENT file's identity — the guarded
        // inode, belonging to whoever owns that file, never to the actor.
        let guarded = access_raw(AccessHook::Open, WARDEN_INTENT_READ, false, 1000);
        let ev = decode_raw(&guarded);
        assert!(ev.access.is_some(), "the slots must still mean ACCESS");
        assert_eq!(ev.actor_exe_file, None);
    }

    #[test]
    fn of_path_names_the_file_not_the_name() {
        // The whole comparison rests on this: two paths, one file. A hardlink (or a
        // bind-mounted copy of the same inode) is the authorized program, and the
        // authorisation is about which CODE ran, not which spelling was typed.
        let dir = std::env::temp_dir().join(format!("warden-exe-id-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let original = dir.join("loader-a");
        let alias = dir.join("loader-b");
        std::fs::write(&original, b"#!/bin/sh\n").expect("write original");
        let _ = std::fs::remove_file(&alias);
        std::fs::hard_link(&original, &alias).expect("hardlink in one temp dir");
        // And a symlink, because `allow_loader_exes` is a path an operator writes and
        // `/usr/local/bin/warden` is very often one. `of_path` must FOLLOW it: the
        // authorisation is about the file that ran, and the kernel stamps the
        // resolved `mm->exe_file` inode, so a call site that used
        // `symlink_metadata` would name the link and never match anything.
        let via_link = dir.join("loader-c");
        let _ = std::fs::remove_file(&via_link);
        std::os::unix::fs::symlink(&original, &via_link).expect("symlink in one temp dir");

        let one = ExeIdentity::of_path(original.to_str().unwrap());
        let other = ExeIdentity::of_path(alias.to_str().unwrap());
        let through = ExeIdentity::of_path(via_link.to_str().unwrap());
        std::fs::remove_dir_all(&dir).ok();
        let _ = std::fs::remove_file(&via_link);

        assert_eq!(one, other, "one file must name itself the same way twice");
        assert_eq!(one, through, "a symlink to it is the same file");
        assert!(one.is_some(), "a file that exists must name itself at all");
    }

    #[test]
    fn a_path_that_does_not_resolve_names_no_file() {
        // The unresolvable entry must produce `None` from `of_path`, not a zeroed
        // identity: `Some(0,0)` would compare equal to no-claim records and to nothing
        // else, which is the opposite of what an unreadable path means.
        assert_eq!(
            ExeIdentity::of_path("/nonexistent/warden-loader-under-test"),
            None
        );
    }

    #[test]
    fn of_path_hands_back_the_kernels_dev_encoding_at_its_own_call_site() {
        // `to_kernel_dev` is pinned arithmetically in `crate::guard`; what is NOT
        // pinned there is that `of_path` USES it. A call site that passed the raw
        // glibc `st_dev` would compare two encodings of the same filesystem — the
        // kernel's `s_dev` from the hook against a number that is that same device
        // spelled differently — and they would never match. Never matching is the
        // dangerous direction: every authorised loader reads as a stranger on a
        // host whose configuration is correct.
        let exe = std::env::current_exe().expect("this test binary");
        let path = exe.to_str().expect("utf-8 test path");
        let meta = std::fs::metadata(&exe).expect("stat this test binary");
        let raw = meta.st_dev();
        let id = ExeIdentity::of_path(path).expect("this test binary resolves");

        // Decode the glibc gnu_dev layout here, independently of the helper under
        // test, and re-encode the way the kernel stores `s_dev`.
        let major = ((raw >> 8) & 0xfff) | ((raw >> 32) & !0xfff);
        let minor = (raw & 0xff) | ((raw >> 12) & !0xff);
        let kernel_form = ((major & 0xfff) << 20) | (minor & 0xf_ffff);

        assert_ne!(
            raw, kernel_form,
            "the premise of this test is that this device's two encodings differ; \
             on a major-0/minor-<256 device they coincide and it proves nothing"
        );
        assert_eq!(
            id.dev, kernel_form,
            "of_path must return st_dev({raw:#x}) in the kernel's major<<20|minor form, \
             not the glibc packing"
        );
        assert_eq!(id.ino, meta.st_ino(), "and the inode of that same file");
    }

    #[test]
    fn signal_delivery_class_decodes_only_for_signal_records() {
        // W2K-04: `aux2` is a per-kind scratch slot and the collision is real — the
        // sigqueue class sits in the same bits an IPv4 CONNECT record uses for its
        // address family. A record may carry only the fields its own kind defines.
        let mut raw = zeroed_raw();
        raw.kind = Kind::Signal as u32;
        raw.aux = 11; // SIGSEGV
        raw.target_pid = 131264;

        // Every class the kernel can stamp, at both values of the parent flag.
        for class in 0..7u32 {
            raw.aux2 = class << WARDEN_SIGNAL_DELIVERY_SHIFT;
            let ev = decode_raw(&raw);
            assert_eq!(
                ev.signal_delivery,
                SignalDelivery::from_u32(class),
                "class {class} did not survive the wire"
            );
            assert!(!ev.signal_from_parent);

            raw.aux2 = WARDEN_SIGNAL_FROM_PARENT | (class << WARDEN_SIGNAL_DELIVERY_SHIFT);
            let ev = decode_raw(&raw);
            assert_eq!(ev.signal_delivery, SignalDelivery::from_u32(class));
            assert!(
                ev.signal_from_parent,
                "the parent flag and the class must coexist"
            );
        }

        // An unreadable si_code arrives as 0 == SI_USER: the attack class, never a
        // gentler default.
        raw.aux2 = 0;
        assert_eq!(
            decode_raw(&raw).signal_delivery,
            Some(SignalDelivery::User),
            "an all-zero aux2 must decode as kill(2)"
        );

        // A class number the kernel never stamps is not a record userspace can name,
        // so it is rejected rather than guessed at (append-only ABI discipline).
        raw.aux2 = 7 << WARDEN_SIGNAL_DELIVERY_SHIFT;
        assert!(
            RawEvent::decode(as_bytes(&raw)).is_none(),
            "an unknown delivery class must reject the record"
        );

        // The same bits on a CONNECT record are an address family, not a class.
        raw.kind = Kind::Connect as u32;
        raw.aux2 = 2; // AF_INET
        raw.aux = 443;
        let ev = decode_raw(&raw);
        assert!(
            ev.signal_delivery.is_none(),
            "a connect record's address family must not read as a delivery class"
        );
        assert!(ev.dest.is_some());
    }

    #[test]
    fn decodes_a_mount_with_its_source_device() {
        // A MOUNT record: the mount source in filename (a plain string, not the
        // SERVICE ladder), the MS_* flags in aux. Here a bind mount of the host
        // root — the container-escape tell — with MS_BIND set.
        const MS_BIND: u32 = 4096;
        let mut filename = [0u8; MAX_FILENAME];
        let src = b"/";
        filename[..src.len()].copy_from_slice(src);
        let raw = RawEvent {
            kind: Kind::Mount as u32,
            actor_pid: 9000,
            actor_tid: 9000,
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: MS_BIND,
            aux2: 0,
            ts_ns: 0,
            cap_old: 0,
            cap_new: 0,
            daddr: [0u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename,
        };
        let ev = decode_raw(&raw);
        assert_eq!(ev.kind, Kind::Mount);
        assert_eq!(ev.filename, "/"); // plain string, NOT run through service_path
        assert_eq!(ev.aux & MS_BIND, MS_BIND);
        assert!(ev.dest.is_none() && ev.creds.is_none());
    }

    /// Build an ACCESS record the way the kernel's guard_inode() does: aux = hook,
    /// aux2 = intent nibble OR'd with the DENIED bit when armed, cap_old/cap_new =
    /// the guarded inode's dev/ino, target_pid = the inode's authorized uid.
    fn access_raw(hook: AccessHook, intent: u32, denied: bool, actor_uid: u32) -> RawEvent {
        RawEvent {
            kind: Kind::Access as u32,
            actor_pid: 31337,
            actor_tid: 31337,
            actor_ppid: 1,
            actor_uid,
            target_pid: 33, // the guarded inode's authorized uid (reused slot)
            aux: hook as u32,
            aux2: (intent & 0xF) | if denied { WARDEN_ACCESS_DENIED } else { 0 },
            ts_ns: 999,
            cap_old: 0xfd00, // guarded inode dev (s_dev)
            cap_new: 424242, // guarded inode ino
            daddr: [0u8; WARDEN_ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; MAX_FILENAME],
        }
    }

    #[test]
    fn decodes_an_armed_access_denial() {
        // uid 0 (root) tried to READ a guarded inode whose sole authorized uid is
        // 33; the guard was armed and returned -EPERM. The decoder must fold the
        // overloads into an AccessInfo that reports the hook, the read intent, the
        // denial, the inode identity, and who WAS authorised — the whole conviction
        // in one struct. ACCESS is the one kind that populates `access`.
        let raw = access_raw(AccessHook::Open, WARDEN_INTENT_READ, true, 0);
        let ev = decode_raw(&raw);
        assert_eq!(ev.kind, Kind::Access);
        assert_eq!(ev.actor_uid, 0);
        let a = ev.access.expect("access folded out");
        assert_eq!(a.hook, AccessHook::Open);
        assert_eq!(a.intent, WARDEN_INTENT_READ);
        assert!(a.denied); // armed → actually blocked
        assert_eq!(a.dev, 0xfd00);
        assert_eq!(a.ino, 424242);
        assert_eq!(a.authorized_uid, 33);
        assert_eq!(a.intent_str(), "read");
        // ACCESS never populates the other folded views.
        assert!(ev.dest.is_none() && ev.creds.is_none() && ev.bpf_prog_type.is_none());
    }

    #[test]
    fn decodes_a_shadow_would_deny_access() {
        // The same unauthorised access, but UNARMED: the DENIED bit is clear, so
        // `denied` is false — the access was observed and allowed through, and this
        // record is the "would-deny" an operator watches before arming. The intent
        // nibble can carry more than one bit (an open-for-read-and-write).
        let raw = access_raw(
            AccessHook::Open,
            WARDEN_INTENT_READ | WARDEN_INTENT_WRITE,
            false,
            0,
        );
        let a = decode_raw(&raw).access.expect("access folded out");
        assert!(!a.denied); // shadow — logged, not blocked
        assert_eq!(a.intent, WARDEN_INTENT_READ | WARDEN_INTENT_WRITE);
        assert_eq!(a.intent_str(), "read|write");
    }

    #[test]
    fn an_access_record_with_an_unknown_hook_is_rejected() {
        // aux carries the hook id; a value outside the enum makes the record
        // undecodable (decode returns None) rather than fabricating a hook — the
        // same append-only discipline the kind byte gets.
        let mut raw = access_raw(AccessHook::Open, WARDEN_INTENT_READ, true, 0);
        raw.aux = 99; // not a known warden_access_hook
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        };
        assert!(RawEvent::decode(bytes).is_none());
    }

    #[test]
    fn access_hook_and_intent_names_round_trip() {
        assert_eq!(AccessHook::from_u32(5), Some(AccessHook::Setattr));
        assert_eq!(
            AccessHook::from_u32(6),
            Some(AccessHook::Permission),
            "hook 6 is lsm/file_permission; if the ABI gained a hook, extend this \
             round-trip test with it"
        );
        assert_eq!(AccessHook::Permission.as_str(), "permission");
        assert_eq!(AccessHook::from_u32(0), None);
        assert_eq!(AccessHook::Rename.as_str(), "rename");
        assert_eq!(
            intent_names(WARDEN_INTENT_READ | WARDEN_INTENT_WRITE | WARDEN_INTENT_EXEC),
            "read|write|exec"
        );
        assert_eq!(intent_names(0), "");
    }

    // ── W2K-17: property tests over arbitrary input ─────────────────────────
    //
    // `RawEvent::decode` is the one place in Warden that casts a byte slice from
    // the ring buffer into a struct with `read_unaligned`, and `parse_starttime`
    // is the one place that splits attacker-influenced text (`comm` can be
    // anything via prctl) to find a field by position. Both are parsers of
    // hostile input; both were covered only by hand-written cases, which test the
    // shapes someone thought of. These loops assert the invariants that must hold
    // for *every* input: no panics, no NUL surviving into a String, no field
    // leaking across kinds, and no acceptance of a short buffer.
    //
    // Iteration numbers are in every assert message, because the generator is
    // deterministic (`src/arb.rs`) — a failure here is re-runnable, not a lottery
    // ticket.

    /// Fixed so the corpus never shifts under a passing CI. Bumping it is a
    /// deliberate act, like updating a lockfile.
    const ARB_SEED: u64 = 0x5EED_1234_0000_0000;
    const ARB_ITERS: u32 = 4096;

    /// A zeroed raw record. `RawEvent` is `repr(C)` POD, and zeroing matters
    /// here only so the padding before `ts_ns` holds defined bytes — `decode`
    /// never reads it, but a test that hands out uninitialised memory is a test
    /// that can fail for reasons unrelated to the parser.
    fn zeroed_raw() -> RawEvent {
        // SAFETY: all-0 is a valid bit pattern for this POD (every integer
        // field, and fixed byte arrays have no invalid values).
        unsafe { std::mem::zeroed() }
    }

    fn as_bytes(raw: &RawEvent) -> &[u8] {
        // SAFETY: `raw` is a live repr(C) POD; size_of is the record length the
        // kernel writes and the length `decode` requires.
        unsafe {
            std::slice::from_raw_parts(
                raw as *const RawEvent as *const u8,
                std::mem::size_of::<RawEvent>(),
            )
        }
    }

    #[test]
    fn decode_never_panics_and_never_breaks_its_own_promise_on_arbitrary_bytes() {
        let size = std::mem::size_of::<RawEvent>();
        for i in 0..ARB_ITERS {
            let mut a = crate::arb::Arb::new(ARB_SEED + i as u64);
            let len_extra = a.u32_below(64) as usize;
            let mut buf = a.bytes(size + len_extra);
            // Half the corpus is a truncated or over-long buffer, because the
            // length guard is the unsafe cast's only protection.
            if a.boolean() {
                let cut = a.u64_below(size as u64 + 8) as usize;
                buf.truncate(cut);
            }
            let decoded = RawEvent::decode(&buf);
            let Some(e) = decoded else { continue };
            // Everything below is an invariant of a SUCCESSFUL decode. If any
            // byte pattern can break one, the parser is trusting input it should
            // not — which is the class of bug a fixed corpus of three cases
            // cannot find.
            assert!(
                Kind::ALL.contains(&e.kind),
                "iteration {i}: decoded kind {:?} is not a shipped kind",
                e.kind
            );
            assert!(
                !e.comm.contains('\0'),
                "iteration {i}: NUL survived into comm {:#?}",
                e.comm
            );
            assert!(
                e.comm.chars().count() <= TASK_COMM_LEN,
                "iteration {i}: comm longer than the {TASK_COMM_LEN}-byte wire field"
            );
            assert!(
                !e.filename.contains('\0'),
                "iteration {i}: NUL survived into filename"
            );
            assert!(
                e.filename.len() <= MAX_FILENAME,
                "iteration {i}: filename out of the {MAX_FILENAME}-byte wire bound"
            );
            // The per-kind folds must not leak across kinds: a `Some` here means
            // the record's own kind justified it.
            assert!(
                e.dest.is_none()
                    || e.kind == Kind::Connect
                    || e.kind == Kind::Listen
                    || e.kind == Kind::ConnectResult
                    || e.kind == Kind::Flow,
                "iteration {i}: {:?} produced a decoded endpoint",
                e.kind
            );
            assert!(
                e.connect_outcome.is_none() || e.kind == Kind::ConnectResult,
                "iteration {i}: {:?} produced a connect outcome",
                e.kind
            );
            assert!(
                e.flow.is_none() || e.kind == Kind::Flow,
                "iteration {i}: {:?} produced a flow — its slots are another kind's pid \
                 and capability mask until FLOW claims them",
                e.kind
            );
            // A FLOW is not a verdict. Its aux2 has the same layout as a dial's, bits
            // 24..31 included, and the kernel leaves those zero — but the guarantee
            // userspace makes is stronger than what the kernel happens to write: even
            // arbitrary bytes there must not become a dial outcome on an inbound record.
            assert!(
                !(e.kind == Kind::Flow && e.connect_outcome.is_some()),
                "iteration {i}: a flow borrowed a connect verdict"
            );
            assert!(
                e.creds.is_none() || e.kind == Kind::Creds,
                "iteration {i}: {:?} produced a credential transition",
                e.kind
            );
            assert!(
                e.access.is_none() || e.kind == Kind::Access,
                "iteration {i}: {:?} produced an access record",
                e.kind
            );
            assert!(
                e.bpf_prog_type.is_none() || e.kind == Kind::BpfLoad,
                "iteration {i}: {:?} produced a program type",
                e.kind
            );
            assert!(
                !e.signal_from_parent || e.kind == Kind::Signal,
                "iteration {i}: {:?} claimed a parent-sent signal",
                e.kind
            );
            assert!(
                e.signal_delivery.is_none() || e.kind == Kind::Signal,
                "iteration {i}: {:?} claimed a delivery class",
                e.kind
            );
        }
    }

    #[test]
    fn every_short_buffer_is_rejected_before_the_struct_read() {
        // Exhaustive, not random: the guard is a single `len <` comparison and a
        // one-byte error in it means reading past the ring slice for 344 records
        // out of every flood.
        let size = std::mem::size_of::<RawEvent>();
        let mut a = crate::arb::Arb::new(ARB_SEED);
        for len in 0..size {
            let buf = a.bytes(len);
            assert!(
                RawEvent::decode(&buf).is_none(),
                "a {len}-byte buffer must be refused (record size is {size})"
            );
        }
    }

    #[test]
    fn a_decodable_record_keeps_every_scalar_and_folds_exactly_as_documented() {
        let valid_kinds: [u32; 14] = Kind::ALL
            .iter()
            .map(|k| *k as u32)
            .collect::<Vec<_>>()
            .try_into()
            .expect("Kind::ALL has fourteen entries");
        for i in 0..ARB_ITERS {
            let mut a = crate::arb::Arb::new(ARB_SEED + 7 * i as u64);
            let mut raw = zeroed_raw();
            let kind = valid_kinds[a.u32_below(valid_kinds.len() as u32) as usize];
            raw.kind = kind;
            raw.actor_pid = a.u32_below(u32::MAX - 1);
            raw.actor_tid = a.u32_below(u32::MAX - 1);
            raw.actor_ppid = a.u32_below(u32::MAX - 1);
            raw.actor_uid = a.u32_below(65_534);
            raw.target_pid = a.u32_below(u32::MAX - 1);
            raw.aux = if kind == Kind::Access as u32 {
                // An unknown hook id makes the whole record undecodable, so the
                // accept-path corpus has to name a real one.
                1 + a.u32_below(6)
            } else {
                a.u32_below(u32::MAX - 1)
            };
            raw.aux2 = a.u32_below(u32::MAX - 1);
            if kind == Kind::Signal as u32 {
                // A SIGNAL's delivery class must name a real si_code class or the
                // record is rejected, so pin those four bits and leave the rest of
                // aux2 — including FROM_PARENT — random.
                raw.aux2 = (raw.aux2 & !WARDEN_SIGNAL_DELIVERY_MASK)
                    | (a.u32_below(7) << WARDEN_SIGNAL_DELIVERY_SHIFT);
            }
            if kind == Kind::ConnectResult as u32 {
                // And a verdict record needs a real outcome code in bits 24..31 — the
                // kernel never stamps 0 there, and 0 or 11+ rejects the record. Pin the
                // outcome, leave the family and transport bytes random.
                raw.aux2 = (raw.aux2 & !WARDEN_NET_RESULT_MASK)
                    | ((1 + a.u32_below(10)) << WARDEN_NET_RESULT_SHIFT);
            }
            raw.ts_ns = a.u64_below(u64::MAX);
            raw.cap_old = a.u64_below(u64::MAX);
            raw.cap_new = a.u64_below(u64::MAX);
            a.fill(&mut raw.daddr);
            a.fill(&mut raw.comm);
            a.fill(&mut raw.filename);
            // The wire always NUL-terminates a name; a field full of random bytes
            // with no NUL at all is the *other* edge, so both appear here.
            if a.boolean() {
                let n = a.u64_below(TASK_COMM_LEN as u64) as usize;
                raw.comm[n] = 0;
            }

            let e = RawEvent::decode(as_bytes(&raw)).unwrap_or_else(|| {
                panic!(
                    "iteration {i}: kind {kind} with hook {} must decode",
                    raw.aux
                )
            });
            assert_eq!(e.actor_pid, raw.actor_pid, "iteration {i}");
            assert_eq!(e.actor_ppid, raw.actor_ppid, "iteration {i}");
            assert_eq!(e.actor_uid, raw.actor_uid, "iteration {i}");
            assert_eq!(e.target_pid, raw.target_pid, "iteration {i}");
            assert_eq!(e.aux, raw.aux, "iteration {i}");
            assert_eq!(e.ts_ns, raw.ts_ns, "iteration {i}");
            if kind == Kind::Creds as u32 {
                let c = e.creds.expect("iteration {i}");
                assert_eq!((c.new_uid, c.old_uid), (raw.aux, raw.aux2), "iteration {i}");
                assert_eq!(
                    (c.cap_old, c.cap_new),
                    (raw.cap_old, raw.cap_new),
                    "iteration {i}"
                );
            }
            if kind == Kind::Access as u32 {
                let acc = e.access.expect("iteration {i}");
                assert_eq!(acc.intent, raw.aux2 & 0xF, "iteration {i}");
                assert_eq!(
                    acc.denied,
                    raw.aux2 & WARDEN_ACCESS_DENIED != 0,
                    "iteration {i}"
                );
                assert_eq!(acc.dev, raw.cap_old, "iteration {i}");
                assert_eq!(acc.ino, raw.cap_new, "iteration {i}");
                assert_eq!(acc.authorized_uid, raw.target_pid, "iteration {i}");
            }
            if kind == Kind::BpfLoad as u32 {
                assert_eq!(e.bpf_prog_type, Some(raw.aux2), "iteration {i}");
                assert_eq!(
                    e.actor_exe_file,
                    (raw.cap_new != 0).then_some(ExeIdentity {
                        dev: raw.cap_old,
                        ino: raw.cap_new,
                    }),
                    "iteration {i}: a bpfload record folds its two free slots"
                );
            } else {
                // The stronger half of the rule, over random `cap_*` values: no other
                // kind may read those slots as an executable. CREDS fills them with
                // capability masks, ACCESS with a guarded file's dev/ino, FLOW with a
                // netns inode — and an actor-inode claim made from any of those would
                // be a statement about a file nobody named.
                assert_eq!(
                    e.actor_exe_file, None,
                    "iteration {i}: kind {kind} has no kernel-stamped executable"
                );
            }
            if kind == Kind::Flow as u32 {
                let f = e.flow.expect("iteration {i}: a flow folds its two slots");
                assert_eq!(f.local_port, raw.target_pid as u16, "iteration {i}");
                assert_eq!(f.netns_ino, raw.cap_old, "iteration {i}");
                assert_eq!(e.connect_outcome, None, "iteration {i}");
            }
            if kind == Kind::Signal as u32 {
                assert_eq!(
                    e.signal_from_parent,
                    raw.aux2 & WARDEN_SIGNAL_FROM_PARENT != 0,
                    "iteration {i}"
                );
                assert_eq!(
                    e.signal_delivery,
                    SignalDelivery::from_u32(
                        (raw.aux2 & WARDEN_SIGNAL_DELIVERY_MASK) >> WARDEN_SIGNAL_DELIVERY_SHIFT
                    ),
                    "iteration {i}"
                );
            }
            // `dest` is derived from aux2/aux/daddr; only require that an
            // AF_INET/AF_INET6 stamp yields an endpoint, and that it is not a
            // panic-shaped string.
            if (kind == Kind::Connect as u32
                || kind == Kind::Listen as u32
                || kind == Kind::Flow as u32)
                && (raw.aux2 == AF_INET || raw.aux2 == AF_INET6)
            {
                let d = e.dest.expect("iteration {i}: a known family must decode");
                assert!(d.contains(':'), "iteration {i}: endpoint {d:?} has no port");
            }
        }
    }

    #[test]
    fn wire_strings_never_keep_a_nul_and_survive_invalid_utf8() {
        for i in 0..ARB_ITERS {
            let mut a = crate::arb::Arb::new(ARB_SEED + 11 * i as u64);
            let mut name = [0u8; MAX_FILENAME];
            a.fill(&mut name);
            let plain = cstr(&name);
            let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
            assert!(!plain.contains('\0'), "iteration {i}");
            // Lossy decoding marks invalid bytes; it cannot invent a character, so
            // the character count stays inside the field's byte count. (The BYTE
            // count of the String does not — U+FFFD is three bytes for one
            // offending input byte — which is why this asserts chars, not len.)
            assert!(
                plain.chars().count() <= end,
                "iteration {i}: {} chars out of a {end}-byte field",
                plain.chars().count()
            );
            match std::str::from_utf8(&name[..end]) {
                Ok(s) => assert_eq!(
                    plain.as_str(),
                    s,
                    "iteration {i}: a valid UTF-8 field must round-trip byte for byte"
                ),
                Err(_) => assert!(
                    plain.contains('\u{FFFD}'),
                    "iteration {i}: invalid bytes were dropped instead of marked: {plain:?}"
                ),
            }

            let path = service_path(&name);
            assert!(!path.contains('\0'), "iteration {i}");
            if !path.is_empty() {
                assert!(path.starts_with('/'), "iteration {i}: {path:?}");
            }
        }
    }

    #[test]
    fn a_service_ladder_of_real_dentry_names_rebuilds_root_first() {
        // The random-bytes loop above cannot assert path *shape*: dentry names
        // never contain '/', so a corpus full of them would "find" a violation
        // that the kernel cannot produce. This loop builds the ladder the way
        // `sb_mount`/`service` records really fill it — leaf-first cells, some
        // empty, some the root dentry — and asserts the exact reconstruction.
        for i in 0..ARB_ITERS {
            let mut a = crate::arb::Arb::new(ARB_SEED + 17 * i as u64);
            let mut name = [0u8; MAX_FILENAME];
            let mut cells: Vec<String> = Vec::with_capacity(WARDEN_SVC_DEPTH);
            for r in 0..WARDEN_SVC_DEPTH {
                let cell = match a.u32_below(3) {
                    0 => String::new(),
                    1 => "/".to_string(),
                    _ => {
                        const ALPHABET: &[u8] = b"abcXY.-_019service";
                        let len = 1 + a.u32_below(12) as usize;
                        (0..len)
                            .map(|_| ALPHABET[a.u64_below(ALPHABET.len() as u64) as usize] as char)
                            .collect()
                    }
                };
                let off = r * WARDEN_SVC_SLOT;
                name[off..off + cell.len()].copy_from_slice(cell.as_bytes());
                cells.push(cell);
            }
            let kept: Vec<&str> = cells
                .iter()
                .filter(|c| !c.is_empty() && c.as_str() != "/")
                .map(String::as_str)
                .rev()
                .collect();
            let want = if kept.is_empty() {
                String::new()
            } else {
                format!("/{}", kept.join("/"))
            };
            let got = service_path(&name);
            assert_eq!(got, want, "iteration {i}: ladder {cells:?}");
            if !got.is_empty() {
                assert!(!got.contains("//"), "iteration {i}: {got:?}");
                assert!(!got.ends_with('/'), "iteration {i}: {got:?}");
                assert!(
                    got[1..].split('/').count() <= WARDEN_SVC_DEPTH,
                    "iteration {i}: {got:?} deeper than the {WARDEN_SVC_DEPTH}-cell ladder"
                );
            }
        }
    }

    #[test]
    fn starttime_is_field_22_for_every_comm_shape_and_refuses_a_short_line() {
        // The responder's immunity and W2K-10's recycling check both rest on this
        // one number. `comm` is attacker-controlled text inside parentheses — the
        // parser anchors on the LAST ')', because the kernel escapes a `)` inside
        // comm as `\)`, so this corpus puts parens, spaces and digits in it.
        for i in 0..ARB_ITERS {
            let mut a = crate::arb::Arb::new(ARB_SEED + 13 * i as u64);
            let starttime = a.u64_below(u32::MAX as u64) + 1;
            let comm = a.text(40);
            let tail_fields = a.u32_below(40);
            // Field 1 is the pid, 2 the parenthesised comm, 3 the state; 4..=21
            // are the eighteen fixed fields before starttime.
            let mut prefix = format!("{} ({}) S", a.u32_below(u32::MAX - 1), comm);
            for f in 4..=21 {
                prefix.push_str(&format!(" {f}"));
            }
            let mut line = format!("{prefix} {starttime}");
            for f in 23..23 + tail_fields {
                line.push_str(&format!(" {f}"));
            }
            assert_eq!(
                parse_starttime(&line),
                Some(starttime),
                "iteration {i}: comm {comm:?} with {tail_fields} trailing fields shifted the parse"
            );
            // The same line without field 22 must not answer: guessing a
            // neighbour's value here would hand the responder an identity that is
            // not the process it is about to signal.
            assert_eq!(
                parse_starttime(&prefix),
                None,
                "iteration {i}: a 21-field line was read as a starttime"
            );
        }
    }

    // ── the four identity answers (W2K-37) ──────────────────────────────────

    #[test]
    fn only_enoent_means_the_process_is_gone() {
        let ok = |ticks: u64| {
            // A synthetic /proc/<pid>/stat: pid, comm, state, then fields 4..=21
            // and starttime at 22.
            let mut line = String::from("4242 (warden) S 1 4242");
            // Fields 6..=21: sixteen fillers, so the next token lands on index 19
            // of the post-comm split, which is field 22.
            for _ in 6..22 {
                line.push_str(" 0");
            }
            line.push_str(&format!(" {ticks} 0 0"));
            line
        };
        assert_eq!(
            identity_from_read(Ok(ok(987654))),
            ProcIdentity::Known(987654)
        );
        assert_eq!(
            identity_from_read(Err(std::io::Error::from_raw_os_error(libc::ENOENT))),
            ProcIdentity::Gone
        );
        assert_eq!(
            identity_from_read(Err(std::io::Error::from_raw_os_error(libc::EACCES))),
            ProcIdentity::Hidden(libc::EACCES)
        );
        assert_eq!(
            identity_from_read(Err(std::io::Error::from_raw_os_error(libc::EPERM))),
            ProcIdentity::Hidden(libc::EPERM)
        );
    }

    #[test]
    fn a_readable_stat_that_does_not_parse_is_not_liveness_evidence() {
        // A truncated read (a process mid-exit, or a racing procfs) must not be
        // read as "gone" — that is the same collapse W2K-37 records, just
        // approached from the parse side instead of the errno side.
        assert_eq!(
            identity_from_read(Ok("4242 (warden) S 1 4242".to_string())),
            ProcIdentity::Malformed
        );
        assert_eq!(
            identity_from_read(Err(std::io::Error::other("no errno"))),
            ProcIdentity::Malformed
        );
    }

    #[test]
    fn this_process_and_no_process_at_all_are_the_two_live_answers() {
        let me = identity_of(std::process::id());
        let ProcIdentity::Known(ticks) = me else {
            panic!("a process must be able to read its own start time, got {me:?}");
        };
        assert_eq!(starttime_of(std::process::id()), Some(ticks));
        assert!(ticks > 0, "field 22 read as zero is not an identity");

        // A number no kernel can hand out: procfs answers ENOENT, which is the
        // one errno allowed to mean "exited".
        assert_eq!(identity_of(u32::MAX), ProcIdentity::Gone);
    }

    #[test]
    fn the_hidden_answer_names_what_the_operator_must_fix() {
        let s = ProcIdentity::Hidden(libc::EACCES).explain();
        assert!(s.contains("hidepid="), "{s}");
        assert!(s.contains("identity is unknown"), "{s}");
        assert!(!s.contains("exited"), "{s}");
    }

    #[test]
    fn every_standard_signal_is_named_and_a_realtime_number_is_rendered_not_dropped() {
        // The finding's severity now claims what the number DOES, and an operator
        // checking that claim against `man 7 signal` starts from its name. A record
        // that said "SIG?" for SIGSTKFLT or SIGPWR could not be audited at all — the
        // pre-W2K-41 binary printed exactly that for 4, 5, 34 and 64.
        for sig in 1..=31u32 {
            let name = signal_name(sig);
            assert!(name.len() > 3, "{sig} rendered as {name:?}");
            assert!(name.starts_with("SIG"), "{sig} rendered as {name:?}");
            assert!(!name.ends_with('?'), "{sig} lost its name: {name}");
            assert_ne!(
                name,
                format!("SIG{sig}"),
                "{sig} fell through to the unnumbered-name fallback"
            );
        }
        assert_eq!(signal_name(libc::SIGTERM as u32), "SIGTERM");
        assert_eq!(signal_name(libc::SIGHUP as u32), "SIGHUP");
        assert_eq!(signal_name(libc::SIGSTKFLT as u32), "SIGSTKFLT");
        assert_eq!(signal_name(libc::SIGPWR as u32), "SIGPWR");

        // Real-time and unknown numbers stay countable rather than vanishing.
        assert_eq!(signal_name(34), "SIG34");
        assert_eq!(signal_name(64), "SIG64");
        assert_eq!(signal_name(0), "SIG0");
    }
}
