//! net_snap.rs — the pull half of network visibility.
//!
//! The sensors see a *change*: `security_socket_connect` fires on a dial,
//! `security_socket_listen` on a bind, and the verdict pair on a completed
//! connect. Nothing in that set can tell you what was already true when Warden
//! attached. A listener that predates the daemon, a connection opened while the
//! ring was full, a socket whose sensor was muted — each is invisible for the
//! whole life of the process, and the journal cannot distinguish "nothing is
//! listening" from "nothing listened *while I was watching*".
//!
//! `/proc/net/{tcp,tcp6,udp,udp6}` is the other half of the answer. It holds
//! state, not transitions, so it needs no privileges the unit does not already
//! grant (§39 of the report calls the gap N-03; the roadmap's stage 15 is this
//! file). Reading it costs no capability, attaches no program, and cannot
//! enforce anything, which is exactly why it is safe to ship while the egress
//! *policy* questions (N-07, N-08, N-10) are still open.
//!
//! Three things this module deliberately is not:
//!
//!  - **Not a finding source.** Every result is a journal line. A new label
//!    would travel the bridge, and the bridge's batch contract is the open
//!    F-38.1/N-06/N-07 question; inventing a second consumer for it here would
//!    make an unapproved decision by accident.
//!  - **Not a substitute for the sensors.** It samples; a socket that opens and
//!    closes between two ticks is absent from every snapshot. Push still owns
//!    "what happened", pull owns "what is true, and what did push never get to
//!    see".
//!  - **Not host-wide.** `/proc/net/*` is per-network-namespace and Warden reads
//!    its own. Every socket inside a container's netns is out of scope, and the
//!    report says so rather than reporting an empty table as a quiet host — the
//!    same structural blind spot that made the host's MIB counters undercount
//!    the dial rate (§42.5 of the report).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::time::Instant;

use crate::config::NetworkSnapshot;
use crate::events::{dest_of, family_tag, Event, Kind};

/// The four inet tables the kernel publishes. `unix` is deliberately absent:
/// it carries no address and no `daddr`-shaped identity, so joining it to a
/// sensor record would mean inventing a correspondence the ABI does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Table {
    Tcp4,
    Tcp6,
    Udp4,
    Udp6,
}

impl Table {
    pub const ALL: [Table; 4] = [Table::Tcp4, Table::Tcp6, Table::Udp4, Table::Udp6];

    pub fn path(self) -> &'static str {
        match self {
            Table::Tcp4 => "/proc/net/tcp",
            Table::Tcp6 => "/proc/net/tcp6",
            Table::Udp4 => "/proc/net/udp",
            Table::Udp6 => "/proc/net/udp6",
        }
    }

    /// The address width the kernel prints for this table, in hex characters.
    /// A row whose address has the other width is rejected, not reinterpreted:
    /// reading 16 bytes as four words or vice versa produces an address that
    /// looks plausible and is wrong, which is the N-01 mistake all over again.
    fn addr_hex_len(self) -> usize {
        match self {
            Table::Tcp4 | Table::Udp4 => 8,
            Table::Tcp6 | Table::Udp6 => 32,
        }
    }

    /// The transport as the rest of Warden names it, and the same word the
    /// platform's `protocol` field wants (N-01 closed that gap on the push side).
    pub fn transport(self) -> &'static str {
        match self {
            Table::Tcp4 | Table::Tcp6 => "tcp",
            Table::Udp4 | Table::Udp6 => "udp",
        }
    }
}

/// What a socket is doing, derived from its table and state byte. `Other` keeps
/// a state we do not classify visible instead of quietly dropping it — a
/// SYN-RECV storm is exactly the kind of thing that would vanish if the
/// classification were the filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// TCP in LISTEN — an inbound surface.
    Listener,
    /// A socket with a peer: TCP ESTABLISHED, or UDP that has `connect`ed.
    Connected,
    /// A bound UDP socket with no peer.
    Bound,
    /// Anything else, with the raw state kept alongside.
    Other(u8),
}

impl Role {
    /// `remote` decides for UDP because that table has no LISTEN state; the
    /// state byte alone would call every unconnected bound socket "other".
    pub fn classify(table: Table, state: u8, remote: &str) -> Self {
        if table.transport() == "tcp" {
            return match state {
                0x0A => Role::Listener,
                0x01 => Role::Connected,
                other => Role::Other(other),
            };
        }
        let unconnected = remote.starts_with("0.0.0.0:") || remote.starts_with("[::]:");
        if unconnected {
            Role::Bound
        } else {
            Role::Connected
        }
    }
}

/// The kernel's TCP state numbers, as `/proc/net/tcp` prints them in hex.
/// Unknown numbers render as `state/<hex>` rather than being mapped onto the
/// nearest known one.
fn state_name(table: Table, state: u8) -> String {
    if table.transport() == "udp" {
        return match state {
            0x01 => "connected".to_string(),
            0x07 => "bound".to_string(),
            other => format!("state/{other:02X}"),
        };
    }
    let name = match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => return format!("state/{state:02X}"),
    };
    name.to_string()
}

/// One socket as the table describes it. The address strings come from
/// [`dest_of`], the sensor's own formatter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    pub table: Table,
    pub local: String,
    pub remote: String,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
    pub role: Role,
}

impl Socket {
    /// Identity within one snapshot. The inode is the socket's own number, so a
    /// recycled 4-tuple is a different socket; and because an inode can in
    /// principle be handed to a new socket, the tuple travels in the key too —
    /// an inode reuse under a different tuple reads as close+open, which is
    /// true, instead of as "nothing changed".
    pub fn key(&self) -> (Table, String, String, u64) {
        (
            self.table,
            self.local.clone(),
            self.remote.clone(),
            self.inode,
        )
    }

    pub fn role(&self) -> String {
        match self.role {
            Role::Listener => "listener".to_string(),
            Role::Connected => "connected".to_string(),
            Role::Bound => "udp-bound".to_string(),
            Role::Other(_) => state_name(self.table, self.state),
        }
    }
}

/// Why a row was not turned into a socket. Counted, never silently dropped: a
/// kernel that changes this file's format must show up as a non-zero `rejected`
/// rather than as a host with no sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    TooFewFields,
    AddressWidth,
    BadHex,
    BadPort,
    BadState,
    BadUid,
    BadInode,
}

impl Reject {
    pub fn as_str(self) -> &'static str {
        match self {
            Reject::TooFewFields => "too few fields",
            Reject::AddressWidth => "address width does not match the table",
            Reject::BadHex => "address is not hex",
            Reject::BadPort => "port is not hex",
            Reject::BadState => "state is not hex",
            Reject::BadUid => "uid is not a number",
            Reject::BadInode => "inode is not a number",
        }
    }
}

/// What one table file produced.
#[derive(Debug, Clone)]
pub struct TableRead {
    pub table: Table,
    /// `None` when the file could not be opened at all.
    pub rows: Option<usize>,
    pub rejected: Vec<Reject>,
    /// A short errno string when the open failed.
    pub error: Option<String>,
}

impl TableRead {
    fn unreadable(table: Table, error: String) -> Self {
        Self {
            table,
            rows: None,
            rejected: Vec::new(),
            error: Some(error),
        }
    }

    fn read(table: Table, rows: usize, rejected: Vec<Reject>) -> Self {
        Self {
            table,
            rows: Some(rows),
            rejected,
            error: None,
        }
    }

    pub fn readable(&self) -> bool {
        self.rows.is_some()
    }

    /// `false` only for a file the kernel does not have (`tcp6` on a host with
    /// IPv6 disabled). A missing table is a coverage fact, not an error, and is
    /// reported as "this table is not present" rather than "0 sockets".
    pub fn missing(&self) -> bool {
        self.error
            .as_deref()
            .is_some_and(|e| e.contains("No such file") || e.contains("not exist"))
    }
}

/// Everything one pass over the four tables produced.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub sockets: Vec<Socket>,
    pub reads: Vec<TableRead>,
}

impl Snapshot {
    /// How much of the host this snapshot actually saw. A snapshot with an
    /// unreadable table is not evidence about the sockets that table would have
    /// named, and every consumer of this type has to say which case it is in.
    pub fn complete(&self) -> bool {
        self.reads.iter().all(|r| r.readable())
    }

    pub fn readable_tables(&self) -> usize {
        self.reads.iter().filter(|r| r.readable()).count()
    }

    pub fn rejected_rows(&self) -> usize {
        self.reads.iter().map(|r| r.rejected.len()).sum()
    }

    /// Read every table the kernel publishes. Never fails: a host where none of
    /// the four can be opened reports that through `reads`, because the useful
    /// answer is "I could not look", and that is not an error path in a sensor.
    pub fn take() -> Self {
        let mut out = Snapshot::default();
        for table in Table::ALL {
            match fs::read_to_string(table.path()) {
                Ok(text) => {
                    let (sockets, rejected) = parse_table(&text, table);
                    let n = sockets.len();
                    out.sockets.extend(sockets);
                    out.reads.push(TableRead::read(table, n, rejected));
                }
                Err(e) => out.reads.push(TableRead::unreadable(table, e.to_string())),
            }
        }
        out
    }

    /// Build a four-table snapshot from fixture text. Test-only. A table that no
    /// fixture names is recorded as read-and-empty, which is what lets a test of
    /// the *diff* stay about the diff; a test that wants an unreadable table
    /// builds the `Snapshot` directly, because `TableRead`'s fields are public.
    /// [`Snapshot::take`] always produces exactly four reads, and `complete`,
    /// `readable_tables` and the report's coverage wording are written against
    /// that shape.
    #[cfg(test)]
    pub fn parsed(fixtures: &[(Table, &str)]) -> Self {
        let mut out = Snapshot::default();
        for table in Table::ALL {
            let text = fixtures
                .iter()
                .find(|(t, _)| *t == table)
                .map(|(_, text)| *text)
                .unwrap_or("");
            let (sockets, rejected) = parse_table(text, table);
            let n = sockets.len();
            out.sockets.extend(sockets);
            out.reads.push(TableRead::read(table, n, rejected));
        }
        out
    }
}

/// Parse one `/proc/net/*` table body. The header line is skipped by shape, not
/// by line number, so a kernel that ever prints a different preamble does not
/// shift every subsequent row into the parser.
pub fn parse_table(text: &str, table: Table) -> (Vec<Socket>, Vec<Reject>) {
    let mut sockets = Vec::new();
    let mut rejected = Vec::new();
    // The kernel's byte order is what the hex words encode; on a big-endian
    // host the reversal below would produce a wrong-but-plausible address.
    // Refusing is better than guessing, and nothing Warden targets is big-endian.
    if !cfg!(target_endian = "little") {
        return (sockets, rejected);
    }
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() {
            continue;
        }
        // Header: `  sl  local_address rem_address   st tx_queue ...`
        if line.starts_with("sl ") || line.starts_with("sl\t") {
            continue;
        }
        match parse_row(line, table) {
            Ok(socket) => sockets.push(socket),
            Err(reason) => rejected.push(reason),
        }
    }
    (sockets, rejected)
}

fn parse_hex(text: &str, table: Table) -> Result<IpAddr, Reject> {
    if text.len() != table.addr_hex_len() {
        return Err(Reject::AddressWidth);
    }
    if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Reject::BadHex);
    }
    match table {
        Table::Tcp4 | Table::Udp4 => {
            let word = u32::from_str_radix(text, 16).map_err(|_| Reject::BadHex)?;
            // The kernel prints the address as a host-order word: 127.0.0.1 comes
            // out as `0100007F`, so the octets are the little-endian bytes of the
            // parsed number. Reading the hex left to right gives 1.0.0.127.
            Ok(IpAddr::from(word.to_le_bytes()))
        }
        Table::Tcp6 | Table::Udp6 => {
            let mut octets = [0u8; 16];
            for (i, chunk) in text.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(
                    std::str::from_utf8(chunk).map_err(|_| Reject::BadHex)?,
                    16,
                )
                .map_err(|_| Reject::BadHex)?;
                octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
            }
            Ok(IpAddr::from(octets))
        }
    }
}

fn parse_endpoint(field: &str, table: Table) -> Result<String, Reject> {
    // "0100007F:1F90" — the address never contains ':' in this format, so the
    // split is unambiguous even for the 32-hex-character IPv6 form.
    let (addr, port) = field.rsplit_once(':').ok_or(Reject::AddressWidth)?;
    let ip = parse_hex(addr, table)?;
    if port.len() != 4 {
        return Err(Reject::BadPort);
    }
    let port = u16::from_str_radix(port, 16).map_err(|_| Reject::BadPort)?;
    let octets = match ip {
        IpAddr::V4(v4) => {
            let mut o = [0u8; 16];
            o[..4].copy_from_slice(&v4.octets());
            o
        }
        IpAddr::V6(v6) => v6.octets(),
    };
    // `dest_of` returns None for a family it does not decode; the widths above
    // only produce the two inet families, and a None here would be a formatter
    // regression, so it surfaces as a rejected row rather than a panic.
    dest_of(family_tag(&ip), &octets, port).ok_or(Reject::AddressWidth)
}

fn parse_row(line: &str, table: Table) -> Result<Socket, Reject> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // sl local rem st tx:rx tr:when retrnsmt uid timeout inode …
    if fields.len() < 10 {
        return Err(Reject::TooFewFields);
    }
    let local = parse_endpoint(fields[1], table)?;
    let remote = parse_endpoint(fields[2], table)?;
    if fields[3].len() != 2 {
        return Err(Reject::BadState);
    }
    let state = u8::from_str_radix(fields[3], 16).map_err(|_| Reject::BadState)?;
    let uid = fields[7].parse::<u32>().map_err(|_| Reject::BadUid)?;
    let inode = fields[9].parse::<u64>().map_err(|_| Reject::BadInode)?;
    let role = Role::classify(table, state, &remote);
    Ok(Socket {
        table,
        local,
        remote,
        state,
        uid,
        inode,
        role,
    })
}

/// The process behind one socket inode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    /// `None` when `/proc/<pid>/comm` would not read — the socket is still
    /// attributed to a pid, and the report must not dress that up as a name.
    pub comm: Option<String>,
    pub exe: Option<String>,
    pub cgroup: Option<String>,
}

impl Owner {
    fn read(pid: u32) -> Self {
        Self {
            pid,
            comm: read_trimmed(&format!("/proc/{pid}/comm")),
            exe: crate::events::exe_of(pid),
            cgroup: crate::events::cgroup_of(pid),
        }
    }

    /// One-line rendering used in every journal line this module writes.
    pub fn describe(&self) -> String {
        let mut out = format!("pid {}", self.pid);
        out.push_str(&format!(
            " ({})",
            self.comm
                .clone()
                .unwrap_or_else(|| "comm unreadable".to_string())
        ));
        if let Some(exe) = &self.exe {
            out.push_str(&format!(" exe={exe}"));
        }
        if let Some(cg) = &self.cgroup {
            out.push_str(&format!(" cgroup={cg}"));
        }
        out
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim_end().to_string())
        .filter(|s| !s.is_empty())
}

/// How far the inode→pid walk got. `budget_hit` and `denied_pids` are the two
/// ways a socket can end up with no owner *without* that meaning "no owner
/// exists", and collapsing them is the failure this type exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Walk {
    pub owners: BTreeMap<u64, Owner>,
    /// pids whose `/proc/<pid>/fd` could not be read (`hidepid=`, a process that
    /// exited mid-walk, or a uid Warden may not peek at).
    pub denied_pids: u32,
    pub scanned_pids: u32,
    pub budget_hit: bool,
    /// `true` when `/proc` itself could not be listed. Then nothing is known and
    /// the report must say "attribution unavailable", not "0 attributed".
    pub proc_unreadable: bool,
}

impl Walk {
    /// Every wanted inode found, and nothing left on the table because of a
    /// bound — the only state in which "no owner" is a real answer.
    pub fn exhaustive(&self, wanted: usize) -> bool {
        !self.proc_unreadable && !self.budget_hit && self.denied_pids == 0 && self.found() == wanted
    }

    pub fn found(&self) -> usize {
        self.owners.len()
    }

    /// Walk `/proc/<pid>/fd` for the given socket inodes, stopping as soon as
    /// all are found. The walk is the expensive half of this module, so it is
    /// bounded by policy and it early-exits: on a host with 300 processes and
    /// two sockets to identify, most ticks never reach the end of `/proc`.
    pub fn attribute(wanted: &BTreeSet<u64>, max_pids: u32) -> Walk {
        let mut walk = Walk {
            owners: BTreeMap::new(),
            denied_pids: 0,
            scanned_pids: 0,
            budget_hit: false,
            proc_unreadable: false,
        };
        if wanted.is_empty() {
            return walk;
        }
        let mut pids: Vec<u32> = Vec::new();
        let entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => {
                walk.proc_unreadable = true;
                return walk;
            }
        };
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
        // /proc readdir order follows the pid namespace's idr, which is not
        // sorted. Sorting makes the walk reproducible: with a budget, an
        // unsorted walk attributes a different subset on each tick, and "which
        // sockets got identified" would be noise rather than a report.
        pids.sort_unstable();

        for pid in pids {
            if walk.scanned_pids >= max_pids {
                walk.budget_hit = true;
                break;
            }
            walk.scanned_pids += 1;
            let fd_dir = format!("/proc/{pid}/fd");
            let Ok(dir) = fs::read_dir(&fd_dir) else {
                walk.denied_pids += 1;
                continue;
            };
            for fd in dir.flatten() {
                let Ok(link) = fs::read_link(fd.path()) else {
                    continue;
                };
                let text = link.to_string_lossy();
                if let Some(inode) = socket_inode(&text) {
                    if wanted.contains(&inode) && !walk.owners.contains_key(&inode) {
                        walk.owners.insert(inode, Owner::read(pid));
                    }
                }
            }
            if walk.owners.len() == wanted.len() {
                break;
            }
        }
        walk
    }

    /// The coverage sentence for a walk, in the same words wherever it is used.
    pub fn summary(&self, wanted: usize) -> String {
        if self.proc_unreadable {
            return "attribution UNAVAILABLE (/proc could not be listed)".to_string();
        }
        if wanted == 0 {
            return "attribution: nothing to identify".to_string();
        }
        let mut out = format!("attribution: {} of {wanted} socket(s)", self.found());
        if self.budget_hit {
            out.push_str(&format!(
                ", walk stopped at its {}-pid budget",
                self.scanned_pids
            ));
        }
        if self.denied_pids > 0 {
            // Three causes, and the walk cannot tell them apart from one errno —
            // so name all three rather than picking the flattering one. On an
            // unprivileged host the first is overwhelmingly the real reason
            // (measured on the build host: 1 of 11 attributed, 170 pids denied),
            // and a line that blamed only `hidepid=` would send an operator to
            // remount `/proc` while the actual fix was to run the walk as root.
            out.push_str(&format!(
                ", {} pid(s) had unreadable fds (this process is not root, hidepid=, \
                 or they exited mid-walk)",
                self.denied_pids
            ));
        }
        if self.exhaustive(wanted) {
            out.push_str(" — exhaustive");
        }
        out
    }
}

/// `socket:[12345]` → `Some(12345)`. Anything else (a pipe, a file, an anonymous
/// inode) is not one of ours.
fn socket_inode(link: &str) -> Option<u64> {
    let inner = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

/// `net:[4026531993]` → `Some(4026531993)`. This is the text the kernel writes for
/// a namespace link, and the number in it is the same `ns.inum` a FLOW record
/// carries — so parsing it is what makes the two comparable.
fn netns_inode(link: &str) -> Option<u64> {
    let inner = link.strip_prefix("net:[")?.strip_suffix(']')?;
    inner.parse::<u64>().ok()
}

/// The inode number of the network namespace THIS process lives in, or None when
/// the link could not be read or did not parse. The same `ns.inum` the kernel
/// stamps into a FLOW record, so the two are directly comparable: the number is
/// how a reader tells a host accept from one inside a container's namespace —
/// which is the asymmetry this module exists to declare, since `/proc/net/*`
/// gives it only its own namespace while a kprobe sees every one.
///
/// `None` is reported as such rather than assumed to mean "host": an unreadable
/// `/proc/self/ns/net` would otherwise let every foreign-namespace flow be
/// labelled as belonging here.
pub(crate) fn self_netns_ino() -> Option<u64> {
    let link = std::fs::read_link("/proc/self/ns/net")
        .ok()
        .map(|p| p.to_string_lossy().into_owned())?;
    netns_inode(&link)
}

/// What the sensors told this process, kept so the pull path can name what the
/// push path never reported. Endpoints are stored in the same rendered form the
/// snapshot uses, because they are produced by the same function — if the two
/// sides ever formatted an address differently, the cross-check would report a
/// coverage gap on every socket and the report would be noise forever.
#[derive(Debug, Clone, Default)]
pub struct Sightings {
    pub listens: BTreeSet<String>,
    pub dests: BTreeSet<String>,
}

impl Sightings {
    pub fn describe(&self) -> String {
        format!(
            "sensors this run: {} LISTEN address(es), {} CONNECT destination(s)",
            self.listens.len(),
            self.dests.len()
        )
    }
}

/// The comparison of one snapshot against the previous one plus the sensors'
/// account of the same period.
#[derive(Debug, Clone)]
pub struct Report {
    /// `true` on the first snapshot of the process: there is no previous state,
    /// so nothing can be called "new", and everything present is by definition
    /// older than Warden.
    pub first: bool,
    pub added: Vec<Socket>,
    pub removed: Vec<Socket>,
    /// Listeners this process never saw a LISTEN record for.
    pub unseen_listeners: Vec<Socket>,
    /// Added connected sockets whose peer destination is not in the sensors'
    /// account at all.
    pub unseen_dials: Vec<Socket>,
    pub snapshot: Snapshot,
    pub walk: Walk,
    /// How many inodes the walk was asked to identify. Kept beside the walk
    /// because `Walk::exhaustive` is only meaningful against that number, and a
    /// report that compared `found` to something else would call a complete walk
    /// incomplete.
    pub walk_wanted: usize,
    /// The sensors' own account at the moment of this snapshot, so a reader can
    /// tell "no LISTEN record for this listener" from "no LISTEN record has ever
    /// been seen, because nothing was emitted at all".
    pub sightings: Sightings,
    /// Milliseconds the tick spent, measured on this host. Reported, never
    /// asserted as a bound elsewhere — the blueprint asks for measured budgets,
    /// and this is the measurement.
    pub elapsed_ms: u128,
}

impl Report {
    fn totals(&self) -> (usize, usize, usize, usize) {
        let (mut l, mut c, mut b, mut o) = (0, 0, 0, 0);
        for s in &self.snapshot.sockets {
            match s.role {
                Role::Listener => l += 1,
                Role::Connected => c += 1,
                Role::Bound => b += 1,
                Role::Other(_) => o += 1,
            }
        }
        (l, c, b, o)
    }

    /// The states that the three named roles do not cover, by name and count.
    /// A host sitting in 400 TIME_WAITs and a host sitting in 400 SYN_RECVs are
    /// different facts, and a totals line that lumps both as "other 400" would
    /// hide exactly the half-open flood the pull path exists to notice.
    pub fn other_mix(&self) -> String {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for s in &self.snapshot.sockets {
            if let Role::Other(_) = s.role {
                *counts.entry(s.role()).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .map(|(name, n)| format!("{name}×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Why rows were not parsed, named. A `rejected` count without a reason is a
    /// warning an operator cannot act on, and a format change in the kernel is
    /// the one case where the reason is the whole message.
    pub fn reject_mix(&self) -> String {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for read in &self.snapshot.reads {
            for reason in &read.rejected {
                *counts.entry(reason.as_str()).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .map(|(name, n)| format!("{name}×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn owner_text(&self, socket: &Socket) -> String {
        self.walk
            .owners
            .get(&socket.inode)
            .map(|o| o.describe())
            .unwrap_or_else(|| "owner not attributed".to_string())
    }

    /// Journal lines. Built here rather than in `main.rs` so the wording — which
    /// is the part that has to stay honest about coverage — is under test.
    pub fn lines(&self, policy: &NetworkSnapshot) -> Vec<String> {
        let (listeners, connected, bound, other) = self.totals();
        let rejected = self.snapshot.rejected_rows();
        let mix = self.other_mix();
        let rejects = self.reject_mix();
        let mut out = Vec::new();

        if self.first {
            out.push(format!(
                "socket snapshot: baseline — {listeners} listener(s), {connected} connected, \
                 {bound} udp-bound{}{} across {} of 4 table(s). Every socket here predates this \
                 process, so none of them can have a sensor record.",
                if other > 0 {
                    format!(", {other} other ({mix})")
                } else {
                    String::new()
                },
                if rejected > 0 {
                    format!(", {rejected} row(s) NOT parsed ({rejects})")
                } else {
                    String::new()
                },
                self.snapshot.readable_tables()
            ));
            if !self.snapshot.complete() {
                out.push(format!(
                    "socket snapshot: coverage INCOMPLETE — {} (this is a partial view, not an \
                     empty host)",
                    self.unreadable_text()
                ));
            }
        } else {
            out.push(format!(
                "socket snapshot: +{} / -{} socket(s) — {listeners} listener(s), \
                 {connected} connected, {bound} udp-bound{}{}{}",
                self.added.len(),
                self.removed.len(),
                if other > 0 {
                    format!(", {other} other ({mix})")
                } else {
                    String::new()
                },
                if rejected > 0 {
                    format!(", {rejected} row(s) NOT parsed ({rejects})")
                } else {
                    String::new()
                },
                if self.snapshot.complete() {
                    String::new()
                } else {
                    format!("; coverage INCOMPLETE: {}", self.unreadable_text())
                }
            ));
        }

        // Only listeners are itemised: they are few, they are the inbound
        // surface, and a busy host's established-socket churn would turn a
        // coverage report into a firehose.
        //
        // Not on the baseline tick. There every socket is in `added` because
        // there was nothing before, and a line that reads "NEW listener" about a
        // daemon that has been up for a week is the opposite of the honest
        // coverage statement the first tick exists to make. `unseen_listeners`
        // below names the same sockets with the right framing.
        if !self.first {
            let new_listeners: Vec<&Socket> = self
                .added
                .iter()
                .filter(|s| s.role == Role::Listener)
                .take(policy.report_max_sockets)
                .collect();
            for s in new_listeners {
                out.push(format!(
                    "socket snapshot: NEW listener {}/{} on {} ({})",
                    s.table.transport(),
                    if s.table == Table::Tcp6 || s.table == Table::Udp6 {
                        "ipv6"
                    } else {
                        "ipv4"
                    },
                    s.local,
                    self.owner_text(s)
                ));
            }
            let closed_listeners: Vec<&Socket> = self
                .removed
                .iter()
                .filter(|s| s.role == Role::Listener)
                .take(policy.report_max_sockets)
                .collect();
            for s in closed_listeners {
                out.push(format!(
                    "socket snapshot: listener gone — {} ({})",
                    s.local,
                    self.owner_text(s)
                ));
            }

            let churn = self
                .added
                .iter()
                .chain(self.removed.iter())
                .filter(|s| s.role != Role::Listener)
                .count();
            if churn > 0 {
                out.push(format!(
                    "socket snapshot: {churn} non-listener socket(s) changed since the last \
                     tick (not itemised; a snapshot samples, so a socket that opened and closed \
                     between two ticks is in neither)"
                ));
            }
        }

        if !self.unseen_listeners.is_empty() {
            let shown: Vec<String> = self
                .unseen_listeners
                .iter()
                .take(policy.report_max_sockets)
                .map(|s| format!("{} ({})", s.local, self.owner_text(s)))
                .collect();
            out.push(format!(
                "socket snapshot: {} listener(s) have no LISTEN record from this run — {}{}. \
                 That is a coverage statement, not a detection: they opened before Warden \
                 started, or while the ring was full, or from a sensor whose channel is off.",
                self.unseen_listeners.len(),
                shown.join(", "),
                if self.unseen_listeners.len() > policy.report_max_sockets {
                    format!(
                        " (+{} more)",
                        self.unseen_listeners.len() - policy.report_max_sockets
                    )
                } else {
                    String::new()
                }
            ));
        }

        if !self.unseen_dials.is_empty() {
            // Framed differently on the baseline, and the difference is the
            // point: on the first tick *every* connected socket is unexplained,
            // because the process that opened it was already there, so calling
            // them "new" would invent a change the pull path never observed.
            let (lead, tail) = if self.first {
                (
                    format!(
                        "{} connected socket(s) already dial a destination no CONNECT record \
                         named",
                        self.unseen_dials.len()
                    ),
                    " — expected on a baseline: each of these opened before this process \
                     started, so no sensor could have reported it."
                        .to_string(),
                )
            } else {
                (
                    format!(
                        "{} new connected socket(s) dial a destination no CONNECT record named \
                         in this run",
                        self.unseen_dials.len()
                    ),
                    ". Pre-start connections and ring loss both look like this; neither is a \
                     finding on its own."
                        .to_string(),
                )
            };
            // Distinct destinations, not distinct sockets. One browser keeps a
            // pool of open sockets to a single CDN, and itemising them repeats
            // the same address four times, which uses up the whole bound and
            // hides the actual size of the unexplained surface. The socket
            // count stays in the lead — the set is a *where*, the count is a
            // *how many*, and collapsing either into the other loses one.
            let mut by_dest: BTreeMap<&str, usize> = BTreeMap::new();
            for s in &self.unseen_dials {
                *by_dest.entry(s.remote.as_str()).or_default() += 1;
            }
            let mut dests: Vec<(&str, usize)> = by_dest.into_iter().collect();
            dests.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
            let shown: Vec<String> = dests
                .iter()
                .take(4)
                .map(|(d, n)| {
                    if *n > 1 {
                        format!("{d}×{n}")
                    } else {
                        (*d).to_string()
                    }
                })
                .collect();
            let left_out = dests.len().saturating_sub(shown.len());
            out.push(format!(
                "socket snapshot: {}{} — {}{}{}",
                lead,
                if dests.len() == self.unseen_dials.len() {
                    String::new()
                } else {
                    format!(" ({} distinct destination(s))", dests.len())
                },
                shown.join(", "),
                if left_out > 0 {
                    format!(" (+{left_out} more destination(s))")
                } else {
                    String::new()
                },
                tail
            ));
        }

        if policy.attribute {
            out.push(format!(
                "socket snapshot: {}",
                self.walk.summary(self.walk_wanted)
            ));
        }
        // Said on every tick rather than once at start: the cross-check above is
        // only as meaningful as the sensor side's numbers, and those move.
        out.push(format!("socket snapshot: {}", self.sightings.describe()));
        out.push(format!(
            "socket snapshot: cost {} ms this tick",
            self.elapsed_ms
        ));
        out
    }

    fn unreadable_text(&self) -> String {
        let parts: Vec<String> = self
            .snapshot
            .reads
            .iter()
            .filter(|r| !r.readable())
            .map(|r| {
                let what = if r.missing() {
                    "not present in this kernel"
                } else {
                    "unreadable"
                };
                format!(
                    "{} {what} ({})",
                    r.table.path(),
                    r.error.clone().unwrap_or_default()
                )
            })
            .collect();
        if parts.is_empty() {
            "all four tables readable".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// The pull loop's state: the previous snapshot and the sensors' account.
#[derive(Debug, Clone)]
pub struct Reconciler {
    previous: Option<BTreeMap<(Table, String, String, u64), Socket>>,
    listens: BTreeSet<String>,
    dests: BTreeSet<String>,
    /// The policy the loop is currently running under, so a SIGHUP that changes
    /// cadence or posture can be reported instead of silently taking effect.
    applied: Applied,
    last: Option<Instant>,
    pub ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Applied {
    enabled: bool,
    interval_secs: u64,
    attribute: bool,
}

impl Reconciler {
    pub fn new(policy: &NetworkSnapshot) -> Self {
        Self {
            previous: None,
            listens: BTreeSet::new(),
            dests: BTreeSet::new(),
            applied: Applied {
                enabled: policy.enabled,
                interval_secs: policy.interval_secs,
                attribute: policy.attribute,
            },
            last: None,
            ticks: 0,
        }
    }

    /// Record what a sensor said about an endpoint, so the next tick can tell
    /// "the kernel has a listener here" from "the kernel has a listener here
    /// that I was never told about". Called from the drain loop for every
    /// decoded record, judged or not: the sensors emit a CONNECT/LISTEN whatever
    /// the app cgroup says, and a comparison against only the judged subset
    /// would call every non-app socket unexplained.
    ///
    /// The cost is one `BTreeSet` insert per network record, and the dial rate
    /// measured on the deployment host was ≈2/s (§42.5 of the report) — three
    /// orders of magnitude below what the ring itself absorbs.
    pub fn note(&mut self, event: &Event) {
        match event.kind {
            // LISTEN names the *local* endpoint, CONNECT and CONNECT_RESULT the
            // remote one; `dest` already carries the right side for each kind.
            Kind::Listen => {
                if let Some(local) = event.dest.as_deref() {
                    self.note_listen(local);
                }
            }
            Kind::Connect | Kind::ConnectResult => {
                if let Some(dest) = event.dest.as_deref() {
                    self.note_dial(dest);
                }
            }
            // FLOW deliberately notes NOTHING. Its `dest` is a *remote* endpoint, so it
            // looks like a dial to the eye and is nothing of the kind: it is the peer
            // that arrived. `dests` is compared against the pull path's ESTABLISHED
            // rows to ask "which sockets did someone dial that no sensor reported?" —
            // feeding accepted peers into it would silence exactly the unexplained
            // inbound rows the question is meant to surface, i.e. turn a coverage
            // statement into a false all-clear. Reconciling accepted flows against
            // inbound rows needs its own set, and that is a later stage, not a
            // one-line reuse.
            Kind::Flow => {}
            _ => {}
        }
    }

    fn note_listen(&mut self, local: &str) {
        self.listens.insert(local.to_string());
    }

    fn note_dial(&mut self, dest: &str) {
        self.dests.insert(dest.to_string());
    }

    pub fn sightings(&self) -> Sightings {
        Sightings {
            listens: self.listens.clone(),
            dests: self.dests.clone(),
        }
    }

    /// What changed in policy since the loop last said so.
    pub fn sync_policy(&mut self, policy: &NetworkSnapshot) -> Option<String> {
        let next = Applied {
            enabled: policy.enabled,
            interval_secs: policy.interval_secs,
            attribute: policy.attribute,
        };
        if next == self.applied {
            return None;
        }
        let mut parts = Vec::new();
        if next.enabled != self.applied.enabled {
            parts.push(format!(
                "enabled {} → {}",
                self.applied.enabled, next.enabled
            ));
        }
        if next.interval_secs != self.applied.interval_secs {
            parts.push(format!(
                "interval {}s → {}s",
                self.applied.interval_secs, next.interval_secs
            ));
        }
        if next.attribute != self.applied.attribute {
            parts.push(format!(
                "attribute {} → {}",
                self.applied.attribute, next.attribute
            ));
        }
        self.applied = next;
        Some(parts.join(", "))
    }

    /// Is a snapshot due? The first call is always due: the baseline is the
    /// whole point of the pull path.
    pub fn due(&self, policy: &NetworkSnapshot, now: Instant) -> bool {
        policy.enabled
            && match self.last {
                None => true,
                Some(at) => {
                    now.duration_since(at) >= std::time::Duration::from_secs(policy.interval_secs)
                }
            }
    }

    /// Take a snapshot, diff it against the previous one, attribute what policy
    /// allows, and hand back a report. Also advances the timer, so a caller that
    /// asks `due` and ignores the result cannot get stuck in a tight loop.
    pub fn tick(&mut self, policy: &NetworkSnapshot, now: Instant) -> (Report, Vec<String>) {
        self.tick_with(Snapshot::take(), policy, now)
    }

    /// The diff half of [`Reconciler::tick`], split out so the reconciliation,
    /// the sensor cross-check and every word the report writes can be tested
    /// against a fixture table instead of against whatever is connected while
    /// the tests run.
    fn tick_with(
        &mut self,
        snapshot: Snapshot,
        policy: &NetworkSnapshot,
        now: Instant,
    ) -> (Report, Vec<String>) {
        let started = Instant::now();
        let first = self.previous.is_none();

        let mut current: BTreeMap<_, Socket> = BTreeMap::new();
        for s in &snapshot.sockets {
            current.insert(s.key(), s.clone());
        }
        let added: Vec<Socket> = match &self.previous {
            None => snapshot.sockets.clone(),
            Some(prev) => current
                .values()
                .filter(|s| !prev.contains_key(&s.key()))
                .cloned()
                .collect(),
        };
        let removed: Vec<Socket> = self
            .previous
            .as_ref()
            .map(|prev| {
                prev.values()
                    .filter(|s| !current.contains_key(&s.key()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        let listeners: Vec<Socket> = current
            .values()
            .filter(|s| s.role == Role::Listener)
            .cloned()
            .collect();
        // A listener is "unseen" when no LISTEN record named its bound address in
        // this run. On the baseline tick that is everything, and the report says
        // so as a coverage statement rather than an alarm.
        let unseen_listeners: Vec<Socket> = listeners
            .iter()
            .filter(|s| !self.listens.contains(&s.local))
            .cloned()
            .collect();
        let unseen_dials: Vec<Socket> = added
            .iter()
            .filter(|s| s.role == Role::Connected && s.table.transport() == "tcp")
            .filter(|s| !self.dests.contains(&s.remote))
            .cloned()
            .collect();

        // Only the sockets the report will itemise need an owner — that is what
        // keeps the walk bounded by `report_max_sockets` and not by the size of
        // the host's socket table.
        let mut want: BTreeSet<u64> = BTreeSet::new();
        if policy.attribute {
            let new_listeners = added
                .iter()
                .filter(|s| s.role == Role::Listener)
                .take(policy.report_max_sockets);
            let gone_listeners = removed
                .iter()
                .filter(|s| s.role == Role::Listener)
                .take(policy.report_max_sockets);
            // Current listeners are walked as well: `unseen_listeners` names them
            // and an ownerless listener line is half a sentence.
            let still_listeners = listeners.iter().take(policy.report_max_sockets);
            for s in new_listeners.chain(gone_listeners).chain(still_listeners) {
                want.insert(s.inode);
            }
        }
        let walked = want.len();
        let walk = if policy.attribute {
            Walk::attribute(&want, policy.attribute_max_pids)
        } else {
            Walk::default()
        };

        let mut policy_notes = Vec::new();
        if !snapshot.complete() {
            // Stated once per tick, in the report's own lines, and here so a
            // reader of the summary sees the reason without counting tables.
            policy_notes.push(format!(
                "socket snapshot tables unreadable: {}",
                snapshot
                    .reads
                    .iter()
                    .filter(|r| !r.readable())
                    .map(|r| format!(
                        "{} ({})",
                        r.table.path(),
                        r.error.clone().unwrap_or_default()
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if snapshot.reads.iter().all(|r| !r.readable()) {
            policy_notes.push(
                "socket snapshot: NO /proc/net table could be read — the pull path reports \
                 nothing at all, which must not be read as a host with no sockets"
                    .to_string(),
            );
        }

        let report = Report {
            first,
            added,
            removed,
            unseen_listeners,
            unseen_dials,
            snapshot,
            walk,
            walk_wanted: walked,
            sightings: self.sightings(),
            elapsed_ms: started.elapsed().as_millis(),
        };
        self.previous = Some(current);
        self.last = Some(now);
        self.ticks += 1;
        (report, policy_notes)
    }
}

/// The `--check` line for the pull path. Policy-only, like the rest of the gate:
/// `--check` never touches the kernel and never reads `/proc/net`, so it reports
/// what the operator chose and what that choice hides.
pub fn coverage_line(policy: &NetworkSnapshot) -> String {
    if !policy.enabled {
        return format!(
            "warden: socket snapshot (pull path): OFF — a listener that predates Warden, and \
             any socket opened while the events ring was full, is invisible to every sensor; \
             set [network_snapshot].enabled = true to reconcile against /proc/net every {}s",
            policy.interval_secs
        );
    }
    format!(
        "warden: socket snapshot (pull path): ON, every {}s, attribution {} — it reads only \
         Warden's own network namespace, so sockets inside a container netns stay out of scope, \
         and it reports to the journal only (no finding, no bridge)",
        policy.interval_secs,
        if policy.attribute {
            format!(
                "enabled (≤{} socket(s), ≤{} pid(s) per tick)",
                policy.report_max_sockets, policy.attribute_max_pids
            )
        } else {
            "disabled".to_string()
        }
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// The header `/proc/net/tcp` prints, byte-for-byte as the kernel writes it.
    /// Every fixture below is built on this line, because the parser skips the
    /// header by shape and a fixture that omitted it would not test that.
    const HDR: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
         timeout inode\n";

    /// One table row in the kernel's own field order. `local` and `remote` are
    /// the hex words as printed, `st` the two-digit state.
    fn row(sl: usize, local: &str, remote: &str, st: &str, uid: u32, inode: u64) -> String {
        format!(
            "{sl:>4}: {local} {remote} {st} 00000000:00000000 00:00000000 00000000 {uid:>8} 0 \
             {inode} 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    /// A table body from `(local, remote, state, inode)` tuples, in the kernel's
    /// own column order. Deliberately not named after a transport: the same rows
    /// are what the udp tables print.
    fn body(rows: &[(&str, &str, &str, u64)]) -> String {
        let mut out = HDR.to_string();
        for (i, (local, remote, st, inode)) in rows.iter().enumerate() {
            out.push_str(&row(i, local, remote, st, 0, *inode));
        }
        out
    }

    fn policy() -> NetworkSnapshot {
        NetworkSnapshot {
            enabled: true,
            interval_secs: 300,
            attribute: false,
            report_max_sockets: 32,
            attribute_max_pids: 4096,
        }
    }

    /// A single-listener snapshot on 127.0.0.1:8080, the shape most tests need.
    fn one_listener(inode: u64) -> Snapshot {
        Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[("0100007F:1F90", "00000000:0000", "0A", inode)]),
        )])
    }

    // ── the parser: byte order ──────────────────────────────────────────────

    /// The kernel prints the v4 address as one host-order word, so `0100007F` is
    /// 127.0.0.1. Reading the hex left to right — the obvious mistake, and the
    /// one `netstat`-parsers make constantly — gives 1.0.0.127.
    #[test]
    fn ipv4_words_are_read_little_endian() {
        let (sockets, rejected) = parse_table(
            &body(&[("0100007F:1F90", "00000000:0000", "0A", 111)]),
            Table::Tcp4,
        );
        assert!(rejected.is_empty(), "unexpected rejects: {rejected:?}");
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local, "127.0.0.1:8080");
        assert_eq!(sockets[0].remote, "0.0.0.0:0");
        assert_eq!(sockets[0].role, Role::Listener);
        assert_eq!(sockets[0].state, 0x0A);
        assert_eq!(sockets[0].inode, 111);
    }

    /// IPv6 is four host-order words, not one 128-bit big-endian number: the
    /// v4-mapped loopback and the wildcard are what prove the word-by-word
    /// reversal, because a whole-number read produces an address that looks
    /// real and is not.
    #[test]
    fn ipv6_words_are_reversed_one_word_at_a_time() {
        let v6 = |addr: &str, port: &str, inode: u64| {
            row(
                0,
                &format!("{addr}:{port}"),
                "00000000000000000000000000000000:0000",
                "0A",
                33,
                inode,
            )
        };
        let body = format!(
            "{HDR}{}{}{}",
            v6("00000000000000000000000001000000", "0016", 222),
            v6("0000000000000000FFFF00000100007F", "1F90", 223),
            v6("00000000000000000000000000000000", "0035", 224),
        );
        let (sockets, rejected) = parse_table(&body, Table::Tcp6);
        assert!(rejected.is_empty(), "unexpected rejects: {rejected:?}");
        assert_eq!(sockets[0].local, "[::1]:22");
        assert_eq!(sockets[1].local, "[::ffff:127.0.0.1]:8080");
        assert_eq!(sockets[2].local, "[::]:53");
        // The bracketed form is what `dest_of` writes for v6, so the snapshot's
        // strings and the sensor's strings are the same strings.
        assert_eq!(sockets[1].remote, "[::]:0");
    }

    /// A port is four hex characters and nothing else; 1F90 is 8080.
    #[test]
    fn ports_are_hex_too() {
        let (sockets, _) = parse_table(
            &body(&[("00000000:0050", "0100007F:C001", "01", 5)]),
            Table::Tcp4,
        );
        assert_eq!(sockets[0].local, "0.0.0.0:80");
        assert_eq!(sockets[0].remote, "127.0.0.1:49153");
        assert_eq!(sockets[0].role, Role::Connected);
    }

    // ── the parser: rejection, by name ──────────────────────────────────────

    /// Every malformed row must be *counted and explained*. A kernel that
    /// changed this file's format has to show up as a non-zero `rejected` with a
    /// reason, never as a host with no sockets.
    #[test]
    fn each_malformed_field_is_rejected_with_its_own_reason() {
        let cases: Vec<(&str, Reject)> = vec![
            ("0: 0100007F:1F90 00000000:0000 0A", Reject::TooFewFields),
            (
                "0: 0100007F 00000000:0000 0A 0 0 0 0 0 1",
                Reject::AddressWidth,
            ),
            (
                "0: 0100007G:1F90 00000000:0000 0A 0 0 0 0 0 1",
                Reject::BadHex,
            ),
            (
                "0: 0100007F:1F9 00000000:0000 0A 0 0 0 0 0 1",
                Reject::BadPort,
            ),
            (
                "0: 0100007F:ZZZZ 00000000:0000 0A 0 0 0 0 0 1",
                Reject::BadPort,
            ),
            (
                "0: 0100007F:1F90 00000000:0000 0A1 0 0 0 0 0 1",
                Reject::BadState,
            ),
            (
                "0: 0100007F:1F90 00000000:0000 zz 0 0 0 0 0 1",
                Reject::BadState,
            ),
            (
                "0: 0100007F:1F90 00000000:0000 0A 0 0 0 x 0 1",
                Reject::BadUid,
            ),
            (
                "0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 -3",
                Reject::BadInode,
            ),
            // A v6-width address in the v4 table is a width error, not a
            // reinterpretation.
            (
                "0: 00000000000000000000000001000000:0016 00000000:0000 0A 0 0 0 0 0 1",
                Reject::AddressWidth,
            ),
        ];
        for (line, want) in cases {
            let (sockets, rejected) = parse_table(&format!("{HDR}{line}\n"), Table::Tcp4);
            assert!(sockets.is_empty(), "{line:?} parsed as a socket");
            assert_eq!(
                rejected,
                vec![want],
                "{line:?} rejected for the wrong reason"
            );
            assert!(!want.as_str().is_empty());
        }

        // And the same width rule guards the other direction: an 8-character
        // address in the v6 table.
        let (sockets, rejected) = parse_table(
            &format!(
                "{HDR}{}\n",
                row(0, "0100007F:1F90", "00000000:0000", "0A", 0, 1)
            ),
            Table::Tcp6,
        );
        assert!(sockets.is_empty());
        assert_eq!(rejected, vec![Reject::AddressWidth]);
    }

    /// Rows are skipped by shape, not by position: the header is the only line
    /// that starts with `sl`, and a blank line is not a parse error.
    #[test]
    fn the_header_and_blank_lines_are_not_rows() {
        let (sockets, rejected) = parse_table(&format!("{HDR}\n\n"), Table::Tcp4);
        assert!(sockets.is_empty());
        assert!(rejected.is_empty(), "the header must not count as a row");

        // Leading whitespace is how the kernel writes it, so trimming is not
        // optional.
        let (sockets, rejected) = parse_table(
            &body(&[("0100007F:1F90", "00000000:0000", "0A", 1)]),
            Table::Tcp4,
        );
        assert_eq!(sockets.len(), 1);
        assert!(rejected.is_empty());
    }

    /// An unclassified TCP state keeps its number. The alternative — folding
    /// TIME_WAIT into "other" and dropping the name — is how a SYN-RECV storm
    /// would arrive in the journal as nothing.
    #[test]
    fn an_unknown_state_stays_visible_with_its_number() {
        let (sockets, _) = parse_table(
            &body(&[
                ("0100007F:C000", "0200007F:0050", "06", 1),
                ("0100007F:C001", "0200007F:0050", "03", 2),
                ("0100007F:C002", "0200007F:0050", "FF", 3),
            ]),
            Table::Tcp4,
        );
        assert_eq!(sockets[0].role, Role::Other(0x06));
        assert_eq!(sockets[0].role(), "TIME_WAIT");
        assert_eq!(sockets[1].role(), "SYN_RECV");
        assert_eq!(sockets[2].role(), "state/FF");
        assert_eq!(sockets[2].state, 0xFF);
    }

    /// The UDP table has no LISTEN state, so a peerless bound socket has to be
    /// named by its remote field rather than its state byte.
    #[test]
    fn udp_is_classified_by_whether_it_has_a_peer() {
        let v4 = parse_table(
            &body(&[
                ("00000000:0035", "00000000:0000", "07", 1),
                ("0100007F:C000", "0200007F:0035", "01", 2),
            ]),
            Table::Udp4,
        );
        assert_eq!(v4.0[0].role, Role::Bound);
        assert_eq!(v4.0[1].role, Role::Connected);

        let v6 = parse_table(
            &format!(
                "{HDR}{}\n",
                row(
                    0,
                    "00000000000000000000000000000000:01BB",
                    "00000000000000000000000000000000:0000",
                    "07",
                    0,
                    9
                )
            ),
            Table::Udp6,
        );
        assert_eq!(v6.0[0].local, "[::]:443");
        assert_eq!(v6.0[0].role, Role::Bound);
    }

    #[test]
    fn only_socket_links_are_inodes() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("socket:[0]"), Some(0));
        assert_eq!(socket_inode("/dev/null"), None);
        assert_eq!(socket_inode("pipe:[9]"), None);
        assert_eq!(socket_inode("socket:[abc]"), None);
        assert_eq!(socket_inode("socket:[9]"), Some(9));
        assert_eq!(socket_inode("socket:9]"), None);
    }

    /// A FLOW record's `cap_old` is compared against THIS process's namespace inode,
    /// so the link text the kernel writes is part of the contract: a parse that
    /// quietly stopped matching would label every container accept as a host accept.
    #[test]
    fn the_agents_namespace_link_parses_the_way_the_kernel_writes_it() {
        assert_eq!(netns_inode("net:[4026531993]"), Some(4_026_531_993));
        assert_eq!(netns_inode("net:[1]"), Some(1));
        assert_eq!(netns_inode("mnt:[4026531840]"), None);
        assert_eq!(netns_inode("net:[abc]"), None);
        assert_eq!(netns_inode("net:[]"), None);
        // And the live half: where procfs is readable, the comparison the journal
        // prints must have a left-hand side. Absent procfs is tolerated and said as
        // "agent namespace unknown"; a present-but-unparsable link is a bug.
        if cfg!(target_os = "linux") && std::path::Path::new("/proc/self/ns/net").exists() {
            assert!(
                self_netns_ino().is_some(),
                "/proc/self/ns/net exists but did not parse, so every flow would be \
                 labelled 'agent namespace unknown'"
            );
        }
    }

    // ── the walk: bounds are reported, never hidden ─────────────────────────

    #[test]
    fn a_walk_with_nothing_to_find_does_not_open_proc() {
        let walk = Walk::attribute(&BTreeSet::new(), 4096);
        assert_eq!(walk, Walk::default());
        assert_eq!(walk.summary(0), "attribution: nothing to identify");
    }

    /// The three ways an attribution can come back short are three different
    /// facts, and the sentence has to carry the reason. "0 of 3" alone would let
    /// a `hidepid=` host read as an empty one.
    #[test]
    fn the_attribution_line_names_the_reason_for_every_shortfall() {
        let budget = Walk {
            owners: BTreeMap::new(),
            denied_pids: 0,
            scanned_pids: 4096,
            budget_hit: true,
            proc_unreadable: false,
        };
        assert!(budget.summary(3).contains("stopped at its 4096-pid budget"));
        assert!(!budget.summary(3).contains("exhaustive"));

        let denied = Walk {
            owners: BTreeMap::from([(
                7,
                Owner {
                    pid: 42,
                    comm: Some("nginx".into()),
                    exe: Some("/usr/sbin/nginx".into()),
                    cgroup: Some("/system.slice/nginx.service".into()),
                },
            )]),
            denied_pids: 12,
            scanned_pids: 300,
            budget_hit: false,
            proc_unreadable: false,
        };
        let text = denied.summary(2);
        assert!(text.contains("1 of 2 socket(s)"), "{text}");
        assert!(text.contains("12 pid(s) had unreadable fds"), "{text}");
        // The reason list must include the one that actually bites on an
        // unprivileged host. Blaming only `hidepid=` sends the operator to
        // remount `/proc`; the walk was refused because it is not root.
        assert!(text.contains("not root"), "{text}");
        assert!(text.contains("hidepid="), "{text}");
        assert!(text.contains("exited mid-walk"), "{text}");
        assert!(!text.contains("exhaustive"), "{text}");

        let blind = Walk {
            proc_unreadable: true,
            ..Walk::default()
        };
        assert_eq!(
            blind.summary(3),
            "attribution UNAVAILABLE (/proc could not be listed)"
        );

        let full = Walk {
            owners: (1..=2)
                .map(|i| {
                    (
                        i,
                        Owner {
                            pid: i as u32,
                            comm: None,
                            exe: None,
                            cgroup: None,
                        },
                    )
                })
                .collect(),
            ..Walk::default()
        };
        assert!(full.exhaustive(2));
        assert!(full.summary(2).ends_with("— exhaustive"));
        // An owner whose comm would not read is still a pid, and says so instead
        // of inventing a name.
        assert_eq!(full.owners[&1].describe(), "pid 1 (comm unreadable)");
    }

    // ── the reconciler: the diff and the cross-check ────────────────────────

    /// The first tick has no previous state, so nothing can be "new". Every
    /// listener on it is unexplained *by definition*, and the report has to say
    /// that as a coverage statement rather than as an alarm.
    #[test]
    fn the_baseline_tick_names_every_pre_existing_listener_once() {
        let mut rec = Reconciler::new(&policy());
        let (report, notes) = rec.tick_with(one_listener(111), &policy(), Instant::now());

        assert!(report.first);
        assert_eq!(report.added.len(), 1);
        assert!(report.removed.is_empty());
        assert_eq!(report.unseen_listeners.len(), 1);
        assert!(notes.is_empty(), "unexpected notes: {notes:?}");

        let lines = report.lines(&policy());
        assert!(
            lines[0].starts_with("socket snapshot: baseline"),
            "{lines:?}"
        );
        assert!(lines[0].contains("across 4 of 4 table(s)"), "{}", lines[0]);
        assert!(
            !lines.iter().any(|l| l.contains("NEW listener")),
            "a listener that predates Warden must not be reported as new: {lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("changed since the last tick")),
            "there is no last tick on a baseline: {lines:?}"
        );
        let unseen = lines
            .iter()
            .find(|l| l.contains("no LISTEN record from this run"))
            .expect("the baseline must state the coverage gap");
        assert!(unseen.contains("127.0.0.1:8080"), "{unseen}");
        assert!(
            unseen.contains("a coverage statement, not a detection"),
            "{unseen}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("sensors this run: 0 LISTEN address(es)")),
            "{lines:?}"
        );
    }

    /// A LISTEN record from the push path retires the coverage complaint. This
    /// is the whole cross-check, and it only works because both sides render the
    /// endpoint through `dest_of` — one formatter, or every socket would read as
    /// unexplained forever.
    #[test]
    fn a_listen_record_makes_the_snapshot_stop_calling_it_unseen() {
        let mut rec = Reconciler::new(&policy());
        let snap = one_listener(111);
        let (before, _) = rec.tick_with(snap.clone(), &policy(), Instant::now());
        assert_eq!(before.unseen_listeners.len(), 1);

        rec.note_listen("127.0.0.1:8080");
        let (after, _) = rec.tick_with(snap, &policy(), Instant::now());
        assert!(!after.first);
        assert!(
            after.unseen_listeners.is_empty(),
            "the sensor named this listener, so it is no longer unexplained"
        );
        assert!(after.added.is_empty(), "nothing changed: {after:?}");
    }

    #[test]
    fn an_added_and_a_removed_listener_are_both_said_with_their_endpoints() {
        let mut rec = Reconciler::new(&policy());
        let first = Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[("0100007F:1F90", "00000000:0000", "0A", 111)]),
        )]);
        rec.tick_with(first, &policy(), Instant::now());

        // 8080 closes, 443 opens, and one established socket churns.
        let second = Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[
                ("00000000:01BB", "00000000:0000", "0A", 222),
                ("0100007F:C000", "0200007F:0050", "01", 333),
            ]),
        )]);
        let (report, _) = rec.tick_with(second, &policy(), Instant::now());
        assert_eq!(report.added.len(), 2);
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed[0].local, "127.0.0.1:8080");

        let lines = report.lines(&policy());
        assert!(
            lines
                .iter()
                .any(|l| l.contains("NEW listener tcp/ipv4 on 0.0.0.0:443")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("listener gone — 127.0.0.1:8080")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("1 non-listener socket(s) changed since the last tick")),
            "{lines:?}"
        );
        assert!(
            lines[0].starts_with("socket snapshot: +2 / -1 socket(s)"),
            "{}",
            lines[0]
        );
    }

    /// A connected socket whose peer no CONNECT record named is the pull path
    /// finding a hole in the push path. Only *new* ones are counted, or a single
    /// long-lived connection would be reported on every tick forever.
    #[test]
    fn an_unexplained_new_connection_is_counted_once_not_every_tick() {
        let mut rec = Reconciler::new(&policy());
        let snap = Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[("0100007F:C000", "0200007F:0050", "01", 333)]),
        )]);
        let (first, _) = rec.tick_with(snap.clone(), &policy(), Instant::now());
        assert_eq!(first.unseen_dials.len(), 1, "baseline counts it");
        // …but the baseline says *why* it is unexplained, and "new" is not the
        // reason: nothing on a first tick is new.
        let first_line = first
            .lines(&policy())
            .into_iter()
            .find(|l| l.contains("no CONNECT record named"))
            .expect("the baseline must state the dial coverage gap");
        assert!(
            first_line.contains("already dial") && first_line.contains("expected on a baseline"),
            "{first_line}"
        );

        let (second, _) = rec.tick_with(snap.clone(), &policy(), Instant::now());
        assert!(
            second.unseen_dials.is_empty(),
            "the same socket on the next tick is not new evidence"
        );

        // Once the sensor has reported that destination, even a fresh socket to
        // it is explained. The address is what the fixture's hex words render to
        // (`0200007F` is 127.0.0.2, host-order again), which is the point: the
        // comparison only works because both sides use one formatter.
        let mut rec = Reconciler::new(&policy());
        rec.note_dial("127.0.0.2:80");
        let (dialing, _) = rec.tick_with(snap, &policy(), Instant::now());
        assert!(dialing.unseen_dials.is_empty(), "{dialing:?}");
    }

    /// The unexplained-dial line itemises *destinations*, not sockets. A host
    /// with one busy CDN connection pool otherwise spends its whole bound
    /// repeating a single address, and the operator reads four holes where
    /// there is one. The socket count still leads, because "how many sockets"
    /// and "how many places" are two different facts and collapsing either one
    /// would misstate the coverage.
    #[test]
    fn unexplained_dials_are_itemised_by_destination_not_per_socket() {
        // Three sockets to 127.0.0.2:80, two to 127.0.0.3:443.
        let snap = Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[
                ("0100007F:C000", "0200007F:0050", "01", 501),
                ("0100007F:C001", "0200007F:0050", "01", 502),
                ("0100007F:C002", "0200007F:0050", "01", 503),
                ("0100007F:C003", "0300007F:01BB", "01", 504),
                ("0100007F:C004", "0300007F:01BB", "01", 505),
            ]),
        )]);
        let mut rec = Reconciler::new(&policy());
        let (report, _) = rec.tick_with(snap, &policy(), Instant::now());
        let line = report
            .lines(&policy())
            .into_iter()
            .find(|l| l.contains("no CONNECT record named"))
            .expect("five unexplained sockets must be stated");
        assert_eq!(report.unseen_dials.len(), 5);
        assert!(line.contains("5 connected socket(s)"), "{line}");
        assert!(line.contains("2 distinct destination(s)"), "{line}");
        assert!(line.contains("127.0.0.2:80×3"), "{line}");
        assert!(line.contains("127.0.0.3:443×2"), "{line}");
        assert!(!line.contains("more destination"), "{line}");

        // Six distinct destinations, one socket each: no `×`, and the bound is
        // counted in destinations with its own wording.
        let locals: Vec<String> = (0..6u64)
            .map(|i| format!("0100007F:{:04X}", 0xC000 + i * 16))
            .collect();
        let remotes: Vec<String> = (0..6u64)
            .map(|i| format!("0400007F:{:04X}", 1000 + i))
            .collect();
        let rows: Vec<(&str, &str, &str, u64)> = (0..6)
            .map(|i| {
                (
                    locals[i].as_str(),
                    remotes[i].as_str(),
                    "01",
                    600 + i as u64,
                )
            })
            .collect();
        let many = Snapshot::parsed(&[(Table::Tcp4, &body(&rows))]);
        let mut rec = Reconciler::new(&policy());
        let (report, _) = rec.tick_with(many, &policy(), Instant::now());
        let line = report
            .lines(&policy())
            .into_iter()
            .find(|l| l.contains("no CONNECT record named"))
            .expect("six unexplained sockets must be stated");
        assert!(!line.contains("distinct destination"), "{line}");
        assert!(line.contains("(+2 more destination(s))"), "{line}");
        assert!(!line.contains("×"), "no destination repeats: {line}");
    }

    /// UDP has no CONNECT-of-record for a bound socket, and the pull path must
    /// not claim a hole in the sensor it never claimed to fill: only tcp
    /// connected sockets are cross-checked against the dial sightings.
    #[test]
    fn udp_sockets_are_never_reported_as_unexplained_dials() {
        let mut rec = Reconciler::new(&policy());
        let snap = Snapshot::parsed(&[(
            Table::Udp4,
            &body(&[
                ("00000000:0035", "00000000:0000", "07", 1),
                ("0100007F:C000", "0200007F:0035", "01", 2),
            ]),
        )]);
        let (report, _) = rec.tick_with(snap, &policy(), Instant::now());
        assert!(report.unseen_dials.is_empty(), "{report:?}");
        assert_eq!(report.added.len(), 2);
    }

    /// The bound is what keeps a host with two thousand listeners from writing
    /// two thousand journal lines. It has to say how many it left out.
    #[test]
    fn the_report_itemises_up_to_its_bound_and_says_what_it_left_out() {
        let locals: Vec<String> = (0..5u64).map(|i| format!("00000000:{i:04X}")).collect();
        let rows: Vec<(&str, &str, &str, u64)> = locals
            .iter()
            .enumerate()
            .map(|(i, local)| (local.as_str(), "00000000:0000", "0A", 1000 + i as u64))
            .collect();
        let snap = Snapshot::parsed(&[(Table::Tcp4, &body(&rows))]);

        let mut pol = policy();
        pol.report_max_sockets = 2;
        let mut rec = Reconciler::new(&pol);
        let (report, _) = rec.tick_with(snap, &pol, Instant::now());
        let lines = report.lines(&pol);
        let unseen = lines
            .iter()
            .find(|l| l.contains("5 listener(s) have no LISTEN record"))
            .expect("all five listeners are unexplained on a baseline");
        assert!(unseen.contains("(+3 more)"), "{unseen}");
        assert!(
            lines.iter().filter(|l| l.contains("NEW listener")).count() == 0,
            "a baseline names no listener as new: {lines:?}"
        );
    }

    /// A table the kernel would not open is a coverage fact. The wording must
    /// separate "this table is missing" (IPv6 off) from "this table is locked"
    /// and both from "there are no sockets here".
    #[test]
    fn an_unreadable_table_is_reported_as_a_partial_view_never_as_an_empty_host() {
        let snap = Snapshot {
            sockets: Vec::new(),
            reads: vec![
                TableRead::read(Table::Tcp4, 0, Vec::new()),
                TableRead::unreadable(Table::Tcp6, "No such file or directory".into()),
                TableRead::unreadable(Table::Udp4, "Permission denied".into()),
                TableRead::unreadable(Table::Udp6, "Permission denied".into()),
            ],
        };
        let mut rec = Reconciler::new(&policy());
        let (report, notes) = rec.tick_with(snap, &policy(), Instant::now());
        assert!(!report.snapshot.complete());
        assert_eq!(report.snapshot.readable_tables(), 1);

        let lines = report.lines(&policy());
        let coverage = lines
            .iter()
            .find(|l| l.contains("coverage INCOMPLETE"))
            .expect("an incomplete snapshot must say so");
        assert!(
            coverage.contains("/proc/net/tcp6 not present in this kernel"),
            "{coverage}"
        );
        assert!(coverage.contains("unreadable"), "{coverage}");
        assert!(
            notes
                .iter()
                .any(|n| n.contains("socket snapshot tables unreadable")),
            "{notes:?}"
        );

        // All four unreadable is the loud case: the pull path sees nothing, and
        // that is not the same as a host with no sockets.
        let blind = Snapshot {
            sockets: Vec::new(),
            reads: Table::ALL
                .iter()
                .map(|t| TableRead::unreadable(*t, "Permission denied".into()))
                .collect(),
        };
        let mut rec = Reconciler::new(&policy());
        let (_, notes) = rec.tick_with(blind, &policy(), Instant::now());
        assert!(
            notes
                .iter()
                .any(|n| n.contains("NO /proc/net table could be read")),
            "{notes:?}"
        );
    }

    /// A row the parser refused is counted in the totals line with its reason.
    #[test]
    fn a_rejected_row_is_counted_and_explained_in_the_totals() {
        let snap = Snapshot::parsed(&[(
            Table::Tcp4,
            &format!("{HDR}{}\n", "0: 0100007F:1F9 00000000:0000 0A 0 0 0 0 0 1"),
        )]);
        assert_eq!(snap.rejected_rows(), 1);
        let mut rec = Reconciler::new(&policy());
        let (report, _) = rec.tick_with(snap, &policy(), Instant::now());
        let lines = report.lines(&policy());
        let totals = &lines[0];
        assert!(totals.contains("1 row(s) NOT parsed"), "{totals}");
        assert!(totals.contains("port is not hex"), "{totals}");
    }

    /// W2K-17's corpus for the pull path's parser, which takes *text* from
    /// outside this process exactly as `events.rs` takes bytes. Three invariants
    /// a fixed fixture cannot establish over every shape the kernel might print:
    ///
    /// - **nothing is silently dropped.** Each body line is either a socket or a
    ///   counted rejection. A row that vanished into neither would shrink the
    ///   snapshot while the totals stayed plausible — the one failure mode a
    ///   coverage report must not have.
    /// - **an accepted row is the family its table claims.** An ipv4 table that
    ///   produced a bracketed endpoint, or an ipv6 table that produced a dotted
    ///   one, means the width check and the word-reversal disagree, and the
    ///   cross-check against the sensor records would then compare two different
    ///   renderings of one address forever.
    /// - **`role` is the classifier's answer for the row's own fields,** not
    ///   something the parser remembered from a previous line.
    #[test]
    fn arbitrary_table_text_is_neither_dropped_nor_misfamilied() {
        const ARB_SEED: u64 = 0x5EED_A11E_0000_0000;
        const ARB_ITERS: u32 = 2048;
        let mut accepted = 0usize;
        let mut refused = 0usize;
        for i in 0..ARB_ITERS {
            let mut a = crate::arb::Arb::new(ARB_SEED + i as u64);
            let table = Table::ALL[a.u32_below(Table::ALL.len() as u32) as usize];
            let text = a.procnetish(table.addr_hex_len());
            let (sockets, rejected) = parse_table(&text, table);
            accepted += sockets.len();
            refused += rejected.len();

            let data_lines = text
                .lines()
                .map(str::trim_start)
                .filter(|l| !l.is_empty() && !l.starts_with("sl ") && !l.starts_with("sl\t"))
                .count();
            assert_eq!(
                sockets.len() + rejected.len(),
                data_lines,
                "iteration {i}: table {} dropped a line out of {text:?}",
                table.path()
            );

            for s in &sockets {
                assert_eq!(s.table, table, "iteration {i}: row came from another table");
                assert_eq!(
                    s.role,
                    Role::classify(s.table, s.state, &s.remote),
                    "iteration {i}: role {s:?} is not what its own fields classify"
                );
                let addr = s
                    .local
                    .rsplit_once(':')
                    .map(|(addr, _)| addr)
                    .expect("an accepted endpoint always carries a :port");
                let parsed = addr
                    .strip_prefix('[')
                    .and_then(|a| a.strip_suffix(']'))
                    .unwrap_or(addr)
                    .parse::<IpAddr>()
                    .unwrap_or_else(|e| panic!("iteration {i}: {addr:?} is not an address: {e}"));
                match table {
                    Table::Tcp4 | Table::Udp4 => assert!(
                        parsed.is_ipv4(),
                        "iteration {i}: ipv4 table {table:?} produced {parsed:?}"
                    ),
                    Table::Tcp6 | Table::Udp6 => assert!(
                        parsed.is_ipv6(),
                        "iteration {i}: ipv6 table {table:?} produced {parsed:?}"
                    ),
                }
            }

            // Determinism: the same text parsed twice must agree with itself, or
            // a diff between two ticks would report churn the kernel never made.
            let again = parse_table(&text, table);
            assert_eq!(
                (sockets, rejected),
                again,
                "iteration {i}: the same text parsed differently twice"
            );
        }
        // Both outcomes must actually have occurred, or the invariants above are
        // vacuous: a corpus whose lines all fail the width check proves the
        // reject path counts and nothing about the family of an accepted row.
        // This seed range reaches 548 accepted and 4354 rejected rows; a corpus
        // change that zeroes either side trips here instead of passing quietly.
        assert!(
            accepted > 100 && refused > 100,
            "corpus reached only {accepted} accepted and {refused} rejected rows"
        );
    }

    /// States the three named roles do not cover are broken out by name, because
    /// 400 TIME_WAITs and 400 SYN_RECVs are different facts.
    #[test]
    fn unclassified_states_are_named_in_their_own_counts() {
        let snap = Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[
                ("0100007F:C000", "0200007F:0050", "06", 1),
                ("0100007F:C001", "0200007F:0050", "06", 2),
                ("0100007F:C002", "0200007F:0050", "03", 3),
            ]),
        )]);
        let mut rec = Reconciler::new(&policy());
        let (report, _) = rec.tick_with(snap, &policy(), Instant::now());
        assert_eq!(report.other_mix(), "SYN_RECV×1, TIME_WAIT×2");
        let lines = report.lines(&policy());
        assert!(
            lines[0].contains("3 other (SYN_RECV×1, TIME_WAIT×2)"),
            "{}",
            lines[0]
        );
    }

    /// The cadence is policy, so a tick that is not due must not read the kernel
    /// at all. The first call is always due: the baseline is the point.
    #[test]
    fn the_snapshot_is_due_once_per_interval_and_never_before() {
        let pol = policy();
        let mut rec = Reconciler::new(&pol);
        assert!(rec.due(&pol, Instant::now()));

        let now = Instant::now();
        rec.tick_with(one_listener(1), &pol, now);
        assert!(!rec.due(&pol, now), "a tick just taken is not due again");
        assert!(
            rec.due(&pol, now + Duration::from_secs(300)),
            "the interval has elapsed"
        );

        // Disabled policy: never due, whatever the clock says.
        let mut off = pol;
        off.enabled = false;
        let rec = Reconciler::new(&off);
        assert!(!rec.due(&off, Instant::now()));
    }

    /// SIGHUP reloads this section completely — the pull path holds no thread and
    /// no kernel object — and the change is *said*, not silently applied.
    #[test]
    fn a_reload_reports_only_what_actually_changed() {
        let pol = policy();
        let mut rec = Reconciler::new(&pol);
        assert!(
            rec.sync_policy(&pol).is_none(),
            "an unchanged policy is not news"
        );

        let mut moved = pol.clone();
        moved.enabled = false;
        assert_eq!(
            rec.sync_policy(&moved).as_deref(),
            Some("enabled true → false")
        );
        assert!(
            rec.sync_policy(&moved).is_none(),
            "the same reload twice must not repeat itself"
        );

        let mut both = moved.clone();
        both.enabled = true;
        both.interval_secs = 60;
        both.attribute = true;
        assert_eq!(
            rec.sync_policy(&both).as_deref(),
            Some("enabled false → true, interval 300s → 60s, attribute false → true")
        );
    }

    /// The routing from a decoded record to a sighting. LISTEN names the local
    /// endpoint, CONNECT and CONNECT_RESULT the remote one, FLOW deliberately
    /// names nothing, and no other kind contributes anything.
    ///
    /// The FLOW case is the load-bearing assertion here: its `dest` is formatted
    /// like a dial, so an unwary `is_net`-driven routing would drop accepted peers
    /// into `dests` and mute the very unexplained-inbound rows the reconciler asks
    /// about.
    #[test]
    fn only_network_records_become_sightings() {
        let mut rec = Reconciler::new(&policy());
        rec.note(&event(Kind::Listen, "0.0.0.0:443"));
        rec.note(&event(Kind::Connect, "203.0.113.7:443"));
        rec.note(&event(Kind::ConnectResult, "203.0.113.7:443"));
        rec.note(&event(Kind::Flow, "10.0.0.7:51220"));
        rec.note(&event(Kind::Exec, "/bin/sh"));
        rec.note(&event(Kind::Signal, "nothing"));
        let seen = rec.sightings();
        assert_eq!(seen.listens, BTreeSet::from(["0.0.0.0:443".to_string()]));
        assert_eq!(seen.dests, BTreeSet::from(["203.0.113.7:443".to_string()]));
        assert_eq!(
            seen.describe(),
            "sensors this run: 1 LISTEN address(es), 1 CONNECT destination(s)"
        );
    }

    /// The `--check` line states what an off pull path cannot see, and what an
    /// on one can: the netns bound and the journal-only posture are said here,
    /// not discovered later.
    #[test]
    fn the_check_line_states_the_coverage_of_the_choice() {
        let off = coverage_line(&NetworkSnapshot::default());
        assert!(off.contains("OFF"), "{off}");
        assert!(off.contains("a listener that predates Warden"), "{off}");
        assert!(off.contains("every 300s"), "{off}");

        let mut pol = policy();
        pol.attribute = true;
        let on = coverage_line(&pol);
        assert!(on.contains("ON, every 300s"), "{on}");
        assert!(on.contains("network namespace"), "{on}");
        assert!(on.contains("no finding, no bridge"), "{on}");
        assert!(on.contains("≤32 socket(s), ≤4096 pid(s)"), "{on}");

        let mut quiet = pol;
        quiet.attribute = false;
        assert!(coverage_line(&quiet).contains("attribution disabled"));
    }

    /// Every line this module writes is prefixed the same way, so `journalctl -u
    /// warden -g 'socket snapshot'` gets the whole pull path and nothing else.
    #[test]
    fn every_report_line_carries_the_module_prefix() {
        let mut rec = Reconciler::new(&policy());
        let snap = Snapshot::parsed(&[(
            Table::Tcp4,
            &body(&[
                ("0100007F:1F90", "00000000:0000", "0A", 1),
                ("0100007F:C000", "0200007F:0050", "06", 2),
            ]),
        )]);
        let (baseline, _) = rec.tick_with(snap.clone(), &policy(), Instant::now());
        let (delta, _) = rec.tick_with(snap, &policy(), Instant::now());
        for report in [baseline, delta] {
            for line in report.lines(&policy()) {
                assert!(
                    line.starts_with("socket snapshot: ") || line.starts_with("socket snapshot:"),
                    "unprefixed line: {line:?}"
                );
                assert!(!line.contains("None"), "a debug rendering leaked: {line}");
            }
            assert!(report
                .lines(&policy())
                .iter()
                .any(|l| l.contains("cost ") && l.contains(" ms this tick")));
        }
    }

    // ── against this host's real /proc/net ───────────────────────────────────

    /// The parser against the live kernel rather than a fixture. This is the
    /// difference between the pull path and the push sensors at this stage: no
    /// privileges, no eBPF, no VM — `/proc/net/tcp` is world-readable, so the
    /// byte-order rule that every assertion above pins can be checked here
    /// against the file the kernel actually wrote.
    #[test]
    fn the_live_host_table_parses_without_rejecting_its_own_rows() {
        let snap = Snapshot::take();
        if snap.reads.iter().all(|r| !r.readable()) {
            eprintln!("SKIPPED: this host will not open /proc/net/*");
            return;
        }
        assert!(
            snap.rejects_of(Reject::AddressWidth) == 0,
            "a width reject means the parser disagrees with this kernel's format: {:?}",
            snap.reads
        );
        assert!(
            snap.rejects_of(Reject::TooFewFields) == 0,
            "a field-count reject means the header skip is wrong: {:?}",
            snap.reads
        );
        assert!(
            snap.rejects_of(Reject::BadHex) == 0,
            "a hex reject means the parser mis-accepted a kernel-changed line: {:?}",
            snap.reads
        );
    }

    /// Open a listener, read the table, find it. The endpoint has to render
    /// exactly as `dest_of` renders it, because the sensor cross-check compares
    /// those strings.
    #[test]
    fn a_socket_this_process_is_listening_on_is_in_the_snapshot() {
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("SKIPPED: cannot bind a loopback listener here ({e})");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();
        let want = format!("{addr}");

        let snap = Snapshot::take();
        if snap.reads.iter().all(|r| !r.readable()) {
            eprintln!("SKIPPED: this host will not open /proc/net/*");
            return;
        }
        let found: Vec<&Socket> = snap
            .sockets
            .iter()
            .filter(|s| s.local == want && s.role == Role::Listener)
            .collect();
        assert!(
            !found.is_empty(),
            "our own listener {want} is not in the parsed table; snapshot has {} socket(s) \
             and the v4 table starts {:?}{}",
            snap.sockets.len(),
            std::fs::read_to_string("/proc/net/tcp")
                .unwrap_or_default()
                .lines()
                .take(2)
                .collect::<Vec<_>>(),
            snap.reads
                .iter()
                .map(|r| format!(" {}={:?}", r.table.path(), r.rows))
                .collect::<Vec<_>>()
                .join("")
        );

        // The inode the kernel printed is the one our own fd points at, and the
        // walk must be able to find it back. That is the whole attribution half
        // of this module, end to end, on the build host.
        let mut inode_of_fd = None;
        if let Ok(dir) = fs::read_dir("/proc/self/fd") {
            for entry in dir.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    if let Some(n) = socket_inode(&link.to_string_lossy()) {
                        if n == found[0].inode {
                            inode_of_fd = Some(n);
                        }
                    }
                }
            }
        }
        assert_eq!(
            inode_of_fd,
            Some(found[0].inode),
            "/proc/self/fd does not name the inode the table printed for our listener"
        );

        let mut want_set = BTreeSet::new();
        want_set.insert(found[0].inode);
        let walk = Walk::attribute(&want_set, u32::MAX);
        assert_eq!(
            walk.owners.keys().copied().collect::<Vec<_>>(),
            vec![found[0].inode],
            "the walk could not attribute our own socket: {}",
            walk.summary(1)
        );
        assert_eq!(walk.owners[&found[0].inode].pid, std::process::id());
        // `exhaustive` is deliberately not asserted: an unprivileged watcher
        // cannot read another user's `/proc/<pid>/fd`, so `denied_pids` is
        // non-zero on any real host and the walk is honestly *not* exhaustive.
        // What must hold is that the shortfall is said out loud.
        if walk.denied_pids > 0 {
            assert!(
                walk.summary(1).contains("unreadable fds"),
                "a denied walk must name its blind spot: {}",
                walk.summary(1)
            );
            assert!(!walk.exhaustive(1));
        }

        // …and the same walk with a one-pid budget is reported as bounded, not
        // as a socket with no owner. Whether pid 1 (which it scans first) holds
        // our inode is not knowable, so both outcomes are acceptable; what must
        // never happen is a silent shortfall.
        let bounded = Walk::attribute(&want_set, 1);
        assert!(bounded.scanned_pids <= 1, "{bounded:?}");
        if !bounded.owners.contains_key(&found[0].inode) {
            assert!(
                bounded.summary(1).contains("budget"),
                "{}",
                bounded.summary(1)
            );
        }
    }

    /// A snapshot of a host that is doing nothing still produces four reads and
    /// a tick that does not fail. Nothing here is allowed to be an error path:
    /// the pull path runs inside the loop that drains the ring.
    #[test]
    fn a_live_tick_always_produces_four_reads_and_a_cost() {
        let mut rec = Reconciler::new(&policy());
        let pol = policy();
        let now = Instant::now();
        let (report, _) = rec.tick_with(Snapshot::take(), &pol, now);
        assert_eq!(report.snapshot.reads.len(), 4);
        assert_eq!(rec.ticks, 1);
        assert!(!rec.due(&pol, now));
        assert!(report
            .lines(&pol)
            .iter()
            .all(|l| !l.contains("NaN") && !l.is_empty()));
    }

    // ── helpers used by the tests above ─────────────────────────────────────

    impl Snapshot {
        fn rejects_of(&self, reason: Reject) -> usize {
            self.reads
                .iter()
                .flat_map(|r| r.rejected.iter())
                .filter(|r| **r == reason)
                .count()
        }
    }

    fn event(kind: Kind, dest: &str) -> Event {
        Event {
            kind,
            actor_pid: std::process::id(),
            actor_ppid: 1,
            actor_uid: 0,
            target_pid: 0,
            aux: 0,
            ts_ns: 0,
            comm: String::new(),
            filename: String::new(),
            dest: Some(dest.to_string()),
            protocol: None,
            connect_outcome: None,
            flow: None,
            creds: None,
            bpf_prog_type: None,
            access: None,
            signal_from_parent: false,
            signal_delivery: None,
            actor_exe_file: None,
        }
    }
}
