//! health.rs — `warden --health`: what a RUNNING agent can be seen to be, read
//! from `/proc` and nothing else.
//!
//! The three commands that came before this one all answer questions that are
//! true whether or not an agent exists: `--check` reads the config file,
//! `--doctor` reads the kernel's symbol tables, `--explain` feeds a hypothetical
//! record to the detector. The question an operator asks after a quiet week is
//! none of those — it is "what does the process systemd believes is running
//! actually see right now?". That is this command.
//!
//! THE ANSWER IS WHATEVER `/proc` TELLS ABOUT A PROCESS WE DID NOT START. A
//! running agent keeps its state in three places, and only one of them is
//! readable without privilege:
//!
//! * its kernel-side maps (programs attached, ring-buffer drops, volume totals,
//!   the protected-pid set) — reading those means a `bpf()` syscall and `CAP_BPF`,
//!   so **this command does not read them and says so on its own lines**. That is
//!   the constraint, not an oversight: the live map-backed variant is forbidden
//!   here, and a `health` that needed a map would be a second daemon instead of a
//!   diagnostic. Every such claim is labelled `UNVERIFIED` and named in the
//!   `cannot see/` block, which is printed on every run.
//! * its own `/proc/<pid>` entries — a process this command found by name, whose
//!   `comm`, `cmdline`, `status`, `stat`, `cgroup`, `task/*/comm` are
//!   world-readable and whose `exe` and `fd` links are not (they need
//!   `PTRACE_MODE_READ`, i.e. the same `CAP_SYS_PTRACE` the unit grants the
//!   daemon). Unreadable ones are reported as `CANNOT TELL`, which is the only
//!   reason the vocabulary below has more than two words.
//! * the journal — which is journald's file, not ours. This command spawns
//!   nothing, so it never runs `journalctl`; what the agent *logged* is
//!   `UNVERIFIED` and is named as such instead of being silently folded into a
//!   green line.
//!
//! A FALSE "HEALTHY" IS THE BUG. Every line carries one evidence word from the set
//! `--doctor` already uses — the three presence words ARE `doctor::State::word()`
//! by delegation, so the two commands cannot drift apart on that axis — plus the
//! words the rest of the tree already prints for a claim that is only half-made:
//! `VERIFIED`, `PARTIAL`, `DEGRADED`, `UNAVAILABLE`, `UNSUPPORTED`, `UNVERIFIED`.
//! `UNVERIFIED` in this output means "this would need a live map, the journal, or
//! a privilege this command does not take"; it is never a pass. The `cannot see/`
//! lines at the end are the blueprint's rule that incomplete coverage must be
//! declared: a health line that printed counters it had not read would be the most
//! dangerous line in the tool.

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::config::Config;
use crate::doctor::State;
use crate::events::starttime_of;
use crate::loader::{obj_fingerprint, obj_len};

/// The kernel `comm` this build installs itself under, and the only name the
/// search matches on. Exact equality — see [`matches_agent_name`].
pub const AGENT_COMM: &str = "warden";
/// `TASK_COMM_LEN`: the kernel stores 15 bytes plus NUL, so a 16-character thread
/// name is NOT what `/proc/<pid>/task/<tid>/comm` can ever contain.
const TASK_COMM_LEN: usize = 16;
/// The name the bridge sender thread is spawned with (`src/deliver.rs`).
const DELIVER_THREAD: &str = "warden-deliver";
/// The name the heartbeat thread is spawned with (`src/heartbeat.rs`). SIXTEEN
/// characters — one more than the kernel keeps.
const HEARTBEAT_THREAD: &str = "warden-heartbeat";
/// The cgroup a systemd-managed agent lives under. Substring, because the prefix
/// depends on the slice; the unit name is specific enough to disambiguate.
const UNIT_CGROUP_NEEDLE: &str = "warden.service";
/// The modes that print and return: a same-named process running one of these is
/// a *command*, not the agent, and must never be mistaken for it. This is
/// `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §24 step 6's `pgrep` trap solved structurally
/// instead of by luck.
const PRINT_AND_RETURN: &[&str] = &[
    "--check",
    "--doctor",
    "--health",
    "--version",
    "--explain",
    "--socket-snapshot",
    "--help",
    "-h",
];

/// The one word every line of this report carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `/proc` said so and it is there. The word is `doctor::State`'s, shared.
    Present,
    /// The source was consulted and the thing genuinely is not there.
    Absent,
    /// The source could not be consulted. Same word as the doctor, same rule:
    /// this is never summed into `Absent`.
    CannotTell,
    /// Read directly, with no inference between the read and the claim.
    Verified,
    /// One half of the claim was read; the other half needs a source this command
    /// does not have.
    Partial,
    /// Read, and what it says is worse than the policy asks for.
    Degraded,
    /// The source exists but this uid cannot consult it here, and a different uid
    /// is the only way to change that.
    Unavailable,
    /// No source for this exists anywhere on the path this command takes.
    Unsupported,
    /// The claim would require a live BPF map, the journal's contents, or a
    /// privilege this command deliberately does not take.
    Unverified,
}

impl Verdict {
    pub fn word(self) -> &'static str {
        match self {
            // The presence axis is the doctor's, by delegation rather than by
            // copying strings: if `--doctor` ever renames `CANNOT TELL`, the two
            // commands move together or a test says so.
            Verdict::Present => State::Present.word(),
            Verdict::Absent => State::Absent.word(),
            Verdict::CannotTell => State::Unreadable.word(),
            Verdict::Verified => "VERIFIED",
            Verdict::Partial => "PARTIAL",
            Verdict::Degraded => "DEGRADED",
            Verdict::Unavailable => "UNAVAILABLE",
            Verdict::Unsupported => "UNSUPPORTED",
            Verdict::Unverified => "UNVERIFIED",
        }
    }

    pub fn of_state(state: State) -> Self {
        match state {
            State::Present => Verdict::Present,
            State::Absent => Verdict::Absent,
            State::Unreadable => Verdict::CannotTell,
        }
    }

    /// An errno classified the way `--doctor` classifies it: only `NotFound` is
    /// absence. EACCES/EPERM from a ptrace-gated `/proc` link is the third state,
    /// and this command runs into it on every root-owned agent.
    pub fn of_error(err: &io::Error) -> Self {
        Verdict::of_state(State::from_open_error(err))
    }
}

/// One `/proc` read's outcome, with the third state kept as its own variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading<T> {
    Seen(T),
    Absent,
    /// The message names the path and the errno, because `CANNOT TELL` without a
    /// reason is only a shorter silence.
    Blind(String),
}

impl<T> Reading<T> {
    fn get(&self) -> Option<&T> {
        match self {
            Reading::Seen(v) => Some(v),
            _ => None,
        }
    }
}

/// The single place an io error becomes a `Reading`, so every read in this module
/// shares `--doctor`'s rule instead of re-deriving it.
fn reading_from<T>(err: &io::Error, path: &str) -> Reading<T> {
    match Verdict::of_error(err) {
        Verdict::Absent => Reading::Absent,
        _ => Reading::Blind(format!("{path}: {err}")),
    }
}

/// `prctl(PR_SET_NAME)` / `execve` truncation: what the kernel stores, and
/// therefore the only string worth comparing a `/proc/<pid>/task/<tid>/comm` read
/// against.
///
/// `warden-heartbeat` is 16 characters and `TASK_COMM_LEN` is 16 *including* the
/// NUL, so on a live host the heartbeat thread's comm is `warden-heartbea`. A
/// missing-thread check that compared against the full name would report a healthy
/// heartbeat thread as a dead one — the false negative this whole module is built
/// against, arriving from the other direction.
pub fn comm_visible(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if out.len() + c.len_utf8() >= TASK_COMM_LEN {
            break;
        }
        out.push(c);
    }
    out
}

/// The candidate list's matching rule: exact kernel `comm`, or the exact basename
/// of `argv[0]`.
///
/// Not `cmdline.contains("warden")`, which is the §24 trap in a new costume: it
/// matches `/usr/local/bin/warden-doc-tmp`, matches a config path, and matches this
/// command's own argv. Both fields are compared after taking their basename, so a
/// renamed binary still counts and an unrelated one never does.
pub fn matches_agent_name(comm: Option<&str>, argv0: Option<&str>) -> bool {
    fn base(s: &str) -> &str {
        s.rsplit('/').next().unwrap_or(s)
    }
    comm.map(str::trim).is_some_and(|c| c == AGENT_COMM)
        || argv0.is_some_and(|a| base(a) == AGENT_COMM)
}

/// Whether this same-named process is a *command* rather than the agent: a
/// print-and-return mode anywhere in its argv. A daemon's argv carries `--config`
/// and at most `--debug`; `--health` beside `warden` means somebody else is asking
/// this same question.
pub fn is_a_command_not_the_agent(argv: &[String]) -> bool {
    argv.iter()
        .any(|a| PRINT_AND_RETURN.contains(&a.split('=').next().unwrap_or("")))
}

/// One `/proc` entry that could be the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub pid: u32,
    pub uid: Option<u32>,
    pub cgroup: Option<String>,
    pub comm: Option<String>,
}

/// The outcome of the search, before any claim about the process itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// /proc was listed and nothing named `warden` is in it.
    None,
    /// /proc could not be listed, so nothing is concluded.
    Blind,
    /// Exactly one candidate, or one chosen because it is the only one under the
    /// unit's cgroup — `others` counts the same-named processes NOT reported.
    One { agent: Candidate, others: usize },
    /// Several, with no way to tell which is the daemon from /proc alone.
    Several(Vec<Candidate>),
}

/// The pure half of the search, split out so "one candidate is enough" is a
/// decision a test can make happen. A second same-named process is NOT rounded up
/// to "the agent": the lines below would then describe the wrong process, which is
/// worse than saying nothing.
pub fn pick(candidates: Vec<Candidate>, proc_walkable: bool) -> Pick {
    if !proc_walkable {
        return Pick::Blind;
    }
    match candidates.len() {
        0 => Pick::None,
        1 => Pick::One {
            others: 0,
            agent: candidates.into_iter().next().expect("len 1"),
        },
        _ => {
            let under_unit: Vec<Candidate> = candidates
                .iter()
                .filter(|c| {
                    c.cgroup
                        .as_deref()
                        .is_some_and(|cg| cg.contains(UNIT_CGROUP_NEEDLE))
                })
                .cloned()
                .collect();
            let others = candidates.len() - 1;
            if under_unit.len() == 1 {
                return Pick::One {
                    others,
                    agent: under_unit.into_iter().next().expect("one under the unit"),
                };
            }
            Pick::Several(candidates)
        }
    }
}

/// `/proc/<pid>/exe`'s content, after the ` (deleted)` suffix is taken apart from
/// the path it decorates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeInfo {
    pub path: String,
    /// The running image's inode no longer has this name on disk: the binary was
    /// replaced or removed after start.
    pub deleted: bool,
    /// The inode behind this path is the inode this command is running from.
    pub same_file_as_self: bool,
}

/// The config file the agent points at, as it reads RIGHT NOW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseInfo {
    pub parses: bool,
    pub mode: String,
    pub unread_keys: usize,
    /// Whether `[bridge]` is in the file — which is what makes `warden-deliver` an
    /// expected thread of this agent.
    pub bridge: bool,
    pub heartbeat: bool,
    pub error: String,
}

/// One thread of the agent: tid, its kernel comm, its `stat` state character.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub tid: u32,
    pub comm: String,
    pub state: char,
}

impl Thread {
    fn blocked(&self) -> bool {
        matches!(self.state, 'D' | 'Z' | 'T')
    }
}

/// Everything read about one chosen agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    pub pid: u32,
    pub uid: Option<u32>,
    pub cgroup: Option<String>,
    pub comm: Option<String>,
    pub exe: Reading<ExeInfo>,
    pub cmdline: Reading<String>,
    /// The path in the agent's OWN argv, if it named one.
    pub config_path: Option<String>,
    pub sig_cgt: Reading<u64>,
    /// Seconds of uptime this process has been alive.
    pub age_secs: Reading<u64>,
    /// Its start in epoch seconds, when `/proc/stat`'s `btime` could be read too.
    pub start_epoch: Option<u64>,
    pub threads: Reading<Vec<Thread>>,
    /// Where the agent's stderr points — the only thing `/proc` says about its
    /// journal lines, and ptrace-gated for another uid's process.
    pub log_sink: Reading<String>,
    /// The file its argv names, re-read by THIS process.
    pub disk: Reading<ParseInfo>,
    pub mtime_epoch: Option<u64>,
}

/// The whole read, ready to render.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub self_pid: u32,
    pub proc_walkable: bool,
    /// Same-named processes skipped because they are commands: the count is what
    /// tells an operator that a second `warden --health` was running.
    pub commands_skipped: usize,
    pub pick: Pick,
    pub agent: Option<Agent>,
    /// `--config PATH` given to THIS command, which it deliberately does not use.
    pub operator_config: Option<String>,
    pub self_exe: Option<String>,
    /// The build's own facts, read here so the renderer stays pure and the digest
    /// comes from `loader::obj_fingerprint()` rather than a second implementation.
    pub build_version: String,
    pub build_obj_len: usize,
    pub build_obj_digest: u64,
}

// ─────────────────────────────── the reads ───────────────────────────────

fn read_proc_str(path: &str) -> Reading<String> {
    match fs::read_to_string(path) {
        Ok(s) => Reading::Seen(s),
        Err(err) => reading_from(&err, path),
    }
}

fn read_exe(pid: u32) -> Reading<ExeInfo> {
    let path = format!("/proc/{pid}/exe");
    let link = match fs::read_link(&path) {
        Ok(l) => l,
        Err(err) => return reading_from(&err, &path),
    };
    let raw = link.to_string_lossy().into_owned();
    let (clean, deleted) = match raw.strip_suffix(" (deleted)") {
        Some(rest) => (rest.to_string(), true),
        None => (raw, false),
    };
    // A deleted image has no path to stat, so "same file as me" cannot be
    // claimed about it — the answer is `false` and the `deleted` flag says why.
    let same = if deleted {
        false
    } else {
        match (
            fs::metadata(&clean),
            std::env::current_exe().and_then(fs::metadata),
        ) {
            (Ok(theirs), Ok(mine)) => theirs.dev() == mine.dev() && theirs.ino() == mine.ino(),
            _ => false,
        }
    };
    Reading::Seen(ExeInfo {
        path: clean,
        deleted,
        same_file_as_self: same,
    })
}

/// `argv` of a pid, split on the NULs `/proc` actually uses. Joining first — which
/// is what `events::cmdline_of` does for *evidence* — would turn a path with a
/// space into two argv entries and break the exact-basename rule above.
fn read_argv(pid: u32) -> Reading<Vec<String>> {
    let path = format!("/proc/{pid}/cmdline");
    match fs::read(&path) {
        Ok(raw) => {
            let argv: Vec<String> = raw
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            if argv.is_empty() {
                // A zombie, or a process that zeroed its own argv: /proc says there
                // is no command line, which is not "no command line was given".
                Reading::Absent
            } else {
                Reading::Seen(argv)
            }
        }
        Err(err) => reading_from(&err, &path),
    }
}

/// The `SigCgt:` field of `/proc/<pid>/status`: the mask of signals this process
/// has installed a handler for, where bit `n-1` is signal `n`.
pub fn parse_sig_cgt(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("SigCgt:") {
            return u64::from_str_radix(rest.split_whitespace().next()?, 16).ok();
        }
    }
    None
}

/// `/proc/<pid>/task`: every tid, its comm, its state character.
fn read_threads(pid: u32) -> Reading<Vec<Thread>> {
    let dir = format!("/proc/{pid}/task");
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(err) => return reading_from(&err, &dir),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().into_string().ok();
        let Some(tid) = name.as_deref().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let comm_path = format!("/proc/{pid}/task/{tid}/comm");
        // A thread that exited between the listing and this read: its name would be
        // evidence about nothing, so it is skipped rather than counted as missing.
        let Ok(raw) = fs::read_to_string(&comm_path) else {
            continue;
        };
        let comm = raw.trim_end().to_string();
        let state_path = format!("/proc/{pid}/task/{tid}/stat");
        let state = fs::read_to_string(&state_path)
            .ok()
            .and_then(|raw| {
                // Field 2 is the comm in parentheses and may contain spaces or `)`,
                // exactly as in `/proc/<pid>/stat` — so anchor on the LAST `)` and
                // take field 3 (see `events::parse_starttime`).
                let after = &raw[raw.rfind(')')? + 1..];
                after.split_whitespace().next()?.chars().next()
            })
            .unwrap_or('?');
        out.push(Thread { tid, comm, state });
    }
    Reading::Seen(out)
}

/// Where the agent's stderr points. `fd` is mode `0700` for the owning user, so
/// against a root-owned unit as an ordinary user this is the expected `Blind`.
fn read_log_sink(pid: u32) -> Reading<String> {
    let path = format!("/proc/{pid}/fd/2");
    match fs::read_link(&path) {
        Ok(l) => Reading::Seen(l.to_string_lossy().into_owned()),
        Err(err) => reading_from(&err, &path),
    }
}

/// Clock ticks per second, the divisor every `/proc/<pid>/stat` field 22 needs.
fn clk_tck() -> f64 {
    // SAFETY: sysconf(_SC_CLK_TCK) reads a config value with no arguments and no
    // allocator state; a non-positive return falls back to the 100 Hz every Linux
    // build uses (the same reason `config::page_size` trusts sysconf for its value).
    let n = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if n > 0 {
        n as f64
    } else {
        100.0
    }
}

/// Seconds of uptime this process has been alive: `/proc/uptime`'s first field
/// minus field 22 of `/proc/<pid>/stat` over `CLK_TCK`. Both are the kernel's own
/// numbers, so no wall-clock jump can move them.
fn read_age(pid: u32) -> Reading<u64> {
    let uptime = match read_proc_str("/proc/uptime") {
        Reading::Seen(s) => s,
        Reading::Absent => return Reading::Absent,
        Reading::Blind(m) => return Reading::Blind(m),
    };
    let Some(up) = uptime
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
    else {
        return Reading::Blind("/proc/uptime: the first field is not a number".to_string());
    };
    let Some(ticks) = starttime_of(pid) else {
        return Reading::Blind(format!(
            "/proc/{pid}/stat: unreadable or too short (a hidepid= mount?), so this process's \
             start time is not knowable"
        ));
    };
    let age = up - ticks as f64 / clk_tck();
    if !age.is_finite() || age < 0.0 {
        return Reading::Blind(format!(
            "/proc/uptime minus starttime gives {age:.1} s: one of the two numbers is not from \
             this boot, so no age is reported"
        ));
    }
    Reading::Seen(age as u64)
}

/// The absolute start time, for the config-freshness comparison. `btime` is the
/// boot instant in epoch seconds, so `btime + starttime/CLK_TCK` is a wall clock.
fn read_start_epoch(pid: u32) -> Option<u64> {
    let btime = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime ")?.trim().parse::<u64>().ok())?;
    let ticks = starttime_of(pid)?;
    Some(btime.saturating_add((ticks as f64 / clk_tck()) as u64))
}

/// The agent's config file, read by THIS process, now.
fn read_disk_config(path: &str) -> Reading<ParseInfo> {
    // One open before `Config::load`, purely to get the *errno*: "not there" and
    // "not allowed" are answers about the host, while "this text does not parse" is
    // an answer about the file, and collapsing them would turn a deleted config into
    // a syntax complaint. (A file removed between this open and the load reports as a
    // parse failure quoting the real cause — a race this command does not pretend to
    // close.)
    if let Err(err) = fs::File::open(path) {
        return reading_from(&err, path);
    }
    match Config::load(Path::new(path)) {
        Ok(cfg) => Reading::Seen(ParseInfo {
            parses: true,
            mode: format!("{:?}", cfg.mode),
            unread_keys: cfg.unread_keys.len(),
            bridge: cfg.bridge.is_some(),
            heartbeat: cfg.heartbeat.is_some(),
            error: String::new(),
        }),
        Err(err) => Reading::Seen(ParseInfo {
            parses: false,
            mode: String::new(),
            unread_keys: 0,
            bridge: false,
            heartbeat: false,
            error: err.to_string(),
        }),
    }
}

fn mtime_epoch(path: &str) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Every numeric entry in /proc, plus whether the listing itself worked — the
/// difference between "no agent" and "I could not look".
fn list_pids() -> (Vec<u32>, bool) {
    match fs::read_dir("/proc") {
        Ok(entries) => {
            let mut out = Vec::new();
            for e in entries.flatten() {
                if let Ok(name) = e.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        out.push(pid);
                    }
                }
            }
            out.sort_unstable();
            (out, true)
        }
        Err(_) => (Vec::new(), false),
    }
}

fn read_candidate(pid: u32) -> Candidate {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string());
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|raw| {
            raw.lines()
                .find_map(|l| l.strip_prefix("0::").map(|r| r.trim().to_string()))
        });
    let uid = fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|raw| {
            raw.lines().find_map(|l| {
                l.strip_prefix("Uid:")
                    .and_then(|r| r.split_whitespace().next()?.parse::<u32>().ok())
            })
        });
    Candidate {
        pid,
        uid,
        cgroup,
        comm,
    }
}

/// Do the /proc work. Everything the renderer says comes from here, so no claim
/// can be invented at print time.
pub fn gather(operator_config: Option<&Path>) -> Snapshot {
    let self_pid = std::process::id();
    let (pids, proc_walkable) = list_pids();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut commands_skipped = 0usize;
    if proc_walkable {
        for pid in pids {
            // Our own pid is a process named `warden` with our own argv in it: it is
            // the closest thing this command has to a false positive, and it is why
            // the exclusion is by pid rather than by name.
            if pid == self_pid {
                continue;
            }
            let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim_end().to_string());
            let argv = read_argv(pid);
            let argv_ref: Option<&[String]> = match &argv {
                Reading::Seen(v) => Some(v),
                _ => None,
            };
            if !matches_agent_name(
                comm.as_deref(),
                argv_ref.and_then(|v| v.first()).map(String::as_str),
            ) {
                continue;
            }
            if argv_ref.is_some_and(is_a_command_not_the_agent) {
                commands_skipped += 1;
                continue;
            }
            candidates.push(read_candidate(pid));
        }
    }
    let pick = pick(candidates, proc_walkable);
    let agent = match &pick {
        Pick::One { agent, .. } => Some(read_agent(agent.clone())),
        _ => None,
    };
    Snapshot {
        self_pid,
        proc_walkable,
        commands_skipped,
        pick,
        agent,
        operator_config: operator_config.map(|p| p.display().to_string()),
        self_exe: std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().into_owned()),
        build_version: env!("CARGO_PKG_VERSION").to_string(),
        build_obj_len: obj_len(),
        build_obj_digest: obj_fingerprint(),
    }
}

fn read_agent(cand: Candidate) -> Agent {
    let pid = cand.pid;
    let status = read_proc_str(&format!("/proc/{pid}/status"));
    let sig_cgt = match status {
        Reading::Seen(raw) => match parse_sig_cgt(&raw) {
            Some(mask) => Reading::Seen(mask),
            None => Reading::Blind(format!("/proc/{pid}/status: no SigCgt field")),
        },
        Reading::Absent => Reading::Absent,
        Reading::Blind(m) => Reading::Blind(m),
    };
    let argv = read_argv(pid);
    let config_path = argv.get().and_then(|v| config_path_from_argv(v));
    let cmdline = match &argv {
        Reading::Seen(v) => Reading::Seen(v.join(" ")),
        Reading::Absent => Reading::Absent,
        Reading::Blind(m) => Reading::Blind(m.clone()),
    };
    let config_path = config_path.map(str::to_string);
    let disk = match &config_path {
        Some(p) => read_disk_config(p),
        None => Reading::Absent,
    };
    let mtime_epoch = config_path.as_deref().and_then(mtime_epoch);
    Agent {
        pid,
        uid: cand.uid,
        cgroup: cand.cgroup,
        comm: cand.comm,
        exe: read_exe(pid),
        cmdline,
        config_path,
        sig_cgt,
        age_secs: read_age(pid),
        start_epoch: read_start_epoch(pid),
        threads: read_threads(pid),
        log_sink: read_log_sink(pid),
        disk,
        mtime_epoch,
    }
}

/// The path the agent's own argv names: the last `--config`/`-c` wins, exactly as
/// `main.rs`'s parser overwrites its variable on every occurrence. A form the
/// daemon's parser would not accept is not recognised here either.
pub fn config_path_from_argv(argv: &[String]) -> Option<&str> {
    let mut found = None;
    let mut iter = argv.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "--config" || a == "-c" {
            found = iter.next().map(String::as_str);
        }
    }
    found
}

// ─────────────────────────────── the decisions ───────────────────────────────

/// The threads the file on disk says this agent started with.
///
/// The main thread carries the executable's name (the kernel sets `comm` at
/// `execve`) and the two optional threads are named by `std::thread::Builder`. The
/// DNS helper `heartbeat.rs` detaches is deliberately NOT here: it exists for the
/// duration of one blocked `getaddrinfo` and then exits, so its absence is never a
/// gap and its presence is never a surprise.
pub fn expected_threads(bridge: bool, heartbeat: bool) -> Vec<String> {
    let mut out = vec![comm_visible(AGENT_COMM)];
    if bridge {
        out.push(comm_visible(DELIVER_THREAD));
    }
    if heartbeat {
        out.push(comm_visible(HEARTBEAT_THREAD));
    }
    out
}

/// Which expected threads were not seen. Comparison is by name, not by count: a
/// transient helper thread makes a count-based check wrong in both directions.
pub fn missing_threads(expected: &[String], seen: &[Thread]) -> Vec<String> {
    expected
        .iter()
        .filter(|want| !seen.iter().any(|t| t.comm == **want))
        .cloned()
        .collect()
}

/// The verdict for a thread the file asks for and `/proc` does not show.
///
/// Whether that is a dead thread or a file that moved under the agent is decided by
/// the only evidence available: has the config file been touched since this process
/// started? If it has, the agent may have started without that section — and a
/// SIGHUP could not have created the thread anyway, because `[bridge]` and
/// `[heartbeat]` are restart-required (`unapplied_heartbeat_changes`) — so the
/// honest word is `CANNOT TELL`. Only when the file is as old as the process is the
/// absence a `DEGRADED`.
pub fn thread_gap_verdict(file_older_than_start: Option<bool>) -> Verdict {
    match file_older_than_start {
        Some(true) => Verdict::Degraded,
        _ => Verdict::CannotTell,
    }
}

/// The identity verdict. `comm` is settable from inside any process with
/// `prctl(PR_SET_NAME)` and `argv[0]` is settable by whoever exec'd it, so a name
/// match alone can only ever be `PARTIAL`: the exe link is the identity, and for a
/// root-owned process it is ptrace-gated. W2K-18 learned this about loader
/// authorization; the same rule governs the process this command is looking for.
pub fn identity_verdict(exe: &Reading<ExeInfo>) -> Verdict {
    match exe {
        Reading::Seen(info) if info.deleted => Verdict::Degraded,
        Reading::Seen(_) => Verdict::Verified,
        Reading::Absent => Verdict::Absent,
        Reading::Blind(_) => Verdict::Partial,
    }
}

/// Is the agent's `SigCgt` mask arming the SIGHUP control path? SIGHUP is signal 1,
/// so it is bit 0 of the mask.
pub fn sighup_armed(mask: u64) -> bool {
    mask & 1 == 1
}

/// The freshness claim: is the file on disk the text the agent started with?
pub fn freshness_verdict(file_newer: Option<bool>, parses: bool) -> (Verdict, &'static str) {
    if !parses {
        return (
            Verdict::Degraded,
            "the file does not parse now, so no version of it can be trusted as the loaded one",
        );
    }
    match file_newer {
        Some(false) => (
            Verdict::Verified,
            "unmodified since this agent started, so it is the text the agent read at start",
        ),
        Some(true) => (
            Verdict::Partial,
            "NEWER than the process: the agent's in-memory policy is whatever it last \
             re-read successfully, and [bridge], [heartbeat] and [runtime] ring_size_kib stay \
             restart-required even after a SIGHUP",
        ),
        None => (
            Verdict::CannotTell,
            "neither the file's mtime nor the process's start time could be read",
        ),
    }
}

/// What the log sink says about the agent's journal lines.
pub fn log_sink_verdict(sink: Option<&str>) -> (Verdict, &'static str) {
    match sink {
        Some("/dev/null") => (
            Verdict::Degraded,
            "stderr is /dev/null: everything the agent would have printed — every finding's \
             journal line, the ring-buffer drop warnings, the coverage sentences — is discarded \
             by this process's own file table",
        ),
        Some(s) if s.starts_with("pipe:") || s.starts_with("socket:") => (
            Verdict::Partial,
            "stderr is a pipe/socket, which is the shape systemd's journal stream takes: the \
             stream is being captured, and what is IN it is UNVERIFIED here — this command \
             spawns no journalctl",
        ),
        Some(_) => (
            Verdict::Partial,
            "stderr points at a file this command can name but does not read: the agent's lines \
             are wherever that path is, and their contents are UNVERIFIED here",
        ),
        None => (
            Verdict::CannotTell,
            "another uid's /proc/<pid>/fd is mode 0700 and needs PTRACE_MODE_READ, and this \
             command takes no capability, so whether the agent's journal lines are captured or \
             thrown away is not answered",
        ),
    }
}

// ─────────────────────────────── the renderer ───────────────────────────────

/// One claim: `warden: health: <claim>: <STATUS> — <detail>`, always exactly one
/// line, so the report stays greppable and diffable the way `--doctor`'s is.
fn line(claim: &str, verdict: Verdict, detail: impl AsRef<str>) -> String {
    format!(
        "warden: health: {claim}: {} — {}",
        verdict.word(),
        detail.as_ref()
    )
}

pub fn render(snap: &Snapshot) -> Vec<String> {
    let mut out = Vec::new();

    let self_exe = snap.self_exe.as_deref().unwrap_or(
        "nowhere: current_exe() failed, so even the image of the process printing this line is \
         unnamed",
    );
    out.push(line(
        "build",
        Verdict::Verified,
        format!(
            "warden {}, eBPF object {} bytes (fnv-1a {:016x}), this command runs from {self_exe:?}. \
             VERIFIED of the binary printing this line only: it names the object COMPILED INTO \
             IT, not the one a running agent loaded — that claim is \
             `cannot see/attached programs` below.",
            snap.build_version, snap.build_obj_len, snap.build_obj_digest,
        ),
    ));

    match &snap.pick {
        Pick::Blind => out.push(line(
            "process",
            Verdict::CannotTell,
            "/proc could not be listed, so nothing at all is concluded about a running agent. \
             That is not \"no agent\", it is \"no answer\", and the difference between the two \
             is the whole design of this command.",
        )),
        Pick::None => out.push(line(
            "process",
            Verdict::Absent,
            format!(
                "no entry in /proc is named {AGENT_COMM:?} except this command (pid {}). ABSENT \
                 means \"among the entries /proc shows THIS user\": a /proc mounted with \
                 `hidepid=` hides other users' directories from the listing itself, and a unit \
                 whose ExecStart runs this binary under another name is invisible here too, so \
                 this line is never proof that nothing is running. Nothing is loaded, nothing is \
                 judged; {} other same-named process(es) on this host were excluded because \
                 they are commands, not the daemon.",
                snap.self_pid, snap.commands_skipped
            ),
        )),
        Pick::Several(list) => {
            for c in list {
                out.push(line(
                    "candidate",
                    Verdict::Partial,
                    format!(
                        "pid {} — uid {}, cgroup {}, comm {}. One of {} same-named processes, \
                         none excluded as a command, so no single agent was identifiable from \
                         /proc alone.",
                        c.pid,
                        c.uid
                            .map(|u| u.to_string())
                            .unwrap_or_else(|| "?".to_string()),
                        c.cgroup.as_deref().unwrap_or("?"),
                        c.comm.as_deref().unwrap_or("?"),
                        list.len()
                    ),
                ));
            }
            out.push(line(
                "process",
                Verdict::CannotTell,
                format!(
                    "{} live processes named {AGENT_COMM:?} and no way to tell the daemon from a \
                     same-named child: exactly one of them had to sit under the unit's cgroup \
                     (`{UNIT_CGROUP_NEEDLE}`) for this command to choose, and none does, so the \
                     per-agent lines are NOT printed. Attaching one process's facts to another's \
                     identity is the failure this branch exists to prevent.",
                    list.len()
                ),
            ));
        }
        Pick::One { agent, others } => {
            // The three world-readable fields, each said as what it is: a value or an
            // explicit unreadable. `Some(..)`/`None` in an operator's output is a
            // developer's Debug format leaking into a report.
            let uid_note = match agent.uid {
                Some(uid) => format!("uid {uid}"),
                None => "uid unreadable".to_string(),
            };
            let cgroup_note = match agent.cgroup.as_deref() {
                Some(c) => format!("cgroup {c:?}"),
                None => "cgroup unreadable (no /proc/<pid>/cgroup, so the unit tiebreaker did \
                         not apply)"
                    .to_string(),
            };
            let comm_note = match agent.comm.as_deref() {
                Some(c) => format!("comm {c:?}"),
                None => "comm unreadable, so the name match came from argv[0] alone".to_string(),
            };
            out.push(line(
                "process",
                Verdict::Present,
                format!(
                    "pid {} is the agent this report is about — {uid_note}, {cgroup_note}, \
                     {comm_note}. Found by exact name on {AGENT_COMM:?} (/proc/<pid>/comm, else \
                     the argv[0] basename), never by substring: this command's own pid ({}) is \
                     excluded by pid and {} other same-named process(es) were excluded because \
                     their argv carries a print-and-return mode. That is §24 step 6's `pgrep` \
                     lesson applied to the search itself, not to the shell command that runs it.",
                    agent.pid, snap.self_pid, snap.commands_skipped
                ),
            ));
            if *others > 0 {
                out.push(line(
                    "process/ambiguity",
                    Verdict::Partial,
                    format!(
                        "{others} further process(es) named {AGENT_COMM:?} exist on this host and \
                         are NOT the one reported above; this line is the only reason they are \
                         not silently ignored, and nothing else in this output says anything \
                         about them."
                    ),
                ));
            }
        }
    }

    let Some(ag) = &snap.agent else {
        if !snap.proc_walkable {
            out.push(line(
                "visibility",
                Verdict::Unavailable,
                "every line below this one would be a /proc read of another process, and this \
                 user could not list /proc at all: the report stops here rather than printing a \
                 wall of CANNOT TELL about a host this command cannot see.",
            ));
        }
        out.extend(not_seen(snap));
        out.push(footer());
        return out;
    };

    // Identity: the exe link, and what it can and cannot prove.
    let id_verdict = identity_verdict(&ag.exe);
    match &ag.exe {
        Reading::Seen(info) => {
            let same = if info.same_file_as_self {
                "is the same file this command runs from (same dev+ino), so the digest on the \
                 build line IS the digest of the object embedded in the binary this agent \
                 started from"
            } else {
                "is NOT the file this command runs from, so the digest printed above belongs to \
                 a different binary — run `--version` from the agent's own path to compare them"
            };
            out.push(line(
                "identity",
                id_verdict,
                format!(
                    "/proc/{}/exe -> {:?}. The link is readable, so this is the image the kernel \
                     is executing, not a name the process chose: {same}. {}",
                    ag.pid,
                    info.path,
                    if info.deleted {
                        "It ends in ` (deleted)`: the file was replaced or removed AFTER start, \
                         so the bytes now at that path are NOT the bytes this agent is running, \
                         and every digest comparison from here on is about a file the agent has \
                         never executed."
                    } else {
                        ""
                    }
                ),
            ));
        }
        Reading::Absent => out.push(line(
            "identity",
            Verdict::Absent,
            format!(
                "/proc/{}/exe is gone: the pid vanished between the /proc listing and this read, \
                 so the process named above is not one this command can describe. Re-run.",
                ag.pid
            ),
        )),
        Reading::Blind(why) => out.push(line(
            "identity",
            id_verdict,
            format!(
                "{why}. A comm match is an introduction, not an identity: `prctl(PR_SET_NAME)` \
                 sets comm from inside any process and `argv[0]` is chosen by whoever exec'd it, \
                 which is the reason W2K-18 stopped authorizing BPF loaders by comm. So the \
                 process at pid {} is named {AGENT_COMM:?} and is NOT proven to be Warden: the exe \
                 link is the proof and it needs PTRACE_MODE_READ — the CAP_SYS_PTRACE the unit \
                 grants the daemon and that this command deliberately does not take. Running \
                 `--version` on the path in its argv answers the identity half unprivileged; \
                 running THIS command as the service's own uid answers it directly.",
                ag.pid
            ),
        )),
    }

    // The control channel the roadmap names: SIGHUP, and nothing else.
    match &ag.sig_cgt {
        Reading::Seen(mask) => {
            let hup = sighup_armed(*mask);
            out.push(line(
                "control",
                if hup {
                    Verdict::Verified
                } else {
                    Verdict::Degraded
                },
                format!(
                    "/proc/{}/status SigCgt={mask:#018x}: SIGHUP handler armed={}, SIGTERM={}, \
                     SIGINT={}. {} Whether a reload has EVER been delivered is UNVERIFIED and is \
                     not observable from /proc: a signal leaves no trace behind, so \"the policy \
                     in memory equals the policy on disk\" is not a claim this line makes.",
                    ag.pid,
                    hup,
                    mask & (1 << 14) != 0,
                    mask & (1 << 1) != 0,
                    if hup {
                        "So the only control path the unit documents \
                         (ExecReload=/bin/kill -HUP $MAINPID) does reach this process."
                    } else {
                        "This process has NO SIGHUP handler: reloading it would do nothing at all."
                    }
                ),
            ));
        }
        Reading::Absent => out.push(line(
            "control",
            Verdict::Absent,
            format!("/proc/{}/status disappeared.", ag.pid),
        )),
        Reading::Blind(why) => out.push(line(
            "control",
            Verdict::CannotTell,
            format!(
                "{why}: the signal mask is unreadable, so nothing is claimed about the SIGHUP \
                 control path — which is not the same as it being broken."
            ),
        )),
    }

    // Threads: the loops the daemon spawns, as the kernel names them.
    let file_older = match (ag.mtime_epoch, ag.start_epoch) {
        (Some(m), Some(s)) => Some(m <= s),
        _ => None,
    };
    match &ag.threads {
        Reading::Seen(threads) => {
            let parse_ok = ag.disk.get();
            let (bridge, heartbeat) = match parse_ok {
                Some(p) => (p.bridge, p.heartbeat),
                // With no readable file the expectation is the minimum: calling a
                // thread missing needs a source that says it should be there, and
                // inventing one from a default is how a false DEGRADED is published.
                None => (false, false),
            };
            let expected = expected_threads(bridge, heartbeat);
            // The expectation needs a source, and saying which one it came from is
            // the difference between a thread list and a thread list plus the reason
            // it might be shorter than the agent's real one.
            let expect_source = if parse_ok.is_some() {
                "Expected from the config file read now:"
            } else {
                "Expected from THIS BUILD'S MINIMUM, because the file that would set \
                 [bridge]/[heartbeat] is unreadable here (see config/parse), so a thread this \
                 expectation cannot ask for is deliberately NOT reported missing:"
            };
            let missing = missing_threads(&expected, threads);
            let extra: Vec<&Thread> = threads
                .iter()
                .filter(|t| !expected.contains(&t.comm))
                .collect();
            let blocked: Vec<&Thread> = threads.iter().filter(|t| t.blocked()).collect();
            let verdict = if !missing.is_empty() {
                thread_gap_verdict(file_older)
            } else if !blocked.is_empty() {
                Verdict::Degraded
            } else if parse_ok.is_none() {
                Verdict::Partial
            } else {
                Verdict::Present
            };
            out.push(line(
                "threads",
                verdict,
                format!(
                    "/proc/{}/task: {} thread(s) — {}. {} {}. Names compared AFTER the kernel's \
                     15-byte cut, so {:?} is what a live \
                     heartbeat thread is actually called. {}. {}. NOT a liveness proof: a main \
                     thread sleeping in `epoll_wait` and a main thread wedged in a syscall are \
                     the same character here.",
                    ag.pid,
                    threads.len(),
                    threads
                        .iter()
                        .map(|t| format!("tid {} {}/{}", t.tid, t.comm, t.state))
                        .collect::<Vec<_>>()
                        .join(", "),
                    expect_source,
                    expected
                        .iter()
                        .map(|s| format!("{s:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    comm_visible(HEARTBEAT_THREAD),
                    if missing.is_empty() {
                        "every expected thread is present".to_string()
                    } else {
                        format!(
                            "NOT SEEN: {} — {}",
                            missing
                                .iter()
                                .map(|s| format!("{s:?}"))
                                .collect::<Vec<_>>()
                                .join(", "),
                            match file_older {
                                Some(true) => "the config file predates this process, so it \
                                               started with the section that asks for this \
                                               thread and the thread is not there"
                                    .to_string(),
                                Some(false) => "the config file is NEWER than the process: the \
                                               section may have arrived after start, and \
                                               [bridge]/[heartbeat] are restart-required even \
                                               after a SIGHUP"
                                    .to_string(),
                                None => "neither the file's mtime nor the process's start is \
                                        readable, so this cannot be called a gap"
                                    .to_string(),
                            }
                        )
                    },
                    if extra.is_empty() {
                        "no unexplained threads".to_string()
                    } else {
                        format!(
                            "thread(s) the expectation does not name: {} — the heartbeat DNS \
                             helper is transient and asserted in neither direction, so anything \
                             else here is not explained by this build's code",
                            extra
                                .iter()
                                .map(|t| format!("tid {} {:?}", t.tid, t.comm))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    },
                ),
            ));
        }
        Reading::Absent => out.push(line(
            "threads",
            Verdict::Absent,
            format!("/proc/{}/task is gone.", ag.pid),
        )),
        Reading::Blind(why) => out.push(line(
            "threads",
            Verdict::CannotTell,
            format!("{why}: which loops the agent is running is not observable."),
        )),
    }

    // The config the agent was pointed at, and whether it still parses.
    match &ag.config_path {
        None => out.push(line(
            "config/path",
            Verdict::Degraded,
            format!(
                "{} named no `--config`, so this agent judges with `Config::safe_default()` and \
                 whatever file is under /etc/warden is NOT what it runs. That is the strictest \
                 posture rather than a broken one — but it is a posture nobody configured, and \
                 `--check` on that file would describe a policy this process does not implement. \
                 argv read: {}.",
                match &ag.cmdline {
                    Reading::Seen(c) => format!("argv {c:?}"),
                    Reading::Absent => "an empty argv (a zombie, or a process that zeroed it)"
                        .to_string(),
                    Reading::Blind(w) => format!(
                        "unreadable ({w}), so the absence of a flag is not itself evidence"
                    ),
                },
                snap.operator_config
                    .as_ref()
                    .map(|p| format!("the --config {p:?} given to THIS command is not used by \
                                      --health, and there is no agent path to compare it with"))
                    .unwrap_or_else(|| "nothing on this command line was substituted for it".into())
            ),
        )),
        Some(p) => {
            let mut detail = format!(
                "/proc/{}/cmdline names {p:?}, read from the agent's own argv and never from this \
                 command's flags.",
                ag.pid
            );
            if let Some(op) = &snap.operator_config {
                if op != p {
                    detail.push_str(&format!(
                        " The --config {op:?} given to THIS command is DIFFERENT and is NOT used: \
                         an agent's path is its own argv's."
                    ));
                }
            }
            out.push(line("config/path", Verdict::Present, detail));

            match &ag.disk {
                Reading::Seen(info) if info.parses => {
                    let unread = if info.unread_keys == 0 {
                        "no unread keys".to_string()
                    } else {
                        format!(
                            "{} unread key(s) — W2K-23: those names are in the file and no field \
                             of their section reads them, so the value in effect is Warden's \
                             default",
                            info.unread_keys
                        )
                    };
                    out.push(line(
                        "config/parse",
                        Verdict::Verified,
                        format!(
                            "THIS process re-read {p:?} and it parses with this binary: mode={}, \
                             [bridge]={}, [heartbeat]={}, {}. A statement about the file and \
                             about this build's parser — NOT about the policy the agent holds in \
                             memory, which is `cannot see/the policy in the agent's memory`.",
                            info.mode, info.bridge, info.heartbeat, unread
                        ),
                    ));
                    let (fv, note) = freshness_verdict(file_older, true);
                    out.push(line(
                        "config/freshness",
                        fv,
                        format!(
                            "file mtime {:?} vs process start {:?}: {}. Both from stat() on the \
                             path above and from /proc/stat's `btime` plus field 22 of \
                             /proc/{}/stat.",
                            ag.mtime_epoch, ag.start_epoch, note, ag.pid
                        ),
                    ));
                }
                Reading::Seen(info) => {
                    out.push(line(
                        "config/parse",
                        Verdict::Degraded,
                        format!(
                            "{p:?} does NOT parse for this binary: {}. A running agent cannot \
                             have loaded this text as it stands — either the file changed after \
                             the agent started, or the unit's `ExecStartPre` gate (`warden \
                             --check`) was bypassed. The in-memory policy is therefore NOT this \
                             file, and which of the two it is stays UNVERIFIED.",
                            info.error
                        ),
                    ));
                    let (fv, note) = freshness_verdict(file_older, false);
                    out.push(line(
                        "config/freshness",
                        fv,
                        format!(
                            "file mtime {:?} vs process start {:?}: {note}.",
                            ag.mtime_epoch, ag.start_epoch
                        ),
                    ));
                }
                // The two read failures are NOT parse failures, and printing a
                // freshness line for a file whose text could not be read would imply
                // the comparison had a left-hand side.
                Reading::Absent => out.push(line(
                    "config/parse",
                    Verdict::Absent,
                    format!(
                        "{p:?} is not in the filesystem at all: the agent names a file that does \
                         not exist, so nothing on disk can be compared with what it loaded, and \
                         the file was either removed after start or the unit started from a \
                         mount that is gone now."
                    ),
                )),
                Reading::Blind(why) => out.push(line(
                    "config/parse",
                    Verdict::CannotTell,
                    format!(
                        "{why}: the agent's config path is named above and this user cannot read \
                         it, so whether it still parses is not answered — run this as the \
                         service's own uid or as root for that half."
                    ),
                )),
            }
        }
    }

    // Where the agent's own lines go.
    let sink: Option<&str> = ag.log_sink.get().map(String::as_str);
    let (lv, lnote) = log_sink_verdict(sink);
    out.push(line(
        "log sink",
        lv,
        format!(
            "/proc/{}/fd/2: {}. {}",
            ag.pid,
            match &ag.log_sink {
                Reading::Seen(s) => format!("{s:?}"),
                Reading::Absent => "gone".to_string(),
                Reading::Blind(w) => w.clone(),
            },
            lnote
        ),
    ));

    out.push(line(
        "age",
        match &ag.age_secs {
            Reading::Seen(_) => Verdict::Verified,
            Reading::Absent => Verdict::Absent,
            Reading::Blind(_) => Verdict::CannotTell,
        },
        format!(
            "{}. From /proc/uptime minus field 22 of /proc/{}/stat over CLK_TCK, so it is the \
             kernel's own clock and no wall-clock jump can move it. A restart COUNT is not in \
             here: `NRestarts` is a systemd property, not a /proc one, and this command opens no \
             bus socket and spawns nothing.",
            match &ag.age_secs {
                Reading::Seen(secs) => format!("running for {secs} s"),
                Reading::Absent => "the pid is gone".to_string(),
                Reading::Blind(w) => format!("not knowable ({w})"),
            },
            ag.pid
        ),
    ));

    out.extend(not_seen(snap));
    out.push(footer());
    out
}

/// The section that exists because the counters above do not. Every line here is a
/// claim this command is NOT making, and why — the blueprint's rule that incomplete
/// coverage must be declared rather than left as silence. Names use a `/` so the
/// `claim: STATUS — detail` split stays one `split_once` away for any parser.
fn not_seen(snap: &Snapshot) -> Vec<String> {
    let items: [(&str, String, Verdict); 7] = [
        (
            "attached programs",
            "Which of the sensor programs and the six `lsm/*` enforcing programs are attached, \
             and whether BPF-LSM took at all. `--doctor` says which functions THIS kernel has; \
             only a `bpf()` syscall (`BPF_PROG_GET_NEXT_ID` / `BPF_OBJ_GET_INFO_BY_FD`) says what \
             this agent attached, and that needs CAP_BPF — exactly the privilege this command is \
             built not to take. So a running agent's attach set is UNVERIFIED from here, always: \
             a line that read \"sensors up\" would be a fabrication, and the absence of such a \
             line is the honest answer."
                .to_string(),
            Verdict::Unverified,
        ),
        (
            "ring buffer",
            "The capacity the kernel actually built and the per-sensor drop/submitted counters \
             (W-02, W2K-14): both are map reads. The journal line the event loop prints every \
             PROTECT_REFRESH carries them, so where to look is the journal — which this command \
             does not read."
                .to_string(),
            Verdict::Unverified,
        ),
        (
            "volume totals",
            "The per-cgroup send/recv totals (N-05), the hooks' attached-or-not state and BTF \
             ABI rejections, the per-hook fexit invocation counts, the refused-bump count and \
             the sampler's previous-read deltas: all of them are kernel map reads or this \
             agent's own memory. `net_vol::coverage_line` and the tick line are the statements \
             the agent makes about them and they live in the journal, not here."
                .to_string(),
            Verdict::Unverified,
        ),
        (
            "protected pid set",
            format!(
                "The kernel's `protected_pids` map. Re-running `procscan::resolve_protected` in \
                 THIS process would answer a different question: with `protect_self` it inserts \
                 `std::process::id()`, i.e. the pid of whoever is reading ({}), so its output \
                 would be this command's view of the file rather than the agent's map — and \
                 \"what the file says\" is already what `--check` and `--explain` are for.",
                snap.self_pid
            ),
            Verdict::Unverified,
        ),
        (
            "the policy in the agent's memory",
            "What `Detector::new(cfg)` is holding after any number of SIGHUPs. There is no \
             status path: the daemon reads the file at start and on reload and keeps the result \
             in process memory. The file's CURRENT text is reported above, and \"the two agree\" \
             is only ever implied by the freshness line — never claimed."
                .to_string(),
            Verdict::Unverified,
        ),
        (
            "what the agent logged",
            "Findings raised, journal lines suppressed by the 10 s throttle, bridge spool depth, \
             heartbeat beats. Those are journald's records and files under the service's own \
             StateDirectory (mode 0700); this command spawns no `journalctl` and does not walk a \
             root-owned directory it was not given. An operator who wants them asks journald."
                .to_string(),
            Verdict::Unverified,
        ),
        (
            "the unit's own state",
            "`ActiveState`, `NRestarts`, `ExecMainPID`, and whether the process reported here is \
             the one systemd thinks it started. All of that is on the bus, and a health command \
             that talked to systemd would be a second control channel — the roadmap's rule is \
             that control happens by SIGHUP and nowhere else."
                .to_string(),
            Verdict::Unsupported,
        ),
    ];
    let mut out = Vec::new();
    for (name, why, verdict) in items {
        out.push(line(&format!("cannot see/{name}"), verdict, why));
    }
    out.push(line(
        "cannot see/another uid's process",
        Verdict::Unavailable,
        "Every /proc/<pid>/{exe,fd} link of a process owned by another uid needs \
         PTRACE_MODE_READ, and whole entries disappear under a `hidepid=` mount, so a root-owned \
         agent is described here only by the fields that stay world-readable: comm, cmdline, \
         status, stat, cgroup, task/*/comm. The limit is this command's privilege level, not the \
         agent's — run it as the service's own uid and the same lines come back with more of them \
         filled in.",
    ));
    out.push(line(
        "cannot see/sockets outside Warden's namespace",
        Verdict::Unavailable,
        "Sockets in another network namespace — every container's — are invisible to a pull path \
         run from an unprivileged process, so \"what is listening\" is not a question --health \
         answers about anyone but the agent's own netns. `--socket-snapshot` is the command that \
         answers it, and its own report names what it cannot see there.",
    ));
    out
}

fn footer() -> String {
    line(
        "what this did NOT do",
        Verdict::Verified,
        "No `bpf()` syscall, no map opened, nothing attached, nothing loaded, no capability \
         taken, no signal sent, no file written, no subprocess spawned. It listed /proc, read \
         each candidate's comm, argv and status, and for the one process it chose also its exe \
         link, its task/*/comm, its fd/2 and the config path its own argv names. Five commands \
         load nothing: `--version` names THIS BUILD, and four answer four different questions — \
         `--check` = what the FILE says, `--doctor` = what this KERNEL could do, `--explain` = \
         what this config would have said about an event that is not happening, `--health` = what \
         a RUNNING agent can be seen to be from /proc. Only the last is about a process that is \
         up right now, and none of the five measures detection.",
    )
}

/// The entry point: read, then render. `main.rs` prints the lines.
///
/// PRQ-01: redaction is applied here, to the SAME lines the human sees, so the
/// human and JSON views cannot diverge on what was masked. Previously only the
/// JSON view masked (and only double-quoted `api_key` values), leaving the human
/// output able to carry a credential quoted by a TOML parse error.
pub fn report(operator_config: Option<&PathBuf>) -> Vec<String> {
    render(&gather(operator_config.map(PathBuf::as_path)))
        .into_iter()
        .map(|line| redact_secrets(&line))
        .collect()
}

/// Split one rendered line into `(claim, status, detail)`.
///
/// The line grammar is fixed by `line()` above — `warden: health: {claim}:
/// {STATUS} — {detail}` — and the em-dash separator is deliberately not a
/// colon, so a claim that itself contains a colon (or a detail full of them)
/// still splits exactly once. This keeps JSON and human text derived from ONE
/// render pass rather than two independent implementations that could drift.
fn parse_line(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("warden: health: ")?;
    let (claim, rest) = rest.split_once(": ")?;
    let (status, detail) = rest.split_once(" — ")?;
    Some((claim, status, detail))
}

/// Defensive redaction for both human and machine-readable forms.
///
/// The health report never reads a config VALUE (only its path, mode and parse
/// status), but a TOML parse error can quote the offending line — and that line
/// could be `api_key = "secret"`, a literal string (`'secret'`), or a multi-line
/// string. PRQ-01: instead of trying to parse every TOML string form, we redact
/// everything after `=` on any line containing a credential-key assignment.
/// Over-redaction is safe; under-redaction would leak a bridge credential into a
/// monitoring scrape or the operator's terminal.
fn redact_secrets(text: &str) -> String {
    const SECRET_KEYS: &[&str] = &[
        "api_key",
        "apikey",
        "secret",
        "token",
        "password",
        "passwd",
        "private_key",
        "client_secret",
        "root_token",
        "hmac_secret",
    ];

    fn redact_line(line: &str) -> String {
        let newline = if line.ends_with('\n') { "\n" } else { "" };
        let body = line.strip_suffix('\n').unwrap_or(line);
        let lower = body.to_ascii_lowercase();
        let mut best: Option<(usize, usize)> = None; // (start, key_len)
        for key in SECRET_KEYS {
            let mut search = 0usize;
            while let Some(rel) = lower[search..].find(key) {
                let p = search + rel;
                let preceded_ok = p == 0 || {
                    let b = lower.as_bytes()[p - 1];
                    !(b.is_ascii_alphanumeric() || b == b'_')
                };
                let followed_by_eq = lower[p + key.len()..].trim_start().starts_with('=');
                if preceded_ok && followed_by_eq && best.is_none_or(|(bp, _)| p < bp) {
                    best = Some((p, key.len()));
                    break;
                }
                search = p + key.len();
            }
        }
        match best {
            Some((p, klen)) => {
                let eq_rel = body[p + klen..].find('=').unwrap_or(0);
                let eq = p + klen + eq_rel;
                let mut out = String::with_capacity(body.len() + 16);
                out.push_str(&body[..eq + 1]);
                out.push_str(" [REDACTED]");
                out.push_str(newline);
                out
            }
            None => line.to_string(),
        }
    }

    text.split_inclusive('\n').map(redact_line).collect()
}

/// Machine-readable form of the SAME report, for a monitoring scraper.
///
/// No claim is recomputed here: this parses `report()`'s rendered lines, so the
/// human and JSON views cannot disagree about what was seen or about which
/// evidence word qualifies it. `cannot see/…` lines stay in the array with
/// their `UNVERIFIED` status — JSON must not look healthier than text by
/// dropping the things this cap-less command cannot know.
pub fn report_json(operator_config: Option<&PathBuf>) -> serde_json::Value {
    json_from_lines(&report(operator_config))
}

/// The format conversion itself, separated from the `/proc` read so a unit test
/// can pin the line->JSON mapping without depending on a live host.
fn json_from_lines(lines: &[String]) -> serde_json::Value {
    let mut claims = Vec::with_capacity(lines.len());
    let mut by_status: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for line in lines {
        let (claim, status, detail) = parse_line(line).unwrap_or(("unparsed", "UNPARSED", line));
        *by_status.entry(status.to_string()).or_insert(0) += 1;
        claims.push(serde_json::json!({
            "claim": claim,
            "status": status,
            "detail": redact_secrets(detail),
        }));
    }
    let total = claims.len();
    // Phase 1: fold the rendered evidence words into a single structured
    // telemetry state. The cap-less baseline stays UNKNOWN for everything that
    // needs a live map; a claim that is explicitly DEGRADED or UNAVAILABLE is
    // carried through so JSON cannot look healthier than the text it came from.
    let mut overrides: Vec<crate::telemetry::CoverageClaim> = Vec::new();
    if by_status.get("DEGRADED").copied().unwrap_or(0) > 0 {
        overrides.push(crate::telemetry::CoverageClaim::verified(
            "observed_degraded_claim",
            true,
        ));
    }
    if by_status.get("UNAVAILABLE").copied().unwrap_or(0) > 0 {
        overrides.push(crate::telemetry::CoverageClaim::unsupported(
            "source_unavailable",
        ));
    }
    let telemetry = crate::telemetry::TelemetryReport::cap_less().with_claim_overrides(&overrides);
    serde_json::json!({
        "schema": "warden.health.v1",
        "claims": claims,
        "telemetry": telemetry,
        "totals": {
            "claims": total,
            "by_status": by_status,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // PRQ-01: the redactor must cover every TOML string form a parse error can
    // quote, not just double-quoted api_key values. Over-redaction is acceptable;
    // a surviving credential is not.
    #[test]
    fn secret_redaction_covers_all_toml_string_forms_and_keys() {
        let cases = [
            ("api_key = \"bridgesecret\"", "api_key = [REDACTED]"),
            ("api_key = 'literal-secret'", "api_key = [REDACTED]"),
            (
                "api_key = \"\"\"triple-quoted\"\"\"",
                "api_key = [REDACTED]",
            ),
            ("api_key = '''literal-triple'''", "api_key = [REDACTED]"),
            ("secret = 'hmac-value'", "secret = [REDACTED]"),
            ("token = \"bearer-value\"", "token = [REDACTED]"),
            ("password = \"pw\"", "password = [REDACTED]"),
            ("client_secret='x'", "client_secret= [REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_secrets(input), expected, "input: {input}");
        }
    }

    #[test]
    fn secret_redaction_leaves_non_secret_detail_untouched() {
        let plain = "config/warden.toml mode 0640 parse PASS_WITH_WARNINGS";
        assert_eq!(redact_secrets(plain), plain);
        // A bare key NAME (no assignment) is not a value and stays readable.
        let name_only = "never paste api_key into a report";
        assert_eq!(redact_secrets(name_only), name_only);
    }

    fn cand(pid: u32, cgroup: Option<&str>) -> Candidate {
        Candidate {
            pid,
            uid: Some(0),
            cgroup: cgroup.map(str::to_string),
            comm: Some(AGENT_COMM.to_string()),
        }
    }

    fn thread(tid: u32, comm: &str) -> Thread {
        Thread {
            tid,
            comm: comm.to_string(),
            state: 'S',
        }
    }

    /// A snapshot with no agent anywhere: the shape every branch of the renderer
    /// has to survive without inventing a process to describe.
    ///
    /// The two `build_*` values below are the REAL identity of the object embedded in
    /// this binary, not made-up numbers: `the_build_line_names_the_digest_it_actually_has_and_its_limit`
    /// compares the rendered line against `loader::obj_fingerprint()`, so any change to
    /// `bpf/` turns this fixture stale and that test red. That is the canary, not an
    /// accident — but it is machine-sensitive, because the digest is of the bytes this
    /// clang produced: after `make bpf`, refresh both constants from
    /// `warden --version` (or the FNV-1a/64 in `loader::obj_fingerprint`) rather than
    /// relaxing the assertion.
    fn blind_snapshot() -> Snapshot {
        Snapshot {
            self_pid: 4242,
            proc_walkable: true,
            commands_skipped: 0,
            pick: Pick::None,
            agent: None,
            operator_config: None,
            self_exe: Some("/usr/local/sbin/warden".to_string()),
            build_version: "0.1.0".to_string(),
            // PRQ-01 public-release object: rebuilt with -fdebug-prefix-map to
            // remove builder paths. Refreshed for the F06 rebuild; see
            // `warden --version` after make bpf.
            build_obj_len: 1_249_648,
            build_obj_digest: 0x652c_502c_9161_9025,
        }
    }

    fn agent_snapshot() -> Agent {
        Agent {
            pid: 958,
            uid: Some(0),
            cgroup: Some("/system.slice/warden.service".to_string()),
            comm: Some(AGENT_COMM.to_string()),
            exe: Reading::Seen(ExeInfo {
                path: "/usr/local/sbin/warden".to_string(),
                deleted: false,
                same_file_as_self: true,
            }),
            cmdline: Reading::Seen("warden --config /etc/warden/warden.toml".to_string()),
            config_path: Some("/etc/warden/warden.toml".to_string()),
            sig_cgt: Reading::Seen(0x4003),
            age_secs: Reading::Seen(7200),
            start_epoch: Some(1_793_700_000),
            threads: Reading::Seen(vec![
                thread(958, "warden"),
                thread(959, "warden-deliver"),
                thread(960, "warden-heartbea"),
            ]),
            log_sink: Reading::Seen("socket:[12345]".to_string()),
            disk: Reading::Seen(ParseInfo {
                parses: true,
                mode: "Observe".to_string(),
                unread_keys: 0,
                bridge: true,
                heartbeat: true,
                error: String::new(),
            }),
            mtime_epoch: Some(1_793_699_000),
        }
    }

    fn snapshot_with(agent: Agent) -> Snapshot {
        let mut snap = blind_snapshot();
        snap.pick = Pick::One {
            agent: cand(agent.pid, Some("/system.slice/warden.service")),
            others: 0,
        };
        snap.agent = Some(agent);
        snap
    }

    fn find(lines: &[String], claim: &str) -> String {
        lines
            .iter()
            .find(|l| l.starts_with(&format!("warden: health: {claim}: ")))
            .unwrap_or_else(|| panic!("no line for {claim}: {lines:#?}"))
            .clone()
    }

    /// `CANNOT TELL` is one word in this tree, not one per command: the presence
    /// axis IS `doctor::State`'s, so a rename in either module moves both or fails
    /// here. A `--health` saying "UNKNOWN" where `--doctor` says `CANNOT TELL` would
    /// read to an operator as two different states of the same file.
    #[test]
    fn the_presence_words_are_the_doctors_words() {
        assert_eq!(Verdict::Present.word(), State::Present.word());
        assert_eq!(Verdict::Absent.word(), State::Absent.word());
        assert_eq!(Verdict::CannotTell.word(), State::Unreadable.word());
        assert_eq!(Verdict::Present.word(), "present");
        assert_eq!(Verdict::Absent.word(), "ABSENT");
        assert_eq!(Verdict::CannotTell.word(), "CANNOT TELL");
        for (state, want) in [
            (State::Present, Verdict::Present),
            (State::Absent, Verdict::Absent),
            (State::Unreadable, Verdict::CannotTell),
        ] {
            assert_eq!(Verdict::of_state(state), want);
        }
    }

    /// The mutation-proof version of the §23 step-1 incident for this command's own
    /// reads: an EACCES on a ptrace-gated link must never land in the ABSENT
    /// bucket, and both commands must classify the same errno identically.
    #[test]
    fn an_errno_classified_here_is_classified_identically_by_the_doctor() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
            io::ErrorKind::UnexpectedEof,
        ] {
            let err = io::Error::new(kind, "no");
            assert_eq!(
                Verdict::of_error(&err),
                Verdict::CannotTell,
                "{kind:?} must not read as absence"
            );
            assert_eq!(
                Verdict::of_error(&err),
                Verdict::of_state(State::from_open_error(&err)),
                "{kind:?} drifted between --doctor and --health"
            );
        }
        assert_eq!(
            Verdict::of_error(&io::Error::from(io::ErrorKind::NotFound)),
            Verdict::Absent
        );
        // The exact errno a live host gives for a root-owned agent's exe link.
        assert_eq!(
            Verdict::of_error(&io::Error::from_raw_os_error(libc::EACCES)),
            Verdict::CannotTell
        );
        assert_eq!(
            Verdict::of_error(&io::Error::from_raw_os_error(libc::EPERM)),
            Verdict::CannotTell
        );
        assert_eq!(
            Verdict::of_error(&io::Error::from_raw_os_error(libc::ESRCH)),
            Verdict::CannotTell,
            "only NotFound, the errno a path-based read gives, may be called ABSENT"
        );
        // The read layer itself, not just the classification: a missing path is the
        // only thing that may become `Absent`.
        assert!(matches!(
            read_proc_str("/definitely/not/here"),
            Reading::Absent
        ));
    }

    /// The `pgrep` trap (§24 step 6, which bit the worklog twice) as a unit test: a
    /// search for a name that matches the searcher. The exclusion is by PID, so it
    /// survives a renamed binary, a rewritten argv, and this command running twice
    /// at once.
    #[test]
    fn the_command_itself_is_never_the_agent_it_is_looking_for() {
        let me = 4242;
        // Both gates the real search applies, in its order: not this pid, then the
        // exact comm. A same-named entry that is us drops out on the first gate —
        // the searcher must never become the agent it is looking for — and a
        // substring match drops out on the second.
        let seen = [
            (me, "warden"),
            (958, "warden"),
            (12, "warden"),
            (7, "warden-doc"),
        ];
        let found: Vec<u32> = seen
            .iter()
            .filter(|(pid, comm)| *pid != me && matches_agent_name(Some(comm), None))
            .map(|(pid, _)| *pid)
            .collect();
        assert_eq!(
            found,
            vec![958, 12],
            "our own pid matched, or a substring was allowed: the searcher found itself"
        );

        // With only ourselves in /proc the answer is ABSENT, not a confident
        // "the agent is running".
        assert_eq!(pick(Vec::new(), true), Pick::None);
        let proc_line = find(&render(&blind_snapshot()), "process");
        assert!(proc_line.contains("ABSENT"), "{proc_line}");
        assert!(
            proc_line.contains("pid 4242"),
            "our own pid is not named as the reason for the absence: {proc_line}"
        );
    }

    /// The other half of the same trap: the match is an exact name, never a
    /// substring. `warden-doc` was the live incident; a path containing "warden" is
    /// the one waiting for the next author.
    #[test]
    fn the_match_is_an_exact_basename_and_not_a_substring() {
        assert!(matches_agent_name(Some("warden"), None));
        assert!(matches_agent_name(None, Some("/usr/local/sbin/warden")));
        assert!(matches_agent_name(None, Some("./target/debug/warden")));
        assert!(
            !matches_agent_name(Some("warden-doc"), None),
            "a substring match would have called this the agent"
        );
        assert!(!matches_agent_name(None, Some("/tmp/warden-doc-tmp")));
        assert!(!matches_agent_name(None, Some("/usr/bin/wardenx")));
        assert!(!matches_agent_name(Some("systemd"), None));
        assert!(!matches_agent_name(None, None));
        // A 15-char comm of a longer binary name is still not this name.
        assert!(!matches_agent_name(Some("warden-agent12345"), None));
    }

    /// A second `warden --health` (or `--check`) beside the daemon is counted and
    /// excluded; `--debug`, which the daemon itself takes, must not exclude it.
    #[test]
    fn a_same_named_process_running_a_print_and_return_mode_is_a_command() {
        let argv = |s: &[&str]| s.iter().map(|a| a.to_string()).collect::<Vec<String>>();
        assert!(is_a_command_not_the_agent(&argv(&[
            "warden",
            "--config",
            "/etc/warden/warden.toml",
            "--health"
        ])));
        assert!(is_a_command_not_the_agent(&argv(&["warden", "--check"])));
        assert!(is_a_command_not_the_agent(&argv(&[
            "warden",
            "--explain=exec"
        ])));
        assert!(is_a_command_not_the_agent(&argv(&["warden", "-h"])));
        assert!(
            !is_a_command_not_the_agent(&argv(&[
                "warden",
                "--config",
                "/etc/warden/warden.toml",
                "--debug"
            ])),
            "the daemon itself passes --debug; excluding it would hide the agent"
        );
        assert!(!is_a_command_not_the_agent(&argv(&["warden"])));
    }

    /// Two same-named processes with no tiebreaker is `CANNOT TELL`, not "pick the
    /// lowest pid": attaching one process's facts to another's identity is the
    /// failure this command exists to make impossible.
    #[test]
    fn an_ambiguous_search_reports_no_agent_rather_than_a_guess() {
        let two = pick(vec![cand(100, None), cand(200, None)], true);
        assert!(matches!(&two, Pick::Several(l) if l.len() == 2), "{two:?}");
        let with_unit = pick(
            vec![
                cand(100, Some("/system.slice/warden.service")),
                cand(200, Some("/user.slice/user-1000.slice")),
            ],
            true,
        );
        match with_unit {
            Pick::One { agent, others } => {
                assert_eq!(agent.pid, 100);
                assert_eq!(others, 1, "the other process is counted, not dropped");
            }
            other => panic!("expected the unit's cgroup to decide, got {other:?}"),
        }
        // Two under the unit (a restart racing its predecessor): no choice at all.
        assert!(matches!(
            pick(
                vec![
                    cand(100, Some("/system.slice/warden.service")),
                    cand(101, Some("/system.slice/warden.service")),
                ],
                true
            ),
            Pick::Several(_)
        ));
        // A /proc that could not be listed is Blind, never None.
        assert_eq!(pick(Vec::new(), false), Pick::Blind);

        let lines = render(&Snapshot {
            agent: None,
            pick: Pick::Several(vec![cand(1, None), cand(2, None)]),
            ..blind_snapshot()
        });
        let joined = lines.join("\n");
        assert!(joined.contains("candidate: PARTIAL — pid 1"), "{joined}");
        assert!(
            find(&lines, "process").contains("CANNOT TELL"),
            "an ambiguous search must not print a presence claim"
        );
        // And no per-agent line is printed at all, because there is no agent chosen.
        assert!(!joined.contains("health: identity:"));
        assert!(!joined.contains("health: threads:"));
    }

    /// The trap this module exists to not fall into: `warden-heartbeat` is 16
    /// characters and the kernel keeps 15, so the name a live heartbeat thread is
    /// visible under is NOT the name `src/heartbeat.rs` gave it. Compare the wrong
    /// string and a healthy thread is reported as missing.
    #[test]
    fn the_kernel_cuts_a_thread_name_and_the_expectation_knows_it() {
        assert_eq!(HEARTBEAT_THREAD.len(), 16, "the whole point of this test");
        assert_eq!(comm_visible(HEARTBEAT_THREAD), "warden-heartbea");
        assert_eq!(comm_visible(DELIVER_THREAD), "warden-deliver");
        assert_eq!(comm_visible(AGENT_COMM), "warden");
        assert_eq!(
            expected_threads(true, true),
            vec!["warden", "warden-deliver", "warden-heartbea"]
        );
        let seen = vec![
            thread(1, "warden"),
            thread(2, "warden-deliver"),
            thread(3, "warden-heartbea"),
        ];
        assert!(
            missing_threads(&expected_threads(true, true), &seen).is_empty(),
            "a live heartbeat thread was called missing: the truncation is real"
        );
        // The same list against the untruncated name — the bug — finds a gap. Stated
        // as a test because the bug is a one-character edit to the expectation.
        let naive = vec![
            comm_visible(AGENT_COMM),
            DELIVER_THREAD.to_string(),
            HEARTBEAT_THREAD.to_string(),
        ];
        assert_eq!(missing_threads(&naive, &seen), vec![HEARTBEAT_THREAD]);

        // The assumption itself, read from the live kernel instead of from memory: a
        // thread spawned with the 16-character name appears in /proc/self/task under
        // its 15-character form. If std or the kernel ever changes this, the
        // expectation above becomes wrong and this line says so.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name(HEARTBEAT_THREAD.to_string())
            .spawn(move || {
                // SAFETY: SYS_gettid takes no arguments and returns the calling
                // thread's kernel id.
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
                let comm = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm"))
                    .unwrap_or_default()
                    .trim_end()
                    .to_string();
                let _ = tx.send(comm);
            })
            .expect("spawning a named thread in a test");
        assert_eq!(
            rx.recv().expect("the thread reported its own comm"),
            comm_visible(HEARTBEAT_THREAD),
            "the kernel stopped truncating comm, or std stopped applying the thread name before \
             the closure runs: either way the expectation is now wrong"
        );
    }

    /// A thread the file asks for and /proc does not show is only `DEGRADED` when
    /// the file predates the process; otherwise the agent may have started before
    /// that section existed — and SIGHUP could not create the thread anyway.
    #[test]
    fn a_missing_thread_is_a_gap_only_when_the_file_cannot_be_blamed() {
        assert_eq!(
            thread_gap_verdict(Some(true)),
            Verdict::Degraded,
            "the file is as old as the process, so the thread really should be there"
        );
        assert_eq!(
            thread_gap_verdict(Some(false)),
            Verdict::CannotTell,
            "a newer file cannot be blamed on a dead thread: the section may have arrived after \
             start"
        );
        assert_eq!(thread_gap_verdict(None), Verdict::CannotTell);
    }

    #[test]
    fn the_thread_expectation_follows_the_file_not_a_wish() {
        assert_eq!(expected_threads(false, false), vec!["warden"]);
        assert_eq!(
            missing_threads(
                &expected_threads(true, false),
                &[thread(1, "warden"), thread(2, "warden-heartbea")]
            ),
            vec!["warden-deliver"],
            "the bridge thread is expected because the FILE has a [bridge], and a stray \
             heartbeat thread must not satisfy it"
        );
        assert_eq!(
            missing_threads(&expected_threads(false, false), &[thread(1, "warden")]),
            Vec::<String>::new()
        );
    }

    /// `comm` is a name a process chooses and `argv[0]` a name a caller chooses; the
    /// exe link is the only one of the three the kernel enforces. W2K-18's loader
    /// lesson, applied to the process being searched for.
    #[test]
    fn a_name_match_is_an_introduction_and_only_the_exe_link_is_an_identity() {
        assert_eq!(
            identity_verdict(&Reading::Blind(
                "/proc/958/exe: Permission denied".to_string()
            )),
            Verdict::Partial,
            "an unreadable exe must never let the line read as VERIFIED"
        );
        assert_eq!(
            identity_verdict(&Reading::Seen(ExeInfo {
                path: "/usr/local/sbin/warden".to_string(),
                deleted: false,
                same_file_as_self: true,
            })),
            Verdict::Verified
        );
        assert_eq!(
            identity_verdict(&Reading::Seen(ExeInfo {
                path: "/usr/local/sbin/warden".to_string(),
                deleted: true,
                same_file_as_self: false,
            })),
            Verdict::Degraded,
            "a deleted image is not a clean match: the file now at that path was never executed"
        );
        assert_eq!(identity_verdict(&Reading::Absent), Verdict::Absent);
    }

    #[test]
    fn the_sighup_bit_is_read_from_the_mask_and_not_from_a_name() {
        // The mask a running agent really has: SIGHUP (1), SIGINT (2), SIGTERM (15).
        let status = "Name:\twarden\nUmask:\t0077\nSigCgt:\t0000000180004003\nSigBlk:\t0\n";
        assert_eq!(parse_sig_cgt(status), Some(0x1_8000_4003));
        assert!(sighup_armed(parse_sig_cgt(status).unwrap()));
        assert!(sighup_armed(1));
        assert!(
            !sighup_armed(0x4ec),
            "bit 0 clear means no SIGHUP handler — and 0x4ec is pid 1's real mask on this host, \
             so a common mask genuinely is not armed for the reload signal"
        );
        assert_eq!(parse_sig_cgt("SigCgt:\tnot-a-hex\n"), None);
        assert_eq!(parse_sig_cgt("Name:\twarden\n"), None);
    }

    #[test]
    fn the_config_path_is_the_agents_own_and_last_wins_as_in_the_parser() {
        let argv = |s: &[&str]| s.iter().map(|a| a.to_string()).collect::<Vec<String>>();
        assert_eq!(
            config_path_from_argv(&argv(&["warden", "--config", "/etc/warden/w.toml"])),
            Some("/etc/warden/w.toml")
        );
        assert_eq!(
            config_path_from_argv(&argv(&["warden", "-c", "/tmp/x.toml", "--debug"])),
            Some("/tmp/x.toml"),
            "the short form is what an ExecStart could have used"
        );
        assert_eq!(
            config_path_from_argv(&argv(&["warden", "-c", "/old", "--config", "/new"])),
            Some("/new"),
            "main.rs overwrites on every occurrence, so the last one is the live policy"
        );
        assert_eq!(config_path_from_argv(&argv(&["warden", "--debug"])), None);
        assert_eq!(config_path_from_argv(&argv(&["warden", "--config"])), None);
    }

    /// `Config::load`'s two failure shapes must not collapse: a file that is not
    /// there is `ABSENT` and says nothing about syntax, and a file that is there and
    /// does not parse is `Seen` with a parse error — a statement about the file
    /// rather than about the operator's permissions. (The third shape, EACCES, is
    /// `reading_from`'s and is pinned by the errno test above.)
    #[test]
    fn a_missing_file_is_not_an_unparsable_one() {
        assert!(
            matches!(
                read_disk_config("/proc/self/nope/cannot-open.toml"),
                Reading::Absent
            ),
            "a failed read must not become a parse failure"
        );
        let dir = std::env::temp_dir().join(format!("warden-health-parse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "mode = 12\n[[protect.targets]]\nx = [\n").unwrap();
        match read_disk_config(bad.to_str().unwrap()) {
            Reading::Seen(info) => {
                assert!(!info.parses, "a broken file was read as fine");
                assert!(!info.error.is_empty());
            }
            other => panic!("a file that exists and does not parse is Seen-and-broken: {other:?}"),
        }
        // A valid config parses, and the two thread-asking sections come back as the
        // file has them rather than as defaults.
        let good = dir.join("good.toml");
        std::fs::write(
            &good,
            "mode = \"observe\"\n[bridge]\nurl = \"http://127.0.0.1:9/x\"\napi_key = \"k\"\n",
        )
        .unwrap();
        match read_disk_config(good.to_str().unwrap()) {
            Reading::Seen(info) => {
                assert!(info.parses, "{}", info.error);
                assert!(info.bridge && !info.heartbeat, "{info:?}");
            }
            other => panic!("the good file should have parsed: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_freshness_word_moves_only_with_the_two_timestamps_it_has() {
        assert_eq!(
            freshness_verdict(Some(false), true).0,
            Verdict::Verified,
            "a file older than the process is the text it started with"
        );
        let (v, note) = freshness_verdict(Some(true), true);
        assert_eq!(v, Verdict::Partial);
        assert!(
            note.contains("restart-required"),
            "the newer-file note must name [bridge]/[heartbeat]/ring, because SIGHUP applies \
             part of the file and never all of it: {note}"
        );
        assert_eq!(freshness_verdict(None, true).0, Verdict::CannotTell);
        assert_eq!(freshness_verdict(Some(false), false).0, Verdict::Degraded);
    }

    #[test]
    fn the_log_sink_names_a_journal_only_after_seeing_a_pipe() {
        assert_eq!(log_sink_verdict(Some("/dev/null")).0, Verdict::Degraded);
        assert_eq!(log_sink_verdict(Some("pipe:[99]")).0, Verdict::Partial);
        assert_eq!(log_sink_verdict(Some("socket:[12]")).0, Verdict::Partial);
        assert_eq!(log_sink_verdict(Some("/var/log/w.out")).0, Verdict::Partial);
        let (v, why) = log_sink_verdict(None);
        assert_eq!(v, Verdict::CannotTell);
        assert!(
            why.contains("0700"),
            "the reason must be the gate rather than a guess: {why}"
        );
    }

    /// The invariant of the whole command: one line per claim, one prefix, one
    /// status word, no embedded newlines. If the renderer ever wraps a claim or
    /// invents a fourth word, `--doctor`'s diff-ability dies with it.
    #[test]
    fn every_line_is_one_prefixed_claim_with_one_status_word() {
        let words = [
            "present",
            "ABSENT",
            "CANNOT TELL",
            "VERIFIED",
            "PARTIAL",
            "DEGRADED",
            "UNAVAILABLE",
            "UNSUPPORTED",
            "UNVERIFIED",
        ];
        let snaps = [
            blind_snapshot(),
            snapshot_with(agent_snapshot()),
            Snapshot {
                agent: None,
                pick: Pick::Blind,
                proc_walkable: false,
                ..blind_snapshot()
            },
            Snapshot {
                agent: None,
                pick: Pick::Several(vec![cand(1, None), cand(2, None)]),
                ..blind_snapshot()
            },
        ];
        for snap in snaps {
            let lines = render(&snap);
            assert!(!lines.is_empty());
            for l in &lines {
                assert!(l.starts_with("warden: health: "), "bad prefix: {l}");
                assert!(!l.contains('\n'), "a claim must stay one line: {l}");
                let body = &l["warden: health: ".len()..];
                // `<claim>: <WORD> — <detail>`: the claim may contain spaces but never
                // a colon, so the first `": "` is the claim boundary and the first
                // `" — "` closes the status word.
                let (_, rest) = body
                    .split_once(": ")
                    .unwrap_or_else(|| panic!("no status word in: {l}"));
                let (word, detail) = rest
                    .split_once(" — ")
                    .unwrap_or_else(|| panic!("no detail separator: {l}"));
                assert!(
                    words.contains(&word),
                    "unknown status word {word:?} (claim {:?}) in: {l}",
                    body.split_once(": ").map(|(c, _)| c)
                );
                assert!(!detail.is_empty(), "a claim with no reason: {l}");
                assert!(
                    !body[..body.find(": ").unwrap()].contains(':'),
                    "the claim name itself must hold no colon: {l}"
                );
            }
        }
    }

    /// §5 of the blueprint / §15 of the worklog: declare incomplete coverage. The
    /// `cannot see/` block is the reason the counters above can be trusted, so
    /// deleting one of its lines has to fail a test rather than a reader.
    #[test]
    fn the_cannot_see_section_is_always_printed_and_names_every_live_source() {
        for snap in [blind_snapshot(), snapshot_with(agent_snapshot())] {
            let lines = render(&snap);
            let unseen: Vec<&String> = lines
                .iter()
                .filter(|l| l.contains("health: cannot see/"))
                .collect();
            assert!(
                unseen.len() >= 7,
                "the cannot-see section shrank to {}: a health report without it is a claim of \
                 completeness this build cannot make",
                unseen.len()
            );
            let joined = unseen
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            for needed in [
                "attached programs",
                "ring buffer",
                "volume totals",
                "protected pid set",
                "the policy in the agent's memory",
                "what the agent logged",
                "the unit's own state",
                "another uid's process",
                "sockets outside",
            ] {
                assert!(joined.contains(needed), "cannot see/{needed} disappeared");
            }
            // Every one of them is a non-claim by label, never a reassuring count.
            for l in &unseen {
                assert!(
                    l.contains("UNVERIFIED")
                        || l.contains("UNSUPPORTED")
                        || l.contains("UNAVAILABLE"),
                    "a cannot-see line that states evidence: {l}"
                );
            }
            // And the mechanism is named, not just the word: the reader is told which
            // syscall or privilege would be needed.
            let attach = unseen
                .iter()
                .find(|l| l.contains("cannot see/attached programs"))
                .expect("the attach claim must be declared non-made");
            assert!(attach.contains("bpf()"), "{attach}");
            assert!(attach.contains("CAP_BPF"), "{attach}");
        }
    }

    /// The claim this command must never make: that a hook is attached or a counter
    /// was read. Grep-level insurance against a future line sneaking a map read in
    /// through a side door.
    #[test]
    fn no_line_ever_claims_a_hook_attached_or_a_counter_read() {
        for snap in [blind_snapshot(), snapshot_with(agent_snapshot())] {
            for l in render(&snap) {
                if l.contains("attach") {
                    assert!(
                        l.contains("UNVERIFIED")
                            || l.contains("cannot see/")
                            || l.contains("nothing attached")
                            || l.contains("does NOT do")
                            || l.contains("not the one a running agent loaded"),
                        "an attach claim that is not a declared non-claim: {l}"
                    );
                }
                for forbidden in [
                    "hooks attached",
                    "events received",
                    "findings raised: ",
                    "dropped since start",
                    "bumps",
                ] {
                    // The live-counter phrases. A line may mention one only while
                    // declaring that it does NOT measure it — i.e. inside a
                    // `cannot see/` non-claim — never as a measurement.
                    if l.contains(forbidden) {
                        assert!(
                            l.contains("cannot see/"),
                            "a live-counter phrase appeared as a measurement: {l}"
                        );
                    }
                }
            }
        }
    }

    /// The footer is the reader's map of the four commands, so it must name all of
    /// them and all of their privileges- refused. Deleting a command from it — or
    /// turning the cap-less promise into a boast — has to fail here rather than
    /// mislead somebody on a live host.
    #[test]
    fn the_footer_names_every_command_and_every_privilege_this_one_refused() {
        let line = find(&render(&blind_snapshot()), "what this did NOT do");
        // The first phrase is capitalized because it opens the footer's sentence;
        // the rest are mid-sentence, exactly as rendered.
        for needed in [
            "--check",
            "--doctor",
            "--explain",
            "--health",
            "--version",
            "No `bpf()` syscall",
            "no map opened",
            "nothing attached",
            "no capability",
            "no signal sent",
            "no file written",
            "no subprocess spawned",
        ] {
            assert!(line.contains(needed), "the footer lost {needed:?}: {line}");
        }
        // `VERIFIED`, because every item in it is about this process's own code path
        // and nothing else — the one line in the report that can be that sure.
        assert!(line.contains("VERIFIED"), "{line}");
        assert!(line.contains("measures detection"), "{line}");
    }

    /// The build line's own limit, stated where an operator reads it: the digest is
    /// THIS binary's, and the running agent's object is the thing this command
    /// cannot see. Reuses `loader::obj_fingerprint()` rather than recomputing it, so
    /// there is exactly one implementation of the digest in the tree.
    #[test]
    fn the_build_line_names_the_digest_it_actually_has_and_its_limit() {
        let line = find(&render(&blind_snapshot()), "build");
        assert!(
            line.contains(&format!("fnv-1a {:016x}", obj_fingerprint())),
            "the digest printed is not loader::obj_fingerprint()'s: {line}"
        );
        assert!(line.contains(&obj_len().to_string()), "{line}");
        assert!(
            line.contains("not the one a running agent loaded"),
            "{line}"
        );
        assert!(line.contains("/usr/local/sbin/warden"), "{line}");
        assert!(line.contains("VERIFIED"), "{line}");
    }

    /// A healthy agent must be described without a single false gap — including the
    /// one the truncated thread name would otherwise create.
    #[test]
    fn a_healthy_agent_is_described_without_a_single_false_gap() {
        let lines = render(&snapshot_with(agent_snapshot()));
        let joined = lines.join("\n");
        let threads = find(&lines, "threads");
        assert!(
            threads.contains("present"),
            "a complete thread set must not read as a gap: {threads}"
        );
        assert!(
            !joined.contains("NOT SEEN"),
            "the healthy shape reported a missing thread: {joined}"
        );
        assert!(
            threads.contains("Expected from the config file read now"),
            "with a readable config the expectation's source is that file, not a default: {threads}"
        );
        assert!(
            !threads.contains("THIS BUILD'S MINIMUM"),
            "a read file must not be described as an unreadable one: {threads}"
        );
        assert!(threads.contains("warden-heartbea"), "{threads}");
        assert!(joined.contains("pid 958"));
        assert!(joined.contains("/etc/warden/warden.toml"));
        assert!(joined.contains("control: VERIFIED"), "{joined}");
        assert!(joined.contains("age: VERIFIED"), "{joined}");
    }

    /// The live-host shape: the agent is root's, so its exe link, its fd table and
    /// its config file are all gated. Everything that would have been a counters
    /// list becomes `CANNOT TELL`, and the identity claim drops to `PARTIAL` — the
    /// exact output the deployment host produces for an ordinary user.
    #[test]
    fn a_root_owned_agent_seen_by_an_ordinary_user_says_what_it_cannot_see() {
        let mut ag = agent_snapshot();
        ag.exe = Reading::Blind("/proc/958/exe: Permission denied (os error 13)".to_string());
        ag.log_sink = Reading::Blind("/proc/958/fd/2: Permission denied (os error 13)".to_string());
        ag.disk = Reading::Blind(
            "reading config /etc/warden/warden.toml: Permission denied (os error 13)".to_string(),
        );
        ag.threads = Reading::Seen(vec![thread(958, "warden")]);
        ag.mtime_epoch = None;
        let joined = render(&snapshot_with(ag)).join("\n");
        assert!(joined.contains("identity: PARTIAL"), "{joined}");
        assert!(joined.contains("Permission denied"));
        assert!(
            joined.contains("log sink: CANNOT TELL"),
            "an unreadable fd table cannot read as a working journal stream"
        );
        assert!(joined.contains("config/parse: CANNOT TELL"), "{joined}");
        assert!(!joined.contains("identity: VERIFIED"), "{joined}");
        // With no readable file the heartbeat thread is not expected, so a missing
        // thread is not invented out of a default — and the expectation itself is
        // declared Partial.
        assert!(
            joined.contains("threads: PARTIAL"),
            "an expectation inferred from an unreadable file must not read as complete: {joined}"
        );
        assert!(!joined.contains("NOT SEEN"), "{joined}");
        // The expectation's source is named honestly: with no readable config file
        // the thread list is THIS BUILD's minimum, and a line that said "expected
        // from the config file read now" would be pointing at a file it never saw.
        assert!(
            joined.contains("THIS BUILD'S MINIMUM"),
            "an expectation with no file behind it must name its real source: {joined}"
        );
        assert!(
            !joined.contains("Expected from the config file read now"),
            "the thread list claimed an expectation source it did not have: {joined}"
        );
        // A freshness line would compare the file's mtime with the start time, and the
        // file could not be read at all: the comparison has no left-hand side, so the
        // line must not exist rather than exist as a CANNOT TELL.
        assert!(
            !joined.contains("config/freshness"),
            "a freshness claim printed from an unreadable file: {joined}"
        );
    }

    #[test]
    fn a_deleted_image_is_called_a_replaced_one_and_not_a_match() {
        let mut ag = agent_snapshot();
        ag.exe = Reading::Seen(ExeInfo {
            path: "/usr/local/sbin/warden".to_string(),
            deleted: true,
            same_file_as_self: false,
        });
        let line = find(&render(&snapshot_with(ag)), "identity");
        assert!(line.contains("DEGRADED"), "{line}");
        assert!(line.contains("(deleted)"), "{line}");
        assert!(
            line.contains("NOT the bytes this agent is running"),
            "the whole point of the suffix: {line}"
        );
    }

    #[test]
    fn a_process_with_no_handler_for_the_reload_signal_is_degraded() {
        let mut ag = agent_snapshot();
        // pid 1's real mask: several handlers, and none of them SIGHUP.
        ag.sig_cgt = Reading::Seen(0x4ec);
        let line = find(&render(&snapshot_with(ag.clone())), "control");
        assert!(line.contains("DEGRADED"), "{line}");
        assert!(line.contains("NO SIGHUP handler"), "{line}");

        ag.sig_cgt = Reading::Seen(0x1_8000_4003);
        let line = find(&render(&snapshot_with(ag)), "control");
        assert!(line.contains("VERIFIED"), "{line}");
        assert!(line.contains("UNVERIFIED"), "{line}");
        assert!(line.contains("leaves no trace"), "{line}");
    }

    #[test]
    fn an_unreadable_status_is_cannot_tell_about_the_control_path() {
        let mut ag = agent_snapshot();
        ag.sig_cgt = Reading::Blind("/proc/958/status: Permission denied".to_string());
        let line = find(&render(&snapshot_with(ag)), "control");
        assert!(line.contains("CANNOT TELL"), "{line}");
        assert!(
            line.contains("not the same as it being broken"),
            "an unreadable mask must not read as a missing handler: {line}"
        );
    }

    #[test]
    fn an_agent_started_without_a_config_file_is_a_posture_nobody_configured() {
        let mut ag = agent_snapshot();
        ag.config_path = None;
        ag.disk = Reading::Absent;
        ag.mtime_epoch = None;
        let lines = render(&snapshot_with(ag));
        let line = find(&lines, "config/path");
        assert!(line.contains("DEGRADED"), "{line}");
        assert!(line.contains("safe_default"), "{line}");
        // Nothing downstream may claim the file is what the agent runs.
        let joined = lines.join("\n");
        assert!(!joined.contains("config/parse: VERIFIED"), "{joined}");
        assert!(!joined.contains("config/freshness"), "{joined}");
    }

    /// `--config` beside `--health`: the operator's own path is named in the output
    /// or the flag is dropped in silence — W2K-23's failure mode moved into the CLI.
    #[test]
    fn a_config_flag_given_to_this_command_is_named_and_never_used() {
        let mut snap = snapshot_with(agent_snapshot());
        snap.operator_config = Some("/tmp/other.toml".to_string());
        let joined = render(&snap).join("\n");
        assert!(joined.contains("/tmp/other.toml"), "{joined}");
        assert!(
            joined.contains("is NOT used"),
            "the flag would have been dropped in silence: {joined}"
        );
        // Same command line, same path as the agent's: no false alarm.
        snap.operator_config = Some("/etc/warden/warden.toml".to_string());
        let joined = render(&snap).join("\n");
        assert!(!joined.contains("is NOT used"), "{joined}");
    }

    /// The real `/proc` of whatever host runs the tests: the report must be
    /// well-formed whatever it finds, must name its own pid, and must never describe
    /// the test binary itself as the agent.
    #[test]
    fn reading_the_live_proc_of_the_test_host_produces_a_wellformed_report() {
        let snap = gather(None);
        assert_eq!(snap.self_pid, std::process::id());
        let lines = render(&snap);
        assert!(lines.iter().all(|l| l.starts_with("warden: health: ")));
        assert!(lines.iter().all(|l| !l.contains('\n')));
        assert!(lines.iter().any(|l| l.contains("what this did NOT do")));
        assert!(
            lines
                .iter()
                .filter(|l| l.contains("health: cannot see/"))
                .count()
                >= 7
        );
        if let Pick::One { agent, .. } = &snap.pick {
            // An agent really is running here: the lines must be about THAT pid, and
            // it cannot be us.
            assert_ne!(agent.pid, snap.self_pid, "the searcher found itself");
            let joined = lines.join("\n");
            assert!(joined.contains(&format!("pid {}", agent.pid)));
            assert!(joined.contains("identity:"));
        } else {
            assert!(
                lines
                    .iter()
                    .any(|l| l.starts_with("warden: health: process:")),
                "no agent, and no line saying so"
            );
        }
    }

    /// Every fixture thread in this file is `'S'`, so the arm that calls a parked
    /// thread a degraded control path (`blocked()`, and the `DEGRADED` it maps to)
    /// had no test at all: a renderer that stopped treating `D`/`Z`/`T` as a
    /// problem would have stayed green.
    #[test]
    fn a_thread_parked_in_an_uninterruptible_state_degrades_the_thread_claim() {
        let mut ag = agent_snapshot();
        ag.threads = Reading::Seen(vec![
            Thread {
                tid: 958,
                comm: "warden".to_string(),
                state: 'S',
            },
            Thread {
                tid: 959,
                comm: "warden-deliver".to_string(),
                state: 'D',
            },
            Thread {
                tid: 960,
                comm: "warden-heartbea".to_string(),
                state: 'S',
            },
        ]);
        let lines = render(&snapshot_with(ag));
        let threads = find(&lines, "threads");
        assert!(
            threads.starts_with("warden: health: threads: DEGRADED — "),
            "a thread stuck in `D` must not read as a healthy thread set: {threads}"
        );
        assert!(
            threads.contains("tid 959 warden-deliver/D"),
            "the degraded line must name which thread it is blaming: {threads}"
        );
        // Nothing is missing here, so the gap wording belongs to a different claim:
        // conflating them would make a wedged agent look like a half-started one.
        assert!(!threads.contains("NOT SEEN"), "{threads}");
    }

    /// The shape an ordinary user gets on a host with `hidepid=` or a `proc` this
    /// command cannot list: no agent is described, and the whole answer is the one
    /// `visibility` line. Test 2057 renders this snapshot but only checks prefixes,
    /// so the line's own claim — and the silence it has to keep — were unpinned.
    #[test]
    fn a_host_whose_proc_cannot_be_listed_announces_its_own_blindness() {
        let snap = Snapshot {
            agent: None,
            pick: Pick::Blind,
            proc_walkable: false,
            ..blind_snapshot()
        };
        let lines = render(&snap);
        let visibility = find(&lines, "visibility");
        assert!(
            visibility.starts_with("warden: health: visibility: UNAVAILABLE — "),
            "blindness must be declared as its own claim: {visibility}"
        );
        assert!(
            visibility.contains("could not list /proc at all"),
            "the line must say which source failed, not just that it is unavailable: {visibility}"
        );
        // Blindness is not an all-clear: the block that lists what cannot be seen,
        // and the footer that lists what this command refused to do, still have to
        // carry the report.
        assert!(
            lines
                .iter()
                .filter(|l| l.contains("health: cannot see/"))
                .count()
                >= 7,
            "{lines:#?}"
        );
        assert!(lines.iter().any(|l| l.contains("what this did NOT do")));
        // And no per-process claim may appear: with nothing read, describing a
        // process would be a fabrication.
        for claim in ["identity:", "threads:", "config/path:", "age:"] {
            assert!(
                !lines
                    .iter()
                    .any(|l| l.starts_with(&format!("warden: health: {claim}"))),
                "the blind path rendered a per-process claim: {claim} in {lines:#?}"
            );
        }
    }

    /// `main.rs` prints whatever `report()` returns, so the prefix invariant is a
    /// property of the composition, not only of `render`. Nothing called this
    /// function before: a wrapper that dropped the renderer's lines, or added an
    /// unprefixed one of its own, was invisible to the suite.
    #[test]
    fn the_entry_point_returns_the_same_prefixed_lines_as_the_renderer() {
        let lines = report(None::<&std::path::PathBuf>);
        assert!(
            lines.iter().all(|l| l.starts_with("warden: health: ")),
            "{lines:#?}"
        );
        assert!(lines.iter().any(|l| l.contains("what this did NOT do")));
        // A config path the operator names is still this command's own report: it
        // must not become an error page or a partial line set.
        let with_path = report(Some(&std::path::PathBuf::from("/nonexistent/warden.toml")));
        assert!(with_path.iter().all(|l| l.starts_with("warden: health: ")));
        assert!(with_path.iter().any(|l| l.contains("cannot see/")));
    }

    #[test]
    fn parse_line_splits_the_fixed_grammar_once() {
        let (claim, status, detail) = parse_line(
            "warden: health: config/parse: VERIFIED — mode Observe, 0 unread keys: note",
        )
        .expect("parse");
        assert_eq!(claim, "config/parse");
        assert_eq!(status, "VERIFIED");
        assert_eq!(detail, "mode Observe, 0 unread keys: note");
        // A colon inside the detail stays in the detail; only the first `: `
        // after the prefix separates the claim.
        let (claim, _, detail) =
            parse_line("warden: health: build: VERIFIED — warden 0.1.0: key: value").unwrap();
        assert_eq!(claim, "build");
        assert_eq!(detail, "warden 0.1.0: key: value");
        assert!(parse_line("not a health line").is_none());
    }

    #[test]
    fn redact_secrets_masks_an_api_key_value_but_keeps_the_key_name() {
        let line =
            "parsing config /etc/warden/warden.toml: api_key = \"top-secret-value\" at line 4";
        let redacted = redact_secrets(line);
        assert!(!redacted.contains("top-secret-value"), "{redacted}");
        assert!(redacted.contains("[REDACTED]"), "{redacted}");
        assert!(
            redacted.contains("api_key"),
            "the key NAME is useful evidence: {redacted}"
        );
        // No assignment -> no value to hide; the token itself is safe.
        assert_eq!(redact_secrets("api_key mentioned"), "api_key mentioned");
    }

    #[test]
    fn json_is_derived_from_the_text_and_keeps_every_unverified_claim() {
        // One gather, one render. `report()` walks live /proc, and a thread's
        // state can flip between two calls (R -> S while this test is running),
        // so calling `report_json()` here — which gathers again — would compare
        // two different instants and fail for reasons unrelated to the mapping.
        let lines = report(None::<&std::path::PathBuf>);
        let json = json_from_lines(&lines);
        assert_eq!(json["schema"], "warden.health.v1");
        assert_eq!(
            json["totals"]["claims"].as_u64().unwrap(),
            lines.len() as u64
        );
        assert_eq!(json["claims"].as_array().unwrap().len(), lines.len());

        // Every rendered line maps to exactly one JSON claim with the same
        // claim name, evidence word and detail — including `cannot see/` lines.
        for (line, obj) in lines.iter().zip(json["claims"].as_array().unwrap()) {
            let (claim, status, detail) = parse_line(line).unwrap();
            assert_eq!(obj["claim"], claim, "{line}");
            assert_eq!(obj["status"], status, "{line}");
            assert_eq!(obj["detail"], redact_secrets(detail), "{line}");
        }
        let cannot_see = json["claims"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["claim"].as_str().unwrap().starts_with("cannot see/"))
            .count();
        assert!(cannot_see > 0, "the machine view must keep the blind spots");
        assert!(json["totals"]["by_status"].get("UNVERIFIED").is_some());

        // Phase 1: a single structured trust state accompanies the claims.
        // This cap-less command can never see live maps, so it can never say
        // HEALTHY — and its ring-loss measurement carries no fabricated zero.
        assert_eq!(json["telemetry"]["ring_loss"]["status"], "UNKNOWN");
        assert!(json["telemetry"]["ring_loss"]["drops"].is_null());
        assert_ne!(json["telemetry"]["state"], "HEALTHY");

        // A snapshot with a real agent has more claims; the totals follow.
        let snap = snapshot_with(agent_snapshot());
        let snap_lines = render(&snap);
        let snap_json = json_from_lines(&snap_lines);
        assert_eq!(
            snap_json["totals"]["claims"].as_u64().unwrap(),
            snap_lines.len() as u64
        );
    }
}
