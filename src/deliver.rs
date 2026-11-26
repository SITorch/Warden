//! deliver.rs — durable delivery of findings to Sentinel (W-05).
//!
//! W-05: the bridge recorded a delivery failure and then dropped the finding.
//! A transient Sentinel outage, a DNS hiccup or one 503 meant the event was
//! never stored, and the local log did not hold it either — `main.rs` logs
//! severity/type/summary/action, not the envelope. The platform's record of what
//! Warden saw therefore had holes in exactly the moments an operator cares about
//! most, and nothing anywhere said so.
//!
//! This module is the answer to that, and it is three things at once, because
//! doing any one of them alone makes the others worse:
//!
//! 1. **The network is off the drain path** (W-R6). Sending used to happen
//!    inline, in the loop that drains the ring buffer: a slow resolver or a
//!    trickle response stalled the consumer, and the ring overflowed, and those
//!    events were lost through W-02's gap. Retrying inline would have made that
//!    strictly worse, so the delivery attempt moved to its own thread. The drain
//!    path never touches the network. It is a non-blocking hand-off *on the
//!    healthy path*; when the in-memory queue is full it appends the record to
//!    the spool synchronously, including `fsync`, so during a long outage with a
//!    full queue the event loop can be delayed by disk I/O. That is deliberate —
//!    durability is the floor, and an unbounded in-memory queue would turn an
//!    outage into an OOM — but it is a real latency cost: size `queue_max`, the
//!    ring buffer, and the spool's disk for the burst you expect to absorb.
//!
//! 2. **A bounded queue with retry and backoff.** Findings wait in memory for
//!    the sender; a failure that looks transient (timeout, DNS, 5xx, 429) puts
//!    the record on disk and starts a doubling backoff, so a dead endpoint is
//!    not hammered and a recovered one is noticed within `max_backoff_ms`.
//!
//! 3. **A bounded append-only spool**, mode 0600, that survives a restart of
//!    Warden. When the outage ends the backlog is delivered in order, oldest
//!    first. The cap is the one place a finding is still deliberately dropped,
//!    and it is noisy when it happens: an unbounded file on the host's root
//!    filesystem would turn a Sentinel outage into a host outage.
//!
//! Idempotency is the fourth piece and it lives on both sides of the wire: each
//! record is stamped with an `event_id` once, at enqueue, and carried through
//! every retry unchanged. A retry is therefore byte-identical, and a redelivery
//! after a timeout — where Sentinel stored the row but its 200 never arrived —
//! is recognisable by the far side rather than becoming a second row.
//! `<parent-project>/sentinel/` dedupes on that id.
//!
//! What is still NOT durable, stated plainly so nobody infers it: a finding that
//! has been enqueued but not yet written to the spool lives in memory, and a
//! SIGKILL or a power cut loses it. Graceful shutdown, and the transition into
//! backoff, both flush the queue to disk first; only a violent death skips that.
//! Closing it entirely would mean writing every finding to disk before sending
//! it, which trades a bounded, reported loss for unbounded disk I/O on the
//! healthy path.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;

use crate::bridge::{self, BridgeClient, Outcome, Record, RejectedRecord};
use crate::config::Bridge;
use crate::detect::{Finding, FindingType, ProcessInfo, Severity};
use crate::respond::Action;
use crate::telemetry::{SensorHealth, TelemetryReport};

/// How long the sender is willing to sleep before re-checking the stop flag.
/// Also the shutdown latency bound, together with one delivery attempt.
const TICK: Duration = Duration::from_millis(200);

/// Findings sent in one HTTP request. Sentinel's host-ingest validates and
/// accepts up to MAX_FINDINGS_PER_BATCH (64) per request, so this is that limit,
/// not an independent tuning knob. Sending one finding per request is what let a
/// full spool starve: even a healthy endpoint answers a few requests a second,
/// which is slower than an endpoint storm produces findings.
const BATCH_MAX: usize = 64;

/// The drop log is rate-limited to one line per this many losses. A full spool
/// during a long outage would otherwise produce one journal line per finding,
/// and the journal is where the operator looks for the *other* problems.
const DROP_LOG_EVERY: u64 = 100;

/// The event id is stamped into every envelope and Sentinel stores it in a
/// 128-char column, so the host label is clipped rather than allowed to push the
/// id past the cap and turn a durable finding into a 400 — which is permanent,
/// which means dropped.
const MAX_HOST_IN_ID: usize = 64;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned mutex means some thread panicked while holding it. Findings are
    // worth more than the panic: the spool on disk is still consistent (every
    // write is a single append + fsync, and compaction is a rename), so the
    // guard is taken anyway rather than propagating a panic into the sender and
    // silencing the uplink for the rest of the process's life.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Delivery counters. Atomics rather than a mutex so both threads can update
/// them without ever contending on a lock, and so `stats()` can be called from
/// the event loop without blocking.
#[derive(Default)]
struct Counters {
    /// Every finding handed to `enqueue` — the denominator for loss.
    produced: AtomicU64,
    /// Accepted into the in-memory channel.
    queued: AtomicU64,
    /// Removed from the channel by the sender.
    taken: AtomicU64,
    /// Delivered on the first attempt.
    delivered: AtomicU64,
    /// Delivered out of the spool after being buffered.
    replayed: AtomicU64,
    /// Attempts that failed in a way a retry can fix.
    transient: AtomicU64,
    /// Attempts Sentinel refused in a way a retry cannot fix.
    permanent: AtomicU64,
    /// Batches where Sentinel named individual bad findings: the bad ones
    /// went to the dead-letter file, the rest were retried instead of lost.
    isolated: AtomicU64,
    /// Findings written to the 0600 dead-letter file. They are not lost — they
    /// are awaiting an operator fix + replay — so they are counted apart from
    /// `permanent` and `dropped`.
    quarantined: AtomicU64,
    /// Written durably to the spool.
    spooled: AtomicU64,
    /// LOST. Full spool, failed spool write, unserializable finding, or a dead
    /// sender thread. Every one of these is logged when it happens.
    dropped: AtomicU64,
    /// Gauges.
    pending_on_disk: AtomicU64,
    spool_bytes: AtomicU64,
}

/// A read of the counters for one log line. Read one field at a time, so the
/// numbers can be a few events out of step with each other — they are for the
/// operator's eye, not for accounting.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryStats {
    pub produced: u64,
    pub delivered: u64,
    pub replayed: u64,
    pub transient: u64,
    pub permanent: u64,
    pub isolated: u64,
    pub quarantined: u64,
    pub spooled: u64,
    pub dropped: u64,
    pub queue_depth: u64,
    pub pending_on_disk: u64,
    pub spool_bytes: u64,
}

impl DeliveryStats {
    /// Turn a change in delivery health since the last report into a finding
    /// the platform can see. The journal already says this (`main.rs` logs the
    /// same counters on the same tick), but a journal line is not in Sentinel:
    /// an operator looking at the platform would otherwise see a sensor that
    /// went quiet and assume the host went quiet too.
    ///
    /// `None` when nothing degraded — a healthy tick must NOT mint a finding,
    /// or the platform fills with "all is well" rows and the real alarm is
    /// buried. Deltas, not absolutes: the first degraded tick is the one that
    /// says what happened, and later ticks say "still happening" only when a
    /// new loss actually occurs.
    pub fn self_finding(&self, prev: &DeliveryStats) -> Option<Finding> {
        let lost = self.dropped.saturating_sub(prev.dropped);
        let quarantined = self.quarantined.saturating_sub(prev.quarantined);
        let isolated = self.isolated.saturating_sub(prev.isolated);
        if lost == 0 && quarantined == 0 && isolated == 0 {
            return None;
        }
        let severity = if lost > 0 {
            Severity::Critical
        } else if quarantined > 0 {
            Severity::High
        } else {
            Severity::Medium
        };
        let summary = format!(
            "warden uplink degraded: {lost} finding(s) LOST, {quarantined} dead-lettered, \
             {isolated} batch(es) isolated since the last report"
        );
        let detail = serde_json::json!({
            "kind": "self_observability",
            "lost_since_last_report": lost,
            "quarantined_since_last_report": quarantined,
            "isolated_since_last_report": isolated,
            "pending_on_disk": self.pending_on_disk,
            "spool_bytes": self.spool_bytes,
            "total_lost": self.dropped,
            "total_quarantined": self.quarantined,
            // An unauthenticated reader of this row must be able to tell that
            // it describes the sensor, not an attacker on the host.
            "enforcement_requested": false,
        });
        Some(Finding {
            source_ts_ns: 0,
            event_type: FindingType::SelfDegraded,
            severity,
            summary,
            process: ProcessInfo {
                pid: std::process::id(),
                ppid: 0,
                uid: 0,
                comm: "warden".to_string(),
                exe: std::env::current_exe()
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned()),
                cmdline: None,
                cgroup: None,
                starttime: None,
            },
            target_pid: None,
            wants_kill: false,
            detail,
        })
    }

    /// One line, for the periodic health report and the shutdown summary.
    pub fn summary(&self) -> String {
        format!(
            "{} produced, {} delivered ({} replayed from disk), {} attempt(s) failed transiently, \
             {} refused permanently, {} batch(es) isolated ({} dead-lettered at 0600), {} spooled, \
             {} LOST, {} in memory, {} waiting on disk ({} bytes)",
            self.produced,
            self.delivered,
            self.replayed,
            self.transient,
            self.permanent,
            self.isolated,
            self.quarantined,
            self.spooled,
            self.dropped,
            self.queue_depth,
            self.pending_on_disk,
            self.spool_bytes,
        )
    }
}

/// Why a record could not be stored. The distinction is not cosmetic: `Full` is
/// the policy decision the audit asked to be explicit, `Io` is the disk
/// disagreeing with it.
enum SpoolError {
    Full,
    Io(std::io::Error),
}

impl std::fmt::Debug for SpoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpoolError::Full => write!(f, "spool is full"),
            SpoolError::Io(e) => write!(f, "spool write failed: {e}"),
        }
    }
}

/// The append-only on-disk backlog: one JSON envelope per line, oldest first.
///
/// The file is the source of truth and `queued` is its parsed image. Delivery
/// pops from the front of `queued`; the line stays in the file until a
/// compaction rewrites it, which is what makes a crash mid-drain lose nothing —
/// at worst a delivered record is delivered again, and the event id makes that
/// harmless.
struct Spool {
    path: PathBuf,
    file: File,
    queued: VecDeque<Record>,
    /// Records popped from `queued` but still present in the file.
    delivered: usize,
    /// Physical size of the file. The cap applies to this, not to `queued`: the
    /// cap exists to bound disk, so it has to be the disk number.
    file_bytes: u64,
    max_bytes: u64,
}

impl Spool {
    fn open(path: &Path, max_bytes: u64) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;

        // Enforce 0600 on an existing file too, not just at creation: this file
        // holds command lines, executable paths and pids, and a file left by an
        // earlier run under a looser umask — or created by hand — would be a
        // readable record of every process the host found interesting.
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode != 0o600 {
            log::warn!(
                "bridge: spool {} was mode {mode:o}; tightening to 600 — it holds command lines \
                 and paths",
                path.display()
            );
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        let mut queued = VecDeque::new();
        let mut skipped = 0usize;
        for line in BufReader::new(&file).split(b'\n') {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            match parse_spool_line(&line) {
                Some(rec) => queued.push_back(rec),
                // A torn last line from a crash mid-append. It is dropped rather
                // than delivered because it has no readable event id — and an
                // undeduplicatable record is the one thing this whole path
                // cannot make safe. Counted and reported; the next compaction
                // removes it.
                None => skipped += 1,
            }
        }
        if skipped > 0 {
            log::error!(
                "bridge: {skipped} unparseable line(s) in {} were discarded — a torn write from an \
                 unclean shutdown. The findings they stood for are lost.",
                path.display()
            );
        }

        let file_bytes = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            queued,
            delivered: 0,
            file_bytes,
            max_bytes,
        })
    }

    fn len(&self) -> usize {
        self.queued.len()
    }
    fn bytes(&self) -> u64 {
        self.file_bytes
    }
    fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
    #[cfg(test)]
    fn delivered_count(&self) -> usize {
        self.delivered
    }
    #[cfg(test)]
    fn front(&self) -> Option<Record> {
        self.queued.front().cloned()
    }

    /// The oldest `max` undelivered records, without removing them. A batch is
    /// only dropped from the queue after the server has accepted the request, so
    /// a failed attempt leaves every record in place.
    fn front_batch(&self, max: usize) -> Vec<Record> {
        self.queued.iter().take(max).cloned().collect()
    }

    /// True when a rewrite would reclaim at least half of what is on disk
    /// (`delivered >= queued`), or everything is delivered. Compaction rewrites
    /// the whole remaining queue, so doing it while most of the file is still
    /// live copies far more bytes than it frees — at the cap that turned every
    /// append into a full-file fsync and starved the very drain that needed it.
    fn should_compact(&self) -> bool {
        self.queued.is_empty() || (self.delivered > 0 && self.delivered >= self.queued.len())
    }

    /// Drop the front record from the queue. It stays in the file until the next
    /// compaction; `delivered` is what tracks that.
    #[cfg(test)]
    fn pop_delivered(&mut self) {
        self.pop_delivered_n(1);
    }

    fn pop_delivered_n(&mut self, n: usize) {
        let n = n.min(self.queued.len());
        self.queued.drain(..n);
        self.delivered += n;
    }

    /// Persist one record, or refuse.
    ///
    /// On a full spool the *incoming* record is the one refused, not the oldest
    /// one evicted. A spool with a hole in the middle is worse than a spool with
    /// a missing tail: the tail is an obvious, reportable boundary ("the last N
    /// findings of the outage are gone"), whereas an evicted middle leaves a
    /// record that looks complete and is not. The newest events are also the
    /// ones still flowing from a live incident, so evicting the oldest would
    /// discard the beginning of the story the operator is trying to read.
    fn append(&mut self, rec: Record) -> Result<(), SpoolError> {
        let need = rec.body.len() as u64 + 1;
        if self.file_bytes + need > self.max_bytes && self.should_compact() {
            // Reclaim before refusing. Delivered records occupy the file until a
            // rewrite, so without this the cap would fire while the *undelivered*
            // set was still far below it — a spool that refuses to buffer during
            // an outage because of records it has already delivered.
            if let Err(e) = self.compact() {
                log::warn!(
                    "bridge: spool compaction failed ({e}); the cap is now measured against a \
                     file that still holds delivered records"
                );
            }
        }
        if self.file_bytes + need > self.max_bytes {
            return Err(SpoolError::Full);
        }

        let mut line = rec.body;
        line.push(b'\n');
        self.file.write_all(&line).map_err(SpoolError::Io)?;
        // fsync per record. The failure this spool exists for is the host dying
        // or rebooting in the middle of a Sentinel outage, and bytes still in a
        // page cache are exactly the data that was promised to be kept.
        self.file.sync_data().map_err(SpoolError::Io)?;
        self.file_bytes += need;

        line.pop();
        self.queued.push_back(Record {
            event_id: rec.event_id,
            body: line,
        });
        Ok(())
    }

    /// Rewrite the file with exactly the records still in `queued`, atomically.
    /// Shared by `compact` (drop the delivered prefix) and `drop_front_indices`
    /// (drop findings Sentinel named in a 400 — they are dead-lettered instead).
    fn rewrite(&mut self) -> std::io::Result<()> {
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);

        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        let mut bytes = 0u64;
        for rec in &self.queued {
            out.write_all(&rec.body)?;
            out.write_all(b"\n")?;
            bytes += rec.body.len() as u64 + 1;
        }
        // fsync the new file before the rename, so the rename can never publish
        // a name whose contents are not yet on the platter.
        out.sync_all()?;
        // Open the replacement handle while the file still has its temporary
        // name. After the rename there is no fallible operation left: every
        // error happens before publication, so a failed rewrite can never
        // leave the spool file changed while the caller rolls back the queue.
        let file = OpenOptions::new().read(true).append(true).open(&tmp)?;
        drop(out);
        std::fs::rename(&tmp, &self.path)?;
        // Best-effort directory fsync: without it the rename itself can be lost
        // on a crash. Cheap, and the failure mode is only "one extra
        // redelivery", which the event id absorbs.
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }

        self.file = file;
        self.file_bytes = bytes;
        self.delivered = 0;
        Ok(())
    }

    /// Rewrite the file with only the undelivered records, atomically.
    fn compact(&mut self) -> std::io::Result<()> {
        if self.delivered == 0 {
            return Ok(());
        }
        self.rewrite()
    }

    /// Remove specific positions from the FRONT of the queue and rewrite the
    /// file without them. `indices` are relative to the batch just sent, which
    /// is the front of `queued`; findings the server named are already in the
    /// dead-letter file, so leaving them here would re-quarantine the same rows
    /// on every retry and grow the file without bound.
    fn drop_front_indices(&mut self, indices: &[usize]) -> std::io::Result<usize> {
        if indices.is_empty() {
            return Ok(0);
        }
        // Keep the original queue until the rewrite succeeds: a failed rewrite
        // must not drop rows from memory while leaving them on disk, because
        // the caller would then skip survivors that are still queued.
        let original = self.queued.clone();
        let mut kept = VecDeque::with_capacity(self.queued.len());
        let mut removed = 0;
        for (i, rec) in std::mem::take(&mut self.queued).into_iter().enumerate() {
            if indices.contains(&i) {
                removed += 1;
            } else {
                kept.push_back(rec);
            }
        }
        self.queued = kept;
        if removed > 0 {
            if let Err(e) = self.rewrite() {
                self.queued = original;
                return Err(e);
            }
        }
        Ok(removed)
    }

    fn sync(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

/// Cap on the dead-letter file. Bounded like the spool so a contract mismatch
/// cannot fill the root filesystem; small because only refused findings go
/// here, and each of them is already a known-bad row awaiting operator review.
const QUARANTINE_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Where a refused finding waits for an operator to fix the contract and replay
/// it. Mode 0600, one JSON line per finding, exact envelope preserved.
struct Quarantine {
    path: PathBuf,
    file: File,
    bytes: u64,
}

impl Quarantine {
    fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening quarantine {}", path.display()))?;
        // A pre-existing file must not stay world-readable just because it was
        // created by an older build or by hand.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let bytes = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            bytes,
        })
    }

    /// Append one refused finding. Returns false when the cap is reached —
    /// the caller counts that as LOST and says so loudly, never silently.
    fn write(&mut self, rejected: &RejectedRecord, now: u64) -> std::io::Result<bool> {
        let finding =
            serde_json::from_slice::<serde_json::Value>(&rejected.body).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&rejected.body).into_owned())
            });
        let line = serde_json::json!({
            "quarantined_at": now,
            "event_id": rejected.event_id,
            "index": rejected.index,
            "reason": rejected.reason,
            "finding": finding,
        })
        .to_string();
        let need = (line.len() + 1) as u64;
        if self.bytes + need > QUARANTINE_MAX_BYTES {
            return Ok(false);
        }
        self.file.write_all(line.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()?;
        self.bytes += need;
        Ok(true)
    }
}

/// The dead-letter path. Optional in config so existing deploy files keep
/// working; the default is a sibling of the spool in the same 0700 directory.
pub fn quarantine_path(cfg: &Bridge) -> PathBuf {
    cfg.quarantine_path
        .clone()
        .unwrap_or_else(|| cfg.spool_path.with_file_name("bridge_quarantine.jsonl"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Dead-letter the named findings. Returns how many were actually persisted;
/// the caller subtracts that from the batch and counts any remainder as LOST.
fn quarantine_records(cfg: &Bridge, rejected: &[RejectedRecord], c: &Counters) -> usize {
    let path = quarantine_path(cfg);
    let mut q = match Quarantine::open(&path) {
        Ok(q) => q,
        Err(e) => {
            log::error!(
                "bridge: cannot open dead-letter file {} ({e}); {} refused finding(s) are LOST",
                path.display(),
                rejected.len()
            );
            c.dropped
                .fetch_add(rejected.len() as u64, Ordering::Relaxed);
            return 0;
        }
    };
    let now = now_secs();
    let mut written = 0;
    for rec in rejected {
        match q.write(rec, now) {
            Ok(true) => written += 1,
            Ok(false) => log::error!(
                "bridge: dead-letter file {} reached its {} byte cap; finding {} is LOST",
                q.path.display(),
                QUARANTINE_MAX_BYTES,
                rec.event_id
            ),
            Err(e) => log::error!(
                "bridge: writing finding {} to dead-letter {} failed ({e}); it is LOST",
                rec.event_id,
                q.path.display()
            ),
        }
    }
    let lost = rejected.len() - written;
    c.quarantined.fetch_add(written as u64, Ordering::Relaxed);
    if lost > 0 {
        c.dropped.fetch_add(lost as u64, Ordering::Relaxed);
    }
    written
}

/// Operator replay, after the Sentinel contract has been fixed. Reads each
/// dead-lettered envelope and appends it to the spool so the next Warden start
/// delivers it with the original `event_id` (Sentinel dedupes redeliveries).
/// The dead-letter file is renamed to `.replayed.<ts>` rather than truncated,
/// so a second invocation cannot replay the same rows twice.
///
/// Warden must be STOPPED: the running sender holds the spool file handle and
/// an in-memory image of its contents, so appending underneath it would
/// desynchronise the two. The CLI says so; this function never stops a service.
pub fn replay_quarantine(
    spool_path: &Path,
    quarantine_path: &Path,
) -> anyhow::Result<(usize, usize)> {
    let text = std::fs::read_to_string(quarantine_path)
        .with_context(|| format!("reading {}", quarantine_path.display()))?;
    let mut spool = Spool::open(spool_path, REPLAY_SPOOL_CAP)?;
    let mut replayed = 0;
    let mut skipped = 0;
    for line in text.lines() {
        let parsed: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let Some(finding) = parsed.get("finding") else {
            skipped += 1;
            continue;
        };
        let body = match serde_json::to_vec(finding) {
            Ok(b) => b,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let event_id = parsed
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("quarantine-replay")
            .to_string();
        match spool.append(Record { event_id, body }) {
            Ok(()) => replayed += 1,
            Err(e) => {
                log::warn!("replay: could not queue a finding ({e:?})");
                skipped += 1;
            }
        }
    }
    spool.sync()?;
    let mut archived = quarantine_path.as_os_str().to_os_string();
    archived.push(format!(".replayed.{}", now_secs()));
    std::fs::rename(quarantine_path, PathBuf::from(archived))?;
    Ok((replayed, skipped))
}

/// Matches config.rs::default_spool_max_bytes (64 MiB). A replay that finds the
/// spool full must report a skip rather than grow the file past its cap.
const REPLAY_SPOOL_CAP: u64 = 64 * 1024 * 1024;

/// The queue, the sender thread and the spool. Owned by `main`, so the event
/// loop holds only the handle and can never block on the network.
pub struct Deliverer {
    tx: SyncSender<Record>,
    /// Shared with the sender thread: the overflow path and the shutdown flush
    /// both write to it from the producing side.
    spool: Arc<Mutex<Spool>>,
    /// Kept so the producer can stamp an id onto every envelope without asking
    /// the sender thread, and so two findings can never be stamped by two
    /// threads in an interleaved order.
    host: String,
    /// Phase 5: the latest sensor-trust reading, shared with the event loop so
    /// every envelope states whether its findings came from a healthy view.
    /// Starts `UNKNOWN`: an agent that has not yet measured its own ring must
    /// not claim health on the wire.
    sensor_health: Arc<Mutex<SensorHealth>>,
    spool_path: PathBuf,
    counters: Arc<Counters>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Deliverer {
    /// Start delivery. Fails at startup — loudly, once — if the endpoint URL is
    /// unusable or the spool cannot be opened, in the same spirit as the
    /// pre-existing "a bad URL is fatal here, not silently per-event": a bridge
    /// configured to lose data should not come up looking healthy.
    pub fn start(cfg: Bridge) -> anyhow::Result<Self> {
        let client = BridgeClient::new(cfg.clone()).context("configuring the Sentinel bridge")?;
        let spool = Spool::open(&cfg.spool_path, cfg.spool_max_bytes)
            .with_context(|| format!("opening the bridge spool at {}", cfg.spool_path.display()))?;
        let recovered = spool.len();
        if recovered > 0 {
            log::warn!(
                "bridge: {recovered} finding(s) recovered from {} and queued for delivery first \
                 — they are from an earlier run whose Sentinel uplink failed",
                cfg.spool_path.display()
            );
        }

        let counters = Arc::new(Counters::default());
        counters
            .pending_on_disk
            .store(recovered as u64, Ordering::Relaxed);
        counters.spool_bytes.store(spool.bytes(), Ordering::Relaxed);

        let spool = Arc::new(Mutex::new(spool));
        let (tx, rx) = sync_channel(cfg.queue_max.max(1));
        let stop = Arc::new(AtomicBool::new(false));

        let worker = thread::Builder::new()
            .name("warden-deliver".into())
            .spawn({
                let spool = Arc::clone(&spool);
                let counters = Arc::clone(&counters);
                let stop = Arc::clone(&stop);
                let cfg = cfg.clone();
                move || worker(client, spool, rx, counters, stop, &cfg)
            })
            .context("spawning the bridge sender thread")?;

        log::info!(
            "bridge: delivering to {} as host {:?}, queue {} findings, spool {} (cap {} bytes), \
             retry {}ms doubling to {}ms",
            cfg.url,
            cfg.host,
            cfg.queue_max,
            cfg.spool_path.display(),
            cfg.spool_max_bytes,
            cfg.backoff_ms,
            cfg.max_backoff_ms,
        );

        Ok(Self {
            tx,
            spool,
            host: cfg.host.clone(),
            sensor_health: Arc::new(Mutex::new(SensorHealth::unknown())),
            spool_path: cfg.spool_path.clone(),
            counters,
            stop,
            worker: Some(worker),
        })
    }

    /// Phase 5: publish the trust state of the sensor for the envelopes that
    /// are stamped from here on. The value is copied, not shared: a report
    /// rebuilt on a later tick cannot rewrite the health a queued finding
    /// already declared. Lock poisoning is treated as "unknown" — losing the
    /// health reading must never lose the finding.
    pub fn set_sensor_health(&self, report: &TelemetryReport) {
        let next = SensorHealth::from_report(report);
        let mut guard = self.sensor_health.lock().unwrap_or_else(|e| e.into_inner());
        *guard = next;
    }

    /// A failed counter read invalidates the previous snapshot: the next
    /// finding must say UNKNOWN, not repeat a now-stale HEALTHY from an earlier
    /// tick. An unreadable measurement is never collapsed into "nothing lost".
    pub fn set_sensor_health_unknown(&self) {
        let mut guard = self.sensor_health.lock().unwrap_or_else(|e| e.into_inner());
        *guard = SensorHealth::unknown();
    }

    /// Hand one finding, and what the responder just did about it, to the sender.
    /// Never touches the network: this is called from the ring-buffer drain loop,
    /// where a resolver stall or a slow peer is ring loss (W-R6, W-02). Healthy
    /// path is a bounded, non-blocking channel send. The overflow path is not
    /// non-blocking: it appends and fsyncs the record to the spool on this thread,
    /// because the alternative is dropping it or growing memory without bound while
    /// Sentinel is down.
    ///
    /// `action` is a required argument rather than a field of `Finding` on purpose:
    /// the verdict is only knowable after `Responder::act`, and the audit trail is
    /// only true if the record that goes out carries it. Making the caller supply
    /// it means a future call site cannot quietly deliver a finding with no outcome
    /// attached — which is exactly the state that left Sentinel unable to tell a
    /// kill from a refusal (W2K-27).
    pub fn enqueue(&self, f: &Finding, action: Action) {
        self.counters.produced.fetch_add(1, Ordering::Relaxed);

        let event_id = next_event_id(&self.host);
        let health = self
            .sensor_health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let body = match serde_json::to_vec(&bridge::envelope_with_health(
            &self.host, &event_id, f, action, &health,
        )) {
            Ok(b) => b,
            Err(e) => {
                // Serialization cannot fail because of the network. If it fails,
                // it is a bug in this program, and the finding is not
                // recoverable from anywhere else.
                self.counters.dropped.fetch_add(1, Ordering::Relaxed);
                log::error!(
                    "bridge: finding {event_id} ({}) could not be serialized ({e}) and is LOST — \
                     this is a Warden bug, not an outage",
                    f.event_type.as_str()
                );
                return;
            }
        };

        match self.tx.try_send(Record { event_id, body }) {
            Ok(()) => {
                self.counters.queued.fetch_add(1, Ordering::Relaxed);
            }
            // The queue is the shock absorber; the spool is the floor. Overflow
            // is not a loss, it is skipping memory and going to disk.
            Err(TrySendError::Full(rec)) => {
                log::debug!(
                    "bridge: queue full; {} goes to the spool instead of waiting in memory",
                    rec.event_id
                );
                self.spool_one(rec);
            }
            Err(TrySendError::Disconnected(rec)) => {
                log::error!(
                    "bridge: the sender thread is gone; findings can only be spooled now, and \
                     nothing will reach Sentinel until Warden is restarted"
                );
                self.spool_one(rec);
            }
        }
    }

    fn spool_one(&self, rec: Record) {
        spool_one(&self.spool, &self.counters, rec);
    }

    pub fn stats(&self) -> DeliveryStats {
        let q = self.counters.queued.load(Ordering::Relaxed);
        let t = self.counters.taken.load(Ordering::Relaxed);
        DeliveryStats {
            produced: self.counters.produced.load(Ordering::Relaxed),
            delivered: self.counters.delivered.load(Ordering::Relaxed),
            replayed: self.counters.replayed.load(Ordering::Relaxed),
            transient: self.counters.transient.load(Ordering::Relaxed),
            permanent: self.counters.permanent.load(Ordering::Relaxed),
            isolated: self.counters.isolated.load(Ordering::Relaxed),
            quarantined: self.counters.quarantined.load(Ordering::Relaxed),
            spooled: self.counters.spooled.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            queue_depth: q.saturating_sub(t),
            pending_on_disk: self.counters.pending_on_disk.load(Ordering::Relaxed),
            spool_bytes: self.counters.spool_bytes.load(Ordering::Relaxed),
        }
    }

    /// Flush what is in memory to the spool, then stop the sender. Called on the
    /// shutdown path so the final report states what is on disk with nothing
    /// still in flight — and so a restart delivers this run's backlog rather
    /// than losing it.
    ///
    /// Takes `&mut self` rather than consuming, so the caller can still read
    /// `stats()` afterwards and report the state it just flushed to.
    pub fn shutdown(&mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.worker.take() {
            // Bounded: the sender checks the flag between attempts and inside
            // its backoff sleep, so the join waits at most one `timeout_ms` plus
            // one TICK.
            if h.join().is_err() {
                log::error!(
                    "bridge: the sender thread panicked; any finding it was holding is lost, and \
                     {} may be missing the last findings before the panic",
                    self.spool_path.display()
                );
            }
        }
    }
}

impl Drop for Deliverer {
    fn drop(&mut self) {
        // So an early `?` return in `main` still flushes and joins instead of
        // detaching a thread that is mid-write to the spool.
        self.stop_and_join();
    }
}

/// `--check` validation: parse the URL, open the spool, report the backlog.
/// Creates the state directory (and an empty spool file) if they do not exist,
/// which is what the service would do on its first start anyway.
pub fn check(cfg: &Bridge) -> anyhow::Result<String> {
    BridgeClient::new(cfg.clone()).context("bridge.url")?;
    let spool = Spool::open(&cfg.spool_path, cfg.spool_max_bytes)
        .with_context(|| format!("bridge.spool_path ({})", cfg.spool_path.display()))?;
    Ok(format!(
        "{} as host {:?} — spool {} holds {} finding(s), {} of {} bytes",
        cfg.url,
        cfg.host,
        cfg.spool_path.display(),
        spool.len(),
        spool.bytes(),
        spool.max_bytes(),
    ))
}

/// A unique id for one finding, stable across retries because it is generated
/// once. Host plus pid plus nanosecond clock plus a per-process sequence: the
/// pid makes it unique across restarts of Warden without needing the clock to
/// be monotonic, and the sequence disambiguates findings that share a clock
/// tick. Clipped so the whole id stays inside Sentinel's 128-char column.
fn next_event_id(host: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let host: String = host.chars().take(MAX_HOST_IN_ID).collect();
    format!(
        "{host}:{}:{:x}.{:x}.{:x}",
        std::process::id(),
        now.as_secs(),
        now.subsec_nanos(),
        seq
    )
}

fn parse_spool_line(line: &[u8]) -> Option<Record> {
    let v: serde_json::Value = serde_json::from_slice(line).ok()?;
    let event_id = v.get("event_id")?.as_str()?;
    // W2K-17: an empty id is the same absence this function's caller already
    // treats as undeliverable. The id is what makes a crash-mid-drain harmless —
    // Sentinel deduplicates on it — so a record with `""` would be re-delivered
    // as a fresh finding forever, and would also collide with every other
    // idless record. Torn lines already fail the JSON parse; this closes the one
    // shape that parsed.
    if event_id.is_empty() {
        return None;
    }
    Some(Record {
        event_id: event_id.to_string(),
        body: line.to_vec(),
    })
}

fn refresh_gauges(c: &Counters, s: &Spool) {
    c.pending_on_disk.store(s.len() as u64, Ordering::Relaxed);
    c.spool_bytes.store(s.bytes(), Ordering::Relaxed);
}

/// Write one record to the spool, or count it as lost.
fn spool_one(spool: &Arc<Mutex<Spool>>, c: &Counters, rec: Record) {
    let event_id = rec.event_id.clone();
    let mut s = lock(spool);
    match s.append(rec) {
        Ok(()) => {
            c.spooled.fetch_add(1, Ordering::Relaxed);
            refresh_gauges(c, &s);
        }
        Err(SpoolError::Full) => {
            let n = c.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(DROP_LOG_EVERY) {
                log::error!(
                    "bridge: SPOOL FULL — {} of {} bytes used, {n} finding(s) LOST so far, most \
                     recently {event_id}. These were never sent and are not stored anywhere. \
                     Raise bridge.spool_max_bytes, or find out why Sentinel has been unreachable \
                     long enough to fill the spool.",
                    s.bytes(),
                    s.max_bytes(),
                );
            }
        }
        Err(SpoolError::Io(e)) => {
            let n = c.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n.is_multiple_of(DROP_LOG_EVERY) {
                log::error!(
                    "bridge: spool write failed ({e}); {n} finding(s) LOST so far, most recently \
                     {event_id}. The spool cannot be written, so nothing is durable until this is \
                     fixed."
                );
            }
        }
    }
}

/// Move everything already in the channel onto disk, without blocking.
fn absorb(rx: &Receiver<Record>, spool: &Arc<Mutex<Spool>>, c: &Counters) {
    while let Ok(rec) = rx.try_recv() {
        c.taken.fetch_add(1, Ordering::Relaxed);
        spool_one(spool, c, rec);
    }
}

/// Where the sender is in its cycle.
enum State {
    /// Sentinel is answering; deliver each finding as it arrives.
    Live,
    /// Sentinel is failing; absorb to disk and wait out the backoff.
    Backoff,
    /// Sentinel is answering again; work the backlog off disk, oldest first.
    Draining,
}

/// Dead-letter the findings Sentinel named in a 400, remove those rows from
/// the spool, and hand back the survivors for the normal retry path. Returns
/// `(survivors, surviving_spooled_count)`: the first N survivors are still on
/// disk, so only the rest need to be written back by the caller.
fn isolate_batch(
    cfg: &Bridge,
    c: &Counters,
    spool: &Arc<Mutex<Spool>>,
    batch: &[Record],
    rejected: &[RejectedRecord],
    detail: &str,
    spooled_n: usize,
) -> (Vec<Record>, usize) {
    let bad: Vec<usize> = rejected.iter().map(|r| r.index).collect();
    let written = quarantine_records(cfg, rejected, c);
    c.isolated.fetch_add(1, Ordering::Relaxed);
    let spool_bad: Vec<usize> = bad.iter().copied().filter(|i| *i < spooled_n).collect();
    let removed = match lock(spool).drop_front_indices(&spool_bad) {
        Ok(n) => n,
        Err(e) => {
            log::error!("bridge: removing isolated findings from the spool failed ({e})");
            // The rewrite is transactional, so those rows are still at the front
            // of the spool. Skip exactly that many survivors; skipping none would
            // append spooled survivors a second time.
            spool_bad.len()
        }
    };
    let survivors: Vec<Record> = batch
        .iter()
        .enumerate()
        .filter(|(i, _)| !bad.contains(i))
        .map(|(_, r)| r.clone())
        .collect();
    log::error!(
        "bridge: {detail}; {} named finding(s) dead-lettered to {} ({} written, {} lost), \
         the other {} will be retried",
        rejected.len(),
        quarantine_path(cfg).display(),
        written,
        rejected.len().saturating_sub(written),
        survivors.len()
    );
    (survivors, spooled_n.saturating_sub(removed))
}

fn worker(
    client: BridgeClient,
    spool: Arc<Mutex<Spool>>,
    rx: Receiver<Record>,
    c: Arc<Counters>,
    stop: Arc<AtomicBool>,
    cfg: &Bridge,
) {
    let base = Duration::from_millis(cfg.backoff_ms.max(1));
    let max = Duration::from_millis(cfg.max_backoff_ms).max(base);
    let mut backoff = base;
    let mut retry_at = Instant::now();
    // Start at BATCH_MAX and let the endpoint's own latency decide. A batch that
    // hits timeout_ms is halved before the retry — sending 64 findings the far
    // side cannot ingest inside the budget burns the retry and keeps the spool
    // full. Each success grows it back, so a briefly slow server does not pin the
    // throughput low for the rest of the run.
    let mut batch_cap = BATCH_MAX;

    // Anything the last run left on disk goes first: the spool is a FIFO, and an
    // incident reads better from its beginning. Starting in `Draining` also
    // means a host that has just been rebooted through an outage does not wait
    // for a new finding to trigger the backlog flush.
    let mut state = if lock(&spool).len() > 0 {
        State::Draining
    } else {
        State::Live
    };

    while !stop.load(Ordering::Relaxed) {
        match state {
            State::Live => match rx.recv_timeout(TICK) {
                Ok(first) => {
                    c.taken.fetch_add(1, Ordering::Relaxed);
                    // Coalesce whatever else is already waiting. Under a normal
                    // rate this is a batch of one; under a storm it is up to
                    // BATCH_MAX findings per request, which is what keeps the
                    // spool from filling faster than it can drain.
                    let mut batch = Vec::with_capacity(batch_cap);
                    batch.push(first);
                    while batch.len() < batch_cap {
                        match rx.try_recv() {
                            Ok(rec) => {
                                c.taken.fetch_add(1, Ordering::Relaxed);
                                batch.push(rec);
                            }
                            Err(_) => break,
                        }
                    }
                    let n = batch.len();
                    match client.deliver_batch(&batch) {
                        Outcome::Delivered => {
                            c.delivered.fetch_add(n as u64, Ordering::Relaxed);
                            backoff = base;
                            batch_cap = (batch_cap + BATCH_MAX / 4).min(BATCH_MAX);
                        }
                        Outcome::Permanent(e) => {
                            // A refusal is about the request itself — a revoked key,
                            // an unknown event type, a malformed envelope. It cannot
                            // be repaired by replaying the same bytes, but it must
                            // not vanish either: dead-letter all of it at 0600.
                            let refused: Vec<RejectedRecord> = batch
                                .iter()
                                .enumerate()
                                .map(|(i, r)| RejectedRecord {
                                    index: i,
                                    event_id: r.event_id.clone(),
                                    body: r.body.clone(),
                                    reason: e.clone(),
                                })
                                .collect();
                            let written = quarantine_records(cfg, &refused, &c);
                            c.permanent.fetch_add(n as u64, Ordering::Relaxed);
                            log::error!(
                                "bridge: Sentinel REFUSED {} finding(s) starting at {} ({e}). Not \
                                 retried: {written} dead-lettered to {} for operator review. This \
                                 is a Warden/Sentinel contract mismatch to fix, not a network fault.",
                                n,
                                batch[0].event_id,
                                quarantine_path(cfg).display()
                            );
                        }
                        Outcome::Isolated { rejected, detail } => {
                            let (survivors, _) =
                                isolate_batch(cfg, &c, &spool, &batch, &rejected, &detail, 0);
                            if survivors.is_empty() {
                                continue;
                            }
                            // The rest is an ordinary transient failure: keep it
                            // durably and back off, exactly as below.
                            c.transient.fetch_add(1, Ordering::Relaxed);
                            for rec in survivors {
                                spool_one(&spool, &c, rec);
                            }
                            absorb(&rx, &spool, &c);
                            retry_at = Instant::now() + backoff;
                            backoff = (backoff * 2).min(max);
                            state = State::Backoff;
                        }
                        Outcome::Transient(e) => {
                            c.transient.fetch_add(1, Ordering::Relaxed);
                            if n > 1 && n / 2 < batch_cap {
                                batch_cap = (n / 2).max(1);
                                log::warn!(
                                    "bridge: a batch of {n} did not finish in {}ms; retrying in \
                                     batches of {batch_cap} until the endpoint keeps up",
                                    cfg.timeout_ms
                                );
                            }
                            log::warn!(
                                "bridge: delivery failed ({e}); buffering {} finding(s) to disk and \
                                 backing off. They are not lost — they are in {}, and the first \
                                 retry is in {:.1}s.",
                                n,
                                cfg.spool_path.display(),
                                backoff.as_secs_f64(),
                            );
                            for rec in batch {
                                spool_one(&spool, &c, rec);
                            }
                            // Everything else already in the queue follows it to
                            // disk. Draining the channel here, rather than
                            // letting it fill and having the producer spool
                            // directly, keeps the on-disk order closest to the
                            // order the findings were produced in.
                            absorb(&rx, &spool, &c);
                            retry_at = Instant::now() + backoff;
                            backoff = (backoff * 2).min(max);
                            state = State::Backoff;
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            },

            State::Backoff => {
                absorb(&rx, &spool, &c);
                let now = Instant::now();
                if now >= retry_at {
                    state = State::Draining;
                } else {
                    thread::sleep((retry_at - now).min(TICK));
                }
            }

            State::Draining => {
                // Deliberately no `absorb` here any more: pouring every arrival
                // onto disk while the disk is exactly what is being drained made
                // the backlog grow as fast as it shrank (and, at the cap, turned
                // each append into a full-file rewrite). Arrivals wait in the
                // channel and ride along with the next batch instead.
                let spooled = lock(&spool).front_batch(batch_cap);
                match spooled.first() {
                    None => {
                        // The backlog is empty. Reclaim the file before going
                        // back to the live path, so a host that has just
                        // recovered does not sit on a large file of records it
                        // has already delivered.
                        if let Err(e) = lock(&spool).compact() {
                            log::warn!(
                                "bridge: spool compaction failed ({e}); delivery continues, the \
                                 file is only larger than it needs to be"
                            );
                        }
                        refresh_gauges(&c, &lock(&spool));
                        backoff = base;
                        state = State::Live;
                    }
                    Some(_) => {
                        let spooled_n = spooled.len();
                        let mut batch = spooled;
                        // Top the request up with findings that arrived while the
                        // backlog was being worked off. They are newer than every
                        // spooled record, so appending them preserves FIFO order
                        // and keeps them off the file entirely.
                        while batch.len() < batch_cap {
                            match rx.try_recv() {
                                Ok(rec) => {
                                    c.taken.fetch_add(1, Ordering::Relaxed);
                                    batch.push(rec);
                                }
                                Err(_) => break,
                            }
                        }
                        let n = batch.len() as u64;
                        match client.deliver_batch(&batch) {
                            Outcome::Delivered => {
                                lock(&spool).pop_delivered_n(spooled_n);
                                c.delivered.fetch_add(n, Ordering::Relaxed);
                                c.replayed.fetch_add(spooled_n as u64, Ordering::Relaxed);
                                refresh_gauges(&c, &lock(&spool));
                                // One success means the endpoint is back: the next
                                // failure starts its backoff from the beginning
                                // again rather than from where the outage left it.
                                backoff = base;
                                batch_cap = (batch_cap + BATCH_MAX / 4).min(BATCH_MAX);
                            }
                            Outcome::Permanent(e) => {
                                // Dead-letter every refused row instead of
                                // dropping it silently. The spool entry is then
                                // resolved: its disposition is the 0600 file.
                                let refused: Vec<RejectedRecord> = batch
                                    .iter()
                                    .enumerate()
                                    .map(|(i, r)| RejectedRecord {
                                        index: i,
                                        event_id: r.event_id.clone(),
                                        body: r.body.clone(),
                                        reason: e.clone(),
                                    })
                                    .collect();
                                let written = quarantine_records(cfg, &refused, &c);
                                lock(&spool).pop_delivered_n(spooled_n);
                                c.permanent.fetch_add(n, Ordering::Relaxed);
                                log::error!(
                                    "bridge: a batch of {n} finding(s) starting at {} was REFUSED \
                                     ({e}); {written} dead-lettered to {} for operator review. Not \
                                     retried: replaying a refused request cannot succeed.",
                                    batch[0].event_id,
                                    quarantine_path(cfg).display()
                                );
                                if let Err(e) = lock(&spool).compact() {
                                    log::warn!("bridge: spool compaction failed ({e})");
                                }
                                refresh_gauges(&c, &lock(&spool));
                            }
                            Outcome::Isolated { rejected, detail } => {
                                let (survivors, remaining_spooled) = isolate_batch(
                                    cfg, &c, &spool, &batch, &rejected, &detail, spooled_n,
                                );
                                refresh_gauges(&c, &lock(&spool));
                                if survivors.is_empty() {
                                    // Every finding in the batch was named: all
                                    // are now on disk in the dead-letter file.
                                    continue;
                                }
                                c.transient.fetch_add(1, Ordering::Relaxed);
                                if survivors.len() > 1 && survivors.len() / 2 < batch_cap {
                                    batch_cap = (survivors.len() / 2).max(1);
                                }
                                // The first `remaining_spooled` survivors are
                                // still in the spool; only the newer ones need
                                // to be written back, preserving FIFO order.
                                for rec in survivors.into_iter().skip(remaining_spooled) {
                                    spool_one(&spool, &c, rec);
                                }
                                absorb(&rx, &spool, &c);
                                retry_at = Instant::now() + backoff;
                                backoff = (backoff * 2).min(max);
                                state = State::Backoff;
                            }
                            Outcome::Transient(e) => {
                                c.transient.fetch_add(1, Ordering::Relaxed);
                                if n > 1 && (n as usize) / 2 < batch_cap {
                                    batch_cap = (n as usize / 2).max(1);
                                    log::warn!(
                                        "bridge: a batch of {n} did not finish in {}ms; retrying \
                                         in batches of {batch_cap} until the endpoint keeps up",
                                        cfg.timeout_ms
                                    );
                                }
                                // The spooled part is already durable and stays
                                // queued; only the records that never reached disk
                                // have to be written back, after the spooled ones,
                                // so the on-disk order remains the produced order.
                                for rec in batch.drain(spooled_n..) {
                                    spool_one(&spool, &c, rec);
                                }
                                absorb(&rx, &spool, &c);
                                let pending = lock(&spool).len();
                                log::warn!(
                                    "bridge: still failing ({e}); {pending} finding(s) waiting on \
                                     disk, next attempt in {:.1}s",
                                    backoff.as_secs_f64()
                                );
                                retry_at = Instant::now() + backoff;
                                backoff = (backoff * 2).min(max);
                                state = State::Backoff;
                            }
                        }
                    }
                }
                let due = lock(&spool).should_compact();
                if due {
                    if let Err(e) = lock(&spool).compact() {
                        log::warn!(
                            "bridge: spool compaction failed ({e}); delivery continues and the \
                             file is only larger than it needs to be"
                        );
                    }
                    refresh_gauges(&c, &lock(&spool));
                }
            }
        }
    }

    // Shutdown. Findings this process accepted but has not persisted live only
    // in memory, so they go to disk now; the next start delivers them. Then
    // compact, so that start does not re-read what has already been delivered.
    absorb(&rx, &spool, &c);
    let mut s = lock(&spool);
    if let Err(e) = s.sync() {
        log::error!("bridge: final spool fsync failed ({e})");
    }
    if let Err(e) = s.compact() {
        log::warn!("bridge: final spool compaction failed ({e})");
    }
    refresh_gauges(&c, &s);
    let pending = s.len();
    let bytes = s.bytes();
    let path = s.path.display().to_string();
    drop(s);
    if pending > 0 {
        log::warn!(
            "bridge: {pending} finding(s) ({bytes} bytes) are waiting in {path} and will be \
             delivered on the next start — Sentinel has not seen them yet"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Finding, FindingType, ProcessInfo, Severity};
    use std::io::Read;
    use std::net::TcpListener;

    fn temp_dir(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "warden-deliver-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create the test's own temp dir");
        p
    }

    fn finding() -> Finding {
        Finding {
            source_ts_ns: 0,
            event_type: FindingType::SelfTamper,
            severity: Severity::Critical,
            summary: "SIGKILL aimed at a protected daemon".to_string(),
            process: ProcessInfo {
                pid: 4242,
                ppid: 1,
                uid: 0,
                comm: "kill".to_string(),
                exe: Some("/usr/bin/kill".to_string()),
                cmdline: Some("kill -9 1234".to_string()),
                cgroup: None,
                starttime: None,
            },
            target_pid: Some(1234),
            wants_kill: false,
            detail: serde_json::json!({"signal": 9}),
        }
    }

    fn cfg_for(url: &str, dir: &Path) -> Bridge {
        Bridge {
            url: url.to_string(),
            api_key: "k".to_string(),
            host: "test-host".to_string(),
            timeout_ms: 500,
            queue_max: 8,
            spool_path: dir.join("bridge_spool.jsonl"),
            spool_max_bytes: 1 << 20,
            backoff_ms: 20,
            max_backoff_ms: 200,
            allow_public_plaintext: false,
            quarantine_path: None,
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            tls_sni: None,
        }
    }

    /// A real HTTP server on a real socket, replying whatever the closure says
    /// for connection N. Delivery, classification and retry are only worth
    /// testing against an actual peer: a mock of the transport would be a test
    /// of the mock.
    fn serve<F>(reply: F) -> (String, JoinHandle<()>)
    where
        F: Fn(usize) -> &'static str + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let Ok(mut s) = stream else { break };
                // Read the request in full (headers, then Content-Length bytes)
                // so the response cannot race the client's write.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                let mut body_at: Option<usize> = None;
                let mut want = 0usize;
                loop {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if body_at.is_none() {
                                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    body_at = Some(p + 4);
                                    want = content_length(&buf[..p]);
                                }
                            }
                            if let Some(p) = body_at {
                                if buf.len() >= p + want {
                                    break;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                }
                let _ = s.write_all(reply(i).as_bytes());
                let _ = s.flush();
            }
        });
        (format!("http://{addr}/api/v1/sentinel/host/"), handle)
    }

    /// Like [`serve`], but the reply closure also sees the request body. Used
    /// where a test must name a *finding* rather than a connection: the worker
    /// is free to drain the channel before all enqueues land, so "connection 0"
    /// is not reliably "the batch containing the bad row".
    fn serve_body<F>(reply: F) -> (String, JoinHandle<()>)
    where
        F: Fn(&[u8]) -> &'static str + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { break };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                let mut body_at: Option<usize> = None;
                let mut want = 0usize;
                loop {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if body_at.is_none() {
                                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    body_at = Some(p + 4);
                                    want = content_length(&buf[..p]);
                                }
                            }
                            if let Some(p) = body_at {
                                if buf.len() >= p + want {
                                    break;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                }
                let body = body_at.map(|p| buf[p..].to_vec()).unwrap_or_default();
                let _ = s.write_all(reply(&body).as_bytes());
                let _ = s.flush();
            }
        });
        (format!("http://{addr}/api/v1/sentinel/host/"), handle)
    }

    fn content_length(head: &[u8]) -> usize {
        let text = String::from_utf8_lossy(head).to_lowercase();
        text.lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    fn wait_for(mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if pred() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        pred()
    }

    /// (endpoint URL, captured request bodies, server thread).
    type CapturedServer = (String, Arc<Mutex<Vec<Vec<u8>>>>, JoinHandle<()>);

    /// Like [`serve`], but also records the body of every request, so a test can
    /// assert *what* arrived and in which order — not merely how many responses
    /// were written. The body is captured before the reply, so anything the
    /// client has counted as delivered has necessarily been recorded here.
    fn capture_serve<F>(reply: F) -> CapturedServer
    where
        F: Fn(usize) -> &'static str + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let addr = listener.local_addr().expect("local addr");
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&bodies);
        let handle = thread::spawn(move || {
            for (i, stream) in listener.incoming().enumerate() {
                let Ok(mut s) = stream else { break };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                let mut body_at: Option<usize> = None;
                let mut want = 0usize;
                loop {
                    match s.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if body_at.is_none() {
                                if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    body_at = Some(p + 4);
                                    want = content_length(&buf[..p]);
                                }
                            }
                            if let Some(p) = body_at {
                                if buf.len() >= p + want {
                                    break;
                                }
                            }
                        }
                        Err(_) => return,
                    }
                }
                if let Some(p) = body_at {
                    let end = (p + want).min(buf.len());
                    sink.lock().unwrap().push(buf[p..end].to_vec());
                }
                let _ = s.write_all(reply(i).as_bytes());
                let _ = s.flush();
            }
        });
        (
            format!("http://{addr}/api/v1/sentinel/host/"),
            bodies,
            handle,
        )
    }

    /// The findings inside one captured request body: a flat finding, or the
    /// members of a `{"findings": [...]}` batch. Tests assert on findings, not
    /// on how many of them the sender happened to pack into a request.
    fn findings_in(body: &[u8]) -> Vec<Vec<u8>> {
        let v: serde_json::Value = serde_json::from_slice(body).expect("captured body is JSON");
        match v.get("findings").and_then(|f| f.as_array()) {
            Some(arr) => arr
                .iter()
                .map(|f| serde_json::to_vec(f).expect("a batch member re-serialises"))
                .collect(),
            None => vec![body.to_vec()],
        }
    }

    fn all_findings(captured: &[Vec<u8>]) -> Vec<Vec<u8>> {
        captured.iter().flat_map(|b| findings_in(b)).collect()
    }

    /// The trailing per-process sequence from an event id, so a test can prove
    /// delivery order without knowing the ids in advance. `next_event_id` ends
    /// in `{:x}` of a monotonically increasing counter.
    fn event_seq(body: &[u8]) -> u64 {
        let v: serde_json::Value = serde_json::from_slice(body).expect("captured body is JSON");
        let id = v["event_id"]
            .as_str()
            .expect("every envelope carries event_id");
        let seq = id.rsplit('.').next().expect("id has a sequence field");
        u64::from_str_radix(seq, 16).expect("sequence is hexadecimal")
    }

    /// Phase 5: the health snapshot set from the event loop reaches the actual
    /// spooled envelope, and the shared API key never does. Read the on-disk
    /// record — not a helper — because that is what a restart replays to
    /// Sentinel and what an operator inspects during an outage.
    #[test]
    fn spooled_envelopes_carry_the_live_health_and_never_the_api_key() {
        let url = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            format!("http://{a}/api/v1/sentinel/host/")
        };
        let dir = temp_dir("phase5-health");
        let mut cfg = cfg_for(&url, &dir);
        cfg.queue_max = 1; // second enqueue takes the synchronous spool path
        cfg.timeout_ms = 50;
        let mut d = Deliverer::start(cfg).unwrap();
        assert_eq!(
            d.sensor_health.lock().unwrap().state,
            "UNKNOWN",
            "an unmeasured sensor must not claim health on the wire"
        );
        d.set_sensor_health(&crate::telemetry::TelemetryReport::live(
            crate::telemetry::RingLoss::observed(26, 74),
            crate::telemetry::PipelineCounters::unknown(),
            false,
            false,
        ));
        d.enqueue(&finding(), Action::Observed);
        d.enqueue(&finding(), Action::Observed);
        d.shutdown();

        let spool = std::fs::read_to_string(dir.join("bridge_spool.jsonl")).unwrap();
        assert!(!spool.is_empty());
        for line in spool.lines() {
            let env: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(env["schema_version"], bridge::HOST_FINDING_SCHEMA_VERSION);
            assert_eq!(env["agent_id"], "test-host");
            // Ranking is CRITICAL > PARTIALLY_BLIND > DEGRADED: the declared
            // blind spots outrank the measured ring loss, so the wire cannot
            // imply full coverage just because a counter was readable.
            assert_eq!(env["sensor_health"]["state"], "PARTIALLY_BLIND");
            assert_eq!(env["sensor_health"]["ring_loss"], "VERIFIED");
            assert!(
                !line.contains("api_key"),
                "the shared key must never be spooled"
            );
        }
    }

    /// BUG-10: a burst larger than the in-memory queue must not lose or duplicate
    /// a finding. Every produced record has to be on disk (the endpoint is down),
    /// and the counters must add up: delivered + queued + pending + lost == produced.
    /// A pressure path that silently drops is exactly what an outage produces.
    #[test]
    fn a_burst_larger_than_the_queue_is_spooled_without_loss_or_duplication() {
        const N: usize = 200;
        let url = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            format!("http://{a}/api/v1/sentinel/host/")
        };
        let dir = temp_dir("burst");
        let mut cfg = cfg_for(&url, &dir);
        // Small on purpose: most of the burst takes the overflow-to-disk path
        // instead of the in-memory channel.
        cfg.queue_max = 4;
        cfg.timeout_ms = 200;
        cfg.backoff_ms = 5;
        cfg.max_backoff_ms = 50;
        let mut d = Deliverer::start(cfg).expect("start delivery");

        for _ in 0..N {
            d.enqueue(&finding(), Action::Observed);
        }

        assert!(
            wait_for(|| d.stats().pending_on_disk == N as u64),
            "every finding must reach the spool while the endpoint is down; stats = {:?}",
            d.stats()
        );
        let s = d.stats();
        assert_eq!(s.produced, N as u64, "stats = {s:?}");
        assert_eq!(
            s.dropped, 0,
            "a durable outage must not lose a finding: {s:?}"
        );
        assert_eq!(s.delivered, 0, "nothing was deliverable: {s:?}");
        assert_eq!(s.queue_depth, 0, "the queue must have drained: {s:?}");
        assert_eq!(
            s.produced,
            s.delivered + s.queue_depth + s.pending_on_disk + s.dropped,
            "every produced finding must be accounted for exactly once: {s:?}"
        );

        let text = std::fs::read_to_string(dir.join("bridge_spool.jsonl"))
            .expect("read the spool the burst produced");
        let ids: std::collections::HashSet<String> = text
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).expect("spool line is JSON");
                v["event_id"].as_str().expect("event_id").to_string()
            })
            .collect();
        assert_eq!(
            ids.len(),
            N,
            "the spool must hold {N} distinct findings, not duplicates"
        );
        d.shutdown();
    }

    /// BUG-10: when the collector comes back inside one process, the backlog is
    /// delivered once, oldest first, and the live/backoff/draining transitions do
    /// not reorder or duplicate it.
    #[test]
    fn a_recovered_collector_gets_the_backlog_once_in_order() {
        let (url, bodies, _srv) = capture_serve(|i| {
            if i == 0 {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            }
        });
        let dir = temp_dir("reconnect");
        let mut d = Deliverer::start(cfg_for(&url, &dir)).expect("start delivery");

        for _ in 0..3 {
            d.enqueue(&finding(), Action::Observed);
        }

        assert!(
            wait_for(|| d.stats().delivered == 3),
            "the backlog must drain after the first 503; stats = {:?}",
            d.stats()
        );
        let s = d.stats();
        assert_eq!(s.dropped, 0, "recovery must not lose anything: {s:?}");
        assert_eq!(s.permanent, 0, "a 503 is transient: {s:?}");

        let captured = bodies.lock().unwrap();
        // The sender coalesces whatever is already queued, so a finding may
        // arrive alone or as one member of a batch; flatten before asserting.
        let first_batch = findings_in(&captured[0]);
        let flat = all_findings(&captured);
        let seqs: Vec<u64> = flat.iter().map(|b| event_seq(b)).collect();
        // The refused attempt must have carried exactly the same findings that
        // were then delivered — the retry is the same records, not new ones.
        let refused = &seqs[..first_batch.len()];
        let delivered = &seqs[first_batch.len()..];
        assert_eq!(
            delivered.len(),
            3,
            "all three findings must be delivered after recovery; got {seqs:?}"
        );
        assert_eq!(
            refused,
            &delivered[..refused.len()],
            "the retry must carry the same event_ids as the refused attempt"
        );
        let mut sorted = delivered.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            delivered,
            sorted.as_slice(),
            "the backlog must be delivered oldest first; got sequence {delivered:?}"
        );
        let unique: std::collections::HashSet<u64> = delivered.iter().copied().collect();
        assert_eq!(
            unique.len(),
            3,
            "a finding was delivered twice after recovery: {delivered:?}"
        );
        drop(captured);
        d.shutdown();
    }

    /// BUG-10: the spool is a FIFO across a restart. Warden is restarted during
    /// an outage; the next process must deliver the recovered records in the order
    /// they were produced — an incident reads from its beginning.
    #[test]
    fn a_restart_delivers_the_recovered_spool_in_produced_order() {
        let dir = temp_dir("restart-order");
        let path = dir.join("bridge_spool.jsonl");
        {
            let mut spool = Spool::open(&path, 1 << 20).unwrap();
            for id in ["a", "b", "c"] {
                spool.append(record(id)).unwrap();
            }
        }

        let (url, bodies, _srv) = capture_serve(|_| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let mut d = Deliverer::start(cfg_for(&url, &dir)).expect("start delivery");

        assert!(
            wait_for(|| d.stats().replayed == 3),
            "all recovered records must be delivered; stats = {:?}",
            d.stats()
        );
        assert!(
            wait_for(|| d.stats().pending_on_disk == 0),
            "the spool must not retain delivered records; stats = {:?}",
            d.stats()
        );

        let captured = bodies.lock().unwrap();
        let ids: Vec<String> = all_findings(&captured)
            .iter()
            .map(|b| {
                let v: serde_json::Value = serde_json::from_slice(b).expect("finding is JSON");
                v["event_id"].as_str().expect("event_id").to_string()
            })
            .collect();
        assert_eq!(
            ids,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "the recovered backlog must be delivered oldest first"
        );
        let s = d.stats();
        assert_eq!(s.dropped, 0, "stats = {s:?}");
        assert_eq!(s.permanent, 0, "stats = {s:?}");
        d.shutdown();
    }

    #[test]
    fn a_transient_failure_is_buffered_and_retried_rather_than_dropped() {
        let (url, _srv) = serve(|i| {
            if i == 0 {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
            }
        });
        let dir = temp_dir("retry");
        let mut d = Deliverer::start(cfg_for(&url, &dir)).expect("start delivery");

        d.enqueue(&finding(), Action::Observed);

        assert!(
            wait_for(|| d.stats().delivered == 1),
            "the finding must be delivered on retry; stats = {:?}",
            d.stats()
        );
        let s = d.stats();
        assert_eq!(s.dropped, 0, "a 503 must never lose a finding");
        assert_eq!(s.transient, 1, "the 503 must be recorded as transient");
        assert_eq!(s.produced, 1);
        assert!(
            wait_for(|| d.stats().pending_on_disk == 0),
            "the spool must not keep a record it has delivered; stats = {:?}",
            d.stats()
        );
        d.shutdown();

        // And the shutdown compacted the file, so a restart has nothing to redo.
        let spool = Spool::open(&dir.join("bridge_spool.jsonl"), 1 << 20).unwrap();
        assert_eq!(
            spool.len(),
            0,
            "delivered records must not survive as a backlog"
        );
    }

    #[test]
    fn a_permanent_rejection_is_not_retried() {
        let (url, _srv) = serve(|_| "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        let dir = temp_dir("perm");
        let mut d = Deliverer::start(cfg_for(&url, &dir)).expect("start delivery");

        d.enqueue(&finding(), Action::Observed);

        assert!(
            wait_for(|| d.stats().permanent == 1),
            "the 400 must be counted as a permanent refusal; stats = {:?}",
            d.stats()
        );
        // Anything else the sender did with it would show up here: a retry, or a
        // record parked on disk forever.
        thread::sleep(Duration::from_millis(400));
        let s = d.stats();
        assert_eq!(s.permanent, 1, "a refusal must not be retried: {s:?}");
        assert_eq!(s.transient, 0, "{s:?}");
        assert_eq!(
            s.pending_on_disk, 0,
            "a refused record must not be kept: {s:?}"
        );
        assert_eq!(
            s.dropped, 0,
            "a refusal is reported, not silently dropped: {s:?}"
        );
        d.shutdown();
    }

    #[test]
    fn an_unreachable_endpoint_spools_durably_and_survives_a_restart() {
        // Bind and immediately release: the port is closed, so connecting is
        // refused. Refused means nothing was stored, so it is transient and the
        // finding is kept.
        let url = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            format!("http://{a}/api/v1/sentinel/host/")
        };
        let dir = temp_dir("down");
        let mut d = Deliverer::start(cfg_for(&url, &dir)).expect("start delivery");

        d.enqueue(&finding(), Action::Observed);
        assert!(
            wait_for(|| d.stats().pending_on_disk == 1),
            "an unreachable Sentinel must send the finding to disk, not to /dev/null; stats = {:?}",
            d.stats()
        );
        assert_eq!(
            d.stats().dropped,
            0,
            "an outage is not a loss while the spool has room"
        );
        d.shutdown();

        // A restarted Warden finds it: this is the whole point of W-05.
        let spool = Spool::open(&dir.join("bridge_spool.jsonl"), 1 << 20).unwrap();
        assert_eq!(spool.len(), 1);
        let rec = spool.front().expect("the finding is on disk");
        let body = String::from_utf8_lossy(&rec.body);
        assert!(
            body.contains("\"event_id\""),
            "the id must be persisted with it: {body}"
        );
        assert!(body.contains("test-host"));
        assert!(body.contains("endpoint:self_tamper"));
        assert!(
            !rec.event_id.is_empty(),
            "the recovered record must expose its id for deduplication"
        );
    }

    #[test]
    fn the_spool_survives_a_full_cap_by_refusing_the_newest_and_saying_so() {
        let dir = temp_dir("cap");
        let path = dir.join("bridge_spool.jsonl");
        // Room for exactly one envelope, derived from the envelope's real size
        // rather than a hand-counted constant, so this test does not silently
        // stop testing the cap the day the envelope grows a field.
        let cap = record("a").body.len() as u64 + 8;
        let mut spool = Spool::open(&path, cap).unwrap();
        assert!(spool.append(record("a")).is_ok());
        match spool.append(record("b")) {
            Err(SpoolError::Full) => {}
            Ok(()) => panic!(
                "the cap must refuse the record that does not fit: {} bytes accepted into a \
                 {cap}-byte spool",
                spool.bytes()
            ),
            Err(SpoolError::Io(e)) => panic!("unexpected io error: {e}"),
        }
        // The oldest is still there: a truncated tail is a reportable boundary,
        // an evicted middle is a silent hole.
        assert_eq!(spool.len(), 1);
        assert_eq!(spool.front().unwrap().event_id, "a");
    }

    #[test]
    fn a_full_spool_of_already_delivered_records_still_accepts_a_new_one() {
        let dir = temp_dir("cap-reclaim");
        let path = dir.join("bridge_spool.jsonl");
        let cap = record("a").body.len() as u64 + 8;
        let mut spool = Spool::open(&path, cap).unwrap();
        spool.append(record("a")).unwrap();
        // `a` is delivered but its line is still in the file, so the physical cap
        // is full while the *undelivered* set is empty. Without reclaiming first,
        // the spool would refuse to buffer during an outage because of records it
        // has already delivered — a backlog that blocks itself.
        spool.pop_delivered();
        assert!(
            spool.append(record("b")).is_ok(),
            "a delivered record must be reclaimed to make room, not hold the cap hostage"
        );
        assert_eq!(spool.len(), 1);
        assert_eq!(spool.front().unwrap().event_id, "b");
    }

    #[test]
    fn compaction_reclaims_the_file_and_never_loses_an_undelivered_record() {
        let dir = temp_dir("compact");
        let path = dir.join("bridge_spool.jsonl");
        let mut spool = Spool::open(&path, 1 << 20).unwrap();
        for id in ["a", "b", "c"] {
            spool.append(record(id)).unwrap();
        }
        let before = spool.bytes();
        spool.pop_delivered(); // a
        spool.compact().unwrap();

        assert!(spool.bytes() < before, "compaction must shrink the file");
        assert_eq!(spool.len(), 2);
        assert_eq!(spool.delivered_count(), 0);

        // Re-open from disk: the survivors are `b` and `c`, in order, and the
        // delivered `a` is gone for good.
        let reopened = Spool::open(&path, 1 << 20).unwrap();
        let ids: Vec<String> = reopened.queued.iter().map(|r| r.event_id.clone()).collect();
        assert_eq!(ids, vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn a_torn_line_from_a_crash_is_skipped_not_delivered() {
        let dir = temp_dir("torn");
        let path = dir.join("bridge_spool.jsonl");
        {
            let mut spool = Spool::open(&path, 1 << 20).unwrap();
            spool.append(record("good")).unwrap();
        }
        // Append a half-written line the way a kill -9 mid-write would leave it.
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"event_id\":\"tor").unwrap();
        }
        let spool = Spool::open(&path, 1 << 20).unwrap();
        assert_eq!(spool.len(), 1, "only the intact line is deliverable");
        assert_eq!(spool.front().unwrap().event_id, "good");
    }

    #[test]
    fn the_spool_is_readable_only_by_its_owner() {
        let dir = temp_dir("mode");
        let path = dir.join("bridge_spool.jsonl");
        let _spool = Spool::open(&path, 1 << 20).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the spool holds command lines and paths; it must not be group- or world-readable"
        );
    }

    #[test]
    fn event_ids_do_not_repeat_within_a_process() {
        let ids: std::collections::HashSet<String> =
            (0..1000).map(|_| next_event_id("host")).collect();
        assert_eq!(
            ids.len(),
            1000,
            "a repeated id would let a dedupe drop a real finding"
        );
    }

    #[test]
    fn an_over_long_host_cannot_push_the_id_past_sentinel_s_column() {
        let id = next_event_id(&"h".repeat(500));
        assert!(
            id.len() < 128,
            "the id is stored in a 128-char column; an over-long one would be a 400, which is \
             permanent, which means a dropped finding ({})",
            id.len()
        );
    }

    /// A record whose body is what the sender would actually put on the wire, so
    /// the spool tests exercise the real line format.
    fn record(id: &str) -> Record {
        Record {
            event_id: id.to_string(),
            body: serde_json::to_vec(&serde_json::json!({
                "source": "warden",
                "event_id": id,
                "host": "test-host",
            }))
            .unwrap(),
        }
    }

    /// The batch shape is Sentinel's contract (`{"findings": [...]}`), and the
    /// bridge exists to use it: one request must carry every record, with each
    /// envelope intact and in order. A shape mismatch here would be a whole-batch
    /// 400 — permanent, and therefore silently dropped findings.
    #[test]
    fn a_batch_request_carries_every_envelope_in_order() {
        let dir = temp_dir("batch-shape");
        let (url, bodies, _srv) = capture_serve(|_| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let client = BridgeClient::new(cfg_for(&url, &dir)).expect("client");

        let outcome = client.deliver_batch(&[record("a"), record("b"), record("c")]);
        assert!(matches!(outcome, Outcome::Delivered), "{outcome:?}");

        let captured = bodies.lock().unwrap();
        assert_eq!(captured.len(), 1, "a batch must be one request, not N");
        let ids: Vec<String> = findings_in(&captured[0])
            .iter()
            .map(|b| {
                let v: serde_json::Value = serde_json::from_slice(b).unwrap();
                v["event_id"].as_str().unwrap().to_string()
            })
            .collect();
        assert_eq!(
            ids,
            vec!["a", "b", "c"],
            "batch members must keep their order"
        );
    }

    /// A single record keeps the original flat shape; Sentinel accepts it and
    /// older peers only understand it.
    #[test]
    fn a_single_record_is_not_wrapped_in_a_batch() {
        let dir = temp_dir("batch-single");
        let (url, bodies, _srv) = capture_serve(|_| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let client = BridgeClient::new(cfg_for(&url, &dir)).expect("client");

        assert!(matches!(
            client.deliver_batch(&[record("only")]),
            Outcome::Delivered
        ));
        let captured = bodies.lock().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&captured[0]).unwrap();
        assert_eq!(v["event_id"], "only");
        assert!(v.get("findings").is_none(), "single findings stay flat");
    }

    /// Compaction rewrites everything still queued. While most of the file is
    /// live that write costs more than it frees — and at the cap it turned every
    /// append into a 64 MiB rewrite. It must wait until delivered >= queued.
    #[test]
    fn compaction_waits_until_most_of_the_file_is_dead() {
        let dir = temp_dir("compact-threshold");
        let path = dir.join("bridge_spool.jsonl");
        let mut spool = Spool::open(&path, 1 << 20).unwrap();
        for id in ["a", "b", "c", "d"] {
            spool.append(record(id)).unwrap();
        }

        spool.pop_delivered_n(1);
        assert!(
            !spool.should_compact(),
            "1 of 3 still live: rewriting is a loss"
        );
        spool.pop_delivered_n(2);
        assert!(
            spool.should_compact(),
            "3 delivered vs 1 live: the rewrite pays"
        );

        spool.pop_delivered_n(1);
        assert!(spool.should_compact(), "an empty queue always compacts");
    }

    // ---- W2K-17: property tests over arbitrary spool input ------------------

    const SPOOL_SEED: u64 = 0x5EED_5E00;
    const SPOOL_ITERS: u32 = 2048;

    #[test]
    fn a_spool_line_is_a_record_only_if_its_id_and_bytes_are_intact() {
        // The spool is read after a crash, by code that cannot assume the file
        // survived cleanly: a torn final line, a truncated write, or (on a host
        // where something else could append) arbitrary bytes. Two properties are
        // load-bearing. (1) `body` must be the line's own bytes EXACTLY — the
        // envelope is resent to Sentinel verbatim, so any re-serialisation here
        // would change the payload Warden signed. (2) the id must be non-empty,
        // because the id is the only thing that makes a re-delivery harmless.
        for i in 0..SPOOL_ITERS {
            let mut a = crate::arb::Arb::new(SPOOL_SEED + i as u64);
            let line: Vec<u8> = match a.u32_below(4) {
                0 => a.bytes_below(300),
                1 => a.text_below(200).into_bytes(),
                2 => {
                    // Valid JSON, random id (including empty and whitespace-only).
                    let id = match a.u32_below(3) {
                        0 => String::new(),
                        1 => " ".repeat(a.u32_below(3) as usize),
                        _ => a.text(20),
                    };
                    serde_json::to_vec(&serde_json::json!({ "event_id": id })).unwrap()
                }
                _ => {
                    // Random JSON shapes that are not an envelope at all.
                    let v = match a.u32_below(5) {
                        0 => serde_json::json!(a.u64_below(1000)),
                        1 => serde_json::json!(a.text(10)),
                        2 => serde_json::json!([a.text(6), a.text(6)]),
                        3 => serde_json::json!({ "event_id": a.u32_below(9) }),
                        _ => serde_json::json!({ "event_id": serde_json::Value::Null }),
                    };
                    serde_json::to_vec(&v).unwrap()
                }
            };

            let parsed = parse_spool_line(&line);
            let Some(rec) = parsed else {
                continue;
            };
            assert!(
                !rec.event_id.is_empty(),
                "iteration {i}: an empty id was accepted"
            );
            assert_eq!(rec.body, line, "iteration {i}: the envelope was rewritten");
            let v: serde_json::Value =
                serde_json::from_slice(&rec.body).unwrap_or_else(|e| panic!("iteration {i}: {e}"));
            assert_eq!(
                v.get("event_id").and_then(|x| x.as_str()),
                Some(rec.event_id.as_str()),
                "iteration {i}: the id does not match the payload it came from"
            );
        }

        // The two explicit reject cases, stated rather than left to the corpus.
        assert!(parse_spool_line(b"{\"event_id\":\"\"}").is_none());
        assert!(parse_spool_line(b"{\"host\":\"x\"}").is_none());
        assert!(parse_spool_line(b"[1,2,3]").is_none());
        assert!(parse_spool_line(b"{\"event_id\":7}").is_none());
        assert!(parse_spool_line(b"{\"event_id\": \"a\",").is_none());
    }

    #[test]
    fn recovery_keeps_every_whole_line_that_sits_around_arbitrary_garbage() {
        // One torn line must cost one finding, not the rest of the file. The
        // garbage is prefixed so it cannot accidentally be a valid envelope, and
        // carries no newline so the line split sees what a crashed append would.
        for i in 0..64u32 {
            let mut a = crate::arb::Arb::new(SPOOL_SEED + 101 * i as u64);
            let dir = temp_dir(&format!("garbage-{i}"));
            let path = dir.join("bridge_spool.jsonl");

            let mut good = Vec::new();
            let mut file_bytes: Vec<u8> = Vec::new();
            let n = 1 + a.u32_below(12) as usize;
            for k in 0..n {
                let id = format!("host:1:{k:x}.0.1");
                let rec = record(&id);
                file_bytes.extend_from_slice(&rec.body);
                file_bytes.push(b'\n');
                good.push(id);
                // Zero to three junk lines between the real ones.
                for _ in 0..a.u32_below(4) {
                    let mut junk = a.bytes_below(120);
                    junk.retain(|b| *b != b'\n');
                    file_bytes.extend_from_slice(b"GARBAGE");
                    file_bytes.extend_from_slice(&junk);
                    file_bytes.push(b'\n');
                }
            }
            // A torn last line, the shape this path exists for.
            if a.boolean() && !good.is_empty() {
                let mut tail = record("host:1:deadbeef.0.1").body;
                let cut = a.u32_below(tail.len() as u32 - 1) as usize + 1;
                tail.truncate(cut);
                file_bytes.extend_from_slice(&tail);
            }
            std::fs::write(&path, &file_bytes).expect("write the test's own spool");

            let spool = Spool::open(&path, 1 << 20).expect("open a spool with garbage in it");
            let recovered = spool.front_batch(spool.len());
            let ids: Vec<&str> = recovered.iter().map(|r| r.event_id.as_str()).collect();
            assert_eq!(
                ids,
                good.iter().map(String::as_str).collect::<Vec<_>>(),
                "iteration {i}: garbage lines changed which findings survived, or their order"
            );
            for (rec, id) in recovered.iter().zip(good.iter()) {
                assert_eq!(&rec.body, &record(id).body, "iteration {i}: {id}");
            }
            drop(spool);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// W2K-27, at the layer that produces the bytes: the verdict is not only in
    /// the journal. A finding that reached Sentinel without saying what this box
    /// did about it was a record an analyst could not use — a kill, a refusal, a
    /// withheld signal and an observe-mode no-op were one identical row. So this
    /// asserts what actually arrives over TCP, including through the batch
    /// coalescing, which is built from these same bodies and must not flatten the
    /// verdict away.
    #[test]
    fn the_delivered_record_says_what_the_responder_did() {
        let (url, bodies, _srv) = capture_serve(|_| "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let dir = temp_dir("verdict-wire");
        let mut d = Deliverer::start(cfg_for(&url, &dir)).expect("start delivery");

        let mut f = finding();
        f.wants_kill = true;
        d.enqueue(&f, Action::Killed);
        d.enqueue(&f, Action::Refused);
        d.enqueue(&f, Action::Unproven);

        assert!(
            wait_for(|| d.stats().delivered == 3),
            "all three findings must reach the sink; stats = {:?}",
            d.stats()
        );
        let flat = all_findings(&bodies.lock().unwrap());
        let words: Vec<String> = flat
            .iter()
            .map(|b| {
                let v: serde_json::Value =
                    serde_json::from_slice(b).expect("delivered body is JSON");
                // The bool that makes "observed" interpretable travels with the
                // word, and here the class was lethal — the two keys are the whole
                // answer to "did this box try?".
                assert_eq!(v["enforcement_requested"], true, "{v}");
                v["action"]
                    .as_str()
                    .expect("the delivered record must carry an action string")
                    .to_string()
            })
            .collect();
        assert_eq!(
            words,
            vec![
                "killed".to_string(),
                "refused".to_string(),
                "unproven".to_string()
            ],
            "each finding must arrive with its own verdict, in the order produced — a shared or \
             missing action would make three different outcomes one row"
        );
        d.shutdown();
    }

    #[test]
    fn self_findings_report_only_a_change_and_never_ask_for_a_kill() {
        let base = DeliveryStats {
            produced: 10,
            delivered: 8,
            replayed: 0,
            transient: 1,
            permanent: 0,
            isolated: 0,
            quarantined: 0,
            spooled: 2,
            dropped: 0,
            queue_depth: 0,
            pending_on_disk: 2,
            spool_bytes: 1200,
        };
        // A healthy steady tick mints nothing: "all is well" rows would bury
        // the real alarm and fill the platform with noise.
        assert!(base.self_finding(&base).is_none());

        // A loss is the loudest case and must be Critical.
        let lost = DeliveryStats { dropped: 3, ..base };
        let f = lost.self_finding(&base).expect("a loss is a self-finding");
        assert_eq!(f.event_type.as_str(), "endpoint:self_degraded");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.detail["lost_since_last_report"], 3);
        assert_eq!(f.detail["kind"], "self_observability");
        assert!(
            !f.wants_kill,
            "an operational finding never asks for a kill"
        );
        assert!(f.target_pid.is_none());

        // Dead-lettering is High; isolation alone is Medium.
        let quarantined = DeliveryStats {
            quarantined: 2,
            ..base
        };
        assert_eq!(
            quarantined.self_finding(&base).unwrap().severity,
            Severity::High
        );
        let isolated = DeliveryStats {
            isolated: 1,
            ..base
        };
        assert_eq!(
            isolated.self_finding(&base).unwrap().severity,
            Severity::Medium
        );

        // Cumulative totals in the detail are echoed for context, but the
        // DELTA is what decides severity — repeating a lifetime total every
        // tick would keep the alarm at Critical forever.
        let still_lost = DeliveryStats { dropped: 3, ..base };
        assert!(still_lost.self_finding(&lost).is_none());
    }

    #[test]
    fn a_named_400_dead_letters_only_the_bad_finding_and_delivers_the_rest() {
        // The regression §۱۳۰ found: one refused finding in a batch of three
        // used to make Sentinel answer 400, Warden classify the batch Permanent
        // and drop all three. Now the server names index 1, that one goes to
        // the dead-letter file and the other two go through on retry.
        const BAD0: &str = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n\
                           {\"errors\":[{\"index\":0,\"reason\":\"x\"}]}";
        const BAD1: &str = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n\
                           {\"errors\":[{\"index\":1,\"reason\":\"x\"}]}";
        const GOOD: &str = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"accepted\":true}";
        // Tie the refusal to the *row*, not to connection order: the worker may
        // drain the channel before all three enqueues land. A connection-indexed
        // reply would then apply index 1 to a one-row batch and dead-letter it
        // with the whole batch detail instead of the named reason, which made
        // this test flaky under parallel `cargo test`. Parse the batch we were
        // actually sent and name the position of the bad finding.
        let (url, server) = serve_body(move |body| {
            let value: serde_json::Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => return GOOD,
            };
            let rows: Vec<&serde_json::Value> = value
                .get("findings")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().collect())
                .unwrap_or_else(|| vec![&value]);
            match rows.iter().position(|f| f["summary"] == "bad-one") {
                Some(0) => BAD0,
                Some(_) => BAD1,
                None => GOOD,
            }
        });
        let dir = temp_dir("isolate-400");
        let mut cfg = cfg_for(&url, &dir);
        cfg.backoff_ms = 5;
        cfg.max_backoff_ms = 20;
        let mut d = Deliverer::start(cfg).expect("start delivery");

        for summary in ["good-a", "bad-one", "good-b"] {
            let mut f = finding();
            f.summary = summary.to_string();
            d.enqueue(&f, Action::Observed);
        }

        assert!(
            wait_for(|| d.stats().quarantined == 1 && d.stats().delivered == 2),
            "the two good findings must survive and the bad one be dead-lettered; stats = {:?}",
            d.stats()
        );
        assert_eq!(d.stats().isolated, 1);
        assert_eq!(d.stats().dropped, 0, "isolation is not a loss");

        let dead = quarantine_path(&cfg_for(&url, &dir));
        let mode = std::fs::metadata(&dead)
            .expect("dead-letter file exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the dead-letter file holds command lines and pids"
        );
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&dead)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["reason"], "x");
        assert!(
            lines[0]["finding"].is_object(),
            "exact envelope kept for replay"
        );
        assert!(lines[0]["quarantined_at"].as_u64().is_some());

        d.shutdown();
        // The listener thread waits for one more connection; like the other
        // tests here, leave it detached rather than joining on a server that
        // has no reason to close itself.
        drop(server);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drop_front_indices_removes_only_the_named_spool_rows() {
        let dir = temp_dir("drop-indices");
        let mut spool = Spool::open(&dir.join("s.jsonl"), 1 << 20).unwrap();
        for i in 0..5 {
            spool
                .append(Record {
                    event_id: format!("e{i}"),
                    body: format!("{{\"event_id\":\"e{i}\"}}").into_bytes(),
                })
                .unwrap();
        }
        assert_eq!(spool.drop_front_indices(&[1, 3]).unwrap(), 2);
        let ids: Vec<String> = spool.queued.iter().map(|r| r.event_id.clone()).collect();
        assert_eq!(ids, vec!["e0", "e2", "e4"]);
        // The file, not just the in-memory image, lost exactly those rows: a
        // restart must not resurrect a finding that was dead-lettered.
        let text = std::fs::read_to_string(dir.join("s.jsonl")).unwrap();
        assert!(!text.contains("e1"), "{text}");
        assert!(!text.contains("e3"), "{text}");
        assert!(text.contains("e2") && text.contains("e4"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drop_front_indices_restores_the_queue_when_rewrite_fails() {
        let dir = temp_dir("drop-indices-failure");
        let spool_path = dir.join("s.jsonl");
        let mut spool = Spool::open(&spool_path, 1 << 20).unwrap();
        for i in 0..5 {
            spool
                .append(Record {
                    event_id: format!("e{i}"),
                    body: format!("{{\"event_id\":\"e{i}\"}}").into_bytes(),
                })
                .unwrap();
        }
        let before = std::fs::read_to_string(&spool_path).unwrap();
        // A directory at the rewrite temp path makes the rewrite fail before any
        // file is replaced: the in-memory queue must not lose those rows either.
        std::fs::create_dir(format!("{}.tmp", spool_path.display())).unwrap();
        assert!(spool.drop_front_indices(&[1, 3]).is_err());
        let ids: Vec<String> = spool.queued.iter().map(|r| r.event_id.clone()).collect();
        assert_eq!(ids, vec!["e0", "e1", "e2", "e3", "e4"]);
        assert_eq!(std::fs::read_to_string(&spool_path).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_leaves_the_append_handle_on_the_published_file() {
        let dir = temp_dir("rewrite-handle");
        let spool_path = dir.join("s.jsonl");
        let mut spool = Spool::open(&spool_path, 1 << 20).unwrap();
        for i in 0..3 {
            spool
                .append(Record {
                    event_id: format!("e{i}"),
                    body: format!("{{\"event_id\":\"e{i}\"}}").into_bytes(),
                })
                .unwrap();
        }
        spool.pop_delivered();
        assert_eq!(spool.drop_front_indices(&[0]).unwrap(), 1);
        spool
            .append(Record {
                event_id: "e3".to_string(),
                body: br#"{"event_id":"e3"}"#.to_vec(),
            })
            .unwrap();
        let disk = std::fs::read_to_string(&spool_path).unwrap();
        assert_eq!(
            disk.lines().count(),
            2,
            "append must land on the renamed file"
        );
        assert!(disk.contains("\"event_id\":\"e2\""));
        assert!(disk.contains("\"event_id\":\"e3\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn isolate_batch_rewrite_failure_keeps_channel_survivors_without_duplicates() {
        let dir = temp_dir("isolate-failure");
        let cfg = cfg_for("http://127.0.0.1:9/api/", &dir);
        let spool = Arc::new(Mutex::new(
            Spool::open(&cfg.spool_path, cfg.spool_max_bytes).unwrap(),
        ));
        let mut batch = Vec::new();
        for i in 0..4 {
            let rec = Record {
                event_id: format!("e{i}"),
                body: format!("{{\"event_id\":\"e{i}\"}}").into_bytes(),
            };
            lock(&spool).append(rec.clone()).unwrap();
            batch.push(rec);
        }
        let channel = Record {
            event_id: "c0".to_string(),
            body: br#"{"event_id":"c0"}"#.to_vec(),
        };
        batch.push(channel.clone());
        std::fs::create_dir(format!("{}.tmp", cfg.spool_path.display())).unwrap();
        let rejected = vec![1usize, 3]
            .into_iter()
            .map(|index| RejectedRecord {
                index,
                event_id: format!("e{index}"),
                body: format!("{{\"event_id\":\"e{index}\"}}").into_bytes(),
                reason: "x".to_string(),
            })
            .collect::<Vec<_>>();
        let c = Counters::default();
        let (survivors, remaining) =
            isolate_batch(&cfg, &c, &spool, &batch, &rejected, "test detail", 4);
        assert_eq!(remaining, 2, "both spooled bad rows are still queued");
        assert_eq!(
            survivors
                .iter()
                .map(|r| r.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e0", "e2", "c0"]
        );
        assert_eq!(c.dropped.load(Ordering::Relaxed), 0);
        // Apply the caller's skip rule: only the channel-only survivor is new.
        for rec in survivors.into_iter().skip(remaining) {
            spool_one(&spool, &c, rec);
        }
        let ids: Vec<String> = lock(&spool)
            .queued
            .iter()
            .map(|r| r.event_id.clone())
            .collect();
        assert_eq!(ids, vec!["e0", "e1", "e2", "e3", "c0"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replay_moves_dead_letters_back_to_the_spool_and_archives_the_file() {
        let dir = temp_dir("replay");
        let spool_path = dir.join("bridge_spool.jsonl");
        let dead = dir.join("bridge_quarantine.jsonl");
        let envelope = serde_json::json!({
            "source": "warden", "event_id": "replay-me",
            "event_type": "endpoint:access_denied", "detail": {"reason": "x"}
        });
        let line = serde_json::json!({
            "quarantined_at": 1, "event_id": "replay-me", "index": 0,
            "reason": "x", "finding": envelope,
        })
        .to_string();
        std::fs::write(&dead, format!("{line}\nnot json\n")).unwrap();

        let (replayed, skipped) = replay_quarantine(&spool_path, &dead).unwrap();
        assert_eq!((replayed, skipped), (1, 1));
        let spooled = std::fs::read_to_string(&spool_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(spooled.trim()).unwrap();
        assert_eq!(v["event_id"], "replay-me");
        assert!(
            !dead.exists(),
            "the original is archived, so replay cannot double-run"
        );
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .any(|e| e.file_name().to_string_lossy().contains(".replayed.")),
            "archive kept for audit"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The spool holds the same bytes as the wire, so a finding that waits out an
    /// outage does not arrive as an amnesiac record a day later. This is the case
    /// the retry path is for, and it is where a verdict would be lost if the
    /// envelope were rebuilt on the way out instead of replayed.
    #[test]
    fn a_spooled_record_keeps_its_verdict_through_the_outage() {
        let url = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            format!("http://{a}/api/v1/sentinel/host/")
        };
        let dir = temp_dir("verdict-spool");
        let mut cfg = cfg_for(&url, &dir);
        cfg.timeout_ms = 200;
        cfg.backoff_ms = 5;
        cfg.max_backoff_ms = 50;
        let mut d = Deliverer::start(cfg).expect("start delivery");

        let mut f = finding();
        f.wants_kill = true;
        d.enqueue(&f, Action::Unverifiable);

        assert!(
            wait_for(|| d.stats().pending_on_disk == 1),
            "the finding must be spooled while the endpoint is dead; stats = {:?}",
            d.stats()
        );
        let text = std::fs::read_to_string(dir.join("bridge_spool.jsonl"))
            .expect("read the spool the outage produced");
        let line = text.lines().next().expect("one spooled finding");
        let v: serde_json::Value = serde_json::from_str(line).expect("spool line is an envelope");
        assert_eq!(v["action"], "unverifiable");
        assert_eq!(v["enforcement_requested"], true);
        d.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
