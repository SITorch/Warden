//! bridge.rs — the Sentinel uplink: how one judged Finding becomes one request,
//! and what the answer to that request is taken to mean.
//!
//! Deliberately a hand-rolled HTTP/1.1 POST over a byte stream: this daemon must
//! stay small and auditable (see Cargo.toml). The shipped transport is cleartext
//! HTTP with TLS terminated at the deployment edge. Phase 8 adds an OPT-IN mTLS
//! transport for per-agent certificates, implemented in `tls.rs` through direct
//! system-OpenSSL FFI — no new crate and no `Cargo.lock` change.
//!
//! This module does one *attempt* and classifies it. It owns no queue, no retry
//! and no disk — that is `src/deliver.rs`, because "the network is down" must
//! not be answered by the thread draining the ring buffer (see W-R6). Every
//! failure here is returned as an `Outcome` rather than an `Err`, so the caller
//! is forced to decide between retrying and giving up instead of accidentally
//! treating both the same way.
//!
//! Deadlines: `timeout_ms` is one budget for the whole attempt — resolve,
//! connect, write, read. It used to be applied separately to connect, read and
//! write, which meant a slow resolver plus a connect that used its full slice
//! plus a read that used its full slice could occupy the caller for several
//! times the configured timeout. A per-attempt budget is the number the operator
//! actually configured, and it is what makes "the drain loop is never blocked
//! for longer than N ms" a statement with a number in it.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::{classify_ip, Bridge, UplinkTarget};
use crate::detect::Finding;
use crate::respond::Action;
use crate::telemetry::SensorHealth;
use crate::tls::{TlsContext, TlsStream};

/// A response larger than this is not read; we only want the status line.
const MAX_RESPONSE: usize = 8192;

/// Version of the host-finding JSON envelope. Sentinel stores it as-is and
/// tolerates both an absent value (a sensor older than this field) and an
/// unfamiliar one (a newer sensor); the version exists so a future change can
/// be recognised rather than guessed from the presence of a key.
pub const HOST_FINDING_SCHEMA_VERSION: &str = "warden.host-finding.v1";

/// The kernel file that reports per-namespace offsets. A non-zero `monotonic`
/// or `boottime` offset means this process's `CLOCK_MONOTONIC` is not the clock
/// `bpf_ktime_get_ns()` stamped into the ring record; converting the two by
/// subtraction would produce a confidently wrong wall time.
pub const TIMENS_OFFSETS_PATH: &str = "/proc/self/timens_offsets";

/// What happened to one attempted kernel-event clock conversion. These are
/// wire values: Sentinel stores the word, so a failed conversion can never be
/// mistaken for an absent kernel event or for an agent observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockConversionStatus {
    NotApplicable,
    Converted,
    ConvertedWithDrift,
    ClockUnreadable,
    TimeNamespaceMismatch,
    FutureEvent,
    UnstableSample,
    ImplausibleTime,
}

impl ClockConversionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ClockConversionStatus::NotApplicable => "not_applicable",
            ClockConversionStatus::Converted => "converted",
            ClockConversionStatus::ConvertedWithDrift => "converted_with_drift",
            ClockConversionStatus::ClockUnreadable => "failed_clock_unreadable",
            ClockConversionStatus::TimeNamespaceMismatch => "failed_time_namespace_mismatch",
            ClockConversionStatus::FutureEvent => "failed_future_event",
            ClockConversionStatus::UnstableSample => "failed_unstable_sample",
            ClockConversionStatus::ImplausibleTime => "failed_implausible_time",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelClockConversion {
    pub unix_ms: Option<u64>,
    pub status: ClockConversionStatus,
    pub reason: Option<&'static str>,
}

impl KernelClockConversion {
    fn failed(status: ClockConversionStatus, reason: &'static str) -> Self {
        Self {
            unix_ms: None,
            status,
            reason: Some(reason),
        }
    }
}

/// Parse `/proc/self/timens_offsets`. Each line is `clock seconds nanoseconds`;
/// only non-zero offsets for the two monotonic-family clocks matter here.
/// Malformed lines are treated as a mismatch rather than silently ignored: a
/// parser that cannot read the one file that decides clock identity must not
/// produce a wall time it cannot justify.
pub fn timens_offsets_are_nonzero(body: &str) -> bool {
    let mut saw_clock = false;
    for line in body.lines() {
        let mut parts = line.split_whitespace();
        let (Some(clock), Some(secs), Some(nsecs)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if clock != "monotonic" && clock != "boottime" {
            continue;
        }
        saw_clock = true;
        if secs != "0" || nsecs != "0" {
            return true;
        }
    }
    // A file with no recognised clock line is unreadable evidence, not proof
    // that every offset is zero. Callers treat that as a mismatch too.
    !saw_clock
}

fn timens_mismatch() -> bool {
    match std::fs::read_to_string(TIMENS_OFFSETS_PATH) {
        Ok(body) => timens_offsets_are_nonzero(&body),
        // A kernel built without time namespaces has no such file. A read
        // failure on a kernel that does have it is not a licence to guess.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// The pure arithmetic half of clock conversion. The three samples are
/// `CLOCK_MONOTONIC`, `CLOCK_REALTIME`, `CLOCK_MONOTONIC` in that order; the
/// midpoint absorbs a realtime step between the two monotonic reads, and a
/// large span is reported rather than hidden.
fn convert_from_samples(
    monotonic_ns: u64,
    mono_before_ns: i128,
    realtime_ns: i128,
    mono_after_ns: i128,
) -> KernelClockConversion {
    if monotonic_ns == 0 {
        return KernelClockConversion {
            unix_ms: None,
            status: ClockConversionStatus::NotApplicable,
            reason: None,
        };
    }
    if mono_after_ns < mono_before_ns {
        return KernelClockConversion::failed(
            ClockConversionStatus::UnstableSample,
            "CLOCK_MONOTONIC moved backwards while sampling",
        );
    }
    if i128::from(monotonic_ns) > mono_after_ns {
        return KernelClockConversion::failed(
            ClockConversionStatus::FutureEvent,
            "the event claims a monotonic time later than the sample",
        );
    }
    let span = mono_after_ns - mono_before_ns;
    let sample_mono_ns = mono_before_ns + span / 2;
    let unix_ns = realtime_ns - sample_mono_ns + i128::from(monotonic_ns);
    if unix_ns < 1_000_000_000_000 {
        return KernelClockConversion::failed(
            ClockConversionStatus::ImplausibleTime,
            "the converted wall time precedes 2001-09-09",
        );
    }
    let ms = match u64::try_from(unix_ns / 1_000_000) {
        Ok(ms) => ms,
        Err(_) => {
            return KernelClockConversion::failed(
                ClockConversionStatus::ImplausibleTime,
                "the converted wall time exceeds u64 milliseconds",
            )
        }
    };
    let (status, reason) = if span > 100_000_000 {
        (
            ClockConversionStatus::ConvertedWithDrift,
            Some("CLOCK_MONOTONIC moved more than 100 ms during sampling"),
        )
    } else {
        (ClockConversionStatus::Converted, None)
    };
    KernelClockConversion {
        unix_ms: Some(ms),
        status,
        reason,
    }
}

fn timespec_ns(t: libc::timespec) -> i128 {
    i128::from(t.tv_sec) * 1_000_000_000 + i128::from(t.tv_nsec)
}

/// Convert one kernel monotonic timestamp to Unix milliseconds with a
/// bracketed, same-instant sample of the two clocks. Every failure carries a
/// distinct status and NO converted timestamp, so the envelope can fall back
/// to agent observation time without shipping contradictory clock lineage.
pub fn kernel_clock_conversion(monotonic_ns: u64) -> KernelClockConversion {
    if monotonic_ns == 0 {
        return KernelClockConversion {
            unix_ms: None,
            status: ClockConversionStatus::NotApplicable,
            reason: None,
        };
    }
    if timens_mismatch() {
        return KernelClockConversion::failed(
            ClockConversionStatus::TimeNamespaceMismatch,
            "CLOCK_MONOTONIC is offset by this process's time namespace",
        );
    }
    unsafe {
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let (mut before, mut real, mut after) = (zero, zero, zero);
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut before) != 0
            || libc::clock_gettime(libc::CLOCK_REALTIME, &mut real) != 0
            || libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut after) != 0
        {
            return KernelClockConversion::failed(
                ClockConversionStatus::ClockUnreadable,
                "clock_gettime failed for CLOCK_MONOTONIC or CLOCK_REALTIME",
            );
        }
        convert_from_samples(
            monotonic_ns,
            timespec_ns(before),
            timespec_ns(real),
            timespec_ns(after),
        )
    }
}

/// A minimally-parsed `http://host[:port]/path` or, with complete Phase 8 mTLS
/// material, `https://host[:port]/path` URL. Cleartext remains the default: an
/// `https://` URL without a client certificate is rejected loudly so a
/// misconfiguration cannot send plaintext to a port expecting TLS — or claim
/// mTLS while presenting no client identity.
/// Choose the identity that TLS must authenticate. An IP literal is always
/// verified as an IP and never gets a configured domain name as SNI; a DNS
/// target may use the explicit override because that is what the operator
/// configured the certificate name to be.
fn tls_identity<'a>(host: &'a str, configured_sni: Option<&'a str>) -> &'a str {
    if host.parse::<IpAddr>().is_ok() {
        host
    } else {
        configured_sni.unwrap_or(host)
    }
}

struct Target {
    /// The resolver host. For a bracketed IPv6 URL this is the BARE literal
    /// (`::1`), because `ToSocketAddrs` does not read `[::1]` — leaving the
    /// brackets in was W2K-40: every attempt failed to resolve, forever, and
    /// the findings spooled without bound.
    host: String,
    /// What goes in the HTTP `Host:` header. RFC 9112 requires an IPv6 literal
    /// to be bracketed *there*, so this is deliberately a different string
    /// from `host` — one value cannot serve both places correctly.
    host_header: String,
    port: u16,
    path: String,
}

impl Target {
    fn parse(url: &str, mtls: bool) -> anyhow::Result<Self> {
        let (rest, tls) = if let Some(r) = url.strip_prefix("http://") {
            (r, false)
        } else if let Some(r) = url.strip_prefix("https://") {
            if !mtls {
                anyhow::bail!(
                    "bridge.url is https:// but no complete Phase 8 mTLS material \
                     (tls_ca_file + tls_cert_file + tls_key_file) was configured"
                );
            }
            (r, true)
        } else {
            anyhow::bail!("bridge.url must start with http:// or https:// (got {url})");
        };

        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, host_header, port) = if let Some(inner) = authority.strip_prefix('[') {
            // Bracketed IPv6, with or without a trailing `:port`. Split on the
            // closing bracket, NOT on ':' — the address itself is full of them.
            let (addr, tail) = inner.split_once(']').ok_or_else(|| {
                anyhow::anyhow!("unclosed '[' in bridge.url (expected [addr]:port): {url}")
            })?;
            if addr.is_empty() {
                anyhow::bail!("empty IPv6 host in bridge.url: {url}");
            }
            let port = match tail {
                "" => {
                    if tls {
                        443
                    } else {
                        80
                    }
                }
                rest if rest.starts_with(':') => rest[1..]
                    .parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("bad port in bridge.url: {tail}"))?,
                rest => anyhow::bail!("garbage after ']' in bridge.url: {rest}"),
            };
            (addr.to_string(), format!("[{addr}]"), port)
        } else if authority.matches(':').count() > 1 {
            // An unbracketed v6 literal was previously parsed by rsplit_once,
            // which silently read `::1` as host `::` and port `1`. Refuse it
            // loudly rather than dial the wrong service.
            anyhow::bail!(
                "unbracketed IPv6 literal in bridge.url: {url} — write it as [addr]:port"
            );
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => {
                    let port = p
                        .parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("bad port in bridge.url: {p}"))?;
                    (h.to_string(), h.to_string(), port)
                }
                None => (
                    authority.to_string(),
                    authority.to_string(),
                    if tls { 443 } else { 80 },
                ),
            }
        };
        if host.is_empty() {
            anyhow::bail!("empty host in bridge.url: {url}");
        }
        Ok(Target {
            host,
            host_header,
            port,
            path: path.to_string(),
        })
    }
}

/// The byte stream under the HTTP/1.1 request. Both variants expose exactly the
/// same `Read`/`Write` surface, so the request/response parser does not need to
/// know which transport carried it.
enum Stream {
    Plain(TcpStream),
    Tls(TlsStream),
}

impl Stream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.set_read_timeout(timeout),
            Self::Tls(s) => s.set_read_timeout(timeout),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

/// One finding, serialized and stamped, ready for the wire. Built once on the
/// producing thread and carried through every retry unchanged — the retry has to
/// be byte-identical, because the `event_id` inside it is what makes a
/// redelivery idempotent on the far side.
#[derive(Clone)]
pub struct Record {
    /// Stable for the life of this record: created once at enqueue and never
    /// regenerated, so a replay is recognisable as a replay.
    pub event_id: String,
    /// The serialized envelope. For a spooled record this is also exactly what
    /// is on disk, line for line, so the queue and the spool cannot disagree
    /// about what was going to be sent.
    pub body: Vec<u8>,
}

/// The verdict on one delivery attempt.
///
/// The split is not cosmetic. A transient failure means the same bytes have a
/// real chance of landing later, so the record is worth keeping and retrying. A
/// permanent one means the server read the request and refused it: replaying it
/// forever would fill the disk with something that can never be accepted, and
/// would bury the real signal — a Warden/Sentinel contract mismatch — under a
/// retry storm. Retrying only what can succeed is the difference between a
/// durable queue and a stuck one.
#[derive(Debug)]
pub enum Outcome {
    Delivered,
    Transient(String),
    Permanent(String),
    /// Sentinel answered 400 and NAMED the findings it refused. Those rows are
    /// dead-lettered at 0600; the rest of the batch is retried, so one bad
    /// finding can no longer cost the up to 63 good ones beside it.
    Isolated {
        rejected: Vec<RejectedRecord>,
        detail: String,
    },
}

/// One index from the backend's `errors[]` array. Kept separate from the
/// record so a malformed server answer cannot fabricate evidence — the caller
/// looks the index up in the batch it actually sent.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub index: usize,
    pub reason: String,
}

/// A finding the backend explicitly refused, with the exact bytes that were
/// on the wire. Kept verbatim so a replay after the contract is fixed sends a
/// byte-identical envelope and the backend's event-id dedupe still recognises
/// it.
#[derive(Debug, Clone)]
pub struct RejectedRecord {
    pub index: usize,
    pub event_id: String,
    pub body: Vec<u8>,
    pub reason: String,
}

/// The raw verdict of one HTTP attempt. Unlike `Outcome` this says nothing
/// about record disposition — only the worker knows whether a record came
/// from the channel or the spool, and therefore where a retry has to go.
#[derive(Debug)]
enum Attempt {
    Accepted,
    Retry(String),
    Refused(String),
    NamedRejections(Vec<Rejection>, String),
}

/// The JSON envelope Sentinel's host-ingest expects. `source` marks these as
/// first-party host findings (distinct from network NDR ingest), `host` stamps
/// the asset so the platform can attribute per-box, and `event_id` identifies
/// *this* finding across retries so a redelivery after a timeout — where the
/// server stored the row but its 200 never reached us — does not become a second
/// row.
///
/// `action` is the responder's verdict on this finding, and it is here because
/// without it the platform could tell that this box judged something and nothing
/// about what it did: "we SIGKILLed the attacker", "we refused to touch a pid we
/// could not name" (`unproven`, W2K-25) and "we are in observe mode, so we only
/// logged it" all arrived as the same record. The journal printed the word and
/// the wire did not, which is what made respond.rs's "shipped in the finding's
/// action trail" a claim no request carried (W2K-27).
///
/// The word is `Action::as_str()` — the same mapping the log line uses, so the
/// two cannot drift apart, and an operator watching either surface reads one
/// vocabulary.
///
/// `enforcement_requested` is `Finding.wants_kill`, and it is the half that makes
/// `action = "observed"` mean something rather than fill the store: requested +
/// observed says the class is lethal and the global mode was observe; not
/// requested says the finding was never kill-eligible (report-only classes such
/// as `endpoint:module_load`), which no mode change would alter. Shipping that
/// bool is why the daemon's mode does not have to travel in the envelope.
///
/// Phase 5 adds three fields:
///
/// - `schema_version` names the envelope contract, so a backend can tell an
///   old spooled line from a new one without inferring it from missing keys.
/// - `agent_id` is the operator's logical asset label (`bridge.host`). It is
///   **not** a cryptographic identity: the uplink uses one shared Sentinel
///   service key and there is no per-agent enrollment/PKI in this build. The
///   backend therefore stores it as evidence, never as an authentication fact.
/// - `sensor_health` is the Phase 1 trust state at the moment of enqueue. A
///   quiet sensor and a deaf sensor must not look identical on the platform.
///   `envelope()` (used by tests and the un-wired path) uses the honest
///   `UNKNOWN` snapshot; the daemon's enqueue path passes its live reading via
///   [`envelope_with_health`].
///
/// No field here ever carries `api_key`: that header is added to the HTTP
/// request by the sender thread, on a trusted loopback/private path, and is
/// never part of a body that can be spooled to disk.
#[cfg(test)]
pub fn envelope(host: &str, event_id: &str, f: &Finding, action: Action) -> serde_json::Value {
    envelope_with_health(host, event_id, f, action, &SensorHealth::unknown())
}

pub fn envelope_with_health(
    host: &str,
    event_id: &str,
    f: &Finding,
    action: Action,
    health: &SensorHealth,
) -> serde_json::Value {
    // Three distinct claims, never collapsed (F-009 and M15):
    // `observed_at_unix_ms` is when the agent built the envelope;
    // `event_time_unix_ms` is the event time actually used for occurred_at;
    // `kernel_event_*` is shipped ONLY when a bracketed, same-time-namespace
    // conversion succeeded. A finding with a monotonic stamp that cannot be
    // converted keeps the agent-observation fallback and says why in
    // `kernel_event_conversion` — it does NOT ship a raw stamp labelled as an
    // agent observation, which is the contradiction the backend rejects.
    let observed_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as u64);
    let raw_kernel_ts = (f.source_ts_ns > 0).then_some(f.source_ts_ns);
    let conversion = match raw_kernel_ts {
        Some(ts) => kernel_clock_conversion(ts),
        None => KernelClockConversion {
            unix_ms: None,
            status: ClockConversionStatus::NotApplicable,
            reason: None,
        },
    };
    let ship_kernel_lineage = raw_kernel_ts.is_some() && conversion.unix_ms.is_some();
    let kernel_event_ts_ns = ship_kernel_lineage.then_some(raw_kernel_ts).flatten();
    let kernel_event_unix_ms = ship_kernel_lineage.then_some(conversion.unix_ms).flatten();
    let event_time_unix_ms = kernel_event_unix_ms.or(observed_at_unix_ms);
    let event_time_source = if ship_kernel_lineage {
        "kernel_monotonic"
    } else {
        "agent_observed_at"
    };

    serde_json::json!({
        "schema_version": HOST_FINDING_SCHEMA_VERSION,
        "agent_id": host,
        "source": "warden",
        "event_id": event_id,
        "host": host,
        // The field name is unchanged for backend compatibility; its meaning
        // is now labelled explicitly by `event_time_source`.
        "event_time_unix_ms": event_time_unix_ms,
        "observed_at_unix_ms": observed_at_unix_ms,
        "kernel_event_ts_ns": kernel_event_ts_ns,
        "kernel_event_unix_ms": kernel_event_unix_ms,
        "kernel_event_clock": if ship_kernel_lineage { Some("CLOCK_MONOTONIC") } else { None },
        "kernel_event_conversion": conversion.status.as_str(),
        "kernel_event_conversion_reason": conversion.reason,
        "event_time_source": event_time_source,
        "event_time_clock": "realtime_unix_ms",
        "event_type": f.event_type,
        "severity": f.severity,
        "summary": f.summary,
        "process": f.process,
        "target_pid": f.target_pid,
        "action": action.as_str(),
        "enforcement_requested": f.wants_kill,
        "sensor_health": health,
        "detail": f.detail,
    })
}

pub struct BridgeClient {
    cfg: Bridge,
    target: Target,
    /// Loaded once at startup from explicit files. `None` means the shipped
    /// cleartext transport; `Some` means every attempt presents the agent cert.
    tls: Option<TlsContext>,
    /// The resolved address, cached after the first success.
    ///
    /// std's resolver has no timeout parameter, so `to_socket_addrs` is the one
    /// operation here that cannot be given a deadline. Resolving once per
    /// process instead of once per finding bounds that exposure to a single
    /// stall at startup rather than a stall on every event during a DNS
    /// incident — which, on the thread that used to do the sending, was the
    /// ring buffer's problem to absorb.
    ///
    /// A refused address (W2K-28) is cached like an accepted one: the refusal is
    /// about the answer, so re-asking cannot change it, and per-finding lookups
    /// during a DNS incident are exactly what this field exists to prevent.
    resolved: Mutex<Option<SocketAddr>>,
}

impl BridgeClient {
    pub fn new(cfg: Bridge) -> anyhow::Result<Self> {
        let target = Target::parse(&cfg.url, cfg.mtls_enabled())?;
        let tls = if cfg.mtls_enabled() {
            Some(TlsContext::new(
                cfg.tls_ca_file.as_ref().expect("validated above"),
                cfg.tls_cert_file.as_ref().expect("validated above"),
                cfg.tls_key_file.as_ref().expect("validated above"),
            )?)
        } else {
            None
        };
        Ok(Self {
            cfg,
            target,
            tls,
            resolved: Mutex::new(None),
        })
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.cfg.timeout_ms)
    }

    fn cached(&self) -> Option<SocketAddr> {
        *self.resolved.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop the cached address so the next attempt resolves again. Called when a
    /// connect fails, since a stale address (a re-created container, a moved
    /// endpoint) is one of the things a connect failure means.
    fn forget(&self) {
        *self.resolved.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn resolve(&self) -> anyhow::Result<SocketAddr> {
        let addr = match self.cached() {
            Some(a) => a,
            None => {
                let addr = (self.target.host.as_str(), self.target.port)
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("bridge host resolved to no addresses"))?;
                *self.resolved.lock().unwrap_or_else(|e| e.into_inner()) = Some(addr);
                addr
            }
        };
        // W2K-28: the gate at the address this request would actually be sent to.
        //
        // `validate()` refuses a publicly routable IP literal and
        // `config::resolve_uplink_names` refuses a NAME whose startup answer is
        // publicly routable — but both judge an answer from a moment that is not
        // the moment the request goes out. Records move, a name can have a public
        // and a private record, and a cached address is dropped and re-resolved
        // after a connect failure. So the classification is re-made here, against
        // the address that is about to receive `X-API-Key` and this finding's
        // command line, executable path and pid in the clear.
        //
        // The refusal is an `Err`, which `post_body` turns into a transient outcome:
        // the finding stays on the host — queued, then spooled — instead of leaving
        // it. Losing the uplink is survivable; the alternative was sending the
        // evidence to a path nobody attested. The address is cached BEFORE this
        // check on purpose: a refused uplink must not pay a fresh DNS lookup for
        // every finding, which is the stall this cache exists to prevent.
        if self.tls.is_none()
            && classify_ip(addr.ip()) == UplinkTarget::Public
            && !self.cfg.allow_public_plaintext
        {
            anyhow::bail!(
                "{} resolves to {addr}, a PUBLICLY ROUTABLE address, and this is cleartext HTTP: \
                 not sending, because the request carries `X-API-Key` plus this finding's \
                 command line, executable path and pid unencrypted. Repoint bridge.url at your \
                 edge's loopback or private-network address, or set \
                 bridge.allow_public_plaintext = true to attest that the path is protected by \
                 something Warden cannot see.",
                self.target.host
            );
        }
        Ok(addr)
    }

    /// How much of the attempt budget is left, or `None` if it is spent.
    fn remaining(&self, started: Instant) -> Option<Duration> {
        self.timeout()
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
    }

    /// Make one delivery attempt for `rec`, bounded by `timeout_ms` end to end.
    pub fn deliver(&self, rec: &Record) -> Outcome {
        match self.post_body(&rec.body, &rec.event_id) {
            Attempt::Accepted => Outcome::Delivered,
            Attempt::Retry(e) => Outcome::Transient(e),
            Attempt::Refused(e) => Outcome::Permanent(e),
            Attempt::NamedRejections(rejections, detail) => {
                // A single finding that the server named: still dead-letter it
                // instead of dropping it. A redelivery after the contract is
                // fixed is safe — the event id is unchanged.
                let reason = rejections
                    .iter()
                    .find(|r| r.index == 0)
                    .map(|r| r.reason.clone())
                    .unwrap_or_else(|| detail.clone());
                Outcome::Isolated {
                    rejected: vec![RejectedRecord {
                        index: 0,
                        event_id: rec.event_id.clone(),
                        body: rec.body.clone(),
                        reason,
                    }],
                    detail,
                }
            }
        }
    }

    /// Deliver several findings in ONE request, using the backend's documented
    /// `{"findings": [...]}` batch shape (bounded by MAX_FINDINGS_PER_BATCH on
    /// the far side). One finding is the single shape; zero is a no-op.
    ///
    /// Sentinel used to validate a batch all-or-nothing, and Warden treated
    /// every 4xx as Permanent and dropped the whole batch. Now a 400 carries
    /// `errors[].index`; the named findings are reported as `Isolated` for
    /// 0600 dead-lettering and the rest are retried. One malformed finding can
    /// no longer destroy up to 63 good ones beside it (§۱۳۰).
    pub fn deliver_batch(&self, recs: &[Record]) -> Outcome {
        match recs {
            [] => Outcome::Delivered,
            [one] => self.deliver(one),
            _ => {
                let mut body =
                    Vec::with_capacity(recs.iter().map(|r| r.body.len() + 1).sum::<usize>() + 16);
                body.extend_from_slice(b"{\"findings\":[");
                for (i, rec) in recs.iter().enumerate() {
                    if i > 0 {
                        body.push(b',');
                    }
                    body.extend_from_slice(&rec.body);
                }
                body.extend_from_slice(b"]}");
                let label = format!("batch of {} (first {})", recs.len(), recs[0].event_id);
                self.map_attempt(self.post_body(&body, &label), recs)
            }
        }
    }

    /// Turn a raw attempt into a record-aware verdict. Only here do the
    /// server's indices become actual records — from the batch WE sent, never
    /// from anything the response invented.
    fn map_attempt(&self, attempt: Attempt, recs: &[Record]) -> Outcome {
        match attempt {
            Attempt::Accepted => Outcome::Delivered,
            Attempt::Retry(e) => Outcome::Transient(e),
            Attempt::Refused(e) => Outcome::Permanent(e),
            Attempt::NamedRejections(rejections, detail) => {
                let mut seen = std::collections::HashSet::new();
                let mut rejected = Vec::new();
                for r in rejections {
                    if !seen.insert(r.index) {
                        continue;
                    }
                    if let Some(rec) = recs.get(r.index) {
                        rejected.push(RejectedRecord {
                            index: r.index,
                            event_id: rec.event_id.clone(),
                            body: rec.body.clone(),
                            reason: r.reason,
                        });
                    }
                }
                if rejected.is_empty() {
                    // The server named indices outside the batch we sent. That is
                    // a contract mismatch, not an instruction to drop evidence:
                    // the worker will dead-letter the whole batch.
                    return Outcome::Permanent(format!(
                        "{detail} (no named index matched a submitted record)"
                    ));
                }
                Outcome::Isolated { rejected, detail }
            }
        }
    }

    /// Build the request head. Extracted from `post_body` so the `Host:` line —
    /// the one place where the bracketed/unbracketed split matters — can be
    /// tested without opening a socket. Never log the returned string: it
    /// carries `X-API-Key`.
    fn request_head(&self, len: usize) -> String {
        format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             X-API-Key: {key}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n",
            path = self.target.path,
            host = self.target.host_header,
            key = self.cfg.api_key,
        )
    }

    fn post_body(&self, body: &[u8], label: &str) -> Attempt {
        let started = Instant::now();
        let budget_ms = self.cfg.timeout_ms;

        let addr = match self.resolve() {
            Ok(a) => a,
            Err(e) => return Attempt::Retry(format!("resolving {}: {e}", self.target.host)),
        };

        let Some(left) = self.remaining(started) else {
            return Attempt::Retry(format!("timeout_ms={budget_ms} spent before connecting"));
        };
        let tcp = match TcpStream::connect_timeout(&addr, left) {
            Ok(s) => s,
            Err(e) => {
                self.forget();
                return Attempt::Retry(format!("connecting to {addr}: {e}"));
            }
        };
        let _ = tcp.set_nodelay(true);

        let Some(left) = self.remaining(started) else {
            return Attempt::Retry(format!("timeout_ms={budget_ms} spent connecting"));
        };
        if let Err(e) = tcp
            .set_write_timeout(Some(left))
            .and_then(|()| tcp.set_read_timeout(Some(left)))
        {
            return Attempt::Retry(format!("setting transport timeout: {e}"));
        }
        // Both timeouts are installed on the fd BEFORE the TLS handshake: a
        // stalled server must not be able to hold the drain loop past the one
        // budget the operator configured.
        let mut stream = match &self.tls {
            Some(ctx) => {
                let hostname = tls_identity(&self.target.host, self.cfg.tls_sni.as_deref());
                match ctx.connect(tcp, hostname) {
                    Ok(s) => Stream::Tls(s),
                    Err(e) => {
                        return Attempt::Retry(format!(
                            "mutual TLS handshake with {hostname}: {e:#}"
                        ));
                    }
                }
            }
            None => Stream::Plain(tcp),
        };

        let req = self.request_head(body.len());
        // A partial write leaves the peer with a truncated request, so it counts
        // as a transient failure — the far side may have seen nothing at all.
        if let Err(e) = stream
            .write_all(req.as_bytes())
            .and_then(|()| stream.write_all(body))
            .and_then(|()| stream.flush())
        {
            return Attempt::Retry(format!("sending {label}: {e}"));
        }

        // Read only the status line first. Draining the body on every success
        // would let a peer that dribbles its response hold the sender for the
        // whole budget; the 400 case reads the short error body separately,
        // below, because that is where the per-index reasons live.
        let mut buf = Vec::with_capacity(256);
        let mut chunk = [0u8; 256];
        loop {
            let Some(left) = self.remaining(started) else {
                return Attempt::Retry(format!(
                    "timeout_ms={budget_ms} spent before a response arrived"
                ));
            };
            if let Err(e) = stream.set_read_timeout(Some(left)) {
                return Attempt::Retry(format!("setting read timeout: {e}"));
            }
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.contains(&b'\n') || buf.len() >= MAX_RESPONSE {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Attempt::Retry(format!(
                        "reading the response: no complete status line within timeout_ms={budget_ms}"
                    ));
                }
                Err(e) => return Attempt::Retry(format!("reading the response: {e}")),
            }
        }

        if buf.is_empty() {
            // Accepted, then closed without answering. Whether the row was
            // stored is unknowable from here, which is exactly the case the
            // event id exists for: retrying is safe because a redelivery is
            // recognisable.
            return Attempt::Retry(format!("{label}: connection closed with no response"));
        }
        let status = match parse_status(&buf) {
            Ok(status) => status,
            Err(e) => return Attempt::Retry(format!("unparseable response: {e}")),
        };

        if status == 400 {
            // A validation refusal carries `errors[].index`. Read the rest of
            // this short body inside the SAME budget; without it we cannot tell
            // which finding was bad and would be back to dropping the batch.
            read_error_body(&mut stream, &mut buf, started, budget_ms);
            return match parse_rejections(&buf) {
                Some((rejections, detail)) => Attempt::NamedRejections(rejections, detail),
                None => Attempt::Refused(
                    "Sentinel host-ingest returned HTTP 400 without a usable errors[] list"
                        .to_string(),
                ),
            };
        }
        classify(status)
    }
}

/// Finish reading a 400 body. Best-effort by design: a truncated answer still
/// leaves us with the bytes we got, and a parse failure degrades to the old
/// whole-batch refusal rather than to a silent drop. Never blocks past the
/// attempt's end-to-end budget.
fn read_error_body(stream: &mut Stream, buf: &mut Vec<u8>, started: Instant, budget_ms: u64) {
    let mut chunk = [0u8; 256];
    while buf.len() < MAX_RESPONSE {
        let Some(left) = budget_ms
            .checked_sub(started.elapsed().as_millis() as u64)
            .map(Duration::from_millis)
            .filter(|d| !d.is_zero())
        else {
            return;
        };
        if stream.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return;
            }
            Err(_) => return,
        }
    }
}

/// Pull `errors[].index` / `errors[].reason` out of a 400 response. The body is
/// untrusted: indices are bounds-checked by the caller against the batch it
/// actually sent, and the reason is truncated for the journal.
fn parse_rejections(resp: &[u8]) -> Option<(Vec<Rejection>, String)> {
    let text = String::from_utf8_lossy(resp);
    let body = if let Some(i) = text.find("\r\n\r\n") {
        &text[i + 4..]
    } else {
        // No CRLF header/body separator: an LF-only separator is required.
        let i = text.find("\n\n")?;
        &text[i + 2..]
    };
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let errors = value.get("errors")?.as_array()?;
    let mut rejections = Vec::new();
    let mut reasons = Vec::new();
    for err in errors {
        let index = err.get("index")?.as_u64()? as usize;
        let reason = err
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("unspecified reason")
            .chars()
            .take(120)
            .collect::<String>();
        reasons.push(format!("[{index}] {reason}"));
        rejections.push(Rejection { index, reason });
    }
    if rejections.is_empty() {
        return None;
    }
    let detail = format!(
        "Sentinel host-ingest returned HTTP 400: {}",
        reasons.join("; ")
    );
    Some((rejections, detail))
}

/// What an HTTP status means for the fate of this attempt. A 400 is handled
/// by the caller with `parse_rejections`, which can isolate individual rows.
fn classify(status: u16) -> Attempt {
    if (200..300).contains(&status) {
        return Attempt::Accepted;
    }
    // 408/425/429 are the server asking for the same request again later; 5xx is
    // the server failing to answer, not refusing to. Everything else in 4xx is
    // the server having read the request and judged it unacceptable — a
    // malformed envelope, a revoked key, an unknown event type — and none of
    // those is repaired by sending it again.
    if status == 408 || status == 425 || status == 429 || status >= 500 {
        Attempt::Retry(format!("Sentinel host-ingest returned HTTP {status}"))
    } else {
        Attempt::Refused(format!("Sentinel host-ingest returned HTTP {status}"))
    }
}

/// Pull the numeric status out of an "HTTP/1.1 200 OK" status line.
///
/// Deliberately strict (W2K-17): the version token must say `HTTP/` and the code
/// must be exactly three ASCII digits, as RFC 9112 requires. The lenient version
/// of this parser accepted any first token, so a peer that answered with
/// `proxy 200` — or a load balancer's non-HTTP banner — read as a successful
/// delivery and the record was dropped from the spool even though nothing
/// confirmed it. A reply we cannot parse is retried instead, which is safe
/// because Sentinel deduplicates on the event id; a reply we wrongly accept is
/// lost.
fn parse_status(resp: &[u8]) -> anyhow::Result<u16> {
    let head = resp
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(&[]);
    let line = String::from_utf8_lossy(head);
    let mut parts = line.split_whitespace();
    let proto = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty response line: {line:?}"))?;
    if !proto.starts_with("HTTP/") {
        anyhow::bail!("not an HTTP status line: {line:?}");
    }
    let code = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("no status code in response: {line:?}"))?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("status code is not three digits: {code:?}");
    }
    code.parse::<u16>()
        .map_err(|_| anyhow::anyhow!("unparseable status code: {code:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{FindingType, ProcessInfo, Severity};

    #[test]
    fn parses_plain_http_url() {
        let t = Target::parse("http://127.0.0.1:8000/api/v1/sentinel/host/", false).unwrap();
        assert_eq!(t.host, "127.0.0.1");
        assert_eq!(t.port, 8000);
        assert_eq!(t.path, "/api/v1/sentinel/host/");
    }

    #[test]
    fn defaults_port_80_and_root_path() {
        let t = Target::parse("http://ingest.internal", false).unwrap();
        assert_eq!(t.port, 80);
        assert_eq!(t.path, "/");
    }

    // ---- W2K-40: one URL must yield a resolver host AND a Host header --------

    #[test]
    fn parses_bracketed_ipv6_with_and_without_a_port() {
        // The resolver gets the bare literal; the header keeps the brackets.
        // Brackets in the resolver host were the bug: `to_socket_addrs` cannot
        // read `[::1]`, so every delivery failed to resolve and the spool grew.
        for (url, expected_host, expected_header, expected_port, expected_path) in [
            (
                "http://[::1]:9099/api/v1/sentinel/host/",
                "::1",
                "[::1]",
                9099,
                "/api/v1/sentinel/host/",
            ),
            ("http://[fd00::5]/api/", "fd00::5", "[fd00::5]", 80, "/api/"),
            (
                "http://[::ffff:192.168.100.10]:9099/x",
                "::ffff:192.168.100.10",
                "[::ffff:192.168.100.10]",
                9099,
                "/x",
            ),
        ] {
            let t = Target::parse(url, false).unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(t.host, expected_host, "{url}");
            assert_eq!(t.host_header, expected_header, "{url}");
            assert_eq!(t.port, expected_port, "{url}");
            assert_eq!(t.path, expected_path, "{url}");
        }
    }

    #[test]
    fn ipv4_and_hostname_urls_keep_the_old_host_header_shape() {
        // The fix must not change what the deployed bridge already sends.
        for url in [
            "http://127.0.0.1:9099/api/v1/sentinel/host/",
            "http://ingest.internal/api/",
        ] {
            let t = Target::parse(url, false).unwrap();
            assert_eq!(t.host, t.host_header, "{url}");
            assert!(!t.host_header.contains('['), "{url}");
        }
    }

    #[test]
    fn rejects_malformed_ipv6_and_ports_loudly() {
        for url in [
            "http://[::1/api/",           // unclosed bracket
            "http://[]:9099/api/",        // empty address
            "http://[::1]junk/api/",      // garbage after ']'
            "http://[::1]:notaport/api/", // bad port
            "http://::1:9099/api/",       // unbracketed v6
            "http://[::1:9099/api/",      // unclosed again
        ] {
            assert!(Target::parse(url, false).is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn the_host_header_brackets_ipv6_but_the_socket_does_not() {
        // The request head is the only place the two values meet. Assert on
        // substrings, never on the whole header — it contains X-API-Key.
        let cfg = bridge_cfg("http://[::1]:9099/api/", "");
        let client = BridgeClient::new(cfg).expect("v6 client");
        assert_eq!(client.target.host, "::1");
        assert_eq!(client.target.host_header, "[::1]");
        let head = client.request_head(2);
        assert!(head.contains("Host: [::1]\r\n"), "header: {head:?}");
        assert!(!head.contains("Host: [::1]:"), "header: {head:?}");
        assert!(
            head.starts_with("POST /api/ HTTP/1.1\r\n"),
            "header: {head:?}"
        );
    }

    #[test]
    fn rejects_https_without_mtls_material_loudly() {
        assert!(Target::parse("https://host/x", false).is_err());
    }

    #[test]
    fn accepts_https_only_with_complete_mtls_material() {
        let t = Target::parse("https://ingest.example/api/", true).unwrap();
        assert_eq!(t.host, "ingest.example");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn ip_literal_targets_ignore_an_sni_override() {
        assert_eq!(
            tls_identity("127.0.0.1", Some("sentinel.internal")),
            "127.0.0.1"
        );
        assert_eq!(tls_identity("::1", Some("sentinel.internal")), "::1");
        assert_eq!(
            tls_identity("sentinel.internal", Some("cert.internal")),
            "cert.internal"
        );
        assert_eq!(tls_identity("sentinel.internal", None), "sentinel.internal");
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(Target::parse("ftp://host/x", false).is_err());
    }

    // ---- W2K-28: the transport gate at the address actually used ---------------

    fn bridge_cfg(url: &str, extra: &str) -> Bridge {
        toml::from_str(&format!(
            "url = \"{url}\"\napi_key = \"k\"\nspool_path = \"/tmp/warden-bridge-test-spool.jsonl\"\n{extra}\n"
        ))
        .expect("bridge table")
    }

    /// A client whose target host is set directly, bypassing `Target::parse`.
    /// Used only to feed the address classifier numeric v6 literals without
    /// going through a resolver; the URL-shape side of W2K-40 is pinned by the
    /// `parses_*` tests below, which call `Target::parse` itself.
    fn client_at(cfg: Bridge, host: &str) -> BridgeClient {
        BridgeClient {
            cfg,
            target: Target {
                host_header: host.to_string(),
                host: host.to_string(),
                port: 9099,
                path: "/".to_string(),
            },
            tls: None,
            resolved: Mutex::new(None),
        }
    }

    #[test]
    fn a_publicly_routable_answer_is_refused_at_the_address_the_request_would_use() {
        // The literal and the name reach the same line of code, because by the time
        // `resolve` answers, both are just an address. Every host here is numeric,
        // so the test never touches a resolver — and the refusal returns before the
        // connect, so it never sends a packet to any of them either.
        for url in [
            "http://203.0.113.9:9099/api/",
            "http://8.8.8.8/api/",
            "http://100.128.0.1/api/",
            "http://1.1.1.1",
        ] {
            let client = BridgeClient::new(bridge_cfg(url, "")).expect("client");
            let err = client
                .resolve()
                .err()
                .unwrap_or_else(|| panic!("{url} must not be sent to unattested"));
            let msg = err.to_string();
            assert!(msg.contains("PUBLICLY ROUTABLE"), "{msg}");
            assert!(msg.contains("allow_public_plaintext"), "{msg}");
            assert!(msg.contains("X-API-Key"), "{msg}");
        }

        // The v6 shapes, and the IPv4-mapped v6 shape that would otherwise smuggle
        // a public v4 past a rule written for four octets.
        for host in ["2606:4700::1", "::ffff:203.0.113.9", "100.128.0.7"] {
            let client = client_at(bridge_cfg("http://203.0.113.9:9099/api/", ""), host);
            let msg = client
                .resolve()
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| panic!("{host} must not be sent to unattested"));
            assert!(msg.contains("PUBLICLY ROUTABLE"), "{msg}");
        }
    }

    #[test]
    fn the_refusal_reaches_the_caller_as_a_transient_outcome() {
        // Transient, not Permanent: a finding whose uplink is refused stays on this
        // host — queued, then spooled — and the operator sees the reason in the
        // journal. The alternative was either dropping the evidence or shipping it
        // unencrypted, and W2K-27 exists precisely because dropping evidence is a
        // security failure of its own.
        let client =
            BridgeClient::new(bridge_cfg("http://203.0.113.9:9099/api/", "")).expect("client");
        match client.map_attempt(client.post_body(b"{}", "w2k-28-test"), &[]) {
            Outcome::Transient(reason) => {
                assert!(reason.contains("203.0.113.9"), "{reason}");
                assert!(reason.contains("PUBLICLY ROUTABLE"), "{reason}");
            }
            other => panic!("a refused send must be transient, got {other:?}"),
        }
    }

    #[test]
    fn an_attested_public_path_and_every_trusted_shape_still_resolve() {
        // The two ways this gate must not break a deployment: the operator attested
        // the path, or the address is loopback / private / CGNAT / ULA — the shapes
        // the shipped config and the documented installs actually use.
        let client = BridgeClient::new(bridge_cfg(
            "http://203.0.113.9:9099/api/",
            "allow_public_plaintext = true",
        ))
        .expect("client");
        assert_eq!(
            client.resolve().expect("attested").ip().to_string(),
            "203.0.113.9"
        );

        for url in [
            "http://127.0.0.1:9099/api/v1/sentinel/host/",
            "http://192.168.100.10:9099/api/",
            "http://10.8.0.5:9099/api/",
            "http://100.64.0.10/api/",
            "http://169.254.1.1/api/",
        ] {
            let client = BridgeClient::new(bridge_cfg(url, "")).expect("client");
            let got = client.resolve();
            assert!(got.is_ok(), "{url} must resolve: {:?}", got.err());
        }

        // The v6 and mapped shapes an operator gets from DNS or writes directly.
        for host in ["::1", "fd00::5", "fe80::1", "::ffff:192.168.100.10"] {
            let client = client_at(bridge_cfg("http://127.0.0.1:9099/api/", ""), host);
            let got = client.resolve();
            assert!(got.is_ok(), "{host} must resolve: {:?}", got.err());
        }
    }

    #[test]
    fn a_refused_uplink_is_cached_and_re_refused_rather_than_re_resolved_per_finding() {
        // Two properties in one: the refused answer does not cause a fresh DNS
        // lookup for every finding (the stall the cache exists to prevent), and
        // when the cache is dropped — which is what a connect failure does — the
        // new answer goes through the same gate. That re-check is the only thing
        // standing between a short-TTL record and cleartext evidence on the public
        // internet, because the classification at load saw a different answer.
        let client = BridgeClient::new(bridge_cfg("http://203.0.113.9/api/", "")).expect("client");
        assert!(client.cached().is_none(), "nothing resolved yet");
        assert!(client.resolve().is_err());
        assert!(
            client.cached().is_some(),
            "a refused address must still be cached: per-finding lookups during a DNS \
             incident are what this field exists to prevent"
        );
        client.forget();
        assert!(client.cached().is_none());
        assert!(
            client.resolve().is_err(),
            "the re-resolved answer is judged again"
        );
    }

    #[test]
    fn parses_status_line() {
        assert_eq!(parse_status(b"HTTP/1.1 202 Accepted\r\n\r\n").unwrap(), 202);
        assert_eq!(parse_status(b"HTTP/1.1 500 Boom\r\n").unwrap(), 500);
    }

    // ---- W2K-17: property tests over arbitrary peer replies -------------------

    const HTTP_SEED: u64 = 0x5EED_4B50;
    const HTTP_ITERS: u32 = 4096;

    #[test]
    fn any_bytes_a_peer_sends_produce_a_verdict_and_never_a_panic() {
        // This parser runs on bytes off a socket, in the process that owns the
        // durable spool. Two properties are load-bearing: it must not panic on
        // any input, and a success it reports must be a success the peer
        // actually spelled out — never something inferred from noise.
        for i in 0..HTTP_ITERS {
            let mut a = crate::arb::Arb::new(HTTP_SEED + i as u64);
            let resp: Vec<u8> = match a.u32_below(4) {
                0 => a.bytes_below(300),
                1 => a.text_below(200).into_bytes(),
                2 => {
                    // Well-formed prefix, random code token.
                    let code = a.text(6);
                    format!("HTTP/1.1 {code} reason\r\n\r\n").into_bytes()
                }
                _ => {
                    // Random first token, plausible code.
                    let word = a.text(9);
                    format!("{word} {}\r\n\r\n", a.u32_below(1000)).into_bytes()
                }
            };

            match parse_status(&resp) {
                Err(_) => continue,
                Ok(status) => {
                    let head = String::from_utf8_lossy(
                        resp.split(|&b| b == b'\r' || b == b'\n')
                            .next()
                            .unwrap_or(&[]),
                    );
                    let mut parts = head.split_whitespace();
                    assert!(
                        parts.next().unwrap_or_default().starts_with("HTTP/"),
                        "iteration {i}: {resp:?} was accepted as HTTP without saying so"
                    );
                    let token = parts.next().unwrap_or_default();
                    assert_eq!(
                        token.len(),
                        3,
                        "iteration {i}: accepted a status token that is not three digits: \
                         {token:?} from {resp:?}"
                    );
                    assert!(
                        token.bytes().all(|b| b.is_ascii_digit()),
                        "iteration {i}: accepted a non-numeric status token {token:?}"
                    );
                    assert_eq!(
                        token.parse::<u16>().ok(),
                        Some(status),
                        "iteration {i}: the reported code {status} is not the token {token:?}"
                    );
                }
            }
        }

        // The shapes this tightening exists for, stated rather than left to the
        // corpus: an HTTP-shaped verdict must not be inferred from a peer that
        // never spoke HTTP, nor from a code with a sign, a pad, or a length the
        // protocol does not allow.
        for not_http in [
            b"proxy 200 OK\r\n\r\n".as_slice(),
            b"200 OK\r\n".as_slice(),
            b"SSH-2.0-OpenSSH 200\r\n".as_slice(),
            b"HTTP/1.1 +200 OK\r\n".as_slice(),
            b"HTTP/1.1 00200 OK\r\n".as_slice(),
            b"HTTP/1.1 20 OK\r\n".as_slice(),
            b"HTTP/1.1 20o OK\r\n".as_slice(),
            // U+0662 U+0660 U+0662: Arabic-Indic "202", three characters, valid
            // UTF-8, and not one ASCII digit among them.
            b"HTTP/1.1 \xd9\xa2\xd9\xa0\xd9\xa2 OK\r\n".as_slice(),
            b"\r\n".as_slice(),
            b"".as_slice(),
        ] {
            assert!(
                parse_status(not_http).is_err(),
                "{not_http:?} is not a status line"
            );
        }
    }

    #[test]
    fn every_status_the_wire_can_carry_gets_exactly_one_retry_verdict() {
        // Exhaustive over u16, because the failure modes are silent in
        // production: `Delivered` removes the record from the spool, so one
        // non-2xx that classifies as success loses a finding permanently, and
        // one 4xx that classifies as transient replays a poisoned request
        // forever.
        for status in 0u16..=u16::MAX {
            let outcome = classify(status);
            let retryable = status == 408 || status == 425 || status == 429 || status >= 500;
            match &outcome {
                Attempt::Accepted => assert!(
                    (200..300).contains(&status),
                    "{status}: Accepted must mean 2xx and nothing else"
                ),
                Attempt::Retry(m) => {
                    assert!(
                        m.contains(&status.to_string()),
                        "{status}: the verdict must name the code the operator will grep for"
                    );
                    assert!(
                        retryable,
                        "{status}: classified Transient but the contract says give up — it would \
                         be retried forever"
                    );
                }
                Attempt::Refused(m) => {
                    assert!(
                        m.contains(&status.to_string()),
                        "{status}: the verdict must name the code the operator will grep for"
                    );
                    assert!(
                        !retryable && !(200..300).contains(&status),
                        "{status}: classified Refused but it is a success or a retry"
                    );
                }
                Attempt::NamedRejections(_, _) => {
                    panic!("classify() never names records; post_body handles 400 bodies")
                }
            }
        }
    }

    #[test]
    fn parses_per_index_rejections_from_a_400_body() {
        let resp = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\
                     Content-Length: 78\r\n\r\n\
                     {\"accepted\":false,\"errors\":[{\"index\":1,\"reason\":\"unknown event type\"},\
                      {\"index\":5,\"reason\":\"bad event_id\"}]}";
        let (rejections, detail) = parse_rejections(resp).expect("named rejections");
        assert_eq!(rejections.len(), 2);
        assert_eq!(rejections[0].index, 1);
        assert_eq!(rejections[0].reason, "unknown event type");
        assert_eq!(rejections[1].index, 5);
        assert!(detail.contains("HTTP 400"), "{detail}");
        assert!(detail.contains("[1] unknown event type"), "{detail}");
        assert!(detail.contains("[5] bad event_id"), "{detail}");
    }

    #[test]
    fn a_400_without_a_usable_errors_list_is_a_plain_refusal() {
        for resp in [
            &b"HTTP/1.1 400 Bad Request\r\n\r\nnot json"[..],
            &b"HTTP/1.1 400 Bad Request\r\n\r\n{\"accepted\":false}"[..],
            &b"HTTP/1.1 400 Bad Request\r\n\r\n{\"errors\":[]}"[..],
            &b"HTTP/1.1 400 Bad Request\r\n\r\n{\"errors\":[{\"index\":\"x\"}]}"[..],
        ] {
            assert!(parse_rejections(resp).is_none(), "must refuse whole batch");
        }
    }

    #[test]
    fn only_named_indices_in_the_batch_become_rejected_records() {
        let recs: Vec<Record> = (0..3)
            .map(|i| Record {
                event_id: format!("evt-{i}"),
                body: format!("{{\"event_id\":\"evt-{i}\"}}").into_bytes(),
            })
            .collect();
        let client = BridgeClient::new(bridge_cfg("http://127.0.0.1:9099/api/", "")).unwrap();
        let attempt = Attempt::NamedRejections(
            vec![
                Rejection {
                    index: 1,
                    reason: "bad type".into(),
                },
                Rejection {
                    index: 1,
                    reason: "duplicate index".into(),
                },
                Rejection {
                    index: 99,
                    reason: "invented by a broken server".into(),
                },
            ],
            "detail".into(),
        );
        match client.map_attempt(attempt, &recs) {
            Outcome::Isolated { rejected, .. } => {
                assert_eq!(
                    rejected.len(),
                    1,
                    "dupes and out-of-range indices are ignored"
                );
                assert_eq!(rejected[0].index, 1);
                assert_eq!(rejected[0].event_id, "evt-1");
                assert_eq!(rejected[0].reason, "bad type");
                assert_eq!(
                    rejected[0].body, recs[1].body,
                    "replay must be byte-identical"
                );
            }
            other => panic!("expected isolation, got {other:?}"),
        }
        // A server that names nothing we sent cannot make us drop the batch.
        let bogus = Attempt::NamedRejections(
            vec![Rejection {
                index: 42,
                reason: "nope".into(),
            }],
            "detail".into(),
        );
        assert!(matches!(
            client.map_attempt(bogus, &recs),
            Outcome::Permanent(_)
        ));
    }

    /// The retry decision is the whole point of this module, so it is asserted
    /// against a table rather than spot checks: the two ways of getting it wrong
    /// are retrying a refusal forever and giving up on a server that was merely
    /// busy, and both are silent in production.
    #[test]
    fn status_classification_matches_the_retry_contract() {
        for s in [200u16, 201, 202, 204, 299] {
            assert!(matches!(classify(s), Attempt::Accepted), "{s} is a success");
        }
        for s in [408u16, 425, 429, 500, 502, 503, 504, 599] {
            assert!(
                matches!(classify(s), Attempt::Retry(_)),
                "{s} must be retried: the server asked for the request again, or failed to \
                 answer it"
            );
        }
        // Redirects are not delivery confirmations. The hand-rolled client does
        // not follow them, so treating 3xx as success would drop a finding that
        // never reached an ingester; treating it as retry would replay a request
        // to an untrusted destination. Both must be refused.
        for s in [
            301u16, 302, 307, 308, 400, 401, 403, 404, 409, 413, 422, 499,
        ] {
            assert!(
                matches!(classify(s), Attempt::Refused(_)),
                "{s} must NOT be retried or accepted: replaying a request the server called \
                 unacceptable can never succeed and would fill the spool with poison"
            );
        }
    }

    fn finding(wants_kill: bool) -> Finding {
        Finding {
            source_ts_ns: 0,
            event_type: FindingType::ProcessCreation,
            severity: Severity::High,
            summary: "s".to_string(),
            process: ProcessInfo {
                pid: 1,
                ppid: 0,
                uid: 0,
                comm: "c".to_string(),
                exe: None,
                cmdline: None,
                cgroup: None,
                starttime: None,
            },
            target_pid: None,
            wants_kill,
            detail: serde_json::json!({}),
        }
    }

    /// The event id has to be in the envelope, because that is the only place
    /// the far side can read it: Sentinel has no header for it, and a body field
    /// the backend does not know about is dropped silently (which is why the
    /// backend change accompanies this one).
    #[test]
    fn an_impossible_monotonic_stamp_is_not_converted_to_wall_time() {
        // Zero is the "no kernel event" sentinel, and a value larger than the
        // same-instant CLOCK_MONOTONIC reading would put the event in the
        // kernel's future. Both must stay None AND carry distinct statuses so
        // the envelope can fall back to agent observation time and say why.
        let absent = kernel_clock_conversion(0);
        assert_eq!(absent.unix_ms, None);
        assert_eq!(absent.status, ClockConversionStatus::NotApplicable);
        let future = kernel_clock_conversion(u64::MAX);
        assert_eq!(future.unix_ms, None);
        assert_eq!(future.status, ClockConversionStatus::FutureEvent);
        assert_eq!(kernel_clock_conversion(0).unix_ms, None);
        assert_eq!(kernel_clock_conversion(u64::MAX).unix_ms, None);
    }

    #[test]
    fn bracketed_samples_reject_broken_clock_readings_and_report_drift() {
        let real = 1_700_000_000_000_000_000i128;
        let mono = 100_000_000_000_000_000i128;
        let event = (mono - 5_000_000_000) as u64;
        let ok = convert_from_samples(event, mono, real, mono);
        assert_eq!(ok.status, ClockConversionStatus::Converted);
        let event_ms = ok.unix_ms.unwrap();
        assert_eq!(event_ms, (real / 1_000_000 - 5_000) as u64);

        let backwards = convert_from_samples(event, mono, real, mono - 1);
        assert_eq!(backwards.status, ClockConversionStatus::UnstableSample);
        assert_eq!(backwards.unix_ms, None);

        let drift = convert_from_samples(event, mono, real, mono + 200_000_000);
        assert_eq!(drift.status, ClockConversionStatus::ConvertedWithDrift);
        assert!(drift.unix_ms.is_some());
        assert!(drift.reason.unwrap().contains("100 ms"));
    }

    #[test]
    fn a_time_namespace_offset_is_detected_before_any_conversion() {
        assert!(timens_offsets_are_nonzero("monotonic 12 0\nboottime 0 0\n"));
        assert!(timens_offsets_are_nonzero("monotonic 0 0\nboottime 0 7\n"));
        assert!(!timens_offsets_are_nonzero("monotonic 0 0\nboottime 0 0\n"));
        assert!(
            timens_offsets_are_nonzero("unrecognised clock line\n"),
            "an unreadable clock identity must fail closed"
        );
    }

    #[test]
    fn a_failed_conversion_ships_no_kernel_lineage_and_does_not_mislabel_the_event() {
        let mut f = finding(false);
        f.source_ts_ns = u64::MAX;
        let env = envelope("web-01", "id-failed", &f, Action::Observed);
        assert_eq!(env["event_time_source"], "agent_observed_at");
        assert_eq!(env["event_time_unix_ms"], env["observed_at_unix_ms"]);
        assert_eq!(
            env["kernel_event_conversion"],
            ClockConversionStatus::FutureEvent.as_str()
        );
        assert!(
            env["kernel_event_ts_ns"].is_null(),
            "a raw monotonic stamp must not ship beside an agent-observed label: {env}"
        );
        assert!(env["kernel_event_unix_ms"].is_null());
        assert!(env["kernel_event_clock"].is_null());
        assert!(
            env["kernel_event_conversion_reason"]
                .as_str()
                .unwrap()
                .len()
                > 10
        );
    }

    #[test]
    fn the_envelope_carries_the_event_id() {
        let f = finding(false);

        let env = envelope("web-01", "web-01-42-abc", &f, Action::Observed);
        assert_eq!(env["event_id"], "web-01-42-abc");
        assert_eq!(env["host"], "web-01");
        assert_eq!(env["source"], "warden");
        // The bool keeps its own name locally and travels under another one:
        // `wants_kill` is `#[serde(skip)]` on `Finding`, and what the platform is
        // given is `enforcement_requested` — the same fact, named for what the
        // reader can do with it. Two spellings of it in one body would let the
        // two drift, so the local name must stay off the wire.
        assert!(env.get("wants_kill").is_none());
    }

    #[test]
    fn a_finding_without_a_kernel_event_is_labelled_agent_observed() {
        let f = finding(false);
        assert_eq!(f.source_ts_ns, 0);
        let env = envelope("web-01", "id-1", &f, Action::Observed);
        assert_eq!(env["event_time_source"], "agent_observed_at");
        assert_eq!(env["event_time_unix_ms"], env["observed_at_unix_ms"]);
        assert_eq!(
            env["kernel_event_conversion"],
            ClockConversionStatus::NotApplicable.as_str()
        );
        assert!(env["kernel_event_ts_ns"].is_null());
        assert!(env["kernel_event_unix_ms"].is_null());
        assert!(env["kernel_event_clock"].is_null());
    }

    #[test]
    fn a_kernel_stamped_finding_ships_both_clocks_without_substituting_them() {
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut mono = zero;
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono) },
            0
        );
        let mono_ns = (mono.tv_sec as u64) * 1_000_000_000 + mono.tv_nsec as u64;
        let mut f = finding(false);
        f.source_ts_ns = mono_ns - 5_000_000_000; // the event happened 5 s ago
        let wall_now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let env = envelope("web-01", "id-2", &f, Action::Observed);
        assert_eq!(env["event_time_source"], "kernel_monotonic");
        let status = env["kernel_event_conversion"].as_str().unwrap();
        assert!(
            status == ClockConversionStatus::Converted.as_str()
                || status == ClockConversionStatus::ConvertedWithDrift.as_str(),
            "a valid kernel stamp must convert, got {status}: {env}"
        );
        assert_eq!(env["kernel_event_clock"], "CLOCK_MONOTONIC");
        assert_eq!(env["kernel_event_ts_ns"], f.source_ts_ns);
        let event_ms = env["event_time_unix_ms"].as_u64().unwrap();
        assert!(
            event_ms <= wall_now_ms,
            "kernel event in the future: {event_ms}"
        );
        assert!(
            wall_now_ms - event_ms >= 4_000 && wall_now_ms - event_ms < 15_000,
            "kernel event time was not preserved: event={event_ms} now={wall_now_ms}"
        );
        assert!(env["observed_at_unix_ms"].as_u64().unwrap() >= event_ms);
    }

    /// The mapping from a verdict to its wire word, written out here rather than
    /// read from `Action::as_str`, because that is the point of the test: two
    /// independent statements of the mapping, compared. Change one spelling of a
    /// word and this goes red; add an eighth `Action` variant and the match below
    /// stops compiling until the new verdict has a name an analyst can grep for.
    fn the_word_this_verdict_sends(action: Action) -> &'static str {
        match action {
            Action::Observed => "observed",
            Action::Killed => "killed",
            Action::Refused => "refused",
            Action::IdentityChanged => "identity-changed",
            Action::Failed => "failed",
            Action::Unverifiable => "unverifiable",
            Action::Unproven => "unproven",
        }
    }

    /// W2K-27: the responder's verdict is part of the finding's record. Before
    /// this, `act`'s answer went to the journal and nowhere else, so a kill, a
    /// refusal, a withheld signal and an observe-mode no-op were the same row on
    /// the platform side.
    #[test]
    fn every_verdict_the_responder_can_return_rides_the_envelope() {
        for action in [
            Action::Observed,
            Action::Killed,
            Action::Refused,
            Action::IdentityChanged,
            Action::Failed,
            Action::Unverifiable,
            Action::Unproven,
        ] {
            let env = envelope("web-01", "id", &finding(true), action);
            assert_eq!(
                env["action"],
                the_word_this_verdict_sends(action),
                "{action:?} must reach Sentinel as a word, and the wire and the journal must \
                 not be able to disagree about which one"
            );
            assert_eq!(
                env["action"],
                serde_json::Value::String(action.as_str().to_string()),
                "{action:?}: the shipped value must be the string itself, not a nested object \
                 or a number a monitor would have to reinterpret"
            );
        }
    }

    /// `enforcement_requested` is what makes `action = "observed"` a fact instead
    /// of a shrug: with it true the class is lethal and the global mode said no,
    /// with it false the finding was never kill-eligible and no mode change would
    /// have made it so. So it must track `Finding::wants_kill` exactly, both ways.
    #[test]
    fn the_envelope_says_whether_enforcement_was_ever_on_the_table() {
        assert_eq!(
            envelope("h", "id", &finding(true), Action::Killed)["enforcement_requested"],
            true,
            "a lethal class that was killed must say enforcement was requested"
        );
        assert_eq!(
            envelope("h", "id", &finding(false), Action::Observed)["enforcement_requested"],
            false,
            "a report-only class must not claim enforcement was requested"
        );
    }

    /// Phase 5: version + logical agent label + sensor trust on every body.
    /// `agent_id` is the operator's asset label, NOT a cryptographic identity:
    /// the bridge has one shared service key and no per-agent PKI, so the
    /// backend must treat it as evidence rather than as authentication.
    #[test]
    fn the_envelope_is_versioned_and_carries_a_secret_free_health_snapshot() {
        let env = envelope("web-01", "web-01-42-abc", &finding(true), Action::Observed);
        assert_eq!(env["schema_version"], HOST_FINDING_SCHEMA_VERSION);
        assert_eq!(env["agent_id"], "web-01");
        assert_eq!(env["sensor_health"]["state"], "UNKNOWN");
        assert_eq!(env["sensor_health"]["ring_loss"], "UNKNOWN");
        assert!(env["sensor_health"]["loss_rate"].is_null());

        let degraded = crate::telemetry::SensorHealth {
            state: "DEGRADED",
            ring_loss: "VERIFIED",
            loss_rate: Some(0.26),
            source: "live ring counters and declared blind spots",
        };
        let env =
            envelope_with_health("web-01", "id", &finding(false), Action::Observed, &degraded);
        assert_eq!(env["sensor_health"]["state"], "DEGRADED");
        assert_eq!(env["sensor_health"]["ring_loss"], "VERIFIED");
        assert_eq!(env["sensor_health"]["loss_rate"], 0.26);

        // The request header is applied by the sender thread and never becomes
        // part of a body that can be spooled to disk.
        let wire = serde_json::to_string(&env).unwrap();
        for needle in ["api_key", "api-key", "API-Key", "X-API-Key"] {
            assert!(!wire.contains(needle), "{needle} leaked into the envelope");
        }
    }
}
