//! heartbeat.rs — the dead-man's-switch. Warden can't guarantee it survives a
//! determined attacker on the box; what it *can* do is make its own death
//! loud. A background thread pings an off-box collector every `interval_secs`.
//! A gap in that beat is the alarm — evaluated on the far side, where the
//! attacker on this host has no reach.
//!
//! Same cleartext-HTTP-at-the-edge stance as bridge.rs, and the same "never
//! block anything important" contract: the beat runs on its own thread and a
//! failed ping is logged, not fatal.
//!
//! AUTHENTICATION: an unauthenticated beat is forgeable — an attacker who reads
//! the collector URL out of warden.toml could POST fake "alive" beats to mask a
//! takedown. So when `secret` is set, each beat carries `seq`, `ts`, and an
//! HMAC-SHA256 over `host|seq|ts`; the collector verifies the MAC (origin) and
//! that `seq` strictly climbs (anti-replay). The seq is persisted 0600 so it
//! keeps climbing across restarts. The secret authenticates liveness; it is not
//! confidentiality — the beat body is not sensitive.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::Heartbeat;
use crate::hmac::{hex, hmac_sha256};

/// Spawn the heartbeat thread. Returns a handle whose `stop()` (or drop) ends
/// the loop cleanly. Ok(None) when no heartbeat is configured.
pub fn spawn(cfg: Option<Heartbeat>, host: String) -> anyhow::Result<Option<HeartbeatHandle>> {
    let cfg = match cfg {
        Some(c) => c,
        None => return Ok(None),
    };
    // Validate the URL once up front so a typo fails at startup, not silently
    // every interval forever.
    let target = Target::parse(&cfg.url)?;
    if cfg.secret.is_none() {
        log::warn!(
            "heartbeat has no `secret` — beats are UNAUTHENTICATED and forgeable; \
             set heartbeat.secret and verify the MAC off-box"
        );
    }
    // Seed the monotonic sequence from the persisted value so a restart does not
    // replay low numbers the collector has already seen.
    let mut seq = read_seq(&cfg.seq_file);
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();

    let handle = thread::Builder::new()
        .name("warden-heartbeat".into())
        .spawn(move || {
            let interval = Duration::from_secs(cfg.interval_secs.max(1));
            // W-03: report a persistence failure once, then only at debug — an
            // unwritable seq file would otherwise warn every interval for the
            // life of the process. Reset on success so a later break warns again.
            let mut persist_reported = false;
            while flag.load(Ordering::Relaxed) {
                seq = seq.wrapping_add(1);
                match persist_seq(&cfg.seq_file, seq) {
                    Ok(()) => persist_reported = false,
                    Err(why) if !persist_reported => {
                        log::warn!(
                            "heartbeat: the beat sequence is NOT being persisted — {why}. \
                             Beats keep being sent, but after a restart seq begins from the \
                             last value on disk and the collector's anti-replay may reject \
                             them until it climbs past what it already accepted (a false \
                             outage off-box). The default path sits under StateDirectory=warden."
                        );
                        persist_reported = true;
                    }
                    Err(why) => log::debug!("heartbeat: beat sequence still not persisted: {why}"),
                }
                match beat(&target, &host, interval, cfg.secret.as_deref(), seq) {
                    Ok(()) => log::debug!("heartbeat ok → {} (seq={seq})", cfg.url),
                    Err(e) => log::warn!("heartbeat failed → {}: {e}", cfg.url),
                }
                // Sleep in short slices so stop() is responsive, not blocked for
                // a whole interval.
                let mut slept = Duration::ZERO;
                let slice = Duration::from_millis(250);
                while slept < interval && flag.load(Ordering::Relaxed) {
                    thread::sleep(slice);
                    slept += slice;
                }
            }
            log::info!("heartbeat thread stopping");
        })?;

    Ok(Some(HeartbeatHandle {
        running,
        join: Some(handle),
    }))
}

pub struct HeartbeatHandle {
    running: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl HeartbeatHandle {
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for HeartbeatHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Target {
    host: String,
    port: u16,
    path: String,
}

impl Target {
    fn parse(url: &str) -> anyhow::Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("heartbeat.url must start with http:// (got {url})"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| anyhow::anyhow!("bad port in heartbeat.url: {p}"))?,
            ),
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            anyhow::bail!("empty host in heartbeat.url: {url}");
        }
        Ok(Target {
            host,
            port,
            path: path.to_string(),
        })
    }
}

/// Longest status line we will buffer from a peer. The real one is ~20 bytes;
/// this bounds a hostile or broken collector that streams without a CRLF.
const MAX_STATUS_BYTES: usize = 512;

/// The status code from an HTTP/1.x response's status line, if there is one.
///
/// Deliberately narrow: only `HTTP/<version> <code>` at the very start of the
/// line is accepted, with a code of exactly three ASCII digits (RFC 9112).
/// Anything else — an empty response, a non-HTTP banner, a truncated line, a
/// code with a sign or a pad — is `None`, which the caller treats as a failed
/// beat rather than a success. The strictness is the point: this value decides
/// whether a beat counts as alive, and a liveness signal that can be satisfied
/// by a proxy's stray text is worse than no signal.
fn parse_status(head: &[u8]) -> Option<u16> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let rest = line.strip_prefix("HTTP/")?;
    let mut parts = rest.split_whitespace();
    parts.next()?;
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse::<u16>().ok()
}

/// Resolution budget: the smaller of the caller's window and this cap. DNS
/// normally answers in milliseconds; a stalled resolver must not eat the whole
/// beat interval, and the cap keeps the failure mode at "one late beat".
const DNS_BUDGET_CAP: Duration = Duration::from_secs(5);

/// Ceiling on resolver threads stuck inside libc at once. `getaddrinfo` has no
/// timeout of its own (resolv.conf's options timeout/attempts are the only
/// bound) and a `std::thread` cannot be cancelled, so without this cap a
/// black-holed DNS server makes every beat detach another blocked thread.
const MAX_INFLIGHT_RESOLVERS: usize = 2;

static INFLIGHT_RESOLVERS: AtomicUsize = AtomicUsize::new(0);

/// One slot in the bounded resolver pool. The lookup thread holds it until libc
/// returns — however long that takes — so a wedged lookup costs a slot, never an
/// unbounded thread; a new beat that finds the pool full fails fast instead.
struct ResolverSlot;

impl ResolverSlot {
    fn try_acquire() -> Option<Self> {
        let mut current = INFLIGHT_RESOLVERS.load(Ordering::Acquire);
        loop {
            if current >= MAX_INFLIGHT_RESOLVERS {
                return None;
            }
            match INFLIGHT_RESOLVERS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ResolverSlot),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for ResolverSlot {
    fn drop(&mut self) {
        INFLIGHT_RESOLVERS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Resolve `host:port` with a hard deadline. An IP literal — the common
/// production shape of `heartbeat.url` — short-circuits and never touches the
/// resolver. A hostname lookup runs on a helper thread so the beat can give up at
/// the deadline; the resolver slot stays with that thread until libc returns.
fn resolve_bounded(host: &str, port: u16, budget: Duration) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let slot = ResolverSlot::try_acquire().ok_or_else(|| {
        anyhow::anyhow!(
            "heartbeat: {MAX_INFLIGHT_RESOLVERS} DNS lookups are already stalled; \
             skipping this beat rather than stacking threads"
        )
    })?;
    let (tx, rx) = mpsc::sync_channel(1);
    let lookup_host = host.to_string();
    thread::Builder::new()
        .name("warden-hb-resolve".into())
        .spawn(move || {
            let _slot = slot;
            let found = (lookup_host.as_str(), port)
                .to_socket_addrs()
                .map(|mut addrs| addrs.next());
            // Capacity 1: this send never blocks, even if the beat gave up.
            let _ = tx.send(found);
        })?;
    match rx.recv_timeout(budget) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(Ok(None)) => anyhow::bail!("heartbeat host resolved to no addresses"),
        Ok(Err(e)) => anyhow::bail!("heartbeat: DNS resolution failed: {e}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!("heartbeat: DNS resolution did not finish within {budget:?}")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("heartbeat: DNS helper thread failed")
        }
    }
}

/// One ping. A GET with the host + seq + ts stamped in query params, and (when a
/// secret is configured) an HMAC-SHA256 over `host|seq|ts` so the collector can
/// authenticate origin and freshness. Time-boxed to the interval so a stalled
/// ping can't pile threads up.
///
/// W-01: the response's status line is read and checked, and only a 2xx counts
/// as a beat. The original drained into a sink, ignored both the byte count and
/// the status, and returned `Ok(())` whenever there was no I/O error — so a
/// `401`, `403`, `429` or `500` from the collector was logged as `heartbeat ok`.
/// That inverts the meaning of a dead-man's switch: "we got bytes back" is not
/// "the collector accepted the beat". A peer that accepts and then says nothing,
/// or that closes without responding, is now a failed beat too — silence is not
/// acceptance.
///
/// W2K-11: name resolution is bounded (see [`resolve_bounded`]) and whatever it
/// spends comes out of the same interval budget, so a hung DNS server costs one
/// late beat, not a silent dead-man's switch.
fn beat(
    t: &Target,
    host: &str,
    timeout: Duration,
    secret: Option<&str>,
    seq: u64,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let addr = resolve_bounded(&t.host, t.port, timeout.min(DNS_BUDGET_CAP))?;
    // Connect + write + read share what the lookup left, with a small floor so a
    // lookup that used the whole budget still yields a diagnosable connect error.
    let io_timeout = timeout
        .saturating_sub(started.elapsed())
        .max(Duration::from_millis(100));
    let mut stream = TcpStream::connect_timeout(&addr, io_timeout)?;
    stream.set_read_timeout(Some(io_timeout))?;
    stream.set_write_timeout(Some(io_timeout))?;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // The MAC covers exactly the fields the collector re-derives: host|seq|ts.
    let mac = secret
        .map(|s| {
            hex(&hmac_sha256(
                s.as_bytes(),
                format!("{host}|{seq}|{ts}").as_bytes(),
            ))
        })
        .unwrap_or_default();

    let sep = if t.path.contains('?') { '&' } else { '?' };
    let macq = if mac.is_empty() {
        String::new()
    } else {
        format!("&mac={mac}")
    };
    let req = format!(
        "GET {path}{sep}host={host}&seq={seq}&ts={ts}{macq} HTTP/1.1\r\n\
         Host: {h}\r\n\
         User-Agent: warden-heartbeat\r\n\
         Connection: close\r\n\
         \r\n",
        path = t.path,
        h = t.host,
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    // Accumulate until the first line is complete. A single `read` is not
    // guaranteed to return a whole line, so parsing the first chunk directly
    // would misread a split status line as a failure.
    let mut head = Vec::with_capacity(128);
    let mut chunk = [0u8; 128];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break; // peer closed: parse whatever arrived
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(2).any(|w| w == b"\r\n") || head.len() >= MAX_STATUS_BYTES {
            break;
        }
    }

    let status = parse_status(&head)
        .ok_or_else(|| anyhow::anyhow!("heartbeat: no HTTP status line in response"))?;
    if !(200..300).contains(&status) {
        anyhow::bail!("heartbeat: collector rejected the beat with HTTP {status}");
    }
    Ok(())
}

/// Read the persisted monotonic beat sequence (0 if absent/unreadable). Best-
/// effort: a missing file just starts the sequence fresh.
fn read_seq(path: &str) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Persist the beat sequence 0600 (atomic rename) so it keeps climbing across
/// restarts and the collector's anti-replay never sees it reset.
///
/// W-03: best-effort in the sense that a failure must never stop a beat — but
/// *not* in the sense of being silent. This is the one piece of heartbeat state
/// that lives on disk, and a failure here is invisible until a restart replays a
/// stale seq and the collector (correctly) rejects it, at which point the
/// off-box dead-man monitor sees an outage that is not happening. The old code
/// logged both failures at `debug` and swallowed the rename outright, so on a
/// default `log::Level` the operator saw nothing at all. The reason is returned
/// so the caller can report it once, at a level that is actually visible.
///
/// The default path sits under `/var/lib/warden`, which the unit's
/// `StateDirectory=warden` makes writable under `ProtectSystem=strict`.
fn persist_seq(path: &str, seq: u64) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = std::path::Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".hb_seq.{}", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("cannot open {}: {e}", tmp.display()))?;
    if let Err(e) = f.write_all(seq.to_string().as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot write {}: {e}", tmp.display()));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot rename {} into place: {e}", tmp.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_heartbeat_url() {
        let t = Target::parse("http://collector.example:9000/beat").unwrap();
        assert_eq!(t.host, "collector.example");
        assert_eq!(t.port, 9000);
        assert_eq!(t.path, "/beat");
    }

    #[test]
    fn an_ip_literal_is_resolved_without_the_resolver() {
        // The production shape of heartbeat.url — a collector address — must not
        // depend on (or consume a slot in) the bounded resolver pool.
        let before = INFLIGHT_RESOLVERS.load(Ordering::Acquire);
        let addr = resolve_bounded("127.0.0.1", 8443, Duration::from_secs(1)).unwrap();
        assert_eq!(addr, "127.0.0.1:8443".parse().unwrap());
        assert_eq!(INFLIGHT_RESOLVERS.load(Ordering::Acquire), before);
    }

    #[test]
    fn the_resolver_pool_refuses_to_stack_stalled_lookups() {
        // A black-holed DNS server must cost slots, not one thread per interval.
        // When every slot is held by a lookup that has not returned, a beat fails
        // fast instead of spawning another blocked thread.
        let first = ResolverSlot::try_acquire().expect("first slot");
        let second = ResolverSlot::try_acquire().expect("second slot");
        assert!(ResolverSlot::try_acquire().is_none());
        drop(first);
        let third = ResolverSlot::try_acquire().expect("a freed slot is reusable");
        drop(second);
        drop(third);
    }

    #[test]
    fn none_config_spawns_nothing() {
        let h = spawn(None, "host".into()).unwrap();
        assert!(h.is_none());
    }

    /// A one-shot TCP server that reads the request, replies with `response`,
    /// then closes. `bind` happens before the port is returned, so the listener
    /// is already accepting when the caller connects — no startup race.
    fn one_shot_server(response: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut req = [0u8; 512];
                let _ = s.read(&mut req);
                let _ = s.write_all(response.as_bytes());
            }
        });
        port
    }

    /// A server that accepts and then says nothing — the wedged-collector case.
    fn silent_server(hold: Duration) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((_s, _)) = listener.accept() {
                thread::sleep(hold);
            }
        });
        port
    }

    fn target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            path: "/beat".into(),
        }
    }

    #[test]
    fn a_2xx_status_is_an_accepted_beat() {
        let port = one_shot_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert!(beat(&target(port), "host", Duration::from_secs(5), None, 1).is_ok());
    }

    #[test]
    fn a_rejecting_collector_is_not_a_beat() {
        // The whole point of W-01: every one of these was logged as
        // `heartbeat ok`, because only an I/O error counted as failure.
        for response in [
            "HTTP/1.1 401 Unauthorized\r\n\r\n",
            "HTTP/1.1 403 Forbidden\r\n\r\n",
            "HTTP/1.1 429 Too Many Requests\r\n\r\n",
            "HTTP/1.1 500 Internal Server Error\r\n\r\n",
        ] {
            let port = one_shot_server(response);
            let err = beat(&target(port), "host", Duration::from_secs(5), None, 1)
                .expect_err("a non-2xx response must not count as a beat");
            assert!(
                err.to_string().contains("rejected"),
                "unexpected error for {response:?}: {err}"
            );
        }
    }

    #[test]
    fn an_empty_or_non_http_response_is_not_a_beat() {
        // An empty body, a non-HTTP banner, and a status line with the code
        // missing are all "no valid acknowledgement", not success.
        for response in ["", "not http at all\r\n", "HTTP/1.1\r\n"] {
            let port = one_shot_server(response);
            assert!(
                beat(&target(port), "host", Duration::from_secs(5), None, 1).is_err(),
                "{response:?} must not count as a beat"
            );
        }
    }

    #[test]
    fn a_silent_collector_is_not_a_beat() {
        // Accepts the connection and never answers. The old code read into a
        // sink and ignored the result, so this was indistinguishable from a
        // healthy 200.
        let port = silent_server(Duration::from_secs(2));
        assert!(beat(&target(port), "host", Duration::from_millis(300), None, 1).is_err());
    }

    #[test]
    fn parses_status_lines() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.0 429 Too Many Requests\r\n"),
            Some(429)
        );
        // Unterminated: still parseable, which is what lets a status line split
        // across two reads be handled rather than misread as a failure.
        assert_eq!(parse_status(b"HTTP/1.1 503"), Some(503));
        assert_eq!(parse_status(b""), None);
        assert_eq!(parse_status(b"garbage"), None);
        assert_eq!(parse_status(b"HTTP/1.1\r\n"), None);
    }

    // ---- W2K-17: property test over arbitrary peer replies --------------------

    #[test]
    fn only_an_http_status_line_can_ever_count_as_a_beat() {
        // The beat is the liveness signal: a collector outage that reads as
        // healthy is how a dead guardian stays dead for a week. So the property
        // that matters is not "parse never panics" (though it holds here) but
        // that a 2xx verdict is impossible unless the peer literally spelled an
        // HTTP status line. Nothing that does not contain `HTTP/` may produce
        // one, and every Some must be reconstructible from the bytes.
        const HB_SEED: u64 = 0x5EED_BE47;
        for i in 0..4096u32 {
            let mut a = crate::arb::Arb::new(HB_SEED + i as u64);
            let head: Vec<u8> = match a.u32_below(4) {
                0 => a.bytes_below(260),
                1 => a.text_below(200).into_bytes(),
                2 => {
                    let body = a.text(40);
                    format!("HTTP/1.1 {body}\r\n{}", a.text(60)).into_bytes()
                }
                _ => {
                    let word = a.text(8);
                    format!("{word} {}\r\n", a.u32_below(1000)).into_bytes()
                }
            };
            let Some(status) = parse_status(&head) else {
                continue;
            };
            let line = std::str::from_utf8(&head)
                .map(|s| s.lines().next().unwrap_or_default().to_string())
                .unwrap_or_else(|_| {
                    String::from_utf8_lossy(
                        head.windows(2)
                            .position(|w| w == b"\r\n")
                            .map_or(&head[..], |n| &head[..n]),
                    )
                    .into_owned()
                });
            let mut parts = line.split_whitespace();
            let proto = parts.next().unwrap_or_default();
            assert!(
                proto.starts_with("HTTP/"),
                "iteration {i}: {head:?} yielded {status} without an HTTP version token"
            );
            if (200..300).contains(&status) {
                assert!(
                    head.starts_with(b"HTTP/") || line.starts_with("HTTP/"),
                    "iteration {i}: a 2xx beat verdict came from bytes that never said HTTP: \
                     {head:?}"
                );
                let token = parts.next().unwrap_or_default();
                assert!(
                    token.parse::<u16>().ok() == Some(status),
                    "iteration {i}: reported {status} but the token was {token:?}"
                );
            }
        }

        // The shapes the strictness exists for: no banner, no split version, no
        // code without a version, and never a success inferred from a peer that
        // is not speaking HTTP.
        for not_a_status_line in [
            b"".as_slice(),
            b"200 OK\r\n".as_slice(),
            b"proxy 200 OK\r\n".as_slice(),
            b"Redis 200\r\n".as_slice(),
            b"HTTP/1.1\r\n".as_slice(),
            b"HTTP/ 200 OK\r\n".as_slice(),
            b"  HTTP/1.1 200 OK\r\n".as_slice(),
            b"HTTP/1.1\r".as_slice(),
            b"\xff\xfe\xfd 200\r\n".as_slice(),
        ] {
            assert!(
                parse_status(not_a_status_line).is_none()
                    || !matches!(parse_status(not_a_status_line), Some(s) if (200..300).contains(&s)),
                "{not_a_status_line:?} must not read as a successful beat"
            );
        }
    }

    /// A one-shot server that hands back the request bytes it read, so a test can
    /// assert what actually went on the wire. The response is written only after
    /// the request is captured, so a `beat` that returned has already been seen.
    fn capturing_server(response: &'static str) -> (u16, Arc<std::sync::Mutex<Vec<u8>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                if let Ok(n) = s.read(&mut req) {
                    sink.lock().unwrap().extend_from_slice(&req[..n]);
                }
                let _ = s.write_all(response.as_bytes());
            }
        });
        (port, seen)
    }

    #[test]
    fn a_signed_beat_puts_seq_ts_and_mac_on_the_wire() {
        // The off-box collector re-derives HMAC-SHA256(secret, "host|seq|ts") from
        // what arrives, so all three fields have to travel. A beat carrying only
        // the MAC would be unverifiable; one carrying no MAC would be forgeable.
        // This is the contract between Warden and the collector, so it is pinned
        // at the wire rather than at the helper that builds the string.
        let (port, seen) = capturing_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let secret = "collector-shared-secret";
        assert!(beat(
            &target(port),
            "prod-web-01",
            Duration::from_secs(5),
            Some(secret),
            7
        )
        .is_ok());

        let req = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert!(
            req.starts_with("GET /beat?"),
            "unexpected request line: {req}"
        );
        assert!(req.contains("host=prod-web-01"), "no host in: {req}");
        assert!(req.contains("seq=7"), "no seq in: {req}");
        assert!(req.contains("ts="), "no ts in: {req}");
        assert!(req.contains("mac="), "no mac in: {req}");
    }

    #[test]
    fn an_unsigned_beat_carries_no_mac() {
        // No secret configured is a legitimate deployment (the collector then has
        // nothing to verify against), and the request must stay exactly what it
        // always was — not an empty `mac=` the collector would reject.
        let (port, seen) = capturing_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert!(beat(
            &target(port),
            "prod-web-01",
            Duration::from_secs(5),
            None,
            7
        )
        .is_ok());

        let req = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert!(req.contains("seq=7"), "no seq in: {req}");
        assert!(!req.contains("mac="), "unexpected mac in: {req}");
    }

    #[test]
    fn signed_beat_mac_is_stable_and_verifiable() {
        // The collector re-derives HMAC-SHA256(secret, "host|seq|ts") and compares.
        // Pin that the MAC is exactly that, so an off-box verifier written to the
        // same spec accepts a genuine beat and rejects a wrong-key/forged one.
        let secret = b"collector-shared-secret";
        let (host, seq, ts) = ("prod-web-01", 42u64, 1_790_000_000u64);
        let signed = format!("{host}|{seq}|{ts}");
        let want = hex(&hmac_sha256(secret, signed.as_bytes()));
        // Same inputs → same MAC (deterministic, verifiable off-box).
        assert_eq!(want, hex(&hmac_sha256(secret, signed.as_bytes())));
        // A wrong key does NOT verify — the forgery-resistance the beat relies on.
        assert_ne!(want, hex(&hmac_sha256(b"wrong-key", signed.as_bytes())));
        // A bumped seq (replay attempt with a stale MAC) does not match.
        let replayed = format!("{host}|{}|{ts}", seq + 1);
        assert_ne!(want, hex(&hmac_sha256(secret, replayed.as_bytes())));
    }

    #[test]
    fn seq_persist_round_trips_and_climbs() {
        let dir = std::env::temp_dir();
        let path = dir
            .join(format!("warden-hb-seq-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::remove_file(&path);
        // Absent file reads as 0; after persisting, it reads back the written value.
        assert_eq!(read_seq(&path), 0);
        assert!(persist_seq(&path, 7).is_ok());
        assert_eq!(read_seq(&path), 7);
        assert!(persist_seq(&path, 8).is_ok());
        assert_eq!(read_seq(&path), 8);
        // 0600 so the secret-adjacent seq isn't world-readable.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn an_unpersistable_seq_file_reports_why_instead_of_going_silent() {
        // W-03: a persistence failure used to be indistinguishable from success
        // on a default log level. It has to come back as a reason the caller can
        // surface, because the symptom appears a restart later, off-box, as an
        // outage that never happened.
        let dir = std::env::temp_dir().join(format!("warden-hb-seq-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A regular file standing where the parent directory should be, so
        // create_dir_all fails the way a read-only sandbox path does.
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let path = blocker.join("hb_seq").to_string_lossy().into_owned();
        let why = persist_seq(&path, 1).expect_err("must not claim to have persisted");
        assert!(why.contains("cannot create"), "unexpected reason: {why}");
        // read_seq still degrades to 0 rather than failing the beat.
        assert_eq!(read_seq(&path), 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
