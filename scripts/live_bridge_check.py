#!/usr/bin/env python3
"""Live bridge/heartbeat collector for Warden's operational checks (BUG-10).

Warden speaks two hand-rolled HTTP/1.1 protocols; this script implements both
sides so the outage, reconnect, duplicate and heartbeat behaviours can be
exercised against the real binary rather than only in-process Rust tests:

  * bridge    POST <url path>
              X-API-Key: <key>
              Content-Type: application/json
              one JSON finding envelope, with "event_id" inside.

  * heartbeat GET <beat path>?host=...&seq=...&ts=...[&mac=...]
              mac = HMAC-SHA256(secret, "host|seq|ts") in lowercase hex.

`serve` verifies the MAC (when --secret is set) and rejects a seq that does not
strictly climb for its host, which is the anti-forgery / anti-replay contract a
real collector must implement. It can refuse the first N bridge posts, or every
post until a flag file exists, which is how you force Warden's durable spool
without touching the network.

`summarize` re-reads the JSONL log and reports accepted/refused counts,
duplicate event_ids and per-host heartbeat sequences. Exit status is non-zero
when a heartbeat was rejected or a host's accepted seqs are not strictly
increasing.

`selftest` starts the collector on a loopback port and drives it with synthetic
requests, asserting the refusal, duplicate, MAC and seq-replay behaviour. It
needs no privileges and touches no real Warden instance:

    python3 scripts/live_bridge_check.py selftest

The collector needs no privileges. Warden itself must run as root (or with
CAP_BPF/CAP_PERFMON) on a disposable host; see Warden/README.md.

Examples
--------
    # 1. collector that refuses the first 3 findings, then accepts
    python3 scripts/live_bridge_check.py serve \
        --port 9099 --api-key test-key --secret shared-secret \
        --fail-first 3 --log /tmp/warden-live.jsonl

    # 2. start Warden with a config pointing bridge.url at
    #    http://127.0.0.1:9099/api/v1/sentinel/host/ and heartbeat.url at
    #    http://127.0.0.1:9099/beat, generate findings, then stop Warden.

    # 3. report what the collector saw
    python3 scripts/live_bridge_check.py summarize --log /tmp/warden-live.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import signal
import sys
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

DEFAULT_BEAT_PATH = "/beat"
DEFAULT_MAX_BODY = 1 << 20  # a finding envelope is small; 1 MiB is generous


class State:
    """Counters and the append-only JSONL log, shared across handler threads."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        # Reentrant: state.record() takes this same lock, and some callers log
        # while holding it (the heartbeat acceptance path, so the JSONL order
        # matches the accepted order). A plain Lock deadlocks the handler there.
        self.lock = threading.RLock()
        self.log = open(args.log, "a", encoding="utf-8")  # noqa: SIM115 - closed on exit
        self.posts_attempted = 0
        self.posts_accepted = 0
        self.posts_refused = 0
        self.posts_invalid = 0
        self.event_ids: list[str] = []
        self.seen_event_ids: set[str] = set()
        self.id_counts: dict[str, int] = {}
        self.beats_accepted = 0
        self.beats_rejected = 0
        self.beat_seqs: dict[str, list[int]] = {}
        self.last_seq: dict[str, int] = {}
        self.stop_requested = False

    def record(self, rec: dict[str, Any]) -> None:
        rec = {"ts": time.time(), **rec}
        with self.lock:
            self.log.write(json.dumps(rec, sort_keys=True) + "\n")
            self.log.flush()
            os.fsync(self.log.fileno())

    def summary(self) -> dict[str, Any]:
        with self.lock:
            gaps: dict[str, list[list[int]]] = {}
            for host, seqs in self.beat_seqs.items():
                holes = []
                for prev, cur in zip(seqs, seqs[1:]):
                    if cur != prev + 1:
                        holes.append([prev, cur])
                gaps[host] = holes
            return {
                "posts_attempted": self.posts_attempted,
                "posts_accepted": self.posts_accepted,
                "posts_refused": self.posts_refused,
                "posts_invalid": self.posts_invalid,
                "event_ids_unique": len(self.seen_event_ids),
                "event_ids_delivered": len(self.event_ids),
                "duplicate_deliveries": sorted(
                    eid for eid, n in self.id_counts.items() if n > 1
                ),
                "beats_accepted": self.beats_accepted,
                "beats_rejected": self.beats_rejected,
                "beat_seq_gaps": gaps,
            }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "warden-live-check/1"
    # Bound a client that opens a connection and never finishes its request,
    # otherwise server_close() could wait on it forever.
    timeout = 5

    # -- plumbing ---------------------------------------------------------

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Keep stdout clean for the summary; the JSONL log is the record.
        pass

    def _send(self, code: int) -> None:
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _read_body(self) -> Optional[bytes]:
        raw = self.headers.get("Content-Length", "0")
        try:
            length = int(raw or 0)
        except ValueError:
            return None
        if length < 0 or length > self.state.args.max_body:
            return None
        return self.rfile.read(length)

    def _maybe_stop(self) -> None:
        """Stop serve_forever once the requested number of successes is seen."""
        state = self.state
        with state.lock:
            done = (
                (state.args.stop_after_posts
                 and state.posts_accepted >= state.args.stop_after_posts)
                or (state.args.stop_after_beats
                    and state.beats_accepted >= state.args.stop_after_beats)
            )
            if not done or state.stop_requested:
                return
            state.stop_requested = True
        # shutdown() must run outside the serve_forever thread.
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    # -- bridge -----------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        state = self.state
        if urlparse(self.path).path != state.args.post_path:
            self._send(404)
            return

        # Consume the body before deciding anything, even on a bad key: closing
        # a socket with unread request bytes makes the kernel send RST, which can
        # race the response the client is trying to read.
        body = self._read_body()
        if body is None:
            with state.lock:
                state.posts_invalid += 1
            state.record({"kind": "post", "status": 413, "reason": "bad content length"})
            self._send(413)
            return

        key_ok = True
        if state.args.api_key is not None:
            got = self.headers.get("X-API-Key", "")
            key_ok = hmac.compare_digest(got, state.args.api_key)
        if not key_ok:
            # Not an attempt at delivery: a rejected key must not consume the
            # --fail-first budget that is meant to simulate an outage.
            with state.lock:
                state.posts_invalid += 1
            state.record({"kind": "post", "status": 401, "reason": "bad api key"})
            self._send(401)
            return

        # Count the attempt and decide refusal before parsing: a real outage
        # refuses valid findings too, and this is the spool path under test.
        with state.lock:
            state.posts_attempted += 1
            attempt = state.posts_attempted
            refuse = attempt <= state.args.fail_first
        if state.args.fail_until_file and not os.path.exists(state.args.fail_until_file):
            refuse = True
        if refuse:
            with state.lock:
                state.posts_refused += 1
            state.record({"kind": "post", "status": 503, "attempt": attempt})
            self._send(503)
            return

        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            obj = None
        event_id = obj.get("event_id") if isinstance(obj, dict) else None
        if not isinstance(event_id, str) or not event_id:
            with state.lock:
                state.posts_invalid += 1
            state.record({"kind": "post", "status": 400, "reason": "missing event_id"})
            self._send(400)
            return

        with state.lock:
            state.posts_accepted += 1
            state.event_ids.append(event_id)
            state.seen_event_ids.add(event_id)
            state.id_counts[event_id] = state.id_counts.get(event_id, 0) + 1
            duplicate = state.id_counts[event_id] > 1
        state.record({
            "kind": "post",
            "status": 200,
            "attempt": attempt,
            "event_id": event_id,
            "host": obj.get("host"),
            "event_type": obj.get("event_type"),
            "severity": obj.get("severity"),
            # W2K-27: the responder's verdict rides in the envelope, and this
            # log is the only place a live run can be read back afterwards — so
            # a witness that did not copy these two out could not tell "killed"
            # from "observed" after the fact. `None` distinguishes "the sensor
            # sent no verdict" from "the verdict was observed", which is itself
            # the thing an upgrade on either side has to be checked for.
            "action": obj.get("action"),
            "enforcement_requested": obj.get("enforcement_requested"),
            "duplicate": duplicate,
        })
        self._send(200)
        self._maybe_stop()

    # -- heartbeat --------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        state = self.state
        parsed = urlparse(self.path)
        if parsed.path != state.args.beat_path:
            self._send(404)
            return

        qs = parse_qs(parsed.query, keep_blank_values=True)
        host = (qs.get("host") or [""])[0]
        seq_raw = (qs.get("seq") or [""])[0]
        ts_raw = (qs.get("ts") or [""])[0]
        mac = (qs.get("mac") or [""])[0] or None

        reason = None
        try:
            seq = int(seq_raw)
            ts = int(ts_raw)
        except ValueError:
            seq, ts = -1, 0
            reason = "non-numeric seq/ts"

        mac_ok: Optional[bool] = None
        if reason is None and state.args.secret is not None:
            want = hmac.new(
                state.args.secret.encode("utf-8"),
                f"{host}|{seq}|{ts}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            mac_ok = mac is not None and hmac.compare_digest(mac, want)
            if not mac_ok:
                reason = "bad or missing mac"

        seq_ok = False
        if reason is None:
            # Check, update and log under one lock: two beats for the same host
            # must not both pass the climb test against the same previous seq,
            # and the log order must match the order they were accepted in —
            # otherwise summarize reads a concurrent pair as non-monotonic.
            with state.lock:
                if seq > state.last_seq.get(host, -1):
                    state.last_seq[host] = seq
                    state.beat_seqs.setdefault(host, []).append(seq)
                    state.beats_accepted += 1
                    state.record({
                        "kind": "beat", "status": 200, "host": host, "seq": seq,
                        "ts_beat": ts, "mac_ok": mac_ok, "seq_ok": True,
                    })
                    seq_ok = True
                else:
                    reason = "seq did not climb"

        if not seq_ok:
            with state.lock:
                state.beats_rejected += 1
                state.record({
                    "kind": "beat", "status": 401, "host": host, "seq": seq,
                    "ts_beat": ts, "mac_ok": mac_ok, "seq_ok": seq_ok,
                    "reason": reason,
                })
            self._send(401)
            return

        self._send(200)
        self._maybe_stop()


class Server(ThreadingHTTPServer):
    # Wait for in-flight handlers in server_close() rather than letting a
    # daemon thread write to the JSONL log after it has been closed.
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = True


# -- subcommands ----------------------------------------------------------


def serve(args: argparse.Namespace) -> int:
    state = State(args)
    server = Server((args.bind, args.port), Handler)
    server.state = state  # type: ignore[attr-defined]
    host, port = server.server_address[:2]
    print(
        f"listening on http://{host}:{port}"
        f"  post_path={args.post_path}  beat_path={args.beat_path}",
        flush=True,
    )
    print(f"log: {args.log}", flush=True)
    if args.secret is None:
        print("WARNING: no --secret; heartbeat MACs are NOT verified", file=sys.stderr)
    if args.api_key is None:
        print("WARNING: no --api-key; X-API-Key is NOT checked", file=sys.stderr)

    def stop(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        summary = state.summary()
        state.log.close()
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0


def summarize(args: argparse.Namespace) -> int:
    posts_ok = posts_refused = posts_invalid = 0
    delivered: list[str] = []
    beats: dict[str, list[int]] = {}
    rejected: list[dict[str, Any]] = []
    try:
        fh = open(args.log, "r", encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {args.log}: {exc}", file=sys.stderr)
        return 2
    with fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("kind") == "post":
                if rec.get("status") == 200 and rec.get("event_id"):
                    posts_ok += 1
                    delivered.append(rec["event_id"])
                elif rec.get("status") == 503:
                    posts_refused += 1
                elif rec.get("status") in (400, 401, 413):
                    posts_invalid += 1
            elif rec.get("kind") == "beat":
                if rec.get("status") == 200 and rec.get("host") is not None:
                    beats.setdefault(rec["host"], []).append(int(rec["seq"]))
                else:
                    rejected.append(rec)

    duplicates = sorted(
        eid for eid, n in Counter(delivered).items() if n > 1
    )
    non_monotonic = {
        host: seqs for host, seqs in beats.items()
        if any(cur <= prev for prev, cur in zip(seqs, seqs[1:]))
    }
    report = {
        "posts_accepted": posts_ok,
        "posts_refused": posts_refused,
        "posts_invalid": posts_invalid,
        "event_ids_delivered": len(delivered),
        "event_ids_unique": len(set(delivered)),
        "duplicate_deliveries": duplicates,
        "beats_accepted": sum(len(v) for v in beats.values()),
        "beats_rejected": len(rejected),
        "beat_seqs": beats,
        "non_monotonic_hosts": non_monotonic,
    }
    print(json.dumps(report, indent=2, sort_keys=True))

    failed = bool(rejected) or bool(non_monotonic)
    return 1 if failed else 0


def selftest(_args: argparse.Namespace) -> int:
    """Drive the collector with synthetic requests and assert every verdict.

    Runs the same code path as `serve` (real sockets, real handler threads), so
    a passing run is evidence about the collector itself, not a second
    implementation of it.
    """
    import http.client
    import tempfile

    workdir = tempfile.mkdtemp(prefix="warden-live-selftest-")
    log_path = os.path.join(workdir, "collector.jsonl")
    ns = argparse.Namespace(
        bind="127.0.0.1", port=0, log=log_path,
        post_path="/api/v1/sentinel/host/", beat_path=DEFAULT_BEAT_PATH,
        api_key="k", secret="s", fail_first=2, fail_until_file=None,
        max_body=DEFAULT_MAX_BODY, stop_after_posts=0, stop_after_beats=0,
    )
    state = State(ns)
    server = Server((ns.bind, ns.port), Handler)
    server.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    host, port = server.server_address[:2]

    def request(method: str, path: str, body: Optional[bytes] = None,
                headers: Optional[dict[str, str]] = None) -> int:
        conn = http.client.HTTPConnection(host, port, timeout=3)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            resp.read()
            return resp.status
        finally:
            conn.close()

    def post(key: str, event_id: str) -> int:
        body = json.dumps({
            "source": "warden", "event_id": event_id, "host": "h",
            "event_type": "process_creation", "severity": "high",
        }).encode()
        return request(
            "POST", ns.post_path, body,
            {"X-API-Key": key, "Content-Type": "application/json"},
        )

    def beat(seq: int, secret: str = "s", beat_host: str = "h") -> int:
        ts = 1_790_000_000 + seq
        mac = hmac.new(
            secret.encode(), f"{beat_host}|{seq}|{ts}".encode(), hashlib.sha256
        ).hexdigest()
        return request(
            "GET", f"{ns.beat_path}?host={beat_host}&seq={seq}&ts={ts}&mac={mac}"
        )

    checks = [
        ("rejects a wrong api key", post("wrong", "e0"), 401),
        ("refuses post 1 with 503", post("k", "e1"), 503),
        ("refuses post 2 with 503", post("k", "e2"), 503),
        ("accepts post 3", post("k", "e3"), 200),
        ("accepts the same event_id again", post("k", "e3"), 200),
        ("rejects a wrong MAC", beat(5, secret="wrong"), 401),
        ("accepts seq 7", beat(7), 200),
        ("rejects the seq 7 replay", beat(7), 401),
        ("accepts seq 8", beat(8), 200),
        ("rejects seq 6 after seq 8", beat(6), 401),
    ]

    ok = True
    for name, got, want in checks:
        mark = "ok" if got == want else "FAIL"
        ok = ok and got == want
        print(f"{mark}: {name}: got {got}, want {want}")

    server.shutdown()
    thread.join(timeout=3)
    server.server_close()
    summary = state.summary()
    state.log.close()
    print(json.dumps(summary, indent=2, sort_keys=True))

    expected = {
        "posts_attempted": 4, "posts_accepted": 2, "posts_refused": 2,
        "posts_invalid": 1, "event_ids_delivered": 2, "event_ids_unique": 1,
        "duplicate_deliveries": ["e3"], "beats_accepted": 2, "beats_rejected": 3,
        "beat_seq_gaps": {"h": []},
    }
    for key, want in expected.items():
        got = summary.get(key)
        if got != want:
            ok = False
            print(f"FAIL: summary.{key}: got {got!r}, want {want!r}")

    print(f"log kept at {log_path}")
    print("SELFTEST PASS" if ok else "SELFTEST FAIL")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bridge/heartbeat collector for Warden BUG-10 checks.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve", help="run the collector")
    s.add_argument("--bind", default="127.0.0.1")
    s.add_argument("--port", type=int, default=0,
                   help="0 picks a free port and prints it")
    s.add_argument("--log", default="warden-live.jsonl")
    s.add_argument("--post-path", default="/api/v1/sentinel/host/")
    s.add_argument("--beat-path", default=DEFAULT_BEAT_PATH)
    s.add_argument("--api-key", default=None,
                   help="if set, POSTs must carry a matching X-API-Key")
    s.add_argument("--secret", default=None,
                   help="if set, heartbeat MACs are verified with this secret")
    s.add_argument("--fail-first", type=int, default=0,
                   help="refuse the first N POSTs with 503")
    s.add_argument("--fail-until-file", default=None,
                   help="refuse POSTs with 503 until this path exists")
    s.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY)
    s.add_argument("--stop-after-posts", type=int, default=0,
                   help="exit after N accepted POSTs (0 = never)")
    s.add_argument("--stop-after-beats", type=int, default=0,
                   help="exit after N accepted beats (0 = never)")
    s.set_defaults(func=serve)

    m = sub.add_parser("summarize", help="report on a collector JSONL log")
    m.add_argument("--log", required=True)
    m.set_defaults(func=summarize)

    t = sub.add_parser("selftest", help="exercise serve and summarize in-process")
    t.set_defaults(func=selftest)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
