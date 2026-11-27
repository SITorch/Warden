#!/usr/bin/env bash
# Warden Phase 6 — privileged live validation harness.
#
# Runs ON THE ISOLATED VM, AS ROOT. It never touches the host's firewall,
# routing table, production services, credentials or money path. All test
# traffic stays inside a throwaway network namespace, and all processes under
# test live in a throwaway cgroup v2 leaf. The Warden agent itself runs in the
# host namespace/cgroup root so the cgroup hooks apply only to the clients.
#
# Usage:
#   sudo ./phase6_privileged_validation.sh WORKDIR /path/to/warden
#
# The script prints one line per test:
#   CLASSIFICATION: <EXECUTED AND PASSED|EXECUTED AND FAILED|SKIPPED|BLOCKED BY ENVIRONMENT> | name | detail
# followed by a final SUMMARY. The caller must copy those lines verbatim into
# docs/security/warden_phase6_live_validation.md; a green script is not a pass
# unless the individual classifications say so.
set -u

WORK="${1:-}"
BIN="${2:-}"
if [ -z "$WORK" ] || [ ! -x "$BIN" ]; then
    echo "usage: sudo $0 WORKDIR /path/to/warden" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "BLOCKED BY ENVIRONMENT | privilege | this harness must run as root" >&2
    exit 2
fi

NS="warden6-$$"
CG="/sys/fs/cgroup/warden6-$$"
mkdir -p "$WORK"
AGENT_PID=""
LISTENERS=""

classify() { echo "CLASSIFICATION: $1 | $2 | $3"; }
pass()     { classify "EXECUTED AND PASSED" "$1" "$2"; }
fail()     { classify "EXECUTED AND FAILED" "$1" "$2"; }
skip()     { classify "SKIPPED" "$1" "$2"; }
blocked()  { classify "BLOCKED BY ENVIRONMENT" "$1" "$2"; }

cleanup() {
    [ -n "$AGENT_PID" ] && kill -TERM "$AGENT_PID" 2>/dev/null || true
    for p in $LISTENERS; do kill -TERM "$p" 2>/dev/null || true; done
    [ -n "$AGENT_PID" ] && wait "$AGENT_PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rmdir "$CG" 2>/dev/null || true
}
trap cleanup EXIT

# ── environment preflight ───────────────────────────────────────────────────
[ -d /sys/fs/cgroup ] && [ -w /sys/fs/cgroup/cgroup.procs ] || {
    blocked "environment.cgroup2" "cgroup2 not writable"; exit 2;
}
command -v ip >/dev/null 2>&1 || { blocked "environment.ip" "iproute2 missing"; exit 2; }
command -v python3 >/dev/null 2>&1 || { blocked "environment.python" "python3 missing"; exit 2; }

mkdir -p "$CG" || { blocked "environment.cgroup_create" "cannot create $CG"; exit 2; }
ip netns add "$NS" || { blocked "environment.netns" "ip netns add failed"; exit 2; }
# A private address on the namespace's loopback: no packet ever leaves the VM.
ip netns exec "$NS" ip addr add 10.99.0.1/24 dev lo 2>/dev/null || true
ip netns exec "$NS" ip -6 addr add fd00:99::1/128 dev lo 2>/dev/null || true
ip netns exec "$NS" ip link set lo up 2>/dev/null || true

# Two TCP listeners and one UDP echo server, all namespace-local.
ip netns exec "$NS" python3 -m http.server 4444 --bind 10.99.0.1 >"$WORK/listener4444.log" 2>&1 &
LISTENERS="$LISTENERS $!"
ip netns exec "$NS" python3 -m http.server 4445 --bind 10.99.0.1 >"$WORK/listener4445.log" 2>&1 &
LISTENERS="$LISTENERS $!"
ip netns exec "$NS" python3 - "$WORK/udp4446.log" <<'PY' >/dev/null 2>&1 &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.99.0.1", 4446))
with open(sys.argv[1], "w") as f:
    while True:
        d, a = s.recvfrom(64)
        f.write(f"{a!r} {d!r}\n"); f.flush()
PY
LISTENERS="$LISTENERS $!"
sleep 1

# The client helpers live in files, not in shell-quoted `python3 -c` strings:
# nested quoting was a real source of false failures in an earlier run.
cat >"$WORK/tcp_client.py" <<'PY'
import os, socket, sys
print("CLIENT_CGROUP=" + open("/proc/self/cgroup").read().strip(), file=sys.stderr)
family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
try:
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((sys.argv[1], int(sys.argv[2])))
    s.close()
    print("CONNECT_OK")
except OSError as e:
    print(f"CONNECT_ERR:{getattr(e, 'errno', 0)}:{e}")
PY
cat >"$WORK/udp_client.py" <<'PY'
import socket, sys
print("CLIENT_CGROUP=" + open("/proc/self/cgroup").read().strip(), file=sys.stderr)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"x", (sys.argv[1], int(sys.argv[2])))
    print("SEND_OK")
except OSError as e:
    print(f"SEND_ERR:{getattr(e, 'errno', 0)}:{e}")
PY

# Enter BOTH namespaces before dialing. `ip netns exec` unshares the MOUNT
# namespace too, which hides /sys/fs/cgroup — writing cgroup.procs there fails
# and the client silently stays in the host cgroup, so no hook ever fires.
# `nsenter --net=` switches ONLY the network namespace; the shell writes its
# own pid to the cgroup first and `exec` preserves that membership into python.
run_in_test_scope() { # script args...
    local script="$1"; shift
    nsenter --net="/run/netns/$NS" sh -c \
        "echo \$\$ > '$CG/cgroup.procs'; exec python3 '$script' \"\$@\"" \
        sh "$@" 2>&1
}
tcp_connect() { # address port -> prints CONNECT_OK or CONNECT_ERR:<errno>
    run_in_test_scope "$WORK/tcp_client.py" "$1" "$2" | tail -1
}
udp_send() { # address port
    run_in_test_scope "$WORK/udp_client.py" "$1" "$2" | tail -1
}

# The agent starts in the host namespace and root cgroup, so its own traffic is
# never subject to the hooks it attaches to the leaf cgroup.
# Policy installation is asynchronous relative to process start. Sending the
# test dial after a fixed sleep produced false results (the dial happened before
# the rules were in the kernel). Wait for the agent to REPORT the state we are
# about to assert on; a timeout is a real harness failure, not a silent pass.
wait_for_log() { # file pattern seconds
    local file="$1" pattern="$2" seconds="$3" i=0
    while [ "$i" -lt "$seconds" ]; do
        grep -q -- "$pattern" "$file" 2>/dev/null && return 0
        i=$((i + 1))
        sleep 1
    done
    return 1
}

start_agent() { # config tag
    local cfg="$1" tag="$2"
    "$BIN" --debug --config "$WORK/$cfg.toml" >"$WORK/$tag.log" 2>&1 &
    AGENT_PID=$!
    sleep 1
    kill -0 "$AGENT_PID" 2>/dev/null
}
reload_agent() {
    kill -HUP "$AGENT_PID" 2>/dev/null
    sleep 1
}

write_config() { # tag arm
    local tag="$1" arm="$2"
    cat >"$WORK/$tag.toml" <<EOF
mode = "observe"

[egress]
enabled = true
cgroup_path = "$CG"
arm = $arm

[[egress.deny]]
address = "10.99.0.1"
port = 4444
protocol = "tcp"

[[egress.deny]]
address = "fd00:99::1"
port = 4445
protocol = "tcp"

[[egress.deny]]
address = "10.99.0.1"
port = 4446
protocol = "udp"
EOF
}

# ── config-level gates (run with --check, no kernel effect) ─────────────────
cat >"$WORK/bad_arm.toml" <<EOF
[egress]
enabled = false
arm = true
EOF
if "$BIN" --check --config "$WORK/bad_arm.toml" >"$WORK/bad_arm.out" 2>&1; then
    fail "config.arm_without_enable" "--check accepted arm=true with enabled=false"
else
    pass "config.arm_without_enable" "--check refused arm=true with enabled=false, as designed"
fi

cat >"$WORK/bad_root.toml" <<EOF
[egress]
enabled = true
cgroup_path = "/sys/fs/cgroup"
[[egress.deny]]
address = "10.99.0.1"
port = 4444
EOF
if "$BIN" --check --config "$WORK/bad_root.toml" >"$WORK/bad_root.out" 2>&1; then
    fail "config.root_cgroup_rejected" "--check accepted the cgroup root"
else
    pass "config.root_cgroup_rejected" "--check refused /sys/fs/cgroup as egress.cgroup_path"
fi

cat >"$WORK/default.toml" <<'EOF'
EOF
if "$BIN" --check --config "$WORK/default.toml" >"$WORK/default.out" 2>&1; then
    pass "config.default_inert" "--check accepts an empty config (egress disabled by default)"
else
    fail "config.default_inert" "--check rejected the shipped default config"
fi

# ── T1 baseline: no agent, nothing can deny ─────────────────────────────────
BASE="$(tcp_connect 10.99.0.1 4444)"
case "$BASE" in
    CONNECT_OK) pass "traffic.baseline_no_agent" "$BASE" ;;
    *) fail "traffic.baseline_no_agent" "$BASE" ;;
esac
# A hook that did not fire because the client was in the wrong cgroup is a
# harness bug, not an enforcement result. Prove the scope explicitly.
SCOPE="$(run_in_test_scope "$WORK/tcp_client.py" 10.99.0.1 4444 2>&1 | grep '^CLIENT_CGROUP=' | head -1)"
case "$SCOPE" in
    *"warden6-"*) pass "environment.client_in_test_cgroup" "$SCOPE" ;;
    *) fail "environment.client_in_test_cgroup" "$SCOPE" ;;
esac

# ── T2 shadow: hooks attached, arm=false, DENY counted but allowed ─────────
write_config shadow false
if ! start_agent shadow shadow; then
    blocked "traffic.shadow_attach" "agent failed to start; see $WORK/shadow.log"
elif ! wait_for_log "$WORK/shadow.log" 'egress enforcement: SHADOW' 45; then
    blocked "traffic.shadow_attach" "agent never reported SHADOW readiness; see $WORK/shadow.log"
else
    SHADOW="$(tcp_connect 10.99.0.1 4444)"
    case "$SHADOW" in
        CONNECT_OK) pass "traffic.shadow_allows" "$SHADOW" ;;
        *) fail "traffic.shadow_allows" "$SHADOW (shadow must not deny)" ;;
    esac
    if grep -q 'egress enforcement: SHADOW' "$WORK/shadow.log"; then
        pass "report.shadow_statement" "startup log says SHADOW, not ARMED"
    else
        fail "report.shadow_statement" "startup log did not state SHADOW"
    fi
    # Counters are sampled on the agent's 10-second protected-set tick, not on
    # each event. Wait past one full tick before reading the log, or a real
    # counter increment would be misreported as absent.
    sleep 12
    if grep -q 'shadow_deny=[1-9]' "$WORK/shadow.log"; then
        pass "counter.shadow_hit" "kernel egress_stats recorded a shadow DENY match"
    else
        fail "counter.shadow_hit" "no shadow DENY counter increment in $WORK/shadow.log"
    fi
fi

# ── T3 armed: SIGHUP flips arm; the same DENY now returns EPERM ────────────
# Warden reloads the SAME --config path it was started with, so the arm edit
# must go into shadow.toml in place. Writing a different file would be a
# harness bug that makes a correct agent look broken.
write_config shadow true
reload_agent
if ! wait_for_log "$WORK/shadow.log" 'SIGHUP: egress arm=true' 30; then
    blocked "traffic.armed_attach" "agent never reported ARMED readiness; see $WORK/shadow.log"
fi
ARMED="$(tcp_connect 10.99.0.1 4444)"
case "$ARMED" in
    CONNECT_ERR:1:*) pass "traffic.armed_denies_tcp4" "$ARMED" ;;
    *) fail "traffic.armed_denies_tcp4" "$ARMED (expected EPERM/errno 1)" ;;
esac
# Same 10-second tick as above: give the agent a full window to sample the
# armed-denial counter before asserting on the log.
sleep 12
if grep -q 'armed_denied=[1-9]' "$WORK/armed.log" "$WORK/shadow.log" 2>/dev/null; then
    pass "counter.armed_denial" "kernel egress_stats recorded an armed denial"
else
    fail "counter.armed_denial" "no armed-denial counter increment in agent logs"
fi

# ── T4 non-matching port still allowed while armed ─────────────────────────
OTHER="$(tcp_connect 10.99.0.1 4445)"
case "$OTHER" in
    CONNECT_OK) pass "traffic.armed_allows_other_port" "$OTHER" ;;
    *) fail "traffic.armed_allows_other_port" "$OTHER (rule is exact, not port-wildcard)" ;;
esac

# ── T5 UDP sendmsg4 gate ───────────────────────────────────────────────────
UDP="$(udp_send 10.99.0.1 4446)"
case "$UDP" in
    SEND_ERR:1:*) pass "traffic.armed_denies_udp4_sendmsg" "$UDP" ;;
    *) fail "traffic.armed_denies_udp4_sendmsg" "$UDP (expected EPERM/errno 1)" ;;
esac

# ── T6 IPv6 connect gate ───────────────────────────────────────────────────
# http.server's CLI binds AF_INET only, so use an explicit AF_INET6 listener.
ip netns exec "$NS" python3 - "$WORK/listener6.log" <<'PY' >/dev/null 2>&1 &
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("fd00:99::1", 4445))
s.listen(8)
with open(sys.argv[1], "w") as f:
    while True:
        c, a = s.accept()
        f.write(f"ACCEPT {a!r}\n"); f.flush()
        c.close()
PY
V6LIST=$!
LISTENERS="$LISTENERS $V6LIST"
sleep 1
V6="$(tcp_connect fd00:99::1 4445)"
case "$V6" in
    CONNECT_ERR:1:*) pass "traffic.armed_denies_tcp6" "$V6" ;;
    *) fail "traffic.armed_denies_tcp6" "$V6 (expected EPERM/errno 1)" ;;
esac

echo "SUMMARY: log files and full agent output are in $WORK"
