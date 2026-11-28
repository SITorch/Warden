# Warden Network & Attack Coverage Matrix

This is the authoritative, machine-checked statement of what the shipped Warden
build can see, detect and prevent. `Warden/tests/network_coverage_matrix.rs`
reads the embedded eBPF object, the C/header source and the two documents under
`Warden/docs/security/`, then fails the build if the structural claims drift.
The canonical copies of these two documents live inside the standalone `Warden/`
source tree; the repository-level `docs/security/` copies are mirrored for the
mission report and checked for byte-for-byte parity when present.

Empirical claims (a packet actually produced an event, or a syscall was refused
on a given kernel) require the isolated privileged VM. Historical sections that
did not run are still labelled **NOT EXECUTED IN THIS PASS**, and historical live
evidence from earlier phases is history, not a current-source proof. M15's own
live claims are labelled **Live verified (M15)** and name the evidence file
under `Warden/evidence/m15/`; they do not retroactively validate older sections.

Legend: **Implemented** = code ships; **Verified** = unprivileged structural
test passes; **Live verified** = seen on an isolated privileged kernel in the
current pass; **Live verified (M15)** = verifier acceptance, attach and a landed
map bump were recorded for this exact object on the isolated `debian13` VM in
M15; **Implemented, NOT validated live** = built and structurally checked, but
no verifier/attach/bump evidence was collected in that pass; **Partial** = some
cases covered; **Unsupported** = deliberately absent; **Unknown** = no evidence
available. A BTF preflight result alone is never a live bump.

## 1. Address families and transports

| Dimension | Status | What the hook actually sees | Evidence / limitation |
|---|---|---|---|
| IPv4 TCP connect intent | Implemented, Verified | `security_socket_connect` kprobe: family, address, port, protocol, actor pid/uid/comm | `kprobe/security_socket_connect` in embedded object |
| IPv6 TCP connect intent | Implemented, Verified | Same hook, `AF_INET6` in family bits | `WARDEN_NET_FAMILY_MASK` in `warden.h` |
| IPv4-mapped IPv6 | Partial | Decoded by the family field; treated as v6 by the producer | No mapping to a v4 policy key is performed |
| Loopback | Implemented, Verified | Included in connect/listen and in volume counters | `warden.h:595-599` |
| Link-local / multicast | Partial | Represented as addresses; no dedicated policy semantics | — |
| TCP connect result | Partial | `kretprobe __inet_stream_connect` emits a terminal verdict only | Non-blocking dials return `-EINPROGRESS`: 116/128 (91%) of historical live dials had no verdict record |
| TCP accepted flow | Partial | `kretprobe inet_accept` emits inbound FLOW with socket netns inum | No close, duration, or byte count; stream-only |
| Cross-event joins over verdict/flow | Implemented (offline, synthetic tests) | `src/correlate.rs` joins a judged unsanctioned dial with an `Established` verdict, or a judged suspicious listener with a FLOW on the same local port, emitting `endpoint:attack_chain` (observe-only, no kill) | No DNS/SNI/payload/byte count is inferred. A routine verdict or accept still produces no standalone finding; no privileged live validation in this pass |
| Connected UDP | Partial | Datagram dial stamps family+`IPPROTO_UDP`, but reaches no verdict hook | `inet_stream_connect` is TCP-only |
| Unconnected UDP flow | Partial / Optional | By default there is no flow finding. When Phase 7 is explicitly enabled, `cgroup/sendmsg4` and `cgroup/sendmsg6` see the destination before the datagram is sent; the six volume counters see payload but no destination | Denial needs a named isolated cgroup, `enabled = true`, `arm = true` and an exact rule. The observe-only `sendto`/`sendmsg` finding path is still absent |
| ICMP / ICMPv6 | Unsupported | No specific sensor | Would require a different hook family |
| Raw sockets | Partial | Protocol byte may be 0 = "no claim"; never truncated | A zero is rendered absent, never relabelled |
| IPv4 datagram volume | **Live verified (M15)** | `fexit/udp_sendmsg|udp_recvmsg` counters by cgroup | Bytes/ops, not wire bytes; `MSG_PEEK` inflates ingress. M15: 5000B/5 ops each way, and a 1000B send into a 64B receive buffer charged 64B on ingress (`M15_11_traffic_deltas_v2.md`) |
| IPv6 datagram volume | **Live verified (M15)** (`LIVE_VALIDATED_M15`) | `fexit/udpv6_sendmsg`/`fexit/udpv6_recvmsg` ship, pass target-BTF prototype preflight, and are attempted like the four original hooks | Historical §23 proved the v4 hooks missed `[::1]`; M15 recorded all six prototypes `COMPATIBLE` on target BTF `ccdf5d7e…`, verifier accept and six attached programs, plus `[::1]` bumps of 2800B/4 ops each way and IPv4-mapped +3/+3 (`M15_09_vm_btf_parser_fixed.txt`, `M15_11_vm_fixed_parser_clean_traffic.txt`, `M15_11_traffic_deltas_v2.md`). This is IPv6-socket-path accounting, not pure IPv6 wire traffic |
| Fragmented traffic | Unknown | No packet-level hook | — |

## 2. Hook inventory (structural, from the embedded object)

| Hook | Sees | Prevention | Family/transport |
|---|---|---|---|
| `kprobe/security_socket_connect` | Socket operation (intent) | No | v4/v6, TCP/UDP dials |
| `kprobe`+`kretprobe __inet_stream_connect` | Connect terminal verdict | No | blocking TCP only |
| `kprobe`+`kretprobe inet_accept` | Accepted inbound socket | No | TCP only |
| `kprobe/security_socket_listen` | Listen call | No | v4/v6 |
| `fexit/tcp_sendmsg`, `fexit/tcp_cleanup_rbuf` | Byte/op counters | No | TCP (all families via the socket) |
| `fexit/udp_sendmsg`, `fexit/udp_recvmsg` | Byte/op counters | No | IPv4 datagrams — live bumps in M15 |
| `fexit/udpv6_sendmsg`, `fexit/udpv6_recvmsg` | Byte/op counters | No | IPv6-socket-path datagrams — live bumps in M15, not pure IPv6 wire bytes |
| `cgroup/connect4`, `cgroup/connect6` | Destination of an outbound connect | Yes, only when Phase 7 is enabled and armed | IPv4/IPv6 TCP |
| `cgroup/sendmsg4`, `cgroup/sendmsg6` | Destination of an unconnected sendmsg | Yes, only when Phase 7 is enabled and armed | IPv4/IPv6 UDP |
| 6 × `lsm/*` file/inode guards | File/inode access | Yes (`-EPERM`) | Not network |

The four `cgroup/` programs are **optional and disabled by default**. They are
not packet filters: no `cgroup_skb`, TC, XDP, `sock_ops`, network-LSM or
`lsm/socket` program ships. The structural test pins both the presence of the
four documented cgroup hooks and the absence of every forbidden family.

## 3. Egress enforcement

Egress enforcement is **implemented in the tree but disabled by default**. It is
not a full-host firewall: it applies only to one named, validated cgroup2
subtree, and only to exact `(family, protocol, address, port)` rules.

| Gate | Requirement | Failure behaviour |
|---|---|---|
| Attachment | `[egress] enabled = true` plus a validated isolated cgroup path | With defaults, no cgroup program is attached; `EgressHooks` is all false |
| Arming | `CFG_EGRESS_ARM = 1`, written and read back from the kernel | Default is 0; a matching rule is counted as SHADOW and allowed |
| Policy | An exact key in `egress_policy`, with `port = 0` as the only wildcard | No name, CIDR, process name or hostname wildcard exists |

Cgroup validation opens the path one component at a time with `O_NOFOLLOW`,
rejects `.`/`..`/prefix and symlink aliases, requires `fstatfs` to report the
cgroup2 super-magic at the opened fd, compares the opened directory's `(dev,ino)`
against the cgroup2 root visible in this process's mount namespace, refuses the
root or an alias of it, and fails closed when more than one cgroup2 mount could
own the path. The loader attaches from that same validated fd, reducing the
TOCTOU window between validation and `bpf_link_create`. No test in this tree
attaches hooks to the host cgroup root.

SIGHUP reload is transactional and classified A–E:

- **A** enabled → disabled: disarm, read back 0, clear and verify the map, report
  that startup hooks remain attached but cannot deny; a restart detaches them.
- **B** enabled → enabled: disarm and read back, sync the new generation, verify
  the live map, then re-arm only on full success and read back 1.
- **C** `cgroup_path` changed: same disarm/clear as A, plus an explicit
  restart-required report; no claim that the new cgroup is covered.
- **D** disabled → enabled: no arm write, no rule write, restart required;
  startup attachment cannot be manufactured by a reload.
- **E** config load failure: no kernel write, old arm bit, map and generation are
  preserved and reported as the live state.

Map insert/remove/enumeration failures and failed arm writes roll back the old
map and arm bit; an unconfirmed rollback is marked DEGRADED in the report and
fed into `policy::Preflight`. `network_rules.deny_destinations` stays an
observe-only decision and never becomes `traffic_blocked: true`.

## 4. DNS, TLS/QUIC and application layer

| Capability | Status | Honest statement |
|---|---|---|
| Traffic to a DNS resolver | Partial | A dial to port 53 is recorded as a connection with an address and port |
| DNS protocol transaction | Unsupported | No DNS event kind, resolver integration or payload inspection in the host pipeline |
| DNS payload **metadata** (name, type, rcode, entropy) | Unsupported | No source exists locally. A C2 finding must list `dns_query` as an unsupported input, never infer one from a port |
| Port-53 C2 evidence | Partial, capped | A cadenced port-53 dial remains beaconing evidence, but is labelled `T1095` with evidence "DNS-like port-53 CONNECT activity only; no DNS query metadata was observed" and confidence capped at 0.65. Port 53 alone never becomes `T1071.004` |
| DoH / DoT / DoQ | Unsupported | Encrypted; ordinary metadata cannot reveal query contents |
| TLS version / SNI / ALPN from network hooks | Unsupported | Not collected by any shipped network sensor |
| TLS 1.3 / Encrypted Client Hello | Unsupported | SNI is not reliably visible even where TLS metadata exists |
| QUIC metadata | Unsupported | No QUIC-aware collector |
| HTTP/application payload | Unsupported | No payload interception; no invasive decryption |

The optional bridge mTLS transport (`src/tls.rs`) authenticates the Sentinel
server and presents a per-agent client certificate. It protects the delivery
hop; it is not network telemetry and does not give Warden SNI, ALPN or DNS
payload visibility. Its TLS handshake has no insecure fallback: DNS names are
matched with `X509_VERIFY_PARAM_set1_host` and sent as SNI, IP literals are
matched with `X509_VERIFY_PARAM_set1_ip_asc` and send no SNI, verification
parameters are set on the per-connection `SSL` object, and a failed handshake
sends no request bytes.

The backend NDR `dns_tunnel` and `dga` detectors consume `DnsQuery` rows from a
separate `/sentinel/ndr/` telemetry path. They are not fed by Warden host
ingest and must not be described as Warden DNS detection.

## 5. Namespaces and containers

| Dimension | Status | Note |
|---|---|---|
| Host network namespace | Implemented | `/proc/net` snapshot reads Warden's own namespace |
| Non-host network namespace | Partial / Unsupported | The kprobe is global and sees accepts from container netns (FLOW stamps netns inum), but the `/proc/net` pull path is host-namespace only and cannot enumerate those sockets |
| Docker bridge / veth | Unknown | Not measured; no runtime metadata binding |
| Host networking mode | Partial | Looks like host traffic; no container identity from this source |
| cgroup identity | Implemented, Verified | Volume counters keyed by `bpf_get_current_cgroup_id()` (monotone, non-recycled) |
| cgroup v1 vs v2 | Partial | Phase 7 requires cgroup2; config/loader validation reads this process's mount namespace and rejects an unrecognised or ambiguous root |
| Container restart / identity reuse | Partial | cgroup id is the stable key; container name is never used as a security identity |

## 6. Network event schema (what is on the wire)

CONNECT / CONNECT_RESULT / LISTEN / FLOW carry: kind, actor pid/tid/ppid/uid,
comm, timestamp, destination address, family, transport protocol, connect
outcome where provable, and (FLOW) socket netns inum. Missing data is encoded
as an explicit zero meaning "no claim" and rendered as absent — never
fabricated as a protocol or a verdict. Finding envelopes additionally carry the
F-009 clock lineage (`observed_at_unix_ms`, `kernel_event_ts_ns`,
`kernel_event_unix_ms`, `kernel_event_clock`, `event_time_clock`); the backend
stores it in the sealed record and refuses a `kernel_monotonic` label that
contradicts it. FLOW does not carry bytes, duration or listener socket inode.
The fixed 344-byte `RawEvent` is ABI-pinned by
`tests/network_abi.rs`, `connect_outcome_abi.rs`, `accept_flow_abi.rs` and
`net_volume_abi.rs`.

## 7. ATT&CK relevance of the *telemetry* (not detection claims)

These mappings describe what evidence exists for a local or backend analytics
engine; they are not statements that Warden detects the technique.

| Technique | Supporting telemetry | Gap |
|---|---|---|
| T1071.001 Web protocols | Destination, port, timing, process | No payload/SNI from network sensors; can look like any TLS traffic |
| T1071.004 DNS | No definitive support in Warden host telemetry | Port 53 alone is not a DNS transaction. Evidence stays "DNS-like" under T1095 and cannot support DNS analytics |
| T1095 Non-app-layer protocol | Family, protocol byte, destination, cadence | No payload classification; port-53 confidence is capped and `dns_query` is declared unsupported |
| T1571 Non-standard port | Destination port + process | Port alone is not malicious |
| T1572 Protocol tunneling | Connection timing/volume metadata | No payload; no per-flow byte counts |
| T1041 Exfiltration over C2 | cgroup volume counters | Not per-process/per-flow; no universal threshold |

## 8. Verification status

- Structural: `cargo test --offline --all-targets` (includes
  `--test network_coverage_matrix`) — local, unprivileged.
- Format/lint: `cargo fmt --check` and
  `cargo clippy --offline --all-targets -- -D warnings`.
- Release build: locked/offline `cargo build --release --locked --offline` when
  the vendored dependency set is complete.
- Empirical network visibility and armed `-EPERM` on an isolated privileged
  kernel: **NOT EXECUTED IN THIS PASS** on this host (`CapEff=0x0`). Earlier VM
  runs are historical evidence only and are not reused as current-source proof.
- Resource doctor reads only `memory.max`, `pids.max` and `cpu.max`; open-file
  limits and IO weight are declared in the shipped budget but are explicitly
  NOT measured by `--doctor`.

## 9. Packaging contract

The standalone `Warden/` source tree carries its own
`docs/security/warden_coverage_matrix.md` and
`docs/security/warden_phase7_egress_enforcement.md`, so
`tests/network_coverage_matrix.rs` uses paths under `CARGO_MANIFEST_DIR` and an
extracted archive can build without the surrounding repository. Packaging and
release notes must ship those two files alongside the source; an archive that
omits them is incomplete even if compilation succeeds elsewhere.

## 10. Mission 16 delta

The coverage facts above are unchanged: M16 did not alter the BPF object, the
event schema, the six network hooks or the SENTINEL wire contract. It added the
configuration UX and evidence around them.

- `schema_version = 1` is now an explicit document anchor; legacy version 0
  still loads. The config engine serializes/reparses the same `Config` used by
  the daemon, with profiles that are observe-only and capability-aware.
- Additional structural gates: 9 config-engine unit tests plus the shell
  regressions `scripts/tests/test_config_engine_cli.sh` and
  `scripts/tests/test_install_wizard.sh`.
- Isolated VM `debian13`, kernel `6.12.107+deb13-amd64`: a throwaway observer
  with `net_volume.enabled = true` attached six `warden_vol_*` programs and two
  volume maps while the installed four-hook service stayed active with
  `NRestarts=0`. Controlled loopback traffic produced non-zero per-hook
  invocation deltas on all six hooks and a cgroup volume row (evidence
  `M16_09_vm_privileged_live_validation.txt`); cleanup returned the VM to four
  volume programs and two maps.
- A 60 s observe-only load measurement on the same VM produced 32,797 ring
  submissions and 0 drops for that workload, 3.400 s agent CPU and a 732 KiB
  RSS increase. These are one-VM observations, not throughput limits, universal
  thresholds or a long-duration soak. Long-duration soak remains `UNKNOWN`.
- Live SENTINEL platform boundary remains `BLOCKED`; stored-event ingest
  evidence from M15 is historical and is not relabelled as live delivery.
