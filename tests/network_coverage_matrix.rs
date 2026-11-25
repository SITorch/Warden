//! Phase 2 + Phase 7: a machine-checkable network coverage matrix.
//!
//! `docs/security/warden_coverage_matrix.md` is the human-readable promise.
//! The canonical copies live under the standalone `Warden/` source tree, so an
//! extracted archive can build without the surrounding repository. Prose cannot
//! fail a build, so this test freezes the structural half of that promise
//! against the exact eBPF object the binary embeds: which network programs ship,
//! which hook families must NOT ship, which maps back the claims, and which
//! limitations the documentation must keep saying out loud.
//!
//! Phase 7 added four optional cgroup egress programs. They are in the object
//! but attach only to a named isolated cgroup with `[egress] enabled = true`,
//! and deny only with `arm = true` plus an exact rule. This test pins that
//! distinction: the hooks exist, they are documented, and no packet-level,
//! TC/XDP/sockops, or LSM-socket hook sneaks in beside them.
//!
//! This is unprivileged. It parses ELF section names and includes source text;
//! it never loads a program or touches a kernel map. The empirical half — that
//! a packet actually produced an event or was refused on a given kernel — needs
//! the isolated privileged VM and is explicitly NOT claimed here.

use aya::include_bytes_aligned;

fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

const BPF_C: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.c"));
const BPF_H: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.h"));
const COVERAGE_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/security/warden_coverage_matrix.md"
));
const PHASE7_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/security/warden_phase7_egress_enforcement.md"
));

fn u16le(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}
fn u64le(b: &[u8], o: usize) -> usize {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes")) as usize
}

/// ELF section names. A name containing `/` and not starting with `.` is a BPF
/// program section (`.relkprobe/…` is a relocation section; `.text`/`.maps` have
/// no slash). Same filter the capability matrix uses.
fn section_names(elf: &[u8]) -> Vec<String> {
    assert_eq!(&elf[0..4], b"\x7fELF", "embedded object is not ELF");
    let shoff = u64le(elf, 40);
    let shentsize = u16le(elf, 58);
    let shnum = u16le(elf, 60);
    let shstrndx = u16le(elf, 62);
    assert!(shstrndx < shnum, "bad section-header string-table index");
    let strtab = shoff + shstrndx * shentsize;
    let str_off = u64le(elf, strtab + 24);
    let mut out = Vec::new();
    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        let name_off = u32::from_le_bytes(elf[sh..sh + 4].try_into().unwrap()) as usize;
        let start = str_off + name_off;
        let end = elf[start..].iter().position(|&c| c == 0).expect("NUL") + start;
        let name = String::from_utf8_lossy(&elf[start..end]).into_owned();
        if name.contains('/') && !name.starts_with('.') {
            out.push(name);
        }
    }
    out
}

#[test]
fn the_documented_network_programs_are_the_ones_that_ship() {
    let sections = section_names(embedded_object());
    // Every network path the coverage matrix promises: connect intent, the
    // TCP verdict pair, the accepted-flow pair, the listen sensor, six volume
    // counters, and the four OPTIONAL Phase 7 cgroup egress hooks.
    for expected in [
        "kprobe/security_socket_connect",
        "kprobe/__inet_stream_connect",
        "kretprobe/__inet_stream_connect",
        "kprobe/inet_accept",
        "kretprobe/inet_accept",
        "kprobe/security_socket_listen",
        "fexit/tcp_sendmsg",
        "fexit/tcp_cleanup_rbuf",
        "fexit/udp_sendmsg",
        "fexit/udp_recvmsg",
        "fexit/udpv6_sendmsg",
        "fexit/udpv6_recvmsg",
        "cgroup/connect4",
        "cgroup/connect6",
        "cgroup/sendmsg4",
        "cgroup/sendmsg6",
    ] {
        assert!(
            sections.iter().any(|s| s == expected),
            "coverage matrix promises {expected} but it is not in the embedded object"
        );
    }
}

#[test]
fn only_the_documented_cgroup_egress_hooks_ship_and_they_are_gated() {
    let sections = section_names(embedded_object());
    let cgroup: Vec<&String> = sections
        .iter()
        .filter(|s| s.starts_with("cgroup/"))
        .collect();
    assert_eq!(
        cgroup.len(),
        4,
        "Phase 7's contract is exactly four cgroup socket-address programs, found {cgroup:?}"
    );
    // The source itself must carry both independent gates and the honest arm
    // default. A hook that could deny without the second switch would be a new
    // capability and must fail this contract before it can be described as safe.
    for token in [
        "CFG_EGRESS_ARM = 13",
        "egress_policy SEC",
        "egress_stats SEC",
        "SEC(\"cgroup/connect4\")",
        "SEC(\"cgroup/sendmsg6\")",
    ] {
        assert!(
            BPF_H.contains(token) || BPF_C.contains(token),
            "the Phase 7 ABI lost {token} from warden.h / warden.bpf.c"
        );
    }
    let phase7 = PHASE7_DOC.to_ascii_lowercase();
    for phrase in [
        "shadow by default",
        "enabled = true",
        "arm = true",
        "isolated",
    ] {
        assert!(
            phase7.contains(phrase),
            "Phase 7 doc dropped the gate caveat {phrase:?}"
        );
    }
}

#[test]
fn no_packet_level_hook_sneaks_in() {
    let sections = section_names(embedded_object());
    // cgroup/sock_addr sees the *intended destination* of connect/sendmsg before
    // a route is chosen; it is not a packet-level filter. These families remain
    // unsupported, exactly as the coverage matrix says.
    for forbidden in ["xdp", "sockops", "lsm/socket", "lsm/sendmsg"] {
        let hits: Vec<&String> = sections
            .iter()
            .filter(|s| s.to_ascii_lowercase().contains(forbidden))
            .collect();
        assert!(
            hits.is_empty(),
            "coverage matrix says {forbidden} is unsupported, but it ships: {hits:?}"
        );
    }
    // "tc" is a hook family, not a substring of "tcp_sendmsg": match the
    // section prefix only so the six volume counters are not false hits.
    let tc_hits: Vec<&String> = sections
        .iter()
        .filter(|s| s.as_str() == "tc" || s.starts_with("tc/"))
        .collect();
    assert!(tc_hits.is_empty(), "a TC program shipped: {tc_hits:?}");
}

#[test]
fn the_documented_datagram_gaps_are_closed_and_dns_is_still_absent() {
    // These are source/object claims plus the documentation boundary. M15
    // recorded verifier accept, attach and map bumps for both v6 hooks on the
    // isolated VM, so the old IMPLEMENTED_NOT_VALIDATED caveat is superseded;
    // the matrix must now carry the evidence label beside the claim instead.
    // DNS is still absent.
    assert!(
        BPF_C.contains("SEC(\"fexit/udpv6_sendmsg\")"),
        "IPv6 datagram egress volume program disappeared from the BPF source"
    );
    assert!(
        BPF_C.contains("SEC(\"fexit/udpv6_recvmsg\")"),
        "IPv6 datagram ingress volume program disappeared from the BPF source"
    );
    assert!(
        COVERAGE_DOC.contains("LIVE_VALIDATED_M15"),
        "the coverage matrix must name the M15 live-bump evidence for both v6 hooks"
    );
    assert!(
        !BPF_H.contains("WARDEN_KIND_DNS"),
        "a DNS event kind now exists in the header; update the matrix"
    );
    // Network-volume counters are keyed by cgroup, not by flow tuple, so the
    // doc's "no per-flow byte counts" claim remains accurate.
    assert!(BPF_C.contains("bpf_get_current_cgroup_id"));
}

#[test]
fn the_event_header_exposes_the_family_proto_and_verdict_bits() {
    for token in [
        "WARDEN_NET_FAMILY_SHIFT",
        "WARDEN_NET_PROTO_SHIFT",
        "WARDEN_NET_FAMILY_MASK",
        "WARDEN_NET_PROTO_MASK",
        "WARDEN_NET_RESULT_SHIFT",
        "WARDEN_NET_RESULT_MASK",
        "WARDEN_CONNECT_ESTABLISHED",
        "WARDEN_CONNECT_REFUSED",
    ] {
        assert!(BPF_H.contains(token), "network ABI lost {token}");
    }
}

#[test]
fn the_coverage_document_carries_every_limitation_it_claims() {
    let doc = COVERAGE_DOC.to_ascii_lowercase();
    for phrase in [
        "Egress enforcement",
        "cgroup/connect4",
        "cgroup/sendmsg6",
        "DNS payload",
        "DNS-like port-53",
        "unconnected UDP",
        "IPv6 datagram volume",
        "kernel_event_ts_ns",
        "TLS/QUIC",
        "network namespace",
        "ATT&CK",
        "restart required",
    ] {
        assert!(
            doc.contains(&phrase.to_ascii_lowercase()),
            "coverage matrix dropped the '{phrase}' limitation; a doc-only regression"
        );
    }
    assert!(
        !doc.contains("no cgroup/connect4") && !doc.contains("no `cgroup/connect4`"),
        "coverage matrix still claims the shipped cgroup hook is absent"
    );
}

#[test]
fn vendored_docs_match_the_repository_mirrors_when_present() {
    // The standalone Warden tree carries the canonical docs. The repository may
    // keep mirrors for the mission report; when it does, they must be identical
    // so a reader of either copy sees the same machine-checked promise. An
    // extracted archive has no `../docs` and is intentionally allowed to skip
    // this mirror check.
    let pairs = [
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/security/warden_coverage_matrix.md"
            ),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../docs/security/warden_coverage_matrix.md"
            ),
        ),
        (
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/docs/security/warden_phase7_egress_enforcement.md"
            ),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../docs/security/warden_phase7_egress_enforcement.md"
            ),
        ),
    ];
    for (canonical, mirror) in pairs {
        let mirror = std::path::Path::new(mirror);
        if !mirror.exists() {
            continue;
        }
        let canonical_text = std::fs::read_to_string(canonical)
            .expect("canonical vendored coverage doc must be readable");
        let mirror_text =
            std::fs::read_to_string(mirror).expect("repository coverage mirror must be readable");
        assert_eq!(
            canonical_text, mirror_text,
            "the repository mirror {mirror:?} drifted from the canonical vendored doc"
        );
    }
}
