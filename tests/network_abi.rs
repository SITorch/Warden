//! N-01 / stage 13: the network record's `aux2` is one 32-bit word written by two
//! kernel programs, defined in one header, and read by one decoder — and a
//! disagreement between them is silent by construction.
//!
//! The defect this pins is the one the audit raised as N-01: a UDP dial to
//! `8.8.8.8:53` and a TCP dial to the same endpoint arrived byte-identical, so the
//! agent could not tell a resolver from a tunnel and the platform's flow contract
//! (`<parent-project>/sentinel/ndr/records.py`, which requires `protocol`) had nothing to
//! put in the column. The fix packs family and `sk_protocol` into the reserved
//! `aux2` of CONNECT/LISTEN — no size change, no new kind, so every existing
//! record still decodes.
//!
//! That same choice is what makes drift possible: if the Rust shift and the C
//! define disagree, records still parse, findings still fire, and the transport
//! label becomes noise an analyst reads as fact. The compiler cannot see across
//! `bpf/warden.h` → `bpf/warden.bpf.c` → `src/events.rs` → `src/detect.rs`, so
//! this file checks the chain textually. Nothing here needs privileges.
//!
//! The second thing it pins is the harder rule, the one a future "improvement"
//! breaks: `aux2` is append-only and a protocol byte of 0 means *absence*. An
//! object predating this stage wrote only the family there, so the high byte is
//! 0; and 0 is simultaneously a legal `sk_protocol` (`IPPROTO_IP` on a raw
//! socket). Those two cases are indistinguishable on the wire, so both must yield
//! "no claim" — never `"other"`, and never a reskew of the bits to fill the gap.
//!
//! Stage 14 (N-02) took the remaining 8 bits — outcome at 24..31 — and pulled the
//! shared logic out of the two network programs into helpers, because a third
//! producer had to agree with the first two byte-for-byte. The checks below are
//! anchored on the helpers for that reason; `tests/connect_outcome_abi.rs` covers
//! the outcome itself.

/// Read the numeric literal off a declaration line, anchored on the declaration
/// text itself: the bare names also appear in prose and in the programs, and a
/// plain `find` would read a sentence instead of a definition.
///
/// Three files, three syntaxes for one number — `#define X 0x3Cu`, `X = 16,` in
/// an enum, and `pub const X: u32 = 0x00FF_0000;` — so take the token after `=`
/// when the declaration has one, and otherwise the first token that starts with a
/// digit. Scanning for "a number" plainly would read `u32` as 32.
fn decl_value(source: &str, declaration: &str, file: &str) -> u32 {
    let at = source.find(declaration).unwrap_or_else(|| {
        panic!("`{declaration}` is no longer in {file} — the ABI was renamed or removed")
    });
    let line = source[at..].lines().next().unwrap_or("");
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let value = match tokens.iter().position(|t| *t == "=") {
        Some(eq) => *tokens.get(eq + 1).unwrap_or(&""),
        None => tokens
            .iter()
            .copied()
            .find(|t| t.starts_with(|c: char| c.is_ascii_digit()))
            .unwrap_or(""),
    };
    let cleaned: String = value
        .chars()
        .filter(|c| *c != '_' && !matches!(c, 'u' | 'U' | ';' | ','))
        .collect();
    let parsed = if let Some(hex) = cleaned.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else if !cleaned.is_empty() && cleaned.chars().all(|c| c.is_ascii_digit()) {
        cleaned.parse().ok()
    } else {
        None
    };
    parsed.unwrap_or_else(|| panic!("no numeric literal on the declaration line in {file}: {line}"))
}

/// The body of one kprobe program, from its `int BPF_KPROBE(name` to the next
/// `SEC(`. Scoped extraction rather than whole-file `contains`, so a string that
/// exists only in the header comment above the program cannot satisfy a check
/// about the program.
fn kprobe_body<'a>(source: &'a str, name: &str) -> &'a str {
    let anchor = format!("int BPF_KPROBE({name}");
    let at = source
        .find(&anchor)
        .unwrap_or_else(|| panic!("{name} is no longer a kprobe in bpf/warden.bpf.c"));
    let rest = &source[at..];
    let end = rest.find("\nSEC(").unwrap_or(rest.len());
    &rest[..end]
}

/// The body of one `static __always_inline` helper, from its signature to its
/// closing brace. Stage 14 moved the aux2 packing, the `sk_protocol` read and the
/// sockaddr decode out of the programs and into shared helpers; a check about the
/// layout has to read the helper that now owns it, and a whole-file `contains`
/// would let the check pass on a comment.
fn cfn_body<'a>(source: &'a str, signature: &str, file: &str) -> &'a str {
    let at = source.find(signature).unwrap_or_else(|| {
        panic!(
            "`{signature}` is no longer in {file} — the shared helper was renamed or inlined away"
        )
    });
    let rest = &source[at..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{signature} in {file} no longer ends with a column-0 brace"));
    &rest[..end]
}

/// The text of one method inside one `impl` block. Anchoring on the impl rather
/// than the method matters: `events.rs` has six identical
/// `pub fn as_str(self) -> &'static str` signatures, and a bare name search lands
/// on whichever enum happens to be first in the file — which would have this test
/// assert about `Kind`'s labels while `Protocol`'s drifted freely.
fn impl_method<'a>(source: &'a str, impl_head: &str, method: &str, file: &str) -> &'a str {
    let at = source
        .find(impl_head)
        .unwrap_or_else(|| panic!("`{impl_head}` is no longer in {file}"));
    let rest = &source[at..];
    let m = rest
        .find(method)
        .unwrap_or_else(|| panic!("{method} is no longer in {impl_head} in {file}"));
    let body = &rest[m..];
    let end = body
        .find("\n    }\n")
        .unwrap_or_else(|| panic!("{method} in {impl_head} is no longer a 4-space-indented fn"));
    &body[..end]
}

const HEADER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.h"));
const BPF: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.c"));
const EVENTS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/events.rs"));
const DETECT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));

#[test]
fn the_packing_is_the_same_numbers_on_both_sides_of_the_abi() {
    let c_proto_shift = decl_value(HEADER, "WARDEN_NET_PROTO_SHIFT", "bpf/warden.h");
    let rust_proto_shift = decl_value(EVENTS, "pub const WARDEN_NET_PROTO_SHIFT", "src/events.rs");
    let c_family_mask = decl_value(HEADER, "#define WARDEN_NET_FAMILY_MASK", "bpf/warden.h");
    let rust_family_mask = decl_value(EVENTS, "pub const WARDEN_NET_FAMILY_MASK", "src/events.rs");
    let c_proto_mask = decl_value(HEADER, "#define WARDEN_NET_PROTO_MASK", "bpf/warden.h");
    let rust_proto_mask = decl_value(EVENTS, "pub const WARDEN_NET_PROTO_MASK", "src/events.rs");

    assert_eq!(
        (c_family_mask, c_proto_shift, c_proto_mask),
        (rust_family_mask, rust_proto_shift, rust_proto_mask),
        "the kernel writes the transport at bits {:?} and userspace reads it at {:?}: \
         every network record would still decode, and the protocol label would be \
         noise an analyst reads as fact",
        (c_family_mask, c_proto_shift, c_proto_mask),
        (rust_family_mask, rust_proto_shift, rust_proto_mask),
    );

    // The C define lives in an enum, not a #define, so check the family shift the
    // same way it is declared.
    assert_eq!(
        decl_value(HEADER, "WARDEN_NET_FAMILY_SHIFT", "bpf/warden.h"),
        0,
        "the family moved off its historic position. The pre-stage-13 record put the \
         family at bits 0..15 with nothing above it; relocating it breaks every old \
         object's output, which is the append-only rule this stage was built to keep."
    );

    // Structural properties a packing must have and a typo breaks.
    let c_result_mask = decl_value(HEADER, "#define WARDEN_NET_RESULT_MASK", "bpf/warden.h");
    let c_result_shift = decl_value(HEADER, "WARDEN_NET_RESULT_SHIFT", "bpf/warden.h");
    let rust_result_mask = decl_value(EVENTS, "pub const WARDEN_NET_RESULT_MASK", "src/events.rs");
    let rust_result_shift =
        decl_value(EVENTS, "pub const WARDEN_NET_RESULT_SHIFT", "src/events.rs");
    assert_eq!(
        (c_result_shift, c_result_mask),
        (rust_result_shift, rust_result_mask),
        "the kernel stamps the connect outcome at bits {:?} and userspace reads it at \
         {:?}: the endpoint and transport would still decode, and the verdict would be \
         noise an analyst reads as a network fact",
        (c_result_shift, c_result_mask),
        (rust_result_shift, rust_result_mask),
    );
    assert_eq!(
        c_family_mask & c_proto_mask,
        0,
        "the family and transport fields overlap: a transport byte would decode as \
         part of an address family, and the decoder would then misread the address"
    );
    assert_eq!(
        c_result_mask & (c_family_mask | c_proto_mask),
        0,
        "the outcome field overlaps the family or the transport — one dial would decode \
         as a different endpoint or a different protocol"
    );
    assert_eq!(
        c_family_mask, 0xFFFF,
        "the family field is not 16 bits — the kernel's sa_family_t is"
    );
    assert_eq!(
        c_proto_mask >> c_proto_shift,
        0xFF,
        "the transport field is not 8 bits. sk_protocol is one byte; a wider field \
         claims a range the kernel never writes."
    );
    assert_eq!(
        c_result_mask >> c_result_shift,
        0xFF,
        "the outcome field is not 8 bits. The enum needs room for a code appended later, \
         and a narrower field silently collides two verdicts."
    );
    assert_eq!(
        c_proto_mask >> c_proto_shift << c_proto_shift,
        c_proto_mask,
        "the transport mask is not aligned to the shift it is read with"
    );
    assert_eq!(
        c_result_mask >> c_result_shift << c_result_shift,
        c_result_mask,
        "the outcome mask is not aligned to the shift it is read with"
    );
    assert_ne!(
        c_family_mask | c_proto_mask,
        u32::MAX,
        "the packing uses all 32 bits, so the next network field has nowhere to go \
         and will be added by resizing the record instead of by appending bits"
    );
    // Stage 14 spent the last free byte. This is not a failure, it is a notice: the
    // next network field cannot be an append, so it has to be argued as a record
    // resize (a new `struct warden_event` size, pinned by the assert in events.rs)
    // or put somewhere else.
    assert_eq!(
        c_family_mask | c_proto_mask | c_result_mask,
        u32::MAX,
        "aux2 no longer has family + transport + outcome as its three fields. If a field \
         was REMOVED, the records an older object wrote stop decoding — append-only ABI. \
         If one was added, say so here and stop pretending there is room."
    );
}

#[test]
fn both_sides_use_the_kernels_address_family_numbers() {
    // The decoder cannot ask the kernel what AF_INET is; it compares the number
    // the program stamped. If either side's constant is wrong, connect records
    // decode to no destination at all — the failure looks like a silent sensor,
    // not a mismatched constant.
    let c_v4 = decl_value(BPF, "#define AF_INET ", "bpf/warden.bpf.c");
    let c_v6 = decl_value(BPF, "#define AF_INET6", "bpf/warden.bpf.c");
    let rust_v4 = decl_value(EVENTS, "const AF_INET: u32", "src/events.rs");
    let rust_v6 = decl_value(EVENTS, "const AF_INET6: u32", "src/events.rs");
    assert_eq!(
        (c_v4, c_v6),
        (rust_v4, rust_v6),
        "the address family numbers disagree between the program and the decoder"
    );
    // They are uapi ABI (`include/uapi/linux/socket.h`), not our choice.
    assert_eq!(
        (c_v4, c_v6),
        (2, 10),
        "AF_INET/AF_INET6 are fixed by the kernel's uapi; changing them here changes \
         nothing on the host and silently discards every network record"
    );
}

#[test]
fn every_network_program_stamps_the_same_layout_from_the_socket() {
    // One packer, three callers: the producers cannot drift from each other, and a
    // fourth network kind has to go through the same rules.
    let packer = cfn_body(
        BPF,
        "static __always_inline __u32 warden_net_aux2_ex(",
        "bpf/warden.bpf.c",
    );
    assert!(
        packer.contains("proto > 0xFFu"),
        "the packer no longer rejects a transport too wide for its 8 bits. sk_protocol \
         is a u16 now; truncating it would turn one transport into another."
    );
    assert!(
        packer.contains("<< WARDEN_NET_PROTO_SHIFT") && !packer.contains("<< 16"),
        "the packer shifted by a literal instead of the ABI constant, which is the one \
         edit that makes the C and Rust sides disagree invisibly"
    );
    assert!(
        packer.contains("<< WARDEN_NET_RESULT_SHIFT") && !packer.contains("<< 24"),
        "the outcome is stamped by a literal bit count rather than the ABI constant"
    );
    assert!(
        packer.contains("family & WARDEN_NET_FAMILY_MASK"),
        "the family is no longer masked on the way in, so a producer can spill into the \
         transport field by accident — the reason the mask is applied here at all"
    );

    // The two-argument wrapper is what a program with no verdict to state calls. It
    // must say so with the ABI's zero, never by picking a category.
    let wrapper = cfn_body(
        BPF,
        "static __always_inline __u32 warden_net_aux2(__u32 family, __u16 proto)",
        "bpf/warden.bpf.c",
    );
    assert!(
        wrapper.contains("WARDEN_CONNECT_NO_CLAIM"),
        "the no-verdict wrapper stopped stamping the outcome as NO_CLAIM. CONNECT and \
         LISTEN would start carrying an outcome byte the decoder reads as a verdict."
    );

    // The transport comes off the socket, in the one place that reads it.
    // `sk_protocol` is a real BTF member of struct sock on the kernels this object
    // is built for; `__sk_common.skc_protocol` is the older spelling and does not
    // compile against a vmlinux.h without it — caught by `make bpf`, which is the
    // only reason anyone found out.
    let sock_proto = cfn_body(
        BPF,
        "static __always_inline __u16 warden_sock_proto(",
        "bpf/warden.bpf.c",
    );
    assert!(
        sock_proto.contains("BPF_CORE_READ(sk, sk_protocol)"),
        "the socket no longer supplies the transport. Hardcoding it from a syscall's \
         contract is exactly the fabrication N-01 was raised about."
    );
    assert!(
        !sock_proto.contains("skc_protocol"),
        "warden_sock_proto reads __sk_common.skc_protocol, a member struct sock_common \
         does not have on the kernels this object is built for (see N-14)"
    );
    assert!(
        sock_proto.contains("return 0;"),
        "a missing sk no longer yields the 'no claim' transport byte"
    );

    // One sockaddr reader, so the attempt and its verdict cannot disagree about the
    // endpoint they describe.
    let dst = cfn_body(
        BPF,
        "static __always_inline void warden_read_dst(",
        "bpf/warden.bpf.c",
    );
    for member in [
        "sin_addr.s_addr",
        "sin_port",
        "sin6_port",
        "sin6_addr.in6_u.u6_addr8",
    ] {
        assert!(
            dst.contains(member),
            "the shared sockaddr reader no longer reads {member}, so one of the two \
             inet families decodes to an endpoint the other family's record contradicts"
        );
    }

    // Each program's own stamp line, and the zeroing that must precede it.
    for (name, stamp) in [
        (
            "warden_on_connect",
            "e->aux2 = warden_net_aux2(family, warden_sock_proto(sock));",
        ),
        (
            "warden_on_listen",
            "e->aux2 = warden_net_aux2(family, proto);",
        ),
    ] {
        let body = kprobe_body(BPF, name);
        assert!(
            body.contains(stamp),
            "{name} no longer packs aux2 through the shared helper, so the decoder's \
             masks would not match what this program writes"
        );
        if name == "warden_on_listen" {
            // The listener has already unwrapped `sk` for its own endpoint reads, so
            // it takes the transport from that pointer rather than the helper. Same
            // accessor, same rule: read it off the kernel, never assume it.
            assert!(
                body.contains("BPF_CORE_READ(sk, sk_protocol)"),
                "{name} no longer reads sk_protocol off the socket"
            );
            assert!(
                !body.contains("skc_protocol"),
                "{name} reads __sk_common.skc_protocol for the transport (see N-14)"
            );
        }
        // Stamping has to happen after the record is zeroed, or a previous
        // occupant of the slab survives into the aux2 high byte.
        let memset = body
            .find("__builtin_memset(e, 0, sizeof(*e))")
            .unwrap_or_else(|| panic!("{name} no longer zeroes the record before filling it"));
        let at = body.find(stamp).expect("the stamp is asserted above");
        assert!(
            memset < at,
            "{name} packs aux2 before zeroing the record, so an unstamped field can \
             carry bytes from the previous record"
        );
    }
}

#[test]
fn an_unreadable_socket_costs_the_claim_not_the_record() {
    // `connect(2)` gives us the destination from its own argument, so a connect
    // whose `sock->sk` is unreadable is still a real, attributable egress
    // observation with no transport. Dropping it to keep the record "clean" would
    // trade a null field for a missing event — the classify-never-silence rule the
    // signal sensor follows too.
    let connect = kprobe_body(BPF, "warden_on_connect");
    assert!(
        connect.contains("warden_sock_proto(sock)"),
        "the connect path no longer gets its transport from the helper that returns the \
         'no claim' byte for a missing sk"
    );
    assert!(
        !connect.contains("if (!sk)"),
        "the connect path bails out on an unreadable socket again. The destination, \
         port and actor all come from arguments that are still valid there: egress \
         would go unrecorded to avoid a null protocol."
    );
    // The helper's own contract: a null sk is a zero, not a bail-out.
    let sock_proto = cfn_body(
        BPF,
        "static __always_inline __u16 warden_sock_proto(",
        "bpf/warden.bpf.c",
    );
    assert!(
        sock_proto.contains("if (!sk)") && sock_proto.contains("return 0;"),
        "warden_sock_proto no longer maps a missing sk onto the transport byte that \
         means 'no claim', which is the only reason the connect record can survive one"
    );
    // listen(2) is the opposite case and stays that way: without sk there is no
    // bound endpoint at all, so there is nothing worth recording.
    let listen = kprobe_body(BPF, "warden_on_listen");
    assert!(
        listen.contains("if (!sk)"),
        "the listen path lost its sk null-check. It reads the bound endpoint and port \
         off skc_*, so a null socket would produce a listener record with no address."
    );
}

#[test]
fn a_zero_transport_byte_is_absence_and_is_never_relabelled() {
    let at = EVENTS
        .find("fn net_aux2(")
        .expect("the network aux2 split is the decoder's only reader of the packing");
    let body = &EVENTS[at..EVENTS[at..]
        .find("\n}\n")
        .map(|o| at + o + 2)
        .unwrap_or(EVENTS.len())];
    assert!(
        body.contains("0 => None,"),
        "a protocol byte of 0 no longer decodes to None. It is what every record \
         written before this stage carried AND what IPPROTO_IP carries now, so \
         labelling it as a transport invents an observation."
    );
    assert!(
        !body.contains("0 => Some"),
        "the decoder claims a transport from the byte that means 'nothing was stamped'"
    );
    assert!(
        !body.contains(">> 16") && !body.contains(">> 15") && !body.contains(">> 17"),
        "the decoder shifted a hardcoded bit count instead of the ABI constant — the \
         one edit that makes the C and Rust sides disagree invisibly"
    );
}

#[test]
fn the_transport_labels_are_the_platforms_existing_flow_vocabulary() {
    // The far side already refuses unknown values in this column
    // (`ndr/records.py`: KNOWN_PROTOCOLS + DEFAULT_PROTOCOL = "other"), and a
    // Warden finding is judged by the same humans. A private spelling — "TCP",
    // "proto_6", an integer — is either rejected downstream or silently unjoinable.
    let body = impl_method(EVENTS, "impl Protocol {", "pub fn as_str(", "src/events.rs");
    for label in ["\"tcp\"", "\"udp\"", "\"icmp\"", "\"other\""] {
        assert!(
            body.contains(label),
            "the wire label {label} is gone. The transport names are the platform's, \
             not ours to rename."
        );
    }
    assert!(
        !body.contains("\"Other\"") && !body.contains("\"TCP\""),
        "a transport label was capitalised — the flow contract is lowercase"
    );

    // And the numbers behind them are the kernel's IPPROTO_* constants.
    let body = impl_method(
        EVENTS,
        "impl Protocol {",
        "pub fn from_u8(",
        "src/events.rs",
    );
    for (num, variant) in [
        ("6", "Protocol::Tcp"),
        ("17", "Protocol::Udp"),
        ("1", "Protocol::Icmp"),
    ] {
        assert!(
            body.contains(&format!("{num} => {variant}")),
            "IPPROTO_{num} no longer maps to {variant}"
        );
    }
    assert!(
        body.contains("_ => Protocol::Other"),
        "an unrecognised transport no longer falls through to Other. It is a real \
         observation of an unusual transport (SCTP, raw, GRE); rejecting it would drop \
         traffic the host genuinely carried."
    );
}

#[test]
fn the_finding_reports_the_claim_and_the_absence_distinctly() {
    // Both halves matter: reporting the transport is the point of the stage, and
    // reporting null is the point of the append-only rule. A `unwrap_or("other")`
    // here would be the fabrication the decoder exists to prevent.
    assert_eq!(
        DETECT
            .matches("\"protocol\": e.protocol.map(Protocol::as_str)")
            .count(),
        2,
        "exactly two findings carry a transport — egress and listener. Anything else \
         that reports one is inventing a field the record never had."
    );
    assert!(
        !DETECT.contains("protocol.unwrap_or"),
        "judge_*/listen detail fills an absent transport with a guess"
    );
    // The header documents the packing where the ABI is read, so the next writer
    // of a network kind finds the rule instead of rediscovering it.
    assert!(
        HEADER.contains("sk_protocol at bits 16..23"),
        "bpf/warden.h no longer documents the per-kind aux2 packing for CONNECT/LISTEN \
         in the record table"
    );
}
