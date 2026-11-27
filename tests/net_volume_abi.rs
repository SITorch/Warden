//! N-05 (stages 16b, 16f and the IPv6 datagram extension): the shipped
//! `bpf/warden.bpf.o` must carry the per-cgroup volume map, its health counter,
//! and the six fexit programs that fill them.
//!
//! This sensor is the first in Warden whose entire output is a MAP rather than a
//! record, and that is why it needs its own file. A ring record that drifts shows
//! up as a wrong field in one event; a counter map that drifts shows up as a
//! confidently wrong number. Concretely:
//!
//!   - `src/loader.rs` reads the map with `HashMap<MapData, u64, VolumeRecord>`,
//!     whose value type is 40 bytes of five u64s. If `bpf/warden.h` grows a field
//!     and the Rust mirror does not, aya's `Pod` contract is violated and every row
//!     is read against the wrong offsets — a `bytes_out` that is really `last_ns`.
//!     Nothing errors. The number is just wrong, and it is the kind of wrong that
//!     survives review because it looks like a measurement.
//!   - `net_volume_stats` is the denominator for the whole sensor (W2K-14's lesson,
//!     applied to the counter path): without slot 1, "no cgroup has a total" cannot
//!     be told apart from "no hook ever fired".
//!   - the six programs' section names encode their attach targets, and the
//!     targets are what `FExit::load` resolves through BTF at start-up. A rename
//!     here is a silent one-sided total, so the names are pinned as data.
//!   - `CFG_NET_VOLUME_EMIT` is slot 12 of `runtime_cfg`. `sensor_emitting()` fails
//!     OPEN, so an out-of-range slot does not error — it just never mutes. That is
//!     the one failure mode in this design that no runtime log would show.
//!
//! None of this needs privileges: it parses the embedded ELF and its BTF, and reads
//! the two source files the object must not drift from. What it cannot prove is the
//! empirical half — that a program LOADS on a given kernel and that a bump lands in
//! the right cgroup. §22 of `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` collected that for the
//! three stream/datagram-egress hooks on the deployment kernel, and §23 collected it
//! for the fourth, `fexit/udp_recvmsg`: all four attached on `6.12.107+deb13-amd64`
//! and a known IPv4 datagram transfer landed as `out 102400B/100 ops, in
//! 95232B/93 ops`. §23 also measured that an IPv6 datagram dispatches through
//! `udpv6_*` and was therefore invisible; §24 confirmed these names are attachable.
//! The two new v6 programs in this object are **IMPLEMENTED_NOT_VALIDATED_LIVE**:
//! these tests parse the ELF and the source, and cannot claim a verifier accept,
//! an attach, or a bump on any kernel.

use aya::include_bytes_aligned;
use aya_obj::generated::bpf_map_type;

fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

fn source(path: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/{}",
        env!("CARGO_MANIFEST_DIR"),
        path.trim_start_matches("./")
    ))
    .unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// Whether the object's string tables contain `name` as a complete,
/// NUL-terminated entry rather than as a fragment of some longer word. Used for
/// the section texts aya reads as the attach contract: `aya_obj::Program` keeps
/// the raw section name private, so the shipped ELF is the only place it exists.
/// The terminator is what stops `.relfexit/tcp_sendmsg` — a relocation section,
/// not a program — from being read as a match for `fexit/tcp_sendmsg`.
fn has_section_named(elf: &[u8], name: &str) -> bool {
    let needle = name.as_bytes();
    elf.windows(needle.len() + 1)
        .any(|w| &w[..needle.len()] == needle && w[needle.len()] == 0)
}

/// The integer a `name = VALUE` declaration assigns in a source file, anchored on
/// the declaration itself so prose that mentions the same identifier cannot be
/// read as its definition.
fn declared_usize(source: &str, declaration: &str, file: &str) -> u64 {
    let at = source.find(declaration).unwrap_or_else(|| {
        panic!(
            "`{declaration}` is no longer declared in {file} — the mirror was renamed or removed"
        )
    });
    let line = source[at..].lines().next().unwrap_or("");
    // Two shapes in `warden.h`: a `#define NAME VALUE`, and an enum member
    // `NAME = VALUE,` that may carry a trailing `/* … */` on the same line.
    let after_eq = line.split('=').nth(1);
    let value = match after_eq {
        Some(rest) => rest.trim_start(),
        None => line
            .split_whitespace()
            .last()
            .unwrap_or_else(|| panic!("`{line}` has no value token")),
    };
    let digits: String = value
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .parse()
        .unwrap_or_else(|e| panic!("`{line}` is not a numeric declaration: {e}"))
}

/// The tokens inside a `BPF_PROG(...)` in the object's own source: first the
/// program name, then the hooked function's arguments, then its return value.
/// Split on top-level commas only, so a `(*fn)(int)` style argument cannot be
/// read as two.
fn bpf_prog_params(src: &str, name: &str) -> Vec<String> {
    let marker = format!("BPF_PROG({name},");
    let at = src.find(&marker).unwrap_or_else(|| {
        panic!(
            "`{marker}` is no longer in bpf/warden.bpf.c — the program was renamed or the \
                attach contract is unpinned"
        )
    });
    let open = at + src[at..].find('(').unwrap();
    let mut depth = 0i32;
    let mut close = None;
    for (i, b) in src[open..].bytes().enumerate() {
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                close = Some(open + i);
                break;
            }
        }
    }
    let inner = &src[open + 1..close.expect("unbalanced BPF_PROG macro in bpf/warden.bpf.c")];
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for b in inner.bytes() {
        match b {
            b'(' | b')' => {
                depth += if b == b'(' { 1 } else { -1 };
                cur.push(b as char);
            }
            b',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(b as char),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// The body of one `BPF_PROG(...)` in the object's own source, from its opening
/// brace to the matching close. Used to assert ordering (invoke before bump),
/// which a whole-file `contains` check could not prove.
fn bpf_prog_body(src: &str, name: &str) -> String {
    let marker = format!("BPF_PROG({name},");
    let at = src
        .find(&marker)
        .unwrap_or_else(|| panic!("no BPF_PROG({name}"));
    let open = at
        + src[at..]
            .find('{')
            .unwrap_or_else(|| panic!("no opening brace after BPF_PROG({name}"));
    let mut depth = 0i32;
    for (i, b) in src[open..].bytes().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return src[open..=open + i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after BPF_PROG({name})");
}

#[test]
fn the_embedded_object_carries_the_volume_map_at_the_size_both_sides_agree_on() {
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");

    let map = obj.maps.get("net_volume").expect(
        "the embedded object has no `net_volume` map. `src/loader.rs` refuses to start without \
         it — a hard error, not an Option — because reading a map that is not there would print \
         a confident `0 cgroup(s) tracked`. Rebuild with `make bpf`: the object is embedded via \
         include_bytes_aligned!, so editing bpf/warden.bpf.c alone changes nothing at runtime.",
    );

    // A HASH, not a PERCPU_HASH or an LRU: the entry has to be SHARED for a total
    // to mean anything, and an LRU variant would silently evict a busy tenant's
    // accumulated bytes to make room for a new one — turning an audit trail into a
    // sliding window with no report of the eviction.
    assert_eq!(
        map.map_type(),
        bpf_map_type::BPF_MAP_TYPE_HASH as u32,
        "the volume map must be a plain hash; an eviction-typed map would forget totals it \
         never told anyone it forgot"
    );
    assert_eq!(
        map.max_entries(),
        512,
        "the cgroup bound is quoted by the coverage line and mirrored by \
         `loader::NET_VOLUME_MAX`; a mismatch tells an operator a bound the kernel does not have"
    );
    assert_eq!(map.key_size(), 8, "the key is the u64 cgroup id");
    assert_eq!(
        map.value_size(),
        40,
        "the value is `struct warden_net_volume`: five u64 fields, 40 bytes"
    );

    // The three ways this drifts silently, each pinned to the same number.
    let header = source("bpf/warden.h");
    assert_eq!(
        declared_usize(&header, "#define WARDEN_NET_VOLUME_MAX", "bpf/warden.h") as u32,
        map.max_entries(),
        "the C bound and the object disagree"
    );
    let loader = source("src/loader.rs");
    assert_eq!(
        declared_usize(&loader, "pub const NET_VOLUME_MAX", "src/loader.rs"),
        u64::from(map.max_entries()),
        "`loader::NET_VOLUME_MAX` is what the coverage line quotes as the bound; if it is not \
         the map's real size the sensor misreports its own ceiling"
    );
    assert!(
        header.contains("__u64 bytes_out;")
            && header.contains("__u64 ops_out;")
            && header.contains("__u64 bytes_in;")
            && header.contains("__u64 ops_in;")
            && header.contains("__u64 last_ns;"),
        "`struct warden_net_volume` must be exactly these five u64 fields in this order — \
         `net_vol::VolumeRecord` mirrors it field for field and `unsafe impl aya::Pod` says so"
    );
}

#[test]
fn the_volume_map_is_accompanied_by_its_own_denominator() {
    // W2K-14, applied to the counter path: totals with no "was the sensor ever
    // called" count cannot distinguish an idle host from six programs that never
    // attached. `src/loader.rs` reads both slots every tick and refuses to start
    // without the map.
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");

    let stats = obj.maps.get("net_volume_stats").expect(
        "the embedded object has no `net_volume_stats` map; without it a zero-total \
                 host and a dead hook are the same report",
    );
    assert_eq!(
        stats.map_type(),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32,
        "health must be counted per-CPU, or reporting health would put every CPU on one lock \
         in the data path this sensor exists to cheapen"
    );
    assert_eq!(stats.key_size(), 4, "the key is a u32 slot index");
    assert_eq!(stats.value_size(), 8, "the value is a u64 counter");

    let header = source("bpf/warden.h");
    let slot_names = [
        "WARDEN_NETVOLUME_FULL = 0",
        "WARDEN_NETVOLUME_BUMP = 1",
        "WARDEN_NETVOLUME_TCP_OUT = 2",
        "WARDEN_NETVOLUME_TCP_IN = 3",
        "WARDEN_NETVOLUME_UDP_OUT = 4",
        "WARDEN_NETVOLUME_UDP_IN = 5",
        "WARDEN_NETVOLUME_UDP6_OUT = 6",
        "WARDEN_NETVOLUME_UDP6_IN = 7",
        "WARDEN_NETVOLUME_STATS = 8",
    ];
    for name in slot_names {
        assert!(
            header.contains(name),
            "`{name}` is missing or renumbered in bpf/warden.h; the loader reads slots 0..8 by \
             index and a drift would label refusals as bumps or one hook's invocations as another's"
        );
    }
    let loader = source("src/loader.rs");
    for slot in [
        "NET_VOLUME_STAT_FULL: u32 = 0",
        "NET_VOLUME_STAT_BUMP: u32 = 1",
        "NET_VOLUME_STAT_TCP_OUT: u32 = 2",
        "NET_VOLUME_STAT_TCP_IN: u32 = 3",
        "NET_VOLUME_STAT_UDP_OUT: u32 = 4",
        "NET_VOLUME_STAT_UDP_IN: u32 = 5",
        "NET_VOLUME_STAT_UDP6_OUT: u32 = 6",
        "NET_VOLUME_STAT_UDP6_IN: u32 = 7",
    ] {
        assert!(
            loader.contains(slot),
            "`{slot}` is missing from loader.rs; the per-hook counters would be silently unread"
        );
    }
    assert_eq!(
        stats.max_entries(),
        8,
        "the two original health slots plus six per-hook invocation slots are required; a \
         smaller map would make some slots unreadable and a larger one would hide a new writer"
    );
}

#[test]
fn the_six_volume_programs_are_present_and_named_for_their_attach_targets() {
    // aya resolves the function from the section name and `FExit::load` looks it up
    // in the running kernel's BTF, so the section text IS the attach contract. A
    // program renamed or retargeted here while `net_vol::VolumeHook::func()` still
    // says the old name means the loader asks for a function nothing was compiled
    // against — and the missing direction would be reported under the wrong name.
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");
    let elf = embedded_object();

    let expected = [
        ("warden_vol_tcp_out", "fexit/tcp_sendmsg"),
        ("warden_vol_tcp_in", "fexit/tcp_cleanup_rbuf"),
        ("warden_vol_udp_out", "fexit/udp_sendmsg"),
        ("warden_vol_udp_in", "fexit/udp_recvmsg"),
        ("warden_vol_udp6_out", "fexit/udpv6_sendmsg"),
        ("warden_vol_udp6_in", "fexit/udpv6_recvmsg"),
    ];
    for (name, section) in expected {
        let prog = obj
            .programs
            .get(name)
            .unwrap_or_else(|| panic!("program {name} is missing from the embedded object"));
        assert!(
            matches!(prog.section, aya_obj::ProgramSection::FExit { .. }),
            "{name} is not an FExit program any more; the loader's `try_into::<FExit>` would \
             reject it, the hook would silently never attach, and the coverage line would name \
             a missing direction every tick"
        );
        assert!(
            has_section_named(elf, section),
            "the section `{section}` is not in the object any more — that text is what names \
             the kernel function FExit attaches to, so `{name}` would land on another function \
             or fail to load"
        );
    }

    // The Rust side's table of the same six, read from source rather than linked
    // so a mismatch is a red test instead of a compile error nobody notices.
    let net_vol = source("src/net_vol.rs");
    for (name, section) in expected {
        assert!(
            net_vol.contains(&format!("\"{name}\""))
                && net_vol.contains(&format!("\"{}\"", section.trim_start_matches("fexit/"))),
            "`net_vol::VolumeHook` no longer names {name} and its target; the coverage line \
             and the warn-on-missing would report a hook that does not exist"
        );
    }
}

#[test]
fn the_volume_hooks_argument_lists_match_the_kernels_own_btf_prototypes() {
    // An fexit program's parameters must restate the hooked function's prototype
    // exactly; one argument too many or too short is a load-time verifier
    // rejection, which on a running agent shows up as a COVERAGE GAP line rather
    // than a build failure. This is not a hypothetical: the §۳۹ design note gave
    // `tcp_sendmsg` a `struct socket *` first argument, and reading this host's
    // BTF before writing the hook is the only reason that did not ship.
    //
    // `bpf/vmlinux.h` IS that BTF, generated from the deployment kernel by
    // `make bpfheader` (Makefile), so the two authorities agree without needing a
    // running kernel — and this test still proves nothing about attach, which is
    // what §22 and §23 of the runbook are for.
    let obj_src = source("bpf/warden.bpf.c");
    let vmlinux = source("bpf/vmlinux.h");

    // The IPv6 datagram programs reuse these `struct proto` shapes; they are
    // protocol twins of their IPv4 counterparts, not socket-level ops.
    //
    // The two `recvmsg` members differ by one argument, and only one of them is
    // what `udp_recvmsg` implements. Pinning both texts is what stops a future
    // edit from "fixing" the hook into the socket-level shape.
    const PROTO_RECVMSG: &str =
        "int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);";
    const PROTO_OPS_RECVMSG: &str =
        "int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);";
    const PROTO_SENDMSG: &str = "int (*sendmsg)(struct sock *, struct msghdr *, size_t);";
    assert!(vmlinux.contains(PROTO_RECVMSG), "`struct proto::recvmsg` is no longer declared as {PROTO_RECVMSG:?} in bpf/vmlinux.h — the kernel's datagram receive path changed, and `warden_vol_udp_in` must change with it");
    assert!(
        vmlinux.contains(PROTO_OPS_RECVMSG),
        "expected the socket-level `struct proto_ops::recvmsg` beside it; if this host's BTF \
         no longer has that member the two-prototype guard below proves nothing"
    );

    let cases = [
        ("warden_vol_tcp_out", PROTO_SENDMSG, 3),
        ("warden_vol_udp_out", PROTO_SENDMSG, 3),
        ("warden_vol_udp_in", PROTO_RECVMSG, 5),
        ("warden_vol_udp6_out", PROTO_SENDMSG, 3),
        ("warden_vol_udp6_in", PROTO_RECVMSG, 5),
    ];
    for (prog, proto, n_args) in cases {
        let params = bpf_prog_params(&obj_src, prog);
        assert_eq!(
            params.first().map(String::as_str),
            Some(prog),
            "`{prog}` is not the first token of its own BPF_PROG"
        );
        assert_eq!(
            params.last().map(String::as_str),
            Some("int ret"),
            "`{prog}` must end with the hooked function's return value — that is what carries \
             the byte count, and dropping it counts 0 bytes for every call"
        );
        let args = &params[1..params.len() - 1];
        assert_eq!(
            args.len(),
            n_args,
            "`{prog}` declares {} arguments but the kernel's prototype `{proto}` has {n_args}: \
             the verifier will reject the load and the direction this hook feeds will report as \
             a coverage gap",
            args.len()
        );
        assert!(
            args[0].starts_with("struct sock "),
            "`{prog}` must take the `struct sock *` the {proto} prototype declares, not the \
             `struct socket *` that belongs to the socket-level ops"
        );
    }
}

#[test]
fn the_volume_gate_slot_is_inside_the_config_array_the_kernel_reads() {
    // `sensor_emitting()` fails OPEN by design. That is the right default for a
    // sensor gate, and it makes an out-of-range slot index undetectable at
    // runtime: the kernel would read a different slot or none, the mute would do
    // nothing, and the operator's `enabled = false` would silently keep counting.
    // So the slot index is pinned against the array's real size.
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");
    let cfg = obj
        .maps
        .get("runtime_cfg")
        .expect("the embedded object has no `runtime_cfg` map");
    assert_eq!(
        cfg.map_type(),
        bpf_map_type::BPF_MAP_TYPE_ARRAY as u32,
        "runtime_cfg is a plain array so every slot reads a defined value; per-CPU here would \
         let two CPUs disagree about whether a sensor is muted"
    );

    let header = source("bpf/warden.h");
    let loader = source("src/loader.rs");
    let slot_count = declared_usize(&header, "CFG_SLOT_COUNT", "bpf/warden.h");
    let volume_slot = declared_usize(&loader, "const CFG_NET_VOLUME_EMIT", "src/loader.rs");

    assert_eq!(
        slot_count as u32,
        cfg.max_entries(),
        "CFG_SLOT_COUNT and the map's size must be one decision; the kernel reads slots by \
         index and userspace writes them by the same numbers"
    );
    assert!(
        volume_slot < slot_count,
        "CFG_NET_VOLUME_EMIT = {volume_slot} is outside the {slot_count}-slot array: the gate \
         would fail open and the sensor could never be muted"
    );
    assert_eq!(
        volume_slot, 12,
        "slot indices are ABI and are numbered, never reused — a renumbered gate is a config \
         file whose `enabled` now means something else"
    );
}

#[test]
fn the_volume_sensor_adds_programs_without_touching_the_record_abi() {
    // The whole point of the map was to not spend ring records, so this stage must
    // not have changed the record, the kind slots, or the FLOW kind. If it had, the
    // decoder in `src/events.rs` and the platform's ingest would be reading a
    // different struct than the one shipped.
    let header = source("bpf/warden.h");
    assert_eq!(
        declared_usize(&header, "#define WARDEN_KIND_SLOTS", "bpf/warden.h"),
        16,
        "the per-sensor counter maps are sized by this; the volume stage adds no event kind"
    );
    assert!(
        header.contains("WARDEN_FLOW = 14"),
        "WARDEN_FLOW is stage 16's kind and must not be renumbered by 16b"
    );
    assert!(
        !header.contains("WARDEN_NETVOLUME = ") && !header.contains("WARDEN_VOLUME = "),
        "a volume EVENT kind would defeat the design: the answer must come from a map, not \
         from records the lossy ring can drop"
    );

    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");
    let events = obj.maps.get("events").expect("the ring map");
    assert_eq!(
        events.map_type(),
        bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32,
        "the ring is still the record channel; the volume totals live beside it, not inside it"
    );
    assert_eq!(
        obj.programs.len(),
        32,
        "22 programs shipped before stage 16b, three fexit programs made it 25, stage 16f's \
         datagram-ingress hook made 26, Phase 7's four optional cgroup egress hooks made 30, and \
         this revision's two IPv6 datagram volume hooks make 32; a different count means a program \
         was lost or added without the loader and the runbook changing with it"
    );
}

#[test]
fn the_volume_gate_is_rewritten_on_reload_from_the_value_the_kernel_actually_holds() {
    // W2K-31's surviving half. `sensor_emitting()` reads slot 12 on every bump, so
    // the gate is a map write, not a rebuild — a SIGHUP can apply it completely.
    // Before this stage it had exactly one caller, at boot, while the tick that
    // reports the totals reads `detector.config().net_volume`, which the reload
    // DOES replace. So the two halves of one sensor moved at different speeds:
    // enabled → disabled kept counting bytes in the kernel for a report that had
    // gone quiet, and disabled → enabled printed a tick whose totals could not
    // have moved. Both are the failure this file's header already names for the
    // slot index — a config value that silently means something else.
    //
    // Anchored across files on purpose. Inside `src/main.rs` an assertion about
    // this text would match the assertion itself (§۷۰ measured that: the test
    // stayed green with the term deleted); from here `src/main.rs` is data.
    let main = source("src/main.rs");

    // The boot seed is still there, and the reload write still is not it.
    assert!(
        main.contains("loaded.set_net_volume_emit(cfg.net_volume.enabled)?;"),
        "the boot seed is what defines the gate's initial value; without it the reload \
         comparison has nothing to have been comparing against"
    );
    assert!(
        main.contains("loaded.set_net_volume_emit(fresh.net_volume.enabled)?;"),
        "SIGHUP does not rewrite CFG_NET_VOLUME_EMIT, so `[net_volume].enabled` is a boot-only \
         setting while the reporting side of the same sensor follows every reload"
    );

    // The comparison is the whole fix, so it is pinned as tightly as the write.
    assert!(
        main.contains("if fresh.net_volume.enabled != volume_emit {"),
        "the reload compares against `volume_emit`, the value this process last wrote to the \
         slot"
    );
    assert!(
        !main.contains("if fresh.net_volume.enabled != cfg.net_volume.enabled"),
        "comparing against `cfg` is the trap: `cfg` deliberately keeps the boot values forever, \
         so the second half of an `true → false → true` edit would read as 'unchanged' and the \
         kernel would stay muted behind a tick that reports totals"
    );
    assert!(
        main.contains("let mut volume_emit = cfg.net_volume.enabled;"),
        "the live value has to be initialised from the same write that sets it, or the first \
         reload is comparing against a number nobody put in the map"
    );
    assert!(
        main.contains("volume_emit = fresh.net_volume.enabled;"),
        "the state must follow the write — a gate that was applied but not remembered is a \
         gate that gets re-applied on every reload, which makes the next assertion lie"
    );

    // An operator has to be able to tell, from the journal alone, which posture
    // the kernel is in. A bare "reloaded config" would claim the whole file.
    assert!(
        main.contains("net_volume emit gate {} → {}, applied now"),
        "the flip is the one thing in this branch that changes what the kernel does per packet; \
         saying it in the same voice as the responder's mode flip is what makes it findable"
    );
    assert!(
        main.contains("net_vol::coverage_line(&fresh.net_volume, Some(&loaded.volume_hooks))"),
        "the coverage line is the sentence that states what the gate costs and what it answers, \
         and it was printed once at boot about the OLD posture"
    );
    // The fragment, not the whole sentence: rustfmt wraps the summary's string
    // literal across lines, and an anchor that spans the wrap tests the formatter
    // rather than the code.
    assert!(
        main.contains("(kernel gate = {}, interval = {} s)")
            && main.contains("yes_no(volume_emit)"),
        "every reload states the live gate, not only a flip: `enabled = true` in a file nobody \
         reloaded is a different claim from a kernel holding 1"
    );

    // The other direction of the same honesty: `[bridge]` genuinely cannot be
    // re-applied, and that is why it is listed as NOT applied instead of written.
    // The volume gate crossed that line in this stage, so it must have left the
    // restart-required list — a field named in both places is a field whose
    // posture the operator cannot read off the journal. Scoped to the helper that
    // builds the list, because the reload branch beside it now legitimately
    // mentions net_volume where it applies the gate.
    let helper_at = main.find("fn unapplied_reload_changes").expect(
        "`unapplied_reload_changes` is gone: the reload path can no longer say what it \
                 did NOT apply",
    );
    let helper_body = &main[helper_at
        ..helper_at
            + main[helper_at..]
                .find("\n}\n")
                .expect("the helper's body end")];
    assert!(
        helper_body.contains("unapplied_bridge_changes")
            && helper_body.contains("unapplied_heartbeat_changes")
            && helper_body.contains("ring_size_kib"),
        "the restart-required list must still name [bridge], [heartbeat] and the ring size, or \
         the `applied …` line stops meaning anything: this stage moved exactly one field across \
         that line"
    );
    assert!(
        !helper_body.contains("net_volume"),
        "`[net_volume]` is applied on reload now; naming it in the restart-required list too \
         would leave two opposite statements about one field in the same reload"
    );
}

#[test]
fn udp_receive_charges_bytes_the_caller_could_actually_receive() {
    // Linux v6.12 returns the original datagram length under MSG_TRUNC. A BPF
    // fexit that charges `ret` then claims more bytes were copied than fit in
    // the caller's buffer. Both receive hooks must go through one cap helper,
    // and the cap must be `min(ret, len)` rather than a flags-dependent guess.
    let src = source("bpf/warden.bpf.c");
    assert!(
        src.contains("MSG_TRUNC"),
        "the reason for the cap must remain documented next to the hook"
    );
    let helper_at = src
        .find("static __always_inline __u64 net_volume_recv_bytes(int ret, size_t len)")
        .expect("the shared UDP receive cap helper is missing");
    let helper = &src[helper_at..helper_at + 500];
    assert!(helper.contains("ret <= 0"), "{helper}");
    assert!(
        helper.contains("charged < capacity ? charged : capacity"),
        "the helper must charge min(ret, len), not ret or a condition on flags: {helper}"
    );

    for (prog, slot) in [
        ("warden_vol_udp_in", "WARDEN_NETVOLUME_UDP_IN"),
        ("warden_vol_udp6_in", "WARDEN_NETVOLUME_UDP6_IN"),
    ] {
        let body = bpf_prog_body(&src, prog);
        assert!(
            body.contains("net_volume_recv_bytes(ret, len)"),
            "{prog} must cap the return at the caller's len: {body}"
        );
        let invoke = body
            .find("net_volume_invoke(")
            .unwrap_or_else(|| panic!("{prog} has no invocation counter: {body}"));
        let bump = body
            .find("net_volume_bump(")
            .unwrap_or_else(|| panic!("{prog} has no bump: {body}"));
        assert!(
            invoke < bump,
            "{prog} must count the invocation before the emit gate inside net_volume_bump: {body}"
        );
        assert!(body.contains(slot), "{prog} must use {slot}: {body}");
    }

    let bump_at = src
        .find("static __always_inline void net_volume_bump(int egress, __u64 bytes)")
        .expect("net_volume_bump is missing");
    let gate_at = src
        .find("if (!sensor_emitting(CFG_NET_VOLUME_EMIT))")
        .expect("net_volume_bump no longer reads the emit gate");
    assert!(
        helper_at < bump_at && bump_at < gate_at,
        "the invocation counter and the cap helper must be defined before the gate; a gate that \
         runs first would let a disabled sensor look as if its probes never ran"
    );
}
