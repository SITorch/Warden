//! N-02 / stage 14: a connect's VERDICT is one enum shared by five files, and the
//! failure mode of a disagreement is a network fact that never happened.
//!
//! The defect this closes is N-01's successor: Warden could say where an app dialed
//! (`kprobe/security_socket_connect`) but not what the transport decided, so a C2
//! that connected and a C2 that was refused produced the same record, and the
//! platform's flow contract — `<parent-project>/sentinel/ndr/records.py`, whose `conn_state`
//! column its scan detector counts as failure evidence — had nothing to put in that
//! column. The answer is a kprobe/kretprobe pair on `__inet_stream_connect` that
//! stamps an outcome into the last free byte of `aux2`.
//!
//! Why that byte must be pinned by a test rather than by review: the producer
//! (`bpf/warden.bpf.c`), the ABI (`bpf/warden.h`), the decoder (`src/events.rs`),
//! the gate (`src/loader.rs`) and the journal line (`src/main.rs`) each hold one
//! link, and if the C numbering and the Rust numbering disagree the records still
//! decode — they just decode to a *different verdict*. An operator reading "refused"
//! about a dial that succeeded has now been told something false by the security
//! agent, which is worse than being told nothing.
//!
//! The second thing pinned here is the part that was MEASURED, not designed, on the
//! deployment kernel (`6.12.107+deb13-amd64`) with a throwaway kretprobe — see
//! `docs/release/WARDEN_PUBLIC_LIVE_RUNBOOK.md` §42 for the tables. Two results changed the shape of
//! the code:
//!   - the kretprobe's `retval` is a 32-bit return widened into the 64-bit register,
//!     so without a truncation-and-sign-extend every failure decodes as "no claim"
//!     and the sensor appears silent rather than wrong;
//!   - 116 of 128 live stream connects (91%) returned `-EINPROGRESS`, because
//!     "connect with a timeout" is non-blocking underneath. An in-flight dial has no
//!     verdict, so the kernel emits NOTHING for it. A record count lower than the
//!     CONNECT count is therefore the expected shape, and that is what the last test
//!     below keeps somebody from "fixing" by inventing a state.
//!
//! Nothing in this file needs privileges, so it runs in the normal `cargo test`.

/// Read the numeric literal off a declaration line, anchored on the declaration
/// text itself: the bare names also appear in prose and in the programs, and a
/// plain `find` would read a sentence instead of a definition.
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

/// The body of one C function, from a signature substring to its closing brace at
/// column 0. Scoped extraction rather than whole-file `contains`, so a rule about
/// what a program *does* cannot be satisfied by the comment above it.
fn cfn_body<'a>(source: &'a str, signature: &str, file: &str) -> &'a str {
    let at = source.find(signature).unwrap_or_else(|| {
        panic!("`{signature}` is no longer in {file} — the function was renamed or removed")
    });
    let rest = &source[at..];
    let end = rest
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{signature} in {file} no longer ends with a column-0 brace"));
    &rest[..end]
}

/// The body of a probe program, from its `int BPF_KPROBE(name` /
/// `int BPF_KRETPROBE(name` to the next `SEC(`.
fn probe_body<'a>(source: &'a str, macro_name: &str, name: &str) -> &'a str {
    let anchor = format!("int {macro_name}({name}");
    let at = source.find(&anchor).unwrap_or_else(|| {
        panic!("{name} is no longer a {macro_name} program in bpf/warden.bpf.c")
    });
    let rest = &source[at..];
    let end = rest.find("\nSEC(").unwrap_or(rest.len());
    &rest[..end]
}

const HEADER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.h"));
const BPF: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.c"));
const EVENTS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/events.rs"));
const LOADER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader.rs"));
const MAIN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));

/// The C variant name and the Rust variant it must decode to, in wire order.
const OUTCOMES: &[(&str, &str)] = &[
    ("WARDEN_CONNECT_ESTABLISHED", "Established"),
    ("WARDEN_CONNECT_REFUSED", "Refused"),
    ("WARDEN_CONNECT_TIMEOUT", "Timeout"),
    ("WARDEN_CONNECT_UNREACHABLE", "Unreachable"),
    ("WARDEN_CONNECT_BLOCKED", "Blocked"),
    ("WARDEN_CONNECT_ABORTED", "Aborted"),
    ("WARDEN_CONNECT_INTERRUPTED", "Interrupted"),
    ("WARDEN_CONNECT_WOULD_BLOCK", "WouldBlock"),
    ("WARDEN_CONNECT_ALREADY", "AlreadyConnected"),
    ("WARDEN_CONNECT_FAILED_OTHER", "FailedOther"),
];

#[test]
fn every_outcome_number_means_the_same_thing_on_both_sides() {
    // The numbering is the ABI. A reordered enum keeps records decodable while
    // changing what they SAY, which is the one failure mode this file exists for.
    let mut seen = std::collections::HashSet::new();
    for (c_name, rust_variant) in OUTCOMES {
        let n = decl_value(HEADER, c_name, "bpf/warden.h");
        assert!(
            (1..=10).contains(&n),
            "{c_name} is {n}: outcome numbers are append-only and must stay inside the \
             8-bit field, with 0 reserved for 'no claim'"
        );
        assert!(
            seen.insert(n),
            "two outcome variants share number {n} — the decoder would pick one of them \
             for every record that carries it"
        );
        assert!(
            EVENTS.contains(&format!("{n} => Some(ConnectOutcome::{rust_variant})")),
            "the kernel stamps {c_name} = {n} but src/events.rs does not decode {n} as \
             {rust_variant}; a verdict would be reported under the wrong name"
        );
    }

    // 0 is the unstamped value and must never be a verdict. Anchored on the line
    // start, because `10 => Some(…)` contains the bare `0 => Some(…)` as a substring.
    assert_eq!(
        decl_value(HEADER, "WARDEN_CONNECT_NO_CLAIM", "bpf/warden.h"),
        0,
        "NO_CLAIM moved off 0. Every record written before this stage has 0 in the \
         outcome byte, and so does a CONNECT or LISTEN record: it has to mean absence."
    );
    assert!(
        !EVENTS.contains("\n            0 => Some(ConnectOutcome::"),
        "the decoder turned the 'no claim' byte into a verdict"
    );

    // An unknown number rejects the record rather than defaulting to something.
    assert!(
        EVENTS.contains("_ => None,\n        }\n    }"),
        "ConnectOutcome::from_u32 no longer rejects an unknown number with None"
    );
    assert!(
        !EVENTS.contains("_ => Some(ConnectOutcome::"),
        "ConnectOutcome::from_u32 gained a catch-all: a future kernel verdict would \
         decode as whatever the last arm happened to be"
    );

    // The kind itself, on both sides, and inside the counter bound.
    let c_kind = decl_value(HEADER, "WARDEN_CONNECT_RESULT = 13", "bpf/warden.h");
    assert_eq!(c_kind, 13, "the connect-result kind number moved");
    assert!(
        EVENTS.contains("ConnectResult = 13,"),
        "src/events.rs no longer decodes kind 13 as ConnectResult"
    );
    assert!(
        13 < decl_value(HEADER, "#define WARDEN_KIND_SLOTS", "bpf/warden.h") as usize,
        "kind 13 is outside the per-sensor counter slots, so it stops being counted"
    );
}

#[test]
fn the_kernel_emits_only_for_a_verdict_it_actually_knows() {
    // The NO_CLAIM half is not a category — it means "emit nothing". The two codes
    // that mean "still in flight" are the 91% of live dials measured on the
    // deployment kernel, and a record for one of them would state a result the
    // transport had not decided yet.
    let classify = cfn_body(
        BPF,
        "static __always_inline __u8 warden_connect_outcome(",
        "bpf/warden.bpf.c",
    );
    for (code, name) in [("-EINPROGRESS", "115"), ("-EALREADY", "116")] {
        assert!(
            classify.contains(code),
            "the classifier no longer names {code} ({name}); it would fall through to \
             FAILED_OTHER and report an in-flight dial as a failure"
        );
    }
    assert!(
        classify.contains("return WARDEN_CONNECT_NO_CLAIM;"),
        "the in-flight codes no longer map to NO_CLAIM"
    );
    // A positive retval is not a shape this hook produces; saying "failed, unknown
    // reason" about it would be a claim built on a value nobody interpreted.
    assert!(
        classify.contains("if (rc < 0)") && classify.contains("WARDEN_CONNECT_FAILED_OTHER"),
        "the classifier no longer reserves FAILED_OTHER for negative returns only"
    );

    // And NO_CLAIM means no record at all, not a record saying "no claim".
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_connect_result");
    assert!(
        kret.contains("if (outcome == WARDEN_CONNECT_NO_CLAIM)\n\t\treturn 0;"),
        "the return probe emits a record for an outcome it does not know"
    );

    // The measured register shape: without the truncation every failure decodes as
    // NO_CLAIM, and the sensor is silent instead of wrong.
    assert!(
        kret.contains("rc = (int)rc;"),
        "the return probe no longer truncates the 64-bit register to the kernel's int \
         return. Measured on the deployment kernel a failure arrives zero-extended \
         (4294967181 = 0x100000000 - 115), so without this every verdict would be \
         dropped and egress would look like it never failed."
    );
}

#[test]
fn the_attempt_and_the_verdict_agree_on_the_endpoint_and_the_task() {
    // The pair's whole justification is that the destination exists on the way in
    // and the verdict exists on the way out. If the two halves disagree about which
    // dial they describe, userspace correlates one dial's endpoint with another
    // dial's failure — and a flow record built from that is evidence against the
    // wrong process.
    let entry = probe_body(BPF, "BPF_KPROBE", "warden_on_connect_start");
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_connect_result");

    // One reader of the sockaddr, used by both halves and by CONNECT as well, so
    // the endpoint bytes are identical by construction rather than by review.
    for (where_, body) in [
        (
            "warden_on_connect",
            probe_body(BPF, "BPF_KPROBE", "warden_on_connect"),
        ),
        ("the entry probe", entry),
    ] {
        assert!(
            body.contains("warden_read_dst("),
            "{where_} no longer decodes the destination through the shared reader"
        );
    }

    // The stash key is the full pid_tgid word on both sides: the tid alone collides
    // across PID namespaces, and a partial word would hand one task another's dial.
    assert!(
        entry.contains("bpf_get_current_pid_tgid()") && kret.contains("bpf_get_current_pid_tgid()"),
        "the stash key is no longer the full pid_tgid word on both halves of the pair"
    );
    assert!(
        entry.contains("bpf_map_update_elem(&connect_pending, &key, &st, BPF_ANY)"),
        "the entry probe no longer stashes under the key the return probe reads"
    );

    // The verdict carries what the entry stashed — nothing re-read off the socket on
    // the way out, where the task may already have moved on.
    assert!(
        kret.contains("e->aux2 = warden_net_aux2_ex(dialed.family, (__u16)dialed.proto, outcome);"),
        "the return probe no longer packs the endpoint identity the entry probe saw"
    );
    assert!(
        kret.contains("e->aux = dialed.port;") && kret.contains("dialed.daddr"),
        "the return probe no longer reports the port and address the dial was aimed at"
    );
    assert!(
        !kret.contains("warden_read_dst("),
        "the return probe re-reads the sockaddr. The kretprobe's argument registers are \
         the entry's, and `address` may be freed by the time the return runs — the stash \
         exists so this half reads only what the entry half copied."
    );
}

#[test]
fn the_stash_is_drained_even_when_the_sensor_has_been_muted() {
    // The gate is a runtime flip. If the return probe checked the gate before
    // deleting, a mute in flight would leave the entry for the next task to be
    // given that pid_tgid — a verdict attached to someone else's dial.
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_connect_result");
    let delete = kret
        .find("bpf_map_delete_elem(&connect_pending, &key)")
        .expect("the return probe deletes its stash entry");
    let gate = kret
        .find("sensor_emitting(CFG_CONNECT_RESULT_EMIT)")
        .expect("the return probe checks its emit gate");
    assert!(
        delete < gate,
        "the return probe now checks the emit gate before draining the stash: a mute \
         mid-flight leaves an entry behind for a recycled pid_tgid to inherit"
    );
    let copy = kret
        .find("struct warden_connect_stash dialed = *st;")
        .expect("the return probe copies the stash before using it");
    assert!(
        copy < delete,
        "the stash is deleted before it is copied, so the record would be built from \
         a pointer the verifier no longer guarantees is readable"
    );

    // The entry half stashes nothing while muted, so the pair cannot drift into a
    // state where every return probe is a lookup miss.
    let entry = probe_body(BPF, "BPF_KPROBE", "warden_on_connect_start");
    let gate_at = entry
        .find("sensor_emitting(CFG_CONNECT_RESULT_EMIT)")
        .expect("the entry probe checks its emit gate");
    let stash_at = entry
        .find("bpf_map_update_elem(&connect_pending")
        .expect("the entry probe stashes the dial");
    assert!(
        gate_at < stash_at,
        "the entry probe stashes before checking the gate, so a muted sensor still \
         fills the map for no consumer"
    );

    // Both halves share ONE gate slot, and the slot number agrees with the header.
    let c_slot = decl_value(HEADER, "CFG_CONNECT_RESULT_EMIT", "bpf/warden.h");
    let rust_slot = decl_value(LOADER, "const CFG_CONNECT_RESULT_EMIT", "src/loader.rs");
    assert_eq!(
        c_slot, rust_slot,
        "the kernel mutes the outcome sensor on slot {c_slot} and userspace writes slot \
         {rust_slot}: the gate would flip and the sensor keep emitting (or go permanently \
         silent) with nothing in the log to say which"
    );
    assert!(
        c_slot < decl_value(HEADER, "CFG_SLOT_COUNT", "bpf/warden.h"),
        "the outcome gate is outside the runtime_cfg array's capacity"
    );
    assert!(
        MAIN.contains("set_connect_result_emit(true)"),
        "the outcome sensor is never armed at startup: a fresh install would run with \
         the gate at its zero value and the sensor silently off"
    );
}

#[test]
fn the_conn_state_mapping_names_only_states_this_hook_can_prove() {
    // The platform treats `conn_state` as failure EVIDENCE: `FAILED_CONN_STATES` in
    // `<parent-project>/sentinel/ndr/records.py` is {S0, REJ, RSTOS0, RSTRH} and the scan
    // detector counts them. Every extra state Warden invents is therefore a
    // detector's input, not a display string — so the mapping is an allow-list of
    // three, and the absence of a state is the honest answer.
    //
    // The allow-list below is a transcription of the platform's vocabulary, copied
    // with its source path rather than trusted from memory: if the far side ever
    // narrows its own set, this test is where the mismatch surfaces.
    const KNOWN_CONN_STATES: &[&str] = &[
        "S0", "S1", "SF", "REJ", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH",
    ];
    let body = cfn_body(
        EVENTS,
        "pub fn conn_state_hint(self) -> Option<&'static str> {",
        "src/events.rs",
    );
    let mut mapped = 0;
    for line in body.lines() {
        let Some((variant_side, tail)) = line.split_once("=> Some(\"") else {
            continue;
        };
        mapped += 1;
        let state = tail.split('"').next().unwrap_or("");
        assert!(
            variant_side.contains("ConnectOutcome::"),
            "a conn_state arm in conn_state_hint no longer names a ConnectOutcome: {line}"
        );
        assert!(
            KNOWN_CONN_STATES.contains(&state),
            "conn_state_hint returns {state:?}, which the platform's flow ingest \
             refuses outright — the record would be dropped, not corrected"
        );
    }
    assert_eq!(
        mapped, 3,
        "conn_state_hint asserts {mapped} states. Three is what a connect() verdict can \
         prove (established / refused / timed out); a fourth is a claim about a handshake \
         this hook did not see — Zeek's states include teardown, which this record cannot \
         know."
    );
    // The three, by name, so a reordering of the arms cannot quietly trade one for
    // another (e.g. Established -> SF, which needs a close).
    for (variant, state) in [("Established", "S1"), ("Refused", "REJ"), ("Timeout", "S0")] {
        assert!(
            body.contains(&format!("ConnectOutcome::{variant} => Some(\"{state}\")")),
            "{variant} no longer maps to {state}"
        );
    }
    // ENETUNREACH is not "we sent a SYN and heard nothing": it can be produced by
    // the local routing table without a packet leaving, and S0 says a packet left.
    assert!(
        !body.contains("Unreachable => Some("),
        "Unreachable was mapped to a conn_state. A locally generated ENETUNREACH would \
         then be counted by the platform as an unanswered SYN — a phantom scan."
    );
    assert!(
        !body.contains("FailedOther => Some("),
        "FailedOther was mapped to a conn_state. It is the bucket for a code this hook \
         could not classify; giving it a network meaning invents one."
    );
    // And the hint is not a guess the decoder fills in when the field is absent.
    assert!(
        !EVENTS.contains("unwrap_or(\"OTH\")"),
        "a missing conn_state is being filled with OTH — an invented state"
    );
}

#[test]
fn a_verdict_record_is_read_by_someone() {
    // A sensor whose records no consumer touches is invisible loss with a counter
    // attached. In this build the verdict deliberately raises no finding — the
    // dial-time CONNECT record already owns the one egress finding, and a second
    // alert per connection is the flood this pipeline was tuned down for — so the
    // journal line is the whole consumer, and it is the only way to show on a live
    // host that the pair fires and pairs at all.
    assert!(
        MAIN.contains("if let Some(outcome) = event.connect_outcome"),
        "the pipeline no longer reads the decoded outcome. The kretprobe pair then \
         ships two programs whose records are dropped without a word."
    );
    assert!(
        MAIN.contains("conn_state_hint()"),
        "the journal line stopped reporting the platform's vocabulary, which is the \
         reason this stage exists"
    );
    assert!(
        LOADER.contains("prog.attach(\"__inet_stream_connect\", 0)?;"),
        "the outcome pair is no longer attached — the sensor would be loaded and idle"
    );
    // The judge's arm is the documented refusal, not an omission: a missing arm is a
    // compile error today and a silent gap the day somebody adds a wildcard.
    assert!(
        EVENTS.contains("Kind::ConnectResult => \"connect_result\""),
        "the kind has no stable journal name, so an operator's log filter cannot match it"
    );
}
