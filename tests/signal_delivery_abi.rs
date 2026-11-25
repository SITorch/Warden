//! W2K-04: the SIGNAL delivery class is one number shared by four files, and a
//! silent drift between them is the worst kind of bug available here.
//!
//! The kernel reads `si_code` in the hook because nothing else can: by the time
//! userspace decodes the record, the siginfo is gone. So the producer
//! (`bpf/warden.bpf.c`), the ABI (`bpf/warden.h`), the decoder (`src/events.rs`)
//! and the judgement (`src/detect.rs`) each hold one link of a chain no compiler
//! checks end to end. If the Rust constant and the C define disagree, Warden
//! mislabels how a takedown was aimed *quietly* — records still decode, findings
//! still fire, and an operator reads "kill" where the sender in fact named a timer
//! in `rt_sigqueueinfo` to look like one.
//!
//! The header also carries the finding that scoped this stage: a kernel-GENERATED
//! signal never reaches `security_task_kill` at all, because
//! `check_kill_permission()` only calls the LSM hook for `si_fromuser()` siginfo
//! (`si_code <= 0`). That is written down here so nobody adds a "kernel origin"
//! bit again and tests a branch the kernel can never take.
//!
//! Nothing in this file needs privileges, so it runs in the normal `cargo test`.

/// Read the numeric literal from a declaration line, given the declaration text
/// to anchor on. Keyed on the declaration rather than the bare name because the
/// name also appears in prose, and `find` would read the sentence instead.
fn decl_value(source: &str, declaration: &str, file: &str) -> u32 {
    let at = source.find(declaration).unwrap_or_else(|| {
        panic!("`{declaration}` is no longer in {file} — the ABI was renamed or removed")
    });
    let line = source[at..].lines().next().unwrap_or("");
    for token in line.split_whitespace().skip(1) {
        let cleaned = token.trim_end_matches(['u', 'U', ';', ',']);
        let parsed = if let Some(hex) = cleaned.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()
        } else if !cleaned.is_empty() && cleaned.chars().all(|c| c.is_ascii_digit()) {
            cleaned.parse().ok()
        } else {
            None
        };
        if let Some(value) = parsed {
            return value;
        }
    }
    panic!("no numeric literal on the declaration line in {file}: {line}");
}

const HEADER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.h"));
const EVENTS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/events.rs"));
const BPF: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.c"));
const DETECT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));

#[test]
fn the_field_layout_is_the_same_on_both_sides_of_the_abi() {
    let c_shift = decl_value(
        HEADER,
        "#define WARDEN_SIGNAL_DELIVERY_SHIFT",
        "bpf/warden.h",
    );
    let rust_shift = decl_value(
        EVENTS,
        "pub const WARDEN_SIGNAL_DELIVERY_SHIFT",
        "src/events.rs",
    );
    let c_mask = decl_value(
        HEADER,
        "#define WARDEN_SIGNAL_DELIVERY_MASK",
        "bpf/warden.h",
    );
    let rust_mask = decl_value(
        EVENTS,
        "pub const WARDEN_SIGNAL_DELIVERY_MASK",
        "src/events.rs",
    );
    assert_eq!(
        (c_shift, c_mask),
        (rust_shift, rust_mask),
        "the kernel writes the delivery class at bits {:?} of aux2 and userspace reads \
         it at {:?} — the class would decode as garbage while every other field of the \
         record stayed correct",
        (c_shift, c_mask),
        (rust_shift, rust_mask)
    );

    // The class must be a contiguous run of bits, and must not touch the parent
    // flag it shares aux2 with.
    let from_parent = decl_value(HEADER, "#define WARDEN_SIGNAL_FROM_PARENT", "bpf/warden.h");
    assert_eq!(
        c_mask.count_ones(),
        4,
        "the delivery field is not 4 bits wide, so the kernel's class numbers do not fit"
    );
    assert_eq!(
        c_mask >> c_shift << c_shift,
        c_mask,
        "the mask is not aligned to the shift it is read with"
    );
    assert_eq!(
        c_mask & from_parent,
        0,
        "the class field overlaps WARDEN_SIGNAL_FROM_PARENT: a process that is its own \
         parent-flagged sender would decode as some delivery class"
    );

    // Seven classes fit in the field's space and the enum names all of them; a
    // class the kernel could stamp but userspace cannot name would reject records.
    for name in [
        "WARDEN_SIGDELIV_USER",
        "WARDEN_SIGDELIV_TKILL",
        "WARDEN_SIGDELIV_QUEUE",
        "WARDEN_SIGDELIV_TIMER",
        "WARDEN_SIGDELIV_MESGQ",
        "WARDEN_SIGDELIV_ASYNCIO",
        "WARDEN_SIGDELIV_SIGIO",
    ] {
        assert!(HEADER.contains(name), "the ABI lost class {name}");
    }
    assert_eq!(
        decl_value(HEADER, "WARDEN_SIGDELIV_USER", "bpf/warden.h"),
        0,
        "SI_USER must stay class 0: it is also what an unreadable si_code decodes to, \
         and that default has to be the attack class"
    );
    assert_eq!(
        decl_value(HEADER, "WARDEN_SIGDELIV_SIGIO", "bpf/warden.h"),
        6,
        "the class numbers were reordered — append-only ABI, never reorder"
    );
    assert!(
        c_shift >= 2,
        "the delivery field starts at bit {c_shift}, inside the flag bits — FROM_PARENT \
         would decode as a delivery class"
    );
}

#[test]
fn the_kernel_maps_si_code_to_the_class_without_silencing_anything() {
    assert!(
        BPF.contains("BPF_CORE_READ((struct kernel_siginfo *)info, si_code)"),
        "the kill hook no longer reads si_code through CO-RE. A hardcoded `+8` is the \
         bug W2K-04 was raised for: the field's offset is a BTF question, not a constant."
    );
    assert!(
        BPF.contains(
            "e->aux2 |= (delivery << WARDEN_SIGNAL_DELIVERY_SHIFT) & WARDEN_SIGNAL_DELIVERY_MASK;"
        ),
        "the hook no longer stamps the delivery class into aux2 the documented way"
    );

    // Every si_code that can reach this hook has a branch. A missing one silently
    // reports a sigqueue as a kill(2) — evidence an operator would act on.
    for (si, class) in [
        ("WARDEN_SI_TKILL", "WARDEN_SIGDELIV_TKILL"),
        ("WARDEN_SI_QUEUE", "WARDEN_SIGDELIV_QUEUE"),
        ("WARDEN_SI_TIMER", "WARDEN_SIGDELIV_TIMER"),
        ("WARDEN_SI_MESGQ", "WARDEN_SIGDELIV_MESGQ"),
        ("WARDEN_SI_ASYNCIO", "WARDEN_SIGDELIV_ASYNCIO"),
        ("WARDEN_SI_SIGIO", "WARDEN_SIGDELIV_SIGIO"),
    ] {
        assert!(
            BPF.contains(&format!("if (si_code == {si})\n\t\tdelivery = {class};"))
                || BPF.contains(&format!(
                    "else if (si_code == {si})\n\t\tdelivery = {class};"
                )),
            "{si} is not mapped to {class} in the hook, so that delivery would be \
             recorded as a plain kill(2)"
        );
    }

    // "Classify, never silence": nothing may bail out between reading si_code and
    // reserving the ring record. A `return 0` there would drop signals from the
    // journal instead of labelling them.
    let read = BPF
        .find("si_code = BPF_CORE_READ")
        .expect("the kill hook reads si_code");
    let reserve = BPF[read..]
        .find("bpf_ringbuf_reserve(&events")
        .map(|off| read + off)
        .expect("the kill hook reserves its ring record after reading si_code");
    let between = &BPF[read..reserve];
    assert!(
        !between.contains("return"),
        "the kill hook bails out between the si_code read and the reserve, which would \
         silence signals instead of classifying them:\n{between}"
    );
}

#[test]
fn the_self_directed_rule_is_corroborated_and_the_attack_path_is_unchanged() {
    // The judgement W2K-04 actually supports: actor == target means the victim aimed
    // the blow at itself, which is the only shape that can come from inside a
    // `raise()`/`abort()` — and `actor_pid` is the sender's tgid, so no outside
    // process can produce it.
    assert!(
        DETECT.contains("e.actor_pid == e.target_pid && delivery.actor_names_the_sender()"),
        "judge_signal no longer decides self-termination from the pids plus the class that \
         proves the actor IS the sender. Nothing else in the record can tell a crash from a \
         takedown."
    );
    assert!(
        DETECT.contains("wants_kill: !self_directed")
            && DETECT.contains("&& !own_reload")
            && DETECT.contains("&& !init_controlled")
            && DETECT.contains("&& arming"),
        "the responder is armed for a protected process that is already dying — which is \
         how a pid-recycled kill lands on an innocent process. W2K-36 added the two \
         conjuncts beside this one: a reload request and a teardown from pid 1 are the \
         same mistake wearing a different identity, and `arming` is the renamed arm-list \
         test the gate below still has to find."
    );
    assert!(
        DETECT.contains("\"self_termination\""),
        "the verdict no longer travels in the finding detail, so a self-termination is \
         indistinguishable from an outside takedown downstream"
    );
    assert!(
        DETECT.contains("delivery: delivery.as_str()")
            || DETECT.contains("\"delivery\": delivery.as_str()"),
        "the delivery class is decoded but never reported — the wire cost with no evidence"
    );
    assert!(
        !DETECT.contains("signal_delivery.map"),
        "judge_signal is branching on the raw class again. The class may only ever make a \
         judgement stricter: an attacker picks -1..-5 freely with rt_sigqueueinfo, so \
         nothing but the pids and the sender-proveness of the class may soften a takedown"
    );
    // The one branch on the class, checked where it is defined rather than trusted:
    // an allow-list, so a class appended later defaults to proving nothing.
    assert!(
        EVENTS.contains("pub fn actor_names_the_sender(self) -> bool {")
            && EVENTS.contains("matches!(")
            && !EVENTS.contains("!matches!("),
        "actor_names_the_sender is a deny-list, not an allow-list — a new delivery class \
         would inherit the self-termination pass and disarm the responder on an attacker's \
         label"
    );
}

#[test]
fn the_header_records_that_kernel_generated_signals_never_reach_this_hook() {
    // The part of W2K-04 that turned out not to be a defect. Without this written in
    // the ABI, the next reader re-adds a kernel-origin bit and "fixes" a case that
    // cannot occur — and may even silence records to do it.
    assert!(
        HEADER.contains("si_fromuser") && HEADER.contains("check_kill_permission"),
        "bpf/warden.h no longer documents why a SIGSEGV or an OOM kill produces no \
         SIGNAL record; the sensor's scope needs to stay provable, not folklore"
    );
    assert!(
        !HEADER.contains("WARDEN_SIGNAL_KERNEL_ORIGIN"),
        "a kernel-origin flag came back. Kernel-generated siginfo is refused before the \
         LSM hook (si_fromuser: si_code <= 0), so such a bit can never be set by the \
         kernel and would only ever mark a forgery — see §38 of the evaluation report."
    );
}
