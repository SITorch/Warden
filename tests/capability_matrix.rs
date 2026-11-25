//! W-R1 / Phase 7: the shipped capability matrix must not drift away from the
//! shipped object.
//!
//! The audit's finding (W-R1, "DESIGN capability drift") was that the design
//! notes described capabilities the build does not have — an in-kernel egress
//! *block* (`cgroup/connect4|6`) and an in-kernel kill (`bpf_send_signal`) — while
//! under-describing what it does ship (six `lsm/*` guarded-file programs). Prose
//! cannot fail, so the drift survived across revisions: `DESIGN.md` asserted
//! "egress-block already works" while no such program existed anywhere.
//!
//! Phase 7 changes that fact deliberately and with an explicit contract: four
//! `cgroup/sock_addr` programs now ship in the embedded object, but they are
//! **OFF by default**, attach only to a named isolated cgroup when
//! `[egress] enabled = true`, and deny only when `[egress] arm = true` and an
//! exact DENY rule matches. The `Preflight` honesty layer in `src/policy.rs`
//! still requires positive kernel proof before any finding may claim a block.
//! This test is updated in the same change as those programs (the mistake W-R1
//! existed to prevent would be leaving this contract describing the old build).
//!
//! It reads the section table out of the exact bytes the binary embeds (same
//! `include_bytes_aligned!` and same path as `src/loader.rs`, so this is the
//! shipping artifact and not a copy of it) and freezes the set of eBPF programs
//! that ship. Then it asserts:
//!
//!   1. the shipped program set is exactly the documented ones (thirty-two since
//!      Phase 7 added the four optional cgroup egress programs and this revision
//!      added the two IPv6 datagram volume hooks);
//!   2. the cgroup egress set is exactly the four Phase 7 programs — neither a
//!      fifth hook nor a missing v6/sendmsg half may slip in;
//!   3. every shipped section is named in `README.md`, and the README and DESIGN
//!      say the cgroup hooks are optional and shadow-by-default.
//!
//! It runs unprivileged: it reads the ELF and source text, it does not load
//! programs or touch a kernel map. The empirical half — that an armed rule
//! actually returns -EPERM on a real kernel — needs the isolated privileged VM
//! and lives in `docs/security/warden_phase6_live_validation.md`; it is never
//! faked here with a test that would pass without loading a BPF instruction.

use aya::include_bytes_aligned;

/// The bytes embedded into the `warden` binary. Same macro and same path as
/// `src/loader.rs`, so this is what ships — `bpf/warden.bpf.o` is prebuilt and
/// embedded, never read from disk at runtime.
fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

/// The README as compiled into this test, so the cross-check cannot read a
/// different file than the one the repository ships.
const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
const DESIGN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/DESIGN.md"));

fn u16le(b: &[u8], o: usize) -> usize {
    u16::from_le_bytes([b[o], b[o + 1]]) as usize
}
fn u32le(b: &[u8], o: usize) -> usize {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize
}
fn u64le(b: &[u8], o: usize) -> usize {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes")) as usize
}

/// The names of the object's program sections — i.e. the `SEC("…")` strings that
/// became real, loadable programs. Read straight from the ELF section-header
/// string table.
///
/// Filtering to names that contain `/` and do not start with `.` selects exactly
/// the program sections: relocation sections (`.relkprobe/…`) are dot-prefixed,
/// and clang's own sections (`.text`, `.maps`, `.rodata`, `license`, …) carry no
/// slash. This keeps the test from mistaking a string *literal* in the object for
/// a section name, which a raw `strings | grep` would.
fn program_sections(elf: &[u8]) -> Vec<String> {
    assert_eq!(
        &elf[0..4],
        b"\x7fELF",
        "the embedded object is not an ELF file"
    );
    assert_eq!(elf[4], 2, "expected ELFCLASS64; the BPF target is 64-bit");
    assert_eq!(elf[5], 1, "expected ELFDATA2LSB (little-endian)");

    let shoff = u64le(elf, 40);
    let shentsize = u16le(elf, 58);
    let shnum = u16le(elf, 60);
    let shstrndx = u16le(elf, 62);
    assert!(shnum > 0, "the object has no section headers");

    // The section-header string table, by its own header's offset/size.
    let strtab_hdr = shoff + shstrndx * shentsize;
    let str_off = u64le(elf, strtab_hdr + 24);
    let str_size = u64le(elf, strtab_hdr + 32);
    let strtab = &elf[str_off..str_off + str_size];

    let mut names = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        let name_off = u32le(elf, hdr); // sh_name
        if name_off >= strtab.len() {
            continue;
        }
        let rest = &strtab[name_off..];
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        let name = String::from_utf8_lossy(&rest[..end]).into_owned();
        if name.contains('/') && !name.starts_with('.') {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The thirty-two programs the build ships: the original sensor/LSM/volume set,
/// the four Phase 7 cgroup egress programs (OFF by default — see the next test),
/// and the two IPv6 datagram volume programs (IMPLEMENTED_NOT_VALIDATED_LIVE).
const SHIPPED: &[&str] = &[
    // ── nineteen observational program rows ─────────────────────────────────
    "kprobe/commit_creds",
    "kprobe/__inet_stream_connect",
    "kprobe/inet_accept",
    "kprobe/security_bpf",
    "kprobe/security_inode_create",
    "kprobe/security_inode_rename",
    "kprobe/security_inode_unlink",
    "kprobe/security_ptrace_access_check",
    "kprobe/security_sb_mount",
    "kprobe/security_socket_connect",
    "kprobe/security_socket_listen",
    "kprobe/security_task_kill",
    "kretprobe/__inet_stream_connect",
    "kretprobe/inet_accept",
    "tp/module/module_load",
    "tp/sched/sched_process_exec",
    // ── six fexit volume counters (N-05, off by default) ───────────────────
    "fexit/tcp_cleanup_rbuf",
    "fexit/tcp_sendmsg",
    "fexit/udp_recvmsg",
    "fexit/udp_sendmsg",
    "fexit/udpv6_recvmsg",
    "fexit/udpv6_sendmsg",
    // ── six LSM guarded-file programs (the original deny-capable set) ───────
    "lsm/file_open",
    "lsm/file_permission",
    "lsm/inode_rename",
    "lsm/inode_setattr",
    "lsm/inode_unlink",
    "lsm/mmap_file",
    // ── four Phase 7 cgroup egress hooks (disabled unless explicitly enabled) ─
    "cgroup/connect4",
    "cgroup/connect6",
    "cgroup/sendmsg4",
    "cgroup/sendmsg6",
];

#[test]
fn the_shipped_program_set_is_exactly_the_documented_thirty_two() {
    let actual = program_sections(embedded_object());
    // `SHIPPED` is grouped by role to stay readable; `program_sections` returns
    // ELF order sorted. Sort a copy rather than reorder the constant, so the
    // declaration keeps explaining itself and both are compared as sets.
    let mut expected: Vec<String> = SHIPPED.iter().map(|s| s.to_string()).collect();
    expected.sort();

    assert_eq!(
        actual, expected,
        "\n\nThe set of eBPF programs in the embedded object changed.\n\
         If you ADDED a program, add it to SHIPPED here AND to the README capability \
         matrix AND to DESIGN §4 — an undocumented capability is the W-R1 bug.\n\
         If you REMOVED one, remove it from all three, and say so in the commit \
         message: a sensor that stops shipping is a detection gap, not a tidy-up.\n\
         If the change is only a rename, update SHIPPED and both docs.\n"
    );
}

#[test]
fn the_only_cgroup_hooks_are_the_four_documented_phase7_egress_programs() {
    let sections = program_sections(embedded_object());

    let cgroup: Vec<&String> = sections
        .iter()
        .filter(|s| s.starts_with("cgroup/"))
        .collect();
    let expected = [
        "cgroup/connect4",
        "cgroup/connect6",
        "cgroup/sendmsg4",
        "cgroup/sendmsg6",
    ];
    for name in expected {
        assert!(
            cgroup.iter().any(|s| s.as_str() == name),
            "Phase 7 promised the cgroup hook {name}, but it is not in the embedded object"
        );
    }
    assert_eq!(
        cgroup.len(),
        expected.len(),
        "an undocumented cgroup/… program ships ({cgroup:?}). Phase 7's contract is \
         exactly connect4/connect6/sendmsg4/sendmsg6 — a fifth hook is a new \
         capability and must be documented in README, DESIGN and the Phase 7 matrix"
    );

    // The six LSM programs are the file-guard surface. Pinning the count keeps
    // "the file guard" from silently growing a seventh hook that no document
    // describes, and keeps the two deny families distinct in the docs.
    let lsm: Vec<&String> = sections.iter().filter(|s| s.starts_with("lsm/")).collect();
    assert_eq!(
        lsm.len(),
        6,
        "expected exactly six lsm/* guarded-file programs, found {}: {lsm:?}",
        lsm.len()
    );
}

#[test]
fn the_docs_say_the_cgroup_egress_hooks_are_optional_and_shadow_by_default() {
    // W-R1's lesson: adding a program without rewriting the prose is exactly how
    // a "would deny" becomes a false "traffic blocked" claim. Pin the three
    // sentences an operator reads before trusting the feature.
    let readme = README.to_ascii_lowercase();
    for phrase in [
        "egress blocking",
        "disabled by default",
        "arm = true",
        "shadow",
        "isolated cgroup",
    ] {
        assert!(
            readme.contains(phrase),
            "README lost the Phase 7 egress caveat {phrase:?}; a shipped cgroup hook \
             must never be described as an always-on blocker"
        );
    }
    let design = DESIGN.to_ascii_lowercase();
    assert!(
        design.contains("phase 7") && design.contains("shadow by default"),
        "DESIGN must describe the Phase 7 cgroup hooks as optional and shadow-by-default"
    );
}

#[test]
fn every_shipped_program_is_named_in_the_readme() {
    let sections = program_sections(embedded_object());

    let missing: Vec<&String> = sections
        .iter()
        .filter(|name| !README.contains(name.as_str()))
        .collect();

    assert!(
        missing.is_empty(),
        "\nThese programs ship but are not named anywhere in README.md: {missing:?}\n\
         The README's \"What it detects today\" table is the operator-facing list of \
         what the agent can see; a sensor missing from it is a capability nobody knows \
         they have. Add each one to the table (and its `endpoint:*` finding type).\n"
    );
}
