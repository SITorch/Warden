//! The ELF tests in this directory only mean something if the bytes they read are
//! the bytes that ship.
//!
//! `bpf/warden.bpf.o` is embedded with `include_bytes_aligned!` — a *compile-time*
//! read. Cargo decides whether to recompile from file mtimes, and an mtime that
//! goes backwards is invisible to it: `cp -p`, a restored backup, a rsync from the
//! build host, or a git checkout of an older committed object all leave a `.o` on
//! disk that is older than the last build and different in content. The Makefile
//! already learned that lesson for the clang side (its hash stamp exists because
//! mtime made a stale object look current — §38 F-38.2) and the same failure was
//! live on the Rust side: a throwaway object without the stage-۱۶f hook, stamped
//! four hours back, produced a completely green `cargo test --test net_volume_abi`
//! run that never recompiled and therefore asserted against bytes that no longer
//! existed. `programs: 26` was reported for an object holding 25.
//!
//! So this test does one thing: it compares the embedded bytes to the file on disk,
//! read at *run* time, which is the only moment cargo cannot fake. It cannot make
//! the build fresher — it makes staleness impossible to pass silently.

use aya::include_bytes_aligned;

fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

/// FNV-1a/64. Not a security hash: this only has to distinguish two builds of the
/// same file, and pulling a dependency in to do that would be its own risk.
fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[test]
fn the_embedded_object_is_byte_for_byte_the_object_on_disk() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o");
    let disk = std::fs::read(path).expect("bpf/warden.bpf.o must exist to build against");
    let embedded = embedded_object();

    if embedded != disk.as_slice() {
        panic!(
            "the eBPF object compiled into this test binary is NOT the object on disk: \
             embedded {} bytes (fnv {:016x}), disk {} bytes (fnv {:016x}). Cargo kept a stale \
             build artifact because the file's mtime did not move forwards. Every ELF assertion \
             in `net_volume_abi.rs` and `capability_matrix.rs` is now describing bytes nobody \
             ships. Fix: `cargo clean -p warden && make bpf && cargo test`, or touch \
             src/loader.rs. Do not edit the expectation to match — that is how a stale object \
             becomes a passing test.",
            embedded.len(),
            fingerprint(embedded),
            disk.len(),
            fingerprint(&disk),
        );
    }

    // The disk object is the one that ships, so the program set is counted from it
    // rather than only from the embedded copy. Thirty-two since this revision
    // added two IPv6 datagram volume programs: 26 original + Phase 7's four
    // optional cgroup egress programs (connect4/connect6/sendmsg4/sendmsg6) +
    // udpv6_sendmsg/udpv6_recvmsg. The cgroup four are compiled in but not
    // attached by default.
    let obj = aya_obj::Object::parse(&disk).expect("parse the on-disk eBPF object");
    assert_eq!(
        obj.programs.len(),
        32,
        "the object on disk does not carry the 32 programs the capability matrix documents"
    );
}
