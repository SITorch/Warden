//! W2K-13: the ring size policy names must be the ring the kernel builds.
//!
//! The audit's complaint about the events ring was not its 256 KiB — it was that
//! the journal's own drop warning told the operator to raise it *in the C source*,
//! which nobody running the packaged single binary can do. `[runtime].ring_size_kib`
//! closes that, but it only closes it if the override reaches the map-creation
//! syscall: `bpf/warden.bpf.c` still bakes a size into the embedded object, and aya
//! overrides it between parsing the object and calling `BPF_MAP_CREATE`. If that
//! plumbing did not work, Warden would log one capacity and run another, and every
//! "N events dropped" the W-02 counters report would be a fraction of a number
//! nobody had measured.
//!
//! So this is the load-path half of the contract, and it is deliberately not
//! faked: `BPF_MAP_CREATE` needs `CAP_BPF`, and a test that asserts on a map it
//! never created would prove nothing. Without the privilege the test says so and
//! returns, exactly as `tests/preopened_fd_guard.rs` does for its LSM run. What it
//! can check without privileges — that the shipped object still bakes 256 KiB, so
//! that the override is the thing deciding the size — is checked first, always.

use aya::include_bytes_aligned;
use aya::maps::Map;
use aya::EbpfLoader;

/// The bytes `warden` embeds: same macro, same path as `src/loader.rs`.
fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

/// A ring the config is allowed to ask for and that survives the page rounding:
/// 1 MiB is 256 pages of 4 KiB, or 16 pages of 64 KiB — a power of two either way.
const REQUEST: u32 = 1024 * 1024;

#[test]
fn the_shipped_object_still_bakes_the_default_ring() {
    // Unprivileged, always runs. If this passes, `events` exists in the embedded
    // object with the size `[runtime]`'s default re-states — which is what makes
    // the override below the *only* thing that can change the capacity, and the
    // default config a no-op. `src/config.rs` pins the same number from the policy
    // side; `tests/ringbuf_drop_counter.rs` pins the counters that measure it.
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");
    let ring = obj
        .maps
        .get("events")
        .expect("the embedded object has no `events` ring buffer");
    assert_eq!(
        ring.max_entries(),
        256 * 1024,
        "`bpf/warden.bpf.c` baked a different ring than the 256 KiB `[runtime]` defaults \
         to, so the default config is no longer a no-op"
    );
}

#[test]
fn the_ring_policy_asks_for_is_the_ring_the_kernel_creates() {
    let mut loader = EbpfLoader::new();
    loader.set_max_entries("events", REQUEST);
    let ebpf = match loader.load(embedded_object()) {
        Ok(e) => e,
        Err(e) => {
            println!(
                "SKIPPED (needs CAP_BPF and a kernel that creates the map): {e} — this \
                 host cannot prove the override reaches BPF_MAP_CREATE; it is recorded as \
                 UNVERIFIED, not as a pass."
            );
            return;
        }
    };
    let map = ebpf
        .map("events")
        .expect("loaded object has no `events` map");
    let data = match map {
        Map::RingBuf(data) => data,
        other => panic!(
            "`events` came back as {other:?}, not a ring buffer — RingBuf::try_from in \
             src/loader.rs would refuse this object at startup"
        ),
    };
    let info = match data.info() {
        Ok(info) => info,
        Err(e) => {
            println!("SKIPPED (BPF_OBJ_GET_INFO_BY_FD unavailable): {e}");
            return;
        }
    };
    assert_eq!(
        info.max_entries(),
        REQUEST,
        "the kernel built a {} byte ring although policy asked for {REQUEST} — \
         `[runtime].ring_size_kib` is not reaching map creation, so the capacity in the \
         drop-rate warning is not the capacity in use",
        info.max_entries()
    );
}
