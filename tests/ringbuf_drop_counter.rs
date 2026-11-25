//! W-02: the shipped `bpf/warden.bpf.o` must actually carry the ring-buffer drop
//! counter that `src/loader.rs` reads and `src/main.rs` reports.
//!
//! The audit's finding was not that the ring loses events — it is lossy by
//! contract, and blocking a syscall to avoid that would be worse. The finding was
//! that `bpf/warden.bpf.c`'s comment *promised* a userspace-visible drop counter
//! while no counter existed anywhere: not in the object, not in the Rust side. So
//! a flood that overran the 256 KiB ring produced silence, and silence is what a
//! quiet host looks like. Zero events read as "nothing happened" when they may
//! have meant "nothing got through".
//!
//! A promise in a comment cannot fail. This test can. It parses the exact bytes
//! the binary embeds — same `include_bytes_aligned!` macro and same path as
//! `src/loader.rs`, so it is the shipping artifact and not a copy of it — which
//! means the object and the loader can no longer drift apart without something
//! going red. It runs unprivileged: it reads the ELF and its BTF, it does not
//! load programs or touch a kernel map.
//!
//! What this does NOT prove is the empirical half of the audit's fix ("fill the
//! ring on purpose and show the metric moves"). That needs root and a real
//! kernel; it is an integration step on the deployment host, tracked with OPS-01,
//! and it is deliberately not faked here with a test that would pass without ever
//! running a single BPF instruction.
//!
//! W2K-14 extends the same guarantee to *attribution*: both counter maps must
//! carry one slot per event kind, so the journal can say which sensor lost events
//! and which sensor never produced any. A per-kind map that userspace does not
//! read is the same drift this file was written to catch.

use aya::include_bytes_aligned;
use aya_obj::generated::bpf_map_type;

/// The bytes embedded into the `warden` binary. Same macro and same path as
/// `src/loader.rs`, so this is what ships — `bpf/warden.bpf.o` is prebuilt and
/// embedded, never read from disk at runtime, which is exactly why a source-only
/// change to the counter would be invisible in production.
fn embedded_object() -> &'static [u8] {
    include_bytes_aligned!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.o"))
}

#[test]
fn the_embedded_object_carries_the_drop_counter() {
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");

    let map = obj.maps.get("ringbuf_drops").expect(
        "the embedded object has no `ringbuf_drops` map. `src/loader.rs` refuses to start \
         without it (a hard error, not an Option — an uncounted ring is the W-02 bug itself), \
         so this object cannot be paired with this source. Rebuild it with `make bpf`: the \
         .o is embedded with include_bytes_aligned!, so editing bpf/warden.bpf.c alone \
         changes nothing at runtime.",
    );

    // PERCPU_ARRAY and not a single global counter: one slot per CPU per event kind
    // means the hot path in the kernel is a lock-free bump of this CPU's private
    // copy, and it stays correct when an NMI interrupts a Warden program with
    // another Warden program on the same CPU. A global atomic would put every CPU
    // on one cache line in the path that runs when the host is already under load.
    assert_eq!(
        map.map_type(),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32,
        "the drop counter must be per-CPU; a global counter would contend on exactly the \
         path that runs when the ring is already overflowing"
    );
    // One slot per event kind (index = `enum warden_event_kind`, slot 0 unused), so
    // the warning in `src/main.rs` can name the sensor that is bleeding — W2K-14.
    // `Loaded::sensor_counters()` reads exactly this many slots, and
    // `src/loader.rs::KIND_SLOTS` is the Rust mirror of the bound.
    assert_eq!(
        map.max_entries(),
        16,
        "the drop counter must carry one slot per event kind; `Loaded::sensor_counters()` \
         sums slots 0..KIND_SLOTS, so a smaller map silently loses attribution"
    );
    assert_eq!(map.key_size(), 4, "the key is a u32 slot index");
    assert_eq!(
        map.value_size(),
        8,
        "the value is a u64 — the counter is monotonic and must not wrap at 2^32 on a host \
         that is up for a long time"
    );
}

#[test]
fn the_embedded_object_carries_the_submitted_counter_too() {
    // W2K-14: drops alone cannot tell a quiet host from a sensor that stopped
    // firing, so every successful submit is counted in a mirror map. `src/loader.rs`
    // refuses to start without it, same as the drop counter.
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");

    let submitted = obj.maps.get("ringbuf_events").expect(
        "the embedded object has no `ringbuf_events` map. `src/loader.rs` refuses to start \
         without it, so a sensor that never fired would be indistinguishable from a host \
         that never produced an event. Rebuild with `make bpf`.",
    );

    assert_eq!(
        submitted.map_type(),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY as u32,
        "the submit counter must be per-CPU, like the drop counter it is compared against"
    );
    assert_eq!(
        submitted.max_entries(),
        16,
        "the submit counter must have one slot per event kind, the same shape as \
         `ringbuf_drops` — the two are read together to form a per-sensor ratio"
    );
    assert_eq!(submitted.key_size(), 4);
    assert_eq!(submitted.value_size(), 8);
}

#[test]
fn the_ring_the_counter_counts_for_is_still_the_ring() {
    let obj = aya_obj::Object::parse(embedded_object()).expect("parse the embedded eBPF object");
    let ring = obj
        .maps
        .get("events")
        .expect("the embedded object has no `events` ring buffer");

    assert_eq!(
        ring.map_type(),
        bpf_map_type::BPF_MAP_TYPE_RINGBUF as u32,
        "`events` must be a BPF ring buffer — the drop counter exists to measure loss on this \
         specific map, and `bpf_ringbuf_reserve` failures on anything else would not be counted"
    );
    // 256 KiB is what the counter was sized and documented against, and it is now
    // only the *default*: W2K-13 lets `[runtime] ring_size_kib` override the ring
    // when its map is created (`src/loader.rs::attach`), so this assertion is about
    // the object, not the running capacity. If the baked size is deliberately
    // changed, `config::DEFAULT_RING_KIB`, the `--check` line and
    // `tests/ring_size_override.rs::the_shipped_object_still_bakes_the_default_ring`
    // all have to move with it — the drop ratio the counter reports is always a
    // fraction of the capacity actually in force, which the log line now names.
    assert_eq!(
        ring.max_entries(),
        256 * 1024,
        "the events ring baked into the object changed size; `config::DEFAULT_RING_KIB`, \
         the operator-facing advice in src/main.rs, and the unprivileged assertion in \
         tests/ring_size_override.rs were written against 256 KiB"
    );
}
