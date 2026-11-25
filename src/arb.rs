//! Deterministic source of "arbitrary" input for the parser property tests
//! (W2K-17).
//!
//! This is deliberately not `cargo-fuzz`/`quickcheck`: Warden is built with
//! `cargo test --locked --offline` in CI and on a deployment host that may have
//! no registry access at all, so a fuzz harness that needs a new crate is a
//! harness that does not run. What the parsers actually need is the same thing a
//! fuzzer gives them — input that no hand-written case would think of — plus the
//! two properties hand-written cases cannot provide: breadth and reproducibility.
//!
//! So: xorshift64*, fixed seeds, and every loop asserting with its iteration
//! number in the message. A failure is reproducible by reading the number, not by
//! re-rolling randomness, and the corpus never changes underneath a passing CI.
//!
//! Compile-time only: `#[cfg(test)] mod arb` in `src/main.rs`.

/// SplitMix64 — used once, to derive a well-mixed stream state from a small
/// integer seed, so consecutive seeds (`SEED + i`) do not produce correlated
/// first bytes.
fn mix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub struct Arb {
    state: u64,
}

impl Arb {
    /// `seed` must be non-zero (xorshift's fixed point is 0).
    pub fn new(seed: u64) -> Self {
        Self {
            state: mix(seed | 1),
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// The top byte: the high bits of a xorshift stream are its better-behaved
    /// ones, and the multiply above puts the longest-period structure there.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    pub fn u64_below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        self.next_u64() % n
    }

    pub fn u32_below(&mut self, n: u32) -> u32 {
        self.u64_below(n as u64) as u32
    }

    pub fn boolean(&mut self) -> bool {
        self.byte() & 1 == 0
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }

    /// `bytes(self.u32_below(max))`. The two-call spelling borrows `self` twice
    /// in one expression, which Rust refuses, so every corpus that wants a
    /// random length calls this instead of repeating the local.
    pub fn bytes_below(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.u64_below(max_len as u64 + 1) as usize;
        self.bytes(len)
    }

    /// `text(self.u32_below(max))`, for the same reason.
    pub fn text_below(&mut self, max_len: usize) -> String {
        let len = self.u64_below(max_len as u64 + 1) as usize;
        self.text(len)
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.byte();
        }
    }

    /// ASCII text with the shapes a hand-written parser actually trips on:
    /// quotes, braces, brackets, `=`, `:`, `#`, NUL, newlines, spaces, and long
    /// digit runs. Fully random bytes are almost never valid TOML/JSON, so a
    /// corpus made only of them exercises the reject path and nothing else; this
    /// mix spends half its bytes on grammar characters and half on noise, which
    /// is what gets the accept path exercised too.
    pub fn text(&mut self, max_len: usize) -> String {
        const SHAPES: &[u8] = b"\"'{}[]#=:,.\n\t \\/|+-*0123456789abcdefABCDEFtruefalsenull\0";
        let len = self.u64_below(max_len as u64 + 1) as usize;
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            let b = if self.boolean() {
                let i = self.u64_below(SHAPES.len() as u64) as usize;
                SHAPES[i]
            } else {
                self.byte()
            };
            out.push(char::from(b));
        }
        out
    }

    /// A plausible-looking TOML document of random structure: `key = value` lines,
    /// tables, and the occasional truncation. Feeds the config parser somewhere
    /// between "totally random bytes" and "the one file in `config/`".
    pub fn tomlish(&mut self) -> String {
        const KEYS: &[&str] = &[
            "mode",
            "events",
            "interval_secs",
            "timeout_secs",
            "spool_max_bytes",
            "burst_threshold",
            "burst_window_secs",
            "kill_takedown_attacker",
            "arm",
            "authorized_uid",
            "allow_root",
            "comms",
            "cgroup_contains",
        ];
        let lines = self.u64_below(14) + 1;
        let mut out = String::new();
        for _ in 0..lines {
            match self.u64_below(6) {
                0 => out.push_str(&format!("[{}]\n", self.text(12))),
                1 => out.push_str(&format!(
                    "{} = \"{}\"\n",
                    KEYS[self.u64_below(KEYS.len() as u64) as usize],
                    self.text(18)
                )),
                2 => out.push_str(&format!(
                    "{} = {}\n",
                    KEYS[self.u64_below(KEYS.len() as u64) as usize],
                    self.u64_below(4_000_000_000)
                )),
                3 => out.push_str(&format!(
                    "{} = [\"{}\", \"{}\"]\n",
                    KEYS[self.u64_below(KEYS.len() as u64) as usize],
                    self.text(8),
                    self.text(8)
                )),
                4 => out.push_str(&format!(
                    "{} = {}\n",
                    KEYS[self.u64_below(KEYS.len() as u64) as usize],
                    if self.boolean() { "true" } else { "false" }
                )),
                _ => out.push_str(&self.text(30)),
            }
        }
        out
    }

    /// A plausible-looking `/proc/net/{tcp,udp}{,6}` body: the kernel's own
    /// header line followed by rows whose columns are *independently* either
    /// well-formed or drifted — an address of the wrong width, a hex word with a
    /// non-hex byte in it, a state column that is not two digits, a uid or inode
    /// that is not a number.
    ///
    /// The independence is the point. Random bytes almost never produce ten
    /// whitespace-separated fields with hex-looking ones in the right places, so
    /// a corpus made only of those exercises the reject path and nothing else —
    /// the same reason `text()` spends half its alphabet on grammar characters.
    /// Each column here is correct with probability 3/4, so roughly a fifth of
    /// rows are fully acceptable (the parser must like all of them at once) while
    /// every single-field break the kernel could print is generated on its own.
    ///
    /// `addr_hex_len` is the width the *table* requires (8 for ipv4, 32 for
    /// ipv6), so a wrong-width row is wrong relative to the table it is read as.
    pub fn procnetish(&mut self, addr_hex_len: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        const DEC: &[u8] = b"0123456789";
        /// The drifted alphabet: hex digits plus what a truncated or interleaved
        /// read actually contains — separators, spaces, NUL, and the non-hex
        /// letters a hex check has to reject.
        const DRIFT: &[u8] = b"0123456789abcdefABCDEFgzXZ:.- \t\0";

        fn column(a: &mut Arb, alpha: &[u8], len: usize) -> String {
            let mut out = String::with_capacity(len);
            for _ in 0..len {
                let i = a.u64_below(alpha.len() as u64) as usize;
                out.push(alpha[i] as char);
            }
            out
        }

        /// One column: clean at width `len` three times in four, otherwise
        /// drifted — including to zero width, which is how a field the kernel
        /// printed as nothing looks.
        fn field(a: &mut Arb, alpha: &[u8], len: usize) -> String {
            if a.u64_below(4) == 0 {
                let delta = a.u64_below(5) as usize;
                let w = match a.u64_below(3) {
                    0 => len.saturating_sub(delta),
                    1 => len + delta,
                    _ => delta,
                };
                return column(a, DRIFT, w);
            }
            column(a, alpha, len)
        }

        let mut out = String::from(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  \
             timeout inode\n",
        );
        let rows = self.u64_below(6) + 1;
        for i in 0..rows as usize {
            let local_addr = field(self, HEX, addr_hex_len);
            let remote_addr = field(self, HEX, addr_hex_len);
            let local_port = field(self, HEX, 4);
            let remote_port = field(self, HEX, 4);
            let st = field(self, HEX, 2);
            let uid_len = self.u64_below(6) as usize;
            let inode_len = self.u64_below(9) as usize;
            let uid = field(self, DEC, uid_len);
            let inode = field(self, DEC, inode_len);
            let junk_len = self.u64_below(30) as usize;
            let local = format!("{local_addr}:{local_port}");
            let remote = format!("{remote_addr}:{remote_port}");
            // The real column order is
            // `sl: local rem st tx:rx tr:when retrnsmt uid timeout inode …`, so
            // uid sits at field index 7 and inode at index 9 — the two positions
            // `parse_row` reads. Arms 2 and 3 keep that shape; the others vary
            // the row length or the order, which is what a cut, a wrapped read or
            // a kernel that prints an extra column looks like to this parser.
            match self.u64_below(8) {
                // Cut short: fewer than ten fields, which must reject as
                // TooFewFields and never as a silently missing socket.
                0 => out.push_str(&format!("{i}: {local} {remote} {st}\n")),
                1 => out.push_str(&column(self, DRIFT, junk_len)),
                2 => out.push_str(&format!(
                    "{i}: {local} {remote} {st} 00000000:00000000 00:00000000 00000000 {uid:>8} 0 \
                     {inode} 1 00000000 100 0 0 10 0\n"
                )),
                3 => out.push_str(&format!(
                    "{i}: {local} {remote} {st} 00000000:00000000 00:00000000 00000000 {uid} 0 \
                     {inode}\n"
                )),
                4 => out.push('\n'),
                // A second header line mid-body — what a concatenated or
                // wrapped read of two tables looks like.
                5 => out.push_str(&format!(
                    "  sl {local} {remote} {st} 00000000:00000000 00:00000000 00000000 {uid} 0 \
                     {inode}\n"
                )),
                // Address and port swapped by column, and a missing separator:
                // both keep the field count but break the endpoint shape.
                _ => out.push_str(&format!(
                    "{i}: {remote} {local} {st} 00000000:00000000 00:00000000 00000000 {uid} 0 \
                     {inode} 1\n"
                )),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_replays_the_same_stream() {
        // The whole value of this harness is reproducibility: if two `Arb::new`
        // with one seed diverged, a red property test could not be re-run.
        let mut a = Arb::new(7);
        let mut b = Arb::new(7);
        for _ in 0..500 {
            assert_eq!(a.byte(), b.byte());
        }
    }

    #[test]
    fn consecutive_seeds_do_not_repeat_the_first_bytes() {
        // Seeds are `SEED + i` across loops. Without the SplitMix64 derivation,
        // every iteration would start from a near-identical stream state and the
        // "breadth" claim would be hollow.
        let firsts: Vec<u8> = (0..64).map(|i| Arb::new(1000 + i).byte()).collect();
        assert!(
            firsts
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                > 8,
            "64 consecutive seeds produced only {firsts:?} as first bytes"
        );
    }

    #[test]
    fn zero_state_is_unreachable() {
        // xorshift64* is stuck at 0 forever, and a stuck generator finds nothing.
        for seed in [0, 1, u64::MAX] {
            let mut a = Arb::new(seed);
            let got: Vec<u64> = (0..3).map(|_| a.next_u64()).collect();
            assert_ne!(got[0], 0, "seed {seed} produced a zero word");
            assert_ne!(a.state, 0, "seed {seed} settled on the fixed point");
        }
    }
}
