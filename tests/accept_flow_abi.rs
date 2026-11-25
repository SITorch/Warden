//! N-03 (accept half) / N-04 / N-12: stage 16 — the record of who was let IN.
//!
//! Every other network sensor in this object looks outward. `security_socket_listen`
//! says a door exists; `security_socket_connect` says someone aimed a dial at one.
//! Neither can answer the question an operator actually asks after a breach —
//! "who walked through?" — because nothing in the push path saw the accepted child
//! socket. This file locks the two programs that close that gap, a kprobe/kretprobe
//! pair on `inet_accept`, and the `WARDEN_FLOW` record they produce.
//!
//! Why the pair needs tests rather than review is the same reason
//! `connect_outcome_abi.rs` exists: the record's meaning is spread over six files
//! (kernel program, `bpf/warden.h`, `src/events.rs`, `src/detect.rs`,
//! `src/net_snap.rs`, `src/loader.rs`, `src/main.rs`), and the ways it can break are
//! all silent. Three of them are worth naming, because each is a *false statement*
//! rather than a missing one:
//!   - `target_pid` is overloaded. For PTRACE it is a victim pid and the detector
//!     reads it; if the flow decode and the kernel disagree about whose port lives
//!     there, a judgement about a ptrace and a description of a listener collide.
//!   - `aux2` bits 24..31 are the dial's verdict. A FLOW that packed an outcome
//!     there would make an inbound connection look like it was a dial that failed.
//!   - the stash key is a `pid_tgid` that gets recycled the moment the task returns.
//!     A pair that drains in the wrong order hands one task another task's socket
//!     pointer, and the record names the wrong acceptor.
//!
//! The second thing pinned here was MEASURED, not designed, on the deployment
//! kernel (`6.12.107+deb13-amd64`) with a throwaway kprobe/kretprobe pair — tables
//! in `EVALUATION-AND-FIXES.md` §46 and `scripts/LIVE_VALIDATION.md` §18. Three
//! measurements changed the code's shape:
//!   - the obvious hook does not work. `security_socket_accept` runs before the
//!     protocol family installs the child, and `newsock->sk` was NULL in 2021 of
//!     2021 entry probes and 2184 of 2184 return probes. A FLOW from there has no
//!     peer, no port and no namespace, so the stable hook is deliberately NOT used.
//!   - `bpf_get_netns_cookie()` is verifier-rejected for kprobe programs and
//!     `struct net` has no `proc_inum` on this kernel, so the namespace identity is
//!     a CO-RE walk of `skc_net.net->ns.inum`.
//!   - the first shipped version of the return probe did not LOAD. Following the
//!     stashed pointer with `BPF_CORE_READ(taken.newsock, sk)` compiles cleanly and
//!     is rejected by `bpftool prog loadall` with -22, because the relocation's first
//!     link is `struct warden_accept_stash` — a type with no kernel BTF entry. That
//!     one is pinned by `no_co_re_relocation_is_resolved_against_a_type_this_object_invents`.
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

/// The body of one probe program: from its `int BPF_KPROBE(name` /
/// `int BPF_KRETPROBE(name` to the function's own closing brace at column 0.
/// Bounded by the brace rather than by the next `SEC(` so that the prose header of
/// the FOLLOWING section cannot satisfy or defeat a rule about this program.
fn probe_body<'a>(source: &'a str, macro_name: &str, name: &str) -> &'a str {
    let anchor = format!("int {macro_name}({name}");
    let at = source.find(&anchor).unwrap_or_else(|| {
        panic!("{name} is no longer a {macro_name} program in bpf/warden.bpf.c")
    });
    let rest = &source[at..];
    let end = rest.find("\n}\n").unwrap_or_else(|| {
        panic!("{name} in bpf/warden.bpf.c no longer ends with a column-0 brace")
    });
    &rest[..end]
}

const HEADER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.h"));
const BPF: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/bpf/warden.bpf.c"));
const EVENTS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/events.rs"));
const DETECT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/detect.rs"));
const NETSNAP: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/net_snap.rs"));
const LOADER: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/loader.rs"));
const MAIN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));

#[test]
fn the_flow_kind_and_its_gate_mean_the_same_number_everywhere() {
    // The kind. 14 is the next free slot after CONNECT_RESULT; the number is the
    // wire format, so a renumbering that keeps records decodable re-labels every
    // historical flow record as something else.
    assert_eq!(
        decl_value(HEADER, "WARDEN_FLOW = 14", "bpf/warden.h"),
        14,
        "the flow kind number moved"
    );
    assert!(
        EVENTS.contains("Flow = 14,"),
        "src/events.rs no longer declares Kind::Flow as 14"
    );
    assert!(
        EVENTS.contains("14 => Some(Kind::Flow)"),
        "the decoder no longer maps wire kind 14 to Kind::Flow"
    );
    assert!(
        EVENTS.contains("Kind::Flow => \"flow\""),
        "the kind has no stable journal name, so an operator's log filter cannot match it"
    );
    assert!(
        EVENTS.contains("pub const ALL: [Kind; 14]"),
        "Kind::ALL was not grown for Flow. The per-sensor counter report walks ALL, so a \
         kind outside it has a kernel counter no one prints"
    );

    // Inside the kernel's counter arrays, which are sized by WARDEN_KIND_SLOTS and
    // indexed by the discriminant. Outside them the sensor still records, but its
    // drop count — the only evidence that it is losing events — silently vanishes.
    assert!(
        14 < decl_value(HEADER, "#define WARDEN_KIND_SLOTS", "bpf/warden.h"),
        "kind 14 is outside the per-sensor counter slots"
    );

    // The gate: one slot, shared by both halves, named the same in C and Rust.
    let c_slot = decl_value(HEADER, "CFG_FLOW_EMIT", "bpf/warden.h");
    let rust_slot = decl_value(LOADER, "const CFG_FLOW_EMIT", "src/loader.rs");
    assert_eq!(
        c_slot, rust_slot,
        "the kernel mutes the flow sensor on slot {c_slot} and userspace writes slot \
         {rust_slot}: the gate would flip and the sensor keep emitting — or go permanently \
         silent — with nothing in the log to say which"
    );
    assert!(
        c_slot < decl_value(HEADER, "CFG_SLOT_COUNT", "bpf/warden.h"),
        "the flow gate is outside the runtime_cfg array's capacity, so the write fails at \
         startup and the agent does not boot"
    );
    assert!(
        MAIN.contains("loaded.set_flow_emit(true)?;"),
        "the flow sensor is never armed at startup: a fresh install runs with the gate at \
         its zero value, which reads as 'no inbound connections' rather than 'not looking'"
    );
}

#[test]
fn the_pair_is_attached_where_the_child_socket_exists_not_at_the_lsm_gate() {
    // The single most likely future edit to this stage is "move it back to the
    // stable LSM hook", and that edit is wrong for a measured reason. The numbers
    // have to stay on the page with the decision, or the next reader re-derives the
    // wrong conclusion from the general rule that LSM hooks are preferable.
    assert!(
        BPF.contains("2021 of") && BPF.contains("2184 of 2184 return calls"),
        "the reason `security_socket_accept` was rejected is no longer recorded with its \
         counts. Without the numbers this reads as a preference, and it was a measurement: \
         at that hook newsock->sk is NULL, so there is no peer to report"
    );
    assert!(
        BPF.contains("newsock->sk == NULL"),
        "the measured NULL child is no longer stated where the hook choice is explained"
    );

    // Both halves attach to inet_accept, and nothing in the loader attaches the flow
    // sensor to the LSM hook.
    let attaches = LOADER.matches("prog.attach(\"inet_accept\", 0)?;").count();
    assert_eq!(
        attaches, 2,
        "the accept pair should contribute exactly two attach calls (entry + return); \
         found {attaches}. One half alone cannot produce a record: the entry stashes the \
         child pointer and the return reads it"
    );
    assert!(
        !LOADER.contains("attach(\"security_socket_accept\""),
        "the loader attaches something to security_socket_accept for the flow path — the \
         hook that was measured to have no child socket"
    );

    // What the return probe reads, and how. These are the four measured field facts;
    // each has a different way to be silently wrong.
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_flow");
    assert!(
        kret.contains("bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport))"),
        "the peer port is no longer converted from network byte order. `skc_dport` is the \
         one network-order field in this struct; without ntohs every record names a \
         plausible-but-wrong ephemeral port (htons of the real one)"
    );
    assert!(
        kret.contains("BPF_CORE_READ(sk, __sk_common.skc_num)")
            && !kret.contains("bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num))"),
        "`skc_num` is already host order. Converting it would report port 8200 as 33074 \
         and break the comparison against the pull path's local endpoint"
    );
    assert!(
        kret.contains("BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum)"),
        "the namespace is no longer read by CO-RE off the socket. The alternatives were \
         tried and rejected on the deployment kernel: bpf_get_netns_cookie() is verifier-\
         rejected for kprobe programs, and struct net has no proc_inum"
    );
    // The helper is only ever named here in prose, never called: the two call shapes
    // it would take are rejected, and the comment that says why travels with them.
    assert!(
        !kret.contains("bpf_get_netns_cookie(NULL)") && !kret.contains("bpf_get_netns_cookie(ctx)"),
        "the flow probe calls bpf_get_netns_cookie(). It is verifier-rejected for \
         kprobe-type programs on the deployment kernel — the load fails, and the loader is \
         fail-closed, so the agent would not start"
    );
    assert!(
        kret.contains("bpf_get_netns_cookie()` is rejected for"),
        "the reason the namespace is read by a CO-RE walk rather than by the purpose-built \
         helper is no longer recorded where the walk is"
    );

    // The peer address, family-selected, and the PEER's field — not the local one
    // the LISTEN probe reads. Reading skc_rcv_saddr here would describe the door
    // and claim it was the visitor.
    assert!(
        kret.contains("skc_daddr") && kret.contains("skc_v6_daddr"),
        "the flow probe no longer selects the peer address by family; one of the two \
         families would record the listener's address or zeros"
    );
    assert!(
        !kret.contains("skc_rcv_saddr") && !kret.contains("skc_v6_rcv_saddr"),
        "the flow probe reads a LOCAL receive address into daddr. dest would then render \
         as the host's own endpoint, and the sensor that exists to name the visitor would \
         name the visited"
    );

    // The entry half cannot read any of that: at entry the child has no socket, which
    // is the whole reason for the pair. It filters on the LISTENER's family.
    let entry = probe_body(BPF, "BPF_KPROBE", "warden_on_accept_start");
    assert!(
        entry.contains("BPF_CORE_READ(sock, sk, __sk_common.skc_family)"),
        "the entry probe no longer filters on the listener's family. At entry the child \
         has no sk, so this is the only family available — and the only one worth paying a \
         map update to filter on"
    );
    assert!(
        !entry.contains("skc_dport") && !entry.contains("taken.newsock"),
        "the entry probe reads child-socket state. It does not exist yet at that point; \
         this is the measurement that moved the sensor off the LSM hook"
    );
}

#[test]
fn the_stash_is_drained_before_anything_can_short_circuit_it() {
    // The key is a pid_tgid, which the kernel recycles as soon as the task exits or
    // a thread is recreated. An entry left behind is not merely a leak: the next
    // holder of that key finds a socket pointer from a task that is gone — and the
    // record would attribute one process's accepted connection to another.
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_flow");
    let copy = kret
        .find("struct warden_accept_stash taken = *st;")
        .expect("the return probe copies the stash before using it");
    let delete = kret
        .find("bpf_map_delete_elem(&accept_pending, &key)")
        .expect("the return probe deletes its stash entry");
    let gate = kret
        .find("sensor_emitting(CFG_FLOW_EMIT)")
        .expect("the return probe checks its emit gate");
    let rc = kret
        .find("(int)rc_in != 0")
        .expect("the return probe rejects a failed accept");

    assert!(
        copy < delete,
        "the stash is deleted before it is copied, so the record would be built from a \
         map value the verifier no longer guarantees is readable"
    );
    assert!(
        delete < gate && delete < rc,
        "the return probe now has an early return before draining the map. A mute flipped \
         mid-flight, or an -EAGAIN accept, would leave the entry for a recycled pid_tgid \
         to inherit"
    );

    // The key word is the full pid_tgid on both halves. The tid alone is unique only
    // inside one pid namespace, and this host runs containers.
    assert!(
        kret.contains("bpf_get_current_pid_tgid()") && {
            let entry = probe_body(BPF, "BPF_KPROBE", "warden_on_accept_start");
            entry.contains("bpf_get_current_pid_tgid()")
        },
        "the stash key is no longer the full pid_tgid word on both halves of the pair"
    );
    assert!(
        kret.contains("bpf_map_lookup_elem(&accept_pending, &key)") && {
            let entry = probe_body(BPF, "BPF_KPROBE", "warden_on_accept_start");
            entry.contains("bpf_map_update_elem(&accept_pending, &key, &st, BPF_ANY)")
        },
        "the two halves no longer use the same map and the same key"
    );

    // The entry half stashes nothing while muted, so the pair cannot drift into a
    // state where every return probe is a lookup miss on a full map.
    let entry = probe_body(BPF, "BPF_KPROBE", "warden_on_accept_start");
    let gate_at = entry
        .find("sensor_emitting(CFG_FLOW_EMIT)")
        .expect("the entry probe checks its emit gate");
    let stash_at = entry
        .find("bpf_map_update_elem(&accept_pending")
        .expect("the entry probe stashes the child socket");
    assert!(
        gate_at < stash_at,
        "the entry probe stashes before checking the gate, so a muted sensor still pays a \
         map update per accept — including every unix-socket handshake on the host"
    );

    // The map is bounded. Peak outstanding accepts measured on the deployment host
    // was 3; the cap exists so a pathological burst cannot grow kernel memory, and a
    // full map costs a record rather than a connection.
    let close = BPF
        .find("} accept_pending SEC(\".maps\");")
        .expect("the accept stash map is no longer declared the way the pair expects");
    let open = BPF[..close]
        .rfind("struct {")
        .expect("the accept stash map is no longer an anonymous BTF-defined struct");
    let map = &BPF[open..close];
    assert!(
        map.contains("__uint(max_entries, 4096)")
            && map.contains("__uint(type, BPF_MAP_TYPE_HASH)"),
        "the accept stash map is no longer a bounded hash: {map}"
    );
}

#[test]
fn a_flow_is_recorded_only_for_an_accept_the_kernel_finished() {
    // Two registers' worth of measured behaviour, both of which fail closed only if
    // written this way.
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_flow");

    // The kretprobe hands back the whole 64-bit register and the deployment kernel
    // zero-extends the errno there, so -EAGAIN arrives as 0xFFFFFF93. Truncating to
    // int is what the dial's return probe does for the same reason.
    assert!(
        kret.contains("if ((int)rc_in != 0)"),
        "the return probe no longer truncates the return register. A failed accept would \
         then be recorded as a successful flow, and the -EAGAIN polls measured at 157 of \
         4008 calls would arrive as connections that never happened"
    );

    // A zero return with no child socket is a shape this kernel did not produce; if
    // it ever appears, the honest answer is silence, not a record with an empty peer.
    assert!(
        kret.contains("if (!sk)\n\t\treturn 0;"),
        "the return probe follows the stashed pointer without checking for a child socket"
    );
    assert!(
        kret.contains("if (family != AF_INET && family != AF_INET6)"),
        "the return probe no longer re-checks the family off the child. The entry checked \
         the listener; only the child's own family proves the address bytes about to be \
         copied mean anything"
    );

    // No verdict borrowed: the outcome bits stay zero, which is why this packs with
    // the two-argument helper and never the three-argument one.
    assert!(
        kret.contains("e->aux2 = warden_net_aux2(family, proto);")
            && !kret.contains("warden_net_aux2_ex"),
        "the flow probe packs an outcome into aux2 bits 24..31. Those bits mean 'what the \
         transport decided about a dial we aimed'; an inbound connection is not one"
    );

    // Both attribution counters carry the flow kind, so ring loss is reported against
    // this sensor rather than a neighbour's.
    assert!(
        kret.contains("count_drop(WARDEN_FLOW)") && kret.contains("count_submit(WARDEN_FLOW)"),
        "the flow probe no longer attributes its own submissions and drops"
    );
}

#[test]
fn the_decoder_reads_exactly_the_slots_the_kernel_wrote() {
    // FLOW reuses four fields that other kinds own outright. Each pairing is a
    // decision recorded in bpf/warden.h; a decoder that reads a different one turns
    // a port into a pid, or a namespace into a capability mask.
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_flow");
    assert!(
        kret.contains("e->aux = peer_port;") && kret.contains("e->target_pid = local_port;"),
        "the kernel no longer writes the peer port into aux and the local port into \
         target_pid — the pairing src/events.rs decodes"
    );
    assert!(
        kret.contains("e->cap_old = net_inum;"),
        "the kernel no longer writes the namespace inode into cap_old"
    );
    assert!(
        !kret.contains("e->cap_new"),
        "the flow probe wrote cap_new. For ACCESS that slot is an inode number and for \
         CREDS a capability mask; the listener's socket inode is reachable only through an \
         unmeasured container_of walk, and an unverified guess in a field another kind \
         decodes is worse than leaving it zero"
    );

    assert!(
        EVENTS.contains("local_port: raw.target_pid as u16")
            && EVENTS.contains("netns_ino: raw.cap_old"),
        "the flow fold no longer reads the slots the kernel writes"
    );
    assert!(
        EVENTS.contains("let flow = if kind == Kind::Flow {"),
        "the flow fold no longer gates on the kind. Every other kind's target_pid and \
         cap_old mean something else, and a PTRACE record would grow a phantom listener \
         port"
    );

    // A FLOW is rendered by the same formatter a dial is, which is what makes the
    // two paths comparable string for string — and the reason `dest` for a FLOW is
    // the PEER, not the local endpoint.
    assert!(
        EVENTS.contains("|| kind == Kind::Flow;"),
        "Kind::Flow is no longer part of the network-record set that decodes an endpoint. \
         The record would carry an address the platform never sees"
    );
    assert!(
        EVENTS.contains("let connect_outcome = if kind == Kind::ConnectResult {"),
        "the verdict decode no longer belongs to CONNECT_RESULT alone: a FLOW with zeroed \
         outcome bits would decode NO_CLAIM and be reported as a dial outcome"
    );
}

#[test]
fn an_accepted_flow_is_journal_only_by_decision_not_by_omission() {
    // Three consumers were deliberately declined, and each decline is an arm that a
    // later refactor could quietly reverse. All three reversals turn a normal fact
    // into an alarm or into a false all-clear.
    //
    // 1. No finding. This machine's job is accepting connections — measured at
    //    ≈3.9 accepts/s in a quiet window on the deployment host — so the host agent
    //    cannot know which peers are sanctioned; the platform's allowlist does.
    let judge = cfn_body(
        DETECT,
        "pub fn judge(&self, e: &Event) -> Option<Finding> {",
        "src/detect.rs",
    );
    assert!(
        judge.contains("Kind::Flow => None,"),
        "the detector no longer has an explicit no-finding arm for FLOW. A wildcard arm \
         would alert on every accepted connection and bury the signals the detector is \
         tuned for"
    );
    assert!(
        !judge.contains("Kind::Flow => Some("),
        "a judgement was added to FLOW. That decision belongs to the platform's peer \
         allowlist, and a host rule for it fires on legitimate traffic first"
    );

    // 2. No sighting. An accepted peer looks like a dial to `dest` and is nothing of
    //    the kind; feeding it into the reconciler's dial set would mute the very
    //    unexplained-inbound rows the reconciliation asks about.
    let note = cfn_body(
        NETSNAP,
        "pub fn note(&mut self, event: &Event) {",
        "src/net_snap.rs",
    );
    assert!(
        note.contains("Kind::Flow => {}"),
        "the reconciler no longer records an explicit nothing-for-FLOW arm. `dest` is a \
         remote endpoint either way, so a careless `is_net` routing would push accepted \
         peers into the dial set and turn 'which inbound sockets are unexplained?' into a \
         guaranteed no"
    );

    // 3. A journal line that says what the namespace number means. The field is the
    //    sensor's whole extra reach — the kprobe is global, the /proc/net walk is not
    //    — and it is meaningless to an operator without the comparison against
    //    Warden's own namespace.
    assert!(
        MAIN.contains("if let Some(flow) = event.flow"),
        "nothing reads the decoded flow. The pair would ship two programs whose records \
         are dropped without a word"
    );
    assert!(
        MAIN.contains("\"inbound flow: pid") && MAIN.contains("net_snap::self_netns_ino()"),
        "the journal line stopped naming the accepting task, the local port and whether \
         the socket's namespace is one this agent can enumerate"
    );
    assert!(
        MAIN.contains("warden: inbound flows:"),
        "`--check` no longer states what the flow sensor cannot see. A sensor whose limits \
         are only in a README will be read as an all-clear"
    );
    assert!(
        MAIN.contains("\"netns unreadable in-kernel\""),
        "netns 0 is no longer rendered as an unreadable read. A real netns inode is never \
         0, so the zero has to say 'no claim' rather than 'namespace zero'"
    );
    assert!(
        NETSNAP.contains("pub(crate) fn self_netns_ino()"),
        "the agent no longer resolves its own namespace, so every flow is reported \
         without the one comparison that makes the field useful"
    );
}

/// The source with block and line comments removed, so a rule about what the code
/// does cannot be satisfied — or defeated — by prose. This matters here
/// specifically: the rejected CO-RE shape is quoted *inside* a comment, explaining
/// why it was rejected, and a scan of the raw file would read that quotation as a
/// live call.
///
/// Deliberately a shallow stripper (no string-literal awareness): nothing in this
/// object's string literals contains a `/*` or `//`, and if one later does, the
/// scan below loses a call site rather than inventing one — the wrong direction for
/// a regression lock, which is why the direct assertions on the fixed read shape
/// live next to it and are not replaced by the scan.
fn code_only(source: &str) -> String {
    let cs: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < cs.len() {
        if cs[i] == '/' && i + 1 < cs.len() && cs[i + 1] == '*' {
            let mut j = i + 2;
            while j + 1 < cs.len() && !(cs[j] == '*' && cs[j + 1] == '/') {
                j += 1;
            }
            i = (j + 2).min(cs.len());
            continue;
        }
        if cs[i] == '/' && i + 1 < cs.len() && cs[i + 1] == '/' {
            let mut j = i + 2;
            while j < cs.len() && cs[j] != '\n' {
                j += 1;
            }
            i = j;
            continue;
        }
        out.push(cs[i]);
        i += 1;
    }
    out
}

/// Every char index at which `needle` occurs in `hay`.
fn find_all(hay: &[char], needle: &str) -> Vec<usize> {
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() {
        return Vec::new();
    }
    (0..hay.len().saturating_sub(n.len() - 1))
        .filter(|&i| hay[i..].starts_with(&n[..]))
        .collect()
}

/// The arguments of the call whose open paren is at char index `open`, split at
/// top-level commas, plus the index just past its closing paren. Nested parens (a
/// cast, `sizeof(*e)`) must not split an argument.
fn call_args(cs: &[char], open: usize) -> (Vec<String>, usize) {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    let mut i = open + 1;
    while i < cs.len() {
        match cs[i] {
            '(' => {
                depth += 1;
                current.push('(');
            }
            ')' if depth == 0 => {
                args.push(current.trim().to_string());
                return (args, i + 1);
            }
            ')' => {
                depth -= 1;
                current.push(')');
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current = String::new();
            }
            c => current.push(c),
        }
        i += 1;
    }
    panic!("unterminated call at {open} — the file no longer balances its parens");
}

/// The type a CO-RE relocation is resolved against: the variable the chain starts
/// from, with any `&`, cast, or trailing member steps removed.
fn chain_root(arg: &str) -> String {
    let mut s = arg.trim();
    if let Some(rest) = s.strip_prefix('&') {
        s = rest.trim_start();
    }
    for sep in ["->", "."] {
        if let Some(at) = s.find(sep) {
            s = s[..at].trim_end();
        }
    }
    if let Some(at) = s.rfind(')') {
        s = s[at + 1..].trim_start();
    }
    s.trim().to_string()
}

#[test]
fn no_co_re_relocation_is_resolved_against_a_type_this_object_invents() {
    // The stage-16 defect that this file exists to keep fixed.
    //
    // `BPF_CORE_READ(taken.newsock, sk)` — the obvious way to follow the stashed
    // child socket — COMPILES and is REJECTED AT LOAD: `bpftool prog loadall` on
    // 6.12.107+deb13-amd64 returned -22 / "failed to resolve CO-RE relocation
    // <byte_off> struct warden_accept_stash.newsock". The access-index builtin
    // emits a relocation for the whole chain, and its first link is a type that
    // exists only inside this BPF object, so there is no kernel BTF entry to
    // resolve it against. Because the loader is fail-closed (N-14), that is not a
    // missing field: the agent refuses to start, on every host, for every sensor.
    //
    // The lock is therefore not "the flow probe reads it the other way" alone —
    // that is one line below — but "no CO-RE chain anywhere in the object is rooted
    // on a variable whose struct this file or warden.h defines", so the next stash,
    // the next key type, the next helper argument cannot repeat it.
    let code = code_only(BPF);
    let cs: Vec<char> = code.chars().collect();
    let words: Vec<&str> = code.split_whitespace().collect();

    // Every Warden-defined struct type used in a declaration in this object, and
    // the local variables of those types. `struct warden_event *e` counts too: a
    // chain rooted on a pointer to one of OUR types relocates against our type just
    // the same — kernel BTF describes the kernel, not this file.
    let mut ours: Vec<String> = Vec::new();
    let mut our_vars: Vec<String> = Vec::new();
    for i in 0..words.len() {
        if words[i] != "struct" {
            continue;
        }
        let Some(ty) = words.get(i + 1) else { continue };
        let ty = ty.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        if !ty.starts_with("warden_") {
            continue;
        }
        ours.push(ty.to_string());
        let Some(name) = words.get(i + 2) else {
            continue;
        };
        let name = name
            .trim_start_matches('*')
            .trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '_'));
        if !name.is_empty() && name != ";" {
            our_vars.push(name.to_string());
        }
    }
    ours.sort_unstable();
    ours.dedup();
    our_vars.sort_unstable();
    our_vars.dedup();

    assert!(
        ours.iter().any(|t| t == "warden_accept_stash")
            && ours.iter().any(|t| t == "warden_connect_stash")
            && ours.iter().any(|t| t == "warden_event"),
        "the scan no longer finds the object's own struct types, so it would find \
         nothing to forbid: {ours:?}"
    );
    assert!(
        our_vars.iter().any(|v| v == "taken") && our_vars.iter().any(|v| v == "dialed"),
        "the scan no longer finds the stash locals, which is the whole population the \
         rule guards: {our_vars:?}"
    );

    // (call form, char index of its open paren, index of the root argument).
    // BPF_CORE_READ roots on arg 0; BPF_CORE_READ_INTO takes the destination first
    // and roots on arg 1; the direct bpf_core_read() form relocates against its
    // SOURCE, arg 2. "BPF_CORE_READ(" cannot match inside "BPF_CORE_READ_INTO(" —
    // the '(' is what makes each needle its own call form.
    let sites = [
        ("BPF_CORE_READ(", 0usize),
        ("BPF_CORE_READ_INTO(", 1usize),
        ("bpf_core_read(", 2usize),
    ];
    let mut checked = 0usize;
    for (macro_name, root_index) in sites {
        for at in find_all(&cs, macro_name) {
            let open = at + macro_name.chars().count() - 1;
            let (args, _after) = call_args(&cs, open);
            let root = chain_root(args.get(root_index).unwrap_or(&String::new()));
            checked += 1;
            assert!(
                !our_vars.contains(&root),
                "`{macro_name}{}` resolves its CO-RE relocation against `{root}`, a \
                 variable of a struct defined inside this object. Kernel BTF has no \
                 entry for it, so the program is rejected at LOAD (-22), the loader is \
                 fail-closed, and the agent does not start. Read the stash member as a \
                 plain load and relocate from the kernel type it points at.",
                args.join(", ")
            );
        }
    }
    assert!(
        checked > 20,
        "the scan found {checked} CO-RE call sites — it is not scanning the file it \
         thinks it is, and this test would pass an empty program"
    );

    // The fixed shape itself, positively: the stash member is a plain load and the
    // only relocated chain starts at `struct socket`, a kernel type.
    let kret = probe_body(BPF, "BPF_KRETPROBE", "warden_on_flow");
    // The rejected spelling is QUOTED in the comment above the fix, so the "is it
    // gone from the code" question has to be asked of the comment-free source.
    let kret_code = code_only(kret);
    assert!(
        kret.contains("struct socket *newsock = taken.newsock;")
            && kret.contains("if (bpf_core_read(&sk, sizeof(sk), &newsock->sk))"),
        "the child socket is no longer read as a plain stash load followed by a \
         relocation rooted on struct socket — which is the version that loads"
    );
    assert!(
        !kret_code.contains("BPF_CORE_READ(taken.") && !kret_code.contains("BPF_CORE_READ(&taken."),
        "the flow probe relocated through the stash struct again"
    );
    // A failed read says nothing, rather than recording a flow with a zero peer.
    assert!(
        kret.contains("return 0;") && kret.contains("struct sock *sk = NULL;"),
        "the child-socket read no longer starts from a null initialisation and refuses \
         to record when the read fails — an unreadable peer would be reported as \
         0.0.0.0:0, which is a statement, not a gap"
    );
    // The measurement travels with the code: the -22, the tool that shows it, and
    // the fail-closed consequence. Each has survived at least one reader who would
    // otherwise "simplify" the read back into the shape that does not load.
    assert!(
        BPF.contains("bpftool prog loadall")
            && BPF.contains("struct warden_accept_stash.newsock")
            && BPF.contains("fail-closed"),
        "the reason this read is written the awkward way is no longer on the page where \
         it is written. `make bpf` does NOT catch this — only loading the object on the \
         target kernel does, and `cargo test` cannot load it either"
    );
    assert!(
        BPF.contains("does not load") && BPF.contains("-EINVAL"),
        "the rejected spelling is quoted in the source without the sentence that says it \
         was rejected, and with what the kernel said when it was — a reader cannot tell \
         the quotation from a live call"
    );
}
