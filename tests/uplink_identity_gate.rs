//! W2K-28: `warden --check` must classify an uplink written as a NAME.
//!
//! The unit tests in `src/config.rs` and `src/bridge.rs` call the classifier and
//! the delivery gate with an injected resolver. What no unit test can see is the
//! *wiring*: that `main` actually asks, prints the answer on the `--check` path,
//! and logs it on the daemon path. Stage 10 measured exactly that blind spot —
//! pinning `main.rs` to a constant verdict left all 463 bin tests green (report
//! section 79) — so the property "the gate runs when the binary runs" gets a
//! process-level test here rather than only a manual witness.
//!
//! These cases are unprivileged and send nothing anywhere: `--check` loads the
//! config, prints policy, and exits. The hosts are chosen so the DNS answer does
//! not matter for the assertion — `.invalid` is the RFC 6761 TLD that must never
//! resolve, and a loopback literal must not be looked up at all.

use std::process::Command;

/// Run `warden --check` on a throwaway config and return (exit code, all output).
fn check(config: &str) -> (i32, String) {
    let dir = std::env::temp_dir();
    let stem = format!(
        "warden-uplink-gate-{}-{}",
        std::process::id(),
        config
            .bytes()
            .fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64))
    );
    let path = dir.join(format!("{stem}.toml"));
    let spool = dir.join(format!("{stem}.spool.jsonl"));
    // The spool is created by `--check` itself; keep it beside the throwaway config
    // so the test never touches /var/lib or a real StateDirectory.
    std::fs::write(&path, config.replace("{SPOOL}", &spool.to_string_lossy()))
        .expect("writing the throwaway config");

    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .args(["--config", &path.to_string_lossy(), "--check"])
        .output()
        .expect("running warden --check");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&spool);
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

const BRIDGE: &str = "[bridge]\nurl = \"{URL}\"\napi_key = \"k\"\nspool_path = \"{SPOOL}\"\n";

fn bridge_to(url: &str) -> String {
    BRIDGE.replace("{URL}", url)
}

#[test]
fn an_unresolvable_name_is_said_and_the_check_still_passes() {
    // The property that makes a config-time resolver safe: a name Warden cannot
    // classify is reported, not fatal. A host whose DNS is down must still start
    // its detection agent — and the `--check` that systemd runs as ExecStartPre
    // must not be the thing that stops it.
    let (code, text) = check(&bridge_to("http://warden-uplink-gate.invalid:9099/api/"));
    assert_eq!(
        code, 0,
        "--check must pass on an unclassifiable name:\n{text}"
    );
    assert!(
        text.contains("uplink host warden-uplink-gate.invalid"),
        "the wiring is the whole point: `--check` must print what the gate \
         concluded about the configured name.\n{text}"
    );
    assert!(text.contains("could not be classified"), "{text}");
    assert!(text.contains("still starts"), "{text}");
}

#[test]
fn a_name_that_answers_is_printed_with_its_address() {
    // `localhost` is the name every install already uses for an on-box edge. The
    // assertion is that the gate RAN and named the host; the address itself is the
    // resolver's business (a host without a localhost entry gets the
    // cannot-classify note above, which is why that is accepted here too).
    let (code, text) = check(&bridge_to("http://localhost:9099/api/"));
    assert_eq!(code, 0, "--check must pass on a loopback name:\n{text}");
    assert!(
        text.contains("uplink host localhost"),
        "--check said nothing about the name, so the gate is not wired in: {text}"
    );
    let classified = text.contains("resolved to") || text.contains("could not be classified");
    assert!(
        classified,
        "neither an answer nor a failure was said:\n{text}"
    );
    assert!(
        !text.contains("PUBLICLY ROUTABLE"),
        "a name on this host must not be refused as public without evidence:\n{text}"
    );
}

#[test]
fn an_ip_literal_uplink_is_never_asked() {
    // The shipped shape — and every documented install — must cost no resolver
    // call and no extra line. This is the end-to-end half of the unit test that
    // counts injected lookups; here it proves the same thing through `main`, where
    // a regression would quietly add a startup DNS dependency to every host.
    let (code, text) = check(&bridge_to("http://127.0.0.1:9099/api/"));
    assert_eq!(code, 0, "--check must pass a loopback literal:\n{text}");
    assert!(text.contains("bridge transport"), "{text}");
    assert!(
        !text.contains("uplink host"),
        "an IP literal went through the NAME gate and paid a lookup:\n{text}"
    );
}

#[test]
fn a_public_literal_is_refused_before_the_resolver_is_ever_needed() {
    // W2K-19's own case, re-run through the binary next to W2K-28's: the two gates
    // must be the same refusal. If a NAME could reach the wire where a literal
    // could not, the gate would be a spelling test rather than a security control.
    let refused = check(&bridge_to("http://203.0.113.9:9099/api/"));
    assert_ne!(
        refused.0, 0,
        "a public literal must fail --check:\n{}",
        refused.1
    );
    assert!(refused.1.contains("PUBLICLY ROUTABLE"), "{}", refused.1);
    assert!(
        refused.1.contains("allow_public_plaintext"),
        "the refusal must name the escape:\n{}",
        refused.1
    );
}
