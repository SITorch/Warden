//! Safe, allowlisted rendering for operational log lines.
//!
//! WARDEN's journal is a different exposure boundary from the Sentinel
//! envelope. Remote telemetry retains the full finding (subject to its own
//! transport policy); a local line needs only enough context to correlate an
//! event with the decision taken on this host. Nothing here accepts a raw
//! `Finding`, an error's `Debug`, or a formatted request head: callers pass
//! explicit fields, and this module is the single place that decides which of
//! them may appear.

#[cfg(test)]
use std::error::Error;
use std::fmt;

/// Redaction marker kept identical to the health-report marker so operators
/// see the same replacement text in every surface.
const REDACTED: &str = "[REDACTED]";

/// Credential-bearing assignment keys. The key name is kept because it is the
/// evidence an operator needs; the value never is.
const SECRET_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "token",
    "password",
    "passwd",
    "private_key",
    "private-key",
    "client_secret",
    "root_token",
    "hmac_secret",
];

/// Markers whose *remainder of line* is never safe to print. This covers HTTP
/// auth headers and CLI flags, where the secret is a value after a marker
/// rather than a TOML `key = value` assignment.
const VALUE_MARKERS: &[&str] = &[
    "x-api-key:",
    "authorization:",
    "proxy-authorization:",
    "api-key:",
    "access-token:",
    "bearer ",
    "--api-key",
    "--apikey",
    "--token",
    "--password",
    "--secret",
    "--private-key",
    "private_key:",
    "private-key:",
];

/// Redact credential material from text that may reach a log or an assertion
/// message.
///
/// This is deliberately over-inclusive. A whole line after an auth marker is
/// dropped, and a document containing a PEM private-key header is replaced in
/// its entirety. Missing a secret is worse than hiding a benign suffix.
pub(crate) fn redact_secrets(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    if lower.contains("-----begin") && lower.contains("private key") {
        return "[REDACTED: PRIVATE KEY MATERIAL]".to_string();
    }

    let mut out = String::with_capacity(text.len() + 16);
    for line in text.split_inclusive('\n') {
        out.push_str(&redact_line(line));
    }
    out
}

fn redact_line(line: &str) -> String {
    let newline = if line.ends_with('\n') { "\n" } else { "" };
    let body = line.strip_suffix('\n').unwrap_or(line);
    let lower = body.to_ascii_lowercase();

    // 1. Credential assignment: keep `api_key =`, drop everything after `=`.
    let mut assignment: Option<usize> = None;
    for key in SECRET_KEYS {
        let mut search = 0usize;
        while let Some(rel) = lower[search..].find(key) {
            let p = search + rel;
            let preceded_ok = p == 0 || {
                let b = lower.as_bytes()[p - 1];
                !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            };
            let followed_by_eq = lower[p + key.len()..].trim_start().starts_with('=');
            if preceded_ok && followed_by_eq && assignment.is_none_or(|old| p < old) {
                assignment = Some(p + key.len());
                break;
            }
            search = p + key.len();
        }
    }

    // 2. Header/CLI marker: keep the marker itself, drop its value. Choose the
    //    earliest marker so a command line with several flags is all masked.
    let mut marker: Option<(usize, usize)> = None;
    for needle in VALUE_MARKERS {
        let mut search = 0usize;
        while let Some(rel) = lower[search..].find(needle) {
            let p = search + rel;
            if marker.is_none_or(|(old, _)| p < old) {
                marker = Some((p, needle.len()));
                break;
            }
            search = p + needle.len();
        }
    }

    let mut end = body.len();
    if let Some(key_end) = assignment {
        if let Some(eq_rel) = body[key_end..].find('=') {
            end = end.min(key_end + eq_rel + 1);
        }
    }
    if let Some((p, n)) = marker {
        end = end.min(p + n);
    }
    if end == body.len() && assignment.is_none() && marker.is_none() {
        return line.to_string();
    }

    let mut out = String::with_capacity(body.len() + 16);
    out.push_str(&body[..end]);
    out.push(' ');
    out.push_str(REDACTED);
    out.push_str(newline);
    out
}

/// Render an error chain without using `Debug` and without carrying a secret
/// quoted by one of its causes.
#[cfg(test)]
pub(crate) fn safe_error(err: &(dyn Error + 'static)) -> String {
    let mut parts = Vec::new();
    let mut current = Some(err);
    // Error chains are ordinarily short. The bound keeps a pathological
    // self-referential source from turning a diagnostic into a hang.
    for _ in 0..8 {
        let Some(e) = current else { break };
        parts.push(redact_secrets(&e.to_string()));
        current = e.source();
    }
    parts.join(": ")
}

/// A diagnostic-only view of a command invocation: allowlisted command words
/// and flag names only. Argument *values* are where credentials hide, so they
/// are never included.
#[cfg(test)]
pub(crate) fn safe_command_summary(args: &[&str]) -> String {
    const COMMANDS: &[&str] = &[
        "req", "x509", "verify", "version", "pkcs12", "ca", "genrsa", "rsa", "dgst", "rand",
        "s_client", "s_server",
    ];
    let mut parts = Vec::new();
    for arg in args {
        if parts.len() == 8 {
            break;
        }
        let token = arg.split('=').next().unwrap_or(arg);
        let flag_like = token.starts_with('-')
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if flag_like || COMMANDS.contains(&token) {
            parts.push(token.to_string());
        }
    }
    if parts.is_empty() {
        "(no allowlisted command tokens)".to_string()
    } else {
        parts.join(" ")
    }
}

/// The fields a local finding line is allowed to carry.
///
/// No summary, detail, comm, exe, cmdline, cgroup, environment or request body
/// is present by construction. The stable event id ties the local line to the
/// full remote record; pid is kept because it is the operator's immediate
/// correlate on the host.
pub(crate) struct FindingLog<'a> {
    event_id: Option<&'a str>,
    severity: &'static str,
    event_type: &'static str,
    action: &'static str,
    pid: u32,
}

impl<'a> FindingLog<'a> {
    pub(crate) fn new(
        event_id: Option<&'a str>,
        severity: &'static str,
        event_type: &'static str,
        action: &'static str,
        pid: u32,
    ) -> Self {
        Self {
            event_id,
            severity,
            event_type,
            action,
            pid,
        }
    }
}

impl fmt::Display for FindingLog<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[event_id={}] {} {} action={} pid={}",
            self.event_id.unwrap_or("pending"),
            self.severity,
            self.event_type,
            self.action,
            self.pid
        )
    }
}

/// Even an accidental `Debug` formatting of this wrapper uses the allowlisted
/// Display form; there is no derived field dump to bypass redaction.
impl fmt::Debug for FindingLog<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{Finding, FindingType, ProcessInfo, Severity};
    use serde_json::json;
    use std::fmt;
    use std::io;

    const API_KEY_CANARY: &str = "CANARY_NOT_REAL_API_KEY_4d21";
    const AUTH_CANARY: &str = "CANARY_NOT_REAL_BEARER_8ba7";
    const KEY_CANARY: &str = "CANARY_NOT_REAL_PRIVATE_KEY_BODY_6c02";
    const CONFIG_CANARY: &str = "CANARY_NOT_REAL_CONFIG_SECRET_1f93";
    const COMMAND_CANARY: &str = "CANARY_NOT_REAL_CLI_PASSWORD_7e44";
    const FINDING_CANARY: &str = "CANARY_NOT_REAL_FINDING_DETAIL_0a55";

    fn assert_no_canary(text: &str, canary: &str) {
        assert!(
            !text.contains(canary),
            "redacted text must not carry the synthetic canary"
        );
    }

    #[derive(Debug)]
    struct Inner;

    impl fmt::Display for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "inner: Authorization: Bearer {AUTH_CANARY}")
        }
    }

    impl Error for Inner {}

    #[derive(Debug)]
    struct Outer;

    impl fmt::Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "outer: X-API-Key: {API_KEY_CANARY}")
        }
    }

    impl Error for Outer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&Inner)
        }
    }

    #[test]
    fn api_key_header_is_redacted() {
        let input = format!("request head\r\nX-API-Key: {API_KEY_CANARY}\r\nContent-Length: 2");
        let redacted = redact_secrets(&input);
        assert_no_canary(&redacted, API_KEY_CANARY);
        assert!(redacted.contains("X-API-Key:"));
        assert!(redacted.contains(REDACTED));
    }

    #[test]
    fn authorization_header_is_redacted() {
        let input = format!("Authorization: Bearer {AUTH_CANARY}");
        let redacted = redact_secrets(&input);
        assert_no_canary(&redacted, AUTH_CANARY);
        assert!(redacted.contains("Authorization:"));
    }

    #[test]
    fn private_key_contents_are_redacted_as_a_whole_document() {
        let input =
            format!("-----BEGIN PRIVATE KEY-----\n{KEY_CANARY}\n-----END PRIVATE KEY-----\n");
        let redacted = redact_secrets(&input);
        assert_no_canary(&redacted, KEY_CANARY);
        assert!(redacted.contains("PRIVATE KEY MATERIAL"));
    }

    #[test]
    fn secret_bearing_config_error_is_redacted() {
        let input = format!("TOML parse error: api_key = \"{CONFIG_CANARY}\"\n");
        let redacted = redact_secrets(&input);
        assert_no_canary(&redacted, CONFIG_CANARY);
        assert!(redacted.contains("api_key"));
        assert!(redacted.contains(REDACTED));
    }

    #[test]
    fn command_line_credentials_are_not_in_the_summary() {
        let args = [
            "openssl",
            "req",
            "--password",
            COMMAND_CANARY,
            "--api-key=another-value",
            "/tmp/warden-canary.pem",
        ];
        let summary = safe_command_summary(&args);
        assert_no_canary(&summary, COMMAND_CANARY);
        assert!(!summary.contains("/tmp/warden-canary.pem"));
        assert!(summary.contains("req"));
        assert!(summary.contains("--password"));
    }

    #[test]
    fn nested_formatted_errors_are_redacted_without_debug() {
        let outer = Outer;
        let rendered = safe_error(&outer);
        assert_no_canary(&rendered, API_KEY_CANARY);
        assert_no_canary(&rendered, AUTH_CANARY);
        assert!(rendered.contains("outer"));
        assert!(rendered.contains("inner"));
    }

    #[test]
    fn io_error_chain_is_rendered_without_raw_debug() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "no canary here");
        let rendered = safe_error(&err);
        assert!(rendered.contains("no canary here"));
        assert!(!rendered.contains("PermissionDenied {"));
    }

    #[test]
    fn finding_log_omits_sensitive_fields_but_keeps_audit_metadata() {
        let finding = Finding {
            source_ts_ns: 42,
            event_type: FindingType::AccessDenied,
            severity: Severity::High,
            summary: format!("summary with {FINDING_CANARY}"),
            detail: json!({"cmdline": FINDING_CANARY, "secret": FINDING_CANARY}),
            process: ProcessInfo {
                pid: 4242,
                ppid: 1,
                uid: 0,
                comm: "canary-comm".to_string(),
                exe: Some(format!("/tmp/{FINDING_CANARY}")),
                cmdline: Some(FINDING_CANARY.to_string()),
                cgroup: Some(FINDING_CANARY.to_string()),
                starttime: Some(7),
            },
            target_pid: None,
            wants_kill: false,
        };
        let line = FindingLog::new(
            Some("event-001"),
            finding.severity_str(),
            finding.event_type_str(),
            "observed",
            finding.process.pid,
        )
        .to_string();

        assert_no_canary(&line, FINDING_CANARY);
        assert!(line.contains("event_id=event-001"));
        assert!(line.contains("high"));
        assert!(line.contains("endpoint:access_denied"));
        assert!(line.contains("action=observed"));
        assert!(line.contains("pid=4242"));
    }

    #[test]
    fn debug_formatting_cannot_bypass_the_allowlist() {
        let line = format!(
            "{:?}",
            FindingLog::new(None, "critical", "endpoint:self_tamper", "killed", 9)
        );
        assert!(line.contains("endpoint:self_tamper"));
        assert!(line.contains("action=killed"));
        assert!(!line.contains("Finding {"));
        assert!(!line.contains("ProcessInfo"));
    }
}
