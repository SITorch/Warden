# Security Policy

WARDEN is experimental Alpha software that runs with elevated privileges and
interacts with kernel security hooks. Security reports are taken seriously and
handled with coordinated disclosure.

> **Release gate status (WARDEN-OSR-FINAL-03):** this policy designates GitHub
> Private Vulnerability Reporting (PVR) as the intended private channel. On the
> currently private `SITorch/Warden` repository the channel is
> `NOT_CONFIGURED` and `NOT_TESTED`. Publication remains `BLOCKED` until a
> repository administrator enables PVR on the actual repository, confirms that
> a monitored account receives notifications, and completes one harmless
> end-to-end test report. Creating or editing this file does not enable PVR.
> No email address, PGP key, security team, bug bounty, response SLA, or
> third-party reporting account has been invented.

## Private channel verification record

Before public visibility, the repository administrator must record all three
checks here:

| Check | Status | Evidence |
|---|---|---|
| PVR enabled on `SITorch/Warden` | `NOT_CONFIGURED` | Repository Security settings |
| Notifications monitored by an existing maintainer account | `NOT_TESTED` | Maintainer confirmation |
| Harmless end-to-end private report completed | `NOT_TESTED` | Maintainer confirmation |

## Supported versions

| Version | Supported |
|---|---|
| `v0.1.0-alpha.1` (proposed) | Alpha — security fixes on a best-effort basis, no stability guarantee |
| development `main` | Yes — preferred target for reports against current code |

Pre-Alpha internal builds are not supported. Because there are no prior public
releases, there is no supported older line.

## Where to report (private channel)

Use the hosting platform's **private vulnerability reporting** facility for this
repository (on GitHub: the repository's *Security → Report a vulnerability*
tab). That channel keeps the report between you and the maintainers and is the
only accepted route for sensitive findings.

- Do **not** open a public issue for a vulnerability.
- Do **not** include real credentials, guarded-file contents, signed heartbeat
  URLs (`mac=` parameters), or production data in a report.
- If the private channel is not available, treat that as a release blocker and
  contact the maintainers through an already-established private channel; do
  not publish the finding publicly.

## What a report should contain

- Affected version or commit, distribution, kernel release (`uname -r`),
  architecture, and whether BTF / the `bpf` LSM were available.
- A clear statement of the security boundary you believe was crossed.
- Minimal reproduction steps and observed vs expected behaviour.
- Any relevant log lines, with all credentials, private hostnames/IPs,
  usernames, and local absolute paths redacted.
- Whether the finding needs root / `CAP_BPF` / a disposable VM to reproduce.

## What is *not* a vulnerability

The following are documented, deliberate Alpha limitations rather than private
security bugs (they are tracked publicly in `docs/release/WARDEN_KNOWN_LIMITATIONS.md`):

- WARDEN is not a complete EDR, host firewall, or intrusion-prevention system.
- Detection findings (including C2 cadence findings) do not block traffic; they
  are analytic leads that never set `wants_kill`.
- File/inode denial is limited to explicit guarded inodes and only when the
  `bpf` LSM is active, the program attached, and enforcement armed. It does not
  revoke descriptors or mappings opened before arming.
- cgroup egress denial is scoped to the configured cgroup and is not a full-host
  firewall; it is not enabled by default.
- IPv6 volume accounting is IPv6-**socket-path** accounting, not all IPv6 wire
  traffic. UDP counts are per `sendmsg`/`recvmsg` operation, not per packet.
- Live SENTINEL delivery, multi-kernel compatibility, and long-duration soak are
  not yet qualified.

Reports that only restate these known limits are useful as documentation
feedback but are not treated as new vulnerabilities.

## Severity and triage

Reports are triaged against the boundary they cross:

- **Critical** — remote code execution, credential disclosure, or reliable
  privilege escalation with no preconditions.
- **High** — local privilege escalation, bypass of an armed denial, or silent
  data loss in the delivery path under realistic conditions.
- **Medium** — misleading security state, incomplete redaction, or a
  denial-of-service in the agent under bounded conditions.
- **Low / Informational** — hardening opportunities, documentation errors, or
  issues requiring already-privileged local access.

Maintainers acknowledge reports through the private channel, investigate,
agree a severity, and coordinate a fix and disclosure timeline with the
reporter. Fixes are prepared privately and released with an advisory. Reporters
are credited if they wish.

## Coordinated disclosure

Please give maintainers a reasonable opportunity to investigate and prepare a
fix before public disclosure. WARDEN will not seek to delay disclosure of
actively exploited issues.

When a fix is ready, the intended path is a GitHub Security Advisory and a
public release note describing the affected versions and mitigation. No
advisory, fix, or user notification has been issued by this candidate. The
actual maintainer must confirm that advisory notifications reach a monitored
account before publication.

## Bug bounty program

No bug bounty program exists for this candidate and none is claimed. Reports are
accepted through the private reporting channel described above once it is
actually enabled and monitored.

## Scope

In scope: the Rust agent, shipped eBPF programs and their ABI, the configuration
engine and its strict-validation gate, the delivery/bridge/HMAC/TLS paths, the
installer and systemd units, and the security claims made in documentation.

Out of scope: the upstream Linux kernel, OpenSSL, third-party services the agent
reports to, and vulnerabilities that require root to exploit against a host the
attacker already fully controls.

## Testing boundaries relevant to reporters

Ordinary CI is unprivileged: it never loads BPF, attaches LSM/cgroup programs,
or exercises kill responders. The privileged BPF-LSM runtime test is `#[ignore]`d
and is reachable only through `scripts/test-privileged.sh` in a disposable VM.
A skipped test is never reported as a pass. See
`docs/release/PRQ_02_SECURITY_REVIEW.md`,
`docs/release/PRQ_06_ENFORCEMENT_QUALIFICATION.md`, and
`docs/release/WARDEN_KNOWN_LIMITATIONS.md`.

## Hardening assumptions

The deployed configuration must be mode `0640` or stricter and owned by the
service account/root. The public Alpha sample and operational fixture are both
`0640` (historically `0664`); any deployed copy must remain `0640 root:warden`.
The optional mTLS bridge requires
complete CA/cert/key material and always verifies the peer; there is no
"verification off" option. Cleartext HTTP transport is the default and assumes
TLS is terminated at a trusted edge.
