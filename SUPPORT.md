# Support

WARDEN is a community-maintained Public Alpha. This document describes the
support boundary that actually exists; it does not promise a service level.

## Supported versions

| Version | Security fixes | General help |
|---|---|---|
| `v0.1.0-alpha.1` (proposed; not tagged) | Best effort on the current Alpha line | Current candidate only |
| development `main` | Preferred target for current-code reports | Current source only |
| pre-Alpha internal builds | Not supported | Not supported |

There are no older public releases to support.

## Where to ask for help

After a maintainer publishes the sanitized repository:

- Use GitHub Issues for reproducible, non-security bugs and installation
  questions. Use the supplied issue templates and redact host details.
- Use Discussions only if the maintainer enables them; no discussion forum is
  assumed by this candidate.
- For suspected vulnerabilities, use the repository's private vulnerability
  reporting channel **only if** the maintainer confirms it is enabled and
  monitored. Until then, publication is blocked. See `SECURITY.md`.

No support email, chat channel, commercial support desk, security team, or
response-time commitment is claimed by this candidate.

## What is in scope for help

- Building the shipped source and running the documented local checks.
- Configuration validation and the read-only self-test.
- Unprivileged test behaviour and documented Alpha limitations.
- Clarifying the difference between compile-time support, runtime detection,
  successful BPF verification/attachment, observed events, and enforcement.

## What is not in scope

- Production deployment design, tuning, or incident response.
- Live SENTINEL integration; it is `BLOCKED / NOT_RUN` in this Alpha.
- Multi-kernel compatibility certification or long-duration soak qualification.
- Privileged testing on a shared, production, or sole SSH-accessible host.
- Third-party kernel, OpenSSL, systemd, or distribution issues.

## Before opening an issue

Record the exact command, exit status, WARDEN commit, distribution, kernel
release (`uname -r`), architecture, and whether BTF and the `bpf` LSM are
available. State `PASS`, `FAIL`, `SKIP`, `BLOCKED`, `UNKNOWN`, `NOT_RUN`, or
`NOT_APPLICABLE` truthfully. A skipped privileged test is not a pass.

Do not paste credentials, guarded-file contents, signed heartbeat URLs,
customer data, private hostnames, private IPs, usernames, or absolute home
paths. Suspected security issues must not be opened as public issues.
