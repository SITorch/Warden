# WARDEN-PRQ-FINAL-02 — Security Disclosure Readiness

status=`BLOCKED_EXTERNAL_MAINTAINER_ACTION`. Prepared 2026-11-24. This gate is
independent of code quality: a genuine, monitored, private reporting channel
does not yet exist because the public repository does not exist.

## 1. Mechanism assessment

| Item | Finding |
|---|---|
| Intended public repository | not created; no public remote configured by this mission |
| Current origin | private monorepo remote; not a public WARDEN repository |
| GitHub Private Vulnerability Reporting | not enabled (no public repository to enable it on) |
| Equivalent private security-advisory mechanism | not configured |
| Genuinely monitored dedicated security mailbox | none established |
| Responsible maintainer identity | not asserted; no identity invented |
| Notification path to a monitored account | `UNKNOWN` |
| Response-time guarantee | not claimed (none invented) |

No email address, PGP key, security-team identity, response SLA or third-party
reporting account was invented. No remote visibility was changed.

## 2. `SECURITY.md` review

The candidate `SECURITY.md` was reviewed line by line and already contains:

- Supported versions (`v0.1.0-alpha.1` proposed, development `main`), with
  pre-Alpha builds excluded.
- A single private reporting route: the hosting platform's private
  vulnerability reporting facility (GitHub *Security → Report a vulnerability*
  when hosted there).
- Explicit instruction not to open public issues for vulnerabilities and not to
  include credentials, guarded-file contents, signed heartbeat URLs or
  production data.
- Required report content: version/commit, distribution, kernel, BTF/LSM
  availability, security boundary, reproduction, redacted logs, privilege
  requirements.
- A documented non-vulnerability list that preserves all six Alpha limitations.
- A severity/triage rubric (Critical / High / Medium / Low) and coordinated
  disclosure expectations.
- Scope and out-of-scope statements, testing boundaries, and hardening
  assumptions.
- An explicit release-gate note stating that the channel must be enabled and
  monitored before publication and that the release remains `BLOCKED` until
  then.

No change was required. The policy is accurate; the **mechanism** is absent.
A paragraph in a policy file is not an operational channel.

## 3. Exact external actions required

`BLOCKED_EXTERNAL_MAINTAINER_ACTION` — responsible party: repository maintainer.

1. Create the public WARDEN repository from the frozen, sanitized source
   snapshot (no inherited private history).
2. Enable the platform's private vulnerability reporting feature on that
   repository (GitHub: *Settings → Security → Private vulnerability reporting*;
   Forgejo/Gitea equivalent if that is the chosen host).
3. Confirm a named maintainer has maintainer/admin access to triage advisories,
   and that notifications reach an account that is actually monitored.
4. Verify end to end that a reporter can submit a private report without
   public disclosure and that the maintainer receives it.
5. Re-read `SECURITY.md` against the chosen host and adjust only the
   platform-specific sentence if the host is not GitHub. Do not add invented
   contact details.
6. Record the verification (platform, date, maintainer role, sanitized
   evidence) and only then re-evaluate this gate.

Until step 5 is done, the document's GitHub-specific wording is a conditional
instruction, not a false claim of an operational channel.

## 4. Gate summary

| Requirement | Status |
|---|---|
| Real reporting destination exists | `BLOCKED_EXTERNAL_MAINTAINER_ACTION` |
| Maintainer access confirmed | `BLOCKED_EXTERNAL_MAINTAINER_ACTION` |
| Reports can be submitted privately | `BLOCKED_EXTERNAL_MAINTAINER_ACTION` |
| Notifications reach monitored account | `UNKNOWN` / blocked |
| Responsible maintainer identified | `BLOCKED_EXTERNAL_MAINTAINER_ACTION` |
| Supported versions defined | `PASS` (`SECURITY.md`) |
| Triage process documented | `PASS` (`SECURITY.md`) |
| Coordinated disclosure documented | `PASS` (`SECURITY.md`) |
| Known limitations documented | `PASS` (`SECURITY.md`, `WARDEN_KNOWN_LIMITATIONS.md`) |
| No invented contact details | `PASS` |
| Publication | `NOT_PERFORMED` |
