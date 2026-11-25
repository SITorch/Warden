# WARDEN — FINAL-02 Operator Handoff

This handoff is for an operator evaluating the Alpha in a lab. It does not
authorize production use or claim full live enforcement qualification. Narrow
armed VM cases on one kernel are proven; the remaining matrix is open.

## 1. Before installation

- Use a disposable or lab host. Privileged enforcement tests require an
  isolated VM with verified snapshot/recovery; never run them on an active
  host.
- Confirm kernel capability presence with `--doctor`. It reports capability
  presence, not attachment.
- Confirm the sample config with `--config-validate --strict`; the result
  `PASS_WITH_WARNINGS` is not an attach claim.
- Keep config mode `0640`. Treat the config as security-sensitive: several
  documented limitations depend on an attacker not being able to write it.

## 2. Install

`scripts/install_wizard.sh` is preview-first: without confirmation flags it
writes nothing. `make install` installs the binary, sample policy, units and
docs but does not enable or start the service. Both preserve existing policy.
No installation of the final candidate on a clean host was completed in this
mission; that gate remains `NOT_RUN`.

## 3. Status vocabulary

| Command / result | Meaning |
|---|---|
| `--check` | validates config and prints planned coverage; no live `bpf()` claim |
| `--self-test` | local contract checks only; no BPF load, no service start, no SENTINEL contact; uses `PASS`, `FAIL`, `UNKNOWN`, `NOT_RUN`, `NOT_APPLICABLE` |
| `--doctor` | kernel capability *presence*, not attachment |
| `--health` | `/proc`-only sensor view; uses `cannot see/…` where kernel state is unavailable |
| `--version` | reports the digest of the BPF object compiled into that binary |
| `scripts/test-privileged.sh` exit `77` | `SKIP`; never a pass |
| `scripts/test-privileged.sh` exit `0` in a disposable VM | `PASS` only for the executed privileged case; not a full matrix |
| `gitleaks` / `cargo audit` | local gates passed; hosted CI still must run |

## 4. Default posture and enforcement

Default posture is observe-only. Arming denial is a separate, explicit decision:
`[enforce] arm = false` and `[egress] enabled = false, arm = false` in the
public example. BPF-LSM, cgroup egress and kill responders all remain off until
an operator deliberately configures them.

Even when configured:

- egress DENY applies only inside the attached cgroup, not the whole host;
  representative armed TCP4/UDP4/TCP6 denials were proven in a disposable VM,
  but direct UDP6 and the full matrix remain untested;
- IPv6 volume numbers are socket-path counters, not wire traffic;
- kill fallback can have a TOCTOU window where pidfd is unavailable; only the
  pidfd takedown path was exercised in the VM;
- an insert refusal now increments `WARDEN_EGRESS_MAP_FULL`, but no live armed
  insert refusal was produced on this candidate;
- guarded files are only those in explicit policy, and inode-key reconciliation
  has a bounded refresh lag; the pre-opened-fd LSM case passed in the VM, but
  other LSM hooks and writable mappings remain untested.

## 5. SENTINEL

The local collector self-test passed. That proves the local bridge/contract
only. There is no authorized staging endpoint, tenant, credential, CA or
egress permission in this mission, so real delivery is `BLOCKED` / `NOT_RUN`.
Do not configure a production endpoint from guesswork.

## 6. Escalation and handoff checklist

- Treat all `NOT_RUN`, `BLOCKED` and `UNKNOWN` items in
  `WARDEN_FINAL_KNOWN_LIMITATIONS.md` as open work, not as implicit passes.
- Before any production claim: complete the remaining armed matrix cases for
  all three enforcement axes (including direct UDP6, forced E-09 refusal and
  full kill/LSM cases), additional kernel validation, a defined soak,
  clean-host install/reload/deadman exercise, authorized live SENTINEL
  integration, and hosted CI including `cargo deny`.
- Before any public release: enable a real monitored private vulnerability
  reporting channel and complete the external actions in
  `WARDEN_FINAL_RELEASE_DECISION.md`.
- No contact, key, endpoint or reporting address is provided here; do not
  invent one.

## 7. Publication status

Nothing has been committed, tagged, pushed, published or exposed. The parent
SENTINEL repository and all unrelated user work were left untouched.
