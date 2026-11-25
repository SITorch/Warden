# WARDEN — FINAL-02 Production Qualification Decision

**Decision: `NOT QUALIFIED`. Status: `BLOCKED`.** Prepared 2026-11-24 as the
final authority for WARDEN-PRQ-FINAL-02. This document supersedes the PRQ-01
production decision for *this candidate* without reopening M16.

M16 remains `COMPLETED_WITH_LIMITATIONS` with readiness `LAB_VALIDATED`.
Nothing in FINAL-02 re-runs, regrades, or upgrades that historical verdict.

## 1. Gate-by-gate decision

| Gate | Status | Evidence / blocker |
|---|---|---|
| Canonical baseline and user-work preservation | `PARTIAL` | HEAD `e4d5f7adea0f957d37c70dbc162782583a0ce01c`, branch `main`; deleted tracked `Warden/warden.zip`, `<parent-project>/`, `<parent-project>/`, `<parent-project>/` changes preserved and `git diff --check` exit 0. Untracked `Warden/warden2.zip` was recorded `PRESENT` in earlier FINAL-02 integrity logs but is `ABSENT` at final recheck; cause `UNKNOWN`, no copy found in targeted host paths or the disposable VM, and it was not reconstructed from the sanitized export |
| Sanitized final snapshot | `PASS` | Allow-list export, no private history, no raw evidence, no ZIPs; exact count/digest in `PRQ_FINAL_EVIDENCE_INDEX.md` |
| Secret and history audit | `PASS` | gitleaks 8.30.1 checksum verified; public export and canonical tree 0 findings; fallback pattern review classified all matches; BPF metadata 0 private paths, 0 xattrs, 0 symlinks |
| Advisory audit for final lockfile | `PASS` | cargo-audit 0.23.0, RustSec DB `1d328b6bb9f2f350bf65c1c81ab68781cb9e018a`, 1566 advisories, 72 deps, exit 0; evidence in `evidence/prq/final/supply_chain/` |
| License / attribution / SBOM | `PASS` / `PARTIAL` | GPL-2.0 text unchanged, SPDX headers, 79-package SBOM; native-library legal determination remains open for binary distribution |
| Static security review and documented defects | `PASS_WITH_LIMITATIONS` | E-09 fixed with three regressions; 3xx redirect regression added; R-06…R-13 and R-14/R-15 remain documented and accepted only as Alpha limitations |
| Clean-clone build, format, lint, unprivileged tests | `PASS` | Final clean-export gates; exact test tally in `PRQ_FINAL_EVIDENCE_INDEX.md`; privileged runner exit 77 `SKIP` on the host, never counted as a pass; VM exit 0 is separate evidence |
| Public CI (hosted) | `NOT_RUN` | No authorized staging repository or runner; local replay only |
| `cargo deny` licenses/bans policy | `NOT_RUN` | Tool unavailable locally; hosted CI must run it |
| Disposable-VM recovery for armed proof | `PASS` | Fresh `prq_final2_baseline` created, reverted and verified running; exact BPF SHA and binary re-checked afterward |
| Armed BPF-LSM pre-opened-fd case on final source | `PASS` (representative case; full matrix `PARTIAL`) | `scripts/test-privileged.sh` exit 0 in VM; `read`, `write`, `ftruncate`, `fchmod` through a pre-armed fd all returned `-EPERM`; remaining hook/allowed/disarm cases `NOT_RUN` |
| Armed cgroup egress denial on final source | `PASS` (with harness artifacts) | VM: shadow allowed with `shadow_deny=1`; armed TCP4/UDP4/TCP6 returned `-EPERM`; non-matching port allowed; log read-back `ARMED`, hooks 4/4 attached. Direct UDP6 case `NOT_RUN`; baseline timing failure and stale grep expectation recorded as artifacts |
| Armed kill responder takedown on final source | `PASS` (single case; full matrix `PARTIAL`) | Throwaway victim signalled after protected-set refresh; Warden killed the exact actor with SIGKILL via `pidfd_send_signal` and logged `action=killed`; PID reuse, exclusions, other kill flags and disarm `NOT_RUN` |
| Kernel/distribution matrix beyond the tested Debian 13 VM | `UNKNOWN` | `PRQ_FINAL_KERNEL_COMPATIBILITY.md` |
| Long-duration soak / resource stability | `UNKNOWN` | `PRQ_FINAL_PERFORMANCE_AND_SOAK.md`; no 24-hour test performed |
| Real SENTINEL integration | `BLOCKED` / `NOT_RUN` | No authorized endpoint, tenant, credentials, CA, egress permission or test-data authorization; none invented |
| Clean-host install / SIGHUP reload / deadman recovery | `NOT_RUN` | `PRQ_FINAL_INSTALLER_AND_RECOVERY.md`; CLI/installer script tests only |
| Private vulnerability reporting channel | `BLOCKED` | External maintainer action; no contact, PGP key or account invented |

Any `NOT_RUN`, `BLOCKED` or `UNKNOWN` row is sufficient to withhold production
qualification; several remain.

## 2. What the evidence supports

- The final source is a single Rust/eBPF implementation with no second config
  engine, rewritten installer or duplicate enforcement subsystem.
- Static review found no new undocumented defect after E-09 was fixed. The
  telemetry defect removed a false `map_full=0` reassurance signal; it was not a
  fail-open. The E-09 insert-refusal path is still proven only by regressions:
  no live `map_full` refusal was produced in the VM run.
- The exact final BPF object now has disposable-VM lab proof on Debian 13 /
  `6.12.107+deb13-amd64`: one pre-opened-fd LSM case, representative armed
  egress denials and one armed kill takedown case. This is not a full hook
  matrix, not a multi-kernel qualification and not a production claim.
- Historical M15/M16 evidence still applies to the old object and observe-only
  M16 config; it is retained with provenance and is not upgraded by the new run.
- The SENTINEL collector self-test is a local contract check. It is not live
  backend delivery and not an integration pass.
- The untracked `Warden/warden2.zip` was present during earlier FINAL-02
  integrity checks but is absent at the final recheck. Its disappearance is not
  attributed to any actor; it was not recreated from the public snapshot, and
  the user-work preservation gate is `PARTIAL`, not `PASS`.

## 3. Required before re-evaluation

1. Complete the remaining armed matrix cases against the exact final candidate:
   all BPF-LSM hooks with allowed/denied/event/unrelated/reload/disarm cases,
   direct UDP6 egress, full kill identity/PID-reuse/exclusion/other-flag cases,
   and forced E-09 insert refusal. Record 0/1/77 verbatim; never fold `SKIP`
   into pass.
2. Expand the kernel/distribution matrix with attach IDs, read-back arm state,
   map contents, positive and negative results, and cleanup verification. The
   single Debian 13 VM proof does not satisfy this item.
3. Define a soak with workload, duration and acceptance limits, then report
   CPU, memory, spool depth and ring behaviour.
4. Run an authorized live SENTINEL integration test with redacted evidence.
5. Enable and test a real private vulnerability reporting channel, create the
   public repository from the sanitized export, and confirm hosted CI is green
   including `cargo deny`.
6. Close or formally accept each item in `WARDEN_FINAL_KNOWN_LIMITATIONS.md`.

## 4. Public statement

> WARDEN is an experimental, observe-first eBPF Alpha with optional,
> off-by-default enforcement. Local source readiness is `PASS`, and
> representative armed VM proofs exist on one kernel, but production
> qualification is `NOT QUALIFIED`. The full enforcement matrix, multi-kernel
> compatibility, soak stability and real SENTINEL delivery remain unverified.


## OSR-FINAL-03 reconciliation — 2026-11-25

This section was added after FINAL-02. It does not alter the historical record
above. The user has explicitly confirmed that `Warden/warden2.zip` was
intentionally deleted by the user. Current status for present-day readiness:

```text
status      = ABSENT
cause       = USER_CONFIRMED_INTENTIONAL_DELETION
recovery    = NOT_REQUIRED
replacement = NOT_CREATED
```

The earlier FINAL-02 `UNKNOWN` classification is superseded for
WARDEN-OSR-FINAL-03 readiness purposes only. This mission did not restore,
reconstruct, search indefinitely for, or substitute the archive. The deletion
is not classified as accidental data loss.
