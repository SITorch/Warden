# WARDEN — FINAL-02 Authoritative Known Limitations

This is the consolidated limitation record for the FINAL-02 candidate. It does
not reopen M16. New VM evidence promoted only the specific cases it exercised;
all other `NOT_RUN`, `BLOCKED` and `UNKNOWN` gates remain unchanged. All
statements here are permitted for public Alpha documentation; anything not
listed here must not be claimed.

## 1. Mandatory capability limits

| Limitation | Why it matters | Claim boundary |
|---|---|---|
| IPv6 volume accounting is socket-path based, not wire traffic | BPF hooks observe socket operations, not every packet on the wire | No IPv6 bandwidth/packet-capture equivalence claim |
| C2 cadence is not malice detection | Periodic reporting shows activity/risk indicators, not intent | No \"malware detected\" claim from cadence alone |
| Egress DENY is scoped to the attached cgroup | It is not a host firewall and does not cover all processes | No host-wide containment claim |
| Guarded files require explicit policy | Only paths in the configured guard set are protected | No whole-filesystem immutability claim |
| A temporary observer is not every installation | Coverage depends on runtime attachment and configuration | No coverage claim for unattached or unconfigured hosts |
| Local collector self-test is not real backend delivery | `SELFTEST PASS` proves only the local contract, not a live SENTINEL endpoint | No integration or delivery claim |

## 2. Current-candidate proof gaps

| Item | Status | Boundary |
|---|---|---|
| Full six-hook BPF-LSM armed matrix | `PARTIAL` | One pre-opened-fd case passed in the disposable VM (`read`/`write`/`ftruncate`/`fchmod` → `-EPERM`, two programs attached). Other hooks, allowed-action, event, unrelated-denial, reload and disarm cases remain `NOT_RUN` |
| Full cgroup egress test matrix | `PARTIAL` | All four hooks attached and ARMED read-back; armed TCP4/UDP4/TCP6 denial and non-match allow passed. Direct UDP6 datagram traffic, exhaustive reload/disarm and scope cases remain `NOT_RUN`; two harness classifications are recorded artifacts, not passes |
| Armed kill responder matrix | `PARTIAL` | One throwaway takedown case passed with `pidfd_send_signal` and `action=killed`. PID reuse, exclusions, other `kill_*` flags, repeated events and disarm remain `NOT_RUN` |
| Default safety after an armed reload/reboot or disarm | `NOT_RUN` | Egress SIGHUP reload to `ARMED` was observed in the VM; static/config validation covers defaults. Post-arm reboot and disarm were not exercised |
| Fresh disposable-VM snapshot | `PASS` | Earlier `Input/output error` (guest disk 97%) was resolved by removing rebuildable VM copies; fresh `prq_final2_baseline` was created, reverted and verified with exact BPF SHA, binary and SSH reachability |
| E-09 live insert-refusal telemetry | `NOT_RUN` | Three regressions pass; no VM run forced an insert refusal, so `map_full` remains code-proven only |
| Additional kernels/distributions | `UNKNOWN` | Only historical Debian 13 / `6.12.107+deb13-amd64` is lab-validated for the old object |
| Long-duration soak | `UNKNOWN` | No 24-hour or 48–72-hour test; bounded 60 s historical workload only |
| Real SENTINEL integration | `BLOCKED` / `NOT_RUN` | No authorized endpoint, tenant, credential, CA, egress permission or test-data permission; none invented |
| Clean-host install/service/reload/deadman | `NOT_RUN` | Installer CLI tests and historical reports only |
| Hosted CI | `NOT_RUN` | Local replay only; no authorized staging repository/runner |
| `cargo deny` policy gate | `NOT_RUN` | Tool unavailable locally |
| Private vulnerability reporting channel | `BLOCKED` | External maintainer action |

## 3. Documented hardening items still open

| ID | Severity | Summary |
|---|---|---|
| R-06 | High, conditional | `Config::load()` does not enforce the validator's mode/symlink checks |
| R-07 | Medium | Spool open and permission repair can follow symlinks |
| R-08 | Medium | Predictable `<spool>.tmp` without `O_EXCL` |
| R-09 | Medium, conditional | `kill(2)` fallback TOCTOU when pidfd is unavailable |
| R-10 | Medium | Raw control characters can reach bridge request headers |
| R-11 | Medium, bounded | Inode-key guard lags atomic file replacement until refresh |
| R-12 | Low | DNS resolution has no deadline |
| R-13 | Low | `RLIMIT_MEMLOCK` failure only debug-logged |
| R-14 | Low | Ring-loss ratio is not reset after a clean/unreadable tick |
| R-15 | Low | Ring-drop counter measures reserve failures only, not end-to-end loss |
| E-02 / E-03 | Documented | Remaining eBPF risk-register items, including partial LSM attach behavior |
| E-04 / E-05 / E-06 / E-07 / E-08 | Documented | Return-convention prose inversion in docs, UDP per-operation accounting, IPv6 socket-path accounting, reserve-only drop counter, internal kprobe limits |
| E-09 | Fixed in code, live insert refusal `NOT_RUN` | `WARDEN_EGRESS_MAP_FULL` was never written; now counted once per refused insert with three regressions. The VM run exercised armed egress denial but did not force a refused insert, so no live `map_full` observation exists |

## 4. Explicit non-claims

WARDEN does **not** claim:

- production qualification or certification of any kind;
- production-grade, multi-kernel or full-matrix verified live denial; only
  representative lab cases on one Debian 13 kernel are proven;
- host-wide firewall or filesystem lockdown;
- real SENTINEL delivery or backend acceptance;
- zero vulnerabilities, zero event loss, or a defined performance envelope;
- protection against an unrestricted local root attacker;
- that `SKIP`, `NOT_RUN` or `UNKNOWN` is a pass;
- that a fresh private repository, reporting channel or CI run already exists.

## 5. Review rule

Whenever a gate above changes, update `WARDEN_FINAL_PRODUCTION_QUALIFICATION.md`,
`WARDEN_FINAL_RELEASE_DECISION.md`, `PRQ_FINAL_EVIDENCE_INDEX.md` and the public
release readiness record in the same change. A single document must not move a
status without its evidence.
