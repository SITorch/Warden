# WARDEN-PRQ-01 — Phase 5 Kernel / Distribution Compatibility Matrix

status=`PARTIAL` — one privileged kernel has historical evidence; all others are
`UNKNOWN` or `BLOCKED`. No new kernel test was run in PRQ.

## 1. Matrix

| Kernel / distribution | Evidence level | Load & attach | Detection | Enforcement | Status |
|---|---|---|---|---|---|
| Debian 13, `6.12.107+deb13-amd64` (disposable VM, M15/M16) | Raw privileged evidence: BTF preflight, verifier accept, 6 program attaches on M15; `[::1]` +4/+4 2800 B; 60 s workload. M16 used a schema-v1 **observe-only, no-egress** config and is evidence for volume accounting and the unchanged installed service — **not** armed egress | `PASS` (historical object) | `PASS` (historical object) | Armed kill `NOT_RUN`; BPF-LSM denial `NOT_RUN` in M16; cgroup armed `-EPERM` evidence comes from an earlier **Phase 6** isolated-VM run (13/13 executed, historical/environment-specific), not from M16 | `LAB_VALIDATED` (historical) |
| Host dev kernel `7.0.0-15-generic` (unprivileged) | Capability read only: `btf=VERIFIED`, `cgroup_v2=VERIFIED`, `bpffs=VERIFIED`, `bpf_lsm=VERIFIED`, `perf_gate=UNAVAILABLE`, `bpf_syscall=UNKNOWN`, six hook capabilities `VERIFIED` in `--config-validate` output | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `UNKNOWN` — readiness only |
| Any other kernel / distribution | None | `NOT_RUN` | `NOT_RUN` | `NOT_RUN` | `UNKNOWN` |

## 2. Important boundaries

- `bpf_lsm=VERIFIED` means `bpf` appears in `/sys/kernel/security/lsm`
  (`src/config_engine.rs:335-359`). It does **not** mean a program attached, a
  map was populated, or a syscall was denied.
- CO-RE/BTF compatibility is about compiled field relocations. It does **not**
  guarantee the internal kprobe symbols `__inet_stream_connect` and
  `inet_accept` exist or are attachable; those attach paths fail closed.
- The public Alpha object was rebuilt with `-fdebug-prefix-map`; program text
  and BTF type data are byte-identical to the M15/M16 object, so the historical
  kernel evidence is applicable in substance. This is a lineage statement, not
  a new test result.
- The 60 s measured workload is **not** a soak test.

## 3. Blockers to broader qualification

| Blocker | Status |
|---|---|
| Disposable VM provisioning for additional distributions/kernels | `BLOCKED` — no authorized test environment |
| Host with `bpf` in boot `lsm=` and `CAP_BPF` for LSM attach | `BLOCKED` |
| Permission to run privileged enforcement tests on any host | `BLOCKED` — never on active host |

## 4. Required future matrix expansion

For each additional target, run in a disposable VM with recovery:

1. `--config-validate --strict` capability output;
2. `bpftool btf dump` of host BTF and target-BTF preflight;
3. load/attach of all structural programs, recording per-hook successes;
4. bounded event generation and counter deltas;
5. separate privileged runs for LSM denial, cgroup egress denial, and kill
   responder, each with explicit PASS/FAIL/SKIP and rollback verification.

## 5. Decision

Kernel compatibility is `PARTIAL`. Production qualification across kernels is
`BLOCKED`; see `WARDEN_PRODUCTION_QUALIFICATION.md`.
