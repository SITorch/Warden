# WARDEN-PRQ-FINAL-02 — Final Kernel & Distribution Compatibility

status=`PARTIAL`. One disposable-VM kernel now has representative privileged
evidence for the exact FINAL-02 candidate; the full hook matrix and all other
kernels/distributions remain `UNKNOWN` / `NOT_RUN`. Prepared 2026-11-24.

## 1. Conservative support matrix

| Distribution | Kernel | BTF | Verifier | Hook coverage | Runtime validation | Status |
|---|---|---|---|---|---|---|
| Debian 13 (disposable VM, M15/M16 historical object) | `6.12.107+deb13-amd64` | present | `PASS` historical | 6 BPF-LSM attaches on M15; four cgroup egress programs in historical Phase 6 work | 60 s observe workload, `[::1]` v6 counters, historical; M16 config was observe-only | `LAB_VALIDATED` (historical object/config) |
| Debian 13 (exact FINAL-02 candidate in disposable VM) | `6.12.107+deb13-amd64` | present | `PASS` for loaded programs | `PARTIAL` — LSM `file_permission`/`inode_setattr`, four cgroup egress hooks, sensors; remaining LSM/vector cases `NOT_RUN` | Pre-opened-fd `-EPERM`, armed TCP4/UDP4/TCP6 egress `-EPERM` with non-match control, kill takedown `SIGKILL`; snapshot reverted and verified | `PARTIAL` (representative lab `PASS`, not full qualification) |
| Ubuntu dev host | `7.0.0-15-generic` | present | `NOT_RUN` (unprivileged) | capability presence only | read-only capability checks; no `bpf()` call | `UNKNOWN` |
| Other distributions / kernels | — | `UNKNOWN` | `UNKNOWN` | `UNKNOWN` | `NOT_RUN` | `UNTESTED` |

No universal Linux compatibility claim is made.

## 2. Actual observed environment facts

Development host (read-only):

- Ubuntu 26.04.1 LTS, Linux `7.0.0-15-generic`, x86_64, UID 1000.
- `/sys/kernel/btf/vmlinux` present; cgroup v2 controllers present;
  `lsm=lockdown,capability,landlock,yama,apparmor,bpf,ima,evm`; bpffs mounted.
- `bpftool prog list` / `map list` returned `Operation not permitted`:
  no unprivileged kernel state claim.

Disposable VM `debian13` (verified this mission):

- Debian 13, Linux `6.12.107+deb13-amd64`, 2 vCPU / 3.5 GiB.
- `/sys/kernel/btf/vmlinux` present; cgroup v2 controllers present;
  `lsm=lockdown,capability,landlock,yama,apparmor,bpf,ima,evm`; bpffs mounted.
- Full effective root capabilities under sudo (`cap_bpf`, `cap_perfmon`,
  `cap_sys_admin`, etc.); passwordless sudo available.
- Historical snapshot `m15_baseline` exists. A fresh FINAL-02 snapshot
  `prq_final2_baseline` was created after removing rebuildable VM copies, then
  reverted and verified while the VM remained `running`.
- Current source copied to the VM; shipped BPF object SHA-256 there =
  `2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`.
- The earlier `Input/output error` snapshot attempt at 97% guest disk use is
  historical and superseded; the fresh snapshot and post-revert kernel/BPF/
  binary/SSH checks are the recovery evidence for the armed runs.

## 3. Failure and degradation behaviour (documented, not newly executed)

- Missing BTF / verifier rejection / unsupported hook: startup reports the
  failed program and does not claim coverage; internal kprobes fail closed
  (E-08).
- Partial LSM attach leaves earlier links live and is reported DEGRADED
  (E-03); the guarded-inode map handle is retained only when LSM attached.
- cgroup attach failure: `EgressRuntime` reports hooks actually attached;
  disabled-by-default config never arms a primitive with no reader.
- `--doctor` reports hook *presence*, not attachment; `--health` reports
  `cannot see/…` for kernel state it cannot observe.

## 4. Compatibility claims allowed

Debian 13 / `6.12.107+deb13-amd64` may be called **lab-tested with
representative armed cases** for the exact FINAL-02 BPF object, with the tested
cases and the untested matrix stated explicitly. The historical M15/M16 object
and observe-only config remain separately labelled. Everything else is
`UNKNOWN` or `UNTESTED`. No distribution claim is based on a successful build.

## 5. Remaining action

Complete the untested cases in the same VM pattern: each remaining BPF-LSM
program individually, direct UDP6 egress, forced E-09 insert refusal, full kill
matrix, reload/disarm and post-arm reboot. Then repeat on additional kernels
with verifier/attach/map/ring results and revert/cleanup checks. Hosted CI adds
Ubuntu `ubuntu-latest` compile/test coverage only, not kernel attachment
evidence.
