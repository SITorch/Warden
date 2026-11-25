# WARDEN-PRQ-FINAL-02 — Final Installer & Recovery Report

status=`PASS_WITH_LIMITATIONS` for packaged CLI/installer; `NOT_RUN` for a
clean-system installation of the FINAL-02 candidate. Prepared 2026-11-24.

## 1. Shipped mechanisms

One installation mechanism is preserved; no second config engine or installer
was introduced.

| Entry point | Behaviour | Default posture |
|---|---|---|
| `make install` | Installs release binary, sample policy (mode `0640`), two systemd units and docs; does not enable/start the service | observe-only, no bridge, no denial, no kill |
| `scripts/install_wizard.sh` | Preview-first, idempotent; supports profiles, prefixes, `--enable-service`, `--self-test`, `--uninstall`, `--test-mode` | no writes without confirmation; existing config preserved; no secret printed |
| `scripts/test-privileged.sh` | Explicit 0 PASS / 1 FAIL / 77 SKIP for the ignored LSM pre-opened-fd case; disposable VMs only | `SKIP` unless root + `CAP_BPF` + bpf LSM + object |

`--test-mode` refuses targets outside `/tmp`, a guard against accidental
writes. Uninstall requires typing `UNINSTALL`.

## 2. Operator CLI truth

`--check` does not claim attach; `--doctor` reports capability presence, not
attachment; `--health` is `/proc`-only with `cannot see/…` for kernel state;
`--self-test` uses `PASS`/`FAIL`/`UNKNOWN`/`NOT_RUN`/`NOT_APPLICABLE` and does
not load BPF, start services or contact SENTINEL; `--version` reports the
digest of the object compiled into that binary; `--config-plan` claims no
`bpf()` call; `--config-rollback` refuses backups that arm kill/denial.

## 3. Evidence reused from PRQ-01

- `scripts/tests/test_config_engine_cli.sh` exit 0.
- `scripts/tests/test_install_wizard.sh` exit 0.
- Both config validations exit 0 (`PASS_WITH_WARNINGS`).
- `--self-test --config config/warden.example.toml` exit 0;
  without `--config` on the operational sample exit 1 `configuration FAIL`
  — truthful failure, deliberately not hidden.
- Installed/public config modes verified `0640`.
- PRQ-01 clean-export suite: 718 passed / 0 failed / 2 ignored; FINAL-02 clean-export suite: 721 passed / 0 failed / 2 ignored.

## 4. This mission's additional observations

- The FINAL-02 source was copied to the disposable Debian 13 VM and the BPF
  object digest was confirmed identical there; the release binary was built
  successfully in the VM.
- A fresh recovery snapshot `prq_final2_baseline` was created after guest
  cleanup, reverted and verified (`running`, SSH, exact BPF SHA, binary
  present). The earlier `Input/output error` attempt is historical.
- Representative armed enforcement runs were then executed and the VM was
  restored to the snapshot. This is VM lab recovery evidence, not clean-host
  installation or service recovery qualification.
- Clean installation, upgrade, migration, rollback on a fresh host remain
  `NOT_RUN`.

## 5. Unexecuted qualification

| Item | Status |
|---|---|
| Clean installation on a fresh VM | `NOT_RUN` |
| Prerequisite detection / interrupted install / invalid permissions | `NOT_RUN` |
| Service enable/start, health, sensor status, log access | historical only |
| Upgrade, config migration, backup, rollback | `NOT_RUN` |
| Uninstall on a host (script tests only: `PARTIAL`) | `PARTIAL` |
| Service SIGHUP reload and deadman restart live | `NOT_RUN` (egress policy reload-to-ARMED was observed in the VM, not service recovery) |
| Disk-pressure / missing-BTF / unsupported-kernel failure paths | `NOT_RUN` |

## 6. Decision

The installer and operator CLI remain contributor- and operator-ready for a
public Alpha with explicit limitations: preview-first writes, safe defaults,
honest status vocabulary, and no invented success. Live installation and
recovery qualification of the final candidate remain open and are a production
blocker, not a publication blocker once the disclosure channel exists.
