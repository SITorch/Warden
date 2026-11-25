# WARDEN-PRQ-FINAL-02 — Final Secret, History and Public-Disclosure Audit

status=`PASS` for the frozen public export: no confirmed unresolved secret
exposure. Prepared 2026-11-24. Raw evidence is private and excluded from the
export: `Warden/evidence/prq/final/secret_scan_evidence/`.

## 1. Tool acquisition and integrity

PRQ-01 could not run dedicated scanners. This mission closed that gap for one
reliable scanner without modifying the active host permanently:

| Item | Value |
|---|---|
| Scanner | gitleaks `8.30.1` (official GitHub release, tag `v8.30.1`, published 2026-03-21) |
| Source | `https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/...` (official release only; no mirror) |
| Asset | `gitleaks_8.30.1_linux_x64.tar.gz` |
| Official SHA-256 | `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` |
| Computed SHA-256 | identical; `sha256sum -c` → `OK` |
| Install location | `/tmp/opencode/prq/tools/gitleaks` (volatile; no system-wide install) |
| Version check | `gitleaks version` → `8.30.1` |
| Other scanners | TruffleHog, GitHub secret scanning: not available; not installed. This remains a tool-coverage limitation, not a pass. |

Evidence: `gitleaks_8.30.1_checksums.txt` (official checksum file).

## 2. Scan commands and scope

All commands used `--redact` so no matched value was printed. JSON reports
contain zero findings, therefore no values.

| Command | Scope | Exit | Result |
|---|---|---:|---|
| `gitleaks detect --no-git --redact --source . --report-format json --report-path gitleaks_public_export.json --exit-code 0` | all 112 frozen candidate files, including hidden files | 0 | `no leaks found`; `findings=0`; full final export scanned |
| `gitleaks detect --no-git --redact --source . ...` on canonical private `Warden/` | canonical private `Warden/` tree including excluded raw evidence, ZIPs and scratch | 0 | `no leaks found`; `findings=0` |
| `fallback_scan.py` | 112 candidate files (BPF object excluded from text scan) | 0 | 52 pattern matches; 45 synthetic fixtures, 7 reviewed false positives (§3) |
| BPF object string scan | `bpf/warden.bpf.o` | 0 | 0 matches for `/home/`, `/opt/vault`, private hostnames, private IPs, key blocks, `password=`, `api_key=` |
| ELF / metadata check | BPF object and all 112 files | 0 | relocatable eBPF ELF with debug info; only absolute string fragment `/usr/include/bpf`; 0 files with extended attributes; 0 symlinks |
| Forbidden-file check | all 112 files | 0 | no `*.pem`, `*.key`, `*.crt`, `.env*`, ZIP, archive, or raw `LIVE_VALIDATION.md` |

Evidence: `gitleaks_public_export.{json,stdout}`,
`gitleaks_canonical_tree.{json,stdout}`, `fallback_scan_redacted.txt`,
`fallback_scan.json`, `bpf_and_metadata_scan.txt`.

## 3. Fallback pattern findings and classification

The fallback scanner emits file/line/type only — never matched values.
Counts: `private_ip=36`, `credential_assignment=6`, `home_path=8`, `email=2`;
45 were classified as synthetic test fixtures and 7 were reviewed individually.
All 52 are **false positives** for public disclosure:

| Type / location | Severity | False-positive determination | Resolution / verification |
|---|---|---|---|
| `private_ip` ×36 total (33 synthetic in `src/**`, `bpf/warden.bpf.c`) (e.g. RFC1918/CGNAT literals in `src/config.rs`, `src/bridge.rs`, `src/detect.rs`, `src/events.rs`, `src/explain.rs`, `src/net_snap.rs`, `bpf/warden.bpf.c`) | Low | Synthetic literals required by unit tests that classify `UplinkTarget::Private` and private-network handling; not real infrastructure addresses. Canonical source uses the same literals; PRQ-01 deliberately retained them because generic redaction breaks tests. | Tests pass in the clean export (721 passed / 0 failed). Verified by source inspection and `gitleaks` zero-finding result. |
| `home_path` ×8 in `src/detect.rs`, `src/procscan.rs` | Low | Synthetic filesystem fixtures in unit tests (guard-path and mount-attribution cases). | Retained; tests pass. |
| `credential_assignment` ×4 in `src/health.rs`, `src/heartbeat.rs` | Low | Synthetic test inputs for redaction/header construction; values are test literals such as a shared-secret string used to assert that secrets are not logged. | Retained; tests pass. A dedicated test verifies health redaction. |
| `private_ip` ×3 in `README.md`, `config/warden.toml`, `PRQ_FINAL_SECRET_AND_HISTORY_AUDIT.md` | Low | `100.64.0.0/10` is a documentation CIDR explaining CGNAT handling, not a host address. | Retained. |
| `credential_assignment` ×2 in `config/warden.toml:900,1007` | Low | Commented example placeholders for operator-supplied bridge/heartbeat keys; no live value. | Retained; config validates `PASS_WITH_WARNINGS`. |
| `email` ×2 in `src/detect.rs:6451,6521` | Low | Systemd unit filenames containing `@` matched the email heuristic; not email addresses. | Retained. |

No real credential, private key, HMAC secret, token, personal data, cloud
credential or private infrastructure identifier was found in the public export.
No value is reproduced in this report or in the evidence files.

## 4. History verification

| Check | Result |
|---|---|
| `.git` directory in public export | absent (`git_dirs=0`) |
| `.git*` files other than `.gitignore` / `.gitattributes` | absent |
| Public release strategy | sanitized independent source snapshot; no inherited parent commits |
| Canonical private history | not rewritten, not exported, not pushed |
| PRQ-01 path-only history scan | 47 WARDEN-touching commits reviewed by path; 270 path hits with literal assignment patterns, including excluded `scratch/**`, `evidence/**` and raw runbook paths |
| Historical credential assessment | Pattern hits are in **private** history that is deliberately not part of the public snapshot. Gitleaks found no leaks in the current canonical tree either. No credential was printed, revoked or independently rotated. Rotation remains a maintainer decision if any historical value was ever real. |

The public candidate therefore has **no Git history to leak**. This is the
central reason the release strategy uses a fresh export rather than a filtered
clone or a push of the private branch.

## 5. Post-remediation verification

No remediation was required for a real secret. The only export-only change
after the first scan was sanitizing bare parent-project area names from new
FINAL-02 docs. After all scans, the candidate was re-inventoried against the
frozen manifest: 112 files, exact byte count in the manifest, BPF SHA-256
`2461fbcded10b6caacef31d587df007e3ed935740327c47196a50fd7eaae5b3a`.

## 6. Limitations

- Only one dedicated scanner (gitleaks) was available; TruffleHog and hosted
  secret scanning were not run. `PARTIAL` tool coverage is recorded even though
  the gate itself passes on the evidence obtained.
- The fallback classifier uses path/context rules; a novel credential format
  could evade both scanners. This is a residual risk, not a claimed zero risk.
- The BPF object retains DWARF debug info with relative source paths. It was
  rebuilt with `-fdebug-prefix-map` in PRQ-01; no absolute developer path or
  private string was found. Debug info increases artifact size.
- No formal legal or credential-rotation determination was made.

## 7. Gate

| Requirement | Status |
|---|---|
| Reliable secret scan of complete public export | `PASS` |
| Relevant release history examined | `PASS` (no history in public candidate) |
| No confirmed unresolved real credential | `PASS` |
| No private key material | `PASS` |
| No private infrastructure details | `PASS` |
| No unintended parent-project source | `PASS` |
| No raw machine evidence or archives | `PASS` |
| Tool coverage | `PARTIAL` (one dedicated scanner) |
