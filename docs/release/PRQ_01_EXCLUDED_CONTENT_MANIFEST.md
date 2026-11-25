# WARDEN-PRQ-01 — Phase 1 Excluded Content Manifest

status=`PASS` — exclusion verified against the public snapshot rescan.

This manifest records what the public export deliberately omits. It is an
allow-list complement: the snapshot is built by including only the files listed
here as *included*, and this document records the high-risk categories that are
never included.

## 1. Included categories (public)

| Path / category | Rationale |
|---|---|
| `Cargo.toml`, `Cargo.lock`, `LICENSE` | Build and license inputs; lockfile checksums required for reproducibility |
| `Makefile` | Build entry point (now with path-prefix stripping) |
| `README.md`, `DESIGN.md`, `SECURITY.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` | Sanitized public-facing docs |
| `.gitignore`, `.gitattributes`, `.github/**` | Contributor-ready repository infrastructure and unprivileged CI |
| `src/**`, `bpf/**`, `tests/**`, `systemd/**` | Canonical Rust/eBPF source, tests, and units (path fixtures sanitized) |
| `config/warden.example.toml` | Safe observe-only example, mode `0640`; the install default in the public export |
| `config/warden.toml` | Sanitized **compile-time test fixture only** — `src/config.rs` uses `include_str!` on it, so the public export cannot build without it. Mode `0640`, observe-only, no live credentials; install targets are export-rewritten to the example. |
| `scripts/install_wizard.sh`, `scripts/live_bridge_check.py`, `scripts/phase6_privileged_validation.sh`, `scripts/test-privileged.sh`, `scripts/tests/**` | Installer, validation helpers, honest privileged runner |
| `docs/security/warden_coverage_matrix.md`, `docs/security/warden_threat_model.md`, `docs/security/warden_phase7_egress_enforcement.md` | Conceptual security docs (reference targets rewritten at export) |
| `docs/release/**` | Sanitized PRQ reports and fallback SBOM |

## 2. Excluded categories (never public)

| Excluded path / category | Reason | Evidence |
|---|---|---|
| `target/` | Build artifacts; may embed local paths and absolute debug info | Rescan |
| `scratch/**` | Raw investigation outputs, possibly containing private data | Rescan |
| `evidence/m15/**`, `evidence/m16/**` | Raw privileged validation logs with host identities, IPs, PIDs, BTF IDs, cgroups | Rescan |
| `evidence/prq/**` (raw scans, fix evidence, gates) | Contains local host details and toolchain paths; sanitized summaries are in `docs/release/` instead | Rescan |
| `warden.zip` | Deleted tracked user file — preserved, not restored, not published | User-work preservation |
| `warden2.zip` | Stale untracked snapshot (29 src / 8 scripts / 3 systemd vs current 26 / 6 / 2) with raw evidence and unredacted docs; present at scan time, absent at FINAL-02 final recheck (cause `UNKNOWN`, not reconstructed) | Rescan |
| `docs/security/WARDEN_MISSION_15_FINAL_REPORT.md`, `WARDEN_MISSION_16_FINAL_REPORT.md`, `WARDEN_NEXT_GEN_FINAL_REPORT.md`, `WARDEN_MISSION_16_OPERATOR_GUIDE.md` | Mission reports containing build artifact hashes, BTF IDs, private deployment details | Rescan |
| `scripts/LIVE_VALIDATION.md` | Raw validation log with hostnames, accounts, IPs, PIDs, ports, cgroups | Rescan |
| Parent SENTINEL backend, frontend, and ML source trees (and their virtualenvs) | Different project; outside WARDEN's public scope | Rescan — no such files present |
| Local environment / credential files (`.env*`, `*.pem`, `*.key`, `credentials.json`) | Security; none found in the Warden source set | `PRQ_01_SECRET_SCAN_REPORT.md` |

## 3. Export-time transformations

The following are changed **only in the public snapshot**, not in the canonical
tree (so the parent-mirrored doc check stays green):

| Canonical text | Public text | Reason |
|---|---|---|
| `warden_phase6_live_validation.md` | `docs/release/PRQ_06_ENFORCEMENT_QUALIFICATION.md` | Target file is excluded raw evidence; replace with sanitized qualification report |
| `warden_kernel_compatibility_matrix.md` | `docs/release/PRQ_05_KERNEL_COMPATIBILITY_MATRIX.md` | Target file does not exist; replace with PRQ compatibility report |
| `scripts/LIVE_VALIDATION.md`, historical mission report paths, private-platform source paths | Corresponding sanitized PRQ reports / neutral descriptions | No private log or parent source in the public repo |
| `config/warden.toml` (in Makefile, wizard, and prose) | `config/warden.example.toml` | Public installs must use the safe example; the operational sample remains only as a test fixture |
| Private IP / home / private URL strings | `<internal-ip>` / `<home>` / `<redacted-private-url>` | Sanitization |

Because the parent SENTINEL repository keeps byte-identical mirrors of two
docs, the canonical WARDEN copies were deliberately left unchanged; the public
snapshot carries the corrected references. This divergence is intentional and
documented.

## 4. Verification performed

- 73 files in the initial snapshot; 0 PEM/key/cert files; 0 parent-SENTINEL
  source paths; all excluded paths confirmed absent (`PRQ_01_PUBLIC_SNAPSHOT_RESCAN.txt`).
- Final rescan after the test-fixture fix confirmed no known private deployment
  identifiers remain (the BPF object path issue was resolved afterward and is
  tracked in `PRQ_01_PUBLIC_SANITIZATION_REPORT.md` §3).
- A final rebuild and rescan is recorded in `PRQ_FINAL_EVIDENCE_INDEX.md`.

## 5. Status

| Check | Status |
|---|---|
| Inclusion allow-list applied | `PASS` |
| All excluded categories absent | `PASS` |
| No parent SENTINEL source leaked | `PASS` |
| No credential/key material present | `PASS` |
| Final post-rebuild rescan | `PASS` (see final evidence index) |


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
