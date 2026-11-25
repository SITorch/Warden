#!/usr/bin/env bash
# WARDEN MISSION 16 — guided, idempotent installation and maintenance CLI.
#
# This extends (does not replace) the existing `make install` path: it uses the
# same binary, sample config and systemd units, writes no new policy format, and
# never enables or starts a service unless explicitly asked to do so.
#
# Safe defaults:
#   * without --yes/--unattended it is a PREVIEW and writes nothing;
#   * an existing config is preserved; a new sample is installed beside it;
#   * system directories are only touched when the operator explicitly confirms;
#   * uninstall removes only WARDEN's known files and keeps operator policy;
#   * no secret value is printed.
set -euo pipefail

PROFILE=""
PREFIX="/usr/local"
CONFIG_DIR="/etc/warden"
UNIT_DIR="/etc/systemd/system"
DOC_DIR=""
BINARY=""
CONFIG_SOURCE=""
UNIT_SOURCE=""
DOCTOR_SOURCE=""
YES=0
UNATTENDED=0
REPLACE_CONFIG=0
ENABLE_SERVICE=0
UNINSTALL=0
SELF_TEST=0
TEST_MODE=0

log() { printf 'warden-install: %s\n' "$*"; }
fail() { printf 'warden-install: ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Usage:
  install_wizard.sh --profile essential|balanced|advanced|hardened|custom
                    [--binary PATH] [--config-source PATH]
                    [--prefix DIR] [--config-dir DIR] [--unit-dir DIR] [--doc-dir DIR]
                    [--yes] [--unattended] [--replace-config] [--enable-service]
                    [--self-test] [--test-mode]
  install_wizard.sh --uninstall [--prefix DIR] [--config-dir DIR] [--unit-dir DIR]
                    [--doc-dir DIR] [--yes] [--unattended]

Default is a read-only preview. --unattended implies --yes and requires --profile.
--replace-config overwrites an existing config only after a verified backup.
--enable-service is the only option that calls systemctl; it is never implied.
--test-mode permits unprivileged installation into /tmp-only targets for CI; it cannot enable services.
EOF
}

while (($#)); do
  case "$1" in
    --profile) PROFILE="${2:-}" ; shift 2 ;;
    --prefix) PREFIX="${2:-}" ; shift 2 ;;
    --config-dir) CONFIG_DIR="${2:-}" ; shift 2 ;;
    --unit-dir) UNIT_DIR="${2:-}" ; shift 2 ;;
    --doc-dir) DOC_DIR="${2:-}" ; shift 2 ;;
    --binary) BINARY="${2:-}" ; shift 2 ;;
    --config-source) CONFIG_SOURCE="${2:-}" ; shift 2 ;;
    --unit-source) UNIT_SOURCE="${2:-}" ; shift 2 ;;
    --yes) YES=1 ; shift ;;
    --unattended) UNATTENDED=1; YES=1; shift ;;
    --replace-config) REPLACE_CONFIG=1 ; shift ;;
    --enable-service) ENABLE_SERVICE=1 ; shift ;;
    --self-test) SELF_TEST=1 ; shift ;;
    --test-mode) TEST_MODE=1 ; shift ;;
    --uninstall) UNINSTALL=1 ; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if ((UNATTENDED)) && [[ -z "$PROFILE" ]] && ((UNINSTALL == 0)); then
  fail "--unattended requires an explicit --profile"
fi
UID_NOW_EARLY="$(id -u)"
if [[ -z "$DOC_DIR" ]]; then DOC_DIR="$PREFIX/share/doc/warden"; fi
if [[ "$PREFIX" == "/" || "$CONFIG_DIR" == "/" || "$UNIT_DIR" == "/" ]]; then
  fail "refusing '/' as an installation root"
fi
for p in "$PREFIX" "$CONFIG_DIR" "$UNIT_DIR" "$DOC_DIR"; do
  [[ "$p" == *".."* ]] && fail "refusing a path containing '..': $p"
done
if ((ENABLE_SERVICE && UNINSTALL)); then fail "--enable-service is invalid with --uninstall"; fi

# Uninstall is handled before binary/config generation: it needs no profile,
# never validates a new policy, and must work even if the binary is gone.
if ((UNINSTALL)); then
  SBINDIR_EARLY="$PREFIX/sbin"
  TARGET_BIN_EARLY="$SBINDIR_EARLY/warden"
  TARGET_UNIT_EARLY="$UNIT_DIR/warden.service"
  TARGET_DOC_EARLY="$DOC_DIR/README.md"
  if ((UID_NOW_EARLY != 0)) && ((YES == 0)) && ((TEST_MODE == 0)); then
    log "preview only: uninstall requires root or --yes; nothing removed"
    exit 0
  fi
  if ((YES == 0)); then
    read -r -p "Type UNINSTALL to remove only $TARGET_BIN_EARLY, $TARGET_UNIT_EARLY and $TARGET_DOC_EARLY: " ANSWER
    [[ "$ANSWER" == "UNINSTALL" ]] || fail "authorization not given; nothing removed"
  fi
  rm -f "$TARGET_BIN_EARLY" "$TARGET_UNIT_EARLY" "$TARGET_DOC_EARLY"
  rmdir "$DOC_DIR" 2>/dev/null || true
  log "uninstall: removed WARDEN binary, unit and docs; policy under $CONFIG_DIR was kept"
  log "uninstall: run 'systemctl daemon-reload' if the removed unit was registered"
  exit 0
fi

if ((TEST_MODE)); then
  for p in "$PREFIX" "$CONFIG_DIR" "$UNIT_DIR" "$DOC_DIR"; do
    [[ "$p" == /tmp/* ]] || fail "--test-mode targets must all be under /tmp: $p"
  done
  if ((ENABLE_SERVICE)); then fail "--test-mode cannot enable or start services"; fi
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ -z "$BINARY" ]]; then
  if [[ -x "$REPO_DIR/target/release/warden" ]]; then
    BINARY="$REPO_DIR/target/release/warden"
  elif [[ -x "$REPO_DIR/target/debug/warden" ]]; then
    BINARY="$REPO_DIR/target/debug/warden"
  else
    fail "no warden binary found; build first with 'make' and rerun"
  fi
fi
if [[ -z "$CONFIG_SOURCE" ]]; then CONFIG_SOURCE="$REPO_DIR/config/warden.toml"; fi
if [[ -z "$UNIT_SOURCE" ]]; then UNIT_SOURCE="$REPO_DIR/systemd/warden.service"; fi
[[ -x "$BINARY" ]] || fail "binary is not executable: $BINARY"
[[ -r "$CONFIG_SOURCE" ]] || fail "config source is not readable: $CONFIG_SOURCE"
[[ -r "$UNIT_SOURCE" ]] || fail "unit source is not readable: $UNIT_SOURCE"

SBINDIR="$PREFIX/sbin"
TARGET_BIN="$SBINDIR/warden"
TARGET_CONF="$CONFIG_DIR/warden.toml"
TARGET_SAMPLE="$CONFIG_DIR/warden.toml.sample"
TARGET_UNIT="$UNIT_DIR/warden.service"
TARGET_DOC="$DOC_DIR/README.md"

# ── 1-10: environment assessment (read-only) ───────────────────────────────
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo unknown)"
ARCH="$(uname -m)"
KERNEL="$(uname -r)"
CGROUP="UNAVAILABLE"
[[ -r /sys/fs/cgroup/cgroup.controllers ]] && CGROUP="VERIFIED"
BTF="UNAVAILABLE"
[[ -r /sys/kernel/btf/vmlinux ]] && BTF="VERIFIED"
LSM="$(cat /sys/kernel/security/lsm 2>/dev/null | tr ',' ' ' || true)"
BPF_LSM="UNKNOWN"
[[ " $LSM " == *" bpf "* ]] && BPF_LSM="VERIFIED"
UID_NOW="$(id -u)"
MEM_KB="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
CPU_COUNT="$(nproc 2>/dev/null || echo unknown)"
PERF_PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)"

log "assessment: os=$OS_NAME arch=$ARCH kernel=$KERNEL"
log "assessment: BTF=$BTF cgroup_v2=$CGROUP bpf_lsm=$BPF_LSM perf_event_paranoid=$PERF_PARANOID"
log "assessment: cpus=$CPU_COUNT mem_available_kib=$MEM_KB euid=$UID_NOW"
if [[ -n "$PROFILE" && "$PROFILE" != custom ]]; then
  RECOMMENDED="$PROFILE"
else
  RECOMMENDED="balanced"
  [[ "$BTF" != "VERIFIED" ]] && RECOMMENDED="essential"
fi
log "profile: selected=${PROFILE:-$RECOMMENDED} (recommended=$RECOMMENDED)"
if [[ "$BPF_LSM" != "VERIFIED" ]]; then
  log "capability note: bpf LSM not verified; guarded-file denial will not be armed by any profile"
fi
if [[ "$CGROUP" != "VERIFIED" ]]; then
  log "capability note: cgroup v2 not verified; volume counters and egress enforcement stay off"
fi
if ((UID_NOW != 0)) && ((YES)) && ((TEST_MODE == 0)); then
  fail "installation requires root (euid=$UID_NOW); preview is available without root, or use --test-mode with /tmp-only targets"
fi

WORK_DIR="$(mktemp -d /tmp/warden-install.XXXXXXXX)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT
GENERATED="$WORK_DIR/warden.generated.toml"
if [[ -n "$PROFILE" && "$PROFILE" != custom ]]; then
  "$BINARY" --profile "$PROFILE" >"$GENERATED" \
    || fail "profile generation failed for $PROFILE"
else
  cp "$CONFIG_SOURCE" "$GENERATED"
fi
"$BINARY" --config-validate --strict --config "$GENERATED" >"$WORK_DIR/validate.txt" 2>&1 \
  || { cat "$WORK_DIR/validate.txt" >&2; fail "intended configuration did not validate"; }
log "validation: intended configuration PASS (see generated profile notes above)"
log "preview: binary $BINARY -> $TARGET_BIN (0755)"
log "preview: config $GENERATED -> $TARGET_CONF (0640; existing config is preserved)"
log "preview: sample -> $TARGET_SAMPLE (0644)"
log "preview: unit $UNIT_SOURCE -> $TARGET_UNIT (0644)"
log "preview: docs -> $TARGET_DOC (0644)"
log "preview: service enable/start = $([[ $ENABLE_SERVICE -eq 1 ]] && echo requested || echo no)"
log "preview: uninstall removes only $TARGET_BIN, $TARGET_UNIT and installed docs; keeps $TARGET_CONF"

if ((YES == 0)); then
  read -r -p "Type INSTALL to apply this preview: " ANSWER
  [[ "$ANSWER" == "INSTALL" ]] || fail "authorization not given; nothing changed"
fi

mkdir -p "$SBINDIR" "$CONFIG_DIR" "$UNIT_DIR" "$DOC_DIR"
install -m 0755 "$BINARY" "$TARGET_BIN"
install -m 0644 "$UNIT_SOURCE" "$TARGET_UNIT"
install -m 0644 "$REPO_DIR/README.md" "$TARGET_DOC"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -f "$TARGET_CONF" ]] && ((REPLACE_CONFIG == 0)); then
  install -m 0644 "$GENERATED" "$TARGET_SAMPLE"
  log "config: kept existing $TARGET_CONF and refreshed $TARGET_SAMPLE"
elif [[ -f "$TARGET_CONF" ]] && ((REPLACE_CONFIG == 1)); then
  cp -p "$TARGET_CONF" "$TARGET_CONF.before-wizard.$STAMP"
  install -m 0640 "$GENERATED" "$TARGET_CONF"
  log "config: backed up previous file to $TARGET_CONF.before-wizard.$STAMP and installed generated policy"
else
  install -m 0640 "$GENERATED" "$TARGET_CONF"
  log "config: installed generated policy at $TARGET_CONF (0640)"
fi

if ((ENABLE_SERVICE)); then
  command -v systemctl >/dev/null 2>&1 || fail "--enable-service requested but systemctl is unavailable"
  systemctl daemon-reload
  systemctl enable --now warden.service
  log "service: systemctl enable --now warden.service completed"
else
  log "service: not touched; next steps: systemctl daemon-reload && systemctl enable --now warden"
fi

if ((SELF_TEST)); then
  "$TARGET_BIN" --self-test --config "$TARGET_CONF" >"$WORK_DIR/selftest.txt" 2>&1 || true
  log "self-test results:"
  sed 's/^/  /' "$WORK_DIR/selftest.txt"
  if grep -q '^warden: FAIL:' "$WORK_DIR/selftest.txt"; then
    fail "installation self-test reported FAIL; review the output above"
  fi
  log "self-test: no FAIL status (NOT_RUN items remain external validation requirements)"
fi

log "final report: os=$OS_NAME kernel=$KERNEL profile=${PROFILE:-$RECOMMENDED} mode=$(grep -m1 '^mode' "$TARGET_CONF" | tr -d '\r')"
log "final report: installed binary=$TARGET_BIN config=$TARGET_CONF unit=$TARGET_UNIT"
log "final report: validate with '$TARGET_BIN --check --strict --config $TARGET_CONF'; observe with '$TARGET_BIN --health'"
