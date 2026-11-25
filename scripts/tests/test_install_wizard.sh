#!/usr/bin/env bash
# M16 regression: guided installer preview is read-only; unattended install is
# idempotent, preserves operator config, and uninstall keeps policy.
set -euo pipefail

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/warden}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
[[ -x "$BIN" ]] || { echo "missing warden binary: $BIN" >&2; exit 1; }
WORK="$(mktemp -d /tmp/warden-m16-install-cli.XXXXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PREFIX="$WORK/prefix"
CONF_DIR="$WORK/etc/warden"
UNIT_DIR="$WORK/etc/systemd/system"
DOC_DIR="$WORK/share/doc/warden"
WIZARD="$REPO/scripts/install_wizard.sh"

# Preview with no --yes must not create anything.
printf 'NO\n' | "$WIZARD" --profile balanced --binary "$BIN" \
  --prefix "$PREFIX" --config-dir "$CONF_DIR" --unit-dir "$UNIT_DIR" --doc-dir "$DOC_DIR" \
  >"$WORK/preview.txt" 2>&1 || true
[[ ! -e "$PREFIX" && ! -e "$CONF_DIR" && ! -e "$UNIT_DIR" ]] || {
  echo "FAIL: preview wrote to disk" >&2; exit 1;
}

"$WIZARD" --unattended --test-mode --profile balanced --binary "$BIN" \
  --prefix "$PREFIX" --config-dir "$CONF_DIR" --unit-dir "$UNIT_DIR" --doc-dir "$DOC_DIR" \
  >"$WORK/install.txt"
[[ -x "$PREFIX/sbin/warden" ]] || { echo "FAIL: binary missing" >&2; exit 1; }
[[ -f "$CONF_DIR/warden.toml" ]] || { echo "FAIL: config missing" >&2; exit 1; }
[[ "$(stat -c '%a' "$CONF_DIR/warden.toml")" == 640 ]] || {
  echo "FAIL: config mode is not 0640" >&2; exit 1;
}
[[ -f "$UNIT_DIR/warden.service" ]] || { echo "FAIL: unit missing" >&2; exit 1; }

printf '\n# OPERATOR_MARKER\n' >>"$CONF_DIR/warden.toml"
"$WIZARD" --unattended --test-mode --profile hardened --binary "$BIN" \
  --prefix "$PREFIX" --config-dir "$CONF_DIR" --unit-dir "$UNIT_DIR" --doc-dir "$DOC_DIR" \
  >"$WORK/reinstall.txt"
grep -q 'kept existing' "$WORK/reinstall.txt"
grep -q 'OPERATOR_MARKER' "$CONF_DIR/warden.toml" || {
  echo "FAIL: reinstall overwrote operator config" >&2; exit 1;
}

"$WIZARD" --unattended --test-mode --uninstall \
  --prefix "$PREFIX" --config-dir "$CONF_DIR" --unit-dir "$UNIT_DIR" --doc-dir "$DOC_DIR" \
  >"$WORK/uninstall.txt"
[[ ! -e "$PREFIX/sbin/warden" ]] || { echo "FAIL: binary survived uninstall" >&2; exit 1; }
[[ ! -e "$UNIT_DIR/warden.service" ]] || { echo "FAIL: unit survived uninstall" >&2; exit 1; }
grep -q 'OPERATOR_MARKER' "$CONF_DIR/warden.toml" || {
  echo "FAIL: uninstall removed operator config" >&2; exit 1;
}

echo "ok: installer wizard regression passed"
