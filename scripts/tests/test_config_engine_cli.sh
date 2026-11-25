#!/usr/bin/env bash
# M16 regression: the config-engine CLI must validate, plan, migrate, baseline,
# drift-detect and refuse unsafe rollback without touching the kernel.
set -euo pipefail

BIN="${1:-$(cd "$(dirname "$0")/../.." && pwd)/target/debug/warden}"
[[ -x "$BIN" ]] || { echo "missing warden binary: $BIN" >&2; exit 1; }
WORK="$(mktemp -d /tmp/warden-m16-config-cli.XXXXXXXX)"
trap 'rm -rf "$WORK"' EXIT

"$BIN" --profile-list --config-json >"$WORK/profiles.json"
grep -q '"schema": "warden.profile-catalog.v1"' "$WORK/profiles.json"

for profile in essential balanced advanced hardened; do
  "$BIN" --profile "$profile" >"$WORK/$profile.toml"
  grep -q '^schema_version = 1' "$WORK/$profile.toml"
  grep -q '^mode = "observe"' "$WORK/$profile.toml"
  "$BIN" --config-validate --strict --config "$WORK/$profile.toml" >"$WORK/$profile.validate"
done

"$BIN" --config-plan --config "$WORK/balanced.toml" --config-json >"$WORK/plan.json"
grep -q 'SIMULATION ONLY' "$WORK/plan.json"

printf 'mode = "observe"\n' >"$WORK/legacy.toml"
"$BIN" --config-migrate --target-version 1 --config "$WORK/legacy.toml" >"$WORK/migrate.json"
grep -q '"from_version": 0' "$WORK/migrate.json"
grep -q '"changed": true' "$WORK/migrate.json"
"$BIN" --config-migrate --target-version 1 --config "$WORK/legacy.toml" >"$WORK/migrate-again.json"
grep -q '"changed": false' "$WORK/migrate-again.json"

"$BIN" --config-baseline "$WORK/baseline.json" --config "$WORK/legacy.toml" >"$WORK/baseline.log"
"$BIN" --config-drift "$WORK/baseline.json" --config-json >"$WORK/drift-same.json"
if grep -q '"status": "DRIFT"' "$WORK/drift-same.json"; then
  echo "FAIL: unchanged config reported drift" >&2; exit 1
fi
printf 'schema_version = 1\nmode = "enforce"\n' >"$WORK/legacy.toml"
"$BIN" --config-drift "$WORK/baseline.json" --config-json >"$WORK/drift-changed.json"
grep -q '"status": "DRIFT"' "$WORK/drift-changed.json"

printf 'schema_version = 1\nmode = "observe"\n' >"$WORK/target.toml"
printf 'schema_version = 1\nmode = "enforce"\n[respond]\nkill_reverse_shell = true\n' >"$WORK/unsafe.toml"
if "$BIN" --config-rollback --config "$WORK/target.toml" --from "$WORK/unsafe.toml" >"$WORK/rollback-refused" 2>&1; then
  echo "FAIL: unsafe rollback was accepted" >&2; exit 1
fi
grep -q 'refusing rollback' "$WORK/rollback-refused"

"$BIN" --self-test --config "$WORK/legacy.toml" >"$WORK/selftest.txt" 2>&1 || true
grep -q 'NOT_RUN: kernel_sensor_load' "$WORK/selftest.txt"
grep -q 'NOT_RUN: runtime_startup' "$WORK/selftest.txt"

echo "ok: config engine CLI regression passed"
