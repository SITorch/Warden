#!/usr/bin/env bash
# Run the pinned Gitleaks CLI over an already verified explicit range and fail
# closed if the scanner reports zero commits for a non-empty expected range.
#
# Required environment:
#   GITLEAKS_BIN             executable path to the pinned binary
#   GITLEAKS_LOG_OPTS        exact --log-opts value from gitleaks_range.sh
#   GITLEAKS_EXPECTED_COMMITS  positive integer from gitleaks_range.sh
# Optional environment:
#   GITLEAKS_REPORT_PATH     SARIF output path (default results.sarif)
#   GITLEAKS_STDERR_LOG      sanitized diagnostic log path
set -euo pipefail

die() { printf 'gitleaks-scan: ERROR: %s\n' "$*" >&2; exit 1; }

bin="${GITLEAKS_BIN:-}"
log_opts="${GITLEAKS_LOG_OPTS:-}"
expected="${GITLEAKS_EXPECTED_COMMITS:-}"
report="${GITLEAKS_REPORT_PATH:-results.sarif}"
stderr_log="${GITLEAKS_STDERR_LOG:-gitleaks-scan.log}"
config="${GITLEAKS_CONFIG:-}"

[[ -x "$bin" ]] || die "GITLEAKS_BIN is not executable: ${bin:-<empty>}"
[[ -n "$log_opts" ]] || die "GITLEAKS_LOG_OPTS is empty"
[[ "$expected" =~ ^[0-9]+$ ]] || die "GITLEAKS_EXPECTED_COMMITS is not numeric: ${expected:-<empty>}"
((10#$expected > 0)) || die "GITLEAKS_EXPECTED_COMMITS must be greater than zero"

: > "$stderr_log" || die "cannot write GITLEAKS_STDERR_LOG: $stderr_log"
args=(detect --source . --redact --verbose --exit-code=2 --report-format=sarif --report-path="$report" --log-opts="$log_opts")
if [[ -n "$config" ]]; then
  args+=(--config "$config")
fi
rc=0
"$bin" "${args[@]}" 2>"$stderr_log" || rc=$?
cat "$stderr_log" >&2

scanned="$(
  sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$stderr_log" \
    | grep -oE '[0-9]+ commits scanned' \
    | tail -n 1 \
    | awk '{print $1}'
)"
[[ "$scanned" =~ ^[0-9]+$ ]] \
  || die "could not determine Gitleaks commits scanned from $stderr_log"
((10#$scanned > 0)) \
  || die "Gitleaks reported 0 commits scanned despite verified non-empty range (expected $expected)"

case "$rc" in
  0)
    printf 'gitleaks: no findings in verified range (%s commits scanned; expected %s)\n' \
      "$scanned" "$expected"
    ;;
  2)
    printf 'gitleaks: findings detected; see %s (%s commits scanned; expected %s)\n' \
      "$report" "$scanned" "$expected" >&2
    exit 1
    ;;
  *)
    die "gitleaks exited unexpectedly with code $rc"
    ;;
esac
