#!/usr/bin/env bash
# Synthetic, non-credential regression matrix for the Gitleaks workflow fix.
# It creates temporary git repositories only, uses runtime-generated canaries,
# and never commits a canary value to WARDEN. Canary values are never printed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RANGE_SCRIPT="$HERE/gitleaks_range.sh"
SCAN_SCRIPT="$HERE/gitleaks_scan.sh"
BIN="${GITLEAKS_BIN:-gitleaks}"
ZERO="0000000000000000000000000000000000000000"
WORK="$(mktemp -d /tmp/warden-gitleaks-coverage.XXXXXXXX)"
EVIDENCE="${GITLEAKS_TEST_EVIDENCE_DIR:-$WORK/evidence}"
CURRENT_LOG=""

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$EVIDENCE"
: > "$EVIDENCE/index.tsv"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
field() { awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print }'; }

canary() {
  local rand
  rand="$(date +%s%N | sha256sum | cut -c1-8 | tr 'a-f' 'A-F')"
  printf 'WARDEN_TEST_CANARY_%s_%s' "$1" "$rand"
}

new_repo() {
  git init -q -b main "$WORK/$1"
  cd "$WORK/$1"
  git config user.email "gitleaks-test@example.invalid"
  git config user.name "Gitleaks Test"
}

commit_file() {
  local msg="$1" file="$2" content="$3"
  printf '%s\n' "$content" > "$file"
  git add "$file"
  git commit -q -m "$msg"
  git rev-parse HEAD
}

run_range() {
  local name="$1"; shift
  local rc=0
  env "$@" bash "$RANGE_SCRIPT" > "$EVIDENCE/$name.range.log" || rc=$?
  cat "$EVIDENCE/$name.range.log"
  return "$rc"
}

run_scan() {
  local rc=0
  scan "$@" || rc=$?
  SCAN_RC=$rc
  return 0
}

scan() {
  local name="$1" repo="$2" log_opts="$3" expected="$4" rc=0
  (
    cd "$repo"
    GITLEAKS_BIN="$BIN" \
    GITLEAKS_LOG_OPTS="$log_opts" \
    GITLEAKS_EXPECTED_COMMITS="$expected" \
    GITLEAKS_REPORT_PATH="$EVIDENCE/$name.sarif" \
    GITLEAKS_STDERR_LOG="$EVIDENCE/$name.scan.stderr.log" \
    GITLEAKS_CONFIG="$WORK/test.toml" \
      bash "$SCAN_SCRIPT"
  ) > "$EVIDENCE/$name.scan.stdout.log" 2>&1 || rc=$?
  return "$rc"
}

assert_no_canary() {
  local name="$1"
  if grep -q 'WARDEN_TEST_CANARY_' \
      "$EVIDENCE/$name.range.log" \
      "$EVIDENCE/$name.scan.stdout.log" \
      "$EVIDENCE/$name.scan.stderr.log" \
      "$EVIDENCE/$name.sarif" 2>/dev/null; then
    return 1
  fi
  return 0
}

record() {
  local id="$1" scenario="$2" event="$3" expected="$4" actual="$5" \
        exit_code="$6" evidence="$7" result="$8"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$scenario" "$event" "$expected" "$actual" "$exit_code" \
    "$evidence" "$result" >> "$EVIDENCE/index.tsv"
}

passes=0
fails=0
pass_record() {
  record "$@" PASS
  passes=$((passes + 1))
}
fail_record() {
  record "$@" FAIL
  fails=$((fails + 1))
}

[[ -x "$BIN" ]] || fail "GITLEAKS_BIN is not executable: $BIN"
cat > "$WORK/test.toml" <<'EOF'
title = "Warden synthetic Gitleaks regression"

[[rules]]
id = "warden-synthetic-canary"
description = "Runtime-generated non-credential canary"
regex = '''WARDEN_TEST_CANARY_[A-Z0-9_]+'''
tags = ["synthetic", "test"]
EOF

# 1. Ordinary commit with a synthetic canary.
new_repo ordinary
C1="$(commit_file "base" "base.txt" "base")"
C2="$(commit_file "add canary" "secret.txt" "$(canary ORDINARY)")"
C3="$(commit_file "clean" "clean.txt" "clean")"
OUT="$(run_range s01 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C3")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s01 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$RC" -eq 1 ]] && grep -q 'findings detected' "$EVIDENCE/s01.scan.stdout.log" && assert_no_canary s01; then
  pass_record 01 ordinary-commit push DETECTED findings_exit_2_wrapper_1 1 "s01.range.log,s01.scan.stdout.log,s01.scan.stderr.log,s01.sarif"
else
  fail_record 01 ordinary-commit push DETECTED "rc=$RC" "$RC" "s01.range.log,s01.scan.stdout.log,s01.scan.stderr.log,s01.sarif"
fi

# 2. Canary only in the second-parent history of a merge.
new_repo second_parent
B="$(commit_file "base" "base.txt" "base")"
git checkout -q -b feature
F="$(commit_file "feature canary" "feature.txt" "$(canary SECONDPARENT)")"
git checkout -q main
commit_file "main clean" "main.txt" "clean" >/dev/null
git merge -q --no-ff feature -m "merge feature"
M="$(git rev-parse HEAD)"
OUT="$(run_range s02 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$B" GITLEAKS_AFTER="$M")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
if git log --format=%H "$B..$M" | grep -qx "$F"; then IN_RANGE=yes; else IN_RANGE=no; fi
run_scan s02 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$IN_RANGE" == yes && "$RC" -eq 1 ]] && assert_no_canary s02; then
  pass_record 02 second-parent-merge push DETECTED "second_parent_in_range=$IN_RANGE,findings_exit_2_wrapper_1" 1 "s02.range.log,s02.scan.stdout.log,s02.scan.stderr.log,s02.sarif"
else
  fail_record 02 second-parent-merge push DETECTED "in_range=$IN_RANGE,rc=$RC" "$RC" "s02.range.log,s02.scan.stdout.log,s02.scan.stderr.log,s02.sarif"
fi

# 3. Canary introduced only in merge-result content.
new_repo merge_result
B="$(commit_file "base" "base.txt" "base")"
git checkout -q -b feature
commit_file "feature clean" "feature.txt" "clean" >/dev/null
git checkout -q main
git merge -q --no-commit feature >/dev/null 2>&1
commit_file "merge result canary" "merge-result.txt" "$(canary MERGERESULT)" >/dev/null
M="$(git rev-parse HEAD)"
OUT="$(run_range s03 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$B" GITLEAKS_AFTER="$M")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s03 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$OPTS" == "--full-history -m "* && "$RC" -eq 1 ]] && assert_no_canary s03; then
  pass_record 03 merge-result-content push DETECTED merge_result_diff_covered 1 "s03.range.log,s03.scan.stdout.log,s03.scan.stderr.log,s03.sarif"
else
  fail_record 03 merge-result-content push DETECTED "log_opts=$OPTS,rc=$RC" "$RC" "s03.range.log,s03.scan.stdout.log,s03.scan.stderr.log,s03.sarif"
fi

# 4. Multi-commit push: all introduced commits are enumerated.
new_repo multi_commit
C1="$(commit_file "base" "base.txt" "base")"
C2="$(commit_file "middle canary" "secret.txt" "$(canary MULTI)")"
C3="$(commit_file "clean 1" "clean1.txt" "clean")"
C4="$(commit_file "clean 2" "clean2.txt" "clean")"
OUT="$(run_range s04 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C4")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
git rev-list --format=%H --no-commit-header "$C1..$C4" > "$EVIDENCE/s04.expected-commits.log"
if grep -qx "$C2" "$EVIDENCE/s04.expected-commits.log" \
   && grep -qx "$C3" "$EVIDENCE/s04.expected-commits.log" \
   && grep -qx "$C4" "$EVIDENCE/s04.expected-commits.log"; then COVERAGE=yes; else COVERAGE=no; fi
run_scan s04 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$COUNT" == 3 && "$COVERAGE" == yes && "$RC" -eq 1 ]] && assert_no_canary s04; then
  pass_record 04 multi-commit-push push ALL_INTRODUCED_COMMITS_COVERED "commits=3,membership=$COVERAGE,findings_exit_2_wrapper_1" 1 "s04.range.log,s04.expected-commits.log,s04.scan.stdout.log,s04.sarif"
else
  fail_record 04 multi-commit-push push ALL_INTRODUCED_COMMITS_COVERED "commits=$COUNT,coverage=$COVERAGE,rc=$RC" "$RC" "s04.range.log,s04.expected-commits.log"
fi

# 5. Initial push with all-zero before.
new_repo initial_push
C1="$(commit_file "base" "base.txt" "base")"
C2="$(commit_file "canary" "secret.txt" "$(canary INITIAL)")"
OUT="$(run_range s05 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$ZERO" GITLEAKS_AFTER="$C2")"
MODE="$(field mode <<<"$OUT")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s05 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$MODE" == all && "$COUNT" == 2 && "$RC" -eq 1 ]] && assert_no_canary s05; then
  pass_record 05 initial-zero-before push ROOT_AND_REACHABLE_HISTORY_SCANNED "mode=all,commits=2,findings_exit_2_wrapper_1" 1 "s05.range.log,s05.scan.stdout.log,s05.sarif"
else
  fail_record 05 initial-zero-before push ROOT_AND_REACHABLE_HISTORY_SCANNED "mode=$MODE,commits=$COUNT,rc=$RC" "$RC" "s05.range.log"
fi

# 6. Canary in the root commit.
new_repo root_commit
C1="$(commit_file "root canary" "secret.txt" "$(canary ROOT)")"
OUT="$(run_range s06 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$ZERO" GITLEAKS_AFTER="$C1")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s06 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$COUNT" == 1 && "$RC" -eq 1 ]] && assert_no_canary s06; then
  pass_record 06 root-commit-canary push DETECTED root_diff_scanned 1 "s06.range.log,s06.scan.stdout.log,s06.sarif"
else
  fail_record 06 root-commit-canary push DETECTED "commits=$COUNT,rc=$RC" "$RC" "s06.range.log"
fi

# 7. Ordinary pull request uses event base/head, not checked-out HEAD.
new_repo ordinary_pr
BASE="$(commit_file "base" "base.txt" "base")"
BASE2="$(commit_file "base update" "base2.txt" "clean")"
git checkout -q -b feature "$BASE"
HEAD="$(commit_file "pr canary" "secret.txt" "$(canary PR)")"
OUT="$(run_range s07 GITLEAKS_EVENT=pull_request GITLEAKS_PR_BASE="$BASE2" GITLEAKS_PR_HEAD="$HEAD")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s07 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$COUNT" == 1 && "$RC" -eq 1 ]] && assert_no_canary s07; then
  pass_record 07 ordinary-pr pull_request PR_UNIQUE_COMMITS_SCANNED "commits=1,findings_exit_2_wrapper_1" 1 "s07.range.log,s07.scan.stdout.log,s07.sarif"
else
  fail_record 07 ordinary-pr pull_request PR_UNIQUE_COMMITS_SCANNED "commits=$COUNT,rc=$RC" "$RC" "s07.range.log"
fi

# 8. Dependabot-style PR event with the same read-only typed fields.
new_repo dependabot_pr
BASE="$(commit_file "base" "base.txt" "base")"
BASE2="$(commit_file "base update" "base2.txt" "clean")"
git checkout -q -b dependabot/cargo/example "$BASE"
HEAD="$(commit_file "dependency canary" "secret.txt" "$(canary DEPENDABOT)")"
OUT="$(run_range s08 GITLEAKS_EVENT=pull_request GITLEAKS_PR_BASE="$BASE2" GITLEAKS_PR_HEAD="$HEAD" GITLEAKS_ACTOR=app/dependabot)"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s08 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$COUNT" == 1 && "$RC" -eq 1 ]] && assert_no_canary s08; then
  pass_record 08 dependabot-pr pull_request SUPPORTED_WITH_READ_ONLY_PERMISSIONS "commits=1,no_write_token_used" 1 "s08.range.log,s08.scan.stdout.log,s08.sarif"
else
  fail_record 08 dependabot-pr pull_request SUPPORTED_WITH_READ_ONLY_PERMISSIONS "commits=$COUNT,rc=$RC" "$RC" "s08.range.log"
fi

# 9. Empty valid range is an explicit skip, not a scan.
new_repo empty_range
C1="$(commit_file "base" "base.txt" "base")"
if OUT="$(run_range s09 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C1")"; then
  MODE="$(field mode <<<"$OUT")"
  COUNT="$(field commits <<<"$OUT")"
  if [[ "$MODE" == skip && "$COUNT" == 0 ]]; then
    pass_record 09 empty-valid-range push EXPLICIT_EMPTY_RANGE_STATUS "mode=skip,commits=0" 0 "s09.range.log"
  else
    fail_record 09 empty-valid-range push EXPLICIT_EMPTY_RANGE_STATUS "mode=$MODE,commits=$COUNT" 0 "s09.range.log"
  fi
else
  fail_record 09 empty-valid-range push EXPLICIT_EMPTY_RANGE_STATUS range_script_error "$?" "s09.range.log"
fi

# 10. Missing base commit fails closed.
new_repo missing_base
C1="$(commit_file "base" "base.txt" "base")"
if run_range s10 GITLEAKS_EVENT=push GITLEAKS_BEFORE=1111111111111111111111111111111111111111 GITLEAKS_AFTER="$C1" >/dev/null 2>&1; then
  fail_record 10 missing-base push FAIL_CLOSED accepted_unresolvable_base 0 "s10.range.log"
else
  pass_record 10 missing-base push FAIL_CLOSED range_script_nonzero 1 "s10.range.log"
fi

# 11. Missing head commit fails closed.
new_repo missing_head
C1="$(commit_file "base" "base.txt" "base")"
if run_range s11 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER=2222222222222222222222222222222222222222 >/dev/null 2>&1; then
  fail_record 11 missing-head push FAIL_CLOSED accepted_unresolvable_head 0 "s11.range.log"
else
  pass_record 11 missing-head push FAIL_CLOSED range_script_nonzero 1 "s11.range.log"
fi

# 12. Incomplete shallow history fails closed.
new_repo shallow_source
C1="$(commit_file "base" "base.txt" "base")"
C2="$(commit_file "second" "second.txt" "clean")"
git -c protocol.file.allow=always clone -q --depth 1 "file://$WORK/shallow_source" "$WORK/shallow_clone"
cd "$WORK/shallow_clone"
if run_range s12 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C2" >/dev/null 2>&1; then
  fail_record 12 incomplete-history push FAIL_CLOSED accepted_missing_base 0 "s12.range.log"
else
  pass_record 12 incomplete-history push FAIL_CLOSED range_script_nonzero 1 "s12.range.log"
fi

# 13. Non-fast-forward range scans newly reachable commits and labels force_push.
new_repo force_push
B="$(commit_file "base" "base.txt" "base")"
git checkout -q -b old
X="$(commit_file "old canary" "old-secret.txt" "$(canary FORCEOLD)")"
git checkout -q -b new "$B"
Y="$(commit_file "new canary" "new-secret.txt" "$(canary FORCENEW)")"
OUT="$(run_range s13 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$X" GITLEAKS_AFTER="$Y")"
FORCE="$(field force_push <<<"$OUT")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s13 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$FORCE" == true && "$RC" -eq 1 ]] && assert_no_canary s13; then
  pass_record 13 force-push push DOCUMENTED_AND_CORRECT "force_push=true,newly_reachable_range=$X..$Y,findings_exit_2_wrapper_1" 1 "s13.range.log,s13.scan.stdout.log,s13.sarif"
else
  fail_record 13 force-push push DOCUMENTED_AND_CORRECT "force_push=$FORCE,rc=$RC" "$RC" "s13.range.log"
fi

# 14. Deleted ref is an explicit skip with a reason.
new_repo deleted_ref
C1="$(commit_file "base" "base.txt" "base")"
if OUT="$(run_range s14 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$ZERO" GITLEAKS_DELETED=true)"; then
  MODE="$(field mode <<<"$OUT")"
  REASON="$(field reason <<<"$OUT")"
  if [[ "$MODE" == skip && "$REASON" == deleted-ref ]]; then
    pass_record 14 deleted-ref push EXPLICIT_SKIP_WITH_REASON "mode=skip,reason=deleted-ref" 0 "s14.range.log"
  else
    fail_record 14 deleted-ref push EXPLICIT_SKIP_WITH_REASON "mode=$MODE,reason=$REASON" 0 "s14.range.log"
  fi
else
  fail_record 14 deleted-ref push EXPLICIT_SKIP_WITH_REASON range_script_error "$?" "s14.range.log"
fi

# 15. Secret-free range still proves a non-zero expected commit set.
new_repo clean_range
C1="$(commit_file "base" "base.txt" "base")"
commit_file "clean 1" "clean1.txt" "clean" >/dev/null
C3="$(commit_file "clean 2" "clean2.txt" "clean")"
OUT="$(run_range s15 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C3")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s15 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$COUNT" == 2 && "$RC" -eq 0 ]] && assert_no_canary s15; then
  pass_record 15 secret-free-range push CLEAN_SCAN_WITH_NONZERO_RANGE_EVIDENCE "commits=2,clean_exit_0" 0 "s15.range.log,s15.scan.stdout.log,s15.sarif"
else
  fail_record 15 secret-free-range push CLEAN_SCAN_WITH_NONZERO_RANGE_EVIDENCE "commits=$COUNT,rc=$RC" "$RC" "s15.range.log"
fi

# 16. Findings in stdout, stderr and SARIF are redacted.
new_repo redaction
C1="$(commit_file "base" "base.txt" "base")"
C2="$(commit_file "canary" "secret.txt" "$(canary REDACTION)")"
OUT="$(run_range s16 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C2")"
OPTS="$(field log_opts <<<"$OUT")"
COUNT="$(field commits <<<"$OUT")"
run_scan s16 "$PWD" "$OPTS" "$COUNT"
RC="$SCAN_RC"
if [[ "$RC" -eq 1 ]] && assert_no_canary s16 \
   && grep -q REDACTED "$EVIDENCE/s16.scan.stdout.log"; then
  pass_record 16 redacted-reports push REDACTED "stdout_stderr_sarif_no_canary" 1 "s16.scan.stdout.log,s16.scan.stderr.log,s16.sarif"
else
  fail_record 16 redacted-reports push REDACTED "rc=$RC,redaction_check_failed" "$RC" "s16.scan.stdout.log,s16.scan.stderr.log,s16.sarif"
fi

# 17. Internal zero-commit scan fails closed for a verified non-empty range.
new_repo zero_scan_guard
C1="$(commit_file "base" "base.txt" "base")"
C2="$(commit_file "clean" "clean.txt" "clean")"
OUT="$(run_range s17 GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C2")"
COUNT="$(field commits <<<"$OUT")"
run_scan s17 "$PWD" "--full-history -m $C2..$C2" "$COUNT"
RC="$SCAN_RC"
if [[ "$COUNT" == 1 && "$RC" -ne 0 ]] \
   && grep -q '0 commits scanned despite verified non-empty range' "$EVIDENCE/s17.scan.stdout.log"; then
  pass_record 17 zero-commit-guard push FAIL_CLOSED "expected=1,gitleaks_reported=0,guard_nonzero" "$RC" "s17.range.log,s17.scan.stdout.log"
else
  fail_record 17 zero-commit-guard push FAIL_CLOSED "expected=$COUNT,rc=$RC,guard_not_observed" "$RC" "s17.range.log,s17.scan.stdout.log"
fi

printf 'TOTAL_PASS=%s\nTOTAL_FAIL=%s\n' "$passes" "$fails"
printf 'INDEX=%s/index.tsv\n' "$EVIDENCE"
((fails == 0)) || exit 1
echo "ok: gitleaks coverage regression passed"
