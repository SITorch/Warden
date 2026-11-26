#!/usr/bin/env bash
# Focused local regression for gitleaks_range.sh using synthetic git history.
# The marker below is a harmless runtime-generated string, never a credential
# and never committed to this repository. No Gitleaks binary is required.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
RANGE_SCRIPT="$HERE/gitleaks_range.sh"
WORK="$(mktemp -d /tmp/warden-gitleaks-range.XXXXXXXX)"
trap 'rm -rf "$WORK"' EXIT
ZERO="0000000000000000000000000000000000000000"
MARKER="RANGE_MARKER_$(date +%s)_$$"

fail() { echo "FAIL: $*" >&2; exit 1; }
field() { awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); print }'; }
run_range() { env "$@" bash "$RANGE_SCRIPT"; }

git init -q -b main "$WORK/repo"
cd "$WORK/repo"
git config user.email "range-test@example.invalid"
git config user.name "Range Test"

commit_marker() {
  printf '%s\n' "$MARKER" >> markers.txt
  git add markers.txt
  git commit -q -m "$1"
  git rev-parse HEAD
}

C1="$(commit_marker "base commit")"
C2="$(commit_marker "second base commit")"

# Push: explicit before..after from event fields.
OUT="$(run_range GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C1" GITLEAKS_AFTER="$C2")"
[[ "$(field mode <<<"$OUT")" == "range" ]] || fail "push mode: $OUT"
[[ "$(field range <<<"$OUT")" == "$C1..$C2" ]] || fail "push range: $OUT"
[[ "$(field commits <<<"$OUT")" == "1" ]] || fail "push commit count: $OUT"
[[ "$(field log_opts <<<"$OUT")" == "--full-history -m $C1..$C2" ]] \
  || fail "push log opts must include all parents: $OUT"

# Push with all-zero before: whole reachable history of after.
OUT="$(run_range GITLEAKS_EVENT=push GITLEAKS_BEFORE="$ZERO" GITLEAKS_AFTER="$C2")"
[[ "$(field mode <<<"$OUT")" == "all" ]] || fail "all-zero mode: $OUT"
[[ "$(field range <<<"$OUT")" == "$C2" ]] || fail "all-zero range: $OUT"
[[ "$(field commits <<<"$OUT")" == "2" ]] || fail "all-zero commit count: $OUT"

# Equal before/after is an explicitly empty range, not an error.
OUT="$(run_range GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C2" GITLEAKS_AFTER="$C2")"
[[ "$(field mode <<<"$OUT")" == "skip" ]] || fail "skip mode: $OUT"
[[ "$(field commits <<<"$OUT")" == "0" ]] || fail "skip count: $OUT"

# An unresolvable base fails closed rather than silently widening the range.
if run_range GITLEAKS_EVENT=push \
    GITLEAKS_BEFORE="1111111111111111111111111111111111111111" \
    GITLEAKS_AFTER="$C2" >"$WORK/bad-base.out" 2>&1; then
  fail "unresolvable base was accepted"
fi
grep -q 'not a resolvable commit' "$WORK/bad-base.out" || fail "missing fail-closed diagnostic"

# Pull request: merge-base(base.sha, head.sha)..head includes second-parent
# content from the PR side without a pull_request_target event.
git checkout -q -b feature "$C1"
C3="$(commit_marker "feature-side content")"
git checkout -q main
git merge -q --no-ff feature -m "merge feature"
MERGE="$(git rev-parse HEAD)"
OUT="$(run_range GITLEAKS_EVENT=pull_request GITLEAKS_PR_BASE="$C2" GITLEAKS_PR_HEAD="$C3")"
[[ "$(field mode <<<"$OUT")" == "range" ]] || fail "pull_request mode: $OUT"
PR_RANGE="$(field range <<<"$OUT")"
[[ "$PR_RANGE" == "$C1..$C3" ]] || fail "pull_request range: $OUT"
git log --format=%H "$PR_RANGE" | grep -qx "$C3" || fail "PR range omitted second-parent commit"
git log -p --full-history "$PR_RANGE" | grep -q "$MARKER" || fail "PR range omitted marker content"

# A push range that contains the merge must include the second-parent commit.
OUT="$(run_range GITLEAKS_EVENT=push GITLEAKS_BEFORE="$C2" GITLEAKS_AFTER="$MERGE")"
PUSH_RANGE="$(field range <<<"$OUT")"
[[ "$(field commits <<<"$OUT")" == "2" ]] || fail "merge push commit count: $OUT"
git log --format=%H "$PUSH_RANGE" | grep -qx "$C3" || fail "merge push range omitted second-parent commit"
git log -p --full-history -m "$PUSH_RANGE" | grep -q "$MARKER" \
  || fail "merge push diff omitted second-parent marker content"

echo "ok: gitleaks range derivation regression passed"
