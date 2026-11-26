#!/usr/bin/env bash
# Derive and independently verify the explicit git revision range used by the
# direct Gitleaks CLI. Inputs come only from environment variables populated by
# the workflow from typed GitHub event fields; every SHA is validated as a full
# 40-hex commit identity before it reaches a git command.
#
# Outputs (safe key=value lines, suitable for $GITHUB_OUTPUT):
#   mode=range|all|skip
#   range=<git revision expression>
#   commits=<git rev-list --count --full-history result>
#   log_opts=--full-history -m <range>   (empty when mode=skip)
#   reason=<stable token describing why this mode was selected>
#   force_push=true|false
#   event=<validated event name>
set -euo pipefail

die() { printf 'gitleaks-range: ERROR: %s\n' "$*" >&2; exit 1; }
is_sha() { [[ "$1" =~ ^[0-9a-fA-F]{40}$ ]]; }
require_sha() { is_sha "$2" || die "$1 is not a full 40-hex SHA: ${2:-<empty>}"; }
require_commit() {
  local label="$1" sha="$2"
  require_sha "$label" "$sha"
  git cat-file -e "${sha}^{commit}" 2>/dev/null \
    || die "$label is not a resolvable commit in this checkout: $sha"
  git rev-parse --verify -q "${sha}^{commit}" >/dev/null \
    || die "$label could not be verified as a commit: $sha"
}
is_true() {
  local value="${1,,}"
  [[ "$value" == "true" || "$value" == "1" || "$value" == "yes" ]]
}

ZERO="0000000000000000000000000000000000000000"
[[ "$(git rev-parse --is-inside-work-tree 2>/dev/null || true)" == "true" ]] \
  || die "not inside a git work tree"

event="${GITLEAKS_EVENT:-}"
force_push=false

case "$event" in
  push)
    before="${GITLEAKS_BEFORE:-}"
    after="${GITLEAKS_AFTER:-}"
    deleted="${GITLEAKS_DELETED:-false}"
    require_sha "github.event.before" "$before"
    require_sha "github.event.after" "$after"

    if is_true "$deleted"; then
      # A deleted ref has no new content. after is the zero SHA, so scanning it
      # as a commit would be invalid. Report an explicit skip with a reason.
      [[ "$after" == "$ZERO" ]] \
        || die "deleted push must have an all-zero after SHA: $after"
      mode=skip
      range=""
      reason="deleted-ref"
    else
      [[ "$after" != "$ZERO" ]] \
        || die "after is the zero SHA but github.event.deleted is not true"
      require_commit "github.event.after" "$after"

      if [[ "$before" == "$ZERO" ]]; then
        # Initial branch/tag creation: scan the whole intended history.
        mode=all
        range="$after"
        reason="initial-push"
      elif [[ "${before,,}" == "${after,,}" ]]; then
        # Explicit empty range; the workflow skips the scan.
        mode=skip
        range=""
        reason="empty-range"
      else
        # before is the explicit push base, not event.commits[0].
        require_commit "github.event.before" "$before"
        if git merge-base --is-ancestor "$before" "$after" 2>/dev/null; then
          force_push=false
        else
          # Non-fast-forward: scan all newly reachable commits under after.
          # Removed commits are not new content and are not scanned.
          force_push=true
        fi
        mode=range
        range="$before..$after"
        reason="push-range"
      fi
    fi
    ;;
  pull_request)
    base="${GITLEAKS_PR_BASE:-}"
    head="${GITLEAKS_PR_HEAD:-}"
    require_commit "pull_request.base.sha" "$base"
    require_commit "pull_request.head.sha" "$head"
    merge_base="$(git merge-base "$base" "$head")" \
      || die "no merge base between $base and $head; refusing to guess a range"
    [[ -n "$merge_base" ]] || die "merge-base returned an empty value"
    mode=range
    range="$merge_base..$head"
    reason="pull-request"
    ;;
  workflow_dispatch|schedule)
    head="$(git rev-parse --verify HEAD)" || die "HEAD is missing or unresolvable"
    require_commit "HEAD" "$head"
    mode=all
    range="$head"
    reason="manual-full"
    ;;
  *)
    die "unsupported GITLEAKS_EVENT: ${event:-<empty>}"
    ;;
esac

if [[ "$mode" == "skip" ]]; then
  commits=0
  log_opts=""
else
  # No --no-merges and no --first-parent: all parents stay in the traversal.
  # -m forces merge commits to emit diffs against each parent, so a secret
  # introduced only in the merge result is visible to Gitleaks as well.
  commits="$(git rev-list --count --full-history "$range")" \
    || die "git rev-list failed for range: $range"
  [[ "$commits" =~ ^[0-9]+$ ]] || die "git rev-list returned a non-numeric count: $commits"
  ((10#$commits > 0)) || die "expected commits in range '$range' but git rev-list found 0"
  log_opts="--full-history -m $range"
fi

printf 'mode=%s\n' "$mode"
printf 'range=%s\n' "$range"
printf 'commits=%s\n' "$commits"
printf 'log_opts=%s\n' "$log_opts"
printf 'reason=%s\n' "$reason"
printf 'force_push=%s\n' "$force_push"
printf 'event=%s\n' "$event"
