#!/usr/bin/env bash
# Breaking-change gate for proto/ (buf FILE rules).
# Usage: buf-breaking.sh [GIT_REF | --baseline]
#   GIT_REF     compare against proto/ at that ref. Default: refs/heads/develop, else
#               refs/remotes/origin/develop. CI passes refs/remotes/origin/develop.
#               Only fully qualified refs (refs/...) are accepted, and each must exist under
#               exactly that name (git show-ref --verify). rev-parse would instead expand a
#               missing name through refs/tags/ (origin/develop -> refs/tags/origin/develop,
#               refs/heads/develop -> refs/tags/refs/heads/develop), so a pushed tag could
#               swap the baseline. A ref that does not exist is an error, never a skip.
#   --baseline  compare against the frozen proto/.baseline/v1.binpb instead.
set -euo pipefail
cd "$(dirname "$0")/../proto"

if [[ "${1:-}" == --baseline ]]; then
  echo "buf breaking against .baseline/v1.binpb"
  exec buf breaking --against .baseline/v1.binpb
fi

if [[ $# -gt 0 ]]; then
  if [[ "$1" != refs/* ]]; then
    echo "ERROR: $1 is not a fully qualified ref (use e.g. refs/remotes/origin/develop)" >&2
    exit 1
  fi
  candidates=("$1")
else
  candidates=(refs/heads/develop refs/remotes/origin/develop)
fi
commit=""
for ref in "${candidates[@]}"; do
  # show-ref --verify matches the exact refname only; then peel that object to a commit.
  if object="$(git show-ref --verify --hash "$ref" 2>/dev/null)" \
    && commit="$(git rev-parse --verify -q --end-of-options "$object^{commit}")"; then
    break
  fi
  commit=""
done
if [[ -z "$commit" ]]; then
  echo "ERROR: ${candidates[*]} does not resolve to a commit (fetch it first)" >&2
  exit 1
fi

# The common dir also works from a linked worktree, whose .git is a file.
gitdir="$(git rev-parse --path-format=absolute --git-common-dir)"
echo "buf breaking against $ref ($commit)"
buf breaking --against "$gitdir#ref=$commit,subdir=proto"
