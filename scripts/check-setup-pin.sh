#!/usr/bin/env bash
# Fail unless cl-verify is the only production caller of the trusted-setup loader, pinned to the
# beta.4 mainnet digest:
#   rg 'load_pinned\(' crates/ -g '!crates/crypto-kzg/**' -g '!crates/spec-tests/**' -g '!**/tests/**'
# must find exactly one call (calls are counted, not lines), in crates/cl-verify/src/kzg.rs, and
# that call must pass BETA4_MAINNET_SHA256 as its whole second argument on the same line. Hidden
# and ignored files are searched too, so rg and grep agree.
# Usage: scripts/check-setup-pin.sh [repo-root]
# Env: SETUP_PIN_CHECK_NO_RG=1 forces the grep fallback. Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
call='load_pinned\('
# The call itself, with the digest constant as its whole second argument, on one line.
pinned='load_pinned\([^(),]*,[[:space:]]*BETA4_MAINNET_SHA256[[:space:]]*\)'
caller=crates/cl-verify/src/kzg.rs

if [[ ! -d crates ]]; then
  echo "ERROR: crates/ not found under $root"
  exit 1
fi

# search <regex>: one `file:line:match` per occurrence (not per line) outside the excluded trees.
search() {
  local rc=0 out
  if [[ -z ${SETUP_PIN_CHECK_NO_RG:-} ]] && command -v rg >/dev/null 2>&1; then
    out=$(rg -o -n --hidden --no-ignore -e "$1" crates/ \
      -g '!crates/crypto-kzg/**' -g '!crates/spec-tests/**' -g '!**/tests/**') || rc=$?
  else
    out=$(grep -rnoE -e "$1" crates/ |
      grep -vE '^crates/(crypto-kzg|spec-tests)/|(^|/)tests/') || rc=$?
  fi
  if ((rc > 1)); then
    echo "ERROR: searching crates/ failed (exit $rc)" >&2
    return 2
  fi
  printf '%s' "$out"
}

count() { if [[ -n $1 ]]; then printf '%s\n' "$1" | wc -l | tr -d ' '; else echo 0; fi; }

calls=$(search "$call") || exit 1
if (($(count "$calls") != 1)); then
  echo "ERROR: want exactly one load_pinned( call outside crypto-kzg, spec-tests and tests/, in $caller; found $(count "$calls"):"
  printf '%s\n' "$calls"
  exit 1
fi
case $calls in
  "$caller:"*) ;;
  *) echo "ERROR: the load_pinned( call is not in $caller:"; printf '%s\n' "$calls"; exit 1 ;;
esac
hits=$(search "$pinned") || exit 1
if (($(count "$hits") != 1)) || [[ ${hits%%:*} != "$caller" ]]; then
  echo "ERROR: the load_pinned( call in $caller does not pass BETA4_MAINNET_SHA256 as its digest:"
  printf '%s\n' "$calls"
  exit 1
fi
echo "setup pin OK: $hits"
