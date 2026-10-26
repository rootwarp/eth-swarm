#!/usr/bin/env bash
# Tests for scripts/check-verify-cache-deps.sh.
# Run: bash scripts/tests/check-verify-cache-deps.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-verify-cache-deps.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

ws="$tmp/ok"
crate "$ws" cl-verify-cache '[dependencies]' 'sha2 = { path = "../sha2" }' \
  '[dev-dependencies]' 'state-transition = { path = "../state-transition" }' \
  'crypto-bls = { path = "../crypto-bls" }' 'blst = { path = "../blst" }'
crate "$ws" sha2
crate "$ws" state-transition
crate "$ws" crypto-bls '[dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check pass "dev-dependencies only" "$script" \
  "$(workspace ok cl-verify-cache sha2 state-transition crypto-bls blst)" "deps OK"

ws="$tmp/stf"
crate "$ws" cl-verify-cache '[dependencies]' 'state-transition = { path = "../state-transition" }'
crate "$ws" state-transition
check fail "a normal state-transition dependency" "$script" \
  "$(workspace stf cl-verify-cache state-transition)" "state-transition is a normal dependency"

ws="$tmp/bls"
crate "$ws" cl-verify-cache '[dependencies]' 'crypto-bls = { path = "../crypto-bls" }'
crate "$ws" crypto-bls '[dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check fail "a normal crypto-bls dependency (and blst through it)" "$script" \
  "$(workspace bls cl-verify-cache crypto-bls blst)" "crypto-bls is a normal dependency"

ws="$tmp/transitive"
crate "$ws" cl-verify-cache '[dependencies]' 'other = { path = "../other" }'
crate "$ws" other '[dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check fail "blst through another crate" "$script" \
  "$(workspace transitive cl-verify-cache other blst)" "blst is a normal dependency"

ws="$tmp/feature"
crate "$ws" cl-verify-cache '[dependencies]' \
  'state-transition = { path = "../state-transition", optional = true }' \
  '[features]' 'stf = ["dep:state-transition"]'
crate "$ws" state-transition
check fail "behind an optional feature" "$script" \
  "$(workspace feature cl-verify-cache state-transition)" "state-transition is a normal dependency"

ws="$tmp/target"
crate "$ws" cl-verify-cache "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" \
  'crypto-bls = { path = "../crypto-bls" }'
crate "$ws" crypto-bls
check fail "on another target platform" "$script" \
  "$(workspace target cl-verify-cache crypto-bls)" "crypto-bls is a normal dependency"

ws="$tmp/lookalike"
crate "$ws" cl-verify-cache '[dependencies]' 'blst-like = { path = "../blst-like" }'
crate "$ws" blst-like
check pass "a crate whose name only starts with blst" "$script" \
  "$(workspace lookalike cl-verify-cache blst-like)"

ws="$tmp/missing"
crate "$ws" other
check fail "no cl-verify-cache package (the check would be vacuous)" "$script" \
  "$(workspace missing other)" "want exactly one cl-verify-cache"

check pass "real workspace" "$script" "$repo/Cargo.toml" "deps OK"

echo "# $passed passed, $failed failed"
((failed == 0))
