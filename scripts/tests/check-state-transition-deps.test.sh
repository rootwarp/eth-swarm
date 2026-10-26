#!/usr/bin/env bash
# Tests for scripts/check-state-transition-deps.sh.
# Run: bash scripts/tests/check-state-transition-deps.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-state-transition-deps.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

ws="$tmp/ok"
crate "$ws" state-transition '[dependencies]' 'other = { path = "../other" }'
crate "$ws" other
crate "$ws" blst
check pass "no blst in the graph" "$script" "$(workspace ok state-transition other blst)" "deps OK"

ws="$tmp/direct"
crate "$ws" state-transition '[dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check fail "direct blst dependency" "$script" "$(workspace direct state-transition blst)" "blst v0.1.0"

ws="$tmp/transitive"
crate "$ws" state-transition '[dependencies]' 'crypto-bls = { path = "../crypto-bls" }'
crate "$ws" crypto-bls '[dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check fail "blst through another crate" "$script" \
  "$(workspace transitive state-transition crypto-bls blst)" "blst is a dependency"

ws="$tmp/dev"
crate "$ws" state-transition '[dev-dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check fail "a blst dev-dependency counts too" "$script" "$(workspace dev state-transition blst)" \
  "blst is a dependency"

ws="$tmp/build"
crate "$ws" state-transition '[build-dependencies]' 'blst = { path = "../blst" }'
crate "$ws" blst
check fail "a blst build-dependency counts too" "$script" "$(workspace build state-transition blst)" \
  "blst is a dependency"

ws="$tmp/target"
crate "$ws" state-transition "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" \
  'blst = { path = "../blst" }'
crate "$ws" blst
check fail "blst on another target platform" "$script" "$(workspace target state-transition blst)" \
  "blst is a dependency"

ws="$tmp/feature"
crate "$ws" state-transition '[dependencies]' 'blst = { path = "../blst", optional = true }' \
  '[features]' 'bls = ["dep:blst"]'
crate "$ws" blst
check fail "blst behind an optional feature" "$script" "$(workspace feature state-transition blst)" \
  "blst is a dependency"

ws="$tmp/lookalike"
crate "$ws" state-transition '[dependencies]' 'blst-like = { path = "../blst-like" }'
crate "$ws" blst-like
check pass "a crate whose name only starts with blst" "$script" \
  "$(workspace lookalike state-transition blst-like)"

ws="$tmp/missing"
crate "$ws" other
check fail "no state-transition package (the check would be vacuous)" "$script" \
  "$(workspace missing other)" "want exactly one state-transition"

check pass "real workspace" "$script" "$repo/Cargo.toml" "no blst"

echo "# $passed passed, $failed failed"
((failed == 0))
