#!/usr/bin/env bash
# Tests for scripts/check-dep-cycles.sh. Run: bash scripts/tests/check-dep-cycles.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-dep-cycles.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

ws="$tmp/dag"
crate "$ws" a '[dependencies]' 'b = { path = "../b" }' 'c = { path = "../c" }'
crate "$ws" b '[dependencies]' 'c = { path = "../c" }'
crate "$ws" c '[dev-dependencies]' 'd = { path = "../d" }'
crate "$ws" d
check pass "acyclic workspace (diamond plus a dev edge)" "$script" "$(workspace dag a b c d)" \
  "no dependency cycles among 4 workspace crates"

ws="$tmp/dev-cycle"
crate "$ws" a '[dev-dependencies]' 'b = { path = "../b" }'
crate "$ws" b '[dependencies]' 'a = { path = "../a" }'
check fail "cycle closed by a dev-dependency" "$script" "$(workspace dev-cycle a b)" "a -> b -> a"

ws="$tmp/long-cycle"
crate "$ws" a '[dependencies]' 'b = { path = "../b" }'
crate "$ws" b '[dependencies]' 'c = { path = "../c" }'
crate "$ws" c '[dev-dependencies]' 'a = { path = "../a" }'
check fail "three-crate cycle" "$script" "$(workspace long-cycle a b c)" "a -> b -> c -> a"

# The edge to b exists only with a's non-default feature; without --all-features it is missed.
ws="$tmp/optional-cycle"
crate "$ws" a '[dependencies]' 'b = { path = "../b", optional = true }' '[features]' 'extra = ["dep:b"]'
crate "$ws" b '[dev-dependencies]' 'a = { path = "../a" }'
check fail "cycle through an optional dependency" "$script" "$(workspace optional-cycle a b)" "a -> b -> a"

# Cargo refuses a cycle of normal dependencies outright; that failure must not pass.
ws="$tmp/normal-cycle"
crate "$ws" a '[dependencies]' 'b = { path = "../b" }'
crate "$ws" b
manifest=$(workspace normal-cycle a b)
crate "$ws" b '[dependencies]' 'a = { path = "../a" }'
check fail "cycle of normal dependencies" "$script" "$manifest" "cargo metadata failed"

check pass "real workspace" "$script" "$repo/Cargo.toml"

echo "# $passed passed, $failed failed"
((failed == 0))
