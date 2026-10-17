#!/usr/bin/env bash
# Tests for scripts/check-m2a-deps.sh. Run: bash scripts/tests/check-m2a-deps.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-m2a-deps.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

# cl_p2p <ws> [Cargo.toml tail...]: cl-p2p with an m2a-session binary.
cl_p2p() {
  local ws=$1
  shift
  crate "$ws" cl-p2p "$@"
  mkdir -p "$ws/cl-p2p/src/bin/m2a-session"
  echo 'fn main() {}' > "$ws/cl-p2p/src/bin/m2a-session/main.rs"
}

ws="$tmp/ok"
cl_p2p "$ws" '[dependencies]' 'other = { path = "../other" }'
crate "$ws" other
crate "$ws" discv5
check pass "no discv5 in the graph" "$script" "$(workspace ok cl-p2p other discv5)" "deps OK"

ws="$tmp/direct"
cl_p2p "$ws" '[dependencies]' 'discv5 = { path = "../discv5" }'
crate "$ws" discv5
check fail "direct discv5 dependency" "$script" "$(workspace direct cl-p2p discv5)" "discv5 v0.1.0"

ws="$tmp/transitive"
cl_p2p "$ws" '[dependencies]' 'mid = { path = "../mid" }'
crate "$ws" mid '[dependencies]' 'discv5 = { path = "../discv5" }'
crate "$ws" discv5
check fail "discv5 through another crate" "$script" "$(workspace transitive cl-p2p mid discv5)" \
  "discv5 is a dependency"

ws="$tmp/target"
cl_p2p "$ws" "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" 'discv5 = { path = "../discv5" }'
crate "$ws" discv5
check fail "discv5 on another target platform" "$script" "$(workspace target cl-p2p discv5)" \
  "discv5 is a dependency"

ws="$tmp/dev"
cl_p2p "$ws" '[dev-dependencies]' 'discv5 = { path = "../discv5" }'
crate "$ws" discv5
check pass "a dev-dependency is not linked into the binary" "$script" "$(workspace dev cl-p2p discv5)"

ws="$tmp/nobin"
crate "$ws" cl-p2p
check fail "no m2a-session binary (the check would be vacuous)" "$script" "$(workspace nobin cl-p2p)" \
  "no m2a-session binary"

check pass "real workspace" "$script" "$repo/Cargo.toml"

echo "# $passed passed, $failed failed"
((failed == 0))
