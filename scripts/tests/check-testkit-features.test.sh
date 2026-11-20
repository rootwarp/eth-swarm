#!/usr/bin/env bash
# Tests for scripts/check-testkit-features.sh. Run: bash scripts/tests/check-testkit-features.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-testkit-features.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

services="cl-chain cl-store cl-engine cl-verify cl-p2p cl-discv5 cl-sync cl-api"
testkit_features='[features]
test-support = []
mock-el = []'

# base <ws> [testkit features]: testkit, and each service except cl-chain with no dependency.
base() {
  crate "$1" testkit "${2:-$testkit_features}"
  for s in $services; do
    [[ $s == cl-chain ]] || crate "$1" "$s"
  done
}

# members [more...]: testkit, each service, and more.
members() { echo testkit $services "$@"; }

dev='testkit = { path = "../testkit", features = ["test-support"] }'

ws="$tmp/dev"; base "$ws"
crate "$ws" cl-chain '[dev-dependencies]' "$dev"
# shellcheck disable=SC2046 # the member names are words
check pass "a dev-dependency enables it" "$script" "$(workspace dev $(members))" \
  "no service links testkit/test-support"

ws="$tmp/plain"; base "$ws"
crate "$ws" cl-chain '[dependencies]' 'testkit = { path = "../testkit", features = ["mock-el"] }'
# shellcheck disable=SC2046
check pass "a normal dependency without the feature" "$script" "$(workspace plain $(members))"

ws="$tmp/normal"; base "$ws"
crate "$ws" cl-chain '[dependencies]' "$dev"
# shellcheck disable=SC2046
check fail "a normal dependency enables it" "$script" "$(workspace normal $(members))" \
  "cl-chain links testkit/test-support"

ws="$tmp/build"; base "$ws"
crate "$ws" cl-chain '[build-dependencies]' "$dev"
# shellcheck disable=SC2046
check fail "a build dependency enables it" "$script" "$(workspace build $(members))" \
  "cl-chain links testkit/test-support"

ws="$tmp/target"; base "$ws"
crate "$ws" cl-chain "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" "$dev"
# shellcheck disable=SC2046
check fail "a target-specific dependency enables it" "$script" "$(workspace target $(members))" \
  "cl-chain links testkit/test-support"

ws="$tmp/transitive"; base "$ws"
crate "$ws" helper '[dependencies]' "$dev"
crate "$ws" cl-chain '[dependencies]' 'helper = { path = "../helper" }'
# shellcheck disable=SC2046
check fail "a crate in between enables it" "$script" "$(workspace transitive $(members helper))" \
  "cl-chain links testkit/test-support"

ws="$tmp/forward"; base "$ws"
crate "$ws" cl-chain '[dependencies]' 'testkit = { path = "../testkit", optional = true }' \
  '[features]' 'fixtures = ["testkit/test-support"]'
# shellcheck disable=SC2046
check fail "a service feature forwards to it" "$script" "$(workspace forward $(members))" \
  "cl-chain links testkit/test-support"

ws="$tmp/default"
base "$ws" '[features]
default = ["test-support"]
test-support = []'
crate "$ws" cl-chain '[dependencies]' 'testkit = { path = "../testkit" }'
# shellcheck disable=SC2046
check fail "a testkit default implies it" "$script" "$(workspace default $(members))" \
  "cl-chain links testkit/test-support"

ws="$tmp/other-service"; base "$ws"
crate "$ws" cl-chain
crate "$ws" cl-api '[dependencies]' "$dev"
# shellcheck disable=SC2046
check fail "each service is checked" "$script" "$(workspace other-service $(members))" \
  "cl-api links testkit/test-support"

ws="$tmp/tool"; base "$ws"
crate "$ws" cl-chain '[dev-dependencies]' "$dev"
crate "$ws" devnet-probe '[dependencies]' "$dev"
# shellcheck disable=SC2046
check pass "a package that is not a service may enable it" "$script" \
  "$(workspace tool $(members devnet-probe))"

ws="$tmp/missing"; base "$ws"
# shellcheck disable=SC2046
check fail "a service that is gone fails" "$script" \
  "$(workspace missing testkit cl-store cl-engine cl-verify cl-p2p cl-discv5 cl-sync cl-api)" \
  "service cl-chain is not in the workspace"

ws="$tmp/renamed"; base "$ws" '[features]
fixtures = []'
crate "$ws" cl-chain
# shellcheck disable=SC2046
check fail "testkit without the feature fails" "$script" "$(workspace renamed $(members))" \
  "testkit has no test-support feature"

# A cargo that fails (here: a stale lockfile under --locked) is not a pass.
ws="$tmp/stale"; base "$ws"
crate "$ws" cl-chain
# shellcheck disable=SC2046
manifest=$(workspace stale $(members))
crate "$ws" cl-chain '[dependencies]' 'other = { path = "../other" }'
crate "$ws" other
check fail "cargo failure is not a pass" "$script" "$manifest"

check pass "real workspace" "$script" "$repo/Cargo.toml" "no service links testkit/test-support"

echo "# $passed passed, $failed failed"
((failed == 0))
