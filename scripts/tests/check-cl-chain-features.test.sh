#!/usr/bin/env bash
# Tests for scripts/check-cl-chain-features.sh. Run: bash scripts/tests/check-cl-chain-features.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-cl-chain-features.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

bls_features='[features]
verify = []
aggregate = []
test-vectors = []'

# bls <ws>: the crypto-bls stand-in, with the real feature names.
bls() { crate "$1" crypto-bls "$bls_features"; }

ws="$tmp/absent"; bls "$ws"; crate "$ws" other
check pass "no cl-chain in the workspace" "$script" "$(workspace absent crypto-bls other)" \
  "cl-chain is not in the workspace yet"

ws="$tmp/aggregate"; bls "$ws"
crate "$ws" cl-chain '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["aggregate"] }'
check pass "cl-chain links only crypto-bls/aggregate" "$script" "$(workspace aggregate crypto-bls cl-chain)" \
  "does not link crypto-bls/verify"

ws="$tmp/verify"; bls "$ws"
crate "$ws" cl-chain '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["aggregate", "verify"] }'
check fail "planted crypto-bls/verify in cl-chain" "$script" "$(workspace verify crypto-bls cl-chain)" \
  "cl-chain links crypto-bls/verify"

ws="$tmp/transitive"; bls "$ws"
crate "$ws" helper '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["verify"] }'
crate "$ws" cl-chain '[dependencies]' 'helper = { path = "../helper" }'
check fail "crypto-bls/verify through another crate" "$script" \
  "$(workspace transitive crypto-bls helper cl-chain)" "helper"

ws="$tmp/optional"; bls "$ws"
crate "$ws" cl-chain '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["aggregate"] }' \
  '[features]' 'slow-path = ["crypto-bls/verify"]'
check fail "crypto-bls/verify behind a cl-chain feature" "$script" "$(workspace optional crypto-bls cl-chain)"

ws="$tmp/dev"; bls "$ws"
crate "$ws" cl-chain '[dev-dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["verify"] }'
check fail "crypto-bls/verify as a dev-dependency" "$script" "$(workspace dev crypto-bls cl-chain)"

ws="$tmp/neighbour"; bls "$ws"
crate "$ws" cl-chain '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["aggregate"] }'
crate "$ws" spec-tests '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["verify", "test-vectors"] }'
check pass "another crate's crypto-bls/verify does not leak into cl-chain" "$script" \
  "$(workspace neighbour crypto-bls cl-chain spec-tests)"

# A cargo that fails (here: a stale lockfile under --locked) is not a pass.
ws="$tmp/stale"; bls "$ws"
crate "$ws" cl-chain '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["aggregate"] }'
manifest=$(workspace stale crypto-bls cl-chain)
crate "$ws" cl-chain '[dependencies]' 'crypto-bls = { path = "../crypto-bls", features = ["aggregate"] }' \
  'other = { path = "../other" }'
crate "$ws" other
check fail "cargo failure is not a pass" "$script" "$manifest"

check pass "real workspace" "$script" "$repo/Cargo.toml"

echo "# $passed passed, $failed failed"
((failed == 0))
