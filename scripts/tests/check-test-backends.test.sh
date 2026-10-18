#!/usr/bin/env bash
# Tests for scripts/check-test-backends.sh. Run: bash scripts/tests/check-test-backends.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-test-backends.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

feature='[features]'
defined='test-backends = []'
self_dev='cl-verify = { path = ".", features = ["test-backends"] }'

ws="$tmp/ok"
crate "$ws" cl-verify "$feature" "$defined" '[dev-dependencies]' "$self_dev"
crate "$ws" user '[dependencies]' 'cl-verify = { path = "../cl-verify" }'
check pass "only cl-verify's own dev-dependency enables it" "$script" "$(workspace ok cl-verify user)" \
  "test-backends OK"

ws="$tmp/normal-user"
crate "$ws" cl-verify "$feature" "$defined" '[dev-dependencies]' "$self_dev"
crate "$ws" user '[dependencies]' 'cl-verify = { path = "../cl-verify", features = ["test-backends"] }'
check fail "another crate's normal dependency enables it" "$script" \
  "$(workspace normal-user cl-verify user)" "enabled by user"

ws="$tmp/dev-user"
crate "$ws" cl-verify "$feature" "$defined"
crate "$ws" user '[dev-dependencies]' 'cl-verify = { path = "../cl-verify", features = ["test-backends"] }'
check fail "another crate's dev-dependency enables it" "$script" \
  "$(workspace dev-user cl-verify user)" "enabled by user"

ws="$tmp/user-feature"
crate "$ws" cl-verify "$feature" "$defined"
crate "$ws" user '[dependencies]' 'cl-verify = { path = "../cl-verify" }' '[features]' \
  'x = ["cl-verify/test-backends"]'
check fail "another crate's feature enables it" "$script" \
  "$(workspace user-feature cl-verify user)" "enabled by user"

ws="$tmp/renamed-feature"
crate "$ws" cl-verify "$feature" "$defined"
crate "$ws" user '[dependencies]' 'v = { package = "cl-verify", path = "../cl-verify" }' \
  '[features]' 'default = ["v/test-backends"]'
check fail "a renamed dependency's feature forward enables it" "$script" \
  "$(workspace renamed-feature cl-verify user)" "enabled by user (feature default)"

ws="$tmp/renamed-optional"
crate "$ws" cl-verify "$feature" "$defined"
crate "$ws" user '[dependencies]' \
  'v = { package = "cl-verify", path = "../cl-verify", optional = true }' \
  '[features]' 'x = ["v?/test-backends"]'
check fail "a renamed optional dependency's weak forward enables it" "$script" \
  "$(workspace renamed-optional cl-verify user)" "enabled by user (feature x)"

ws="$tmp/renamed-dep"
crate "$ws" cl-verify "$feature" "$defined"
crate "$ws" user '[dev-dependencies]' \
  'v = { package = "cl-verify", path = "../cl-verify", features = ["test-backends"] }'
check fail "a renamed dependency's features enable it" "$script" \
  "$(workspace renamed-dep cl-verify user)" "enabled by user (dev dependency)"

ws="$tmp/renamed-other"
crate "$ws" cl-verify "$feature" "$defined"
crate "$ws" other "$feature" "$defined"
crate "$ws" user '[dependencies]' 'v = { package = "cl-verify", path = "../cl-verify" }' \
  'cl-verify = { package = "other", path = "../other" }' '[features]' \
  'x = ["cl-verify/test-backends"]'
check pass "another package renamed to cl-verify is not cl-verify" "$script" \
  "$(workspace renamed-other cl-verify other user)" "test-backends OK"

ws="$tmp/default"
crate "$ws" cl-verify "$feature" "$defined" 'default = ["test-backends"]'
check fail "a default feature" "$script" "$(workspace default cl-verify)" "cl-verify feature default"

ws="$tmp/implied"
crate "$ws" cl-verify "$feature" "$defined" 'extra = ["test-backends"]'
check fail "implied by another cl-verify feature" "$script" "$(workspace implied cl-verify)" \
  "cl-verify feature extra"

ws="$tmp/missing"
crate "$ws" cl-verify
check fail "feature missing (the check would be vacuous)" "$script" "$(workspace missing cl-verify)" \
  "no test-backends feature"

check pass "real workspace" "$script" "$repo/Cargo.toml"

echo "# $passed passed, $failed failed"
((failed == 0))
