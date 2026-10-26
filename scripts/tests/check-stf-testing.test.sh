#!/usr/bin/env bash
# Tests for scripts/check-stf-testing.sh. Run: bash scripts/tests/check-stf-testing.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-stf-testing.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

feature='[features]'
defined='testing = []'
stf='state-transition'

ws="$tmp/ok"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dependencies]' 'state-transition = { path = "../state-transition" }' \
  '[dev-dependencies]' 'state-transition = { path = "../state-transition", features = ["testing"] }'
check pass "a dev-dependency enables it" "$script" "$(workspace ok $stf user)" "testing OK"

ws="$tmp/self-dev"
crate "$ws" $stf "$feature" "$defined" '[dev-dependencies]' \
  'state-transition = { path = ".", features = ["testing"] }'
check pass "state-transition's own dev-dependency enables it" "$script" \
  "$(workspace self-dev $stf)" "testing OK"

ws="$tmp/normal"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dependencies]' 'state-transition = { path = "../state-transition", features = ["testing"] }'
check fail "a normal dependency enables it" "$script" "$(workspace normal $stf user)" \
  "enabled by user (normal dependency)"

ws="$tmp/build"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[build-dependencies]' \
  'state-transition = { path = "../state-transition", features = ["testing"] }'
check fail "a build dependency enables it" "$script" "$(workspace build $stf user)" \
  "enabled by user (build dependency)"

ws="$tmp/target"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" \
  'state-transition = { path = "../state-transition", features = ["testing"] }'
check fail "a target-specific normal dependency enables it" "$script" \
  "$(workspace target $stf user)" "enabled by user (normal dependency)"

ws="$tmp/target-build"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user "[target.'cfg(unix)'.build-dependencies]" \
  'state-transition = { path = "../state-transition", features = ["testing"] }'
check fail "a target-specific build dependency enables it" "$script" \
  "$(workspace target-build $stf user)" "enabled by user (build dependency)"

ws="$tmp/forward"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dependencies]' 'state-transition = { path = "../state-transition" }' \
  '[features]' 'foo = ["state-transition/testing"]'
check fail "a feature forward enables it" "$script" "$(workspace forward $stf user)" \
  "enabled by user (feature foo)"

ws="$tmp/weak-forward"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dependencies]' 'state-transition = { path = "../state-transition", optional = true }' \
  '[features]' 'foo = ["state-transition?/testing"]'
check fail "a weak feature forward enables it" "$script" "$(workspace weak-forward $stf user)" \
  "enabled by user (feature foo)"

ws="$tmp/renamed-dep"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dependencies]' \
  'stf = { package = "state-transition", path = "../state-transition", features = ["testing"] }'
check fail "a renamed normal dependency enables it" "$script" "$(workspace renamed-dep $stf user)" \
  "enabled by user (normal dependency)"

ws="$tmp/renamed-forward"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dependencies]' 'stf = { package = "state-transition", path = "../state-transition" }' \
  '[features]' 'default = ["stf/testing"]'
check fail "a renamed dependency's feature forward enables it" "$script" \
  "$(workspace renamed-forward $stf user)" "enabled by user (feature default)"

ws="$tmp/renamed-dev"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" user '[dev-dependencies]' \
  'stf = { package = "state-transition", path = "../state-transition", features = ["testing"] }'
check pass "a renamed dev-dependency enables it" "$script" "$(workspace renamed-dev $stf user)" \
  "testing OK"

ws="$tmp/renamed-other"
crate "$ws" $stf "$feature" "$defined"
crate "$ws" other "$feature" "$defined"
crate "$ws" user '[dependencies]' 'stf = { package = "state-transition", path = "../state-transition" }' \
  'state-transition = { package = "other", path = "../other" }' '[features]' \
  'x = ["state-transition/testing"]'
check pass "another package renamed to state-transition is not state-transition" "$script" \
  "$(workspace renamed-other $stf other user)" "testing OK"

ws="$tmp/default"
crate "$ws" $stf "$feature" "$defined" 'default = ["testing"]'
check fail "a default feature" "$script" "$(workspace default $stf)" \
  "state-transition feature default"

ws="$tmp/implied"
crate "$ws" $stf "$feature" "$defined" 'extra = ["testing"]'
check fail "implied by another state-transition feature" "$script" "$(workspace implied $stf)" \
  "state-transition feature extra"

ws="$tmp/missing"
crate "$ws" $stf
check fail "feature missing (the check would be vacuous)" "$script" "$(workspace missing $stf)" \
  "no testing feature"

check pass "real workspace" "$script" "$repo/Cargo.toml" "testing OK"

echo "# $passed passed, $failed failed"
((failed == 0))
