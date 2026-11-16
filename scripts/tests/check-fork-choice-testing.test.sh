#!/usr/bin/env bash
# Tests for scripts/check-fork-choice-testing.sh. Run:
#   bash scripts/tests/check-fork-choice-testing.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-fork-choice-testing.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

feature='[features]'
defined='testing = []'
fc='fork-choice'

ws="$tmp/ok"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dependencies]' 'fork-choice = { path = "../fork-choice" }' \
  '[dev-dependencies]' 'fork-choice = { path = "../fork-choice", features = ["testing"] }'
check pass "a dev-dependency enables it" "$script" "$(workspace ok $fc user)" \
  "fork-choice/testing OK"

ws="$tmp/self-dev"
crate "$ws" $fc "$feature" "$defined" '[dev-dependencies]' \
  'fork-choice = { path = ".", features = ["testing"] }'
check pass "fork-choice's own dev-dependency enables it" "$script" \
  "$(workspace self-dev $fc)" "fork-choice/testing OK"

ws="$tmp/normal"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dependencies]' 'fork-choice = { path = "../fork-choice", features = ["testing"] }'
check fail "a normal dependency enables it" "$script" "$(workspace normal $fc user)" \
  "fork-choice/testing enabled by user (normal dependency)"

ws="$tmp/build"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[build-dependencies]' \
  'fork-choice = { path = "../fork-choice", features = ["testing"] }'
check fail "a build dependency enables it" "$script" "$(workspace build $fc user)" \
  "enabled by user (build dependency)"

ws="$tmp/target"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" \
  'fork-choice = { path = "../fork-choice", features = ["testing"] }'
check fail "a target-specific normal dependency enables it" "$script" \
  "$(workspace target $fc user)" "enabled by user (normal dependency)"

ws="$tmp/target-build"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user "[target.'cfg(unix)'.build-dependencies]" \
  'fork-choice = { path = "../fork-choice", features = ["testing"] }'
check fail "a target-specific build dependency enables it" "$script" \
  "$(workspace target-build $fc user)" "enabled by user (build dependency)"

ws="$tmp/target-dev"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user "[target.'cfg(unix)'.dev-dependencies]" \
  'fork-choice = { path = "../fork-choice", features = ["testing"] }'
check pass "a target-specific dev-dependency enables it" "$script" \
  "$(workspace target-dev $fc user)" "fork-choice/testing OK"

ws="$tmp/forward"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dependencies]' 'fork-choice = { path = "../fork-choice" }' \
  '[features]' 'foo = ["fork-choice/testing"]'
check fail "a feature forward enables it" "$script" "$(workspace forward $fc user)" \
  "enabled by user (feature foo)"

ws="$tmp/weak-forward"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dependencies]' 'fork-choice = { path = "../fork-choice", optional = true }' \
  '[features]' 'foo = ["fork-choice?/testing"]'
check fail "a weak feature forward enables it" "$script" "$(workspace weak-forward $fc user)" \
  "enabled by user (feature foo)"

ws="$tmp/renamed-dep"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dependencies]' \
  'fc = { package = "fork-choice", path = "../fork-choice", features = ["testing"] }'
check fail "a renamed normal dependency enables it" "$script" "$(workspace renamed-dep $fc user)" \
  "enabled by user (normal dependency)"

ws="$tmp/renamed-forward"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dependencies]' 'fc = { package = "fork-choice", path = "../fork-choice" }' \
  '[features]' 'default = ["fc/testing"]'
check fail "a renamed dependency's feature forward enables it" "$script" \
  "$(workspace renamed-forward $fc user)" "enabled by user (feature default)"

ws="$tmp/renamed-dev"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" user '[dev-dependencies]' \
  'fc = { package = "fork-choice", path = "../fork-choice", features = ["testing"] }'
check pass "a renamed dev-dependency enables it" "$script" "$(workspace renamed-dev $fc user)" \
  "fork-choice/testing OK"

ws="$tmp/renamed-other"
crate "$ws" $fc "$feature" "$defined"
crate "$ws" other "$feature" "$defined"
crate "$ws" user '[dependencies]' 'fc = { package = "fork-choice", path = "../fork-choice" }' \
  'fork-choice = { package = "other", path = "../other" }' '[features]' \
  'x = ["fork-choice/testing"]'
check pass "another package renamed to fork-choice is not fork-choice" "$script" \
  "$(workspace renamed-other $fc other user)" "fork-choice/testing OK"

ws="$tmp/default"
crate "$ws" $fc "$feature" "$defined" 'default = ["testing"]'
check fail "a default feature" "$script" "$(workspace default $fc)" \
  "fork-choice feature default"

ws="$tmp/implied"
crate "$ws" $fc "$feature" "$defined" 'extra = ["testing"]'
check fail "implied by another fork-choice feature" "$script" "$(workspace implied $fc)" \
  "fork-choice feature extra"

ws="$tmp/missing"
crate "$ws" $fc
check fail "feature missing (the check would be vacuous)" "$script" "$(workspace missing $fc)" \
  "no testing feature"

ws="$tmp/absent"
crate "$ws" user
check fail "no fork-choice package (the check would be vacuous)" "$script" \
  "$(workspace absent user)" "exactly one fork-choice package"

check pass "real workspace" "$script" "$repo/Cargo.toml" "fork-choice/testing OK"

echo "# $passed passed, $failed failed"
((failed == 0))
