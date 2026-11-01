#!/usr/bin/env bash
# Tests for scripts/check-store-schema-deps.sh.
# Run: bash scripts/tests/check-store-schema-deps.test.sh
# Each case is a throwaway workspace of path-only crates (offline); one runs the real repo.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-store-schema-deps.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# shellcheck source=workspace-fixture.sh
. "$here/workspace-fixture.sh"

ws="$tmp/ok"
crate "$ws" store-schema '[dependencies]' 'libmdbx = { path = "../libmdbx" }' \
  'thiserror = { path = "../thiserror" }' \
  '[dev-dependencies]' 'tempfile = { path = "../tempfile" }' 'mdbx-sys = { path = "../mdbx-sys" }'
crate "$ws" libmdbx '[dependencies]' 'mdbx-sys = { path = "../mdbx-sys" }' 'bitflags = { path = "../bitflags" }'
crate "$ws" mdbx-sys
crate "$ws" bitflags
crate "$ws" thiserror
crate "$ws" tempfile
check pass "libmdbx and thiserror; their own deps and dev-dependencies do not count" "$script" \
  "$(workspace ok store-schema libmdbx mdbx-sys bitflags thiserror tempfile)" "deps OK"

ws="$tmp/all"
crate "$ws" store-schema '[dependencies]' 'libmdbx = { path = "../libmdbx" }' \
  'thiserror = { path = "../thiserror" }' 'consensus-types = { path = "../consensus-types" }'
crate "$ws" libmdbx
crate "$ws" thiserror
crate "$ws" consensus-types '[dependencies]' 'tracing = { path = "../tracing" }'
crate "$ws" tracing
check pass "consensus-types too (its own deps are not store-schema's)" "$script" \
  "$(workspace all store-schema libmdbx thiserror consensus-types tracing)" "deps OK"

ws="$tmp/direct"
crate "$ws" store-schema '[dependencies]' 'libmdbx = { path = "../libmdbx" }' \
  'tracing = { path = "../tracing" }'
crate "$ws" libmdbx
crate "$ws" tracing
check fail "a direct tracing dependency" "$script" \
  "$(workspace direct store-schema libmdbx tracing)" "tracing is a direct normal dependency"

ws="$tmp/feature"
crate "$ws" store-schema '[dependencies]' 'tracing = { path = "../tracing", optional = true }' \
  '[features]' 'log = ["dep:tracing"]'
crate "$ws" tracing
check fail "behind an optional feature" "$script" \
  "$(workspace feature store-schema tracing)" "tracing is a direct normal dependency"

ws="$tmp/target"
crate "$ws" store-schema "[target.'cfg(target_os = \"fuchsia\")'.dependencies]" \
  'tracing = { path = "../tracing" }'
crate "$ws" tracing
check fail "on another target platform" "$script" \
  "$(workspace target store-schema tracing)" "tracing is a direct normal dependency"

ws="$tmp/renamed"
crate "$ws" store-schema '[dependencies]' 'mdbx = { package = "tracing", path = "../tracing" }'
crate "$ws" tracing
check fail "renamed to look like another crate" "$script" \
  "$(workspace renamed store-schema tracing)" "tracing is a direct normal dependency"

ws="$tmp/build"
crate "$ws" store-schema '[build-dependencies]' 'cc = { path = "../cc" }'
crate "$ws" cc
check pass "a build-dependency is not a normal one" "$script" \
  "$(workspace build store-schema cc)" "deps OK"

ws="$tmp/missing"
crate "$ws" other
check fail "no store-schema package (the check would be vacuous)" "$script" \
  "$(workspace missing other)" "want exactly one store-schema"

check pass "real workspace" "$script" "$repo/Cargo.toml" "deps OK"

echo "# $passed passed, $failed failed"
((failed == 0))
