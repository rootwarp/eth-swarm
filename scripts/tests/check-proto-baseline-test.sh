#!/usr/bin/env bash
# Tests for scripts/check-proto-baseline.sh. Offline and hermetic: every case runs against a copy
# of proto/ in a temp dir, so the committed baseline is never touched.
#   bash scripts/tests/check-proto-baseline-test.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
check="$here/../check-proto-baseline.sh"
src_proto="$here/../../proto"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The buf used for fixtures and passed to the checker; honours BUF like the checker does.
real_buf="$(command -v "${BUF:-buf}")" || { echo "buf not found (${BUF:-buf}); install buf or set BUF" >&2; exit 2; }
case "$real_buf" in /*) ;; *) real_buf="$PWD/$real_buf" ;; esac
export BUF="$real_buf"

pass=0
fail=0

# Fresh copy of proto/ with a baseline built from its current sources. Failures return non-zero
# explicitly: errexit is not inherited inside $(...), so a broken fixture would otherwise go unnoticed.
fresh_copy() {
  local dir="$work/$1"
  mkdir -p "$dir" || return 1
  cp -R "$src_proto" "$dir/proto" || return 1
  (cd "$dir/proto" && "$real_buf" build -o .baseline/v1.binpb) || { echo "fixture build failed: $1" >&2; return 1; }
  printf '%s\n' "$dir/proto"
}

# expect <name> <want-exit> <want-output-substring> -- <command...>
expect() {
  local name="$1" want_rc="$2" want_out="$3"
  shift 4
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [[ "$rc" == "$want_rc" && "$out" == *"$want_out"* ]]; then
    pass=$((pass + 1))
    echo "ok   $name"
  else
    fail=$((fail + 1))
    echo "FAIL $name: exit $rc (want $want_rc), output:"
    printf '%s\n' "$out" | sed 's/^/     | /'
  fi
}

dir="$(fresh_copy in_sync)"
expect "baseline in sync passes" 0 "proto baseline OK" -- bash "$check" "$dir"

dir="$(fresh_copy tampered)"
printf '\0' >>"$dir/.baseline/v1.binpb"
expect "tampered baseline fails" 1 "proto baseline drift" -- bash "$check" "$dir"

dir="$(fresh_copy proto_edited)"
printf '\n// drift\nmessage DriftProbe {}\n' >>"$dir/ethswarm/api/v1/api.proto"
expect "proto edited without re-baseline fails" 1 "proto baseline drift" -- bash "$check" "$dir"

dir="$(fresh_copy comment_edited)"
# A comment attached to a field is part of the descriptor's source info.
perl -pi -e 's{^(\s*)// 48 bytes each, compressed G1; }{$1// Edited. 48 bytes each, compressed G1; }' "$dir/ethswarm/verify/v1/verify.proto"
grep -q 'Edited. 48 bytes each' "$dir/ethswarm/verify/v1/verify.proto"
expect "comment-only edit without re-baseline fails" 1 "proto baseline drift" -- bash "$check" "$dir"

dir="$(fresh_copy missing)"
rm "$dir/.baseline/v1.binpb"
expect "missing baseline fails" 1 "baseline not found" -- bash "$check" "$dir"

dir="$(fresh_copy broken)"
printf '\nthis is not proto\n' >>"$dir/ethswarm/api/v1/api.proto"
expect "proto that does not build fails" 1 "buf build failed" -- bash "$check" "$dir"

expect "missing proto dir fails" 2 "not a directory" -- bash "$check" "$work/does-not-exist"

dir="$(fresh_copy no_buf)"
expect "missing buf fails" 2 "buf not found" -- env BUF="$work/no-such-buf" bash "$check" "$dir"

dir="$(fresh_copy relative_buf)"
mkdir -p "$work/tools"
ln -s "$real_buf" "$work/tools/buf"
expect "relative BUF override is resolved before cd" 0 "proto baseline OK" -- \
  bash -c 'cd "$1" && BUF=./tools/buf bash "$2" "$3"' _ "$work" "$check" "$dir"

dir="$(fresh_copy other_buf_version)"
mkdir -p "$work/stub"
cat >"$work/stub/buf" <<STUB
#!/bin/sh
if [ "\$1" = "--version" ]; then echo 1.73.0; exit 0; fi
exec "$real_buf" "\$@"
STUB
chmod +x "$work/stub/buf"
expect "buf version mismatch fails before comparing" 2 "buf version 1.73.0, baseline built with 1.74.0" -- \
  env BUF="$work/stub/buf" bash "$check" "$dir"

# The checker gets a TMPDIR of its own: counting entries in the shared TMPDIR races every other run of
# the checker on the machine. A buf that logs its -o path shows the build output went there.
dir="$(fresh_copy clean_tmp)"
own_tmp="$work/clean_tmp/tmpdir"
outputs="$work/clean_tmp/build-outputs"
mkdir -p "$own_tmp" "$work/logbuf"
cat >"$work/logbuf/buf" <<STUB
#!/bin/sh
if [ "\$1" = build ] && [ "\$2" = -o ]; then printf '%s\n' "\$3" >>"$outputs"; fi
exec "$real_buf" "\$@"
STUB
chmod +x "$work/logbuf/buf"
expect "check passes with its own TMPDIR" 0 "proto baseline OK" -- \
  env TMPDIR="$own_tmp" BUF="$work/logbuf/buf" bash "$check" "$dir"
built="$(cat "$outputs" 2>/dev/null || true)"
left="$(find "$own_tmp" -mindepth 1 | wc -l | tr -d ' ')"
if [[ "$(wc -l <"$outputs" 2>/dev/null | tr -d ' ')" == 1 && "$built" == "$own_tmp/check-proto-baseline."*/v1.binpb \
  && ! -e "$built" && "$left" == 0 ]]; then
  pass=$((pass + 1)); echo "ok   temp build output is removed"
else
  fail=$((fail + 1)); echo "FAIL temp build output is removed: built to '${built}', $left entries left in $own_tmp"
fi

echo "$pass passed, $fail failed"
[[ "$fail" == 0 ]]
