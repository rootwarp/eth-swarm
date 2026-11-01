#!/usr/bin/env bash
# Tests for scripts/mdbx-chk-envs.sh and scripts/build-mdbx-chk.sh.
# Run: bash scripts/tests/mdbx-chk-envs.test.sh
# Builds mdbx_chk once from the pinned sources and fills one env with the fill_env example
# (needs cargo, a C compiler and the crates of Cargo.lock), then checks copies of that env:
# clean, and corrupted two ways, each of which must fail the run. The build script's pins
# are tested with a stub cargo and a failing compiler.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../mdbx-chk-envs.sh"
build="$here/../build-mdbx-chk.sh"
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0

# check <expect: pass|fail> <description> <text the output must contain> <command...>
check() {
  local expect=$1 desc=$2 want=$3 rc=0 out ok=0
  shift 3
  out=$("$@" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | tail -n 30 | sed 's/^/       /'
  fi
}

# corrupt <env> <first page> <pages> <byte, octal>: overwrites 4 KiB pages of its mdbx.dat.
corrupt() {
  head -c $(($3 * 4096)) /dev/zero | tr '\000' "\\$4" |
    dd of="$1/mdbx.dat" bs=4096 seek="$2" conv=notrunc status=none
}

bash "$build" "$tmp/bin" > "$tmp/build.log" 2>&1 || { cat "$tmp/build.log"; exit 1; }
chk="$tmp/bin/mdbx_chk"
check pass "the build names the pinned source and its VERSION.txt" "mdbx-sys-12.13.2/libmdbx" \
  cat "$tmp/build.log"
check pass "the binary is that libmdbx" "mdbx_chk version 0.12.13.5" "$chk" -V

cargo run --quiet --locked --manifest-path "$repo/Cargo.toml" -p store-schema \
  --example fill_env -- "$tmp/clean" > /dev/null
check pass "a filled env (blocks, stamps, columns) is clean" "mdbx_chk OK: $tmp/clean" \
  env MDBX_CHK="$chk" bash "$script" "$tmp/clean"

cp -R "$tmp/clean" "$tmp/btree"
corrupt "$tmp/btree" 3 512 245
check fail "b-tree pages overwritten" "mdbx_chk found errors in $tmp/btree" \
  env MDBX_CHK="$chk" bash "$script" "$tmp/btree"

cp -R "$tmp/clean" "$tmp/metas"
corrupt "$tmp/metas" 0 3 000
check fail "every meta page zeroed" "mdbx_chk found errors in $tmp/metas" \
  env MDBX_CHK="$chk" bash "$script" "$tmp/metas"

check fail "one clean env does not hide a corrupt one" "mdbx_chk OK: $tmp/clean" \
  env MDBX_CHK="$chk" bash "$script" "$tmp/clean" "$tmp/btree"

check fail "an MDBX_CHK that is not an executable" "is not an executable" \
  env MDBX_CHK="$tmp/absent" bash "$script" "$tmp/clean"

check pass "no ENV_DIR: fills its own env and checks it" "No error is detected" \
  env MDBX_CHK="$chk" bash "$script"

# build-mdbx-chk.sh's pins, with a stub cargo printing canned metadata.
mkdir -p "$tmp/stub" "$tmp/fake/libmdbx"
for f in mdbx_chk.c mdbx.c mdbx.h; do : > "$tmp/fake/libmdbx/$f"; done
echo 0.12.14.0 > "$tmp/fake/libmdbx/VERSION.txt"
stub() {
  printf '#!/bin/sh\necho %s\n' "'$1'" > "$tmp/stub/cargo"
  chmod +x "$tmp/stub/cargo"
}
stub '{"packages":[{"name":"mdbx-sys","version":"12.13.1","manifest_path":"/x/Cargo.toml"}]}'
check fail "build: another mdbx-sys version" "not the pinned 12.13.2" \
  env CARGO="$tmp/stub/cargo" bash "$build" "$tmp/out1"
stub '{"packages":[]}'
check fail "build: no mdbx-sys at all" "found 0" \
  env CARGO="$tmp/stub/cargo" bash "$build" "$tmp/out2"
stub "{\"packages\":[{\"name\":\"mdbx-sys\",\"version\":\"12.13.2\",\"manifest_path\":\"$tmp/fake/Cargo.toml\"}]}"
check fail "build: a VERSION.txt other than 0.12.13.5" "not 0.12.13.5" \
  env CARGO="$tmp/stub/cargo" bash "$build" "$tmp/out3"
check fail "build: a failing compiler" "" env CC=false bash "$build" "$tmp/out4"
check pass "build: a failed build leaves no binary" "" test ! -e "$tmp/out4/mdbx_chk"

echo "passed $passed, failed $failed"
((failed == 0))
