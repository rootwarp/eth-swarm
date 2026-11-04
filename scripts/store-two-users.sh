#!/usr/bin/env bash
# Runs cl-store's read-only tests as a second OS user against a store env that another OS user
# wrote: reader::tests::cannot_write and reader::tests::env_permissions (#290).
#
# Run as root (the root-tests CI job). It builds cl-store's lib test binary and cl-chain-columns'
# fill_env example (the production writer paths, as scripts/mdbx-chk-envs.sh uses it), copies
# both into a fresh 0755 temp directory, and makes the env directory there, owned
# WRITER:GROUP with mode 0750 (GROUP: READER's primary group, the store group). fill_env fills
# it as WRITER (`sudo -u`). Then, as [5.43] has it, mdbx.dat is 0640 and mdbx.lck 0660, both
# in GROUP. The two tests run as READER (`sudo -u`), with CL_STORE_TWO_USER_ENV naming the
# env. Each prints a `two-user: <test> ok` line once it has checked that env as that user; the
# run fails unless both lines are there, so a test that skipped or was filtered out fails it.
#
# Usage: scripts/store-two-users.sh WRITER READER
# Env: CARGO (default `cargo`), SUDO (default `sudo`), CARGO_TARGET_DIR.
# Exit: 0 both tests passed as READER; 1 otherwise: not root, a user missing or root, one UID
#       for both, a failed build or fill, a failed or skipped test.
# Works on bash 3.2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cargo=${CARGO:-cargo}
sudo=${SUDO:-sudo}
tests="reader::tests::cannot_write reader::tests::env_permissions"

if (($# != 2)); then
  echo "usage: $0 WRITER READER"
  exit 1
fi
writer=$1 reader=$2
if [[ $(id -u) != 0 ]]; then
  echo "ERROR: run as root: it switches to $writer and $reader with $sudo -u"
  exit 1
fi
for user in "$writer" "$reader"; do
  uid=$(id -u "$user" 2>/dev/null) || { echo "ERROR: no user $user"; exit 1; }
  if [[ $uid == 0 ]]; then
    echo "ERROR: $user is root; the run needs two unprivileged users"
    exit 1
  fi
done
if [[ $(id -u "$writer") == "$(id -u "$reader")" ]]; then
  echo "ERROR: $writer and $reader are one user (UID $(id -u "$writer"))"
  exit 1
fi
group=$(id -g "$reader")
cd "$root"

# --color never: the path is parsed from this output, and CI sets CARGO_TERM_COLOR=always.
rc=0
out=$("$cargo" test --locked --manifest-path "$root/Cargo.toml" -p cl-store --lib --no-run --color never 2>&1) || rc=$?
printf '%s\n' "$out"
if ((rc != 0)); then
  echo "ERROR: building cl-store's tests failed (exit $rc)"
  exit 1
fi
bin=$(printf '%s\n' "$out" | sed -n 's/^ *Executable unittests src\/lib\.rs (\(.*\))$/\1/p' | tail -n 1)
if [[ -z $bin ]]; then
  echo "ERROR: cargo named no cl-store unittests executable"
  exit 1
fi
[[ $bin == /* ]] || bin="$root/$bin"
rc=0
"$cargo" build --locked --manifest-path "$root/Cargo.toml" -p cl-chain-columns --example fill_env || rc=$?
fill="${CARGO_TARGET_DIR:-$root/target}/debug/examples/fill_env"
if ((rc != 0)) || [[ ! -x $fill ]]; then
  echo "ERROR: building fill_env failed (exit $rc)"
  exit 1
fi

base=$(mktemp -d)
trap 'rm -rf "$base"' EXIT
chmod 0755 "$base"
cp "$bin" "$base/cl-store-tests"
cp "$fill" "$base/fill_env"
chmod 0755 "$base/cl-store-tests" "$base/fill_env"
env_dir="$base/env"
mkdir "$env_dir"
chown "$writer:$group" "$env_dir"
chmod 0750 "$env_dir"
cd "$base"

rc=0
"$sudo" -u "$writer" "$base/fill_env" "$env_dir" || rc=$?
if ((rc != 0)); then
  echo "ERROR: fill_env as $writer failed (exit $rc)"
  exit 1
fi
for file in mdbx.dat mdbx.lck; do
  if [[ ! -f $env_dir/$file ]]; then
    echo "ERROR: fill_env left no $file in $env_dir"
    exit 1
  fi
done
chgrp "$group" "$env_dir/mdbx.dat" "$env_dir/mdbx.lck"
chmod 0640 "$env_dir/mdbx.dat"
chmod 0660 "$env_dir/mdbx.lck"

rc=0
# shellcheck disable=SC2086 # $tests is the list of test names
out=$("$sudo" -u "$reader" env CL_STORE_TWO_USER_ENV="$env_dir" "$base/cl-store-tests" \
  --exact $tests --nocapture --test-threads=1 2>&1) || rc=$?
printf '%s\n' "$out"
if ((rc != 0)); then
  echo "ERROR: the tests failed as $reader (exit $rc)"
  exit 1
fi
for test in cannot_write env_permissions; do
  # libtest prints a test's output after its `test <name> ... `, on the same line.
  if ! grep -q "two-user: $test ok " <<<"$out"; then
    echo "ERROR: $test did not check the env as $reader (skipped, or filtered out)"
    exit 1
  fi
done
echo "store two-user OK: $writer wrote $env_dir, $reader read it and could not write it"
