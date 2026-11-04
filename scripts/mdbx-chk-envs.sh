#!/usr/bin/env bash
# Runs mdbx_chk on store envs that hold real written data, and fails on any error or warning
# (#130 A5, #295).
#
# With no ENV_DIR, fills a fresh env in a temp directory with
# crates/cl-chain-columns/examples/fill_env.rs and checks that: blocks through
# store_schema::blocks::put with a new stamp in each commit, then column sidecars written
# through cl-chain-columns' ColumnWriter (16 per txn, each carrying the stamp) and a prune
# through ColumnWriter::prune_finalized. Each ENV_DIR given is checked as it is instead
# (scripts/tests/mdbx-chk-envs.test.sh passes a corrupted one). mdbx_chk is MDBX_CHK if set,
# else built by scripts/build-mdbx-chk.sh from the pinned libmdbx sources. Each env is checked
# with `mdbx_chk -v` (read-only; the full b-tree, GC and meta walk), its stdout and stderr
# printed. The run fails on a nonzero exit from it (errors), on a line of its output that
# starts with " ~ " (a warning: mdbx_chk 0.12.13 prints libmdbx's warnings so and does not
# count them, so it still exits 0), or on a failure to fill the env.
#
# Usage: scripts/mdbx-chk-envs.sh [ENV_DIR...]
# Env: MDBX_CHK (a built mdbx_chk), CARGO (default `cargo`), CARGO_TARGET_DIR.
# Exit: 0 every env checked clean, 1 otherwise.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
cargo=${CARGO:-cargo}

chk=${MDBX_CHK:-}
if [[ -z $chk ]]; then
  rc=0
  built=$(bash "$here/build-mdbx-chk.sh") || rc=$?
  printf '%s\n' "$built"
  if ((rc != 0)); then
    echo "ERROR: building mdbx_chk failed (exit $rc)"
    exit 1
  fi
  chk=$(printf '%s\n' "$built" | tail -n 1)
fi
if [[ ! -x $chk ]]; then
  echo "ERROR: mdbx_chk $chk is not an executable"
  exit 1
fi

tmp=""
if (($# == 0)); then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  rc=0
  "$cargo" run --quiet --locked --manifest-path "$root/Cargo.toml" -p cl-chain-columns \
    --example fill_env -- "$tmp/env" || rc=$?
  if ((rc != 0)); then
    echo "ERROR: fill_env failed (exit $rc)"
    exit 1
  fi
  set -- "$tmp/env"
fi

status=0
for env in "$@"; do
  rc=0
  out=$("$chk" -v "$env" 2>&1) || rc=$?
  printf '%s\n' "$out"
  if ((rc != 0)); then
    echo "ERROR: mdbx_chk found errors in $env (exit $rc)"
    status=1
  elif grep -q '^ ~ ' <<<"$out"; then
    echo "ERROR: mdbx_chk reported warnings in $env (lines starting with \" ~ \" above)"
    status=1
  else
    echo "mdbx_chk OK: $env"
  fi
done
exit "$status"
