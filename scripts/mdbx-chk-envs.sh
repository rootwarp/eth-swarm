#!/usr/bin/env bash
# Runs mdbx_chk on store envs that hold real written data, and fails on any error (#130 A5).
#
# With no ENV_DIR, fills a fresh env in a temp directory with
# crates/store-schema/examples/fill_env.rs (blocks through blocks::put, a stamp in every
# commit, column sidecars in 16-column txns, a prune) and checks that. Each ENV_DIR given is
# checked as it is instead (scripts/tests/mdbx-chk-envs.test.sh passes a corrupted one).
# mdbx_chk is MDBX_CHK if set, else built by scripts/build-mdbx-chk.sh from the pinned libmdbx
# sources. Each env is checked with `mdbx_chk -v` (read-only; the full b-tree, GC and meta
# walk); a nonzero exit from it, or from filling the env, fails the run.
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
  "$cargo" run --quiet --locked --manifest-path "$root/Cargo.toml" -p store-schema \
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
  "$chk" -v "$env" || rc=$?
  if ((rc != 0)); then
    echo "ERROR: mdbx_chk found errors in $env (exit $rc)"
    status=1
  else
    echo "mdbx_chk OK: $env"
  fi
done
exit "$status"
