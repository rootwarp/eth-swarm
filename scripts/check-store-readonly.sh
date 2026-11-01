#!/usr/bin/env bash
# Fail if cl-store can open the store env for write (#130, A2).
#
# cl-chain is the env's one writer; cl-store opens it read-only (MDBX_RDONLY) and has no write
# RPC (proto/README.md). This check searches every file under crates/cl-store/ (tests and
# comments too: cl-store has no reason to name any of these) for a write entry point:
#   Mode::ReadWrite    a read-write libmdbx open
#   begin_rw_txn       a write transaction
#   open_writer        store_schema::env::open_writer / open_writer_with
#   ColumnWriter       cl-chain-columns' writer
# If crates/cl-store/ is absent there is nothing to check: the script says so and passes.
#
# Usage: scripts/check-store-readonly.sh [repo-root]   (default: this repo)
# Exit: 0 clean (or no crates/cl-store/), 1 a hit (listed as file:line) or grep failed.
# Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
dir=crates/cl-store
pattern='Mode::ReadWrite|begin_rw_txn|open_writer|ColumnWriter'

if [[ ! -d $dir ]]; then
  echo "store readonly OK ($dir does not exist: nothing to check)"
  exit 0
fi
rc=0
hits=$(grep -rnE -e "$pattern" "$dir") || rc=$?
if ((rc == 0)); then
  echo "ERROR: $dir names a write path of the env ($pattern); cl-store opens it read-only:"
  printf '%s\n' "$hits"
  exit 1
fi
if ((rc != 1)); then
  echo "ERROR: grep failed on $dir (exit $rc)"
  exit 1
fi
echo "store readonly OK (nothing under $dir matches $pattern)"
