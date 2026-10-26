#!/usr/bin/env bash
# Fail if blst is anywhere in the dependency graph of state-transition.
#
# state-transition is the pure core of the state transition: no I/O and no BLS library.
# Signatures leave it as signature sets, and a backend the caller supplies checks them
# (cl-verify, or an in-process backend in the spec-vector runner). So no blst (and no crate
# that pulls it in, such as crypto-bls or c-kzg) may be in `cargo tree -p state-transition`:
# normal, build and dev dependencies, every feature, every target platform.
# The check also fails if the workspace has no state-transition package, so it can never pass
# vacuously.
#
# Usage: scripts/check-state-transition-deps.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}
package=state-transition

rc=0
meta=$("$cargo" metadata --locked --no-deps --format-version 1 --manifest-path "$manifest") \
  || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc)" >&2
  exit 1
fi
printf '%s' "$meta" | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
found = [p for p in meta["packages"] if p["name"] == sys.argv[1] and p["id"] in members]
if len(found) != 1:
    sys.exit("ERROR: want exactly one %s workspace package, found %d" % (sys.argv[1], len(found)))
' "$package"

rc=0
tree=$("$cargo" tree --locked -p "$package" -e normal,build,dev --all-features --target all \
  --prefix none --format '{p}' --manifest-path "$manifest") || rc=$?
if ((rc != 0)) || [[ $tree != *"$package v"* ]]; then
  echo "ERROR: cargo tree -p $package failed (exit $rc):" >&2
  printf '%s\n' "$tree" >&2
  exit 1
fi
found=$(printf '%s\n' "$tree" | grep -E '^blst v' | sort -u || true)
if [[ -n $found ]]; then
  echo "ERROR: blst is a dependency of $package (the pure core links no BLS library):"
  printf '%s\n' "$found" | sed 's/^/  /'
  "$cargo" tree --locked -p "$package" -e normal,build,dev --all-features --target all \
    -i blst --manifest-path "$manifest" 2>/dev/null | sed 's/^/  /' || true
  exit 1
fi
echo "$package deps OK (no blst in its normal, build or dev dependency graph)"
