#!/usr/bin/env bash
# Fail unless every direct normal dependency of store-schema is consensus-types, libmdbx or
# thiserror.
#
# store-schema is the MDBX env layout every store crate shares (ADR-008): its options, tables,
# keys and schema version. It stays that small, so its normal dependencies are fixed (#107):
# consensus-types, libmdbx and thiserror, nothing else (no tracing; logging belongs to its
# callers). Their own dependencies are theirs. The check reads the direct normal dependencies
# (`cargo tree -e normal --depth 1`) with every feature on, on every target platform, so an
# optional dependency or a platform-specific one counts too, and a renamed one shows under its
# package name. Build and dev dependencies do not count. The check also fails if the workspace
# has no store-schema package, so it can never pass vacuously.
#
# Usage: scripts/check-store-schema-deps.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}
package=store-schema
allowed="consensus-types libmdbx thiserror"

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
tree=$("$cargo" tree --locked -p "$package" -e normal --all-features --target all --depth 1 \
  --prefix none --format '{p}' --manifest-path "$manifest") || rc=$?
if ((rc != 0)) || [[ $tree != "$package v"* ]]; then
  echo "ERROR: cargo tree -p $package failed (exit $rc):" >&2
  printf '%s\n' "$tree" >&2
  exit 1
fi
status=0
# The first line is store-schema itself; every other line is one direct dependency.
while read -r name version _; do
  if [[ " $allowed " != *" $name "* ]]; then
    echo "ERROR: $name is a direct normal dependency of $package ($name $version;" \
      "allowed: $allowed)"
    status=1
  fi
done < <(printf '%s\n' "$tree" | tail -n +2 | sort -u)
if ((status != 0)); then
  exit 1
fi
echo "$package deps OK (direct normal dependencies within: $allowed)"
