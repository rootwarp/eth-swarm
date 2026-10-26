#!/usr/bin/env bash
# Fail if state-transition, crypto-bls or blst is a normal dependency of cl-verify-cache.
#
# cl-verify-cache is a leaf crate: the pubkey caches of cl-verify, with no BLS library and no
# state transition. The caller decodes keys (`KeyCodec`, the `K` of the caches). Its builder-key
# tests drive the real state transition and check real BLS signatures, so state-transition,
# crypto-bls and blst are dev-dependencies of the crate, and only that. This check reads the
# normal graph (`cargo tree -e normal`) with every feature on, on every target platform, so an
# optional dependency or a platform-specific one counts too. Build and dev dependencies do not
# count. The check also fails if the workspace has no cl-verify-cache package, so it can never
# pass vacuously.
#
# Usage: scripts/check-verify-cache-deps.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}
package=cl-verify-cache

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
tree=$("$cargo" tree --locked -p "$package" -e normal --all-features --target all \
  --prefix none --format '{p}' --manifest-path "$manifest") || rc=$?
if ((rc != 0)) || [[ $tree != *"$package v"* ]]; then
  echo "ERROR: cargo tree -p $package failed (exit $rc):" >&2
  printf '%s\n' "$tree" >&2
  exit 1
fi
status=0
for name in state-transition crypto-bls blst; do
  found=$(printf '%s\n' "$tree" | grep -E "^$name v" | sort -u || true)
  if [[ -n $found ]]; then
    echo "ERROR: $name is a normal dependency of $package (a leaf crate; dev-dependency only):"
    printf '%s\n' "$found" | sed 's/^/  /'
    "$cargo" tree --locked -p "$package" -e normal --all-features --target all -i "$name" \
      --manifest-path "$manifest" 2>/dev/null | sed 's/^/  /' || true
    status=1
  fi
done
if ((status != 0)); then
  exit 1
fi
echo "$package deps OK (no state-transition, crypto-bls or blst in its normal dependency graph)"
