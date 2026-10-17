#!/usr/bin/env bash
# Fail if cl-chain links `crypto-bls/verify`. cl-chain may link only `crypto-bls/aggregate`
# (eth_aggregate_pubkeys); every signature check goes through cl-verify.
#
# Runs `cargo tree -p cl-chain -e features` with all of cl-chain's features on and every target,
# so an optional or platform-gated path that turns `verify` on counts too. `-e features` alone
# also follows dev and build dependencies. Selecting cl-chain alone (`-p`) keeps other crates'
# features out: spec-tests enabling `verify` does not leak into the check.
#
# The check reads the *resolved* feature set of every crypto-bls node (`--format '{p} {f}'`),
# not the `crypto-bls feature "verify"` edge lines: a feature that cl-chain itself turns on
# (`[features] x = ["crypto-bls/verify"]`) shows up only in the resolved set.
#
# Limit: this reads cl-chain's own resolve (`-p cl-chain`), not cargo's feature unification
# across a build. spec-tests enables `crypto-bls/verify` (and `test-vectors`), so any build that
# includes spec-tests (e.g. `cargo build --workspace`) compiles crypto-bls with `verify` for
# cl-chain too, and this script does not see it. Release artifacts must therefore come from
# per-service builds. Once cl-chain exists, CI must also run
# `cargo check -p cl-chain --all-targets --locked` on its own; that step is deferred until the
# cl-chain crate lands.
#
# Passes with a message while the workspace has no cl-chain package. A failed or empty
# `cargo tree` is not a pass.
#
# Usage: scripts/check-cl-chain-features.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}
package=cl-chain
forbidden='crypto-bls feature "verify"'

rc=0
meta=$("$cargo" metadata --locked --no-deps --format-version 1 --manifest-path "$manifest") || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc)" >&2
  exit 1
fi
present=$(printf '%s' "$meta" | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
print(any(p["name"] == sys.argv[1] and p["id"] in members for p in meta["packages"]))
' "$package")
if [[ $present != True ]]; then
  echo "$package is not in the workspace yet: nothing to check (crypto-bls/verify gate passes)"
  exit 0
fi

rc=0
tree=$("$cargo" tree --locked --manifest-path "$manifest" -p "$package" -e features \
  --all-features --target all --prefix none --no-dedupe --format '{p} {f}' 2>&1) || rc=$?
if ((rc != 0)) || [[ $tree != *"$package"* ]]; then
  echo "ERROR: cargo tree -p $package -e features failed (exit $rc):" >&2
  printf '%s\n' "$tree" >&2
  exit 1
fi
# `crypto-bls v0.1.0 (/path) aggregate,verify`: the last field lists the resolved features.
linked=$(awk '$1 == "crypto-bls" && $2 ~ /^v/ {
  n = split($NF, f, ",")
  for (i = 1; i <= n; i++) if (f[i] == "verify") { print "yes"; exit }
}' <<<"$tree")
if [[ $linked == yes ]] || grep -qF "$forbidden" <<<"$tree"; then
  echo "ERROR: $package links crypto-bls/verify; it may link only crypto-bls/aggregate." >&2
  echo "--- what enables it (cargo tree -p $package -e features -i crypto-bls)" >&2
  "$cargo" tree --locked --manifest-path "$manifest" -p "$package" -e features --all-features \
    --target all -i crypto-bls >&2 || true
  exit 1
fi
echo "$package does not link crypto-bls/verify"
