#!/usr/bin/env bash
# Fail unless spec-tests is the only crate that turns on `crypto-bls/test-vectors`.
#
# The feature exposes sign/aggregate_signatures/aggregate_verify for the spec-vector `bls`
# runner. Anything that enables it (a normal or dev dependency, an optional feature, a
# crypto-bls feature that implies it, or a crate that pulls in spec-tests) gets those into
# its build. All features of every crate are on, so optional paths count too.
#
# Limit: this checks declared enables, not cargo's feature unification. Once spec-tests
# enables test-vectors, any build that includes spec-tests (e.g. `cargo build --workspace`)
# compiles crypto_bls::sign into every crate of that build, and this script does not list
# them. Release artifacts must therefore come from per-service builds; once service crates
# exist, CI must also build each one alone (`cargo build -p <svc> --locked`). That CI step
# is deferred until the service crates exist.
#
# Usage: scripts/check-bls-features.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Runs `cargo tree --locked`; set CARGO to choose the cargo binary. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}
allowed="spec-tests"

# Inverted feature tree rooted at crypto-bls. Below each `crypto-bls feature "X"` node are
# the packages and features that enable X, transitively. `--prefix depth` puts the depth
# before each line; `--no-dedupe` expands repeated subtrees so no enabler hides behind (*).
tree=$("$cargo" tree --locked --manifest-path "$manifest" --workspace --all-features \
  --target all -e features -i crypto-bls --no-dedupe --prefix depth)

# Every package name inside a `crypto-bls feature "test-vectors"` subtree, or the marker
# line `!missing` if the feature does not exist (the check would then be vacuous).
enablers=$(printf '%s\n' "$tree" | awk '
  match($0, /^[0-9]+/) {
    depth = substr($0, 1, RLENGTH) + 0
    node = substr($0, RLENGTH + 1)
    if (inside && depth <= inside_depth) inside = 0
    if (inside) { split(node, f, " "); print f[1]; next }
    if (node ~ /^crypto-bls feature "test-vectors"/) { seen = 1; inside = 1; inside_depth = depth }
  }
  END { if (!seen) print "!missing" }
' | sort -u)

if [[ $enablers == *'!missing'* ]]; then
  echo "ERROR: crypto-bls has no \`test-vectors\` feature; update scripts/check-bls-features.sh" >&2
  exit 1
fi

fail=0
while IFS= read -r name; do
  [[ -z $name || $name == crypto-bls || $name == "$allowed" ]] && continue
  echo "ERROR: crypto-bls/test-vectors enabled by $name (only $allowed may enable it)" >&2
  fail=1
done <<<"$enablers"

if [[ $fail != 0 ]]; then
  echo "--- cargo tree -e features -i crypto-bls" >&2
  printf '%s\n' "$tree" >&2
  exit 1
fi
echo "crypto-bls/test-vectors OK (only $allowed may enable it)"
