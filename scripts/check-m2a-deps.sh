#!/usr/bin/env bash
# Fail if discv5 is anywhere in the dependency graph the m2a-session binary links.
#
# m2a-session dials one pinned peer and must have no discovery at all, so no discv5 (and no
# crate that pulls it in) may be a normal dependency of cl-p2p, on any target platform.
# `cargo tree` has no --bin filter, but a binary links exactly its package's normal
# dependencies, so the graph of `cargo tree -p cl-p2p -e normal --target all` is the binary's.
# The check also fails if cl-p2p has no m2a-session binary, so it can never pass vacuously.
#
# Usage: scripts/check-m2a-deps.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}

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
pkgs = [p for p in meta["packages"] if p["name"] == "cl-p2p"]
if len(pkgs) != 1:
    sys.exit("ERROR: want exactly one cl-p2p package, found %d" % len(pkgs))
bins = [t["name"] for t in pkgs[0]["targets"] if "bin" in t["kind"]]
if "m2a-session" not in bins:
    sys.exit("ERROR: cl-p2p has no m2a-session binary (bins: %s)" % ", ".join(bins))
'

rc=0
tree=$("$cargo" tree --locked -p cl-p2p -e normal --target all --prefix none --format '{p}' \
  --manifest-path "$manifest") || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo tree failed (exit $rc)" >&2
  exit 1
fi
found=$(printf '%s\n' "$tree" | grep -E '^discv5 v' | sort -u || true)
if [[ -n $found ]]; then
  echo "ERROR: discv5 is a dependency of cl-p2p (m2a-session must have no discovery):"
  printf '%s\n' "$found" | sed 's/^/  /'
  "$cargo" tree --locked -p cl-p2p -e normal --target all -i discv5 --manifest-path "$manifest" \
    2>/dev/null | sed 's/^/  /' || true
  exit 1
fi
echo "m2a-session deps OK (no discv5 in cl-p2p's normal dependency graph)"
