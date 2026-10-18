#!/usr/bin/env bash
# Image pin gate for the Kurtosis devnet's ethereum-package args files: every image in
# testing/kurtosis/*.yaml (and *.yml) must be pinned as repo:tag@sha256:<64 hex>, and none may be
# left to a package default. The rules (and their tests) live in crates/ci-checks/src/kurtosis.rs,
# which parses each file as YAML; this wrapper builds and runs that checker from the locked
# workspace.
# Usage: check-kurtosis-pins.sh [DIR]   (default: testing/kurtosis of this repo)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$root/testing/kurtosis}"
[[ "$dir" == /* ]] || dir="$PWD/$dir"
exec cargo run --quiet --locked --manifest-path "$root/Cargo.toml" \
  -p ci-checks --bin check-kurtosis-pins -- "$dir"
