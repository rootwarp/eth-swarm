#!/usr/bin/env bash
# CI hardening gate for GitHub Actions workflows. The rules (and their tests) live in
# crates/ci-checks/src/lib.rs, which parses each workflow as YAML; this wrapper builds and
# runs that checker from the locked workspace.
# Usage: check-workflows.sh [DIR]   (default: .github/workflows of this repo)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$root/.github/workflows}"
[[ "$dir" == /* ]] || dir="$PWD/$dir"
exec cargo run --quiet --locked --manifest-path "$root/Cargo.toml" \
  -p ci-checks --bin check-workflows -- "$dir"
