#!/usr/bin/env bash
# Fail unless `fork-choice/testing` is enabled only through dev-dependencies.
#
# The feature makes `fork_choice::testing` public: seams that change the store without the
# checks of the handlers that they stand for (`mark_payload_verified`, `set_latest_message`,
# `add_equivocating_index`). A service that links the feature could put a payload, a vote or an
# equivocation in its store that no handler checked. The rules are those of
# scripts/check-stf-testing.sh, for the package fork-choice: no default, no other feature
# that implies it, and only a `[dev-dependencies]` entry (any name or target) may enable it.
#
# Usage: scripts/check-fork-choice-testing.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
exec bash "$here/check-stf-testing.sh" "${1:-$here/../Cargo.toml}" fork-choice
