#!/usr/bin/env bash
# Fail if a workflow `run:` step can call cargo without `--locked`, so CI never resolves
# dependencies past the committed Cargo.lock (bench/verify-ipc's own lockfile included).
#
# The rules (and their tests) live in crates/ci-checks/src/locked.rs. That checker reads each
# workflow and composite action with a YAML parser and fails closed: a line that can run cargo
# and holds a quote, a backslash, a continuation, a substitution, a glob or a redirect other
# than a trailing `2>&1` fails, unless a reviewed allow-list entry names that exact line. It
# also checks `shell:` templates, CARGO_ALIAS_ keys and the aliases of the repository's cargo
# config files. An oracle test runs generated lines in bash with a stub cargo (and a sample
# with real cargo) and finds no line that the check passes but that runs cargo unlocked. This
# wrapper builds and runs that checker from the locked workspace.
#
# Usage: scripts/check-locked.sh [FILE|DIR...]   (default: this repository: .github/workflows,
#        .github/actions and every .cargo/config(.toml); a directory contributes its *.yml and
#        *.yaml files and each action.yml and action.yaml below it)
# Exit: 0 clean, 1 a cargo command without --locked, 2 nothing to check, 3 the scan failed
#       (the checker did not build or run, or a file could not be read).
# Works on bash 3.2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
(($# > 0)) || set -- --repo "$root"

rc=0
cargo run --quiet --locked --manifest-path "$root/Cargo.toml" \
  -p ci-checks --bin check-locked -- "$@" || rc=$?
case $rc in
  0 | 1 | 2 | 3) exit "$rc" ;;
  *) echo "ERROR: the check-locked checker did not run (exit $rc)"; exit 3 ;;
esac
