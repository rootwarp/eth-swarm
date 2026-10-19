#!/usr/bin/env bash
# Verifies a fuzz gate-2b file (fuzz/run-gate2b.sh) against this tree: fuzz/check-m2a-gate.sh
# with --gate gate2b. The file must say "gate": "gate2b-fuzz", list exactly gate 2b's target
# (column_contract), run to completion for >= 3600 s with executions, exit 0 and 0 crashes,
# 0 OOMs and 0 timeouts, from a clean tree whose gate-2b decoder key, limits, toolchain,
# cargo-fuzz and seed corpus are the file's, past its coverage floor, and no tool override. Its
# `head` must be a commit of this repository, an ancestor of HEAD, whose decoder key (computed
# from git at that commit) is the file's: the report names a commit that was fuzzed.
#
# Usage: fuzz/check-gate2b.sh <gate2b.json> | --print-key | --print-expected
# Exit: 0 valid, 1 invalid or stale, 2 usage error or the key cannot be computed.
# Works on bash 3.2.
set -euo pipefail
exec bash "$(dirname "$0")/check-m2a-gate.sh" --gate gate2b "$@"
