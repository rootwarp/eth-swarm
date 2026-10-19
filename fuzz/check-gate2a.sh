#!/usr/bin/env bash
# Verifies a fuzz gate-2a file (fuzz/run-gate2a.sh) against this tree: fuzz/check-m2a-gate.sh
# with --gate gate2a. The file must say "gate": "gate2a-fuzz", list exactly gate 2a's three
# targets, each run to completion for >= 3600 s with executions, exit 0 and 0 crashes, 0 OOMs
# and 0 timeouts, from a clean tree whose gate-2a decoder key, limits, toolchain, cargo-fuzz and
# seed corpora are the file's, every target past its coverage floor, and no tool override. Its
# `head` must be a commit of this repository, an ancestor of HEAD, whose decoder key (computed
# from git at that commit) is the file's: the report names a commit that was fuzzed.
#
# Usage: fuzz/check-gate2a.sh <gate2a.json> | --print-key | --print-expected
# Exit: 0 valid, 1 invalid or stale, 2 usage error or the key cannot be computed.
# Works on bash 3.2.
set -euo pipefail
exec bash "$(dirname "$0")/check-m2a-gate.sh" --gate gate2a "$@"
