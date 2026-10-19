#!/usr/bin/env bash
# Fuzz gate 2b: the column handlers, fuzzed for an hour from gate 2a's seeds and the negative
# serving cases.
#
# Target (GATE2B_TARGETS in fuzz/m2a-common.sh): column_contract, cl-chain's storage contract
# and column store (ColumnIngest on a temp column env per input, a stub reference that vouches
# for fixed blocks, a stub cl-verify whose verdict comes from the input) and its column RPCs
# (ReqRespServer), driven with sequences of gossip sidecars and range and root requests; a
# sidecar the contract rejected must never come back in an answer. This is fuzz/run-m2a-gate.sh
# with --gate gate2b: the same build, environment refusals, limits (-rss_limit_mb=2048, which
# covers the column env's map, -malloc_limit_mb=128, -timeout=10, the per-target -max_len) and
# clean-tree rule, gate 2b's decoder key, and the gate file fuzz/artifacts/gate2b.json (log:
# gate2b.log beside it) recording the commit, the target's seconds, executions, crashes, OOMs,
# timeouts and seed-corpus sha256. fuzz/check-gate2b.sh verifies the file.
#
# Usage: fuzz/run-gate2b.sh [--seconds N] [--out FILE] [--log FILE] [--sequential] [--allow-dirty]
#   --seconds N  per target (default 3600, the gate; less is a smoke run the checker refuses)
# Exit: as fuzz/run-m2a-gate.sh (0 every target clean, 1 a finding, 2 usage or setup error).
# Works on bash 3.2.
set -euo pipefail
exec bash "$(dirname "$0")/run-m2a-gate.sh" --gate gate2b "$@"
