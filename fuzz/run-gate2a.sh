#!/usr/bin/env bash
# Fuzz gate 2a: the column decoders, each fuzzed for an hour on the oversize and bomb seeds.
#
# Targets (GATE2A_TARGETS in fuzz/m2a-common.sh): data_column_sidecar (the Gloas
# DataColumnSidecar as a gossip message and as a response chunk of both column protocols, on the
# pinned Sepolia blob schedule's caps), columns_by_range_req and columns_by_root_req (the two
# column requests through the timed codec, then the admission check). This is
# fuzz/run-m2a-gate.sh with --gate gate2a: the same build, environment refusals, limits
# (-rss_limit_mb=2048, -malloc_limit_mb=128, -timeout=10, the per-target -max_len) and
# clean-tree rule, gate 2a's decoder key, and the gate file fuzz/artifacts/gate2a.json (log:
# gate2a.log beside it) recording the commit, every target's seconds, executions, crashes, OOMs,
# timeouts and seed-corpus sha256. fuzz/check-gate2a.sh verifies the file.
#
# Usage: fuzz/run-gate2a.sh [--seconds N] [--out FILE] [--log FILE] [--sequential] [--allow-dirty]
#   --seconds N  per target (default 3600, the gate; less is a smoke run the checker refuses)
# Exit: as fuzz/run-m2a-gate.sh (0 every target clean, 1 a finding, 2 usage or setup error).
# Works on bash 3.2.
set -euo pipefail
exec bash "$(dirname "$0")/run-m2a-gate.sh" --gate gate2a "$@"
