#!/usr/bin/env bash
# Fuzz gate 1: the probe's peer-input decoders, each fuzzed for an hour on the bomb seeds.
#
# Targets (GATE1_TARGETS in fuzz/m2a-common.sh): rpc_chunk, gossip_transform, message_id,
# enr_fields, and the control decoders status_v2, metadata_v3 and ping_goodbye (Status, MetaData,
# Ping and Goodbye through the timed codec, both directions). This is fuzz/run-m2a-gate.sh with
# --gate gate1: the same build, environment refusals, limits (-rss_limit_mb=2048,
# -malloc_limit_mb=128, -timeout=10, the per-target -max_len) and clean-tree rule, gate 1's
# decoder key, and the gate file fuzz/artifacts/gate1.json (log: gate1.log beside it) recording
# the commit, every target's seconds, executions, crashes, OOMs, timeouts and seed-corpus
# sha256. fuzz/check-gate1.sh verifies the file.
#
# Usage: fuzz/run-gate1.sh [--seconds N] [--out FILE] [--log FILE] [--sequential] [--allow-dirty]
#   --seconds N  per target (default 3600, the gate; less is a smoke run the checker refuses)
# Exit: as fuzz/run-m2a-gate.sh (0 every target clean, 1 a finding, 2 usage or setup error).
# Works on bash 3.2.
set -euo pipefail
exec bash "$(dirname "$0")/run-m2a-gate.sh" --gate gate1 "$@"
