#!/usr/bin/env bash
# Breaking-change gate for proto/. Against the frozen baseline until git main exists.
set -euo pipefail
cd "$(dirname "$0")/../proto"
if git rev-parse --verify -q main >/dev/null 2>&1; then
  buf breaking --against "../.git#branch=main,subdir=proto"
else
  buf breaking --against .baseline/v1.binpb
fi
