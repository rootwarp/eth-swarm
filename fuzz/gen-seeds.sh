#!/usr/bin/env bash
# Regenerates fuzz/corpus from the p2p-wire encoder and the beta.4 mainnet ssz_static vectors.
# Usage: fuzz/gen-seeds.sh [VECTORS_DIR]   (default SPEC_VECTORS_DIR, else target/spec-vectors)
# fuzz/tests/corpus.rs fails if the committed corpus differs from what this writes.
set -euo pipefail
cd "$(dirname "$0")"
exec cargo ${FUZZ_TOOLCHAIN:+"+$FUZZ_TOOLCHAIN"} run --quiet --locked --example gen-seeds -- "$@"
