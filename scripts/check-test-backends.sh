#!/usr/bin/env bash
# Fail unless cl-verify's own dev-dependency on itself is the only thing that turns on
# `cl-verify/test-backends`.
#
# The feature exposes `VerifyServer::with_backends*` and the `KzgBackend` trait, which build a
# server over any KZG verifier. Without it the only constructor is `VerifyServer::new`, whose KZG
# backend is loaded through `load_pinned` with BETA4_MAINNET_SHA256 (scripts/check-setup-pin.sh).
# So the feature must not be a default, must not be implied by another cl-verify feature, and no
# other crate may enable it through a dependency (normal, dev or build) or one of its features.
#
# Usage: scripts/check-test-backends.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}

rc=0
meta=$("$cargo" metadata --locked --no-deps --format-version 1 --manifest-path "$manifest") \
  || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc)" >&2
  exit 1
fi
printf '%s' "$meta" | python3 -I -c '
import sys, json

FEATURE = "test-backends"
meta = json.load(sys.stdin)
pkgs = meta["packages"]
owner = [p for p in pkgs if p["name"] == "cl-verify"]
if len(owner) != 1:
    sys.exit("ERROR: want exactly one cl-verify package, found %d" % len(owner))
owner = owner[0]
if FEATURE not in owner["features"]:
    sys.exit("ERROR: cl-verify has no test-backends feature; update scripts/check-test-backends.sh")

errors = []
for name, enables in owner["features"].items():
    if name != FEATURE and FEATURE in enables:
        errors.append("cl-verify feature %s implies %s" % (name, FEATURE))
for p in pkgs:
    for d in p["dependencies"]:
        if d["name"] != "cl-verify" or FEATURE not in d["features"]:
            continue
        if p["name"] == "cl-verify" and d["kind"] == "dev":
            continue
        errors.append("cl-verify/%s enabled by %s (%s dependency)" % (FEATURE, p["name"], d["kind"] or "normal"))
    if p["name"] == "cl-verify":
        continue
    for name, enables in p["features"].items():
        if any(e in ("cl-verify/" + FEATURE, "cl-verify?/" + FEATURE) for e in enables):
            errors.append("cl-verify/%s enabled by %s (feature %s)" % (FEATURE, p["name"], name))

for e in errors:
    print("ERROR: " + e, file=sys.stderr)
if errors:
    sys.exit(1)
print("test-backends OK (only cl-verify'"'"'s own tests enable it)")
'
