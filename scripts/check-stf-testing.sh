#!/usr/bin/env bash
# Fail unless `state-transition/testing` is enabled only through dev-dependencies.
#
# The feature makes `state_transition::testing` public: test states, requests and bids, and
# signature backends without BLS. `ContractBackend` accepts each set without a BLS check, so a
# service that links the feature could verify invalid signatures as valid. The feature must not
# be a default, must not be implied by another state-transition feature, and a crate may enable
# it only in `[dev-dependencies]` (its own name or a rename, on any target). A normal or a build
# dependency (also target-specific) and a feature forward (`x = ["state-transition/testing"]`,
# `s/testing` or `s?/testing` for a rename `s = { package = "state-transition" }`) fail: a
# feature can forward only to a normal or a build dependency.
#
# Usage: scripts/check-stf-testing.sh [path/to/workspace/Cargo.toml]   (default: this repo)
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

OWNER, FEATURE = "state-transition", "testing"
meta = json.load(sys.stdin)
pkgs = meta["packages"]
owner = [p for p in pkgs if p["name"] == OWNER]
if len(owner) != 1:
    sys.exit("ERROR: want exactly one %s package, found %d" % (OWNER, len(owner)))
owner = owner[0]
if FEATURE not in owner["features"]:
    sys.exit("ERROR: %s has no %s feature; update scripts/check-stf-testing.sh" % (OWNER, FEATURE))

errors = []
for name, enables in owner["features"].items():
    if name != FEATURE and FEATURE in enables:
        errors.append("%s feature %s implies %s" % (OWNER, name, FEATURE))
for p in pkgs:
    deps = [d for d in p["dependencies"] if d["name"] == OWNER]
    for d in deps:
        if FEATURE in d["features"] and d["kind"] != "dev":
            errors.append("%s/%s enabled by %s (%s dependency)"
                          % (OWNER, FEATURE, p["name"], d["kind"] or "normal"))
    # A feature forwards through the dependency key, which a rename replaces.
    aliases = {d.get("rename") or d["name"] for d in deps}
    forwards = {a + sep + FEATURE for a in aliases for sep in ("/", "?/")}
    for name, enables in p["features"].items():
        if forwards.intersection(enables):
            errors.append("%s/%s enabled by %s (feature %s)" % (OWNER, FEATURE, p["name"], name))

for e in errors:
    print("ERROR: " + e, file=sys.stderr)
if errors:
    sys.exit(1)
print("state-transition/testing OK (enabled by dev-dependencies only)")
'
