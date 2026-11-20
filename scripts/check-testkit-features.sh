#!/usr/bin/env bash
# Fail if a service links `testkit/test-support`.
#
# The feature makes testkit's test fixtures public: write-fault injection, the scripted
# collector clock and fixture beacon node (a hyper server), the export's fixture devnet and the
# anchor loader (`testkit::anchor`). A service that links it ships those fixtures, and the anchor
# loader checks the files and the roots of an anchor directory, not where the anchor comes from.
# The chain core tests use it, so only a `[dev-dependencies]` entry may turn it on.
#
# For each service (cl-chain, cl-store, cl-engine, cl-verify, cl-p2p, cl-discv5, cl-sync, cl-api)
# this runs `cargo tree -p <service> -e normal,build,features` with all of the service's
# features on and every target. Without the dev edges, cargo resolves the features as for a
# build of the service, so a dev-dependency that turns the feature on does not count, but a
# normal or a build dependency, a crate in between, a service feature that forwards to it, or a
# testkit default that implies it does. The check reads the resolved feature set of each testkit
# node (`--format '{p} {f}'`) and the feature edge lines.
#
# Each service must be in the workspace: a service that is gone or renamed fails, so that the
# list does not go stale without notice. testkit must have a `test-support` feature. Other
# packages are not checked: devnet-probe, a test tool for a local devnet, turns the feature on
# through its own `test-support` feature, for its tests.
#
# Limit (as for scripts/check-cl-chain-features.sh): this reads each service's own resolve, not
# the feature unification of one build of several packages. Release artifacts come from
# per-service builds. A failed or empty `cargo tree` is not a pass.
#
# Usage: scripts/check-testkit-features.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}
services="cl-chain cl-store cl-engine cl-verify cl-p2p cl-discv5 cl-sync cl-api"
forbidden='testkit feature "test-support"'

rc=0
meta=$("$cargo" metadata --locked --no-deps --format-version 1 --manifest-path "$manifest") || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc)" >&2
  exit 1
fi
# shellcheck disable=SC2086 # the service names are words
printf '%s' "$meta" | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
names = {p["name"]: p for p in meta["packages"] if p["id"] in members}
errors = []
testkit = names.get("testkit")
if testkit is None:
    errors.append("no testkit package in the workspace")
elif "test-support" not in testkit["features"]:
    errors.append("testkit has no test-support feature; update scripts/check-testkit-features.sh")
for service in sys.argv[1:]:
    if service not in names:
        errors.append("service %s is not in the workspace; update scripts/check-testkit-features.sh"
                      % service)
for e in errors:
    print("ERROR: " + e, file=sys.stderr)
sys.exit(1 if errors else 0)
' $services

failed=0
for service in $services; do
  rc=0
  tree=$("$cargo" tree --locked --manifest-path "$manifest" -p "$service" -e normal,build,features \
    --all-features --target all --prefix none --format '{p} {f}' 2>&1) || rc=$?
  if ((rc != 0)) || [[ $tree != *"$service"* ]]; then
    echo "ERROR: cargo tree -p $service -e normal,build,features failed (exit $rc):" >&2
    printf '%s\n' "$tree" >&2
    exit 1
  fi
  # `testkit v0.1.0 (/path) mock-el,test-support`: the last field lists the resolved features.
  linked=$(awk '$1 == "testkit" && $2 ~ /^v/ {
    n = split($NF, f, ",")
    for (i = 1; i <= n; i++) if (f[i] == "test-support") { print "yes"; exit }
  }' <<<"$tree")
  if [[ $linked == yes ]] || grep -qF "$forbidden" <<<"$tree"; then
    echo "ERROR: $service links testkit/test-support; only dev-dependencies may enable it." >&2
    echo "--- what enables it (cargo tree -p $service -e normal,build,features -i testkit)" >&2
    "$cargo" tree --locked --manifest-path "$manifest" -p "$service" -e normal,build,features \
      --all-features --target all -i testkit >&2 || true
    failed=1
  fi
done
if ((failed)); then
  exit 1
fi
echo "no service links testkit/test-support ($services)"
