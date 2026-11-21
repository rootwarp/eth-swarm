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
# The same rules hold for the `testing` feature of another package: the second argument names
# it (scripts/check-fork-choice-testing.sh checks `fork-choice/testing` this way).
#
# The rules hold for each package that cargo builds from a path: the workspace members, and the
# path crates outside the workspace directory, which `cargo metadata --no-deps` does not list.
# The check follows each path dependency of a member (any kind) and the normal and build path
# dependencies of an outside crate (cargo builds no dev-dependency of a package outside the
# workspace), and reads each outside crate with its own `cargo metadata --no-deps --offline`. So
# it resolves nothing and fetches nothing.
#
# Usage: scripts/check-stf-testing.sh [path/to/workspace/Cargo.toml] [package]
#   (default: this repo, and the package state-transition)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
package=${2:-state-transition}
cargo=${CARGO:-cargo}

rc=0
meta=$("$cargo" metadata --locked --no-deps --format-version 1 --manifest-path "$manifest") \
  || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc)" >&2
  exit 1
fi
printf '%s' "$meta" | python3 -I -c '
import sys, json, os, subprocess

OWNER, CARGO, FEATURE = sys.argv[1], sys.argv[2], "testing"
meta = json.load(sys.stdin)
pkgs = meta["packages"]

def real(path):
    return os.path.realpath(path)

# The path crates outside the workspace, reached through path dependencies.
seen = {real(p["manifest_path"]) for p in pkgs}
queue = [(p, True) for p in pkgs]
while queue:
    p, member = queue.pop()
    for d in p["dependencies"]:
        if d.get("path") is None or (d["kind"] == "dev" and not member):
            continue
        manifest = real(os.path.join(d["path"], "Cargo.toml"))
        if manifest in seen:
            continue
        seen.add(manifest)
        out = subprocess.run([CARGO, "metadata", "--no-deps", "--offline", "--format-version",
                              "1", "--manifest-path", manifest], capture_output=True, text=True)
        if out.returncode != 0:
            sys.exit("ERROR: cargo metadata failed for %s (exit %d):\n%s"
                     % (manifest, out.returncode, out.stderr))
        found = [q for q in json.loads(out.stdout)["packages"]
                 if real(q["manifest_path"]) == manifest]
        if len(found) != 1:
            sys.exit("ERROR: no package at %s" % manifest)
        pkgs.append(found[0])
        queue.append((found[0], False))

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
print("%s/%s OK (enabled by dev-dependencies only)" % (OWNER, FEATURE))
' "$package" "$cargo"
