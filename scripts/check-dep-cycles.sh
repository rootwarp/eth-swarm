#!/usr/bin/env bash
# Fail if the workspace crates form a dependency cycle over any edge kind.
#
# Cargo itself refuses cycles of normal dependencies, but it accepts one that closes through a
# dev or build dependency (a dev-depends on b, b depends on a). Such a cycle still ties the two
# crates together, so this check reads the resolve graph of `cargo metadata` (every target,
# every edge kind, every feature on, so optional dependencies count) restricted to workspace
# members and prints each cycle it finds. A crate's dev-dependency on itself (the usual way to
# enable a test-only feature for its own integration tests) is not counted.
#
# Usage: scripts/check-dep-cycles.sh [path/to/workspace/Cargo.toml]   (default: this repo)
# Env: CARGO (default `cargo`). Needs python3. Works with bash 3.2.
set -euo pipefail

manifest=${1:-"$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"}
cargo=${CARGO:-cargo}

rc=0
meta=$("$cargo" metadata --locked --all-features --format-version 1 --manifest-path "$manifest") \
  || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc); a cycle of normal dependencies fails here" >&2
  exit 1
fi
printf '%s' "$meta" | python3 -I -c '
import json, sys

meta = json.load(sys.stdin)
members = set(meta["workspace_members"])
names = {p["id"]: p["name"] for p in meta["packages"]}
if not meta.get("resolve") or not members:
    sys.exit("ERROR: cargo metadata has no resolve graph or no workspace members")
def self_dev_edge(node_id, dep):
    # A crate dev-depending on itself (to turn on a test-only feature) ties no two crates together.
    return dep["pkg"] == node_id and all(k["kind"] == "dev" for k in dep["dep_kinds"])

edges = {}
for node in meta["resolve"]["nodes"]:
    if node["id"] in members:
        edges[node["id"]] = sorted(
            d["pkg"] for d in node["deps"]
            if d["pkg"] in members and not self_dev_edge(node["id"], d))

WHITE, GREY, BLACK = 0, 1, 2
color = dict.fromkeys(edges, WHITE)
cycles = []

def visit(start):
    # Iterative DFS; `path` is the grey chain from `start`.
    path, stack = [start], [iter(edges[start])]
    color[start] = GREY
    while stack:
        nxt = next(stack[-1], None)
        if nxt is None:
            color[path.pop()] = BLACK
            stack.pop()
        elif color[nxt] == GREY:
            cycles.append(path[path.index(nxt):] + [nxt])
        elif color[nxt] == WHITE:
            color[nxt] = GREY
            path.append(nxt)
            stack.append(iter(edges[nxt]))

for member in sorted(edges):
    if color[member] == WHITE:
        visit(member)

if cycles:
    for c in cycles:
        print("ERROR: dependency cycle: " + " -> ".join(names[i] for i in c), file=sys.stderr)
    sys.exit(1)
print(f"no dependency cycles among {len(edges)} workspace crates")
'
