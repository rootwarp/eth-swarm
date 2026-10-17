#!/usr/bin/env bash
# Fail unless the fuzz workspace (fuzz/, its own Cargo.lock) links exactly the dependencies the
# root workspace does, so the fuzzed decoder is the decoder the binaries ship.
#
# A [patch.crates-io] applies only in the workspace that declares it, so fuzz/Cargo.toml carries
# a copy of the root one (the sigp SSZ revs and the rust-libp2p commit). Checks:
#   - fuzz/Cargo.toml's [patch.crates-io] equals the root Cargo.toml's (as parsed TOML);
#   - every fuzz/Cargo.lock package other than the fuzz-only ones (FUZZ_ONLY below) appears in
#     the root Cargo.lock with the same name, version and source. A libp2p* or SSZ crate from
#     crates.io instead of the pinned git source, or a second version of anything, fails here;
#   - the fuzz-only packages come from crates.io (or are the fuzz crate itself);
#   - every dependency edge resolves, in its own lock, to exactly one package: a dependency
#     string is "name", "name version" or "name version (source)", as cargo writes it;
#   - every shared package's dependencies in fuzz/Cargo.lock are a subset of its dependencies in
#     the root Cargo.lock, compared as full (name, version, source) IDs. A subset, not equality:
#     the lockfile holds the optional dependencies some workspace member's features turn on, and
#     the root workspace has members (cl-sync, cl-api, ...) whose features the fuzz build never
#     enables, so the fuzz lock may lack an edge. It may never point an edge at another package
#     (another version, another source) or add one the root lock does not give that package.
# scripts/check-libp2p-revs.sh and scripts/check-ssz-revs.sh then vouch for the root lock, and
# so for both.
#
# Usage: scripts/check-fuzz-lock.sh [ROOT]   (default: this repo)
# Exit: 0 OK, 1 a mismatch, 2 a file is missing or does not parse. Needs python3 >= 3.11.
set -euo pipefail
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}

python3 -I - "$root" <<'PY'
import sys, tomllib
from pathlib import Path

# libFuzzer and its input crate; the fuzz crate itself has no source.
FUZZ_ONLY = {"ethswarm-fuzz", "libfuzzer-sys", "arbitrary"}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

root = Path(sys.argv[1])
def load(rel):
    try:
        with open(root / rel, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        print(f"ERROR: {rel}: {e}")
        sys.exit(2)

root_toml, fuzz_toml = load("Cargo.toml"), load("fuzz/Cargo.toml")
root_lock, fuzz_lock = load("Cargo.lock"), load("fuzz/Cargo.lock")
errors = []

want = root_toml.get("patch", {}).get("crates-io")
got = fuzz_toml.get("patch", {}).get("crates-io")
if want != got:
    names = sorted(set(want or {}) ^ set(got or {}) | {k for k in set(want or {}) & set(got or {}) if want[k] != got[k]})
    errors.append(f"fuzz/Cargo.toml [patch.crates-io] differs from the root Cargo.toml's: {', '.join(names) or 'missing'}")

def key(p):
    return (p["name"], p["version"], p.get("source"))

def show(k):
    """name version, with the source unless it is crates.io (or a path)."""
    return f"{k[0]} {k[1]}" + (f" ({k[2]})" if k[2] not in (None, REGISTRY) else "")

def edges(lock, label):
    """package ID -> set of dependency IDs, each dependency string resolved within `lock`."""
    pkgs = lock.get("package", [])
    by_name = {}
    for p in pkgs:
        by_name.setdefault(p["name"], []).append(key(p))
    out = {}
    for p in pkgs:
        deps = set()
        for d in p.get("dependencies", []):
            parts = d.split(" ", 2)
            name = parts[0]
            version = parts[1] if len(parts) > 1 else None
            source = parts[2][1:-1] if len(parts) > 2 and parts[2].startswith("(") and parts[2].endswith(")") else None
            if len(parts) > 2 and source is None:
                errors.append(f"{label}: {show(key(p))}: dependency {d!r} does not parse")
                continue
            hits = [k for k in by_name.get(name, [])
                    if (version is None or k[1] == version) and (source is None or k[2] == source)]
            if len(hits) != 1:
                what = "names no package" if not hits else f"matches {len(hits)} packages"
                errors.append(f"{label}: {show(key(p))}: dependency {d!r} {what}")
                continue
            deps.add(hits[0])
        out[key(p)] = deps
    return out

shared = {key(p) for p in root_lock.get("package", [])}
root_edges = edges(root_lock, "Cargo.lock")
fuzz_edges = edges(fuzz_lock, "fuzz/Cargo.lock")
for p in fuzz_lock.get("package", []):
    name, version, source = key(p)
    if name in FUZZ_ONLY:
        if source not in (None, REGISTRY):
            errors.append(f"fuzz/Cargo.lock: fuzz-only {name} {version} from {source}, want crates.io")
    elif (name, version, source) not in shared:
        errors.append(f"fuzz/Cargo.lock: {name} {version} ({source or 'path'}) is not in Cargo.lock")
    else:
        k = (name, version, source)
        for d in sorted(fuzz_edges.get(k, set()) - root_edges.get(k, set()), key=str):
            errors.append(f"fuzz/Cargo.lock: {show(k)} -> {show(d)}: not a dependency of {name} {version} in Cargo.lock")

if errors:
    for e in errors:
        print(f"ERROR {e}")
    sys.exit(1)
n = len(fuzz_lock.get("package", []))
n_edges = sum(len(v) for v in fuzz_edges.values())
print(f"fuzz lock OK: {n} packages and {n_edges} dependency edges, all but {sorted(FUZZ_ONLY)} resolved as in Cargo.lock")
PY
