#!/usr/bin/env bash
# Regenerates fuzz/Cargo.lock from the root Cargo.lock. Run it whenever a fuzzed crate's
# dependencies change (a manifest under crates/ or the root Cargo.lock), then commit the lock;
# scripts/check-fuzz-lock.sh fails CI until the two agree and the fuzz lock satisfies its
# manifests.
#
# The new lock starts as the root lock plus the fuzz-only packages (libfuzzer-sys, arbitrary)
# of the current fuzz lock, so they keep their versions; `cargo metadata` in fuzz/ then drops
# every package the fuzz workspace does not use. Every shared package keeps its root version
# and source. Offline: every package must be in the local cargo cache (`cargo fetch --locked`
# in the root fetches the shared ones). Ends with scripts/check-fuzz-lock.sh.
#
# Usage: fuzz/regen-lock.sh [ROOT]   (default: this repo)
# Exit: 0 regenerated and checked, non-zero otherwise. Needs cargo and python3 >= 3.11.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=${1:-$(cd "$here/.." && pwd)}
lock="$root/fuzz/Cargo.lock"
[[ -f $root/Cargo.lock ]] || { echo "ERROR: $root/Cargo.lock missing"; exit 2; }

new=$(mktemp "$root/fuzz/Cargo.lock.XXXXXX")
trap 'rm -f "$new"' EXIT
# The fuzz-only names are scripts/check-fuzz-lock.sh's FUZZ_ONLY, less the fuzz crate itself
# (cargo writes its entry afresh).
python3 -I - "$root/Cargo.lock" "$lock" > "$new" <<'PY'
import re, sys
FUZZ_ONLY = {"libfuzzer-sys", "arbitrary"}
root = open(sys.argv[1]).read().rstrip("\n")
try:
    fuzz = open(sys.argv[2]).read()
except FileNotFoundError:
    fuzz = ""
print(root)
for block in re.split(r"\n(?=\[\[package\]\]\n)", fuzz)[1:]:
    name = re.search(r'^name = "([^"]+)"$', block, re.M)
    if name and name.group(1) in FUZZ_ONLY:
        print()
        print(block.rstrip("\n"))
PY
mv "$new" "$lock"
(cd "$root/fuzz" && cargo metadata --offline --format-version 1 >/dev/null)
bash "$here/../scripts/check-fuzz-lock.sh" "$root"
