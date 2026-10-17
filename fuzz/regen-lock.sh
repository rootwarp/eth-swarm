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
# The new lock is built in a temp file and made mode 0644 (mktemp creates 0600). cargo has no
# stable way to resolve against a lockfile at another path, so the candidate is moved into
# place to be pruned and checked, with the old lock saved beside it: any failure (or an
# interrupt) puts the old lock back byte for byte, with its mode; only a lock that passes both
# `cargo metadata --offline` and scripts/check-fuzz-lock.sh stays.
#
# Usage: fuzz/regen-lock.sh [ROOT]   (default: this repo)
# Exit: 0 regenerated and checked, non-zero otherwise. Needs cargo and python3 >= 3.11.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=${1:-$(cd "$here/.." && pwd)}
lock="$root/fuzz/Cargo.lock"
[[ -f $root/Cargo.lock ]] || { echo "ERROR: $root/Cargo.lock missing"; exit 2; }

new=$(mktemp "$root/fuzz/Cargo.lock.new.XXXXXX")
saved=""
installed=0 done=0
restore() {
  if ((!done && installed)); then
    if [[ -n $saved ]]; then
      mv -f "$saved" "$lock"
      saved=""
    else
      rm -f "$lock"
    fi
    echo "ERROR: fuzz/regen-lock.sh failed; fuzz/Cargo.lock is unchanged" >&2
  fi
  rm -f "$new" ${saved:+"$saved"}
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
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
chmod 644 "$new"
if [[ -e $lock ]]; then
  saved=$(mktemp "$root/fuzz/Cargo.lock.saved.XXXXXX")
  cp -p "$lock" "$saved"
fi
installed=1
mv -f "$new" "$lock"
(cd "$root/fuzz" && cargo metadata --offline --format-version 1 >/dev/null)
bash "$here/../scripts/check-fuzz-lock.sh" "$root"
chmod 644 "$lock"
done=1
