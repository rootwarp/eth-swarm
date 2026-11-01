#!/usr/bin/env bash
# Builds mdbx_chk from the libmdbx sources that mdbx-sys =12.13.2 vendors: the same C sources
# the libmdbx crate links into every store binary (ADR-0009), never a distro package.
#
# Finds the mdbx-sys package with `cargo metadata --locked` (which also unpacks it into the
# cargo registry), so the source is exactly what Cargo.lock resolves. Fails unless that is
# mdbx-sys 12.13.2 and its libmdbx/VERSION.txt is 0.12.13.5. Compiles libmdbx/mdbx_chk.c with
# libmdbx/mdbx.c the way the vendored GNUmakefile builds its tools: C as -std=gnu11 -O2
# -pthread, MDBX_BUILD_OPTIONS -DNDEBUG=1, MDBX_BUILD_FLAGS defined (its config.h does that),
# linked with -lm -lrt. Prints the source directory and version it built from, then the binary.
#
# Usage: scripts/build-mdbx-chk.sh [OUT_DIR]
#   OUT_DIR defaults to $CARGO_TARGET_DIR/mdbx-chk, else target/mdbx-chk. The binary is
#   OUT_DIR/mdbx_chk, replaced only once the build succeeded.
# Env: CARGO (default `cargo`), CC (default `cc`). Needs python3; links -lrt, so Linux (the CI
# runners).
# Exit: 0 built, 1 the source is not the pinned one or the build failed.
# Works on bash 3.2.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"${CARGO_TARGET_DIR:-$root/target}/mdbx-chk"}
cargo=${CARGO:-cargo}
cc=${CC:-cc}
crate=mdbx-sys
crate_version=12.13.2
libmdbx_version=0.12.13.5

rc=0
meta=$("$cargo" metadata --locked --format-version 1 --manifest-path "$root/Cargo.toml") || rc=$?
if ((rc != 0)); then
  echo "ERROR: cargo metadata failed (exit $rc)"
  exit 1
fi
rc=0
manifest=$(printf '%s' "$meta" | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
found = [p for p in meta["packages"] if p["name"] == sys.argv[1]]
if len(found) != 1:
    sys.exit("ERROR: want exactly one %s package, found %d" % (sys.argv[1], len(found)))
if found[0]["version"] != sys.argv[2]:
    sys.exit("ERROR: %s is %s, not the pinned %s" % (sys.argv[1], found[0]["version"], sys.argv[2]))
print(found[0]["manifest_path"])
' "$crate" "$crate_version") || rc=$?
if ((rc != 0)); then
  echo "ERROR: $crate $crate_version not found in the locked graph"
  exit 1
fi
src="$(dirname "$manifest")/libmdbx"
for file in mdbx_chk.c mdbx.c mdbx.h VERSION.txt; do
  if [[ ! -f $src/$file ]]; then
    echo "ERROR: $src/$file missing"
    exit 1
  fi
done
version=$(tr -d '[:space:]' < "$src/VERSION.txt")
if [[ $version != "$libmdbx_version" ]]; then
  echo "ERROR: $src/VERSION.txt is $version, not $libmdbx_version"
  exit 1
fi

mkdir -p "$out"
tmp=$(mktemp "$out/mdbx_chk.XXXXXX")
trap 'rm -f "$tmp"' EXIT
"$cc" -std=gnu11 -O2 -pthread -DNDEBUG=1 \
  "-DMDBX_BUILD_FLAGS=\"scripts/build-mdbx-chk.sh -std=gnu11 -O2 -DNDEBUG=1\"" \
  "-I$src" "$src/mdbx_chk.c" "$src/mdbx.c" -lm -lrt -o "$tmp"
chmod 0755 "$tmp"
mv -f "$tmp" "$out/mdbx_chk"
trap - EXIT

echo "mdbx_chk source: $src"
echo "mdbx_chk libmdbx VERSION.txt: $version ($crate $crate_version)"
echo "$out/mdbx_chk"
