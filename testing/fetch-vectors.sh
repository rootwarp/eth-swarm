#!/usr/bin/env bash
# Fetch pinned test vectors by exact tag, verify sha256, and extract them.
# Exits non-zero on any mismatch or download failure.
# Usage: fetch-vectors.sh [MANIFEST] [DEST]
#   MANIFEST defaults to testing/vectors.manifest.toml (falls back to the .example)
#   DEST     defaults to target/spec-vectors
# Env: INCLUDE_OPTIONAL=1 to also fetch assets marked optional = true.
#      PRESETS="minimal general" to restrict consensus-specs assets by file stem.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
manifest="${1:-$here/vectors.manifest.toml}"
[[ -f "$manifest" ]] || manifest="$here/vectors.manifest.example.toml"
dest="${2:-${DEST:-target/spec-vectors}}"
include_optional="${INCLUDE_OPTIONAL:-0}"
presets="${PRESETS:-}"

command -v python3 >/dev/null || { echo "python3 (>=3.11, for tomllib) required" >&2; exit 2; }
command -v sha256sum >/dev/null || { echo "sha256sum required" >&2; exit 2; }

# Emit one tab-separated line per asset: name repo tag file sha256 optional
mapfile -t rows < <(python3 - "$manifest" <<'PY'
import sys, tomllib, re
m = tomllib.load(open(sys.argv[1], "rb"))
for s in m["source"]:
    if not re.fullmatch(r"v\d+\.\d+\.\d+([.-][0-9A-Za-z.]+)?", s["tag"]):
        sys.exit(f"tag {s['tag']!r} is not an exact version tag")
    for a in s["asset"]:
        h = a["sha256"]
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            sys.exit(f"{s['name']}/{a['file']}: sha256 missing or placeholder")
        print("\t".join([s["name"], s["repo"], s["tag"], a["file"], h, str(int(a.get("optional", False)))]))
PY
)

fail=0
for row in "${rows[@]}"; do
  IFS=$'\t' read -r name repo tag file sha opt <<<"$row"
  [[ "$opt" == 1 && "$include_optional" != 1 ]] && { echo "skip optional $name/$file"; continue; }
  if [[ -n "$presets" && "$name" == consensus-specs ]]; then
    [[ " $presets " == *" ${file%.tar.gz} "* ]] || { echo "skip preset $file"; continue; }
  fi
  outdir="$dest/$name/$tag"; mkdir -p "$outdir"
  archive="$outdir/$file"; stamp="$outdir/.${file}.ok"
  if [[ -f "$stamp" && "$(cat "$stamp")" == "$sha" ]]; then echo "cached $name/$tag/$file"; continue; fi
  url="https://github.com/$repo/releases/download/$tag/$file"
  echo "fetch $url"
  curl -fsSL --retry 3 -o "$archive.part" "$url"
  got="$(sha256sum "$archive.part" | cut -d' ' -f1)"
  if [[ "$got" != "$sha" ]]; then
    echo "SHA256 MISMATCH $name/$tag/$file: expected $sha got $got" >&2
    rm -f "$archive.part"; fail=1; continue
  fi
  mv "$archive.part" "$archive"
  rm -rf "$outdir/${file%.tar.gz}"; mkdir -p "$outdir/${file%.tar.gz}"
  tar -xzf "$archive" -C "$outdir/${file%.tar.gz}"
  rm -f "$archive"; echo "$sha" >"$stamp"
  echo "ok $name/$tag/$file"
done
exit "$fail"
