#!/usr/bin/env bash
# Baseline-drift gate for proto/: the committed .baseline/v1.binpb must equal a fresh
# `buf build -o` of the current sources, so the committed baseline stays in sync with the sources
# (used by `buf-breaking.sh --baseline`).
#   bash scripts/check-proto-baseline.sh [PROTO_DIR]   (default: proto/ of this repo)
# Exit 0 = in sync, 1 = drift / missing baseline / build failure, 2 = usage or tooling error
# (bad proto dir, buf missing, buf version other than BASELINE_BUF_VERSION).
# Set BUF to use a specific buf binary (absolute, relative to the caller's cwd, or a name on PATH).
# The descriptor bytes depend on the buf version, so the version must equal BASELINE_BUF_VERSION;
# bump it together with a re-baseline built by the new buf. Runs offline.
set -euo pipefail

BASELINE_BUF_VERSION="1.74.0"

proto_dir="${1:-$(dirname "$0")/../proto}"
buf="${BUF:-buf}"
baseline_rel=".baseline/v1.binpb"

[[ -d "$proto_dir" ]] || { echo "ERROR: $proto_dir is not a directory" >&2; exit 2; }
# Resolve buf to an absolute path before the cd below, so a relative BUF keeps pointing at the same file.
buf_path="$(command -v "$buf" 2>/dev/null)" || { echo "ERROR: buf not found ($buf); install buf or set BUF" >&2; exit 2; }
case "$buf_path" in /*) ;; *) buf_path="$PWD/$buf_path" ;; esac
buf="$buf_path"

buf_version="$("$buf" --version 2>/dev/null)" || { echo "ERROR: '$buf --version' failed" >&2; exit 2; }
if [[ "$buf_version" != "$BASELINE_BUF_VERSION" ]]; then
  echo "ERROR: buf version $buf_version, baseline built with $BASELINE_BUF_VERSION; install buf $BASELINE_BUF_VERSION or set BUF" >&2
  exit 2
fi

cd "$proto_dir"
[[ -f "$baseline_rel" ]] || { echo "ERROR: baseline not found: $proto_dir/$baseline_rel" >&2; exit 1; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/check-proto-baseline.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

if ! "$buf" build -o "$tmp/v1.binpb"; then
  echo "ERROR: buf build failed in $proto_dir" >&2
  exit 1
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if ! cmp -s "$tmp/v1.binpb" "$baseline_rel"; then
  echo "ERROR: proto baseline drift: $baseline_rel differs from a fresh buf build" >&2
  echo "  committed: $(sha256 "$baseline_rel")" >&2
  echo "  fresh:     $(sha256 "$tmp/v1.binpb")" >&2
  echo "  Pre-v1 fix: run 'buf build -o $baseline_rel' in proto/ and commit it on its own" >&2
  echo "  with one line in the proto/README.md re-baseline log." >&2
  exit 1
fi

echo "proto baseline OK ($(sha256 "$baseline_rel"))"
