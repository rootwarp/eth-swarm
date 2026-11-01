#!/usr/bin/env bash
# Fail if a write transaction of the store env can commit without its stamp row (#130).
#
# Every write transaction of the env commits through store_schema::txn::commit, which writes
# the head/finalized stamp row in the same transaction (crates/store-schema/src/txn.rs). This
# check finds a raw commit anywhere else in the two crates that write the env:
#   - Files: every *.rs under crates/store-schema/src and crates/cl-chain-columns/src, except
#     crates/store-schema/src/txn.rs, the one place that calls it.
#   - A hit is a call of `commit` as a method or through the type: `.commit(` or
#     `Transaction::commit(`, spaces allowed before `(`. A read-only txn needs no commit, so
#     the rule does not tell the two apart. `txn::commit(` is not a hit.
#   - Skipped: comment lines (first non-blank characters `//`), and test modules: from a
#     `#[cfg(test)]` line directly followed by `mod tests {` (or `pub(crate) mod tests {`) to
#     the `}` at that line's indentation. Nothing else is exempt, a `#[cfg(test)]` helper fn
#     outside the tests module included.
#   - A directory that is missing fails: the check never passes vacuously.
#
# Usage: scripts/check-stamped-commits.sh [repo-root]   (default: this repo)
# Exit: 0 clean, 1 a raw commit (listed as file:line) or a missing directory.
# Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
dirs="crates/store-schema/src crates/cl-chain-columns/src"
allowed=crates/store-schema/src/txn.rs

files=()
for dir in $dirs; do
  if [[ ! -d $dir ]]; then
    echo "ERROR: $dir not found under $root"
    exit 1
  fi
  while IFS= read -r file; do
    [[ $file == "$allowed" ]] || files+=("$file")
  done < <(find "$dir" -type f -name '*.rs' | LC_ALL=C sort)
done
if ((${#files[@]} == 0)); then
  echo "ERROR: no Rust files under $dirs"
  exit 1
fi

hits=$(awk '
  FNR == 1 { skip = 0; prev = "" }
  {
    if (!skip && prev ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ &&
        $0 ~ /^[[:space:]]*(pub(\(crate\))?[[:space:]]+)?mod tests[[:space:]]*\{[[:space:]]*$/) {
      skip = 1
      match($0, /^[[:space:]]*/)
      close_line = substr($0, 1, RLENGTH) "}"
    } else if (skip) {
      if ($0 == close_line) skip = 0
    } else if ($0 !~ /^[[:space:]]*\/\// &&
               $0 ~ /(\.|Transaction::)[[:space:]]*commit[[:space:]]*\(/) {
      print FILENAME ":" FNR ": " $0
    }
    prev = $0
  }
' "${files[@]}")

if [[ -n $hits ]]; then
  echo "ERROR: a raw commit of a write transaction; commit through store_schema::txn::commit" \
    "(Update::New or Update::Carry), which writes the stamp row:"
  printf '%s\n' "$hits"
  exit 1
fi
echo "stamped commits OK (${#files[@]} files; only $allowed commits a write transaction)"
