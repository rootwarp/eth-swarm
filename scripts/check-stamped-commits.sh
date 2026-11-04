#!/usr/bin/env bash
# Fail if a write transaction of the store env can commit without its stamp row (#130, #295).
#
# Every write transaction of the env commits through store_schema::txn::commit, which writes
# the head/finalized stamp row in the same transaction (crates/store-schema/src/txn.rs); the
# writer's open commits through txn::commit_open, which applies the same no-stamp rules. This
# check finds a raw commit, or that open path used elsewhere, in the crates that write the env:
#   - Files: every *.rs under crates/store-schema/src, crates/cl-chain-columns/src and
#     crates/cl-chain/src, except crates/store-schema/src/txn.rs, the one place that commits
#     raw (and defines commit_open).
#   - A raw commit is a hit:
#       a method call `.commit(`;
#       a path to `commit` other than `txn::commit`: `RwTxn::commit(`, `Transaction::commit(`,
#         `libmdbx::Transaction::commit(`, `Transaction::<RW, NoWriteMap>::commit(` (any
#         `<path>::commit` or `<...>::commit`, called or passed as a value);
#       `commit_and_rebind_open_dbs`, as a method or a path.
#     Spaces are allowed around `.`, `::` and before `(`. A read-only txn needs no commit, so
#     the rule does not tell the two apart. `txn::commit(` (also `crate::txn::commit(`,
#     `store_schema::txn::commit(`) is not a hit.
#   - `commit_open` is a hit anywhere (called, imported with `use`, or named) unless the file is
#     exactly crates/store-schema/src/env.rs: its one caller is env::open_writer_with.
#   - Skipped: comment lines (first non-blank characters `//`), and test modules: from a
#     `#[cfg(test)]` line directly followed by `mod tests {` (or `pub(crate) mod tests {`) to
#     the `}` at that line's indentation. Nothing else is exempt, a `#[cfg(test)]` helper fn
#     outside the tests module included.
#   - A directory that is missing fails: the check never passes vacuously.
#
# Usage: scripts/check-stamped-commits.sh [repo-root]   (default: this repo)
# Exit: 0 clean, 1 a hit (listed as file:line) or a missing directory.
# Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
dirs="crates/store-schema/src crates/cl-chain-columns/src crates/cl-chain/src"
allowed=crates/store-schema/src/txn.rs
open_caller=crates/store-schema/src/env.rs

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

# Each line is padded with a space at both ends, so "not an identifier character" also matches
# at the line's start and end (no `^`/`$` inside groups, which not every awk takes).
hits=$(awk -v open_caller="$open_caller" '
  FNR == 1 { skip = 0; prev = "" }
  {
    if (!skip && prev ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ &&
        $0 ~ /^[[:space:]]*(pub(\(crate\))?[[:space:]]+)?mod tests[[:space:]]*\{[[:space:]]*$/) {
      skip = 1
      match($0, /^[[:space:]]*/)
      close_line = substr($0, 1, RLENGTH) "}"
    } else if (skip) {
      if ($0 == close_line) skip = 0
    } else if ($0 !~ /^[[:space:]]*\/\//) {
      line = " " $0 " "
      # txn::commit is the stamped commit: drop it before looking for a path to commit.
      gsub(/[^A-Za-z0-9_]txn[[:space:]]*::[[:space:]]*commit[^A-Za-z0-9_]/, " ", line)
      if (line ~ /\.[[:space:]]*commit[[:space:]]*\(/ ||
          line ~ /::[[:space:]]*commit[^A-Za-z0-9_]/ ||
          line ~ /[^A-Za-z0-9_]commit_and_rebind_open_dbs[^A-Za-z0-9_]/ ||
          (FILENAME != open_caller && line ~ /[^A-Za-z0-9_]commit_open[^A-Za-z0-9_]/)) {
        print FILENAME ":" FNR ": " $0
      }
    }
    prev = $0
  }
' "${files[@]}")

if [[ -n $hits ]]; then
  echo "ERROR: a raw commit of a write transaction, or txn::commit_open outside $open_caller;" \
    "commit through store_schema::txn::commit (Update::New or Update::Carry), which writes the" \
    "stamp row:"
  printf '%s\n' "$hits"
  exit 1
fi
echo "stamped commits OK (${#files[@]} files; only $allowed commits a write transaction," \
  "only $open_caller calls txn::commit_open)"
