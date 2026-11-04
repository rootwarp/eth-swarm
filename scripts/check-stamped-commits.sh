#!/usr/bin/env bash
# Fail if a write transaction of the store env can commit without its stamp row (#130, #295).
#
# Every write transaction of the env commits through store_schema::txn::commit, which writes
# the head/finalized stamp row in the same transaction (crates/store-schema/src/txn.rs); the
# writer's open commits through txn::commit_open, which applies the same no-stamp rules. The
# type system already keeps a raw commit out of other crates (store_schema::txn::RwTxn has no
# commit of its own); this check also finds one, or that open path used elsewhere, in source:
#   - Files: every *.rs under crates/*/src, every crate of the workspace, except
#     crates/store-schema/src/txn.rs, the one place that commits raw (and defines commit_open).
#     crates/store-schema, crates/cl-chain-columns and crates/cl-chain, the crates that write
#     the env, must exist: the check never passes vacuously.
#   - Each file is matched as a whole, so a call split across lines (`txn\n.commit()`,
#     `txn.commit\n()`, `txn.\ncommit()`, `Transaction::\ncommit(txn)`) is one call; the line
#     reported is the one the name (`commit`, `as`, `type`) is on.
#   - A raw commit is a hit:
#       a method call `.commit(`;
#       a path to `commit` other than `txn::commit`: `RwTxn::commit(`, `Transaction::commit(`,
#         `libmdbx::Transaction::commit(`, `Transaction::<RW, NoWriteMap>::commit(` (any
#         `<path>::commit` or `<...>::commit`, called or passed as a value);
#       `commit_and_rebind_open_dbs`, as a method or a path.
#     Spaces and newlines are allowed around `.`, `::` and before `(`. A read-only txn needs no
#     commit, so the rule does not tell the two apart. `txn::commit(` (also
#     `crate::txn::commit(`, `store_schema::txn::commit(`) is not a hit.
#   - A commit under another name is a hit: `commit as <name>` (a `use` that renames it, also
#     in a `{...}` group), `as commit`, `as txn` and `type txn` (a `txn` that is not
#     store-schema's module, whose `txn::commit(raw)` would read as the stamped commit).
#   - `commit_open` is a hit anywhere (called, imported with `use`, or named) unless the file is
#     exactly crates/store-schema/src/env.rs: its one caller is env::open_writer_with.
#   - Not an env txn: a `.commit(` or `<path>::commit` of another type (cl-verify-cache's
#     StagedSnapshot) is not a hit when its line, the one `commit` is on, ends with the comment
#     `// stamped-commits: not an env txn (<type>)`, naming the type. Nothing else is exempted
#     by it.
#   - Skipped: comment lines (first non-blank characters `//`), and test modules: from a
#     `#[cfg(test)]` line directly followed by `mod tests {` (or `pub(crate) mod tests {`) to
#     the `}` at that line's indentation. Nothing else is exempt, a `#[cfg(test)]` helper fn
#     outside the tests module included.
#
# Usage: scripts/check-stamped-commits.sh [repo-root]   (default: this repo)
# Exit: 0 clean, 1 a hit (listed as file:line) or a missing directory.
# Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
writers="crates/store-schema/src crates/cl-chain-columns/src crates/cl-chain/src"
allowed=crates/store-schema/src/txn.rs
open_caller=crates/store-schema/src/env.rs

for dir in $writers; do
  if [[ ! -d $dir ]]; then
    echo "ERROR: $dir not found under $root"
    exit 1
  fi
done
files=()
crates=0
for dir in crates/*/src; do
  [[ -d $dir ]] || continue
  crates=$((crates + 1))
  while IFS= read -r file; do
    [[ $file == "$allowed" ]] || files+=("$file")
  done < <(find "$dir" -type f -name '*.rs' | LC_ALL=C sort)
done
if ((${#files[@]} == 0)); then
  echo "ERROR: no Rust files under crates/*/src"
  exit 1
fi

# Each file's text is its lines, each padded with a space at both ends ("not an identifier
# character" then also matches at a line's start and end, with no `^`/`$` inside groups, which
# not every awk takes) and joined by newlines. Skipped lines stay as empty lines, so the line of
# a match is one more than the newlines before it.
hits=$(awk -v open_caller="$open_caller" '
  # The line of position `pos` of the text.
  function line_of(pos,   head) {
    head = substr(text, 1, pos - 1)
    return gsub(/\n/, "", head) + 1
  }
  # Marks the line of every match of `re` in `t` (same length as the text): the line of the
  # first letter of the match. A line with the not-an-env-txn marker is left out if `markable`.
  function find(t, re, markable,   off, start, len, k) {
    off = 0
    while (match(t, re)) {
      start = RSTART
      len = RLENGTH
      match(substr(t, start, len), /[A-Za-z]/)
      k = line_of(off + start + RSTART - 1)
      if (!(markable && marked[k])) hit[k] = 1
      off += start
      t = substr(t, start + 1)
    }
  }
  # `t` with every match of `re` (one identifier character each side) blanked, newlines kept.
  function blank(t, re,   out, seg) {
    out = ""
    while (match(t, re)) {
      seg = substr(t, RSTART + 1, RLENGTH - 2)
      gsub(/[^\n]/, " ", seg)
      out = out substr(t, 1, RSTART) seg
      t = substr(t, RSTART + RLENGTH - 1)
    }
    return out t
  }
  function scan(   t, k) {
    split("", hit)
    find(text, "[^A-Za-z0-9_]commit_and_rebind_open_dbs[^A-Za-z0-9_]", 0)
    if (file != open_caller) find(text, "[^A-Za-z0-9_]commit_open[^A-Za-z0-9_]", 0)
    find(text, "[^A-Za-z0-9_]commit[[:space:]]+as[^A-Za-z0-9_]", 0)
    find(text, "[^A-Za-z0-9_]as[[:space:]]+(commit|txn)[^A-Za-z0-9_]", 0)
    find(text, "[^A-Za-z0-9_]type[[:space:]]+txn[^A-Za-z0-9_]", 0)
    # txn::commit is the stamped commit: blanked before looking for a path to commit.
    t = blank(text, "[^A-Za-z0-9_]txn[[:space:]]*::[[:space:]]*commit[^A-Za-z0-9_]")
    find(t, "\\.[[:space:]]*commit[[:space:]]*\\(", 1)
    find(t, "::[[:space:]]*commit[^A-Za-z0-9_]", 1)
    for (k = 1; k <= n; k++) if (k in hit) print file ":" k ": " orig[k]
  }
  FNR == 1 {
    if (NR > 1) scan()
    file = FILENAME; text = ""; n = 0; skip = 0; prev = ""
    split("", orig); split("", marked)
  }
  {
    n++
    orig[n] = $0
    code = ""
    if (!skip && prev ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ &&
        $0 ~ /^[[:space:]]*(pub(\(crate\))?[[:space:]]+)?mod tests[[:space:]]*\{[[:space:]]*$/) {
      skip = 1
      match($0, /^[[:space:]]*/)
      close_line = substr($0, 1, RLENGTH) "}"
    } else if (skip) {
      if ($0 == close_line) skip = 0
    } else if ($0 !~ /^[[:space:]]*\/\//) {
      code = $0
      if ($0 ~ /\/\/[[:space:]]*stamped-commits:[[:space:]]*not an env txn[[:space:]]*\([^()]*[A-Za-z][^()]*\)[[:space:]]*$/)
        marked[n] = 1
    }
    text = text " " code " \n"
    prev = $0
  }
  END { if (NR > 0) scan() }
' "${files[@]}")

if [[ -n $hits ]]; then
  echo "ERROR: a raw commit of a write transaction, a commit under another name, or" \
    "txn::commit_open outside $open_caller; commit through store_schema::txn::commit" \
    "(Update::New or Update::Carry), which writes the stamp row:"
  printf '%s\n' "$hits"
  exit 1
fi
echo "stamped commits OK (${#files[@]} files in $crates crates; only $allowed commits a write" \
  "transaction, only $open_caller calls txn::commit_open)"
