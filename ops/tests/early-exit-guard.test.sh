#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted $s are snippet text, written literally
# Offline tests for the early-exit pipe guard (ops/tests/early-exit-guard.sh) that the collector
# and probe suites run on themselves. Run: bash ops/tests/early-exit-guard.test.sh
# Each snippet in early-exit-fixtures/flagged.txt holds exactly one pipe into a reader that can
# exit before its input ends; the guard must report that one pipe, on the line its header names.
# No snippet in early-exit-fixtures/clean.txt may be reported. A "#### " line starts a snippet
# (flagged: "#### <line> <name>", clean: "#### <name>") and each snippet is checked as its own
# file. Also checks that the guard fails closed on a missing file and on input it cannot follow
# to the end. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fixtures="$here/early-exit-fixtures"
# shellcheck source=ops/tests/early-exit-guard.sh
. "$here/early-exit-guard.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

# split_snippets FIXTURE DIR: writes snippet N to DIR/N.sh and its header (after "#### ") to
# DIR/N.name; prints the number of snippets.
split_snippets() {
  local fixture=$1 dir=$2 n=0 line
  mkdir -p "$dir"
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == '#### '* ]]; then
      n=$((n + 1))
      printf '%s\n' "${line#'#### '}" >"$dir/$n.name"
      : >"$dir/$n.sh"
    elif ((n > 0)); then
      printf '%s\n' "$line" >>"$dir/$n.sh"
    fi
  done <"$fixture"
  echo "$n"
}

count=$(split_snippets "$fixtures/flagged.txt" "$tmp/flagged")
if ((count < 40)); then bad "flagged.txt holds only $count snippets"; fi
i=1
while ((i <= count)); do
  header=$(cat "$tmp/flagged/$i.name")
  want_line=${header%% *} name=${header#* }
  file="$tmp/flagged/$i.sh"
  if out=$(early_exit_pipes "$file"); then
    bad "flags $name" "$(cat "$file")"
  elif [[ $(grep -c . <<<"$out") != 1 ]]; then
    bad "flags $name exactly once" "$out"
  elif [[ $out != "$file:$want_line: "* ]]; then
    bad "flags $name on line $want_line" "$out"
  else
    ok "flags $name"
  fi
  i=$((i + 1))
done

count=$(split_snippets "$fixtures/clean.txt" "$tmp/clean")
if ((count < 40)); then bad "clean.txt holds only $count snippets"; fi
i=1
while ((i <= count)); do
  name=$(cat "$tmp/clean/$i.name")
  if out=$(early_exit_pipes "$tmp/clean/$i.sh"); then
    ok "passes $name"
  else
    bad "passes $name" "$out"
  fi
  i=$((i + 1))
done

# Several files in one call: each finding names its own file and line.
split=$(grep -lx '2 a trailing pipe, the reader on the next line' "$tmp"/flagged/*.name)
split=${split%.name}.sh
if out=$(early_exit_pipes "$tmp/flagged/1.sh" "$tmp/clean/1.sh" "$split"); then
  bad "flags pipes across several files" "$out"
elif [[ $out != "$tmp/flagged/1.sh:1: "*$'\n'"$split:2: "* ]]; then
  bad "names each file and line across several files" "$out"
else
  ok "names each file and line across several files"
fi

# Fail closed: a file it cannot read, or one that ends inside a quote, a substitution or a
# heredoc (everything after the opener would go unseen).
if out=$(early_exit_pipes "$tmp/missing.sh" 2>&1); then
  bad "fails on a missing file" "$out"
else
  ok "fails on a missing file"
fi
printf '%s\n' 'echo "a' 'printf a | grep -q x' >"$tmp/open-quote.sh"
printf '%s\n' 'x=$(printf a' 'echo b' >"$tmp/open-subst.sh"
printf '%s\n' 'cat <<EOF' 'printf a | grep -q x' >"$tmp/open-heredoc.sh"
for f in open-quote open-subst open-heredoc; do
  if out=$(early_exit_pipes "$tmp/$f.sh"); then
    bad "fails on a file that ends inside its opener ($f)"
  elif ! grep -q -- "$tmp/$f.sh:1: unterminated" <<<"$out"; then
    bad "names the unterminated opener and its line ($f)" "$out"
  else
    ok "fails on a file that ends inside its opener ($f)"
  fi
done

if out=$(early_exit_pipes "$here/$(basename "${BASH_SOURCE[0]}")"); then
  ok "no check in this script pipes into an early-exiting reader"
else
  bad "a check in this script pipes into an early-exiting reader (read a here-string)" "$out"
fi

echo "early-exit guard tests: $passed passed, $failed failed"
((failed == 0))
