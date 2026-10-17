#!/usr/bin/env bash
# Fail if a workflow `run:` step invokes cargo without `--locked`, so CI never resolves
# dependencies past the committed Cargo.lock (bench/verify-ipc's own lockfile included).
#
# Only `run:` values are read: an inline value, or a literal (`|`) block line by line, after joining
# `\` continuations and dropping shell `#` comments. A line is split into commands at `&`, `|` and
# `;` (so `&&` and `||` too); each cargo command must carry its own `--locked` before any `--`.
# Global options and `+toolchain` may sit between `cargo` and the subcommand.
#   - Subcommands that resolve the lockfile need --locked: build b test t clippy run r doc d bench
#     check c install nextest llvm-cov deny.
#   - Allowlisted without a lock: fmt (formats sources, reads no lockfile), help and version, and
#     the informational global flags --version -V --help -h --list.
#   - Any other subcommand (user aliases, xtask, typos) fails until it is added to one list, and
#     `cargo` with no visible subcommand fails too.
#   - A folded (`>`) run: scalar that mentions cargo is refused: folding joins its lines, so a
#     command split across them cannot be checked line by line. Use a literal `|` block.
# A plain run: value continued on more-indented lines is checked line by line, which can only
# refuse more, never less.
#
# Usage: scripts/check-locked.sh [FILE|DIR...]   (default: .github/workflows of this repo; a
#        directory contributes its *.yml and *.yaml files)
# Exit: 0 clean, 1 a cargo command without --locked, 2 nothing to check, 3 the scan failed.
# Works on bash 3.2 and with any POSIX awk.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
(($# > 0)) || set -- "$root/.github/workflows"

files=()
for path in "$@"; do
  if [[ -d $path ]]; then
    for f in "$path"/*.yml "$path"/*.yaml; do
      if [[ -f $f ]]; then files+=("$f"); fi
    done
  elif [[ -f $path ]]; then
    files+=("$path")
  else
    echo "ERROR: $path: no such file or directory"
    exit 2
  fi
done
if ((${#files[@]} == 0)); then
  echo "ERROR: no workflow files in $*"
  exit 2
fi

rc=0
awk '
  BEGIN {
    split("build b test t clippy run r doc d bench check c install nextest llvm-cov deny", a, " ")
    for (i in a) need[a[i]] = 1
    split("fmt help version", a, " ")
    for (i in a) nolock[a[i]] = 1
    split("--version -V --help -h --list", a, " ")
    for (i in a) info[a[i]] = 1
    # Global options that take their value as the next word.
    split("--color --config -Z -C --manifest-path --target-dir", a, " ")
    for (i in a) valued[a[i]] = 1
    lead = "^[\"\047`(${]+"
    trail = "[\"\047`);},]+$"
  }
  function report(file, line, msg, text) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", text)
    printf "%s:%d: %s: %s\n", file, line, msg, text
    bad = 1
  }
  function norm(w) {
    gsub(lead, "", w)
    gsub(trail, "", w)
    return w
  }
  function is_cargo(w) { return w == "cargo" || w ~ /\/cargo$/ }
  function has_cargo(text,   n, w, i) {
    n = split(text, w, /[[:space:]]+/)
    for (i = 1; i <= n; i++) if (is_cargo(norm(w[i]))) return 1
    return 0
  }
  # One command (no &, |, ;): every cargo invocation in it must be classified and locked.
  function check_command(c, file, line, text,   n, w, i, j, t, cmd, locked, informational) {
    n = split(c, w, /[[:space:]]+/)
    for (i = 1; i <= n; i++) {
      if (!is_cargo(norm(w[i]))) continue
      locked = 0; informational = 0; cmd = ""
      for (j = i + 1; j <= n; j++) {
        t = norm(w[j])
        if (t == "") continue
        if (t == "--") break
        if (t !~ /^[-+]/) { cmd = t; break }
        if (t == "--locked") locked = 1
        if (t in info) informational = 1
        if ((t in valued) && j < n) j++
      }
      if (cmd == "") {
        if (!informational) report(file, line, "cargo without a visible subcommand", text)
        return
      }
      if (cmd in nolock) { i = j; continue }
      if (!(cmd in need)) {
        report(file, line, "unknown cargo subcommand \"" cmd "\" (classify it in scripts/check-locked.sh)", text)
        return
      }
      for (j = j + 1; j <= n; j++) {
        t = norm(w[j])
        if (t == "--") break
        if (t == "--locked") locked = 1
      }
      if (!locked) {
        report(file, line, "cargo " cmd " without --locked", text)
        return
      }
      i = j
    }
  }
  function check_text(text, file, line,   n, i, parts) {
    n = split(text, parts, /[&|;]/)
    for (i = 1; i <= n; i++) check_command(parts[i], file, line, text)
  }
  # A shell line of a run: value; `\` continuations are joined before checking.
  function shell_line(l, file, lineno) {
    sub(/(^|[[:space:]])#.*$/, "", l)
    if (buf == "") start = lineno
    if (l ~ /\\[[:space:]]*$/) {
      sub(/\\[[:space:]]*$/, " ", l)
      buf = buf l
      return
    }
    check_text(buf l, file, start)
    buf = ""
  }
  function end_run(file) {
    if (buf != "") check_text(buf, file, start)
    buf = ""
    inrun = 0
  }
  FNR == 1 && inrun { end_run(prev) }
  {
    prev = FILENAME
    line = $0
    match(line, /^[[:space:]]*/)
    indent = RLENGTH
    if (inrun) {
      if (line ~ /^[[:space:]]*$/) next
      if (indent > runcol) {
        if (folded) {
          if (has_cargo(line)) report(FILENAME, FNR, "folded run: scalar mentions cargo (use a literal | block)", line)
        } else {
          shell_line(substr(line, indent + 1), FILENAME, FNR)
        }
        next
      }
      end_run(FILENAME)
    }
    if (!match(line, /^[[:space:]]*(-[[:space:]]+)?run:/)) next
    runcol = RLENGTH - 4
    value = substr(line, RLENGTH + 1)
    if (value != "" && value !~ /^[[:space:]]/) next
    sub(/^[[:space:]]+/, "", value)
    if (value ~ /^[|>]/) {
      inrun = 1
      folded = (value ~ /^>/)
      next
    }
    if (value == "" || value ~ /^#/) next
    inrun = 1
    folded = 0
    shell_line(value, FILENAME, FNR)
  }
  END {
    if (inrun) end_run(prev)
    exit bad
  }
' "${files[@]}" || rc=$?

case $rc in
  0) echo "cargo --locked OK (${#files[@]} workflow files)" ;;
  1) echo "ERROR: every cargo command in a CI run: step needs --locked (or an allowlist entry)" ;;
  *) echo "ERROR: scanning workflows failed (exit $rc)"; rc=3 ;;
esac
exit $rc
