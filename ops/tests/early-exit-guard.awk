# early-exit-guard.awk: report each pipe into a reader that can exit before its input ends.
# Run through early_exit_pipes (early-exit-guard.sh): awk -f early-exit-guard.awk FILE...
#
# Under `set -o pipefail`, `producer | grep -q x` can fail although x matched: grep exits at its
# first match, the producer's next write dies of SIGPIPE and the pipeline reports 141. Readers
# that exit early: grep (and egrep, fgrep) with -q, --quiet, --silent, -m N, --max-count, -l or
# -L; head, unless its count is negative (all but the last N); awk whose program has an `exit`
# outside its END blocks; sed whose script has a q or Q command.
#
# A small shell lexer, not a parser. It joins backslash continuations, drops comments, skips
# heredoc bodies, and never sees a pipe inside quotes, ${...} or arithmetic. It follows $(...)
# and backquotes, also inside double quotes. After a pipe it skips newlines, comment lines,
# `(`, `{`, assignments and the wrappers command, env, exec, builtin, nohup and time, takes the
# command's basename (so \grep, "grep" and /usr/bin/grep count), and reads its options.
# Prints FILE:LINE: TEXT for each reader (LINE is where its name is) and exits 1 if any.
# A file that ends inside a quote, a substitution or a heredoc is reported as unterminated:
# whatever followed the opener went unseen.
#
# What it cannot see: a reader reached through a function, alias, variable ($cmd -q) or
# eval; a pipeline inside an unquoted heredoc body; an awk or sed program read from a file
# (-f); grep options abbreviated (--qui) or set by the environment; other early readers (read,
# dd count=, cmp, a while loop that breaks). A `)` of a case pattern inside $(...) ends the
# substitution early, and a case pattern spelled like a reader (`a|head)`) is reported. `((`
# opening a word is always arithmetic, `$((` always arithmetic expansion (never a subshell).

BEGIN {
  SQ = "\047"
  OPS3 = " <<- <<< &>> ;;& "
  OPS2 = " << >> >| >& <& <> &> && || |& ;; ;& "
  READER["grep"]; READER["egrep"]; READER["fgrep"]; READER["ggrep"]
  READER["head"]; READER["ghead"]
  READER["awk"]; READER["gawk"]; READER["mawk"]; READER["nawk"]
  READER["sed"]; READER["gsed"]
  WRAPPER["command"]; WRAPPER["env"]; WRAPPER["exec"]; WRAPPER["builtin"]
  WRAPPER["nohup"]; WRAPPER["time"]
  REDIR[">"]; REDIR["<"]; REDIR[">>"]; REDIR[">|"]; REDIR[">&"]; REDIR["<&"]
  REDIR["<>"]; REDIR["&>"]; REDIR["&>>"]; REDIR["<<<"]
  n = split("regexp file after-context before-context context devices directories " \
    "binary-files label exclude include exclude-dir exclude-from group-separator", a, " ")
  for (i = 1; i <= n; i++) GREP_LONG_ARG[a[i]]
  OPEN["S"] = "single quote"; OPEN["D"] = "double quote"; OPEN["A"] = "$" SQ "..." SQ " string"
  OPEN["P"] = "$( substitution"; OPEN["B"] = "backquote substitution"
  OPEN["E"] = "${ expansion"; OPEN["M"] = "arithmetic (("
}

FNR == 1 {
  if (NR > 1) end_file()
  start_file()
}

{
  file = FILENAME
  L[FNR] = $0
  if (hd_mode) { heredoc_line($0); next }
  lex($0)
}

END {
  if (NR > 0) end_file()
  exit found ? 1 : 0
}

function start_file() {
  delete L
  sp = 1; ctx[1] = "T"; depth[1] = 0; pst[1] = 0; skip[1] = 0
  word = ""; inword = 0
  hd_n = 0; hd_i = 0; hd_mode = 0; hd_next = 0
}

function end_file() {
  if (hd_n > 0) {
    report_open(hd_line[hd_i > 0 ? hd_i : 1], "heredoc <<" hd_word[hd_i > 0 ? hd_i : 1])
  } else if (sp > 1) {
    report_open(oline[2], OPEN[ctx[2]])
  } else {
    flush(); finish(1)
  }
}

function report_open(line, what) {
  print file ":" line ": unterminated " what; found = 1
}

# A line inside a heredoc body: it ends the body only if it is the delimiter itself (after
# leading tabs, for <<-).
function heredoc_line(s) {
  if (hd_dash[hd_i]) sub(/^\t+/, "", s)
  if (s != hd_word[hd_i]) return
  if (++hd_i > hd_n) { hd_mode = 0; hd_n = 0; hd_i = 0 }
}

# ---- lexer ---------------------------------------------------------------------------------
# ctx[sp]: T top-level code, P $(...) code, B `...` code, D "...", S '...', A $'...',
# E ${...}, M $((...)) or ((...)). Words collect into `word`; operators and words go to the
# pipe tracker of the innermost code context (onop, onword).

function code(t) { return t == "T" || t == "P" || t == "B" }

function push(t) {
  sp++; ctx[sp] = t; depth[sp] = 0; oline[sp] = FNR
  if (t == "P" || t == "B") {
    saved[sp] = word; word = ""; inword = 0; pst[sp] = 0; skip[sp] = 0
  } else {
    inword = 1
  }
}

# Close the $(...) or `...` at the top: its last command ends, the outer word resumes.
function close_subst() {
  flush(); finish(sp)
  word = saved[sp] "$()"; inword = 1
  sp--
}

# $( $(( ${ and ` start a nested context; returns the characters consumed, or 0.
function expansion(s, i, t,   c, c2) {
  c = substr(s, i, 1)
  if (c == "`") {
    if (t == "B") { close_subst(); return 1 }
    push("B"); return 1
  }
  if (c != "$") return 0
  c2 = substr(s, i + 1, 1)
  if (c2 == "(" && substr(s, i + 2, 1) == "(") { push("M"); return 3 }
  if (c2 == "(") { push("P"); return 2 }
  if (c2 == "{") { push("E"); return 2 }
  return 0
}

function lex(s,   n, i, c, t, op, k, cont) {
  n = length(s); i = 1; cont = 0
  while (i <= n) {
    c = substr(s, i, 1); t = ctx[sp]
    if (t == "S") {
      if (c == SQ) sp--; else word = word c
      i++; continue
    }
    if (t == "A") {
      if (c == "\\") { word = word substr(s, i, 2); i += 2; continue }
      if (c == SQ) sp--; else word = word c
      i++; continue
    }
    if (c == "\\") {
      if (i == n) { cont = 1; i++; continue }
      word = word substr(s, i + 1, 1); inword = 1; i += 2; continue
    }
    if (t == "D") {
      if (c == "\"") { sp--; i++; continue }
      if (k = expansion(s, i, t)) { i += k; continue }
      word = word c; i++; continue
    }
    if (t == "E" || t == "M") {
      if (c == SQ && ctx[sp - 1] != "D") { push("S"); i++; continue }
      if (c == "\"") { push("D"); i++; continue }
      if (k = expansion(s, i, t)) { i += k; continue }
      if (t == "E" && c == "}" && depth[sp] == 0) { sp--; i++; continue }
      if (t == "M" && c == ")" && depth[sp] == 0) {
        sp--; i += (substr(s, i + 1, 1) == ")") ? 2 : 1; continue
      }
      if (c == "{" || c == "(") depth[sp]++
      if (c == "}" || c == ")") depth[sp]--
      word = word c; i++; continue
    }
    # code: T, P or B
    if (c == " " || c == "\t") { flush(); i++; continue }
    if (c == "#" && !inword) break
    if (c == SQ) { inword = 1; push("S"); i++; continue }
    if (c == "\"") { inword = 1; push("D"); i++; continue }
    if (c == "$" && substr(s, i + 1, 1) == SQ) { inword = 1; push("A"); i += 2; continue }
    if (k = expansion(s, i, t)) { i += k; continue }
    if (c == "(" && substr(s, i + 1, 1) == "(" && !inword) { push("M"); i += 2; continue }
    if (index("|&;()<>", c)) {
      op = c
      if (index(OPS3, " " substr(s, i, 3) " ")) op = substr(s, i, 3)
      else if (index(OPS2, " " substr(s, i, 2) " ")) op = substr(s, i, 2)
      flush()
      if (t == "P" && op == ")") {
        if (depth[sp] == 0) { close_subst(); i++; continue }
        depth[sp]--
      }
      if (t == "P" && op == "(") depth[sp]++
      onop(op); i += length(op); continue
    }
    word = word c; inword = 1; i++
  }
  if (cont) return
  if (code(ctx[sp])) {
    flush(); onop("\n")
    if (hd_n > 0) { hd_mode = 1; hd_i = 1 }
  } else {
    word = word "\n"
  }
}

function flush() {
  if (!inword) return
  if (hd_next) {
    hd_n++; hd_word[hd_n] = word; hd_dash[hd_n] = (hd_next == 2); hd_line[hd_n] = FNR
    hd_next = 0
  } else {
    onword(word)
  }
  word = ""; inword = 0
}

# ---- pipe tracker --------------------------------------------------------------------------
# pst[k]: 0 no pipe pending, 1 a pipe wants its command, 2 inside a wrapper (env, command…),
# 3 collecting a reader's arguments arg[k, 1..nargs[k]].

function onop(op,   k) {
  k = sp
  if (op == "|" || op == "|&") { finish(k); pst[k] = 1; return }
  if ((op == "\n" || op == "(") && pst[k] == 1) return
  if (op == "<<" || op == "<<-") { hd_next = (op == "<<-") ? 2 : 1; return }
  if (op in REDIR) { skip[k] = 1; return }
  finish(k)
}

function onword(w,   k, name) {
  k = sp
  if (skip[k]) { skip[k] = 0; return }
  if (pst[k] == 1 || pst[k] == 2) {
    if (w ~ /^[A-Za-z_][A-Za-z0-9_]*\+?=/) return
    if (pst[k] == 1 && (w == "{" || w == "!")) return
    if (pst[k] == 1 && (w in WRAPPER)) { pst[k] = 2; return }
    if (pst[k] == 2 && w ~ /^-/) { if (w == "-u") skip[k] = 1; return }
    name = w; sub(/.*\//, "", name)
    if (name in READER) { pst[k] = 3; reader[k] = name; nargs[k] = 0; rline[k] = FNR }
    else pst[k] = 0
    return
  }
  if (pst[k] == 3) arg[k, ++nargs[k]] = w
}

function finish(k) {
  if (pst[k] == 3 && early(k)) { print file ":" rline[k] ": " L[rline[k]]; found = 1 }
  pst[k] = 0; skip[k] = 0
}

function early(k,   name) {
  name = reader[k]
  if (name ~ /grep$/) return grep_early(k, nargs[k])
  if (name ~ /head$/) return head_early(k, nargs[k])
  if (name ~ /awk$/) return awk_early(k, nargs[k])
  return sed_quits(sed_script(k, nargs[k]))
}

# ---- readers -------------------------------------------------------------------------------

function grep_early(k, n,   j, a, o, p, c) {
  for (j = 1; j <= n; j++) {
    a = arg[k, j]
    if (a == "--") return 0
    if (a ~ /^--/) {
      o = substr(a, 3); p = index(o, "=")
      if (p) o = substr(o, 1, p - 1)
      if (o == "quiet" || o == "silent" || o == "max-count" || o == "files-with-matches" \
        || o == "files-without-match") return 1
      if (!p && (o in GREP_LONG_ARG)) j++
      continue
    }
    if (a !~ /^-./) continue
    for (p = 2; p <= length(a); p++) {
      c = substr(a, p, 1)
      if (index("qmlL", c)) return 1
      if (index("efABCdD", c)) { if (p == length(a)) j++; break }
    }
  }
  return 0
}

function head_early(k, n,   j, a, v) {
  for (j = 1; j <= n; j++) {
    a = arg[k, j]; v = ""
    if (a == "-n" || a == "-c" || a == "--lines" || a == "--bytes") v = arg[k, ++j]
    else if (a ~ /^-[nc]./) v = substr(a, 3)
    else if (a ~ /^--(lines|bytes)=/) v = substr(a, index(a, "=") + 1)
    if (v ~ /^-/) return 0
  }
  return 1
}

function awk_early(k, n,   j, a, prog) {
  prog = ""
  for (j = 1; j <= n; j++) {
    a = arg[k, j]
    if (a == "--") { if (j < n) prog = arg[k, j + 1]; break }
    if (a == "-f" || a ~ /^-f./ || a ~ /^--file(=|$)/) return 0
    if (a == "-e" || a == "--source") { prog = arg[k, j + 1]; break }
    if (a ~ /^--source=/) { prog = substr(a, 10); break }
    if (a == "-F" || a == "-v") { j++; continue }
    if (a ~ /^-./) continue
    prog = a; break
  }
  return without_end_blocks(prog) ~ /(^|[^A-Za-z0-9_])exit([^A-Za-z0-9_]|$)/
}

# The awk program without its END { ... } blocks: an exit there runs after the whole input.
function without_end_blocks(p,   out, q, d, c, m) {
  out = ""
  while (match(p, /(^|[^A-Za-z0-9_])END[ \t\n]*[{]/)) {
    out = out substr(p, 1, RSTART - 1)
    m = length(p); d = 0
    for (q = RSTART + RLENGTH - 1; q <= m; q++) {
      c = substr(p, q, 1)
      if (c == "\"") {
        for (q++; q <= m && substr(p, q, 1) != "\""; q++) if (substr(p, q, 1) == "\\") q++
      } else if (c == "{") {
        d++
      } else if (c == "}" && --d == 0) {
        break
      }
    }
    p = substr(p, q + 1)
  }
  return out p
}

# The sed script from -e/--expression, else the first operand ("" when read from -f).
function sed_script(k, n,   j, a, p, c, script, have) {
  script = ""; have = 0
  for (j = 1; j <= n; j++) {
    a = arg[k, j]
    if (a == "--") { if (!have && j < n) script = arg[k, j + 1]; break }
    if (a == "--expression") { script = script "\n" arg[k, ++j]; have = 1; continue }
    if (a ~ /^--expression=/) { script = script "\n" substr(a, 14); have = 1; continue }
    if (a == "--file") { j++; have = 1; continue }
    if (a ~ /^--file=/) { have = 1; continue }
    if (a == "--line-length") { j++; continue }
    if (a ~ /^--/) continue
    if (a ~ /^-./) {
      for (p = 2; p <= length(a); p++) {
        c = substr(a, p, 1)
        if (c == "e") {
          script = script "\n" (p < length(a) ? substr(a, p + 1) : arg[k, ++j]); have = 1; break
        }
        if (c == "f") { if (p == length(a)) j++; have = 1; break }
        if (c == "l") { if (p == length(a)) j++; break }
        if (c == "i") break
      }
      continue
    }
    if (!have) { script = a; have = 1 }
  }
  return script
}

# Whether a sed script has a q or Q command: walks addresses, skips the text of s, y, a, i, c,
# labels and file names, so a q inside a regex, a replacement or text is not a command.
function sed_quits(s,   n, i, c, d) {
  n = length(s); i = 1
  while (i <= n) {
    c = substr(s, i, 1)
    if (index(" \t\n;{}!", c)) { i++; continue }
    if (c == "#") { i = line_end(s, i); continue }
    i = sed_address(s, i)
    while (index(" \t!", substr(s, i, 1)) && i <= n) i++
    if (substr(s, i, 1) == ",") { i++; i = sed_address(s, i) }
    while (index(" \t!", substr(s, i, 1)) && i <= n) i++
    c = substr(s, i, 1)
    if (c == "q" || c == "Q") return 1
    if (c == "s" || c == "y") {
      d = substr(s, i + 1, 1)
      i = past_delim(s, past_delim(s, i + 2, d), d)
      while (i <= n && !index(";\n}", substr(s, i, 1))) i++
      continue
    }
    if (index("aicrwRWe", c) && c != "") { i = line_end(s, i); continue }
    if (index("btT:", c) && c != "") {
      for (i++; i <= n && !index(";\n", substr(s, i, 1)); i++) ;
      continue
    }
    i++
  }
  return 0
}

function line_end(s, i,   p) {
  p = index(substr(s, i), "\n")
  return p ? i + p : length(s) + 1
}

# Past one address at i: a line number (first~step), $, /regex/ or \cregexc (with I or M
# flags), or a GNU +N / ~N second address.
function sed_address(s, i,   c, d) {
  c = substr(s, i, 1)
  if (c ~ /[0-9+~]/) {
    for (i++; substr(s, i, 1) ~ /[0-9~]/ && i <= length(s); i++) ;
  } else if (c == "$") {
    i++
  } else if (c == "/" || c == "\\") {
    if (c == "\\") { d = substr(s, i + 1, 1); i += 2 } else { d = "/"; i++ }
    i = past_delim(s, i, d)
    while (substr(s, i, 1) ~ /[IM]/ && i <= length(s)) i++
  }
  return i
}

function past_delim(s, i, d,   n, c) {
  n = length(s)
  for (; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\") { i++; continue }
    if (c == d) return i + 1
  }
  return i
}
