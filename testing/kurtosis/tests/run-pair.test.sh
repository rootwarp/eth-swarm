#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted stub bodies expand when the stubs run, on purpose
# Offline tests for testing/kurtosis/run-pair.sh. Run: bash testing/kurtosis/tests/run-pair.test.sh
# The script runs from a copy of the repo layout in a temp dir (its own copy of run-pair.sh and
# gloas-genesis.yaml, a stub check-devnet.sh and a stub scripts/check-kurtosis-pins.sh), with
# kurtosis, docker, date and sleep as stubs on PATH. `date +%s` reads a fake clock that the stub
# sleep and `kurtosis run` advance, so a 900 s lead takes no time. No network, no Kurtosis, no
# Docker. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
kurtosis_dir="$here/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

# --- stubs ---------------------------------------------------------------------------------------

stubs="$tmp/stubs"
mkdir -p "$stubs"
export STUB_DIR="$tmp/stub"
NOW=1790000000

cat > "$stubs/kurtosis" <<'SH'
#!/usr/bin/env bash
# kurtosis stub; every call is logged to $STUB_DIR/kurtosis.log. The control files are keyed by the
# enclave name without run-pair.sh's -<T>-<pid> suffix (run.ethswarm-gloas-a.rc for
# ethswarm-gloas-a-1790000900-4242); $STUB_DIR/exists.<full name> is an enclave on the engine.
# `run --enclave E ...`: creates E; the n-th run of E exits with $STUB_DIR/run.<K>.rc.<n>, else
#   $STUB_DIR/run.<K>.rc, else 0; it first advances the fake clock by $STUB_DIR/run.<K>.advance
#   seconds; with $STUB_DIR/run.<K>.orphan it leaves a grandchild in its process group that ignores
#   TERM (its pid in $STUB_DIR/run.<K>.orphan.pid; it runs for at most 60 s), and with
#   $STUB_DIR/run.<K>.leftover one that does not (run.<K>.leftover.pid, at most 60 s); with
#   $STUB_DIR/run.<K>.await (holding a pid file name) it waits up to 5 s for that process to be
#   gone and writes `gone` or `alive` to $STUB_DIR/run.<K>.saw; with $STUB_DIR/run.<K>.leader it
#   writes its own pid (the launch's process group) to $STUB_DIR/run.<K>.leader.pid; and with
#   $STUB_DIR/run.<K>.block it blocks (its pid in $STUB_DIR/run.<K>.pid).
# `enclave ls`: the n-th call prints $STUB_DIR/enclave-ls.<n>, else $STUB_DIR/enclave-ls, else the
#   UUID header and a row per enclave on the engine; $STUB_DIR/ls.rc or $STUB_DIR/ls.rc.<n> fails
#   it, and with $STUB_DIR/ls.block.<n> the n-th call first hangs for 60 s (its pid in
#   $STUB_DIR/ls.pid).
# `enclave rm -f E`: advances the fake clock by $STUB_DIR/rm.<K>.advance seconds; with
#   $STUB_DIR/rm.<K>.block it blocks (its pid in $STUB_DIR/rm.<K>.pid), and with
#   $STUB_DIR/rm.<K>.block-once the first call removes that file and E (the engine did it, the CLI
#   hangs) and hangs for 60 s (the same pid file); else it exits with $STUB_DIR/rm.<K>.rc (else 0),
#   and removes E unless $STUB_DIR/rm.<K>.keep.
# `clean -a`: exits with $STUB_DIR/clean.rc (else 0); with $STUB_DIR/clean.block it first hangs
#   for 60 s (its pid in $STUB_DIR/clean.pid).
printf '%s\n' "$*" >> "$STUB_DIR/kurtosis.log"
key() { sed -E 's/-[0-9]+-[0-9]+$//' <<<"$1"; }
stubborn='trap "" TERM; echo $$ > "$STUB_DIR/$0.pid"; for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done'
case "$1 ${2:-}" in
  "run --enclave")
    e=$3 k=$(key "$3")
    counter="$STUB_DIR/run.$k.count"
    n=$(( $(cat "$counter" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$counter"
    touch "$STUB_DIR/exists.$e"
    echo "kurtosis run stub: enclave $e"
    if [[ -f $STUB_DIR/run.$k.leader ]]; then echo $$ > "$STUB_DIR/run.$k.leader.pid"; fi
    if [[ -f $STUB_DIR/run.$k.advance ]]; then
      echo $(( $(cat "$STUB_DIR/now") + $(cat "$STUB_DIR/run.$k.advance") )) > "$STUB_DIR/now"
    fi
    if [[ -f $STUB_DIR/run.$k.orphan ]]; then
      ( bash -c "$stubborn" "run.$k.orphan" & ) >/dev/null 2>&1
      for ((i = 0; i < 50; i++)); do if [[ -f $STUB_DIR/run.$k.orphan.pid ]]; then break; fi; /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/run.$k.leftover ]]; then
      ( bash -c 'echo $$ > "$STUB_DIR/$0.pid"; for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done' "run.$k.leftover" & ) >/dev/null 2>&1
      for ((i = 0; i < 50; i++)); do if [[ -f $STUB_DIR/run.$k.leftover.pid ]]; then break; fi; /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/run.$k.await ]]; then
      f="$STUB_DIR/$(cat "$STUB_DIR/run.$k.await")" saw=alive
      for ((i = 0; i < 50; i++)); do
        if [[ -f $f ]] && ! ps -p "$(cat "$f")" >/dev/null 2>&1; then saw=gone; break; fi
        /bin/sleep 0.1
      done
      echo "$saw" > "$STUB_DIR/run.$k.saw"
    fi
    if [[ -f $STUB_DIR/run.$k.block ]]; then
      echo $$ > "$STUB_DIR/run.$k.pid"
      while :; do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/run.$k.rc.$n ]]; then exit "$(cat "$STUB_DIR/run.$k.rc.$n")"; fi
    if [[ -f $STUB_DIR/run.$k.rc ]]; then exit "$(cat "$STUB_DIR/run.$k.rc")"; fi
    exit 0 ;;
  "enclave ls")
    n=$(( $(cat "$STUB_DIR/ls.count" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$STUB_DIR/ls.count"
    if [[ -f $STUB_DIR/ls.block.$n ]]; then
      echo $$ > "$STUB_DIR/ls.pid"
      for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/ls.rc.$n ]]; then exit "$(cat "$STUB_DIR/ls.rc.$n")"; fi
    if [[ -f $STUB_DIR/ls.rc ]]; then exit "$(cat "$STUB_DIR/ls.rc")"; fi
    if [[ -f $STUB_DIR/enclave-ls.$n ]]; then cat "$STUB_DIR/enclave-ls.$n"
    elif [[ -f $STUB_DIR/enclave-ls ]]; then cat "$STUB_DIR/enclave-ls"
    else
      echo "UUID   Name   Status   Creation Time"
      for f in "$STUB_DIR"/exists.*; do
        if [[ -f $f ]]; then echo "0a1b2c3d4e5f   ${f##*/exists.}   RUNNING   Sun, 19 Oct 2026 00:12:03 KST"; fi
      done
    fi ;;
  "enclave rm")
    e=$4 k=$(key "$4")
    if [[ -f $STUB_DIR/rm.$k.advance ]]; then
      echo $(( $(cat "$STUB_DIR/now") + $(cat "$STUB_DIR/rm.$k.advance") )) > "$STUB_DIR/now"
    fi
    if [[ -f $STUB_DIR/rm.$k.block ]]; then
      echo $$ > "$STUB_DIR/rm.$k.pid"
      while :; do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/rm.$k.block-once ]]; then
      rm -f "$STUB_DIR/rm.$k.block-once" "$STUB_DIR/exists.$e"
      echo $$ > "$STUB_DIR/rm.$k.pid"
      for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/rm.$k.rc ]]; then exit "$(cat "$STUB_DIR/rm.$k.rc")"; fi
    if [[ ! -f $STUB_DIR/rm.$k.keep ]]; then rm -f "$STUB_DIR/exists.$e"; fi ;;
  "clean -a")
    if [[ -f $STUB_DIR/clean.block ]]; then
      echo $$ > "$STUB_DIR/clean.pid"
      for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/clean.rc ]]; then exit "$(cat "$STUB_DIR/clean.rc")"; fi ;;
  *) exit 64 ;;
esac
SH
cat > "$stubs/docker" <<'SH'
#!/usr/bin/env bash
# docker stub: `pull -q IMAGE` exits 1 for an image listed in $STUB_DIR/pull.fail, else 0;
# `stats --no-stream` prints a canned line, or with $STUB_DIR/stats.block hangs (its pid in
# $STUB_DIR/stats.pid). Every call is logged to $STUB_DIR/docker.log.
printf '%s\n' "$*" >> "$STUB_DIR/docker.log"
case "$1" in
  pull) if [[ -f $STUB_DIR/pull.fail ]] && grep -qxF -- "$3" "$STUB_DIR/pull.fail"; then exit 1; fi
        echo "$3" ;;
  stats)
    if [[ -f $STUB_DIR/stats.block ]]; then
      echo $$ > "$STUB_DIR/stats.pid"
      while :; do /bin/sleep 0.1; done
    fi
    echo "CONTAINER ID   NAME   CPU %   MEM USAGE / LIMIT" ;;
  *) exit 64 ;;
esac
SH
cat > "$stubs/date" <<'SH'
#!/usr/bin/env bash
# date stub: `date +%s` is the fake clock in $STUB_DIR/now.
if [[ ${1:-} == +%s ]]; then cat "$STUB_DIR/now"; exit 0; fi
exec /bin/date "$@"
SH
cat > "$stubs/sleep" <<'SH'
#!/usr/bin/env bash
# sleep stub: advances the fake clock by $1 seconds and returns at once; a fraction of a second (a
# fast poll) really sleeps and leaves the clock alone. With $STUB_DIR/sleep.block, the first call
# longer than 1 s (the wait for genesis, not a 1 s poll) removes that file and really sleeps for
# the seconds it holds (empty: 30), the fake clock left alone (its pid in $STUB_DIR/sleep.pid).
printf '%s\n' "$1" >> "$STUB_DIR/sleep.log"
if [[ $1 == *.* ]]; then exec /bin/sleep "$1"; fi
if [[ -f $STUB_DIR/sleep.block ]] && (($1 > 1)); then
  real=$(cat "$STUB_DIR/sleep.block")
  rm -f "$STUB_DIR/sleep.block"
  echo $$ > "$STUB_DIR/sleep.pid"
  exec /bin/sleep "${real:-30}"
fi
echo $(( $(cat "$STUB_DIR/now") + $1 )) > "$STUB_DIR/now"
SH
cat > "$stubs/tee" <<'SH'
#!/usr/bin/env bash
# tee stub: with $STUB_DIR/tee.fail it copies its input to stdout and exits 1, like a tee whose log
# cannot be written; else the real tee.
if [[ -f $STUB_DIR/tee.fail ]]; then cat; exit 1; fi
for t in /usr/bin/tee /bin/tee; do if [[ -x $t ]]; then exec "$t" "$@"; fi; done
exit 127
SH
cat > "$stubs/ps" <<'SH'
#!/usr/bin/env bash
# ps stub, over the real ps; a line it adds has the fields of the -o lists:
#   $STUB_DIR/ps.reused: `ps ... -p PID` reports every pid as a running process (as if each pid
#     were taken by another process the moment it ends).
#   $STUB_DIR/ps.reuse (names of pid files under $STUB_DIR, one per line): each pid in those files
#     that the real ps no longer shows is reported as taken by another process, the leader of a new
#     group (its pgid the same pid, ppid 1, its command `foreign`), in a listing of every process
#     (-A) and for `-p` that pid.
#   $STUB_DIR/ps.fake (lines `<pid> <ppid> <command...>`; a ppid `@<name>` is the pid in
#     $STUB_DIR/<name>, and the line waits for that file): each is reported, whatever the real ps
#     shows, as a process that leads its own group (pgid the pid, stat S), in a listing of every
#     process and for `-p` that pid. A listing that shows ppids then leaves out each real process
#     whose ppid is 1, so no walk down from a fake pid 1 reaches a real process.
#   $STUB_DIR/ps.fail-A: a listing of every process fails, with no output.
#   $STUB_DIR/ps.fail-A.after-kill (a number N): once $STUB_DIR/kill.log exists (a kill_logged
#     copy has signalled), the next N listings of every process fail, with no output.
#   $STUB_DIR/ps.A.count (a counter the test starts at 0): each listing of every process counts
#     itself there, and the n-th first runs $STUB_DIR/ps.before-A.<n> (shell source) if it exists.
#   $STUB_DIR/ps.locale: unless LC_ALL is C or POSIX, lstart comes out in seven words, as macOS
#     words it under ko_KR.UTF-8 (the real ps runs with LC_ALL=C).
#   An exported COLUMNS cuts each line of a listing that shows the command to that many
#   characters unless -ww is given, as Linux procps does even when its output is a pipe.
# Else the real ps.
cols=${COLUMNS:-}
if [[ -f $STUB_DIR/ps.reused && " $* " == *" -p "* ]]; then echo "S"; exit 0; fi
real=''
for p in /bin/ps /usr/bin/ps; do if [[ -x $p ]]; then real=$p; break; fi; done
if [[ -z $real ]]; then exit 127; fi
args=("$@") fields=() want='' all=0 ww=0 cmd=0 lstart=0 ppid=0 sim=0 extra='' nl=$'\n'
for ((i = 0; i < ${#args[@]}; i++)); do
  case ${args[i]} in
    -o) IFS=, read -r -a f <<<"${args[i + 1]}"; fields+=("${f[@]}") ;;
    -p) want=${args[i + 1]} ;;
    -A) all=1 ;;
    -ww) ww=1 ;;
  esac
done
# Word numbers in a line: every field is one word but lstart (five, under LC_ALL=C) and the
# command (the rest of the line).
for ((i = 0; i < ${#fields[@]}; i++)); do
  case ${fields[i]%%=*} in
    command | args) cmd=1 ;;
    lstart) lstart=$((i + 1)) ;;
    ppid) ppid=$((i + 1)) ;;
  esac
done
if ((lstart && ppid > lstart)); then ppid=$((ppid + 4)); fi
if [[ -f $STUB_DIR/ps.locale && ${LC_ALL:-} != C && ${LC_ALL:-} != POSIX ]] && ((lstart)); then sim=1; fi
if ((cmd == 0 || ww)); then cols=''; fi
if ((all)) && [[ -f $STUB_DIR/ps.A.count ]]; then
  n=$(( $(cat "$STUB_DIR/ps.A.count") + 1 ))
  echo "$n" > "$STUB_DIR/ps.A.count"
  if [[ -f $STUB_DIR/ps.before-A.$n ]]; then bash "$STUB_DIR/ps.before-A.$n"; fi
fi
if ((all)) && [[ -f $STUB_DIR/ps.fail-A ]]; then exit 1; fi
if ((all)) && [[ -f $STUB_DIR/ps.fail-A.after-kill && -f $STUB_DIR/kill.log ]]; then
  n=$(cat "$STUB_DIR/ps.fail-A.after-kill")
  if ((n > 0)); then echo $((n - 1)) > "$STUB_DIR/ps.fail-A.after-kill"; exit 1; fi
fi
if [[ ! -f $STUB_DIR/ps.reuse && ! -f $STUB_DIR/ps.fake && -z $cols ]] && ((sim == 0)); then
  exec "$real" "$@"
fi
rc=0
if ((sim)); then listing=$(LC_ALL=C "$real" "$@") || rc=$?; else listing=$("$real" "$@") || rc=$?; fi
# add <pid> <pgid> <ppid> <command>: a line of the -o fields, to extra.
add() {
  local field v line=''
  for field in "${fields[@]}"; do
    case ${field%%=*} in
      pid) v=$1 ;;
      pgid) v=$2 ;;
      ppid) v=$3 ;;
      stat) v=S ;;
      lstart) v='Mon Oct 19 00:00:00 2026' ;;
      *) v=$4 ;;
    esac
    line="${line:+$line }$v"
  done
  extra="$extra$line$nl"
}
if [[ -f $STUB_DIR/ps.reuse ]]; then
  while IFS= read -r name; do
    if [[ ! -f $STUB_DIR/$name ]]; then continue; fi
    g=$(cat "$STUB_DIR/$name")
    if ((all == 0)) && [[ $want != "$g" ]]; then continue; fi
    if "$real" -p "$g" >/dev/null 2>&1; then continue; fi
    add "$g" "$g" 1 foreign
  done < "$STUB_DIR/ps.reuse"
fi
if [[ -f $STUB_DIR/ps.fake ]]; then
  if ((ppid)) && [[ -n $listing ]]; then listing=$(awk -v k="$ppid" '$k != 1' <<<"$listing"); fi
  while read -r p pp c; do
    if [[ $pp == @* ]]; then
      if [[ ! -f $STUB_DIR/${pp#@} ]]; then continue; fi
      pp=$(cat "$STUB_DIR/${pp#@}")
    fi
    if ((all == 0)) && [[ $want != "$p" ]]; then continue; fi
    add "$p" "$p" "$pp" "$c"
  done < "$STUB_DIR/ps.fake"
fi
out=$listing
if [[ -n $extra ]]; then out="${out:+$out$nl}${extra%"$nl"}"; fi
if [[ -n $out ]] && ((sim)); then
  out=$(awk -v k="$lstart" '{
    o = ""
    for (i = 1; i <= NF; i++) {
      w = (i == k) ? $(i + 4) "Y " $(i + 1) "M " $(i + 2) "D (" $i ") AM " $(i + 3) " KST" : $i
      o = (i == 1) ? w : o " " w
      if (i == k) i += 4
    }
    print o }' <<<"$out")
fi
if [[ -n $out && -n $cols ]]; then out=$(awk -v w="$cols" '{ print substr($0, 1, w) }' <<<"$out"); fi
if [[ -n $out ]]; then printf '%s\n' "$out"; fi
if [[ -n $extra ]]; then exit 0; fi
exit "$rc"
SH
chmod +x "$stubs/kurtosis" "$stubs/docker" "$stubs/date" "$stubs/sleep" "$stubs/tee" "$stubs/ps"

# The repo layout run-pair.sh expects, under $repo.
repo="$tmp/repo"
script="$repo/testing/kurtosis/run-pair.sh"

# base: a fresh repo copy and stub state; every step passes, the clock at $NOW.
base() {
  rm -rf "$STUB_DIR" "$repo"; mkdir -p "$STUB_DIR" "$repo/testing/kurtosis" "$repo/scripts"
  echo "$NOW" > "$STUB_DIR/now"
  cp "$kurtosis_dir/run-pair.sh" "$kurtosis_dir/gloas-genesis.yaml" "$repo/testing/kurtosis/"
  cat > "$repo/testing/kurtosis/check-devnet.sh" <<'SH'
#!/usr/bin/env bash
# check-devnet.sh stub: logs its args and the fake time, exits with $STUB_DIR/check.rc (else 0).
# With $STUB_DIR/check.block it blocks (its pid in $STUB_DIR/check.pid), like a finality poll;
# with $STUB_DIR/check.advance it advances the fake clock by that many seconds, then hangs for at
# most 60 s (its pid in $STUB_DIR/check.pid); with $STUB_DIR/check.stubborn it first starts a child
# that ignores TERM (its pid in $STUB_DIR/stubborn.pid), and with $STUB_DIR/check.orphan a
# grandchild that ignores TERM and whose parent exits at once, so no walk of the check's children
# finds it (its pid in $STUB_DIR/orphan.pid); either runs for at most 60 s.
printf '%s @%s\n' "$*" "$(cat "$STUB_DIR/now")" >> "$STUB_DIR/check.log"
stubborn='trap "" TERM; echo $$ > "$STUB_DIR/$0.pid"; for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done'
# started <name>: waits (up to 5 s) for $STUB_DIR/<name>.pid.
started() { for ((i = 0; i < 50; i++)); do if [[ -f $STUB_DIR/$1.pid ]]; then return; fi; /bin/sleep 0.1; done; }
if [[ -f $STUB_DIR/check.stubborn ]]; then
  bash -c "$stubborn" stubborn &
  started stubborn
fi
if [[ -f $STUB_DIR/check.orphan ]]; then
  ( bash -c "$stubborn" orphan & ) >/dev/null 2>&1
  started orphan
fi
if [[ -f $STUB_DIR/check.advance ]]; then
  echo $(( $(cat "$STUB_DIR/now") + $(cat "$STUB_DIR/check.advance") )) > "$STUB_DIR/now"
  echo $$ > "$STUB_DIR/check.pid"
  for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
fi
if [[ -f $STUB_DIR/check.block ]]; then
  echo $$ > "$STUB_DIR/check.pid"
  while :; do /bin/sleep 0.1; done
fi
echo "pair verdict: STUB"
exit "$(cat "$STUB_DIR/check.rc" 2>/dev/null || echo 0)"
SH
  cat > "$repo/scripts/check-kurtosis-pins.sh" <<'SH'
#!/usr/bin/env bash
# check-kurtosis-pins.sh stub: logs its args, exits with $STUB_DIR/pins.rc (else 0).
printf '%s\n' "$*" >> "$STUB_DIR/pins.log"
exit "$(cat "$STUB_DIR/pins.rc" 2>/dev/null || echo 0)"
SH
}

out=''
run_env=()
# run <expect-exit> <description> <pattern...> -- <args...>: runs run-pair.sh (with the NAME=value
# entries of run_env in its environment) and wants the exit code and a line matching each extended
# regex; a pattern `!<regex>` wants no line matching it. (Here-strings, not `printf | grep -q`:
# under pipefail, grep -q exiting early fails the printf.)
run() {
  local expect=$1 desc=$2 rc=0 p missing='' unwanted=''
  shift 2
  local patterns=()
  while (($# > 0)) && [[ $1 != -- ]]; do patterns+=("$1"); shift; done
  shift
  out=$(env ${run_env[@]+"${run_env[@]}"} PATH="$stubs:$PATH" bash "$script" "$@" 2>&1) || rc=$?
  for p in ${patterns[@]+"${patterns[@]}"}; do
    if [[ $p == !* ]]; then
      ! grep -Eq -- "${p#!}" <<<"$out" || unwanted="$unwanted /${p#!}/"
    else
      grep -Eq -- "$p" <<<"$out" || missing="$missing /$p/"
    fi
  done
  if ((rc == expect)) && [[ -z $missing && -z $unwanted ]]; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect${missing:+; no line matching$missing}${unwanted:+; a line matching$unwanted})" "$out"
  fi
}

# logged <description> <log name> <extended regex...>: each regex matches a line of the stub log;
# a regex `!<regex>` matches none.
logged() {
  local desc=$1 name=$2 log="$STUB_DIR/$2.log" p missing=''
  shift 2
  for p in "$@"; do
    if [[ $p == !* ]]; then
      ! grep -Eq -- "${p#!}" "$log" 2>/dev/null || missing="$missing !/${p#!}/"
    else
      grep -Eq -- "$p" "$log" 2>/dev/null || missing="$missing /$p/"
    fi
  done
  if [[ -z $missing ]]; then ok "$desc"; else bad "$desc (log $name:$missing)" "$(cat "$log" 2>&1)"; fi
}

# torn_down <description>: both of the run's enclaves (named for the run: the -<T>-<pid> suffix of
# its first launch) removed after the last launch, no other enclave removed, and no `clean -a`
# after the launches (it would remove every enclave on the engine, not just the pair).
torn_down() {
  local log="$STUB_DIR/kurtosis.log" first_run last_run suffix rm_a rm_b others clean
  first_run=$(grep -n '^run --enclave' "$log" 2>/dev/null | sed -n 1p | cut -d: -f1 || true)
  last_run=$(grep -n '^run --enclave' "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  suffix=$(grep -oE '^run --enclave ethswarm-gloas-[ab]-[0-9]+-[0-9]+' "$log" 2>/dev/null |
    sed -n '1s/^run --enclave ethswarm-gloas-[ab]-//p' || true)
  rm_a=$(grep -nxF "enclave rm -f ethswarm-gloas-a-$suffix" "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  rm_b=$(grep -nxF "enclave rm -f ethswarm-gloas-b-$suffix" "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  others=$(grep '^enclave rm ' "$log" 2>/dev/null |
    grep -vxF -e "enclave rm -f ethswarm-gloas-a-$suffix" -e "enclave rm -f ethswarm-gloas-b-$suffix" || true)
  clean=$(grep -n '^clean -a$' "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  if [[ -n $suffix && -n $rm_a && -n $rm_b && -z $others ]] && ((rm_a > ${last_run:-0} && rm_b > ${last_run:-0} &&
       ${clean:-0} < ${first_run:-1})); then
    ok "$1"
  else
    bad "$1" "$(cat "$log" 2>&1)"
  fi
}

# gone <pid>: the process no longer runs (it does not exist, or it is a zombie).
gone() {
  local stat
  stat=$(ps -o stat= -p "$1" 2>/dev/null || true)
  [[ -z $stat || $stat == Z* ]]
}

T=$((NOW + 900))
logs="$repo/target/kurtosis/pair-$T"
# The pair's enclave names, as regexes: run-pair.sh names them for the run (-<T>-<its pid>).
A="ethswarm-gloas-a-$T-[0-9]+" B="ethswarm-gloas-b-$T-[0-9]+"
# name_of <a|b>: the full name the last run gave that enclave (from its first launch).
name_of() {
  grep -oE "^run --enclave ethswarm-gloas-$1-[0-9]+-[0-9]+" "$STUB_DIR/kurtosis.log" 2>/dev/null |
    sed -n '1s/^run --enclave //p' || true
}
# reaped <description> <pid file>: the process in $STUB_DIR/<pid file> is gone within 5 s (a
# survivor is reported, then killed).
reaped() {
  local f="$STUB_DIR/$2" p i=0
  if [[ ! -f $f ]]; then bad "$1 (no $2: it never started)"; return; fi
  p=$(cat "$f")
  until gone "$p"; do
    i=$((i + 1))
    if ((i > 50)); then kill -KILL "$p" 2>/dev/null || true; bad "$1 (pid $p still runs)"; return; fi
    /bin/sleep 0.1
  done
  ok "$1"
}
images=$(grep -oE '[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' "$kurtosis_dir/gloas-genesis.yaml" | sort -u)
n_images=$(printf '%s\n' "$images" | wc -l | tr -d ' ')

# --- the happy path ------------------------------------------------------------------------------

base
run 0 "a pair whose launches and check pass exits 0" \
  "^rendered $logs/gloas-genesis.yaml \(genesis_time $T\)$" \
  '^both enclaves up [0-9]+ s before genesis$' '^pair verdict: STUB$' "^run-pair: exit 0 \(logs in $logs\)$" \
  --
want_pulls=$(printf '%s\n' "$images" | sed 's/^/pull -q /')
got_pulls=$(grep '^pull ' "$STUB_DIR/docker.log" | sort -u)
if [[ $got_pulls == "$want_pulls" && $n_images -ge 7 ]]; then ok "every pinned image of the args file is pulled ($n_images)"; else bad "every pinned image is pulled" "$got_pulls"; fi
if [[ $(grep -c '^  genesis_time: ' "$logs/gloas-genesis.yaml") == 1 ]] &&
   grep -qx "  genesis_time: $T" "$logs/gloas-genesis.yaml"; then
  ok "the rendered copy has genesis_time T = now + 900"
else
  bad "the rendered copy has genesis_time T = now + 900" "$(grep -n genesis_time "$logs/gloas-genesis.yaml" 2>&1)"
fi
if diff <(grep -v '^  genesis_time: ' "$repo/testing/kurtosis/gloas-genesis.yaml") \
        <(grep -v '^  genesis_time: ' "$logs/gloas-genesis.yaml") >/dev/null; then
  ok "the rendered copy differs from the args file only in genesis_time"
else
  bad "the rendered copy differs only in genesis_time"
fi
logged "the rendered copy's directory passes the pin lint" pins "^$logs$"
pkg='github\.com/ethpandaops/ethereum-package@3416a0252e5bc25a0d31d24fea9c46707447eb08'
logged "both enclaves launch from the one rendered copy" kurtosis \
  "^run --enclave $A $pkg --args-file $logs/gloas-genesis.yaml$" \
  "^run --enclave $B $pkg --args-file $logs/gloas-genesis.yaml$"
if [[ $(head -3 "$STUB_DIR/kurtosis.log" | cut -d' ' -f1-2 | tr '\n' ' ') == "enclave ls enclave ls run --enclave " ]]; then
  ok "the pair checks the engine runs no enclave, and checks again just before the launches"
else
  bad "the pair checks the engine runs no enclave, and checks again just before the launches" "$(cat "$STUB_DIR/kurtosis.log")"
fi
logged "without --clean-engine the engine is never cleaned (only the pair's enclaves go)" kurtosis '!^clean'
check=$(cat "$STUB_DIR/check.log" 2>/dev/null || true)
if [[ $check =~ ^--pair\ --record\ $logs/genesis\.json\ $A\ $B\ @([0-9]+)$ ]] &&
   ((BASH_REMATCH[1] >= T)); then
  ok "check-devnet.sh --pair runs once, at or after genesis"
else
  bad "check-devnet.sh --pair runs once, at or after genesis" "$check"
fi
torn_down "a passing pair is torn down"
if [[ -f $logs/check.log && -f $logs/$(name_of a)-run.log && -f $logs/$(name_of b)-run.log ]] &&
   grep -q '^pair verdict: STUB$' "$logs/check.log" && grep -Eq "enclave $B$" "$logs/$(name_of b)-run.log"; then
  ok "the run and check logs are kept under target/kurtosis/pair-T"
else
  bad "the run and check logs are kept" "$(ls -la "$logs" 2>&1)"
fi

# --- the pair's enclave names: this run's own --------------------------------------------------------

# Both enclaves carry the run's T and pid, so another run (from another checkout, in the same
# second) never launches into them, and this run's teardown removes only its own.
base
run 0 "the enclaves are named for the run (ethswarm-gloas-{a,b}-<T>-<pid>)" "^launching $A and $B$" --
first=$(name_of a)
if [[ -n $first && $(name_of b) == "${first/-a-/-b-}" ]]; then ok "both enclaves of a run share its suffix"; else bad "both enclaves of a run share its suffix" "$(cat "$STUB_DIR/kurtosis.log")"; fi
base
run 0 "a second run in the same second passes too" '^run-pair: exit 0 ' --
if [[ -n $first && -n $(name_of a) && $(name_of a) != "$first" ]]; then
  ok "two runs in the same second name their enclaves apart"
else
  bad "two runs in the same second name their enclaves apart" "$first, then $(name_of a)"
fi
torn_down "the second run removes its own enclaves only"

base
run 0 "--lead 1200 renders T = now + 1200" "^rendered .*/pair-$((NOW + 1200))/gloas-genesis.yaml \(genesis_time $((NOW + 1200))\)$" -- --lead 1200

# --- a dedicated engine: no other enclave, unless --clean-engine ------------------------------------

other_enclaves() {
  printf '%s\n' 'UUID           Name             Status     Creation Time' \
    'edf1b1fe1c80   ethswarm-gloas   RUNNING    Sun, 19 Oct 2026 00:12:03 KST' \
    '0a1b2c3d4e5f   scratch          STOPPED    Sun, 19 Oct 2026 00:20:44 KST' > "$STUB_DIR/enclave-ls"
}
base
other_enclaves
run 2 "an engine that runs other enclaves is refused" \
  '^ERROR: the engine has other enclaves \(ethswarm-gloas scratch\); run-pair.sh needs an engine dedicated to this run: remove them, or pass --clean-engine to let kurtosis clean -a remove them$' --
logged "a refused engine is neither cleaned nor launched on" kurtosis '!^clean -a$' '!^run '
if [[ ! -e $STUB_DIR/docker.log ]]; then ok "a refused engine pulls nothing"; else bad "a refused engine pulls nothing"; fi

base
other_enclaves
run 0 "--clean-engine cleans an engine with other enclaves and goes on" '^run-pair: exit 0 ' -- --clean-engine
logged "--clean-engine runs kurtosis clean -a before the launches" kurtosis '^clean -a$' "^run --enclave $A "
if [[ $(grep -c '^clean -a$' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "--clean-engine cleans the engine once, never in the teardown"; else bad "--clean-engine cleans the engine once" "$(cat "$STUB_DIR/kurtosis.log")"; fi

# An enclave created after the first check (during the pulls, render and lint) is not removed
# without --clean-engine: the second listing, just before the launches, refuses it.
base
other_enclaves; mv "$STUB_DIR/enclave-ls" "$STUB_DIR/enclave-ls.2"
run 2 "an enclave that appears after the first check is refused before the launches" \
  '^ERROR: the engine has other enclaves \(ethswarm-gloas scratch\); ' '!^tearing down' --
logged "a late enclave is checked for after the pulls, then neither cleaned nor launched on" kurtosis \
  '^enclave ls$' '!^clean' '!^run ' '!^enclave rm'
if grep -q '^pull ' "$STUB_DIR/docker.log" 2>/dev/null && [[ $(cat "$STUB_DIR/ls.count") == 2 ]]; then
  ok "the second listing comes after the pulls"
else
  bad "the second listing comes after the pulls" "$(cat "$STUB_DIR/kurtosis.log")"
fi
base
echo 1 > "$STUB_DIR/ls.rc"
run 0 "--clean-engine needs no kurtosis enclave ls" '^run-pair: exit 0 ' -- --clean-engine

base
echo 1 > "$STUB_DIR/ls.rc"
run 2 "a failed kurtosis enclave ls is a setup error" '^ERROR: kurtosis enclave ls failed' --
base
printf 'something else entirely\n' > "$STUB_DIR/enclave-ls"
run 2 "an enclave ls answer without its UUID header is refused" '^ERROR: kurtosis enclave ls: no UUID header' --
base
: > "$STUB_DIR/enclave-ls"
run 2 "an empty enclave ls answer (no UUID header) is refused" '^ERROR: kurtosis enclave ls: no UUID header' --
logged "an empty enclave ls answer is neither cleaned nor launched on" kurtosis '!^clean' '!^run '
base
printf 'UUID   Name   Status   Creation Time\n' > "$STUB_DIR/enclave-ls.1"; : > "$STUB_DIR/enclave-ls.2"
run 2 "an empty second enclave ls answer is refused before the launches" '^ERROR: kurtosis enclave ls: no UUID header' --
logged "an empty second enclave ls answer launches nothing" kurtosis '!^clean' '!^run '

# --- before the launches: pull, render, pin lint -----------------------------------------------------

# Two runs in one checkout in the same second render the same T: the second must not touch the
# first's logs directory (its record of jobs, its rendered copy, its logs).
base
mkdir -p "$logs"
echo "first run" > "$logs/job-groups"; echo "first run" > "$logs/gloas-genesis.yaml"
run 2 "a logs directory that exists already (another run, the same T) is a setup error" \
  "^ERROR: $logs exists already: another run has genesis_time $T; start again$" --
if [[ $(cat "$logs/job-groups") == "first run" && $(cat "$logs/gloas-genesis.yaml") == "first run" ]]; then
  ok "the other run's job-groups and rendered copy are left alone"
else
  bad "the other run's job-groups and rendered copy are left alone" "$(ls -la "$logs")"
fi
logged "a run whose logs directory exists launches nothing" kurtosis '!^run '

base
printf 'not a directory\n' > "$repo/target"
run 2 "a logs directory that cannot be made is a setup error (exit 2)" '^ERROR: mkdir ' --
logged "an unwritable logs directory launches nothing" kurtosis '!^run '

base
printf '%s\n' "$images" | sed -n 2p > "$STUB_DIR/pull.fail"
run 2 "a failed image pull stops before any launch" '^ERROR: docker pull .* failed' --
logged "a failed pull launches nothing" kurtosis '!^run '

base
sed -E 's/@sha256:[0-9a-f]{64}//' "$kurtosis_dir/gloas-genesis.yaml" > "$repo/testing/kurtosis/gloas-genesis.yaml"
run 2 "an args file without a pinned image stops before any pull" '^ERROR: no repo:tag@sha256 image in ' --
if [[ ! -e $STUB_DIR/docker.log ]]; then ok "an args file without a pinned image pulls nothing"; else bad "an args file without a pinned image pulls nothing"; fi

base
sed 's/^  genesis_time: 0$/  genesis_time: 1/' "$kurtosis_dir/gloas-genesis.yaml" > "$repo/testing/kurtosis/gloas-genesis.yaml"
run 2 "an args file without 'genesis_time: 0' fails the render check" '^ERROR: render: ' --
logged "a failed render launches nothing" kurtosis '!^run '

base
echo 1 > "$STUB_DIR/pins.rc"
run 2 "a rendered copy that fails the pin lint stops before any launch" '^ERROR: .*check-kurtosis-pins' --
logged "a failed pin lint launches nothing" kurtosis '!^run '

base
echo 1 > "$STUB_DIR/clean.rc"
run 2 "a failed kurtosis clean stops before any launch" '^ERROR: kurtosis clean -a failed' -- --clean-engine
logged "a failed clean launches nothing" kurtosis '!^run '

base
touch "$STUB_DIR/clean.block"
SECONDS=0
run 2 "a kurtosis clean -a that hangs is stopped at its limit (300 s), a setup error" \
  '^ERROR: kurtosis clean -a timed out after 300 s$' -- --clean-engine
if ((SECONDS < 20)); then ok "the hung clean takes no real 300 s"; else bad "the hung clean takes no real 300 s (${SECONDS} s)"; fi
reaped "the hung clean is stopped" clean.pid
logged "a hung clean launches nothing" kurtosis '!^run '

# --- the launches: both succeed, both before genesis ---------------------------------------------

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc"
run 2 "a failed launch exits non-zero" "^ERROR: kurtosis run failed: $B \\(exit 1\\); see .*/$B-run\\.log$" \
  '!^both enclaves up' --
torn_down "a failed launch is torn down"
if [[ ! -e $STUB_DIR/check.log ]]; then ok "a failed launch never runs the check"; else bad "a failed launch never runs the check"; fi
if [[ $(grep -c '^run ' "$STUB_DIR/kurtosis.log") == 2 ]]; then ok "without --sequential-fallback a failed launch is not retried"; else bad "a failed launch is not retried" "$(cat "$STUB_DIR/kurtosis.log")"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-a.rc"; echo 3 > "$STUB_DIR/run.ethswarm-gloas-b.rc"
run 2 "both failed launches are named" "^ERROR: kurtosis run failed: $A \\(exit 1\\), $B \\(exit 3\\);" --
torn_down "two failed launches are torn down"

base
echo 900 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
run 4 "launches that end at genesis (T passed) exit 4" \
  "^ERROR: (the enclaves were up only at [0-9]+, [0-9]+ s after genesis \(T $T\)|kurtosis run still running at genesis \(T $T\): $A); render a later T and start again$" \
  '!^both enclaves up' --
torn_down "a late start is torn down"
if [[ ! -e $STUB_DIR/check.log ]]; then ok "a late start never runs the check"; else bad "a late start never runs the check"; fi

base
echo 885 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
run 0 "launches that end a few seconds before genesis go on" '^both enclaves up ([1-9]|1[0-5]) s before genesis$' --

base
touch "$STUB_DIR/run.ethswarm-gloas-b.block"; echo 895 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
SECONDS=0
run 4 "a launch still running at genesis is stopped, and the run exits 4" \
  "^ERROR: kurtosis run still running at genesis \\(T [0-9]+\\): $B; render a later T and start again$" \
  '!^both enclaves up' --
if ((SECONDS < 10)) && gone "$(cat "$STUB_DIR/run.ethswarm-gloas-b.pid" 2>/dev/null || echo 1)"; then ok "the outstanding launch is stopped"; else bad "the outstanding launch is stopped (${SECONDS} s)"; fi
torn_down "a launch still running at genesis is torn down"

base
echo 905 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
run 4 "launches that end after genesis exit 4" \
  '^ERROR: (the enclaves were up only at [0-9]+, [0-9]+ s after genesis|kurtosis run still running at genesis)' '!^both enclaves up' --

# --- docker stats: bounded, never fatal ---------------------------------------------------------------

base
touch "$STUB_DIR/stats.block"
SECONDS=0
run 0 "a docker stats that hangs is stopped after 30 s and the run goes on" '^warning: docker stats failed or timed out' \
  '^pair verdict: STUB$' '^run-pair: exit 0 ' --
if ((SECONDS < 20)) && gone "$(cat "$STUB_DIR/stats.pid" 2>/dev/null || echo 1)"; then ok "the hung docker stats is stopped"; else bad "the hung docker stats is stopped (${SECONDS} s)"; fi

# --- teardown: every step runs, each bounded ----------------------------------------------------------

base
touch "$STUB_DIR/rm.ethswarm-gloas-a.block"
SECONDS=0
run 2 "an enclave rm that hangs is stopped, the other enclave is still removed, and a PASS exits 2" \
  "^warning: kurtosis enclave rm -f $A failed or timed out$" '^ERROR: teardown failed' --
logged "the second enclave is removed after the first rm hangs" kurtosis "^enclave rm -f $B$"
if ((SECONDS < 30)) && gone "$(cat "$STUB_DIR/rm.ethswarm-gloas-a.pid" 2>/dev/null || echo 1)"; then ok "the hung enclave rm is stopped"; else bad "the hung enclave rm is stopped (${SECONDS} s)"; fi

# --- --sequential-fallback: a failed concurrent launch is relaunched alone, still before T ----------

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"
run 0 "--sequential-fallback relaunches the failed enclave alone and goes on" \
  "^kurtosis run failed: $B \\(exit 1\\)" "^relaunching $B alone \\((8[0-9]{2}|900) s before genesis\\)$" \
  '^both enclaves up [0-9]+ s before genesis$' '^run-pair: exit 0 ' -- --sequential-fallback
b=$(name_of b)
if [[ $(grep -c '^run --enclave ethswarm-gloas-a-' "$STUB_DIR/kurtosis.log") == 1 &&
      $(grep -c "^run --enclave $b " "$STUB_DIR/kurtosis.log") == 2 ]] &&
   [[ $(grep -A2 -xF "enclave rm -f $b" "$STUB_DIR/kurtosis.log" | sed -n 1,3p | tr '\n' ' ') == \
      "enclave rm -f $b enclave ls run --enclave $b "* ]]; then
  ok "the failed enclave is removed, confirmed gone, then relaunched; the other is kept"
else
  bad "the failed enclave is removed, confirmed gone, then relaunched" "$(cat "$STUB_DIR/kurtosis.log" 2>&1)"
fi
if [[ -f $logs/$b-run-concurrent.log && -f $logs/$b-run.log ]]; then ok "the failed concurrent launch's log is kept"; else bad "the failed concurrent launch's log is kept" "$(ls "$logs")"; fi
torn_down "a fallback pair is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-a.rc.1"; echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"
run 0 "--sequential-fallback relaunches both failed enclaves one after the other" \
  "^relaunching $A alone" "^relaunching $B alone" '^run-pair: exit 0 ' -- --sequential-fallback
if [[ $(grep '^run --enclave' "$STUB_DIR/kurtosis.log" | tail -2 | awk '{print $3}' | sed -E 's/-[0-9]+-[0-9]+$//' | tr '\n' ' ') == "ethswarm-gloas-a ethswarm-gloas-b " ]]; then
  ok "the relaunches run a, then b"
else
  bad "the relaunches run a, then b" "$(cat "$STUB_DIR/kurtosis.log")"
fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc"
run 2 "a relaunch that fails too exits 2" "^ERROR: kurtosis run failed: $B \\(exit 1\\); see .*/$B-run\\.log$" \
  -- --sequential-fallback
torn_down "a failed relaunch is torn down"
if [[ ! -e $STUB_DIR/check.log ]]; then ok "a failed relaunch never runs the check"; else bad "a failed relaunch never runs the check"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 500 > "$STUB_DIR/run.ethswarm-gloas-b.advance"
run 4 "a relaunch that ends after genesis exits 4" "^relaunching $B alone \\((3[0-9]{2}|400) s before genesis\\)$" \
  '^ERROR: (the enclaves were up only at [0-9]+, 1[0-9]{2} s after genesis|kurtosis run still running at genesis)' -- --sequential-fallback
torn_down "a late relaunch is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 800 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
run 4 "too little time left for a relaunch exits 4 without one" \
  "^ERROR: [0-9]+ s before genesis is too little to relaunch $B \\(it needs 120 s\\); render a later T and start again$" \
  -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b-' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch starts without the time for it"; else bad "no relaunch starts without the time for it"; fi
torn_down "a pair without time for a relaunch is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/rm.ethswarm-gloas-b.keep"
run 2 "a failed enclave that is still there after rm is not relaunched" \
  "^ERROR: $B still exists after kurtosis enclave rm -f; not relaunching into it$" -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b-' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch into a leftover enclave"; else bad "no relaunch into a leftover enclave"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 850 > "$STUB_DIR/rm.ethswarm-gloas-b.advance"
run 4 "the relaunch margin is checked again after the rm, just before the launch" \
  "^ERROR: [0-9]+ s before genesis is too little to relaunch $B \\(it needs 120 s\\)" -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b-' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch starts when the rm used up the margin"; else bad "no relaunch starts when the rm used up the margin" "$(cat "$STUB_DIR/kurtosis.log")"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/rm.ethswarm-gloas-b.block-once"
SECONDS=0
run 0 "a fallback enclave rm that hangs is stopped at its limit, and the relaunch goes on" \
  "^relaunching $B alone" '^run-pair: exit 0 ' -- --sequential-fallback
if ((SECONDS < 30)) && gone "$(cat "$STUB_DIR/rm.ethswarm-gloas-b.pid" 2>/dev/null || echo 1)"; then ok "the hung fallback enclave rm is stopped"; else bad "the hung fallback enclave rm is stopped (${SECONDS} s)"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/ls.block.3"
SECONDS=0
run 2 "a fallback enclave ls that hangs is stopped, and nothing is relaunched" \
  "^ERROR: kurtosis enclave ls timed out after 30 s \\(is the engine running\\?\\); cannot tell whether $B is gone, not relaunching into it$" \
  -- --sequential-fallback
if ((SECONDS < 30)) && gone "$(cat "$STUB_DIR/ls.pid" 2>/dev/null || echo 1)"; then ok "the hung fallback enclave ls is stopped"; else bad "the hung fallback enclave ls is stopped (${SECONDS} s)"; fi
if [[ $(grep -c '^run --enclave ethswarm-gloas-b-' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch after a hung enclave ls"; else bad "no relaunch after a hung enclave ls" "$(cat "$STUB_DIR/kurtosis.log")"; fi
torn_down "a pair whose fallback enclave ls hangs is torn down"

# Only a well-formed listing without the enclave proves it gone: any other failure (an engine
# error, not just a timeout) stops the run.
base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 1 > "$STUB_DIR/ls.rc.3"
run 2 "a fallback enclave ls that fails is not taken for the enclave being gone" \
  "^ERROR: kurtosis enclave ls failed \\(is the engine running\\?\\); cannot tell whether $B is gone, not relaunching into it$" \
  -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b-' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch after a failed enclave ls"; else bad "no relaunch after a failed enclave ls" "$(cat "$STUB_DIR/kurtosis.log")"; fi
torn_down "a pair whose fallback enclave ls fails is torn down"
base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; : > "$STUB_DIR/enclave-ls.3"
run 2 "a fallback enclave ls without its UUID header is not taken for the enclave being gone" \
  "^ERROR: kurtosis enclave ls: no UUID header, cannot tell which enclaves the engine has; cannot tell whether $B is gone" \
  -- --sequential-fallback

# --- every bound: enclave ls and the check ----------------------------------------------------------

base
touch "$STUB_DIR/ls.block.1"
SECONDS=0
run 2 "a kurtosis enclave ls that hangs is stopped at its limit (30 s), a setup error" \
  '^ERROR: kurtosis enclave ls timed out after 30 s \(is the engine running\?\)$' --
if ((SECONDS < 20)); then ok "the hung enclave ls takes no real 30 s"; else bad "the hung enclave ls takes no real 30 s (${SECONDS} s)"; fi
reaped "the hung enclave ls is stopped" ls.pid
logged "a hung enclave ls launches nothing" kurtosis '!^run '
if [[ ! -e $STUB_DIR/docker.log ]]; then ok "a hung enclave ls pulls nothing"; else bad "a hung enclave ls pulls nothing"; fi

base
echo 4000 > "$STUB_DIR/check.advance"
SECONDS=0
run 2 "a check that runs past its limit (3600 s) is stopped, and the run exits 2" \
  '^ERROR: check-devnet.sh ran past its limit of 3600 s and was stopped$' '^run-pair: exit 2 ' --
if ((SECONDS < 20)); then ok "the check past its limit is stopped at once"; else bad "the check past its limit is stopped at once (${SECONDS} s)"; fi
reaped "the check that ran past its limit is gone" check.pid
torn_down "a check past its limit is torn down"

# --- every job's process group: swept when its leader ends, recorded while it runs ----------------

base
touch "$STUB_DIR/check.orphan"
run 0 "a check that leaves a TERM-ignoring process in its group still passes" '^run-pair: exit 0 ' --
reaped "what a finished check left in its process group is stopped" orphan.pid
base
touch "$STUB_DIR/run.ethswarm-gloas-a.orphan"
run 0 "a launch that leaves a TERM-ignoring process in its group still passes" '^run-pair: exit 0 ' --
reaped "what a finished launch left in its process group is stopped" run.ethswarm-gloas-a.orphan.pid
if [[ ! -e $logs/job-groups ]]; then ok "a run that ends leaves no job-groups record"; else bad "a run that ends leaves no job-groups record" "$(cat "$logs/job-groups")"; fi

# A launch that ends is swept at once, not when the other launch ends: b, still running, sees what a
# left in its group gone.
base
touch "$STUB_DIR/run.ethswarm-gloas-a.leftover"
echo run.ethswarm-gloas-a.leftover.pid > "$STUB_DIR/run.ethswarm-gloas-b.await"
run 0 "a pair whose first launch leaves a process in its group passes" '^run-pair: exit 0 ' --
if [[ $(cat "$STUB_DIR/run.ethswarm-gloas-b.saw" 2>/dev/null) == gone ]]; then
  ok "what a finished launch left is stopped while the other launch still runs"
else
  bad "what a finished launch left is stopped while the other launch still runs" "b saw: $(cat "$STUB_DIR/run.ethswarm-gloas-b.saw" 2>&1)"
fi
reaped "the finished launch's leftover is gone" run.ethswarm-gloas-a.leftover.pid

# A job's end is what bash saw of it, never a pid lookup: a pid that another process takes the
# moment the job ends must not count as the job still running (no false exit 4, no stop of it).
base
touch "$STUB_DIR/ps.reused"
SECONDS=0
run 0 "a pair whose jobs' pids are taken by other processes as they end still passes" \
  '^both enclaves up [0-9]+ s before genesis$' '^run-pair: exit 0 ' --
if ((SECONDS < 30)); then ok "the jobs are seen to end at once"; else bad "the jobs are seen to end at once (${SECONDS} s)"; fi

# kill_logged <script> <copy>: a copy of the script whose every `kill` is logged to
# $STUB_DIR/kill.log (its arguments, one call a line) before it runs. A kill that names 0 or 1 (a
# pid or a group) is only logged: a script under test that got it wrong must not signal its own
# group, or every process of the user.
kill_logged() {
  {
    sed -n '1,/^set -euo pipefail$/p' "$1"
    # shellcheck disable=SC2028 # the line is shell source for the copy, not output
    echo 'kill() { printf "%s\n" "$*" >> "$STUB_DIR/kill.log"; case " $* " in *" 0 "* | *" -0 "* | *" 1 "* | *" -1 "*) return 0 ;; esac; builtin kill "$@"; }'
    sed '1,/^set -euo pipefail$/d' "$1"
  } > "$2"
}

# Once bash has reaped a job's leader, its process group id is a number another process may take:
# when the group has emptied, a new process with that pid can lead a group of its own. Launch a
# ends at once and its pid goes to such a process (ps.reuse): that group is never signalled,
# while what launch b left in its own group still gets TERM.
base
touch "$STUB_DIR/run.ethswarm-gloas-a.leader" "$STUB_DIR/run.ethswarm-gloas-b.leader" \
  "$STUB_DIR/run.ethswarm-gloas-b.leftover"
echo run.ethswarm-gloas-a.leader.pid > "$STUB_DIR/ps.reuse"
kill_logged "$kurtosis_dir/run-pair.sh" "$script"
run 0 "a pair whose finished launch's group id another process's group takes still passes" '^run-pair: exit 0 ' --
rm -f "$STUB_DIR/ps.reuse"
ga=$(cat "$STUB_DIR/run.ethswarm-gloas-a.leader.pid" 2>/dev/null || echo none)
gb=$(cat "$STUB_DIR/run.ethswarm-gloas-b.leader.pid" 2>/dev/null || echo none)
logged "a group whose id a live process holds as its pid is never signalled" kill "!-- -$ga$" "!^-[A-Z]+ $ga$"
logged "a finished launch's own group, still holding its id, gets TERM" kill "^-TERM -- -$gb$"
reaped "what the other launch left in its group is stopped" run.ethswarm-gloas-b.leftover.pid

# --- the check's wrapper: no inherited shell options ---------------------------------------------

# SHELLOPTS exported (errexit and pipefail in it) reaches every bash the script starts; the check's
# wrapper must still read the check's own exit code, so a PASS whose check.log cannot be written is
# a 2, not tee's 1.
base
touch "$STUB_DIR/tee.fail"
run_env=("SHELLOPTS=$SHELLOPTS")
if [[ $SHELLOPTS == *errexit*pipefail* ]]; then ok "the test's SHELLOPTS has errexit and pipefail"; else bad "the test's SHELLOPTS has errexit and pipefail" "$SHELLOPTS"; fi
run 2 "with SHELLOPTS exported, a passing check whose tee fails still exits 2" \
  '^ERROR: tee .*/check.log failed$' '^run-pair: exit 2 ' --
run_env=()

# --- a terminal with tostop --------------------------------------------------------------------

# With `stty tostop` the kernel stops a background process group that writes to its terminal
# (SIGTTOU). The check's tee writes to the terminal from the check's own process group, so the run
# must not stop there: on a pseudo-terminal with tostop set it must finish (exit 0, the check's
# output on the terminal) within 20 s. pty_run kills every process of the run's session at the
# limit. The run goes once with the bash on PATH and once with /bin/bash when that is another
# bash (bash 3.2 on macOS): the script and its check wrapper run on the bash that started them, and
# bash 3.2 sets SIGTTOU back to its default in every child it forks, even one ignored on entry.
pty_run='
import os, pty, select, signal, subprocess, sys, termios, time
limit = float(sys.argv[1])
pid, fd = pty.fork()
if pid == 0:
    try:
        attrs = termios.tcgetattr(0)
        attrs[3] |= termios.TOSTOP
        termios.tcsetattr(0, termios.TCSANOW, attrs)
        os.execvp(sys.argv[2], sys.argv[2:])
    finally:
        os._exit(127)
out = bytearray()
deadline = time.monotonic() + limit
status = None
while True:
    if status is None:
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
    ready, _, _ = select.select([fd], [], [], 0.1)
    data = b""
    if ready:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
    if data:
        out += data
        continue
    if status is not None:
        break
    if time.monotonic() > deadline:
        listing = subprocess.run(["ps", "-A", "-o", "pid="], capture_output=True, text=True).stdout
        for word in listing.split():
            try:
                if os.getsid(int(word)) == pid:
                    os.kill(int(word), signal.SIGKILL)
            except OSError:
                pass
        os.waitpid(pid, 0)
        sys.stdout.write(out.decode(errors="replace").replace("\r\n", "\n"))
        print("pty_run: still running after the limit; killed")
        sys.exit(124)
sys.stdout.write(out.decode(errors="replace").replace("\r\n", "\n"))
sys.exit(os.waitstatus_to_exitcode(status))
'
tostop_bashes=("$(command -v bash)")
if [[ -x /bin/bash && ! /bin/bash -ef ${tostop_bashes[0]} ]]; then tostop_bashes+=(/bin/bash); fi
for sh in "${tostop_bashes[@]}"; do
  base
  rc=0
  version=$("$sh" -c 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"')
  out=$(PATH="$stubs:$PATH" python3 -I -c "$pty_run" 20 "$sh" "$script" 2>&1) || rc=$?
  if ((rc == 0)) && grep -q '^pair verdict: STUB' <<<"$out" && grep -q '^run-pair: exit 0 ' <<<"$out"; then
    ok "on a terminal with tostop, the check's output does not stop the run ($sh, bash $version)"
  else
    bad "on a terminal with tostop, the check's output does not stop the run ($sh, bash $version; exit $rc)" "$out"
  fi
done

# --- the check's exit code ------------------------------------------------------------------------

for code in 1 2 3; do
  base
  echo "$code" > "$STUB_DIR/check.rc"
  run "$code" "a check that exits $code makes the run exit $code" "^run-pair: exit $code " --
  torn_down "a check that exits $code is torn down"
done

# A check.log that tee cannot write must not hide the check's own code.
for code in 3 0; do
  base
  echo "$code" > "$STUB_DIR/check.rc"
  touch "$STUB_DIR/tee.fail"
  want=$code; if ((code == 0)); then want=2; fi
  run "$want" "a check that exits $code with a failing tee exits $want" "^run-pair: exit $want " --
done

base
echo 1 > "$STUB_DIR/rm.ethswarm-gloas-b.rc"
run 2 "a passing pair whose teardown fails exits 2" "^warning: kurtosis enclave rm -f $B failed or timed out$" \
  '^ERROR: teardown failed' --
base
echo 1 > "$STUB_DIR/check.rc"; echo 1 > "$STUB_DIR/rm.ethswarm-gloas-b.rc"
run 1 "a failed teardown does not hide a failed check" "^warning: kurtosis enclave rm -f $B failed or timed out$" --

# --- an interrupt tears down ---------------------------------------------------------------------

# interrupt <expect-exit> <description> <ready condition> <signal> <target> <pid file...>
#   [-- <args...>]: starts run-pair.sh (with the args) in its own process group, waits (up to
#   10 s) until the shell condition holds, and sends the signal. Target `group` sends it to the
#   whole group (a Ctrl-C), `script` to the script alone (a kill), and `piped` runs
#   `run-pair.sh | cat` (cat writing bg.piped, apart from the launcher's bg.out) and signals the
#   group, so the reader dies and the script's stdout is a broken pipe; `none` sends no signal (the
#   ready condition acts on the run, and the signal is only a placeholder). Wants the exit code within
#   20 s of the signal (the stubs block for 30-60 s, so a hang still shows), and every process in
#   the pid files gone within 5 s more (a survivor is reported, then killed). A watchdog KILLs the
#   script's group 40 s after the signal. The NAME=value entries of run_env go into the
#   environment of the launcher, and so of the script.
interrupt() {
  local expect=$1 desc=$2 ready=$3 sig=$4 target=$5 pid i=0 rc=0 alive='' watchdog f p cmd elapsed
  local pid_files=()
  shift 5
  while (($# > 0)) && [[ $1 != -- ]]; do pid_files+=("$1"); shift; done
  if (($# > 0)); then shift; fi
  rm -f "$tmp/bg.rc" "$tmp/bg.piped"
  if [[ $target == piped ]]; then
    cmd='rc_file=$1 out=$2; shift 2; { bash "$0" "$@"; echo $? > "$rc_file"; } | cat > "$out"'
  else
    cmd='rc_file=$1; shift 2; bash "$0" "$@"; echo $? > "$rc_file"'
  fi
  # A background job of a non-interactive shell starts with INT ignored, and bash cannot trap a
  # signal ignored on entry, so the script starts through python: INT and PIPE back to default
  # (as from a terminal), its own process group (the pid is the group id), then exec.
  env ${run_env[@]+"${run_env[@]}"} PATH="$stubs:$PATH" python3 -I -c '
import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
os.setpgid(0, 0)
os.execvp(sys.argv[1], sys.argv[1:])' bash -c "$cmd" "$script" "$tmp/bg.rc" "$tmp/bg.piped" "$@" > "$tmp/bg.out" 2>&1 &
  pid=$!
  until eval "$ready"; do
    i=$((i + 1))
    if ((i > 100)); then break; fi
    /bin/sleep 0.1
  done
  ( /bin/sleep 40; kill -KILL -- -"$pid" ) >/dev/null 2>&1 &
  watchdog=$!
  if [[ $target == none ]]; then
    :
  elif [[ $target == script ]]; then
    kill -"$sig" "$(pgrep -P "$pid")" || true   # none: the script has already ended
  else
    kill -"$sig" -- -"$pid"
  fi
  SECONDS=0
  wait "$pid" || true
  elapsed=$SECONDS
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  rc=$(cat "$tmp/bg.rc" 2>/dev/null || echo none)
  for f in "${pid_files[@]}"; do
    if [[ ! -f $STUB_DIR/$f ]]; then alive="$alive no:$f"; continue; fi
    p=$(cat "$STUB_DIR/$f")
    i=0
    until gone "$p"; do
      i=$((i + 1))
      if ((i > 50)); then alive="$alive $f"; kill -KILL "$p" 2>/dev/null || true; break; fi
      /bin/sleep 0.1
    done
  done
  if [[ $rc == "$expect" ]] && ((elapsed < 20)) && [[ -z $alive ]] &&
     { [[ $target == piped ]] || grep -q "^run-pair: exit $expect " "$tmp/bg.out"; }; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect, ${elapsed} s${alive:+, still running or never started:$alive})" \
      "$(cat "$tmp/bg.out"; if [[ -f $tmp/bg.piped ]]; then echo '-- the piped stdout:'; cat "$tmp/bg.piped"; fi)"
  fi
}

base
touch "$STUB_DIR/run.ethswarm-gloas-a.block" "$STUB_DIR/run.ethswarm-gloas-b.block"
interrupt 130 "Ctrl-C (INT to the process group) during the launches exits 130 and stops both" \
  '[[ -f $STUB_DIR/run.ethswarm-gloas-a.pid && -f $STUB_DIR/run.ethswarm-gloas-b.pid ]]' INT group \
  run.ethswarm-gloas-a.pid run.ethswarm-gloas-b.pid
torn_down "an interrupt during the launches is torn down"

base
touch "$STUB_DIR/sleep.block"
interrupt 143 "TERM while waiting for genesis exits 143 at once" '[[ -f $STUB_DIR/sleep.pid ]]' TERM script sleep.pid
torn_down "an interrupt while waiting for genesis is torn down"

base
touch "$STUB_DIR/check.block"
interrupt 130 "INT to the script during the check exits 130 and stops the check" '[[ -f $STUB_DIR/check.pid ]]' INT script check.pid
torn_down "an interrupt during the check is torn down"

base
touch "$STUB_DIR/sleep.block"
interrupt 129 "HUP (the terminal closed) while waiting for genesis exits 129" '[[ -f $STUB_DIR/sleep.pid ]]' HUP script sleep.pid
torn_down "a hangup is torn down"

base
touch "$STUB_DIR/check.block"
interrupt 130 "Ctrl-C with stdout piped to a reader that dies too still exits 130" '[[ -f $STUB_DIR/check.pid ]]' INT piped check.pid
torn_down "an interrupt whose stdout is a broken pipe still removes both enclaves"

base
touch "$STUB_DIR/check.block" "$STUB_DIR/check.stubborn"
interrupt 143 "TERM during the check also stops a descendant that ignores TERM" \
  '[[ -f $STUB_DIR/check.pid && -f $STUB_DIR/stubborn.pid ]]' TERM script check.pid stubborn.pid
torn_down "an interrupt with a TERM-ignoring descendant is torn down"

base
touch "$STUB_DIR/check.block" "$STUB_DIR/check.orphan"
interrupt 143 "TERM during the check KILLs a TERM-ignoring grandchild that left the process tree" \
  '[[ -f $STUB_DIR/check.pid && -f $STUB_DIR/orphan.pid ]]' TERM script check.pid orphan.pid
torn_down "an interrupt with an orphaned descendant is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/rm.ethswarm-gloas-b.block-once"
interrupt 143 "TERM while a fallback enclave rm hangs exits 143 at once and stops the rm" \
  '[[ -f $STUB_DIR/rm.ethswarm-gloas-b.pid ]]' TERM script rm.ethswarm-gloas-b.pid -- --sequential-fallback
torn_down "a TERM during the fallback is torn down"

# The record of the running jobs' process groups, for a run killed with SIGKILL: while the check
# runs, job-groups holds the check's process group and nothing else; the teardown removes it.
base
touch "$STUB_DIR/check.block"
rm -f "$tmp/check.pgid" "$tmp/job-groups.seen" "$tmp/job-groups.link"
interrupt 143 "TERM during the check, with its process group on record, exits 143" \
  '[[ -f $STUB_DIR/check.pid ]] && ps -o pgid= -p "$(cat "$STUB_DIR/check.pid")" > "$tmp/check.pgid" && cp "$logs/job-groups" "$tmp/job-groups.seen" && ln "$logs/job-groups" "$tmp/job-groups.link"' \
  TERM script check.pid
if [[ -s $tmp/job-groups.seen && $(tr -d ' ' < "$tmp/check.pgid") == "$(cat "$tmp/job-groups.seen")" ]]; then
  ok "while the check runs, job-groups holds its process group, and nothing else"
else
  bad "while the check runs, job-groups holds its process group" "check pgid: $(cat "$tmp/check.pgid" 2>&1); job-groups: $(cat "$tmp/job-groups.seen" 2>&1)"
fi
if [[ ! -e $logs/job-groups ]]; then ok "the teardown removes the job-groups record"; else bad "the teardown removes the job-groups record"; fi
# A hard link to the record taken while the check ran still holds the check's group: each new
# list replaced the file (written apart, then renamed), so it was never truncated in place, and a
# SIGKILL can never leave a partial record.
if [[ -s $tmp/job-groups.link && $(cat "$tmp/job-groups.link") == "$(cat "$tmp/job-groups.seen")" ]]; then
  ok "job-groups is replaced whole, never rewritten in place"
else
  bad "job-groups is replaced whole, never rewritten in place" "link: $(cat "$tmp/job-groups.link" 2>&1)"
fi

# A FIFO put in place of job-groups must not block the run: the record is written to a new file of
# its own and renamed over it, never opened.
base
touch "$STUB_DIR/check.block"
interrupt 143 "TERM during the check, with a FIFO in place of job-groups, still exits 143" \
  '[[ -f $STUB_DIR/check.pid ]] && rm -f "$logs/job-groups" && mkfifo "$logs/job-groups"' TERM script check.pid
torn_down "a run whose job-groups was a FIFO is torn down"

# A job stopped with SIGSTOP (here the check's, its process group from job-groups) has not ended: it
# still gets TERM (and CONT, so the TERM lands), and the KILL if it outlives the grace period. bash
# tells a stopped job apart only with job control (SHELLOPTS=monitor here; bash 3.2 sees no stop
# without a terminal, so it still shows the job running).
base
touch "$STUB_DIR/check.block"
run_env=(SHELLOPTS=monitor)
interrupt 143 "TERM with the check's job stopped (SIGSTOP) exits 143 and stops the check" \
  '[[ -f $STUB_DIR/check.pid ]] && kill -STOP -- "-$(cat "$logs/job-groups")" && /bin/sleep 0.5' \
  TERM script check.pid
run_env=()
torn_down "a run whose check was stopped is torn down"

# The wait for genesis polls the job table, so a genesis sleep stopped with SIGSTOP is no failure
# (with job control, `wait` would return at once with 128 + the signal, and errexit would end the
# run): a sleep continued later ends as it would have, and one still stopped at T is stopped, and
# the check runs. The second run moves the fake clock to T while the sleep is stopped.
base
echo 2 > "$STUB_DIR/sleep.block"
run_env=(SHELLOPTS=monitor)
interrupt 0 "a genesis sleep stopped (SIGSTOP), then continued, does not end the run" \
  '[[ -f $STUB_DIR/sleep.pid ]] && kill -STOP "$(cat "$STUB_DIR/sleep.pid")" && /bin/sleep 0.5 && kill -CONT "$(cat "$STUB_DIR/sleep.pid")"' \
  TERM none sleep.pid
logged "the check runs after a genesis sleep that was stopped and continued" check "^--pair .* @[0-9]+$"
base
touch "$STUB_DIR/sleep.block"
interrupt 0 "a genesis sleep still stopped (SIGSTOP) at genesis is stopped, and the check runs" \
  '[[ -f $STUB_DIR/sleep.pid ]] && kill -STOP "$(cat "$STUB_DIR/sleep.pid")" && echo "$T" > "$STUB_DIR/now"' \
  TERM none sleep.pid
run_env=()
logged "the check runs at genesis after a genesis sleep that stayed stopped" check "^--pair .* @$T$"
torn_down "a run whose genesis sleep stayed stopped is torn down"

# A process list that names pid 1 as a job's descendant (as the ps stub does here) must never turn
# into a signal to pid 1 or to group 1 (kill -- -1 reaches every process of the user).
base
touch "$STUB_DIR/check.block"
echo "1 @check.pid fake-init" > "$STUB_DIR/ps.fake"
kill_logged "$kurtosis_dir/run-pair.sh" "$script"
interrupt 143 "TERM during the check, with pid 1 listed as the check's child, exits 143" \
  '[[ -f $STUB_DIR/check.pid ]]' TERM script check.pid
rm -f "$STUB_DIR/ps.fake"
logged "pid 1 and group 1 never get a signal from the teardown" kill '^-TERM -- -[0-9]+$' '!-- -1$' '!^-[A-Z]+ 1$'

# A signal that lands between a job's start and the record of its pid must not leave the job
# untracked. No stub can hit that window reliably, so a copy of the script sends itself TERM right
# after each job start once both listings are done (so at the first launch): the launch must still
# be stopped with the rest.
base
touch "$STUB_DIR/run.ethswarm-gloas-a.block" "$STUB_DIR/run.ethswarm-gloas-b.block"
awk '{ print } /^[[:space:]]*in_group .*&[[:space:]]*$/ { print "if [[ $(cat \"$STUB_DIR/ls.count\" 2>/dev/null) == 2 ]]; then kill -TERM $$; fi" }' \
  "$kurtosis_dir/run-pair.sh" > "$script"
if grep -q 'kill -TERM \$\$' "$script"; then ok "the copy sends TERM right after a job start"; else bad "the copy sends TERM right after a job start"; fi
run 143 "TERM right after a launch starts exits 143" '^run-pair: exit 143 ' --
/bin/sleep 0.5
left=$(pgrep -f "$stubs/kurtosis run" || true)
if [[ -z $left ]]; then
  ok "a launch started just before a signal is stopped too"
else
  bad "a launch started just before a signal is stopped too (still running: $(tr '\n' ' ' <<<"$left"))"
  for p in $left; do kill -KILL "$p" 2>/dev/null || true; done
fi
# The launch may be stopped before the stub logs it, so the removals are matched by name.
logged "a TERM right after a launch starts removes both enclaves" kurtosis "^enclave rm -f $A$" "^enclave rm -f $B$" '!^clean'


# A signal held while a job starts, then a second one right after the hold ends, must not leave the
# held exit pending for the teardown: the teardown's own job starts would act on it and skip the
# enclave removals.
base
touch "$STUB_DIR/run.ethswarm-gloas-a.block" "$STUB_DIR/run.ethswarm-gloas-b.block"
awk '{ print }
  /^[[:space:]]*in_group .*&[[:space:]]*$/ || /^[[:space:]]*held=0$/ {
    print "if [[ $(cat \"$STUB_DIR/ls.count\" 2>/dev/null) == 2 ]]; then kill -TERM $$; fi"
  }' "$kurtosis_dir/run-pair.sh" > "$script"
if [[ $(grep -c 'kill -TERM \$\$' "$script") -ge 2 ]]; then ok "the copy sends TERM in the hold and right after it"; else bad "the copy sends TERM in the hold and right after it"; fi
run 143 "a second TERM right after a held one exits 143" '^run-pair: exit 143 ' --
logged "a second TERM right after a held one still removes both enclaves" kurtosis "^enclave rm -f $A$" "^enclave rm -f $B$"
left=$(pgrep -f "$stubs/kurtosis run" || true)
if [[ -z $left ]]; then ok "no launch outlives the two signals"; else bad "no launch outlives the two signals ($(tr '\n' ' ' <<<"$left"))"; for p in $left; do kill -KILL "$p" 2>/dev/null || true; done; fi

# A signal that lands in the teardown before its traps are reset would run `exit` inside it and
# skip the enclave removals; no stub can hit that window reliably, so this reads the script: the
# teardown's first statement ignores the signals.
first=$(awk '/^teardown\(\) \{$/ { getline; print; exit }' "$kurtosis_dir/run-pair.sh")
if [[ $first == "  trap '' INT TERM HUP PIPE" ]]; then
  ok "the teardown ignores INT, TERM, HUP and PIPE before anything else"
else
  bad "the teardown ignores INT, TERM, HUP and PIPE before anything else" "first statement: $first"
fi

# --- --keep-on-pass: a PASS leaves the pair up for the export ----------------------------------------

base
run 0 "--keep-on-pass leaves a passing pair running" "^kept $A $B running \\(--keep-on-pass\\); tear down with:$" \
  "^  kurtosis enclave rm -f $A; kurtosis enclave rm -f $B$" \
  '!^tearing down' -- --keep-on-pass
logged "a kept pair is not removed" kurtosis '!^enclave rm' "^run --enclave $B "
logged "a kept pair's engine is never cleaned" kurtosis '!^clean'

for code in 1 3; do
  base
  echo "$code" > "$STUB_DIR/check.rc"
  run "$code" "--keep-on-pass still tears down a check that exits $code" '^tearing down' '!^kept ' -- --keep-on-pass
  torn_down "--keep-on-pass with a check exit $code is torn down"
done

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-a.rc"
run 2 "--keep-on-pass still tears down a failed launch" '^tearing down' -- --keep-on-pass
torn_down "--keep-on-pass with a failed launch is torn down"

# --- stop-killed-run.sh: what a run killed with SIGKILL left running ---------------------------------

# A process group leader for the helper to find: `bash leader.sh <name> <tag> [stubborn|deaf]`
# writes its pid to $STUB_DIR/<name>.pid (with `stubborn`, after it starts a child in its group
# that ignores TERM, its pid in $STUB_DIR/<name>.child.pid; with `deaf`, the leader itself ignores
# TERM); <tag> is only there to be on its command line. Each runs for at most 60 s.
cat > "$tmp/leader.sh" <<'SH'
name=$1
if [[ ${3:-} == stubborn ]]; then
  bash -c 'trap "" TERM; echo $$ > "$STUB_DIR/$0.child.pid"; for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done' "$name" &
  for ((i = 0; i < 50; i++)); do if [[ -f $STUB_DIR/$name.child.pid ]]; then break; fi; /bin/sleep 0.1; done
fi
if [[ ${3:-} == deaf ]]; then trap '' TERM; fi
echo $$ > "$STUB_DIR/$name.pid"
for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
SH
# group <name> <tag> [stubborn|deaf]: starts leader.sh as the leader of a new process group, apart
# from this shell (an orphan, so init reaps it once it ends), and waits (up to 5 s) for its pid
# file.
group() {
  local i
  ( python3 -I -c 'import os, sys
os.setpgid(0, 0)
os.execvp(sys.argv[1], sys.argv[1:])' bash "$tmp/leader.sh" "$@" & ) >/dev/null 2>&1
  for ((i = 0; i < 50; i++)); do if [[ -f $STUB_DIR/$1.pid ]]; then return; fi; /bin/sleep 0.1; done
}
# alive <pid file>: the process in $STUB_DIR/<pid file> still runs.
alive() { [[ -f $STUB_DIR/$1 ]] && ! gone "$(cat "$STUB_DIR/$1")"; }
# end_groups <pid file...>: KILL to the process group each leader led.
end_groups() {
  local f
  for f in "$@"; do
    if [[ -f $STUB_DIR/$f ]]; then kill -KILL -- "-$(cat "$STUB_DIR/$f")" 2>/dev/null || true; fi
  done
}
# helper_run <expect-exit> <description> <pattern...> -- <args...>: runs the helper copy (the
# NAME=value entries of run_env in its environment, the stubs on PATH) and wants the exit code and
# a line matching each extended regex (`!<regex>`: no line matching it).
helper_run() {
  local expect=$1 desc=$2 rc=0 p missing='' unwanted=''
  shift 2
  local patterns=()
  while (($# > 0)) && [[ $1 != -- ]]; do patterns+=("$1"); shift; done
  shift
  out=$(env ${run_env[@]+"${run_env[@]}"} PATH="$stubs:$PATH" bash "$helper" "$@" 2>&1) || rc=$?
  for p in ${patterns[@]+"${patterns[@]}"}; do
    if [[ $p == !* ]]; then
      ! grep -Eq -- "${p#!}" <<<"$out" || unwanted="$unwanted /${p#!}/"
    else
      grep -Eq -- "$p" <<<"$out" || missing="$missing /$p/"
    fi
  done
  if ((rc == expect)) && [[ -z $missing && -z $unwanted ]]; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect${missing:+; no line matching$missing}${unwanted:+; a line matching$unwanted})" "$out"
  fi
}

helper="$tmp/stop-killed-run.sh"
kill_logged "$kurtosis_dir/stop-killed-run.sh" "$helper"
killed_run=1790000900-4242
killed="$tmp/killed"

# The killed run's record lists: the run's launch, whose leader dies on TERM while a child ignores
# it (the KILL must still reach the child); the run's check, whose leader ignores TERM (it gets the
# KILL); another run's job, a job of a run whose id has the killed run's as a prefix (-42420),
# and one whose command line has the run's enclave name inside a longer word (-x.log), all never
# touched; and a run's job whose leader dies on TERM and whose pid then passes to another
# process's group (ps.reuse), which must get no KILL. A line that is no pid, pid 0 and
# pid 1 (which ps here reports as a leader that names the run: kill -- -1 would reach every
# process of the user) are skipped.
base
rm -rf "$killed"; mkdir -p "$killed"
group kr.a "ethswarm-gloas-a-$killed_run" stubborn
group kr.deaf "ethswarm-gloas-b-$killed_run" deaf
group kr.other "ethswarm-gloas-a-1790000900-4343"
group kr.longer "ethswarm-gloas-a-1790000900-42420"
group kr.suffix "ethswarm-gloas-a-$killed_run-x.log"
group kr.b "ethswarm-gloas-b-$killed_run"
ka=$(cat "$STUB_DIR/kr.a.pid") kd=$(cat "$STUB_DIR/kr.deaf.pid") ko=$(cat "$STUB_DIR/kr.other.pid")
kl=$(cat "$STUB_DIR/kr.longer.pid") ks=$(cat "$STUB_DIR/kr.suffix.pid") kb=$(cat "$STUB_DIR/kr.b.pid")
printf '%s\n' "$ka" not-a-pid 0 1 "$kd" "$ko" "$kl" "$ks" "$kb" > "$killed/job-groups"
echo kr.b.pid > "$STUB_DIR/ps.reuse"
echo "1 0 kurtosis run --enclave ethswarm-gloas-a-$killed_run" > "$STUB_DIR/ps.fake"
helper_run 0 "stop-killed-run.sh --list lists the run's groups only" \
  "^group $ka:" "^group $kd:" "^group $kb:" "!^group $ko:" "!^group $kl:" "!^group $ks:" '!^group 1:' -- --list "$killed" "$killed_run"
if [[ ! -e $STUB_DIR/kill.log ]] && alive kr.a.pid && alive kr.a.child.pid && alive kr.deaf.pid && alive kr.b.pid; then
  ok "stop-killed-run.sh --list signals nothing"
else
  bad "stop-killed-run.sh --list signals nothing" "$(cat "$STUB_DIR/kill.log" 2>&1)"
fi
helper_run 0 "stop-killed-run.sh stops a killed run's groups (exit 0)" "^sent KILL to " -- "$killed" "$killed_run"
reaped "a TERM-ignoring child whose group leader TERM ended still gets the KILL" kr.a.child.pid
reaped "a group leader that ignores TERM gets the KILL" kr.deaf.pid
logged "the run's groups get TERM, and KILL only while they still hold their id" kill \
  "^-TERM -- -$ka$" "^-KILL -- -$ka$" "^-TERM -- -$kd$" "^-KILL -- -$kd$" "^-TERM -- -$kb$" "!^-KILL -- -$kb$" \
  "!-- -$ko$" '!-- -0$'
logged "a run whose id has the killed run's as a prefix, or whose name holds it, gets no signal" kill \
  "!-- -$kl$" "!-- -$ks$"
logged "pid 1 and group 1 never get a signal" kill '!-- -1$' '!^-[A-Z]+ 1$'
if alive kr.other.pid && alive kr.longer.pid && alive kr.suffix.pid; then ok "other runs' recorded groups are left alone"; else bad "other runs' recorded groups are left alone"; fi
rm -f "$STUB_DIR/ps.reuse" "$STUB_DIR/ps.fake"
end_groups kr.a.pid kr.deaf.pid kr.other.pid kr.longer.pid kr.suffix.pid kr.b.pid

# The start time saved for a group and the one read before the KILL both come from ps under
# LC_ALL=C: macOS words lstart by the locale (seven words under ko_KR.UTF-8, four under
# ja_JP.UTF-8), and a start that never matched would leave a leader that ignores TERM running.
base
touch "$STUB_DIR/ps.locale"
lst=$(LC_ALL=ko_KR.UTF-8 PATH="$stubs:$PATH" ps -o lstart= -p $$ 2>/dev/null | wc -w | tr -d ' ')
if [[ $lst == 7 ]]; then ok "the ps stub words lstart in seven under ko_KR.UTF-8"; else bad "the ps stub words lstart in seven under ko_KR.UTF-8 ($lst words)"; fi
rm -rf "$killed"; mkdir -p "$killed"
group kr.deaf "ethswarm-gloas-a-$killed_run" deaf
kd=$(cat "$STUB_DIR/kr.deaf.pid")
echo "$kd" > "$killed/job-groups"
run_env=(LC_ALL=ko_KR.UTF-8 LANG=ko_KR.UTF-8)
helper_run 0 "under ko_KR.UTF-8, stop-killed-run.sh still stops a TERM-ignoring leader" "^sent KILL to $kd$" -- "$killed" "$killed_run"
run_env=()
reaped "under ko_KR.UTF-8, a group leader that ignores TERM gets the KILL" kr.deaf.pid
end_groups kr.deaf.pid

# An exported COLUMNS cuts ps's command column (Linux procps does so even into a pipe): the
# helper asks for unlimited width (-ww), or it would see no run on the leader's command line.
base
COLUMNS=20 PATH="$stubs:$PATH" ps -o command= -p $$ > "$tmp/ps.cut"
if (($(wc -c < "$tmp/ps.cut") <= 21)); then ok "the ps stub cuts the command at an exported COLUMNS"; else bad "the ps stub cuts the command at an exported COLUMNS" "$(cat "$tmp/ps.cut")"; fi
rm -rf "$killed"; mkdir -p "$killed"
group kr.wide "ethswarm-gloas-a-$killed_run"
kw=$(cat "$STUB_DIR/kr.wide.pid")
echo "$kw" > "$killed/job-groups"
run_env=(COLUMNS=20)
helper_run 0 "with COLUMNS=20 exported, stop-killed-run.sh still finds and stops the run's group" \
  "^group $kw:" '!^no recorded group' -- "$killed" "$killed_run"
run_env=()
reaped "with COLUMNS=20 exported, the run's group is stopped" kr.wide.pid
end_groups kr.wide.pid

# The helper never signals its own process group, nor itself: run from a group whose leader names
# the run, and as such a leader (exec -a puts the run's name on its own command line).
base
rm -rf "$killed"; mkdir -p "$killed"
for how in 'bash "$0" "$1" "$2"; exit $?' 'exec -a "$3" bash "$0" "$1" "$2"'; do
  rc=0
  out=$(PATH="$stubs:$PATH" python3 -I -c 'import os, sys
os.setpgid(0, 0)
os.execvp(sys.argv[1], sys.argv[1:])' bash -c 'echo $$ > "$1/job-groups"; '"$how" "$helper" "$killed" "$killed_run" \
    "ethswarm-gloas-a-$killed_run" 2>&1) || rc=$?
  if ((rc == 0)) && grep -q "^no recorded group of run $killed_run is left$" <<<"$out" && [[ ! -e $STUB_DIR/kill.log ]]; then
    ok "stop-killed-run.sh never signals its own group ($how)"
  else
    bad "stop-killed-run.sh never signals its own group ($how; exit $rc)" "$out$(cat "$STUB_DIR/kill.log" 2>/dev/null)"
  fi
done

# A process list that cannot be read proves nothing: once TERM is sent, a `ps -A` that keeps
# failing is an exit 2, never "nothing was left for KILL", and the message points at a check by
# hand: a second run would not find a group whose leader the TERM ended.
base
rm -rf "$killed"; mkdir -p "$killed"
group kr.blind "ethswarm-gloas-a-$killed_run"
cp "$STUB_DIR/kr.blind.pid" "$killed/job-groups"
echo 1000 > "$STUB_DIR/ps.fail-A.after-kill"
helper_run 2 "stop-killed-run.sh exits 2 when the process list cannot be read after the TERM" \
  '^ERROR: .*process list' 'by hand' '!run stop-killed-run.sh again' '!nothing was left for KILL' -- "$killed" "$killed_run"
logged "the groups got TERM before the process list failed" kill "^-TERM -- -$(cat "$STUB_DIR/kr.blind.pid")$"
rm -f "$STUB_DIR/ps.fail-A.after-kill"
end_groups kr.blind.pid

# A process list that fails once after the TERM is read again in the same run: the KILL still
# reaches a TERM-ignoring child whose leader the TERM ended (a second run would not find it).
base
rm -rf "$killed"; mkdir -p "$killed"
group kr.retry "ethswarm-gloas-a-$killed_run" stubborn
kt=$(cat "$STUB_DIR/kr.retry.pid")
echo "$kt" > "$killed/job-groups"
echo 1 > "$STUB_DIR/ps.fail-A.after-kill"
helper_run 0 "stop-killed-run.sh reads a process list that failed once again, and goes on" \
  "^sent KILL to $kt$" -- "$killed" "$killed_run"
reaped "after a failed process list, a TERM-ignoring child still gets the KILL" kr.retry.child.pid
rm -f "$STUB_DIR/ps.fail-A.after-kill"
end_groups kr.retry.pid

# A process list that cannot be read when the groups are looked for proves nothing either: an
# exit 2, never "no recorded group ... is left", and nothing is signalled.
base
rm -rf "$killed"; mkdir -p "$killed"
group kr.unread "ethswarm-gloas-a-$killed_run"
cp "$STUB_DIR/kr.unread.pid" "$killed/job-groups"
touch "$STUB_DIR/ps.fail-A"
helper_run 2 "stop-killed-run.sh exits 2 when the process list cannot be read to find the groups" \
  '^ERROR: .*process list' '!no recorded group' -- "$killed" "$killed_run"
rm -f "$STUB_DIR/ps.fail-A"
if [[ ! -e $STUB_DIR/kill.log ]] && alive kr.unread.pid; then ok "an unread process list signals nothing"; else bad "an unread process list signals nothing" "$(cat "$STUB_DIR/kill.log" 2>&1)"; fi
end_groups kr.unread.pid

# The TERM goes only to a group that still holds its id just before it: a leader that ended after
# it was found, its pid then taken by another process (ps.reuse) with another start time, gets no
# TERM. The ps stub ends the leader just before the second listing of every process (the first
# finds the groups).
base
rm -rf "$killed"; mkdir -p "$killed"
group kr.swap "ethswarm-gloas-a-$killed_run"
kx=$(cat "$STUB_DIR/kr.swap.pid")
echo "$kx" > "$killed/job-groups"
echo kr.swap.pid > "$STUB_DIR/ps.reuse"
echo 0 > "$STUB_DIR/ps.A.count"
printf '%s\n' "kill -KILL -- -$kx 2>/dev/null || true" \
  "for ((i = 0; i < 50; i++)); do if ! /bin/ps -p $kx >/dev/null 2>&1; then break; fi; /bin/sleep 0.1; done" \
  > "$STUB_DIR/ps.before-A.2"
helper_run 0 "stop-killed-run.sh sends no TERM to a group whose leader ended after it was found" \
  "^group $kx:" -- "$killed" "$killed_run"
logged "a group whose id another process took before the TERM gets no signal" kill "!-- -$kx$"
rm -f "$STUB_DIR/ps.reuse" "$STUB_DIR/ps.A.count" "$STUB_DIR/ps.before-A.2"
end_groups kr.swap.pid

# The run is <T>-<pid> exactly (an epoch second and a pid of 2 or more), so no short or odd
# argument matches the names of other runs.
base
rm -rf "$killed"; mkdir -p "$killed"
group kr.usage "ethswarm-gloas-a-$killed_run"
cp "$STUB_DIR/kr.usage.pid" "$killed/job-groups"
for arg in 0-4 0-4242 1790000900-1 1790000900-0 1790000900-4242x -1790000900-4242 1790000900--4242 \
    123456789012345678901-4242 1790000900-12345678901 1790000900; do
  helper_run 2 "stop-killed-run.sh with the run '$arg' is a usage error" '^usage: ' -- "$killed" "$arg"
done
helper_run 2 "stop-killed-run.sh without the run suffix is a usage error" '^usage: ' -- "$killed"
if [[ ! -e $STUB_DIR/kill.log ]] && alive kr.usage.pid; then ok "a usage error signals nothing"; else bad "a usage error signals nothing" "$(cat "$STUB_DIR/kill.log" 2>&1)"; fi
end_groups kr.usage.pid

# --- usage ---------------------------------------------------------------------------------------

base
run 2 "--lead below 900 is a usage error" 'lead must be an integer >= 900' -- --lead 899
run 2 "a non-integer --lead is a usage error" 'lead must be an integer >= 900' -- --lead soon
run 2 "an unknown option is a usage error" '^usage: ' -- --frobnicate
run 2 "a positional argument is a usage error" '^usage: ' -- ethswarm-gloas
rc=0; out=$(PATH="/usr/bin:/bin" bash "$script" 2>&1) || rc=$?
if ((rc == 2)) && grep -q '^ERROR: kurtosis not found' <<<"$out"; then ok "a missing kurtosis CLI is a setup error"; else bad "a missing kurtosis CLI is a setup error (exit $rc)" "$out"; fi

echo "# $passed passed, $failed failed"
((failed == 0))
