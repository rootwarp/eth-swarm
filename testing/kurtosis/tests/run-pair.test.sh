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
# kurtosis stub; every call is logged to $STUB_DIR/kurtosis.log.
# `run --enclave E ...`: the n-th run of E exits with $STUB_DIR/run.<E>.rc.<n>, else
#   $STUB_DIR/run.<E>.rc, else 0; it first advances the fake clock by $STUB_DIR/run.<E>.advance
#   seconds, and with $STUB_DIR/run.<E>.block it blocks (its pid in $STUB_DIR/run.<E>.pid).
# `enclave inspect E`: exit 0 only with $STUB_DIR/exists.<E>; with $STUB_DIR/inspect.<E>.block it
#   first hangs for 60 s (its pid in $STUB_DIR/inspect.<E>.pid).
# `enclave ls`: the n-th call prints $STUB_DIR/enclave-ls.<n>, else $STUB_DIR/enclave-ls, else an
#   empty table (the header only); $STUB_DIR/ls.rc fails it.
# `enclave rm -f E`: advances the fake clock by $STUB_DIR/rm.<E>.advance seconds; with
#   $STUB_DIR/rm.<E>.block it blocks (its pid in $STUB_DIR/rm.<E>.pid), and with
#   $STUB_DIR/rm.<E>.block-once the first call removes that file and hangs for 60 s (the same pid
#   file); else it exits with $STUB_DIR/rm.<E>.rc (else 0).
# `clean -a`: exits with $STUB_DIR/clean.rc (else 0).
printf '%s\n' "$*" >> "$STUB_DIR/kurtosis.log"
case "$1 ${2:-}" in
  "run --enclave")
    e=$3
    counter="$STUB_DIR/run.$e.count"
    n=$(( $(cat "$counter" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$counter"
    echo "kurtosis run stub: enclave $e"
    if [[ -f $STUB_DIR/run.$e.advance ]]; then
      echo $(( $(cat "$STUB_DIR/now") + $(cat "$STUB_DIR/run.$e.advance") )) > "$STUB_DIR/now"
    fi
    if [[ -f $STUB_DIR/run.$e.block ]]; then
      echo $$ > "$STUB_DIR/run.$e.pid"
      while :; do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/run.$e.rc.$n ]]; then exit "$(cat "$STUB_DIR/run.$e.rc.$n")"; fi
    if [[ -f $STUB_DIR/run.$e.rc ]]; then exit "$(cat "$STUB_DIR/run.$e.rc")"; fi
    exit 0 ;;
  "enclave inspect")
    if [[ -f $STUB_DIR/inspect.$3.block ]]; then
      echo $$ > "$STUB_DIR/inspect.$3.pid"
      for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
    fi
    [[ -f $STUB_DIR/exists.$3 ]] ;;
  "enclave ls")
    if [[ -f $STUB_DIR/ls.rc ]]; then exit "$(cat "$STUB_DIR/ls.rc")"; fi
    n=$(( $(cat "$STUB_DIR/ls.count" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$STUB_DIR/ls.count"
    if [[ -f $STUB_DIR/enclave-ls.$n ]]; then cat "$STUB_DIR/enclave-ls.$n"
    elif [[ -f $STUB_DIR/enclave-ls ]]; then cat "$STUB_DIR/enclave-ls"
    else echo "UUID   Name   Status   Creation Time"; fi ;;
  "enclave rm")
    e=$4
    if [[ -f $STUB_DIR/rm.$e.advance ]]; then
      echo $(( $(cat "$STUB_DIR/now") + $(cat "$STUB_DIR/rm.$e.advance") )) > "$STUB_DIR/now"
    fi
    if [[ -f $STUB_DIR/rm.$e.block ]]; then
      echo $$ > "$STUB_DIR/rm.$e.pid"
      while :; do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/rm.$e.block-once ]]; then
      rm -f "$STUB_DIR/rm.$e.block-once"
      echo $$ > "$STUB_DIR/rm.$e.pid"
      for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done
    fi
    if [[ -f $STUB_DIR/rm.$e.rc ]]; then exit "$(cat "$STUB_DIR/rm.$e.rc")"; fi ;;
  "clean -a") if [[ -f $STUB_DIR/clean.rc ]]; then exit "$(cat "$STUB_DIR/clean.rc")"; fi ;;
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
# sleep stub: advances the fake clock by $1 seconds and returns at once. With $STUB_DIR/sleep.block,
# the first call longer than 1 s (the wait for genesis, not a 1 s poll) removes that file and
# really sleeps 30 s (its pid in $STUB_DIR/sleep.pid).
printf '%s\n' "$1" >> "$STUB_DIR/sleep.log"
if [[ -f $STUB_DIR/sleep.block ]] && (($1 > 1)); then
  rm -f "$STUB_DIR/sleep.block"
  echo $$ > "$STUB_DIR/sleep.pid"
  exec /bin/sleep 30
fi
echo $(( $(cat "$STUB_DIR/now") + $1 )) > "$STUB_DIR/now"
SH
chmod +x "$stubs/kurtosis" "$stubs/docker" "$stubs/date" "$stubs/sleep"

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
# with $STUB_DIR/check.stubborn it first starts a child that ignores TERM (its pid in
# $STUB_DIR/stubborn.pid), and with $STUB_DIR/check.orphan a grandchild that ignores TERM and whose
# parent exits at once, so no walk of the check's children finds it (its pid in
# $STUB_DIR/orphan.pid); either runs for at most 60 s.
printf '%s @%s\n' "$*" "$(cat "$STUB_DIR/now")" >> "$STUB_DIR/check.log"
stubborn='trap "" TERM; echo $$ > "$STUB_DIR/$0.pid"; for ((i = 0; i < 600; i++)); do /bin/sleep 0.1; done'
if [[ -f $STUB_DIR/check.stubborn ]]; then
  bash -c "$stubborn" stubborn &
fi
if [[ -f $STUB_DIR/check.orphan ]]; then
  ( bash -c "$stubborn" orphan & ) >/dev/null 2>&1
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
# run <expect-exit> <description> <pattern...> -- <args...>: runs run-pair.sh and wants the exit
# code and a line matching each extended regex; a pattern `!<regex>` wants no line matching it.
# (Here-strings, not `printf | grep -q`: under pipefail, grep -q exiting early fails the printf.)
run() {
  local expect=$1 desc=$2 rc=0 p missing='' unwanted=''
  shift 2
  local patterns=()
  while (($# > 0)) && [[ $1 != -- ]]; do patterns+=("$1"); shift; done
  shift
  out=$(PATH="$stubs:$PATH" bash "$script" "$@" 2>&1) || rc=$?
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

# torn_down <description>: both enclaves removed after the last launch, and no `clean -a` after
# the launches (it would remove every enclave on the engine, not just the pair).
torn_down() {
  local log="$STUB_DIR/kurtosis.log" first_run last_run rm_a rm_b clean
  first_run=$(grep -n '^run --enclave' "$log" 2>/dev/null | sed -n 1p | cut -d: -f1 || true)
  last_run=$(grep -n '^run --enclave' "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  rm_a=$(grep -n '^enclave rm -f ethswarm-gloas-a$' "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  rm_b=$(grep -n '^enclave rm -f ethswarm-gloas-b$' "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  clean=$(grep -n '^clean -a$' "$log" 2>/dev/null | tail -1 | cut -d: -f1 || true)
  if [[ -n $rm_a && -n $rm_b ]] && ((rm_a > ${last_run:-0} && rm_b > ${last_run:-0} &&
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
  "^run --enclave ethswarm-gloas-a $pkg --args-file $logs/gloas-genesis.yaml$" \
  "^run --enclave ethswarm-gloas-b $pkg --args-file $logs/gloas-genesis.yaml$"
if [[ $(head -3 "$STUB_DIR/kurtosis.log" | cut -d' ' -f1-2 | tr '\n' ' ') == "enclave ls enclave ls run --enclave " ]]; then
  ok "the pair checks the engine runs no enclave, and checks again just before the launches"
else
  bad "the pair checks the engine runs no enclave, and checks again just before the launches" "$(cat "$STUB_DIR/kurtosis.log")"
fi
logged "without --clean-engine the engine is never cleaned (only the pair's enclaves go)" kurtosis '!^clean'
check=$(cat "$STUB_DIR/check.log" 2>/dev/null || true)
if [[ $check =~ ^--pair\ --record\ $logs/genesis\.json\ ethswarm-gloas-a\ ethswarm-gloas-b\ @([0-9]+)$ ]] &&
   ((BASH_REMATCH[1] >= T)); then
  ok "check-devnet.sh --pair runs once, at or after genesis"
else
  bad "check-devnet.sh --pair runs once, at or after genesis" "$check"
fi
torn_down "a passing pair is torn down"
if [[ -f $logs/check.log && -f $logs/ethswarm-gloas-a-run.log && -f $logs/ethswarm-gloas-b-run.log ]] &&
   grep -q '^pair verdict: STUB$' "$logs/check.log" && grep -q 'enclave ethswarm-gloas-b' "$logs/ethswarm-gloas-b-run.log"; then
  ok "the run and check logs are kept under target/kurtosis/pair-T"
else
  bad "the run and check logs are kept" "$(ls -la "$logs" 2>&1)"
fi

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
logged "--clean-engine runs kurtosis clean -a before the launches" kurtosis '^clean -a$' '^run --enclave ethswarm-gloas-a '
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

# --- the launches: both succeed, both before genesis ---------------------------------------------

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc"
run 2 "a failed launch exits non-zero" '^ERROR: kurtosis run failed: ethswarm-gloas-b \(exit 1\); see .*/ethswarm-gloas-b-run\.log$' \
  '!^both enclaves up' --
torn_down "a failed launch is torn down"
if [[ ! -e $STUB_DIR/check.log ]]; then ok "a failed launch never runs the check"; else bad "a failed launch never runs the check"; fi
if [[ $(grep -c '^run ' "$STUB_DIR/kurtosis.log") == 2 ]]; then ok "without --sequential-fallback a failed launch is not retried"; else bad "a failed launch is not retried" "$(cat "$STUB_DIR/kurtosis.log")"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-a.rc"; echo 3 > "$STUB_DIR/run.ethswarm-gloas-b.rc"
run 2 "both failed launches are named" '^ERROR: kurtosis run failed: ethswarm-gloas-a \(exit 1\), ethswarm-gloas-b \(exit 3\);' --
torn_down "two failed launches are torn down"

base
echo 900 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
run 4 "launches that end at genesis (T passed) exit 4" \
  "^ERROR: (the enclaves were up only at [0-9]+, [0-9]+ s after genesis \(T $T\)|kurtosis run still running at genesis \(T $T\): ethswarm-gloas-a); render a later T and start again$" \
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
  '^ERROR: kurtosis run still running at genesis \(T [0-9]+\): ethswarm-gloas-b; render a later T and start again$' \
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
  '^warning: kurtosis enclave rm -f ethswarm-gloas-a failed or timed out$' '^ERROR: teardown failed' --
logged "the second enclave is removed after the first rm hangs" kurtosis '^enclave rm -f ethswarm-gloas-b$'
if ((SECONDS < 30)) && gone "$(cat "$STUB_DIR/rm.ethswarm-gloas-a.pid" 2>/dev/null || echo 1)"; then ok "the hung enclave rm is stopped"; else bad "the hung enclave rm is stopped (${SECONDS} s)"; fi

# --- --sequential-fallback: a failed concurrent launch is relaunched alone, still before T ----------

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"
run 0 "--sequential-fallback relaunches the failed enclave alone and goes on" \
  '^kurtosis run failed: ethswarm-gloas-b \(exit 1\)' '^relaunching ethswarm-gloas-b alone \((8[0-9]{2}|900) s before genesis\)$' \
  '^both enclaves up [0-9]+ s before genesis$' '^run-pair: exit 0 ' -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-a ' "$STUB_DIR/kurtosis.log") == 1 &&
      $(grep -c '^run --enclave ethswarm-gloas-b ' "$STUB_DIR/kurtosis.log") == 2 ]] &&
   [[ $(grep -A2 '^enclave rm -f ethswarm-gloas-b$' "$STUB_DIR/kurtosis.log" | sed -n 1,3p | tr '\n' ' ') == \
      "enclave rm -f ethswarm-gloas-b enclave inspect ethswarm-gloas-b run --enclave ethswarm-gloas-b "* ]]; then
  ok "the failed enclave is removed, confirmed gone, then relaunched; the other is kept"
else
  bad "the failed enclave is removed, confirmed gone, then relaunched" "$(cat "$STUB_DIR/kurtosis.log" 2>&1)"
fi
if [[ -f $logs/ethswarm-gloas-b-run-concurrent.log && -f $logs/ethswarm-gloas-b-run.log ]]; then ok "the failed concurrent launch's log is kept"; else bad "the failed concurrent launch's log is kept" "$(ls "$logs")"; fi
torn_down "a fallback pair is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-a.rc.1"; echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"
run 0 "--sequential-fallback relaunches both failed enclaves one after the other" \
  '^relaunching ethswarm-gloas-a alone' '^relaunching ethswarm-gloas-b alone' '^run-pair: exit 0 ' -- --sequential-fallback
if [[ $(grep '^run --enclave' "$STUB_DIR/kurtosis.log" | tail -2 | awk '{print $3}' | tr '\n' ' ') == "ethswarm-gloas-a ethswarm-gloas-b " ]]; then
  ok "the relaunches run a, then b"
else
  bad "the relaunches run a, then b" "$(cat "$STUB_DIR/kurtosis.log")"
fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc"
run 2 "a relaunch that fails too exits 2" '^ERROR: kurtosis run failed: ethswarm-gloas-b \(exit 1\); see .*/ethswarm-gloas-b-run\.log$' \
  -- --sequential-fallback
torn_down "a failed relaunch is torn down"
if [[ ! -e $STUB_DIR/check.log ]]; then ok "a failed relaunch never runs the check"; else bad "a failed relaunch never runs the check"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 500 > "$STUB_DIR/run.ethswarm-gloas-b.advance"
run 4 "a relaunch that ends after genesis exits 4" '^relaunching ethswarm-gloas-b alone \((3[0-9]{2}|400) s before genesis\)$' \
  '^ERROR: (the enclaves were up only at [0-9]+, 1[0-9]{2} s after genesis|kurtosis run still running at genesis)' -- --sequential-fallback
torn_down "a late relaunch is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 800 > "$STUB_DIR/run.ethswarm-gloas-a.advance"
run 4 "too little time left for a relaunch exits 4 without one" \
  '^ERROR: [0-9]+ s before genesis is too little to relaunch ethswarm-gloas-b \(it needs 120 s\); render a later T and start again$' \
  -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b ' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch starts without the time for it"; else bad "no relaunch starts without the time for it"; fi
torn_down "a pair without time for a relaunch is torn down"

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/exists.ethswarm-gloas-b"
run 2 "a failed enclave that is still there after rm is not relaunched" \
  '^ERROR: ethswarm-gloas-b still exists after kurtosis enclave rm -f; not relaunching into it$' -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b ' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch into a leftover enclave"; else bad "no relaunch into a leftover enclave"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; echo 850 > "$STUB_DIR/rm.ethswarm-gloas-b.advance"
run 4 "the relaunch margin is checked again after the rm, just before the launch" \
  '^ERROR: [0-9]+ s before genesis is too little to relaunch ethswarm-gloas-b \(it needs 120 s\)' -- --sequential-fallback
if [[ $(grep -c '^run --enclave ethswarm-gloas-b ' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch starts when the rm used up the margin"; else bad "no relaunch starts when the rm used up the margin" "$(cat "$STUB_DIR/kurtosis.log")"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/rm.ethswarm-gloas-b.block-once"
SECONDS=0
run 0 "a fallback enclave rm that hangs is stopped at its limit, and the relaunch goes on" \
  '^relaunching ethswarm-gloas-b alone' '^run-pair: exit 0 ' -- --sequential-fallback
if ((SECONDS < 30)) && gone "$(cat "$STUB_DIR/rm.ethswarm-gloas-b.pid" 2>/dev/null || echo 1)"; then ok "the hung fallback enclave rm is stopped"; else bad "the hung fallback enclave rm is stopped (${SECONDS} s)"; fi

base
echo 1 > "$STUB_DIR/run.ethswarm-gloas-b.rc.1"; touch "$STUB_DIR/inspect.ethswarm-gloas-b.block"
SECONDS=0
run 2 "a fallback enclave inspect that hangs is stopped, and nothing is relaunched" \
  '^ERROR: kurtosis enclave inspect ethswarm-gloas-b timed out; cannot tell whether it is gone, not relaunching into it$' \
  -- --sequential-fallback
if ((SECONDS < 30)) && gone "$(cat "$STUB_DIR/inspect.ethswarm-gloas-b.pid" 2>/dev/null || echo 1)"; then ok "the hung fallback enclave inspect is stopped"; else bad "the hung fallback enclave inspect is stopped (${SECONDS} s)"; fi
if [[ $(grep -c '^run --enclave ethswarm-gloas-b ' "$STUB_DIR/kurtosis.log") == 1 ]]; then ok "no relaunch after a hung inspect"; else bad "no relaunch after a hung inspect" "$(cat "$STUB_DIR/kurtosis.log")"; fi
torn_down "a pair whose fallback inspect hangs is torn down"

# --- the check's exit code ------------------------------------------------------------------------

for code in 1 2 3; do
  base
  echo "$code" > "$STUB_DIR/check.rc"
  run "$code" "a check that exits $code makes the run exit $code" "^run-pair: exit $code " --
  torn_down "a check that exits $code is torn down"
done

# A check.log that tee cannot write (a directory in its place) must not hide the check's own code.
for code in 3 0; do
  base
  echo "$code" > "$STUB_DIR/check.rc"
  mkdir -p "$logs/check.log"
  want=$code; if ((code == 0)); then want=2; fi
  run "$want" "a check that exits $code with a failing tee exits $want" "^run-pair: exit $want " --
done

base
echo 1 > "$STUB_DIR/rm.ethswarm-gloas-b.rc"
run 2 "a passing pair whose teardown fails exits 2" '^warning: kurtosis enclave rm -f ethswarm-gloas-b failed or timed out$' \
  '^ERROR: teardown failed' --
base
echo 1 > "$STUB_DIR/check.rc"; echo 1 > "$STUB_DIR/rm.ethswarm-gloas-b.rc"
run 1 "a failed teardown does not hide a failed check" '^warning: kurtosis enclave rm -f ethswarm-gloas-b failed or timed out$' --

# --- an interrupt tears down ---------------------------------------------------------------------

# interrupt <expect-exit> <description> <ready condition> <signal> <target> <pid file...>
#   [-- <args...>]: starts run-pair.sh (with the args) in its own process group, waits (up to
#   10 s) until the shell condition holds, and sends the signal. Target `group` sends it to the
#   whole group (a Ctrl-C), `script` to the script alone (a kill), and `piped` runs
#   `run-pair.sh | cat` (cat writing bg.piped, apart from the launcher's bg.out) and signals the
#   group, so the reader dies and the script's stdout is a broken pipe. Wants the exit code within
#   10 s, and every process in the pid files gone within 5 s more (a survivor is reported, then
#   killed).
interrupt() {
  local expect=$1 desc=$2 ready=$3 sig=$4 target=$5 pid i=0 rc=0 alive='' watchdog f p cmd
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
  PATH="$stubs:$PATH" python3 -I -c '
import os, signal, sys
signal.signal(signal.SIGINT, signal.SIG_DFL)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
os.setpgid(0, 0)
os.execvp(sys.argv[1], sys.argv[1:])' bash -c "$cmd" "$script" "$tmp/bg.rc" "$tmp/bg.piped" "$@" > "$tmp/bg.out" 2>&1 &
  pid=$!
  ( /bin/sleep 20; kill -KILL -- -"$pid" ) >/dev/null 2>&1 &
  watchdog=$!
  until eval "$ready"; do
    i=$((i + 1))
    if ((i > 100)); then break; fi
    /bin/sleep 0.1
  done
  if [[ $target == script ]]; then
    kill -"$sig" "$(pgrep -P "$pid")"
  else
    kill -"$sig" -- -"$pid"
  fi
  SECONDS=0
  wait "$pid" || true
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
  if [[ $rc == "$expect" ]] && ((SECONDS < 10)) && [[ -z $alive ]] &&
     { [[ $target == piped ]] || grep -q "^run-pair: exit $expect " "$tmp/bg.out"; }; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect, ${SECONDS} s${alive:+, still running or never started:$alive})" \
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
run 0 "--keep-on-pass leaves a passing pair running" '^kept ethswarm-gloas-a ethswarm-gloas-b running \(--keep-on-pass\); tear down with:$' \
  '^  kurtosis enclave rm -f ethswarm-gloas-a; kurtosis enclave rm -f ethswarm-gloas-b$' \
  '!^tearing down' -- --keep-on-pass
logged "a kept pair is not removed" kurtosis '!^enclave rm' '^run --enclave ethswarm-gloas-b '
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
