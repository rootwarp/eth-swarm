#!/usr/bin/env bash
# Runs the concurrent pair of the Kurtosis Gloas devnet (README.md, "Reproducible genesis" and
# "Acceptance checks") and fails closed at every step:
#   0. refuses an engine that has any enclave (it needs one dedicated to this run), unless
#      --clean-engine;
#   1. pulls every pinned image of gloas-genesis.yaml (docker pull -q), so the clock starts only
#      once both launches can begin;
#   2. renders a copy with genesis_time T = now + --lead (at least 900 s) into
#      target/kurtosis/pair-T/gloas-genesis.yaml, checks that exactly one genesis_time line holds
#      T, and runs scripts/check-kurtosis-pins.sh on the copy's directory;
#   3. cleans the engine (kurtosis clean -a, which removes EVERY enclave on it), then launches
#      ethswarm-gloas-a and ethswarm-gloas-b at once from that copy; both must exit 0 before T (a
#      launch still running at T is stopped);
#   4. waits for genesis and runs check-devnet.sh --pair --record target/kurtosis/pair-T/genesis.json;
#   5. removes both enclaves (kurtosis enclave rm -f, nothing else on the engine), then exits with
#      the check's exit code.
# From step 3 on, an EXIT/INT/TERM/HUP/PIPE trap does the teardown on every exit (a failure, an
# interrupt while waiting for genesis or finality, a closed terminal or output pipe): it stops the
# background jobs and their descendants, then removes both enclaves, each step bounded and run
# even if an earlier one failed, so no ~4.75 GiB pair is left running. The run logs, the check
# log, the genesis record and `docker stats` snapshots stay in target/kurtosis/pair-T/.
#
# Usage: testing/kurtosis/run-pair.sh [--lead S] [--sequential-fallback] [--keep-on-pass]
#                                     [--clean-engine]
#   --lead S               seconds from the render to genesis (default and minimum 900)
#   --sequential-fallback  when a concurrent launch fails, remove each failed enclave and launch it
#                          again alone, one after the other; each relaunch starts only with at
#                          least MIN_RELAUNCH_LEFT s before T, and both must still be up before T
#   --keep-on-pass         on a pair PASS (exit 0), leave both enclaves running (for the block
#                          export) and print the teardown commands; any other exit tears down
#   --clean-engine         start even if the engine has other enclaves: kurtosis clean -a removes
#                          them all. Without it, any enclave on the engine stops the run.
# Exit: the check's exit code (0 pair PASS, 1 FAIL, 2 setup error, 3 DIAGNOSTIC; 2 if the check
# passed but its log could not be written); 2 a usage or setup error before the check (a missing
# tool, an engine with other enclaves, a failed pull, render, pin lint or clean, a failed launch),
# or a failed teardown after a PASS; 4 the launches did not leave both enclaves up before genesis
# (render a later T and start again); 129 on HUP, 130 on INT, 141 on PIPE, 143 on TERM.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
PKG=github.com/ethpandaops/ethereum-package@3416a0252e5bc25a0d31d24fea9c46707447eb08
ENCLAVES=(ethswarm-gloas-a ethswarm-gloas-b)
MIN_LEAD=900
# A relaunch starts only with this much time left before T: a launch took 61-64 s with the images
# pulled (2026-10-19), so this is about twice that.
MIN_RELAUNCH_LEFT=120
STATS_TIMEOUT=30     # seconds for one `docker stats --no-stream`
RM_TIMEOUT=120       # seconds for one `kurtosis enclave rm -f` in the teardown
GRACE=10             # seconds between TERM and KILL when stopping background jobs
IMAGE_RE='[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}'

usage() {
  echo "usage: run-pair.sh [--lead S] [--sequential-fallback] [--keep-on-pass] [--clean-engine]" >&2
  exit 2
}
die() { echo "ERROR: $*" >&2; exit 2; }
now() { date +%s; }

lead=$MIN_LEAD sequential_fallback=0 keep_on_pass=0 clean_engine=0
while (($# > 0)); do
  case $1 in
    --lead) (($# >= 2)) || usage; lead=$2; shift 2 ;;
    --sequential-fallback) sequential_fallback=1; shift ;;
    --keep-on-pass) keep_on_pass=1; shift ;;
    --clean-engine) clean_engine=1; shift ;;
    *) usage ;;
  esac
done
{ [[ $lead =~ ^[0-9]+$ ]] && ((lead >= MIN_LEAD)); } || { echo "--lead must be an integer >= $MIN_LEAD" >&2; usage; }
for tool in kurtosis docker; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done
args_file="$here/gloas-genesis.yaml"
[[ -f $args_file ]] || die "$args_file: no such file"

# 0. A dedicated engine: the clean below removes every enclave on it.
if ((clean_engine == 0)); then
  listing=$(kurtosis enclave ls 2>/dev/null) || die "kurtosis enclave ls failed (is the engine running?)"
  if [[ -n $listing ]]; then
    [[ $listing == UUID* ]] ||
      die "kurtosis enclave ls: no UUID header, cannot tell which enclaves the engine has; pass --clean-engine to clean it anyway"
    others=$(printf '%s\n' "$listing" | awk 'NR > 1 && NF > 0 { print $2 }' | tr '\n' ' ')
    others=${others% }
    [[ -z $others ]] ||
      die "the engine has other enclaves ($others); run-pair.sh needs an engine dedicated to this run:" \
        "remove them, or pass --clean-engine to let kurtosis clean -a remove them"
  fi
fi

# 1. Pre-pull every pinned image.
images=()
while IFS= read -r image; do images+=("$image"); done < <(grep -oE "$IMAGE_RE" "$args_file" | sort -u)
((${#images[@]} > 0)) || die "no repo:tag@sha256 image in $args_file"
for image in "${images[@]}"; do
  docker pull -q "$image" >/dev/null || die "docker pull $image failed"
done
echo "pulled ${#images[@]} pinned images"

# 2. Render the shared copy with one genesis_time T, then lint it.
T=$(( $(now) + lead ))
logs="$root/target/kurtosis/pair-$T"
args="$logs/gloas-genesis.yaml"
mkdir -p "$logs" 2>/dev/null || die "mkdir -p $logs failed"
sed "s/^  genesis_time: 0$/  genesis_time: $T/" "$args_file" > "$args" || die "render: writing $args failed"
[[ $(grep -c "^  genesis_time: $T$" "$args") == 1 ]] ||
  die "render: $args has no single '  genesis_time: $T' line (is '  genesis_time: 0' in $args_file?)"
echo "rendered $args (genesis_time $T)"
"${BASH:-bash}" "$root/scripts/check-kurtosis-pins.sh" "$logs" ||
  die "scripts/check-kurtosis-pins.sh $logs failed"

# 3. A clean engine, then both launches.
kurtosis clean -a >/dev/null || die "kurtosis clean -a failed"

# Every long step (a launch, docker stats, the wait for genesis, the check) runs in the
# background, so a signal reaches its trap within a second rather than after the step; bg_pids
# holds the ones running.
bg_pids=()
# running <pid>: the process exists and is not a zombie.
running() {
  local stat
  stat=$(ps -o stat= -p "$1" 2>/dev/null || true)
  [[ -n $stat && $stat != Z* ]]
}
# descendants <pid>: every descendant of the process, deepest first.
descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null || true); do
    descendants "$child"
    echo "$child"
  done
}
# wait_until <deadline> <pid...>: 0 once none of the processes runs, 1 at the deadline (epoch s).
wait_until() {
  local deadline=$1 pid busy
  shift
  while :; do
    busy=0
    for pid in "$@"; do if running "$pid"; then busy=1; fi; done
    ((busy)) || return 0
    (( $(now) < deadline )) || return 1
    sleep 1
  done
}
# stop <pid...>: TERM to each process and every descendant, KILL to whatever of them still runs
# GRACE seconds later (a descendant that ignores TERM included), then waits for the processes.
stop() {
  local pid p all=()
  for pid in "$@"; do
    for p in $(descendants "$pid") "$pid"; do all+=("$p"); done
  done
  ((${#all[@]} > 0)) || return 0
  for pid in "${all[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
  wait_until $(( $(now) + GRACE )) "${all[@]}" ||
    for pid in "${all[@]}"; do kill -KILL "$pid" 2>/dev/null || true; done
  for pid in "$@"; do wait "$pid" 2>/dev/null || true; done
}
# bounded <seconds> <command...>: runs the command in the background for at most that long; its
# exit code, or 124 once it is stopped at the limit.
bounded() {
  local limit=$1 pid rc=0
  shift
  "$@" &
  pid=$!
  bg_pids+=("$pid")
  if wait_until $(( $(now) + limit )) "$pid"; then
    wait "$pid" || rc=$?
  else
    stop "$pid"
    rc=124
  fi
  bg_pids=()
  return "$rc"
}
# snapshot <name>: `docker stats --no-stream` into $logs/<name>.txt; never fatal.
snapshot() {
  bounded "$STATS_TIMEOUT" docker stats --no-stream > "$logs/$1.txt" 2>&1 ||
    echo "warning: docker stats failed or timed out (see $logs/$1.txt)" >&2
}
# say <text>: a teardown message on stdout. When stdout is gone (a closed pipe or terminal), it
# goes to /dev/null from then on: bash 3.2 keeps the text of a failed write in its stdout buffer
# and would flush it into the next $(...) (a clock read, say), so the next write drains it there.
say() {
  if ! echo "$*" 2>/dev/null; then
    exec >/dev/null
    echo
  fi
}
# warn <text>: a teardown message on stderr; when that write fails, a write to /dev/null drains
# what bash 3.2 kept of it (see say).
warn() {
  echo "$*" >&2 || echo >/dev/null
}
torn_down=0
# teardown (the EXIT trap): stops the background jobs, removes both enclaves, then exits with the
# run's exit code (2 if only the teardown failed). It ignores further signals and write errors,
# and runs every step even when an earlier one fails.
# shellcheck disable=SC2329 # invoked only by the EXIT trap
teardown() {
  local rc=$? e failed=0
  set +e
  trap '' INT TERM HUP PIPE
  ((torn_down == 0)) || return 0
  torn_down=1
  # The first message comes before any $(...): it also finds out whether stdout still works.
  if ((rc == 0 && keep_on_pass)); then
    say "kept ${ENCLAVES[*]} running (--keep-on-pass); tear down with:"
    say "  kurtosis enclave rm -f ${ENCLAVES[0]}; kurtosis enclave rm -f ${ENCLAVES[1]}"
    stop ${bg_pids[@]+"${bg_pids[@]}"}
    say "run-pair: exit $rc (logs in $logs)"
    exit "$rc"
  fi
  say "tearing down ${ENCLAVES[*]}"
  stop ${bg_pids[@]+"${bg_pids[@]}"}
  bg_pids=()
  for e in "${ENCLAVES[@]}"; do
    if ! bounded "$RM_TIMEOUT" kurtosis enclave rm -f "$e" >/dev/null 2>&1; then
      warn "warning: kurtosis enclave rm -f $e failed or timed out"
      failed=1
    fi
  done
  if ((failed && rc == 0)); then
    warn "ERROR: teardown failed; remove what is left (kurtosis enclave ls)"
    rc=2
  fi
  say "run-pair: exit $rc (logs in $logs)"
  exit "$rc"
}
trap teardown EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 141' PIPE

# launch <enclave...>: starts a `kurtosis run` per enclave in the background, all at once, and
# waits for every one until T; launch_failed lists each that failed, with its exit code. A launch
# still running at T is an exit 4 (the teardown stops it).
launch_failed=()
launch() {
  local e pid rc i
  local started=("$@") still=()
  bg_pids=()
  for e in "$@"; do
    kurtosis run --enclave "$e" "$PKG" --args-file "$args" > "$logs/$e-run.log" 2>&1 &
    bg_pids+=($!)
  done
  if ! wait_until "$T" "${bg_pids[@]}"; then
    for ((i = 0; i < ${#bg_pids[@]}; i++)); do
      if running "${bg_pids[i]}"; then still+=("${started[i]}"); fi
    done
    if ((${#still[@]} > 0)); then
      echo "ERROR: kurtosis run still running at genesis (T $T): ${still[*]}; render a later T and start again" >&2
      exit 4
    fi
  fi
  launch_failed=()
  for ((i = 0; i < ${#bg_pids[@]}; i++)); do
    rc=0
    wait "${bg_pids[i]}" || rc=$?
    if ((rc != 0)); then launch_failed+=("${started[i]} (exit $rc)"); fi
  done
  bg_pids=()
}
# launch_failure: the failed launches and their logs, one line.
launch_failure() {
  local f logs_of=''
  for f in "${launch_failed[@]}"; do logs_of="$logs_of $logs/${f%% *}-run.log"; done
  echo "kurtosis run failed: $(printf '%s, ' "${launch_failed[@]}" | sed 's/, $//'); see${logs_of}"
}
# launch_report: dies (exit 2) when a launch failed.
launch_report() {
  ((${#launch_failed[@]} == 0)) || die "$(launch_failure)"
}
# relaunch_margin <enclave>: exits 4 unless MIN_RELAUNCH_LEFT seconds are left before T; prints
# the seconds left.
relaunch_margin() {
  local left
  left=$(( T - $(now) ))
  if ((left < MIN_RELAUNCH_LEFT)); then
    echo "ERROR: $left s before genesis is too little to relaunch $1 (it needs $MIN_RELAUNCH_LEFT s);" \
      "render a later T and start again" >&2
    exit 4
  fi
  echo "$left"
}
# relaunch <enclave...>: --sequential-fallback; removes each failed enclave and launches it alone,
# one after the other, each only with MIN_RELAUNCH_LEFT seconds still before T (checked before the
# removal and again just before the launch).
relaunch() {
  local e left
  for e in "$@"; do
    left=$(relaunch_margin "$e") || exit 4
    kurtosis enclave rm -f "$e" >/dev/null 2>&1 || true
    if kurtosis enclave inspect "$e" >/dev/null 2>&1; then
      die "$e still exists after kurtosis enclave rm -f; not relaunching into it"
    fi
    mv "$logs/$e-run.log" "$logs/$e-run-concurrent.log" || die "mv $logs/$e-run.log failed"
    left=$(relaunch_margin "$e") || exit 4
    echo "relaunching $e alone ($left s before genesis)"
    launch "$e"
    launch_report
  done
}
# before_genesis: exits 4 unless it is still before T.
before_genesis() {
  local t
  t=$(now)
  if ((t >= T)); then
    echo "ERROR: the enclaves were up only at $t, $((t - T)) s after genesis (T $T); render a later T and start again" >&2
    exit 4
  fi
}

start=$(now)
launch "${ENCLAVES[@]}"
if ((${#launch_failed[@]} > 0 && sequential_fallback)); then
  echo "$(launch_failure); --sequential-fallback: relaunching each alone"
  failed_enclaves=()
  for f in "${launch_failed[@]}"; do failed_enclaves+=("${f%% *}"); done
  relaunch "${failed_enclaves[@]}"
fi
launch_report
before_genesis
echo "launches took $(( $(now) - start )) s"
echo "both enclaves up $(( T - $(now) )) s before genesis"
snapshot stats-up

# 4. After genesis: every criterion on both enclaves, then one genesis across them.
while (( $(now) < T )); do
  left=$(( T - $(now) ))
  echo "waiting $left s for genesis"
  sleep "$left" &
  bg_pids=($!)
  wait "${bg_pids[0]}"
  bg_pids=()
done
# The check's own exit code, not tee's: a check.log that cannot be written turns only a PASS
# into a 2 (no record of it), never a FAIL or DIAGNOSTIC into something else.
(
  set +e +o pipefail
  "${BASH:-bash}" "$here/check-devnet.sh" --pair --record "$logs/genesis.json" "${ENCLAVES[@]}" 2>&1 |
    tee "$logs/check.log"
  codes=("${PIPESTATUS[@]}")
  if ((codes[0] != 0)); then exit "${codes[0]}"; fi
  if ((codes[1] != 0)); then echo "ERROR: tee $logs/check.log failed" >&2; exit 2; fi
  exit 0
) &
bg_pids=($!)
rc=0
wait "${bg_pids[0]}" || rc=$?
bg_pids=()
snapshot stats-checked
exit "$rc"
