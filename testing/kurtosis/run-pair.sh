#!/usr/bin/env bash
# Runs the concurrent pair of the Kurtosis Gloas devnet (README.md, "Reproducible genesis" and
# "Acceptance checks") and fails closed at every step:
#   0. refuses an engine that has any enclave (it needs one dedicated to this run), unless
#      --clean-engine; an `enclave ls` answer without its UUID header (an empty one included) is
#      refused too;
#   1. pulls every pinned image of gloas-genesis.yaml (docker pull -q), so the clock starts only
#      once both launches can begin;
#   2. renders a copy with genesis_time T = now + --lead (at least 900 s) into
#      target/kurtosis/pair-T/gloas-genesis.yaml (a directory it makes itself: one that exists
#      already, another run's with the same T, stops the run), checks that exactly one
#      genesis_time line holds T, and runs scripts/check-kurtosis-pins.sh on the copy's directory;
#   3. lists the enclaves again and refuses any (one created since step 0 is never removed), or
#      with --clean-engine only, cleans the engine (kurtosis clean -a, bounded to CLEAN_TIMEOUT,
#      which removes EVERY enclave on it); then launches the run's two enclaves at once from that
#      copy, named for the run (ethswarm-gloas-a-<T>-<pid> and ethswarm-gloas-b-<T>-<pid>, pid this
#      script's), so no other run ever launches into them or removes them; both must exit 0 before
#      T (a launch still running at T is stopped);
#   4. waits for genesis and runs check-devnet.sh --pair --record
#      target/kurtosis/pair-T/genesis.json on them, bounded to CHECK_TIMEOUT;
#   5. removes both enclaves (kurtosis enclave rm -f, by their names; nothing else on the engine),
#      then exits with the check's exit code.
# Every step that can take long (a pull, a kurtosis call, docker stats, the wait for genesis, the
# check) is a background job, the leader of its own process group, and every kurtosis call and the
# check are bounded. An EXIT/INT/TERM/HUP/PIPE trap, set before step 0, stops the jobs (each one's
# whole process group) and their descendants on every exit (a failure, an interrupt while waiting
# for genesis or finality, a closed terminal or output pipe), and from step 3 on also removes both
# enclaves, each step bounded and run even if an earlier one failed, so no ~4.75 GiB pair is left
# running. A job's process group is also stopped as soon as its leader ends (each launch's as soon
# as that launch ends), so nothing a step left behind outlives it. Whether a job still runs is
# what bash saw of it (its job table, a stopped job counted as running), never a lookup of its
# pid, which another process may have taken once the job ended. A group that bash saw end is
# signalled only while, in the process list read just before, it has a process and no process has
# its id as pid (bash has reaped the leader, so a process with that pid leads another group); what
# that cannot rule out is in signal_left. No id below 2, and never the script's own pid, is
# signalled. Every ps runs under LC_ALL=C.
# While a job runs, target/kurtosis/pair-T/job-groups lists the process group of each (one per
# line, replaced whole; the teardown removes the file), for a run killed with SIGKILL
# (stop-killed-run.sh, and README.md, "Acceptance checks"). The run logs, the check log, the
# genesis record and `docker stats` snapshots stay in target/kurtosis/pair-T/.
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
#                          them all, just before the launches. Without it, the engine is never
#                          cleaned, and any enclave on it (at the start or just before the
#                          launches) stops the run.
# Exit: the check's exit code (0 pair PASS, 1 FAIL, 2 setup error, 3 DIAGNOSTIC; 2 if the check
# passed but its log could not be written, or if it ran past CHECK_TIMEOUT); 2 a usage or setup
# error before the check (a missing tool, an engine with other enclaves or an unreadable or
# timed-out enclave list, a failed pull, render, pin lint or clean, a failed launch, a fallback
# that cannot prove the failed enclave gone), or a failed teardown after a PASS; 4 the launches
# did not leave both enclaves up before genesis (render a later T and start again); 129 on HUP,
# 130 on INT, 141 on PIPE, 143 on TERM.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
PKG=github.com/ethpandaops/ethereum-package@3416a0252e5bc25a0d31d24fea9c46707447eb08
MIN_LEAD=900
# A relaunch starts only with this much time left before T: a launch took 61-64 s with the images
# pulled (2026-10-19), so this is about twice that.
MIN_RELAUNCH_LEFT=120
LS_TIMEOUT=30        # seconds for one `kurtosis enclave ls` (steps 0 and 3, and the fallback)
STATS_TIMEOUT=30     # seconds for one `docker stats --no-stream`
RM_TIMEOUT=120       # seconds for one `kurtosis enclave rm -f` (the teardown and the fallback)
CLEAN_TIMEOUT=300    # seconds for `kurtosis clean -a` (--clean-engine)
# Seconds for check-devnet.sh --pair: its own bounds with its defaults (60 s per kurtosis call, 10 s
# per beacon API request, 40 finality polls 12 s apart) add up to about 52 min on the two enclaves.
CHECK_TIMEOUT=3600
GRACE=10             # seconds between TERM and KILL when stopping background jobs
IMAGE_RE='[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}'

usage() {
  echo "usage: run-pair.sh [--lead S] [--sequential-fallback] [--keep-on-pass] [--clean-engine]" >&2
  exit 2
}
die() { echo "ERROR: $*" >&2; exit 2; }
now() { date +%s; }
# contains <word> <word...>: the first word is one of the rest.
contains() {
  local want=$1 w
  shift
  for w in "$@"; do if [[ $w == "$want" ]]; then return 0; fi; done
  return 1
}

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
for tool in kurtosis docker python3; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool not found on PATH"
done
args_file="$here/gloas-genesis.yaml"
[[ -f $args_file ]] || die "$args_file: no such file"

# --- background jobs -------------------------------------------------------------------------------

# bg_pids holds the jobs whose process groups the teardown stops; once $logs exists, $jobs_file
# lists them too. spawn sets last_job to the job it started.
bg_pids=()
jobs_file=''
last_job=''
# in_group <command...>: execs the command as the leader of a new process group (its pid is the
# group id); it replaces the shell it runs in, so only ever as a background job. SIGPIPE and
# SIGXFSZ go back to default first: python ignores them, and an ignored signal stays ignored across
# the exec. SIGTTOU is ignored: the job is a background process group, and with `stty tostop` the
# kernel would stop it on a write to the terminal (the check's tee), which would hang the run.
in_group() {
  exec python3 -I -c '
import os, signal, sys
for sig in (signal.SIGPIPE, signal.SIGXFSZ):
    signal.signal(sig, signal.SIG_DFL)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
os.setpgid(0, 0)
try:
    os.execvp(sys.argv[1], sys.argv[1:])
except OSError as err:
    print(f"run-pair.sh: {sys.argv[1]}: {err.strerror}", file=sys.stderr)
    os._exit(127)' "$@"
}
# record_jobs: writes bg_pids, one per line, to $jobs_file (once there is one): into a new file
# of its own (mktemp, so never a FIFO or a link put there), renamed over $jobs_file, so the record
# is whole at every instant, a SIGKILL included; never fatal.
record_jobs() {
  local pid tmp
  [[ -n $jobs_file ]] || return 0
  tmp=$(mktemp "$jobs_file.XXXXXX" 2>/dev/null) || return 0
  if { for pid in ${bg_pids[@]+"${bg_pids[@]}"}; do echo "$pid"; done; } 2>/dev/null > "$tmp"; then
    mv -f "$tmp" "$jobs_file" 2>/dev/null || rm -f "$tmp"
  else
    rm -f "$tmp"
  fi
}
# untrack <pid...>: drops the jobs from bg_pids (and $jobs_file).
untrack() {
  local p q keep=()
  for p in ${bg_pids[@]+"${bg_pids[@]}"}; do
    for q in "$@"; do if [[ $p == "$q" ]]; then continue 2; fi; done
    keep+=("$p")
  done
  bg_pids=(${keep[@]+"${keep[@]}"})
  record_jobs
}
held=0 pending=''
# on_signal <exit code> (the INT/TERM/HUP/PIPE trap): exits with the code, so the EXIT trap tears
# down. While spawn is between a job's start and its record in bg_pids, the exit waits for spawn,
# so the teardown always finds the job.
# shellcheck disable=SC2329 # invoked only by the traps
on_signal() {
  if ((held)); then pending=$1; else exit "$1"; fi
}
# spawn <out> <err> <command...>: starts the command in the background, as the leader of its own
# process group (in_group), its stdout to the file <out> and its stderr to <err> (the same file:
# both into it; <out> `-`: both to the script's own), and records it in bg_pids. A signal that
# arrives meanwhile takes effect only once the job is recorded.
spawn() {
  local out=$1 err=$2 code
  shift 2
  held=1
  if [[ $out == - ]]; then
    in_group "$@" &
  elif [[ $err == "$out" ]]; then
    in_group "$@" > "$out" 2>&1 &
  else
    in_group "$@" > "$out" 2> "$err" &
  fi
  last_job=$!
  bg_pids+=("$last_job")
  held=0
  record_jobs
  if [[ -n $pending ]]; then
    code=$pending
    pending=''
    exit "$code"
  fi
}
# live_jobs: sets live to ` <pid> ... `, the jobs bash has not seen end: those it runs and those
# it shows stopped (SIGSTOP; bash tells them apart only with job control, SHELLOPTS=monitor say).
# A stopped job has not ended: it still counts, and gets the signals. (`jobs` straight in the
# $(...): in a function or a group piped to another command, it sees no jobs.)
live=''
live_jobs() {
  local nl=$'\n'
  live=$(jobs -rp; jobs -sp)
  live=" ${live//"$nl"/ } "
}
# jobs_running <pid...>: 0 while bash has not seen one of these jobs end. It reads bash's own job
# table (live_jobs), not the pid: once a job ends, another process may take its pid, and must never
# count.
jobs_running() {
  local pid
  live_jobs
  for pid in "$@"; do if [[ $live == *" $pid "* ]]; then return 0; fi; done
  return 1
}
# signalable <id>: the id may be signalled, as a pid or a group: a number of 2 or more (kill -- -1
# would reach every process the user owns, and 0 this script's own group), not this script's pid.
signalable() {
  [[ $1 =~ ^[1-9][0-9]{0,9}$ ]] && (($1 >= 2 && $1 != $$))
}
# ps_table: one line per process, `pid pgid stat start ppid` (start: ps's lstart under LC_ALL=C,
# so in the same words whatever the locale, its spaces as _).
ps_table() {
  LC_ALL=C ps -A -o pid= -o pgid= -o stat= -o ppid= -o lstart= 2>/dev/null |
    awk '{ s = $5; for (i = 6; i <= NF; i++) s = s "_" $i; print $1, $2, $3, s, $4 }'
}
# descendants <pid> <table>: `pid@start` of every descendant of the process in the ps_table
# <table>, deepest first. The pid and start come from one listing, so each names the process
# that was a descendant when it was read, never one that took its pid later. A pid below 2 is no
# descendant (a listing that says so is wrong): it is left out, and so is everything below it.
descendants() {
  awk -v root="$1" '
    { kids[$5] = kids[$5] " " $1; start[$1] = $4 }
    function walk(p,   list, n, i) {
      if (seen[p]++) return
      n = split(kids[p], list, " ")
      for (i = 1; i <= n; i++) {
        if (list[i] + 0 < 2) continue
        walk(list[i]); print list[i] "@" start[list[i]]
      }
    }
    END { walk(root) }' <<<"$2"
}
# GROUP_LEFT: the awk test, over a ps_table (g: the group id), that the group of a job bash saw end
# still holds its id: a process of the group (a zombie aside) runs, and no process (a zombie
# included) has the id as its pid. bash has reaped the job's leader, and the kernel gives no
# process a pid that is still a group's id, so a process with that pid leads another group, one
# that took the id once the job's group had emptied.
# shellcheck disable=SC2016 # awk source
GROUP_LEFT='{ pid[$1] = 1; if ($2 == g && $3 !~ /^Z/) member = 1 } END { exit !(member && !(g in pid)) }'
# still_here <pid...> -- <pid@start...>: 0 while one of the jobs runs (jobs_running), the group of
# a job still holds its id with a process in it (GROUP_LEFT), or one of the recorded processes (the
# same pid and start, a zombie aside) runs. The job table is read before the process list, so a
# job it shows ended had its leader reaped before the list was read.
# shellcheck disable=SC2329 # invoked by wait_while, as its probe
still_here() {
  local groups=() g table
  while (($# > 0)) && [[ $1 != -- ]]; do groups+=("$1"); shift; done
  if (($# > 0)); then shift; fi
  if jobs_running ${groups[@]+"${groups[@]}"}; then return 0; fi
  table=$(ps_table)
  for g in ${groups[@]+"${groups[@]}"}; do
    if awk -v g="$g" "$GROUP_LEFT" <<<"$table"; then return 0; fi
  done
  awk -v r=" $* " '$3 !~ /^Z/ && index(r, " " $1 "@" $4 " ") { found = 1 } END { exit !found }' <<<"$table"
}
# signal_left <signal> <pid...> -- <pid@start...>: the signal to each job that bash still runs
# (its process group, and the job itself, whose group may not exist yet right after its start), to
# the group of each job that bash saw end only while that group still holds its id (GROUP_LEFT),
# and to each recorded process only while the same process (pid and start) runs. A TERM to a job
# is followed by CONT to it and its group, so a stopped one (live_jobs) acts on it; an id that is
# not signalable gets no signal. The job table is read before the process list (see still_here),
# and the list just before the signals. Two cases remain where a signal can reach another
# process's group: the group empties and its id passes to a new group in the milliseconds between
# that list and the kill; or, before the list, the group emptied, a new process took the id as its
# pid and group, and that process ended while its group lived on. Either needs the kernel to hand
# the same pid out again within that time.
signal_left() {
  local sig=$1 g rec table running
  shift
  live_jobs
  running=$live
  table=$(ps_table)
  while (($# > 0)) && [[ $1 != -- ]]; do
    g=$1
    shift
    if ! signalable "$g"; then continue; fi
    if [[ $running == *" $g "* ]]; then
      kill "-$sig" -- "-$g" 2>/dev/null || true
      kill "-$sig" "$g" 2>/dev/null || true
      if [[ $sig == TERM ]]; then
        kill -CONT -- "-$g" 2>/dev/null || true
        kill -CONT "$g" 2>/dev/null || true
      fi
    elif awk -v g="$g" "$GROUP_LEFT" <<<"$table"; then
      kill "-$sig" -- "-$g" 2>/dev/null || true
    fi
  done
  if (($# > 0)); then shift; fi
  for rec in "$@"; do
    if ! signalable "${rec%%@*}"; then continue; fi
    if awk -v p="${rec%%@*}" -v s="${rec#*@}" '$1 == p && $4 == s && $3 !~ /^Z/ { found = 1 } END { exit !found }' <<<"$table"; then
      kill "-$sig" "${rec%%@*}" 2>/dev/null || true
    fi
  done
}
# wait_while <deadline> <probe> <pid...>: 0 once `<probe> <pid...>` fails (nothing of it runs), 1
# at the deadline (epoch s). It polls every 0.1 s for the first second, then every second.
wait_while() {
  local deadline=$1 probe=$2 polls=0
  shift 2
  while "$probe" "$@"; do
    (( $(now) < deadline )) || return 1
    if ((polls < 10)); then sleep 0.1; else sleep 1; fi
    polls=$((polls + 1))
  done
}
# stop <pid...>: TERM to each background job (signal_left: its process group, the job, and every
# descendant of a job that still runs, one that left the group included), KILL to whatever of them
# still runs GRACE seconds later (a process that ignores TERM, or that left the process tree,
# included), then waits for the jobs and drops them from bg_pids.
stop() {
  local pid rec table recs=()
  (($# > 0)) || return 0
  # The list first: a job that still runs after it was read had the same pid then.
  table=$(ps_table)
  for pid in "$@"; do
    if jobs_running "$pid"; then
      while IFS= read -r rec; do recs+=("$rec"); done < <(descendants "$pid" "$table")
    fi
  done
  signal_left TERM "$@" -- ${recs[@]+"${recs[@]}"}
  wait_while $(( $(now) + GRACE )) still_here "$@" -- ${recs[@]+"${recs[@]}"} ||
    signal_left KILL "$@" -- ${recs[@]+"${recs[@]}"}
  for pid in "$@"; do wait "$pid" 2>/dev/null || true; done
  untrack "$@"
}
# sweep <pid...>: once bash has seen the jobs end, TERM to whatever is left in their process
# groups and KILL to what still runs GRACE seconds later; then drops the jobs from bg_pids.
sweep() {
  if still_here "$@" --; then
    signal_left TERM "$@" --
    wait_while $(( $(now) + GRACE )) still_here "$@" -- || signal_left KILL "$@" --
  fi
  untrack "$@"
}
# bounded <seconds> <out> <err> <command...>: runs the command as a job (spawn: its output to <out>
# and <err>), for at most that long; its exit code, or 124 once it is stopped at the limit. Whatever
# it left in its process group is stopped too. A trap that runs meanwhile still writes to the
# script's own output.
bounded() {
  local limit=$1 out=$2 err=$3 pid rc=0
  shift 3
  spawn "$out" "$err" "$@"
  pid=$last_job
  if wait_while $(( $(now) + limit )) jobs_running "$pid"; then
    sweep "$pid"
    wait "$pid" || rc=$?
  else
    stop "$pid"
    rc=124
  fi
  return "$rc"
}
# snapshot <name>: `docker stats --no-stream` into $logs/<name>.txt; never fatal.
snapshot() {
  bounded "$STATS_TIMEOUT" "$logs/$1.txt" "$logs/$1.txt" docker stats --no-stream ||
    echo "warning: docker stats failed or timed out (see $logs/$1.txt)" >&2
}

# --- the teardown ---------------------------------------------------------------------------------

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
work='' torn_down=0 armed=0 ENCLAVES=()
# teardown <exit code> (the EXIT trap, handed the run's $?): stops the background jobs and, once
# the launches are armed, removes both enclaves, then exits with the run's exit code (2 if only the
# teardown failed). Its first statement ignores further signals (a signal before it would run an
# `exit` inside the teardown and skip the removals), and its second drops any exit that spawn still
# held (the teardown's own job starts would act on it); it ignores write errors too, and runs every
# step even when an earlier one fails.
# shellcheck disable=SC2329 # invoked only by the EXIT trap
teardown() {
  trap '' INT TERM HUP PIPE
  held=0 pending=''
  local rc=$1 e failed=0
  set +e
  ((torn_down == 0)) || return 0
  torn_down=1
  if ((armed == 0)); then
    stop ${bg_pids[@]+"${bg_pids[@]}"}
    if [[ -n $jobs_file ]]; then rm -f "$jobs_file"; fi
    if [[ -n $work ]]; then rm -rf "$work"; fi
    exit "$rc"
  fi
  # The first message comes before any $(...): it also finds out whether stdout still works.
  if ((rc == 0 && keep_on_pass)); then
    say "kept ${ENCLAVES[*]} running (--keep-on-pass); tear down with:"
    say "  kurtosis enclave rm -f ${ENCLAVES[0]}; kurtosis enclave rm -f ${ENCLAVES[1]}"
    stop ${bg_pids[@]+"${bg_pids[@]}"}
    rm -f "$jobs_file"
    rm -rf "$work"
    say "run-pair: exit $rc (logs in $logs)"
    exit "$rc"
  fi
  say "tearing down ${ENCLAVES[*]}"
  stop ${bg_pids[@]+"${bg_pids[@]}"}
  for e in "${ENCLAVES[@]}"; do
    if ! bounded "$RM_TIMEOUT" /dev/null /dev/null kurtosis enclave rm -f "$e"; then
      warn "warning: kurtosis enclave rm -f $e failed or timed out"
      failed=1
    fi
  done
  rm -f "$jobs_file"
  rm -rf "$work"
  if ((failed && rc == 0)); then
    warn "ERROR: teardown failed; remove what is left (kurtosis enclave ls)"
    rc=2
  fi
  say "run-pair: exit $rc (logs in $logs)"
  exit "$rc"
}
trap 'teardown $?' EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP
trap 'on_signal 141' PIPE
work=$(mktemp -d)

# --- the engine's enclaves -------------------------------------------------------------------------

listed=() list_error=''
# list_enclaves: `kurtosis enclave ls` (bounded to LS_TIMEOUT; its stderr apart, see check-devnet.sh)
# sets listed to the names under its UUID header and returns 0. Else it sets list_error and
# returns 1 (the listing failed or timed out) or 3 (no UUID header, an empty answer included: it
# proves nothing).
list_enclaves() {
  local rc=0 name
  listed=() list_error=''
  bounded "$LS_TIMEOUT" "$work/ls.out" "$work/ls.err" kurtosis enclave ls || rc=$?
  if ((rc == 124)); then
    list_error="kurtosis enclave ls timed out after $LS_TIMEOUT s (is the engine running?)"
    return 1
  elif ((rc != 0)); then
    list_error="kurtosis enclave ls failed (is the engine running?)"
    return 1
  fi
  if [[ $(cat "$work/ls.out") != UUID* ]]; then
    list_error="kurtosis enclave ls: no UUID header, cannot tell which enclaves the engine has"
    return 3
  fi
  while IFS= read -r name; do listed+=("$name"); done < <(awk 'NR > 1 && NF > 0 { print $2 }' "$work/ls.out")
}
# no_enclaves: dies (exit 2) unless `kurtosis enclave ls` answers with its UUID header and no
# enclave below it.
no_enclaves() {
  local rc=0
  list_enclaves || rc=$?
  if ((rc == 3)); then die "$list_error; pass --clean-engine to clean it anyway"; fi
  if ((rc != 0)); then die "$list_error"; fi
  ((${#listed[@]} == 0)) ||
    die "the engine has other enclaves (${listed[*]}); run-pair.sh needs an engine dedicated to this run:" \
      "remove them, or pass --clean-engine to let kurtosis clean -a remove them"
}

# 0. A dedicated engine, checked before the pulls (and again before the launches).
if ((clean_engine == 0)); then no_enclaves; fi

# 1. Pre-pull every pinned image.
images=()
while IFS= read -r image; do images+=("$image"); done < <(grep -oE "$IMAGE_RE" "$args_file" | sort -u)
((${#images[@]} > 0)) || die "no repo:tag@sha256 image in $args_file"
for image in "${images[@]}"; do
  spawn "$work/pull.log" "$work/pull.log" docker pull -q "$image"
  rc=0
  wait "$last_job" || rc=$?
  sweep "$last_job"
  if ((rc != 0)); then
    cat "$work/pull.log" >&2 || true
    die "docker pull $image failed"
  fi
done
echo "pulled ${#images[@]} pinned images"

# 2. Render the shared copy with one genesis_time T, then lint it.
T=$(( $(now) + lead ))
logs="$root/target/kurtosis/pair-$T"
args="$logs/gloas-genesis.yaml"
mkdir -p "$root/target/kurtosis" 2>/dev/null || die "mkdir -p $root/target/kurtosis failed"
if ! mkdir "$logs" 2>/dev/null; then
  if [[ -e $logs ]]; then die "$logs exists already: another run has genesis_time $T; start again"; fi
  die "mkdir $logs failed"
fi
jobs_file="$logs/job-groups"
sed "s/^  genesis_time: 0$/  genesis_time: $T/" "$args_file" > "$args" || die "render: writing $args failed"
[[ $(grep -c "^  genesis_time: $T$" "$args") == 1 ]] ||
  die "render: $args has no single '  genesis_time: $T' line (is '  genesis_time: 0' in $args_file?)"
echo "rendered $args (genesis_time $T)"
"${BASH:-bash}" "$root/scripts/check-kurtosis-pins.sh" "$logs" ||
  die "scripts/check-kurtosis-pins.sh $logs failed"
# The run's own enclaves: T and this script's pid, so no other run (another checkout, the same
# second) shares a name with them.
ENCLAVES=("ethswarm-gloas-a-$T-$$" "ethswarm-gloas-b-$T-$$")

# 3. An engine still without enclaves (one may have been created during the pulls, render and
# lint), or with --clean-engine only, a cleaned one; then both launches.
if ((clean_engine)); then
  rc=0
  bounded "$CLEAN_TIMEOUT" "$logs/clean.log" "$logs/clean.log" kurtosis clean -a || rc=$?
  if ((rc == 124)); then die "kurtosis clean -a timed out after $CLEAN_TIMEOUT s"; fi
  ((rc == 0)) || die "kurtosis clean -a failed (see $logs/clean.log)"
else
  no_enclaves
fi

# launch <enclave...>: starts a `kurtosis run` per enclave in the background, all at once, and
# waits for every one until T; launch_failed lists each that failed, with its exit code. Each
# launch is swept (whatever it left in its process group stopped) as soon as bash sees it end,
# while the others may still run. A launch still running at T is an exit 4 (the teardown stops it).
launch_failed=()
launch() {
  local e i rc polls=0 pids=() codes=() left=() still=() started=("$@") names=()
  for e in "$@"; do
    spawn "$logs/$e-run.log" "$logs/$e-run.log" kurtosis run --enclave "$e" "$PKG" --args-file "$args"
    pids+=("$last_job")
    codes+=(0)
  done
  for ((i = 0; i < ${#pids[@]}; i++)); do left+=("$i"); done
  while ((${#left[@]} > 0)); do
    still=()
    for i in "${left[@]}"; do
      if jobs_running "${pids[i]}"; then still+=("$i"); continue; fi
      sweep "${pids[i]}"
      rc=0
      wait "${pids[i]}" || rc=$?
      codes[i]=$rc
    done
    left=(${still[@]+"${still[@]}"})
    ((${#left[@]} > 0)) || break
    if (( $(now) >= T )); then
      names=()
      for i in "${left[@]}"; do names+=("${started[i]}"); done
      echo "ERROR: kurtosis run still running at genesis (T $T): ${names[*]}; render a later T and start again" >&2
      exit 4
    fi
    if ((polls < 10)); then sleep 0.1; else sleep 1; fi
    polls=$((polls + 1))
  done
  launch_failed=()
  for ((i = 0; i < ${#pids[@]}; i++)); do
    if ((codes[i] != 0)); then launch_failed+=("${started[i]} (exit ${codes[i]})"); fi
  done
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
# removal and again just before the launch). The removal is bounded like the teardown's, and only
# a well-formed `kurtosis enclave ls` (bounded too) without the enclave proves it gone: a listing
# that fails, times out, has no UUID header or still lists it stops the run (exit 2).
relaunch() {
  local e left
  for e in "$@"; do
    left=$(relaunch_margin "$e") || exit 4
    bounded "$RM_TIMEOUT" /dev/null /dev/null kurtosis enclave rm -f "$e" || true
    list_enclaves || die "$list_error; cannot tell whether $e is gone, not relaunching into it"
    if contains "$e" ${listed[@]+"${listed[@]}"}; then
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

# From here on, every exit removes both enclaves.
armed=1
start=$(now)
echo "launching ${ENCLAVES[0]} and ${ENCLAVES[1]}"
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
  spawn - - sleep "$left"
  wait "$last_job"
  sweep "$last_job"
done
# The check's own exit code, not tee's: a check.log that cannot be written turns only a PASS
# into a 2 (no record of it), never a FAIL or DIAGNOSTIC into something else. The wrapper resets
# errexit, pipefail and job control (monitor) first: an exported SHELLOPTS would hand it the
# script's own, and with job control its pipeline would leave the job's process group.
rc=0
# shellcheck disable=SC2016 # expanded by the inner bash, from its arguments
bounded "$CHECK_TIMEOUT" - - "${BASH:-bash}" -c '
  set +e +m +o pipefail
  check=$1 log=$2
  shift 2
  "$BASH" "$check" "$@" 2>&1 | tee "$log"
  codes=("${PIPESTATUS[@]}")
  if ((codes[0] != 0)); then exit "${codes[0]}"; fi
  if ((codes[1] != 0)); then echo "ERROR: tee $log failed" >&2; exit 2; fi
  exit 0' run-pair-check "$here/check-devnet.sh" "$logs/check.log" \
  --pair --record "$logs/genesis.json" "${ENCLAVES[@]}" || rc=$?
if ((rc == 124)); then
  echo "ERROR: check-devnet.sh ran past its limit of $CHECK_TIMEOUT s and was stopped" >&2
  rc=2
fi
snapshot stats-checked
exit "$rc"
