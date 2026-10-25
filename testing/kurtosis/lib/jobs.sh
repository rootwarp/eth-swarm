# shellcheck shell=bash
# The background-job machinery of run-pair.sh, for testing/kurtosis/run-units.sh to source: each
# long step runs as a job, the leader of its own process group, bounded in time, and the jobs are
# stopped with their whole process groups and descendants (see run-pair.sh's header for the
# rules). The functions are run-pair.sh's, unchanged apart from the name in JOB_EXEC's error
# line ($JOB_SCRIPT); run-pair.sh keeps its own copy. The sourcing script defines GRACE (seconds
# between TERM and KILL) and sets jobs_file once it has a run directory.
# Works on bash 3.2.

now() { date +%s; }

# bg_pids holds the jobs whose process groups the teardown stops; once $logs exists, $jobs_file
# lists them too. spawn sets last_job to the job it started.
bg_pids=()
jobs_file=''
last_job=''
# JOB_EXEC: python source, run as `python3 -I -c "$JOB_EXEC" <group|-> <command...>`, that execs
# the command (with `group`, as the leader of a new process group first). SIGPIPE and SIGXFSZ go
# back to default: python ignores them, and an ignored signal stays ignored across the exec.
# SIGTTOU is ignored: a job runs in a background process group, and with `stty tostop` the kernel
# would stop it on a write to the terminal (the check's tee), which would hang the run. bash 3.2
# sets SIGTTOU back to its default in every child it forks, even one ignored on entry, so a
# command that a job's bash forks and that writes to the terminal goes through JOB_EXEC too.
# shellcheck disable=SC2016 # python source
JOB_EXEC='
import os, signal, sys
for sig in (signal.SIGPIPE, signal.SIGXFSZ):
    signal.signal(sig, signal.SIG_DFL)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
if sys.argv[1] == "group":
    os.setpgid(0, 0)
try:
    os.execvp(sys.argv[2], sys.argv[2:])
except OSError as err:
    print(f"{os.environ.get('JOB_SCRIPT', 'jobs')}: {sys.argv[2]}: {err.strerror}", file=sys.stderr)
    os._exit(127)'
# in_group <command...>: execs the command as the leader of a new process group (its pid is the
# group id), through JOB_EXEC; it replaces the shell it runs in, so only ever as a background job.
in_group() {
  exec python3 -I -c "$JOB_EXEC" group "$@"
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
