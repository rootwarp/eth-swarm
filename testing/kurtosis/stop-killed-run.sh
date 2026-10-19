#!/usr/bin/env bash
# Stops what a run-pair.sh run killed with SIGKILL left running (README.md, "Acceptance checks"):
# the process groups in its job-groups record whose leader still runs one of the run's commands,
# one whose command line names the run's <T>-<pid> suffix (a `kurtosis run`, a `kurtosis enclave
# rm` or the check). It lists each such group and its processes, sends TERM to each, and GRACE
# seconds later (sooner once none is left) sends KILL to each that is still there. A recorded id
# is only a number, so a group counts as still there only while it holds its id, in the process
# list read just before:
#   - its leader still runs (the same pid and start time as when it was found), or
#   - its leader has ended, a process of the group (a zombie aside) runs, and no process (a zombie
#     included) has the id as its pid: the kernel gives no process a pid that is still a group's
#     id, so a process with that pid leads another group, one that took the id once this one
#     emptied.
# That leaves two cases where the KILL can reach another process's group: the group empties and
# its id passes to a new group in the milliseconds between the list and the kill; or, during the
# grace period, the group emptied, a new process took the id as its pid and group, and that process
# ended while its group lived on. Either needs the kernel to hand the same pid out again first.
# It removes no enclave and leaves job-groups in place (README.md has the rest of the recovery).
# A group's leader names the run when its command line holds ethswarm-gloas-a-<T>-<pid> or
# ethswarm-gloas-b-<T>-<pid> as a whole word (no letter, digit, _, . or - on either side, so 4242
# is not 42420 nor 4242-x). It never signals an id below 2 (kill -- -1 would reach every process
# the user owns), nor its own process group or its own pid. Every ps runs under LC_ALL=C (lstart,
# the start time, is worded by the locale) and, where it shows the command, with -ww (procps cuts
# it at an exported COLUMNS).
#
# Usage: testing/kurtosis/stop-killed-run.sh [--list] <logs dir> <T>-<pid>
#   --list   list the groups and their processes, and signal nothing
# Exit: 0 (the groups were stopped, none was left, or --list), 2 a usage error (a run that is not
# <T>-<pid>: an epoch second of 9 to 11 digits and a pid of 2 or more), an unreadable job-groups,
# or a process list that cannot be read.
# Works on bash 3.2.
set -euo pipefail
GRACE=10 # seconds between TERM and KILL

usage() {
  echo "usage: stop-killed-run.sh [--list] <logs dir> <T>-<pid>" >&2
  exit 2
}
die() { echo "ERROR: $*" >&2; exit 2; }
list=0
if [[ ${1:-} == --list ]]; then list=1; shift; fi
(($# == 2)) || usage
logs=$1 run=$2
{ [[ $run =~ ^[1-9][0-9]{8,10}-[1-9][0-9]{0,9}$ ]] && ((${run#*-} >= 2)); } || usage
record="$logs/job-groups"
[[ -f $record && -r $record ]] || die "$record: no such readable file"
# RUN_RE: a command line that names one of the run's enclaves, as a whole word.
RUN_RE="(^|[^A-Za-z0-9_.-])ethswarm-gloas-[ab]-$run([^A-Za-z0-9_.-]|\$)"
# LSTART: the awk function lstart(i), the start time that begins at word i of a ps line under
# LC_ALL=C (five words), its spaces as _; found and the process list read it the same way.
# shellcheck disable=SC2016 # awk source
LSTART='function lstart(i,   s, n) { s = $i; for (n = i + 1; n < i + 5; n++) s = s "_" $n; return s }'
self_pgid=$(LC_ALL=C ps -o pgid= -p "$$" 2>/dev/null) || self_pgid=''
self_pgid=${self_pgid//[[:space:]]/}
[[ $self_pgid =~ ^[1-9][0-9]*$ ]] || die "cannot read this script's own process group (ps -o pgid= -p $$)"

# signalable <id>: the id may be signalled, as a pid or a group: a number of 2 or more, neither
# this script's pid nor its process group.
signalable() {
  [[ $1 =~ ^[1-9][0-9]{0,9}$ ]] && (($1 >= 2 && $1 != $$ && $1 != self_pgid))
}
# found: `pgid@start` of each recorded group whose leader (pid = pgid) still runs one of this
# run's commands (start: lstart).
found() {
  local g
  while IFS= read -r g; do
    signalable "$g" || continue
    { LC_ALL=C ps -ww -o pid= -o pgid= -o stat= -o lstart= -o command= -p "$g" 2>/dev/null || true; } |
      awk -v g="$g" -v re="$RUN_RE" "$LSTART"'
        $1 == g && $2 == g && $3 !~ /^Z/ && $0 ~ re { print g "@" lstart(4) }'
  done < "$record"
}
# left: sets still to the groups (of those found) that are still there, by the rules above, from
# one process list, read in full first; 1 (still empty) when that list cannot be read.
left() {
  local rec listing table
  still=()
  listing=$(LC_ALL=C ps -A -o pid= -o pgid= -o stat= -o lstart= 2>/dev/null) || return 1
  [[ -n $listing ]] || return 1
  table=$(awk "$LSTART"' { print $1, $2, $3, lstart(4) }' <<<"$listing")
  for rec in "${groups[@]}"; do
    if awk -v g="${rec%%@*}" -v s="${rec#*@}" '
        $1 == g { held = 1; if ($4 == s) ours = 1 }
        $2 == g && $3 !~ /^Z/ { member = 1 }
        END { exit !(member && (ours || !held)) }' <<<"$table"; then
      still+=("${rec%%@*}")
    fi
  done
}
# unlisted: the exit when the process list cannot be read: it proves nothing either way.
unlisted() {
  die "ps -A failed: the process list cannot be read, so whether the groups (${groups[*]%%@*}) are" \
    "still there is unknown; run stop-killed-run.sh again"
}

groups=()
while IFS= read -r rec; do groups+=("$rec"); done < <(found)
if ((${#groups[@]} == 0)); then
  echo "no recorded group of run $run is left"
  exit 0
fi
for rec in "${groups[@]}"; do
  echo "group ${rec%%@*}:"
  { LC_ALL=C ps -ww -A -o pid= -o pgid= -o command= 2>/dev/null || true; } |
    awk -v g="${rec%%@*}" '$2 == g { print "  " $0 }'
done
((list == 0)) || exit 0

for rec in "${groups[@]}"; do
  if signalable "${rec%%@*}"; then kill -TERM -- "-${rec%%@*}" 2>/dev/null || true; fi
done
echo "sent TERM to each; KILL in $GRACE s to what is left"
still=()
for ((i = 0; i < GRACE; i++)); do
  left || unlisted
  ((${#still[@]} > 0)) || break
  sleep 1
done
left || unlisted
for g in ${still[@]+"${still[@]}"}; do
  if signalable "$g"; then kill -KILL -- "-$g" 2>/dev/null || true; fi
done
if ((${#still[@]} > 0)); then echo "sent KILL to ${still[*]}"; else echo "nothing was left for KILL"; fi
