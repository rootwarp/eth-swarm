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
#
# Usage: testing/kurtosis/stop-killed-run.sh [--list] <logs dir> <T>-<pid>
#   --list   list the groups and their processes, and signal nothing
# Exit: 0 (the groups were stopped, none was left, or --list), 2 a usage error or an unreadable
# job-groups.
# Works on bash 3.2.
set -euo pipefail
GRACE=10 # seconds between TERM and KILL

usage() {
  echo "usage: stop-killed-run.sh [--list] <logs dir> <T>-<pid>" >&2
  exit 2
}
list=0
if [[ ${1:-} == --list ]]; then list=1; shift; fi
(($# == 2)) || usage
logs=$1 run=$2
[[ $run =~ ^[0-9]+-[0-9]+$ ]] || usage
record="$logs/job-groups"
[[ -f $record && -r $record ]] || { echo "ERROR: $record: no such readable file" >&2; exit 2; }

# found: `pgid@start` of each recorded group whose leader (pid = pgid) still runs one of this
# run's commands (start: the leader's lstart, its spaces as _).
found() {
  local g
  while IFS= read -r g; do
    [[ $g =~ ^[1-9][0-9]*$ ]] || continue
    { ps -o pid= -o pgid= -o stat= -o lstart= -o command= -p "$g" 2>/dev/null || true; } |
      awk -v g="$g" -v run="$run" '$1 == g && $2 == g && $3 !~ /^Z/ && index($0, run) {
        print g "@" $4 "_" $5 "_" $6 "_" $7 "_" $8 }'
  done < "$record"
}
# ps_table: one line per process, `pid pgid stat start` (start as in found).
ps_table() {
  ps -A -o pid= -o pgid= -o stat= -o lstart= 2>/dev/null |
    awk '{ s = $4; for (i = 5; i <= NF; i++) s = s "_" $i; print $1, $2, $3, s }'
}
# left: the groups (of those found) that are still there, by the rules above.
left() {
  local rec table
  table=$(ps_table)
  for rec in "${groups[@]}"; do
    if awk -v g="${rec%%@*}" -v s="${rec#*@}" '
        $1 == g { held = 1; if ($4 == s) ours = 1 }
        $2 == g && $3 !~ /^Z/ { member = 1 }
        END { exit !(member && (ours || !held)) }' <<<"$table"; then
      echo "${rec%%@*}"
    fi
  done
}

groups=()
while IFS= read -r rec; do groups+=("$rec"); done < <(found)
if ((${#groups[@]} == 0)); then
  echo "no recorded group of run $run is left"
  exit 0
fi
for rec in "${groups[@]}"; do
  echo "group ${rec%%@*}:"
  ps -A -o pid= -o pgid= -o command= 2>/dev/null | awk -v g="${rec%%@*}" '$2 == g { print "  " $0 }' || true
done
((list == 0)) || exit 0

for rec in "${groups[@]}"; do kill -TERM -- "-${rec%%@*}" 2>/dev/null || true; done
echo "sent TERM to each; KILL in $GRACE s to what is left"
for ((i = 0; i < GRACE; i++)); do
  [[ -n $(left) ]] || break
  sleep 1
done
still=()
while IFS= read -r g; do still+=("$g"); done < <(left)
for g in ${still[@]+"${still[@]}"}; do kill -KILL -- "-$g" 2>/dev/null || true; done
if ((${#still[@]} > 0)); then echo "sent KILL to ${still[*]}"; else echo "nothing was left for KILL"; fi
