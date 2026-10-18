#!/usr/bin/env bash
# Runtime acceptance checks for the Kurtosis Gloas devnet (testing/kurtosis/gloas-genesis.yaml).
# Queries every CL's beacon API through `kurtosis port print <enclave> <service> http` and prints
# a verdict per criterion:
#   genesis        every CL reports the same genesis (genesis_time, genesis_validators_root,
#                  genesis_fork_version, genesis block root and state root); with --reference,
#                  the same as an earlier run's record (two runs, same genesis root).
#   fork_schedule  every CL's /eth/v1/config/fork_schedule has Gloas at epoch 0 (and in force
#                  there), GLOAS_FORK_EPOCH is 0, the schedules are equal, and the fork digests
#                  in the CLs' own ENRs (eth2 entry) agree.
#   finality       every CL's finalized epoch (/eth/v1/beacon/states/head/finality_checkpoints)
#                  is at least --min-finalized-epoch and every CL reports the same finalized
#                  checkpoint. Polled up to --attempts times, --interval seconds apart, since the
#                  CLs reach and agree on it over time.
# The evidence and the rules live in lib/devnet.py (standard library Python, run with -I).
#
# --pair ENCLAVE_A ENCLAVE_B checks a concurrent pair (two enclaves from one rendered args file,
# one genesis_time; README.md, "Reproducible genesis"): it runs every check above on each
# enclave in turn, then requires both enclaves' genesis records to be equal (genesis_time,
# genesis_validators_root, genesis_fork_version, genesis block root and state root). The other
# options apply to both enclaves; --record writes the pair's one genesis.
#
# An acceptance PASS needs every CL service the enclave runs, at least 2 distinct ones, and a
# --min-finalized-epoch of at least 3. A run that misses any of these (a --services subset, a
# one-CL enclave, a lower threshold) still checks every criterion, but its verdict is
# DIAGNOSTIC, never PASS: it is not acceptance evidence.
#
# Usage: testing/kurtosis/check-devnet.sh [options] ENCLAVE
#        testing/kurtosis/check-devnet.sh --pair [options] ENCLAVE_A ENCLAVE_B
#   --services "SVC ..."     the CL services to query (default: every cl-<n>-* service that
#                            `kurtosis enclave inspect ENCLAVE` lists). Each must be one of those;
#                            fewer than all of them makes the run DIAGNOSTIC.
#   --record FILE            write this run's genesis record (JSON) to FILE
#   --reference FILE         a record from an earlier run that this run's genesis must equal
#   --min-finalized-epoch N  default 3; below 3 makes the run DIAGNOSTIC
#   --attempts N             finality polls (default 40)
#   --interval S             seconds between finality polls (default 12)
#   --kurtosis-timeout S     seconds for each kurtosis call (enclave inspect, port print; default
#                            60); one that takes longer is stopped, a setup error
#   --pair                   two enclaves, checked as a concurrent pair (see above)
# Exit: 0 acceptance PASS (every criterion passed), 1 a criterion failed, 2 a usage or setup
# error (kurtosis or python3 missing, unknown enclave, no CL service, a --services CL the
# enclave does not run, a port that does not resolve, a kurtosis call that timed out), 3
# DIAGNOSTIC (every criterion passed, but the run is not an acceptance run). With --pair: 2 if
# either enclave's run is a setup error, else 1 if either fails or their genesis differs, else 3
# if either is DIAGNOSTIC, else 0.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
helper="$here/lib/devnet.py"

usage() {
  echo "usage: check-devnet.sh [--services \"SVC ...\"] [--record FILE] [--reference FILE]" \
    "[--min-finalized-epoch N] [--attempts N] [--interval S] [--kurtosis-timeout S] ENCLAVE" >&2
  echo "       check-devnet.sh --pair [options] ENCLAVE_A ENCLAVE_B" >&2
  exit 2
}
die() { echo "ERROR: $*" >&2; exit 2; }
is_uint() { [[ $1 =~ ^[0-9]+$ ]]; }
SERVICE_RE='^cl-[0-9]+-[a-z0-9]+(-[a-z0-9]+)*$'
ACCEPTANCE_MIN_EPOCH=3
MIN_CLS=2
# contains <word> <word...>: the first word is one of the rest.
contains() {
  local want=$1 w
  shift
  for w in "$@"; do if [[ $w == "$want" ]]; then return 0; fi; done
  return 1
}

services='' record='' reference='' min_epoch=3 attempts=40 interval=12 kurtosis_timeout=60 pair=0
enclaves=()
while (($# > 0)); do
  case $1 in
    --services|--record|--reference|--min-finalized-epoch|--attempts|--interval|--kurtosis-timeout)
      (($# >= 2)) || usage
      case $1 in
        --services) services=$2 ;;
        --record) record=$2 ;;
        --reference) reference=$2 ;;
        --min-finalized-epoch) min_epoch=$2 ;;
        --attempts) attempts=$2 ;;
        --interval) interval=$2 ;;
        --kurtosis-timeout) kurtosis_timeout=$2 ;;
      esac
      shift 2 ;;
    --pair) pair=1; shift ;;
    -*) usage ;;
    *) enclaves+=("$1"); shift ;;
  esac
done
if ((pair)); then
  ((${#enclaves[@]} == 2)) || usage
  [[ ${enclaves[0]} != "${enclaves[1]}" ]] || { echo "--pair needs two different enclaves" >&2; usage; }
else
  ((${#enclaves[@]} == 1)) || usage
fi
enclave=${enclaves[0]}
is_uint "$min_epoch" || { echo "--min-finalized-epoch must be a non-negative integer" >&2; usage; }
{ is_uint "$attempts" && ((attempts >= 1)); } || { echo "--attempts must be an integer >= 1" >&2; usage; }
is_uint "$interval" || { echo "--interval must be a non-negative integer" >&2; usage; }
{ is_uint "$kurtosis_timeout" && ((kurtosis_timeout >= 1)); } ||
  { echo "--kurtosis-timeout must be an integer >= 1" >&2; usage; }
if [[ -n $reference && ! -f $reference ]]; then die "--reference $reference: no such file"; fi
command -v kurtosis >/dev/null 2>&1 || die "kurtosis not found on PATH"
command -v curl >/dev/null 2>&1 || die "curl not found on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A concurrent pair: every check on each enclave (this script, once per enclave), then one
# genesis across both.
if ((pair)); then
  sub=(--min-finalized-epoch "$min_epoch" --attempts "$attempts" --interval "$interval"
    --kurtosis-timeout "$kurtosis_timeout")
  if [[ -n $services ]]; then sub+=(--services "$services"); fi
  if [[ -n $reference ]]; then sub+=(--reference "$reference"); fi
  setup=() failed=() diagnostic=() n=0
  for e in "${enclaves[@]}"; do
    n=$((n + 1))
    echo "== $e"
    rc=0
    "${BASH:-bash}" "$here/check-devnet.sh" "${sub[@]}" --record "$work/genesis-$n.json" "$e" || rc=$?
    echo "== $e: exit $rc"
    case $rc in
      0) ;;
      1) failed+=("$e") ;;
      3) diagnostic+=("$e") ;;
      *) setup+=("$e") ;;
    esac
  done
  pair_args=()
  if [[ -n $record ]]; then pair_args+=(--record "$record"); fi
  rc=0
  python3 -I "$helper" pair ${pair_args[@]+"${pair_args[@]}"} \
    "${enclaves[0]}" "$work/genesis-1.json" "${enclaves[1]}" "$work/genesis-2.json" || rc=$?
  if ((rc != 0)); then failed+=("pair genesis"); fi
  if ((${#setup[@]} > 0)); then
    echo "pair verdict: ERROR (setup error in ${setup[*]})"
    exit 2
  fi
  if ((${#failed[@]} > 0)); then
    reasons=$(printf '%s; ' "${failed[@]}")
    echo "pair verdict: FAIL (${reasons%; })"
    exit 1
  fi
  if ((${#diagnostic[@]} > 0)); then
    echo "pair verdict: DIAGNOSTIC (not an acceptance run: ${diagnostic[*]})"
    exit 3
  fi
  echo "pair verdict: PASS (2 enclaves: 3/3 criteria each, one genesis)"
  exit 0
fi

# bounded_py <seconds> <command...>: runs the command (in this process group, so a signal to the
# group reaches it) for at most that long and passes its stdout on; its exit code (128 + the signal
# if one killed it), or 124 once it is killed at the limit. The command writes to a pipe of the
# runner's own, so a process it left holding that pipe open cannot keep the caller's $(...) waiting
# past the limit. TERM, INT and HUP to the runner are passed on to the command.
bounded_py='
import signal, subprocess, sys
limit = int(sys.argv[1])
try:
    child = subprocess.Popen(sys.argv[2:], stdout=subprocess.PIPE)
except OSError as err:
    print(f"check-devnet.sh: {sys.argv[2]}: {err.strerror}", file=sys.stderr)
    sys.exit(127)
def forward(sig, _frame):
    child.send_signal(sig)
for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, forward)
try:
    out, _ = child.communicate(timeout=limit)
except subprocess.TimeoutExpired:
    child.kill()
    child.wait()
    sys.exit(124)
sys.stdout.buffer.write(out)
sys.stdout.flush()
code = child.returncode
sys.exit(128 - code if code < 0 else code)
'
# kurtosis_out <name> <kurtosis args...>: the command's stdout, the command bounded to
# --kurtosis-timeout seconds (a setup error past it). Its stderr goes to $work/<name>.err and is
# shown only when the command fails: Kurtosis 1.22.1 on Docker Desktop (macOS) prints an
# OpenTelemetry WARN to stderr on every call, which must not be parsed as the answer.
kurtosis_out() {
  local name=$1 out rc=0
  shift
  out=$(python3 -I -c "$bounded_py" "$kurtosis_timeout" kurtosis "$@" 2>"$work/$name.err") || rc=$?
  if ((rc == 124)); then die "kurtosis $* timed out after $kurtosis_timeout s"; fi
  if ((rc != 0)); then die "kurtosis $* failed: $(cat "$work/$name.err")"; fi
  printf '%s' "$out"
}

# The enclave's CL services: every cl-<n>-* name in its service table, by index.
found=()
inspect=$(kurtosis_out inspect enclave inspect "$enclave") || exit 2
while IFS= read -r svc; do
  if [[ -n $svc ]]; then found+=("$svc"); fi
done < <(printf '%s\n' "$inspect" | tr -s ' \t' '\n\n' | grep -E "$SERVICE_RE" | sort -u | sort -t- -k2,2n)
((${#found[@]} > 0)) || die "no cl-<n>-* service in enclave $enclave"

# The CL services to check: given (each once, each one the enclave runs), or all of them.
list=()
if [[ -n $services ]]; then
  for svc in $services; do
    [[ $svc =~ $SERVICE_RE ]] || die "$svc: not a cl-<n>-* service name"
    contains "$svc" "${found[@]}" || die "$svc: not a CL service of enclave $enclave (it runs: ${found[*]})"
    if ((${#list[@]} == 0)) || ! contains "$svc" "${list[@]}"; then list+=("$svc"); fi
  done
else
  list=("${found[@]}")
fi
((${#list[@]} > 0)) || die "no CL service to check"
echo "devnet $enclave: ${#list[@]} CL services: ${list[*]}"

# Why this run cannot be an acceptance PASS, one reason per entry (none: it can be).
diagnostic=()
if ((${#list[@]} < ${#found[@]})); then
  skipped=()
  for svc in "${found[@]}"; do
    contains "$svc" "${list[@]}" || skipped+=("$svc")
  done
  diagnostic+=("--services checks ${#list[@]} of the enclave's ${#found[@]} CLs (not checked: ${skipped[*]})")
fi
if ((${#list[@]} < MIN_CLS)); then
  diagnostic+=("only ${#list[@]} distinct CL; an acceptance run needs at least $MIN_CLS")
fi
if ((min_epoch < ACCEPTANCE_MIN_EPOCH)); then
  diagnostic+=("--min-finalized-epoch $min_epoch is below $ACCEPTANCE_MIN_EPOCH, the acceptance threshold")
fi
for reason in ${diagnostic[@]+"${diagnostic[@]}"}; do echo "diagnostic: $reason"; done

# Each service's beacon API base URL, from its `http` port.
for svc in "${list[@]}"; do
  url=$(kurtosis_out port port print "$enclave" "$svc" http) || exit 2
  url=$(printf '%s' "$url" | tr -d '\r')
  [[ $url == *://* ]] || url="http://$url"
  [[ $url =~ ^https?://([A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\]):[0-9]+$ ]] ||
    die "kurtosis port print $enclave $svc http: '$url' is not an http://host:port URL"
  mkdir -p "$work/$svc"
  printf '%s' "$url" > "$work/$svc/url"
  echo "$svc: $url"
done

# fetch <service> <API path> <name>: GET into $work/<service>/<name>.json; a failed request
# leaves no file (the helper reports it) and prints why.
fetch() {
  local out="$work/$1/$3.json" rc=0
  rm -f "$out"
  curl -fsS --max-time 10 -H 'Accept: application/json' -o "$out" "$(cat "$work/$1/url")$2" \
    >/dev/null 2>&1 || rc=$?
  if ((rc != 0)); then
    rm -f "$out"
    echo "$1: GET $2 failed (curl exit $rc)"
  fi
}

failed=()
verdict() { # verdict <criterion> <helper exit code>
  if (($2 != 0)); then failed+=("$1"); fi
}

for svc in "${list[@]}"; do
  fetch "$svc" /eth/v1/beacon/genesis genesis
  fetch "$svc" /eth/v1/beacon/headers/genesis header
done
genesis_args=()
if [[ -n $reference ]]; then genesis_args+=(--reference "$reference"); fi
if [[ -n $record ]]; then genesis_args+=(--record "$record"); fi
rc=0
python3 -I "$helper" genesis ${genesis_args[@]+"${genesis_args[@]}"} "$work" "${list[@]}" || rc=$?
verdict genesis "$rc"

for svc in "${list[@]}"; do
  fetch "$svc" /eth/v1/config/fork_schedule fork_schedule
  fetch "$svc" /eth/v1/config/spec spec
  fetch "$svc" /eth/v1/node/identity identity
done
rc=0
python3 -I "$helper" forks "$work" "${list[@]}" || rc=$?
verdict fork_schedule "$rc"

poll=0 rc=1 evidence=''
while ((poll < attempts)); do
  poll=$((poll + 1))
  evidence=$(
    for svc in "${list[@]}"; do
      fetch "$svc" /eth/v1/beacon/states/head/finality_checkpoints finality
    done
    rc=0
    python3 -I "$helper" finality "$work" "$min_epoch" "${list[@]}" || rc=$?
    echo "#rc=$rc"
  )
  rc=${evidence##*#rc=}
  evidence=${evidence%#rc=*}
  if ((rc == 0)); then break; fi
  if ((poll < attempts)); then sleep "$interval"; fi
done
printf '%s' "$evidence"
if ((rc == 0)); then
  echo "finality: PASS on poll $poll of $attempts (finalized epoch >= $min_epoch, one checkpoint)"
else
  echo "finality: FAIL after $poll polls"
fi
verdict finality "$rc"

if ((${#failed[@]} > 0)); then
  echo "verdict: FAIL (${failed[*]})"
  exit 1
fi
if ((${#diagnostic[@]} > 0)); then
  echo "verdict: DIAGNOSTIC (3/3 criteria passed; not an acceptance run)"
  exit 3
fi
echo "verdict: PASS (3/3 criteria)"
exit 0
