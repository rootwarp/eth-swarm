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
# Usage: testing/kurtosis/check-devnet.sh [options] ENCLAVE
#   --services "SVC ..."     the CL services to query (default: every cl-<n>-* service that
#                            `kurtosis enclave inspect ENCLAVE` lists)
#   --record FILE            write this run's genesis record (JSON) to FILE
#   --reference FILE         a record from an earlier run that this run's genesis must equal
#   --min-finalized-epoch N  default 3
#   --attempts N             finality polls (default 40)
#   --interval S             seconds between finality polls (default 12)
# Exit: 0 every criterion passed, 1 a criterion failed, 2 a usage or setup error (kurtosis or
# python3 missing, unknown enclave, no CL service, a port that does not resolve).
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
helper="$here/lib/devnet.py"

usage() {
  echo "usage: check-devnet.sh [--services \"SVC ...\"] [--record FILE] [--reference FILE]" \
    "[--min-finalized-epoch N] [--attempts N] [--interval S] ENCLAVE" >&2
  exit 2
}
die() { echo "ERROR: $*" >&2; exit 2; }
is_uint() { [[ $1 =~ ^[0-9]+$ ]]; }
SERVICE_RE='^cl-[0-9]+-[a-z0-9]+(-[a-z0-9]+)*$'

services='' record='' reference='' min_epoch=3 attempts=40 interval=12 enclave=''
while (($# > 0)); do
  case $1 in
    --services|--record|--reference|--min-finalized-epoch|--attempts|--interval)
      (($# >= 2)) || usage
      case $1 in
        --services) services=$2 ;;
        --record) record=$2 ;;
        --reference) reference=$2 ;;
        --min-finalized-epoch) min_epoch=$2 ;;
        --attempts) attempts=$2 ;;
        --interval) interval=$2 ;;
      esac
      shift 2 ;;
    -*) usage ;;
    *) [[ -z $enclave ]] || usage; enclave=$1; shift ;;
  esac
done
[[ -n $enclave ]] || usage
is_uint "$min_epoch" || { echo "--min-finalized-epoch must be a non-negative integer" >&2; usage; }
{ is_uint "$attempts" && ((attempts >= 1)); } || { echo "--attempts must be an integer >= 1" >&2; usage; }
is_uint "$interval" || { echo "--interval must be a non-negative integer" >&2; usage; }
if [[ -n $reference && ! -f $reference ]]; then die "--reference $reference: no such file"; fi
command -v kurtosis >/dev/null 2>&1 || die "kurtosis not found on PATH"
command -v curl >/dev/null 2>&1 || die "curl not found on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 not found on PATH"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The CL services: given, or every cl-<n>-* name in the enclave's service table, by index.
list=()
if [[ -n $services ]]; then
  for svc in $services; do
    [[ $svc =~ $SERVICE_RE ]] || die "$svc: not a cl-<n>-* service name"
    list+=("$svc")
  done
else
  inspect=$(kurtosis enclave inspect "$enclave" 2>&1) || die "kurtosis enclave inspect $enclave failed: $inspect"
  while IFS= read -r svc; do
    if [[ -n $svc ]]; then list+=("$svc"); fi
  done < <(printf '%s\n' "$inspect" | tr -s ' \t' '\n\n' | grep -E "$SERVICE_RE" | sort -u | sort -t- -k2,2n)
fi
((${#list[@]} > 0)) || die "no cl-<n>-* service in enclave $enclave"
echo "devnet $enclave: ${#list[@]} CL services: ${list[*]}"

# Each service's beacon API base URL, from its `http` port.
for svc in "${list[@]}"; do
  url=$(kurtosis port print "$enclave" "$svc" http 2>&1) || die "kurtosis port print $enclave $svc http failed: $url"
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

if ((${#failed[@]} == 0)); then
  echo "verdict: PASS (3/3 criteria)"
  exit 0
fi
echo "verdict: FAIL (${failed[*]})"
exit 1
