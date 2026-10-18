#!/usr/bin/env bash
# Pre-flight for the reference node of the .env's NETWORK (sepolia or hoodi): run (as root,
# after setup.sh) before `docker compose up`. An .env with a line compose would read
# differently from these scripts (lib/common.sh env_check: `export`, indentation, a key twice,
# a $ or backtick in a value, any COMPOSE_* key), a NETWORK other than sepolia or hoodi, or a
# COMPOSE_PROJECT_NAME in the environment is refused outright (exit 2). Otherwise every check runs and prints one line; any FAIL fails:
#   - RETH_IMAGE and LIGHTHOUSE_IMAGE are pinned as repo:tag@sha256:<64 lower-case hex>, and
#     README.md's release-note table for the network has a row for each image (by digest)
#     that says the release schedules the network's Gloas / Amsterdam fork;
#   - no variable compose.yaml uses is overridden by the shell environment (compose would
#     take the exported value over .env);
#   - the five ports (lib/common.sh PORT_KEYS) are decimal 1-65535 and distinct;
#   - CHECKPOINT_SYNC_URL (provider 1, which Lighthouse syncs from) and CHECKPOINT_SYNC_URL_2
#     (provider 2: required on Hoodi, optional on Sepolia) are https:// (or http:// to a
#     loopback host), with no query or fragment (the API path is appended to them; a
#     provider key goes in the path), and on two different hosts; TRUSTED_PEERS is empty or
#     a comma-separated list of base58 peer IDs;
#   - the ids setup.sh recorded are numbers and no uid is 0 (in --test-mode too); outside
#     --test-mode RETH_UID and LIGHTHOUSE_UID are distinct and the uids of the network's users
#     (lib/common.sh service_user: reth and lighthouse on Sepolia, reth-hoodi and
#     lighthouse-hoodi on Hoodi), and RETH_GID and LIGHTHOUSE_GID are non-zero, distinct and
#     their gids;
#   - the data directories are 0700 and the JWT copies 0600, each owned by its service's uid,
#     and both copies hold the same 64-hex secret. The copies are opened only through
#     lib/fsguard.py (inspect, same-secret: no symlink anywhere on the path, non-blocking, a
#     regular file with one link), so a link or a FIFO planted there fails instead of blocking
#     or reading another file; the secret is never printed;
#   - each provider's /eth/v1/config/spec matches the network's pinned config (lib/beacon.py
#     spec-diff: every *_FORK_VERSION, *_FORK_EPOCH and the BLOB_SCHEDULE). Public endpoints
#     have served pre-Gloas configs, so an endpoint is checked before it is used;
#   - with two providers, provider 2 holds provider 1's finalized block
#     (/eth/v1/beacon/headers/finalized, then /eth/v1/beacon/headers/<its slot>) with the
#     same block root and header state_root, canonical (lib/beacon.py anchor-compare).
# It also prints the configured ports and the free space under DATA_ROOT (df), for the
# operator's own headroom check. The checkpoint URLs may carry a provider key in their path (a
# query is refused): they are printed as scheme://host only, handed to curl on stdin (never
# argv) and curl's messages are dropped.
# A --test-mode pass prints "preflight OK (test mode: not a deployment gate)".
#
# Usage: ops/ref-node/preflight.sh [--env-file FILE] [--config YAML] [--test-mode]
#   --env-file FILE  default: .env next to this script
#   --test-mode      for a setup.sh --test-mode root: skip the user and distinct-id checks
#   --config YAML    default: crates/network-config/networks/<NETWORK>/config.yaml of this repo
# Exit: 0 every check passed, 1 a check failed, 2 bad usage or a missing or refused .env.
# Needs bash, curl, df and python3.
set -euo pipefail
here=$(cd -P "$(dirname "$0")" && pwd -P)
# shellcheck source=lib/common.sh
source "$here/lib/common.sh"

usage() { sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" | sed '$d' >&2; exit 2; }

env_file="$here/.env" test_mode=0 config=''
while (($# > 0)); do
  case $1 in
    --env-file) (($# > 1)) || usage; env_file=$2; shift 2 ;;
    --config) (($# > 1)) || usage; config=$2; shift 2 ;;
    --test-mode) test_mode=1; shift ;;
    *) usage ;;
  esac
done
if [[ ! -f $env_file ]]; then
  echo "ERROR: $env_file: no such file (cp .env.example .env, fill it, run setup.sh)" >&2
  exit 2
fi
if ! env_check "$env_file" >&2; then
  echo "ERROR: $env_file: fix the lines above" >&2
  exit 2
fi
network=$(env_get "$env_file" NETWORK)
if ! network_known "$network"; then
  echo "ERROR: NETWORK must be sepolia or hoodi (in $env_file)" >&2
  exit 2
fi
if ! msg=$(project_env_check); then
  echo "ERROR: $msg" >&2
  exit 2
fi
config=${config:-$here/../../crates/network-config/networks/$network/config.yaml}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
pass() { echo "$1: PASS"; }
flunk() { echo "$1: FAIL"; fail=1; }
fsguard() { python3 -I "$here/lib/fsguard.py" "$@"; }
helper() { python3 -I "$here/lib/beacon.py" "$@"; }

if [[ $(uname -s) != Linux ]]; then
  echo "WARN: compose.yaml uses network_mode: host, which needs a Linux host"
fi
echo "network: $network (pinned config $(basename "$(dirname "$config")")/$(basename "$config"))"
echo "compose project: $(compose_project "$network") (docker compose -p $(compose_project "$network") --env-file $env_file)"

# The shell environment must not override .env (names only, values are never printed).
while IFS= read -r line; do flunk "${line%: FAIL}"; done < <(env_overrides "$env_file" || true)

# Images, and what README.md's release notes say about the network's fork.
for key in RETH_IMAGE LIGHTHOUSE_IMAGE; do
  image=$(env_get "$env_file" "$key")
  if ! image_pinned "$image"; then
    flunk "$key: not pinned as repo:tag@sha256:<64 hex>"
    continue
  fi
  pass "$key: pinned"
  tag=${image%@*} && tag=${tag##*:}
  if [[ $key == RETH_IMAGE ]]; then svc=reth; else svc=lighthouse; fi
  row=$(release_row "$here/README.md" "$network" "$image")
  if [[ -z $row ]]; then
    flunk "release notes: README.md has no $network row for $svc $tag at this digest"
  elif [[ ${row%%|*} == yes ]]; then
    pass "release notes: $svc $tag schedules $network's Gloas / Amsterdam fork (README.md)"
  else
    flunk "release notes: $svc $tag does not schedule $network's Gloas / Amsterdam fork (README.md): replace it before starting"
  fi
done

# Ports.
while IFS= read -r line; do flunk "$line"; done < <(ports_check "$env_file" || true)
port() { env_get "$env_file" "$1"; }
echo "ports: Engine API 127.0.0.1:$(port ENGINE_PORT), Beacon API 127.0.0.1:$(port BEACON_API_PORT)," \
  "p2p reth $(port RETH_P2P_PORT) tcp/udp, lighthouse $(port LIGHTHOUSE_P2P_PORT) tcp/udp and $(port LIGHTHOUSE_QUIC_PORT) udp"

# The checkpoint providers (named by scheme and host only).
loopback_re='^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/|$)'
# check_url <key>: 0 if the key's URL is usable; else a FAIL line (an empty one is the
# caller's to judge).
check_url() {
  local url origin
  url=$(env_get "$env_file" "$1") && url=${url%/}
  origin=$(redact_url "$url")
  if [[ -z $url ]]; then
    return 1
  elif case $url in *[[:space:]\"\'\\]*) true ;; *) false ;; esac then
    flunk "$1: holds whitespace, a quote or a backslash"
  elif [[ $url == *[?#]* ]]; then
    flunk "$1: $origin has a query or fragment (put a key in the path)"
  elif [[ $url == https://?* || $url =~ $loopback_re ]]; then
    return 0
  else
    flunk "$1: $origin is not https:// (or http:// to a loopback host)"
  fi
  return 1
}
# host_of <url>: the host, without credentials or port.
host_of() {
  local h=${1#*://}
  h=${h%%[/?#]*} && h=${h##*@}
  case $h in \[*) h=${h%%]*}] ;; *) h=${h%%:*} ;; esac
  printf '%s\n' "$h" | tr '[:upper:]' '[:lower:]'
}
need=$(required_providers "$network")
urls=() origins=()
for n in 1 2; do
  if [[ $n == 1 ]]; then key=CHECKPOINT_SYNC_URL; else key=CHECKPOINT_SYNC_URL_2; fi
  url=$(env_get "$env_file" "$key") && url=${url%/}
  if [[ -z $url ]]; then
    if ((n <= need)); then
      if ((need == 1)); then flunk "$key: empty"; else flunk "$key: empty ($network needs $need checkpoint providers, run by different operators)"; fi
    else
      echo "$key: empty (one checkpoint provider; a second one, run by another operator, cross-checks the anchor)"
    fi
    continue
  fi
  check_url "$key" || continue
  if ((n == 2)) && ((${#urls[@]} == 1)) && [[ $(host_of "$url") == "$(host_of "${urls[0]}")" ]]; then
    flunk "$key: the same host as CHECKPOINT_SYNC_URL (want providers run by different operators)"
    continue
  fi
  urls+=("$url") origins+=("$(redact_url "$url")")
  echo "checkpoint provider $n: $(redact_url "$url")"
done

peers=$(env_get "$env_file" TRUSTED_PEERS)
peer_re='[1-9A-HJ-NP-Za-km-z]{32,128}'
if [[ -z $peers ]]; then
  echo "TRUSTED_PEERS: empty (add the m2a-session peer ID before the session)"
elif [[ $peers =~ ^$peer_re(,$peer_re)*$ ]]; then
  n=$(printf '%s' "$peers" | tr ',' '\n' | wc -l | tr -d ' ')
  pass "TRUSTED_PEERS: $((n + 1)) peer(s)"
else
  flunk "TRUSTED_PEERS: not a comma-separated list of base58 peer IDs"
fi

# Ids, directories and the JWT copies.
root=$(env_get "$env_file" DATA_ROOT)
root=${root:-$(default_data_root "$network")}
ids_ok=1
for key in RETH_UID RETH_GID LIGHTHOUSE_UID LIGHTHOUSE_GID; do
  if [[ ! $(env_get "$env_file" "$key") =~ ^[0-9]+$ ]]; then
    flunk "$key: not a number (run setup.sh)"
    ids_ok=0
  fi
done
# owned <path> <mode> <uid>: one verdict line for a directory (stat never blocks on it).
owned() {
  local got
  got=$(file_mode_uid "$1" 2>/dev/null || true)
  if [[ $got == "$2 $3" ]]; then pass "$1: $got"; else flunk "$1: ${got:-missing} (want $2 $3)"; fi
}
# secret_file <path> <uid>: one verdict line for a JWT copy, opened only through fsguard.
secret_file() {
  local got reason
  if got=$(fsguard inspect "$1" 2> "$work/inspect.err"); then
    if [[ $got == "600 $2" ]]; then pass "$1: $got"; else flunk "$1: $got (want 600 $2)"; fi
  else
    # The path is data: strip it with a parameter expansion, never in a sed program.
    reason=$(sed -n '1s/^ERROR: //p' "$work/inspect.err")
    flunk "$1: ${reason#"$1: "} (want 600 $2)"
  fi
}
if ((ids_ok)); then
  reth_uid=$(env_get "$env_file" RETH_UID) lh_uid=$(env_get "$env_file" LIGHTHOUSE_UID)
  for pre in RETH LIGHTHOUSE; do
    if ((10#$(env_get "$env_file" ${pre}_UID) == 0)); then flunk "${pre}_UID: 0 is root"; fi
  done
  if ((test_mode == 0)); then
    for svc in reth lighthouse; do
      if [[ $svc == reth ]]; then pre=RETH; else pre=LIGHTHOUSE; fi
      user=$(service_user "$network" "$svc")
      uid=$(env_get "$env_file" ${pre}_UID) gid=$(env_get "$env_file" ${pre}_GID)
      if ((10#$gid == 0)); then flunk "${pre}_GID: 0 is root's group"; fi
      if ! id -u "$user" >/dev/null 2>&1; then
        flunk "user $user: does not exist (run setup.sh)"
        continue
      fi
      if [[ $uid != "$(id -u "$user")" ]]; then flunk "${pre}_UID: $uid is not user $user's uid $(id -u "$user")"; fi
      if [[ $gid != "$(id -g "$user")" ]]; then flunk "${pre}_GID: $gid is not user $user's gid $(id -g "$user")"; fi
    done
    if ((10#$reth_uid == 10#$lh_uid)); then flunk "RETH_UID, LIGHTHOUSE_UID: the same uid for both services"; fi
    if ((10#$(env_get "$env_file" RETH_GID) == 10#$(env_get "$env_file" LIGHTHOUSE_GID))); then
      flunk "RETH_GID, LIGHTHOUSE_GID: the same gid for both services"
    fi
  fi
  owned "$root/reth/data" 700 "$reth_uid"
  secret_file "$root/reth/jwt.hex" "$reth_uid"
  owned "$root/lighthouse/data" 700 "$lh_uid"
  secret_file "$root/lighthouse/jwt.hex" "$lh_uid"
fi
if fsguard same-secret "$root/reth/jwt.hex" "$root/lighthouse/jwt.hex" 2>/dev/null; then
  pass "jwt: both copies hold the same 32-byte hex secret"
else
  flunk "jwt: the two copies differ or are not a 32-byte hex secret"
fi

# Disk: the free space under DATA_ROOT (the headroom check is the operator's, README.md).
if free=$(df -Pk "$root" 2>/dev/null | awk 'NR == 2 && $4 ~ /^[0-9]+$/ { print int($4 / 1048576) }') && [[ -n $free ]]; then
  echo "disk: $root: $free GiB free"
else
  echo "disk: $root: unknown (df failed)"
fi

# Each provider's spec against the pinned config.
# (An index loop: bash 3.2 under set -u refuses "${a[@]}" of an empty array.)
specs_ok=1 i=0
while ((i < ${#urls[@]})); do
  rc=0
  fetch "${urls[$i]}/eth/v1/config/spec" "$work/spec-$i.json" || rc=$?
  if ((rc != 0)); then
    flunk "spec: could not fetch /eth/v1/config/spec from ${origins[$i]} (curl exit $rc)"; specs_ok=0
  else
    rc=0
    helper spec-diff "$config" "$work/spec-$i.json" || rc=$?
    if ((rc == 0)); then
      pass "spec: ${origins[$i]} matches $(basename "$(dirname "$config")")/$(basename "$config")"
    else
      flunk "spec: ${origins[$i]} differs from the pinned config"; specs_ok=0
    fi
  fi
  i=$((i + 1))
done

# The anchor: provider 2 holds provider 1's finalized block, with the same block and state
# root. Lighthouse syncs from provider 1's finalized checkpoint when it starts, which is this
# block or a later one.
# TODO: once cl-sync's anchor-fetch has `--providers A,B --check` (it fetches the finalized
# state and block from both and compares the block root, the state root and the header's
# state_root), run it here as well, before the start:
#   anchor-fetch --providers "<provider 1>,<provider 2>" --check
# and feed its verified state and block to Lighthouse's checkpoint flags. Mind that a key in a
# provider URL would then be on anchor-fetch's command line.
if ((${#urls[@]} == 2)); then
  if ((specs_ok == 0)); then
    echo "anchor: not compared (a provider failed a check above)"
  else
    rc=0
    fetch "${urls[0]}/eth/v1/beacon/headers/finalized" "$work/anchor-1.json" || rc=$?
    if ((rc != 0)); then
      flunk "anchor: could not fetch the finalized header from ${origins[0]} (curl exit $rc)"
    elif ! slot=$(helper header-slot "$work/anchor-1.json" 2>&1); then
      flunk "anchor: ${origins[0]}: ${slot#ERROR: }"
    else
      fetch "${urls[1]}/eth/v1/beacon/headers/$slot" "$work/anchor-2.json" || rc=$?
      if ((rc != 0)); then
        flunk "anchor: could not fetch slot $slot from ${origins[1]} (curl exit $rc)"
      else
        rc=0
        helper anchor-compare "$work/anchor-1.json" "$work/anchor-2.json" || rc=$?
        if ((rc != 0)); then fail=1; fi
      fi
    fi
  fi
fi

if ((fail)); then
  echo "preflight FAILED"
  exit 1
fi
if ((test_mode)); then
  echo "preflight OK (test mode: not a deployment gate)"
else
  echo "preflight OK"
fi
