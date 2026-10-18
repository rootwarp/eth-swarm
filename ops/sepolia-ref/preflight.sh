#!/usr/bin/env bash
# Pre-flight for the Sepolia reference node: run (as root, after setup.sh) before
# `docker compose up`. An .env with a line compose would read differently from these scripts
# (lib/common.sh env_check: `export`, indentation, a key twice, a $ or backtick in a value) is
# refused outright (exit 2). Otherwise every check runs and prints one line; any FAIL fails:
#   - RETH_IMAGE and LIGHTHOUSE_IMAGE are pinned as repo:tag@sha256:<64 lower-case hex>;
#   - no variable compose.yaml uses is overridden by the shell environment (compose would
#     take the exported value over .env);
#   - CHECKPOINT_SYNC_URL is set, https:// (or http:// to a loopback host), with no query or
#     fragment (the API path is appended to it; a provider key goes in the path), and
#     TRUSTED_PEERS is empty or a comma-separated list of base58 peer IDs;
#   - the ids setup.sh recorded are numbers and no uid is 0 (in --test-mode too); outside
#     --test-mode RETH_UID and LIGHTHOUSE_UID are distinct and the uids of the users reth and
#     lighthouse, and RETH_GID and LIGHTHOUSE_GID are non-zero, distinct and their gids;
#   - the data directories are 0700 and the JWT copies 0600, each owned by its service's uid,
#     and both copies hold the same 64-hex secret (compared with cmp, never printed);
#   - the checkpoint endpoint's /eth/v1/config/spec matches the pinned Sepolia config
#     (lib/beacon.py spec-diff: every *_FORK_VERSION, *_FORK_EPOCH and the BLOB_SCHEDULE).
#     Public endpoints have served pre-Gloas configs, so an endpoint is checked before it is used.
# The checkpoint URL may carry a provider key in its path (a query is refused): it is printed
# as scheme://host only, handed to curl on stdin (never argv) and curl's messages are dropped.
# A --test-mode pass prints "preflight OK (test mode: not a deployment gate)".
#
# Usage: ops/sepolia-ref/preflight.sh [--env-file FILE] [--config YAML] [--test-mode]
#   --env-file FILE  default: .env next to this script
#   --test-mode      for a setup.sh --test-mode root: skip the user and distinct-id checks
#   --config YAML    default: crates/network-config/networks/sepolia/config.yaml of this repo
# Exit: 0 every check passed, 1 a check failed, 2 bad usage or a missing or refused .env.
# Needs bash, curl and python3.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib/common.sh
source "$here/lib/common.sh"

usage() { sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" | sed '$d' >&2; exit 2; }

env_file="$here/.env" test_mode=0
config="$here/../../crates/network-config/networks/sepolia/config.yaml"
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
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail=0
pass() { echo "$1: PASS"; }
flunk() { echo "$1: FAIL"; fail=1; }

if [[ $(uname -s) != Linux ]]; then
  echo "WARN: compose.yaml uses network_mode: host, which needs a Linux host"
fi

# The shell environment must not override .env (names only, values are never printed).
while IFS= read -r line; do flunk "${line%: FAIL}"; done < <(env_overrides "$env_file" || true)

# Images.
for key in RETH_IMAGE LIGHTHOUSE_IMAGE; do
  if image_pinned "$(env_get "$env_file" "$key")"; then
    pass "$key: pinned"
  else
    flunk "$key: not pinned as repo:tag@sha256:<64 hex>"
  fi
done

# The checkpoint endpoint (named by scheme and host only).
url=$(env_get "$env_file" CHECKPOINT_SYNC_URL)
url=${url%/}
origin=$(redact_url "$url")
url_ok=0
loopback_re='^http://(localhost|127\.[0-9]+\.[0-9]+\.[0-9]+|\[::1\])(:[0-9]+)?(/|$)'
if [[ -z $url ]]; then
  flunk "CHECKPOINT_SYNC_URL: empty"
elif case $url in *[[:space:]\"\'\\]*) true ;; *) false ;; esac then
  flunk "CHECKPOINT_SYNC_URL: holds whitespace, a quote or a backslash"
elif [[ $url == *[?#]* ]]; then
  flunk "CHECKPOINT_SYNC_URL: $origin has a query or fragment (put a key in the path)"
elif [[ $url == https://?* || $url =~ $loopback_re ]]; then
  url_ok=1
else
  flunk "CHECKPOINT_SYNC_URL: $origin is not https:// (or http:// to a loopback host)"
fi
if ((url_ok)); then echo "checkpoint endpoint: $origin"; fi

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
root=${root:-/srv/ethswarm-ref}
ids_ok=1
for key in RETH_UID RETH_GID LIGHTHOUSE_UID LIGHTHOUSE_GID; do
  if [[ ! $(env_get "$env_file" "$key") =~ ^[0-9]+$ ]]; then
    flunk "$key: not a number (run setup.sh)"
    ids_ok=0
  fi
done
# owned <path> <mode> <uid>: one verdict line.
owned() {
  local got
  got=$(file_mode_uid "$1" 2>/dev/null || true)
  if [[ $got == "$2 $3" ]]; then pass "$1: $got"; else flunk "$1: ${got:-missing} (want $2 $3)"; fi
}
if ((ids_ok)); then
  reth_uid=$(env_get "$env_file" RETH_UID) lh_uid=$(env_get "$env_file" LIGHTHOUSE_UID)
  for pre in RETH LIGHTHOUSE; do
    if ((10#$(env_get "$env_file" ${pre}_UID) == 0)); then flunk "${pre}_UID: 0 is root"; fi
  done
  if ((test_mode == 0)); then
    for svc in reth lighthouse; do
      if [[ $svc == reth ]]; then pre=RETH; else pre=LIGHTHOUSE; fi
      uid=$(env_get "$env_file" ${pre}_UID) gid=$(env_get "$env_file" ${pre}_GID)
      if ((10#$gid == 0)); then flunk "${pre}_GID: 0 is root's group"; fi
      if ! id -u "$svc" >/dev/null 2>&1; then
        flunk "user $svc: does not exist (run setup.sh)"
        continue
      fi
      if [[ $uid != "$(id -u "$svc")" ]]; then flunk "${pre}_UID: $uid is not user $svc's uid $(id -u "$svc")"; fi
      if [[ $gid != "$(id -g "$svc")" ]]; then flunk "${pre}_GID: $gid is not user $svc's gid $(id -g "$svc")"; fi
    done
    if ((10#$reth_uid == 10#$lh_uid)); then flunk "RETH_UID, LIGHTHOUSE_UID: the same uid for both services"; fi
    if ((10#$(env_get "$env_file" RETH_GID) == 10#$(env_get "$env_file" LIGHTHOUSE_GID))); then
      flunk "RETH_GID, LIGHTHOUSE_GID: the same gid for both services"
    fi
  fi
  owned "$root/reth/data" 700 "$reth_uid"
  owned "$root/reth/jwt.hex" 600 "$reth_uid"
  owned "$root/lighthouse/data" 700 "$lh_uid"
  owned "$root/lighthouse/jwt.hex" 600 "$lh_uid"
fi
jwt_r="$root/reth/jwt.hex" jwt_l="$root/lighthouse/jwt.hex"
if [[ -r $jwt_r && -r $jwt_l ]] && cmp -s -- "$jwt_r" "$jwt_l" &&
  [[ $(wc -c < "$jwt_r" | tr -d ' ') == 64 ]] && grep -Eq '^[0-9a-f]{64}$' "$jwt_r"; then
  pass "jwt: both copies hold the same 32-byte hex secret"
else
  flunk "jwt: the two copies differ or are not a 32-byte hex secret"
fi

# The endpoint's spec against the pinned config.
if ((url_ok)); then
  rc=0
  fetch "$url/eth/v1/config/spec" "$work/spec.json" || rc=$?
  if ((rc != 0)); then
    flunk "spec: could not fetch /eth/v1/config/spec from $origin (curl exit $rc)"
  else
    rc=0
    python3 -I "$here/lib/beacon.py" spec-diff "$config" "$work/spec.json" || rc=$?
    if ((rc == 0)); then pass "spec: $origin matches $(basename "$(dirname "$config")")/$(basename "$config")"; else flunk "spec: $origin differs from the pinned config"; fi
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
