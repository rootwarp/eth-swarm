#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted checks and stub bodies expand later, on purpose
# Offline tests for ops/sepolia-ref. Run: bash ops/sepolia-ref/tests/sepolia-ref.test.sh
# Covers the spec-diff helper (fixtures and the real pinned Sepolia config), the beacon API
# verdicts, the image pin and URL redaction rules, setup.sh in --test-mode under a temp root,
# preflight.sh and collect-run-log.sh end to end against stub curl/ss/stat/docker commands, and
# the compose file when docker is installed. No network, no root. Works on bash 3.2.
# As root it runs only with ETHSWARM_ROOT_TESTS=1 (a throwaway container: it creates users),
# and then runs, besides the pure checks, the root-only part: setup.sh and preflight.sh for
# real (no --test-mode), every setup.sh refusal as real root, and the regression runs of the
# DATA_ROOT ancestor swap and the run-log temp-file swap. The rest runs as a normal user.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
ref=$(cd "$here/.." && pwd)
repo=$(cd "$ref/../.." && pwd)
helper="$ref/lib/beacon.py"
pinned="$repo/crates/network-config/networks/sepolia/config.yaml"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tmp=$(cd -P "$tmp" && pwd -P)   # setup.sh refuses a root reached through a symlink (macOS /var)
start_dir=$PWD
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout

passed=0 failed=0

ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

# check <expect-exit> <description> <command...>: the command's exit code.
check() {
  local expect=$1 desc=$2 rc=0 out
  shift 2
  out=$("$@" 2>&1) || rc=$?
  if ((rc == expect)); then ok "$desc"; else bad "$desc (exit $rc, want $expect)" "$out"; fi
}

# check_out <expect-exit> <description> <pattern> <command...>: the exit code, and an output
# line matching the extended regex <pattern>.
check_out() {
  local expect=$1 desc=$2 pattern=$3 rc=0 out
  shift 3
  out=$("$@" 2>&1) || rc=$?
  if ((rc == expect)) && printf '%s\n' "$out" | grep -Eq -- "$pattern"; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect; want a line matching /$pattern/)" "$out"
  fi
}

# --- spec-diff helper --------------------------------------------------------------------------

# A small pinned config in the shape of network-config's YAML: comments, quoted values, keys
# that are not compared, the blob schedule, and a second list (gas limits) after it.
cat > "$tmp/pinned.yaml" <<'YAML'
# Extends the mainnet preset
PRESET_BASE: 'mainnet'
CONFIG_NAME: 'sepolia'
GENESIS_FORK_VERSION: 0x90000069
# Fulu
FULU_FORK_VERSION: 0x90000075
FULU_FORK_EPOCH: 272640   # trailing comment
# Gloas
GLOAS_FORK_VERSION: "0x90000076"
GLOAS_FORK_EPOCH: 353024
TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: 3599
SECONDS_PER_SLOT: 12

BLOB_SCHEDULE:
  - EPOCH: 274176
    MAX_BLOBS_PER_BLOCK: 15
  # a comment inside the list
  - EPOCH: 275712
    MAX_BLOBS_PER_BLOCK: 21

GAS_LIMIT_SCHEDULE:
  - EPOCH: 353024
    GAS_LIMIT: 200000000
YAML

# spec_json <file> [sed expression]: the node's /eth/v1/config/spec answer matching pinned.yaml,
# as the beacon API writes it (decimal strings), edited by the sed expression.
spec_json() {
  printf '%s' '{"data":{"CONFIG_NAME":"sepolia","GENESIS_FORK_VERSION":"0x90000069",' \
    '"FULU_FORK_VERSION":"0x90000075","FULU_FORK_EPOCH":"272640",' \
    '"GLOAS_FORK_VERSION":"0x90000076","GLOAS_FORK_EPOCH":"353024",' \
    '"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":"3599","SECONDS_PER_SLOT":"12",' \
    '"BLOB_SCHEDULE":[{"EPOCH":"274176","MAX_BLOBS_PER_BLOCK":"15"},' \
    '{"EPOCH":"275712","MAX_BLOBS_PER_BLOCK":"21"}]}}' $'\n' | sed -e "${2:-}" > "$1"
}

diff_case() { # diff_case <expect-exit> <description> <pattern> <sed expression>
  spec_json "$tmp/spec.json" "$4"
  check_out "$1" "spec-diff: $2" "$3" python3 -I "$helper" spec-diff "$tmp/pinned.yaml" "$tmp/spec.json"
}

diff_case 0 "a matching node passes" '^spec diff: empty \(3 fork versions, 2 fork epochs, 2 blob schedule entries\)' ''
diff_case 0 "upper-case hex in a fork version is the same version" '^spec diff: empty' \
  's/"0x90000076"/"0X90000076"/'
diff_case 0 "keys that are not fork keys are not compared" '^spec diff: empty' \
  's/"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":"3599"/"TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH":"1"/'
diff_case 0 "an unwrapped answer (no data object) is read too" '^spec diff: empty' \
  's/^{"data":\(.*\)}$/\1/'
diff_case 1 "a changed fork version fails" '^- GLOAS_FORK_VERSION: pinned 0x90000076, node 0x90000077$' \
  's/"GLOAS_FORK_VERSION":"0x90000076"/"GLOAS_FORK_VERSION":"0x90000077"/'
diff_case 1 "a changed fork epoch fails" '^- GLOAS_FORK_EPOCH: pinned 353024, node 353025$' \
  's/"GLOAS_FORK_EPOCH":"353024"/"GLOAS_FORK_EPOCH":"353025"/'
diff_case 1 "a missing fork epoch fails" '^- FULU_FORK_EPOCH: pinned 272640, missing on the node$' \
  's/"FULU_FORK_EPOCH":"272640",//'
diff_case 1 "an answer without any fork key (a checkpointz proxy) fails with a hint" '^note: the answer has no fork keys at all' \
  's/"GENESIS_FORK_VERSION":"0x90000069","FULU_FORK_VERSION":"0x90000075","FULU_FORK_EPOCH":"272640","GLOAS_FORK_VERSION":"0x90000076","GLOAS_FORK_EPOCH":"353024",//'
diff_case 1 "a missing genesis fork version fails" '^- GENESIS_FORK_VERSION: pinned 0x90000069, missing on the node$' \
  's/"GENESIS_FORK_VERSION":"0x90000069",//'
diff_case 1 "a non-integer fork epoch fails" '^- GLOAS_FORK_EPOCH: pinned 353024, node "soon"' \
  's/"GLOAS_FORK_EPOCH":"353024"/"GLOAS_FORK_EPOCH":"soon"/'
diff_case 1 "an extra fork the node schedules fails" '^- HEZE_FORK_EPOCH: node 400000, not in the pinned config$' \
  's/"CONFIG_NAME"/"HEZE_FORK_VERSION":"0x90000077","HEZE_FORK_EPOCH":"400000","CONFIG_NAME"/'
diff_case 0 "an extra fork at FAR_FUTURE_EPOCH (unscheduled) passes" '^spec diff: empty' \
  's/"CONFIG_NAME"/"HEZE_FORK_VERSION":"0x90000077","HEZE_FORK_EPOCH":"18446744073709551615","CONFIG_NAME"/'
diff_case 1 "an extra fork version without an epoch fails" '^- HEZE_FORK_VERSION: node 0x90000077, not in the pinned config$' \
  's/"CONFIG_NAME"/"HEZE_FORK_VERSION":"0x90000077","CONFIG_NAME"/'
diff_case 1 "a missing BLOB_SCHEDULE fails" '^- BLOB_SCHEDULE: missing on the node$' \
  's/,"BLOB_SCHEDULE":\[.*\]//'
diff_case 1 "an extra BLOB_SCHEDULE entry fails" '^- BLOB_SCHEDULE: epoch 300000 \(max 30\) not in the pinned config$' \
  's/\]}}$/,{"EPOCH":"300000","MAX_BLOBS_PER_BLOCK":"30"}]}}/'
diff_case 1 "a missing BLOB_SCHEDULE entry fails" '^- BLOB_SCHEDULE: epoch 275712 \(max 21\) missing on the node$' \
  's/,{"EPOCH":"275712","MAX_BLOBS_PER_BLOCK":"21"}//'
diff_case 1 "a changed MAX_BLOBS_PER_BLOCK fails" '^- BLOB_SCHEDULE: epoch 275712: pinned max 21, node max 20$' \
  's/"MAX_BLOBS_PER_BLOCK":"21"/"MAX_BLOBS_PER_BLOCK":"20"/'
diff_case 1 "a changed BLOB_SCHEDULE epoch fails both ways" '^- BLOB_SCHEDULE: epoch 275713 \(max 21\) not in the pinned config$' \
  's/"EPOCH":"275712"/"EPOCH":"275713"/'
diff_case 1 "a duplicated BLOB_SCHEDULE epoch on the node fails" '^- BLOB_SCHEDULE: epoch 274176 appears 2 times on the node$' \
  's/"EPOCH":"275712"/"EPOCH":"274176"/'
diff_case 1 "a BLOB_SCHEDULE entry without MAX_BLOBS_PER_BLOCK fails" '^- BLOB_SCHEDULE: entry 2 on the node is not \{EPOCH, MAX_BLOBS_PER_BLOCK\}' \
  's/,"MAX_BLOBS_PER_BLOCK":"21"//'
# Order does not matter: the spec reads the schedule sorted by epoch (get_blob_parameters).
diff_case 0 "a reordered BLOB_SCHEDULE is the same schedule" '^spec diff: empty' \
  's/\[\({"EPOCH":"274176","MAX_BLOBS_PER_BLOCK":"15"}\),\({"EPOCH":"275712","MAX_BLOBS_PER_BLOCK":"21"}\)\]/[\2,\1]/'

printf 'not json' > "$tmp/garbage.json"
check 2 "spec-diff: an answer that is not JSON is an error" \
  python3 -I "$helper" spec-diff "$tmp/pinned.yaml" "$tmp/garbage.json"
check 2 "spec-diff: a missing pinned config is an error" \
  python3 -I "$helper" spec-diff "$tmp/absent.yaml" "$tmp/spec.json"
printf 'GLOAS_FORK_EPOCH: 1\nGLOAS_FORK_EPOCH: 2\nBLOB_SCHEDULE: []\n' > "$tmp/dup.yaml"
check 2 "spec-diff: a key twice in the pinned config is an error" \
  python3 -I "$helper" spec-diff "$tmp/dup.yaml" "$tmp/spec.json"
printf 'GLOAS_FORK_EPOCH: 1\n' > "$tmp/no-schedule.yaml"
check 2 "spec-diff: a pinned config without BLOB_SCHEDULE is an error" \
  python3 -I "$helper" spec-diff "$tmp/no-schedule.yaml" "$tmp/spec.json"
printf 'BLOB_SCHEDULE: []\nSECONDS_PER_SLOT: 12\n' > "$tmp/no-forks.yaml"
check 2 "spec-diff: a pinned config without fork keys is an error" \
  python3 -I "$helper" spec-diff "$tmp/no-forks.yaml" "$tmp/spec.json"
printf 'GLOAS_FORK_EPOCH: 1\nBLOB_SCHEDULE:\n  - EPOCH: 1\n    GAS: 2\n' > "$tmp/odd-entry.yaml"
check 2 "spec-diff: a pinned BLOB_SCHEDULE entry with other keys is an error" \
  python3 -I "$helper" spec-diff "$tmp/odd-entry.yaml" "$tmp/spec.json"

# The real pinned Sepolia config, against an answer built from its own fork lines and schedule.
real_spec_json() {
  {
    printf '{"data":{'
    grep -E '^[A-Z0-9_]+_FORK_(VERSION|EPOCH):' "$pinned" | sed -E 's/^([A-Z0-9_]+): *([^ #]+).*/"\1":"\2",/' | tr -d '\n'
    printf '"SECONDS_PER_SLOT":"12","BLOB_SCHEDULE":['
    awk '/^BLOB_SCHEDULE:/ {on = 1; next} on && /^[^ #-]/ {on = 0}
      on && /EPOCH:/ {e = $NF} on && /MAX_BLOBS_PER_BLOCK:/ {printf "%s{\"EPOCH\":\"%s\",\"MAX_BLOBS_PER_BLOCK\":\"%s\"}", sep, e, $NF; sep = ","}' "$pinned"
    printf ']}}\n'
  } > "$1"
}
real_spec_json "$tmp/real-spec.json"
check_out 0 "spec-diff: the real pinned config against its own answer" \
  '^spec diff: empty \(8 fork versions, 7 fork epochs, 2 blob schedule entries\)' \
  python3 -I "$helper" spec-diff "$pinned" "$tmp/real-spec.json"
sed 's/"GLOAS_FORK_EPOCH":"353024"/"GLOAS_FORK_EPOCH":"18446744073709551615"/' "$tmp/real-spec.json" > "$tmp/pre-gloas.json"
check_out 1 "spec-diff: the real pinned config against a pre-Gloas endpoint" \
  '^- GLOAS_FORK_EPOCH: pinned 353024, node 18446744073709551615$' \
  python3 -I "$helper" spec-diff "$pinned" "$tmp/pre-gloas.json"

# --- beacon API verdicts (collect-run-log.sh's per-criterion logic) ----------------------------

genesis=1655733600
printf '{"data":{"genesis_time":"%s","genesis_validators_root":"0xd8ea","genesis_fork_version":"0x90000069"}}\n' \
  "$genesis" > "$tmp/genesis.json"
now=$((genesis + 12 * 1000 + 5))   # wall-clock slot 1000, 5 s into it

# syncing_case <expect-exit> <description> <pattern> <head_slot> [is_syncing is_optimistic el_offline]
syncing_case() {
  printf '{"data":{"head_slot":"%s","sync_distance":"0","is_syncing":%s,"is_optimistic":%s,"el_offline":%s}}\n' \
    "$4" "${5:-false}" "${6:-false}" "${7:-false}" > "$tmp/syncing.json"
  check_out "$1" "syncing: $2" "$3" \
    python3 -I "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/spec.json" "$now"
}
spec_json "$tmp/spec.json"
syncing_case 0 "head at the wall-clock slot passes" '^head_slot 1000, wall-clock slot 1000 \(lag 0\), is_syncing false, is_optimistic false, el_offline false: PASS$' 1000
syncing_case 0 "a lag of 2 slots passes" '\(lag 2\).*: PASS$' 998
syncing_case 1 "a lag of 3 slots fails" '\(lag 3\).*: FAIL$' 997
syncing_case 0 "a head 2 slots ahead passes (clock skew)" '\(lag -2\).*: PASS$' 1002
syncing_case 1 "a head 3 slots ahead fails" '\(lag -3\).*: FAIL$' 1003
syncing_case 1 "is_syncing true fails" 'is_syncing true.*: FAIL$' 1000 true
syncing_case 1 "is_optimistic true fails" 'is_optimistic true.*: FAIL$' 1000 false true
syncing_case 1 "el_offline true fails" 'el_offline true.*: FAIL$' 1000 false false true
printf '{"data":{"head_slot":"1000","is_syncing":false,"is_optimistic":false}}\n' > "$tmp/syncing.json"
check_out 1 "syncing: a missing el_offline fails" 'el_offline missing.*: FAIL$' \
  python3 -I "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/spec.json" "$now"
syncing_case 1 'is_syncing "false" (a string) fails' 'is_syncing "false".*: FAIL$' 1000 '"false"'
printf '{"data":{"SECONDS_PER_SLOT":"0"}}\n' > "$tmp/zero-sps.json"
check 2 "syncing: SECONDS_PER_SLOT 0 is an error" \
  python3 -I "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/zero-sps.json" "$now"
printf '{"data":{"SLOT_DURATION_MS":"12000"}}\n' > "$tmp/ms-only.json"
check_out 1 "syncing: SLOT_DURATION_MS stands in for a missing SECONDS_PER_SLOT" 'wall-clock slot 1000 ' \
  python3 -I "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/ms-only.json" "$now"

# finalized_case <expect-exit> <description> <pattern> <finalized slot> <database info JSON>
finalized_case() {
  printf '{"data":{"root":"0xab","canonical":true,"header":{"message":{"slot":"%s","proposer_index":"1"}}}}\n' \
    "$4" > "$tmp/finalized.json"
  printf '%s\n' "$5" > "$tmp/dbinfo.json"
  check_out "$1" "finalized: $2" "$3" python3 -I "$helper" finalized "$tmp/finalized.json" "$tmp/dbinfo.json"
}
anchor='{"schema_version":31,"anchor":{"anchor_slot":"9000","oldest_block_slot":"%s","state_upper_limit":"9000","state_lower_limit":"0"}}'
# shellcheck disable=SC2059
finalized_case 0 "128 slots past the oldest block passes" \
  '^finalized slot 10128, oldest block slot 10000 \(anchor\.oldest_block_slot\): 128 slots: PASS$' 10128 "$(printf "$anchor" 10000)"
# shellcheck disable=SC2059
finalized_case 1 "127 slots past the oldest block fails" '127 slots: FAIL$' 10127 "$(printf "$anchor" 10000)"
# No anchor proves nothing about the oldest stored block, so it fails closed.
finalized_case 1 "anchor null fails (the oldest block is unknown)" \
  '^finalized slot 200, oldest block slot unknown \(anchor: null\): FAIL$' 200 '{"schema_version":31,"anchor":null}'
finalized_case 1 "no anchor key fails" '^finalized slot 128, oldest block slot unknown \(no anchor\): FAIL$' 128 '{"schema_version":31}'
finalized_case 1 "an anchor without oldest_block_slot fails" 'oldest block slot unknown.*FAIL$' 9999 \
  '{"anchor":{"anchor_slot":"9000"}}'
# shellcheck disable=SC2059
finalized_case 1 "a finalized slot below the oldest block fails" '-1 slots: FAIL$' 9999 "$(printf "$anchor" 10000)"

# identity_case <expect-exit> <description> <pattern> <public ip> <p2p_addresses JSON> [custody_group_count]
pid=16Uiu2HAmQ5L4BYrnTKcBgvYw1oSv1mYj4tsRkKaJ7NShcC5kU8Jr
identity_case() {
  printf '{"data":{"peer_id":"%s","enr":"enr:-Iu4QA","p2p_addresses":%s,"discovery_addresses":[],"metadata":{"seq_number":"7","attnets":"0x00","syncnets":"0x00"%s}}}\n' \
    "$pid" "$5" "${6-,\"custody_group_count\":\"4\"}" > "$tmp/identity.json"
  check_out "$1" "identity: $2" "$3" python3 -I "$helper" identity "$tmp/identity.json" "$4"
}
identity_case 0 "the public address of the identity is used" \
  "^multiaddr: /ip4/34\.89\.10\.7/tcp/9000/p2p/$pid$" '' \
  "[\"/ip4/10.0.0.5/tcp/9000/p2p/$pid\",\"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"]"
identity_case 0 "--public-ip wins over the identity" "^multiaddr: /ip4/198\.51\.100\.9/tcp/9000/p2p/$pid$" \
  198.51.100.9 "[\"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"]"
identity_case 0 "custody_group_count is recorded" '^custody_group_count: 4$' '' "[\"/ip4/34.89.10.7/tcp/9000\"]"
identity_case 0 "the peer ID is recorded" "^peer_id: $pid$" '' "[\"/ip4/34.89.10.7/tcp/9000\"]"
identity_case 1 "only private addresses and no --public-ip fails" '^error: no public IPv4' '' \
  "[\"/ip4/10.0.0.5/tcp/9000\",\"/ip4/127.0.0.1/tcp/9000\"]"
identity_case 1 "a --public-ip that is not an IPv4 address fails" '^error: --public-ip is not an IPv4 address' 'example.org' '[]'
identity_case 1 "a missing custody_group_count fails" '^error: custody_group_count is missing' '' \
  "[\"/ip4/34.89.10.7/tcp/9000\"]" ''
sed "s/$pid/not-a-peer-id/" "$tmp/identity.json" > "$tmp/bad-identity.json"
check_out 1 "identity: a peer ID that is not base58 fails" '^error: peer_id is not base58 or missing$' \
  python3 -I "$helper" identity "$tmp/bad-identity.json" ''
out=$(python3 -I "$helper" identity "$tmp/bad-identity.json" '' 2>&1 || true)
if printf '%s\n' "$out" | grep -Eq '^(peer_id|custody_group_count|multiaddr): '; then
  bad "identity: an error is never printed as a value line" "$out"
else
  ok "identity: an error is never printed as a value line"
fi
check 2 "an unknown helper command is an error" python3 -I "$helper" frobnicate

# --- shared shell rules (lib/common.sh) --------------------------------------------------------

# shellcheck source=../lib/common.sh
source "$ref/lib/common.sh"
d64=$(printf 'a%.0s' $(seq 1 64))
pin() { check "$1" "image pin: $2" image_pinned "$2"; }
pin 0 "ghcr.io/paradigmxyz/reth:v2.7.0@sha256:$d64"
pin 0 "sigp/lighthouse:v8.3.0-rc.0@sha256:$d64"
pin 0 "registry.example:5000/team/reth:v1@sha256:$d64"
pin 1 "ghcr.io/paradigmxyz/reth:v2.7.0"
pin 1 "ghcr.io/paradigmxyz/reth@sha256:$d64"
pin 1 "ghcr.io/paradigmxyz/reth:v2.7.0@sha256:${d64:0:12}"
pin 1 "ghcr.io/paradigmxyz/reth:v2.7.0@sha256:$(printf '%s' "$d64" | tr a A)"
pin 1 "ghcr.io/paradigmxyz/reth:v2.7.0@sha256:${d64}a"
pin 1 "ghcr.io/paradigmxyz/reth:v2.7.0@sha512:$d64$d64"
pin 1 "ghcr.io/paradigmxyz/reth:latest@sha256:$d64 "
pin 1 ""

# redact <description> <url> <want>
redact() {
  local got
  got=$(redact_url "$2")
  if [[ $got == "$3" ]]; then ok "redact: $1"; else bad "redact: $1 (got '$got', want '$3')"; fi
}
redact "scheme and host only" "https://sepolia.beaconstate.info" "https://sepolia.beaconstate.info"
redact "a trailing slash is not a path" "https://sepolia.beaconstate.info/" "https://sepolia.beaconstate.info"
redact "the port stays" "http://127.0.0.1:5052" "http://127.0.0.1:5052"
redact "a key in the path is cut" "https://eth-sepolia.example.com/v2/KEY123secret" "https://eth-sepolia.example.com/…"
redact "a key in the query is cut" "https://cp.example.com?apikey=KEY123secret" "https://cp.example.com/…"
redact "credentials are cut" "https://user:KEY123secret@cp.example.com/x" "https://cp.example.com/…"
redact "no scheme is not echoed" "KEY123secret" "(not a URL)"

# ss -ltnp as the reference host prints it.
ss_head='State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process'
ss_reth='LISTEN 0      4096       127.0.0.1:8551       0.0.0.0:*    users:(("reth-binary",pid=812,fd=97))'
ss_lh='LISTEN 0      1024       127.0.0.1:5052       0.0.0.0:*    users:(("lighthouse",pid=901,fd=40))'
ss_p2p='LISTEN 0      1024         0.0.0.0:9000       0.0.0.0:*    users:(("lighthouse",pid=901,fd=31))'
binds() { # binds <expect-exit> <description> <pattern> <ss lines...>
  local expect=$1 desc=$2 pattern=$3
  shift 3
  check_out "$expect" "binds: $desc" "$pattern" check_binds "$(printf '%s\n' "$ss_head" "$@")" 8551 5052
}
binds 0 "both on 127.0.0.1, p2p on 0.0.0.0" '^port 5052: 127\.0\.0\.1 only: PASS$' "$ss_reth" "$ss_lh" "$ss_p2p"
binds 1 "8551 on 0.0.0.0 fails" '^port 8551: listening on 0\.0\.0\.0:8551 .*FAIL$' "${ss_reth/127.0.0.1/0.0.0.0}" "$ss_lh"
binds 1 "5052 on [::] fails" '^port 5052: listening on \[::\]:5052 .*FAIL$' "$ss_reth" "${ss_lh/127.0.0.1/[::]}"
binds 1 "5052 on * fails" '^port 5052: listening on \*:5052 .*FAIL$' "$ss_reth" "${ss_lh/127.0.0.1/*}"
binds 1 "a second listener on another address fails" '^port 5052: listening on 10\.0\.0\.5:5052 .*FAIL$' \
  "$ss_reth" "$ss_lh" "${ss_lh/127.0.0.1/10.0.0.5}"
binds 1 "no listener on 8551 fails" '^port 8551: no listener: FAIL$' "$ss_lh"
binds 1 "port 18551 is not port 8551" '^port 8551: no listener: FAIL$' "${ss_reth/:8551/:18551}" "$ss_lh"

check_out 0 "mode: 600 and the service user passes" '^/k: 600 reth: PASS$' check_mode_owner /k "600 reth" reth
check_out 1 "mode: 644 fails" '^/k: 644 reth \(want 600 reth\): FAIL$' check_mode_owner /k "644 reth" reth
check_out 1 "mode: another owner fails" '\(want 600 lighthouse\): FAIL$' check_mode_owner /k "600 reth" lighthouse
check_out 1 "mode: a missing file fails" '^/k: no such file \(want 600 reth\): FAIL$' check_mode_owner /k "" reth
check_out 1 "mode: 6000 is not 600" 'FAIL$' check_mode_owner /k "6000 reth" reth

# refusal_cases [--test-mode]: setup.sh refuses, before it changes anything, every path it
# would follow or reown wrongly, and every .env line compose would read differently. Each
# case: exit 2, and the check after it holds (single-quoted on purpose: evaluated after).
refusal_cases() {
  refuse_flags=${1:-}
  local base="$tmp/refusals${refuse_flags:+-test}"
  mkdir -p "$base" && chmod 0700 "$base"
  refuse_env="$base/refuse.env"
  cp "$ref/.env.example" "$refuse_env"
  mkdir -p "$base/x"
  refuse_case "a .. component" '[[ ! -e $base/srv2 ]]' --root "$base/x/../srv2"
  refuse_case "a . component" '[[ ! -e $base/srv2 ]]' --root "$base/./srv2"
  refuse_case "a relative root" 'true' --root relative/dir
  mkdir -p "$base/realroot" && chmod 0700 "$base/realroot" && ln -s "$base/realroot" "$base/linkroot"
  refuse_case "a root that is a symlink" '[[ -z $(ls -A "$base/realroot") && $(mode_of "$base/realroot") == 700 ]]' --root "$base/linkroot"
  mkdir -p "$base/realparent" && ln -s "$base/realparent" "$base/linkparent"
  refuse_case "a root reached through a symlinked ancestor" '[[ ! -e $base/realparent/srv ]]' --root "$base/linkparent/srv"
  mkdir -p "$base/wroot" && chmod 1777 "$base/wroot"
  refuse_case "a world-writable root (like /tmp)" '[[ $(mode_of "$base/wroot") == 1777 && -z $(ls -A "$base/wroot") ]]' --root "$base/wroot"
  mkdir -p "$base/groot" && chmod 0770 "$base/groot"
  refuse_case "a group-writable root" '[[ $(mode_of "$base/groot") == 770 ]]' --root "$base/groot"
  mkdir -p "$base/wparent" && chmod 0777 "$base/wparent"
  refuse_case "a new root inside a world-writable directory" '[[ ! -e $base/wparent/srv ]]' --root "$base/wparent/srv"
  chmod 0755 "$base/wparent"
  # Every directory from / down counts, not only the root and its parent.
  mkdir -p "$base/gw/mid" && chmod 0770 "$base/gw" && chmod 0755 "$base/gw/mid"
  refuse_case "a group-writable directory two levels up (new root)" '[[ ! -e $base/gw/mid/srv ]]' --root "$base/gw/mid/srv"
  refuse_case "a group-writable directory one level up (existing root)" '[[ $(mode_of "$base/gw/mid") == 755 && -z $(ls -A "$base/gw/mid") ]]' --root "$base/gw/mid"
  r="$base/plant-svc"; mkdir -m 0700 "$r"; ln -s "$tmp/decoy" "$r/reth"
  refuse_case "a service dir that is a symlink (reth -> elsewhere)" \
    '[[ $(file_mode_uid "$tmp/decoy") == "755 $me_uid" && -z $(ls -A "$tmp/decoy") && ! -e $r/lighthouse && ! -e $r/.staging ]]' --root "$r"
  r="$base/plant-lh"; mkdir -m 0700 "$r"; ln -s "$tmp/decoy" "$r/lighthouse"
  refuse_case "the lighthouse dir as a symlink" '[[ $(mode_of "$tmp/decoy") == 755 && ! -e $r/reth ]]' --root "$r"
  r="$base/plant-data"; mkdir -m 0700 "$r" "$r/reth"; ln -s "$tmp/decoy" "$r/reth/data"
  refuse_case "a data dir that is a symlink" '[[ $(mode_of "$tmp/decoy") == 755 ]]' --root "$r"
  r="$base/plant-file"; mkdir -m 0700 "$r"; : > "$r/reth"
  refuse_case "a service dir that is a regular file" '[[ -f $r/reth ]]' --root "$r"
  r="$base/plant-staging"; mkdir -m 0700 "$r"; ln -s "$tmp/decoy" "$r/.staging"
  refuse_case "a staging dir that is a symlink" '[[ -z $(ls -A "$tmp/decoy") ]]' --root "$r"
  r="$base/stale-staging"; mkdir -m 0700 "$r" "$r/.staging"; ln -s "$tmp/decoy" "$r/.staging/jwt.new.AAAAAA"
  refuse_case "a staging dir that is not empty" '[[ ! -e $r/reth ]]' --root "$r"
  r="$base/open-staging"; mkdir -m 0700 "$r"; mkdir -m 0777 "$r/.staging"
  refuse_case "a staging dir open to others" '[[ $(mode_of "$r/.staging") == 777 && ! -e $r/reth ]]' --root "$r"
  # A set-up root, then a JWT copy replaced by a symlink or a hard link to a victim file.
  r="$base/plant-jwt"; mkdir -m 0700 "$r"
  # shellcheck disable=SC2086 # $refuse_flags is empty or one flag
  bash "$setup" $refuse_flags --env-file "$refuse_env" --root "$r" >/dev/null 2>&1
  printf 'victim' > "$base/victim" && chmod 0644 "$base/victim"
  rm "$r/reth/jwt.hex" && ln -s "$base/victim" "$r/reth/jwt.hex"
  refuse_case "a JWT copy that is a symlink" '[[ $(cat "$base/victim") == victim && $(file_mode_uid "$base/victim") == "644 $me_uid" ]]' --root "$r"
  rm "$r/reth/jwt.hex" && ln "$base/victim" "$r/reth/jwt.hex"
  refuse_case "a JWT copy that is a hard link" '[[ $(cat "$base/victim") == victim && $(file_mode_uid "$base/victim") == "644 $me_uid" ]]' --root "$r"
  rm "$r/reth/jwt.hex" && mkdir "$r/reth/jwt.hex"
  refuse_case "a JWT path that is a directory" '[[ -d $r/reth/jwt.hex ]]' --root "$r"
  # .env lines compose reads differently: export (last one wins), indentation, a key twice,
  # $ or a backtick (expanded). setup.sh refuses before it creates anything.
  local line
  for line in 'export RETH_UID=0' ' RETH_UID=0' 'RETH_IMAGE=again' 'CHECKPOINT_SYNC_URL=https://x.example/$SECRETPART' \
    'TRUSTED_PEERS=`id`'; do
    cp "$ref/.env.example" "$refuse_env" && printf '%s\n' "$line" >> "$refuse_env"
    refuse_case ".env line '${line%%=*}=…'" '[[ ! -e $base/env-root ]]' --root "$base/env-root"
  done
  cp "$ref/.env.example" "$refuse_env"
}
refuse_case() {
  local desc=$1 after=$2 rc=0 out
  shift 2
  # shellcheck disable=SC2086 # $refuse_flags is empty or one flag
  out=$(bash "$setup" $refuse_flags --env-file "$refuse_env" "$@" 2>&1) || rc=$?
  if ((rc == 2)) && eval "$after"; then ok "setup refuses${refuse_flags:+ (test mode)}: $desc"; else bad "setup refuses: $desc (exit $rc, check: $after)" "$out"; fi
}

# --- setup.sh --test-mode under a temp root (not as root) --------------------------------------

setup="$ref/setup.sh"
me_uid=$(id -u) me_gid=$(id -g)
if ((me_uid == 0)) && [[ ${ETHSWARM_ROOT_TESTS:-} != 1 ]]; then
  echo "# as root this suite needs ETHSWARM_ROOT_TESTS=1 (a throwaway container only); run it as a normal user"
  exit 2
fi
mode_of() { file_mode_uid "$1" | cut -d' ' -f1; }
mkdir -p "$tmp/decoy" && chmod 0755 "$tmp/decoy"
if ((me_uid != 0)); then
root="$tmp/srv"
env_file="$tmp/setup.env"
cp "$ref/.env.example" "$env_file"
outs="$tmp/setup-outputs"
: > "$outs"
# run_setup <expect-exit> <description> [args...]: setup.sh against $env_file, its stdout and
# stderr kept in $outs for the secret check below.
run_setup() {
  local expect=$1 desc=$2 rc=0 out
  shift 2
  out=$(bash "$setup" --test-mode --env-file "$env_file" "$@" 2>&1) || rc=$?
  printf '%s\n' "$out" >> "$outs"
  if ((rc == expect)); then ok "setup: $desc"; else bad "setup: $desc (exit $rc, want $expect)" "$out"; fi
}
jwt_r="$root/reth/jwt.hex" jwt_l="$root/lighthouse/jwt.hex"
# is_secret <file>: exactly 64 lower-case hex characters, no newline.
is_secret() { [[ $(wc -c < "$1" | tr -d ' ') == 64 ]] && grep -Eq '^[0-9a-f]{64}$' "$1"; }

run_setup 0 "first run under a temp root" --root "$root"
if [[ -f $jwt_r && -f $jwt_l ]]; then ok "setup: both JWT copies exist"; else bad "setup: both JWT copies exist"; fi
for f in "$jwt_r" "$jwt_l"; do
  m=$(file_mode_uid "$f" 2>/dev/null || true)
  if [[ $m == "600 $me_uid" ]]; then ok "setup: ${f#"$root"/} is 0600"; else bad "setup: ${f#"$root"/} is 0600 (got '$m')"; fi
done
for d in reth reth/data lighthouse lighthouse/data; do
  m=$(file_mode_uid "$root/$d" 2>/dev/null || true)
  if [[ $m == "700 $me_uid" ]]; then ok "setup: $d is 0700"; else bad "setup: $d is 0700 (got '$m')"; fi
done
if cmp -s "$jwt_r" "$jwt_l"; then ok "setup: the copies are equal"; else bad "setup: the copies are equal"; fi
if is_secret "$jwt_r"; then ok "setup: the secret is 64 hex characters"; else bad "setup: the secret is 64 hex characters"; fi
want_env=$(printf '%s\n' "DATA_ROOT=$root" "RETH_UID=$me_uid" "RETH_GID=$me_gid" "LIGHTHOUSE_UID=$me_uid" "LIGHTHOUSE_GID=$me_gid")
got_env=$(grep -E '^(DATA_ROOT|RETH_UID|RETH_GID|LIGHTHOUSE_UID|LIGHTHOUSE_GID)=' "$env_file" || true)
if [[ $got_env == "$want_env" ]]; then ok "setup: .env records DATA_ROOT and the ids, once each"; else bad "setup: .env records DATA_ROOT and the ids" "$got_env"; fi
if grep -q '^RETH_IMAGE=' "$env_file"; then ok "setup: other .env lines are kept"; else bad "setup: other .env lines are kept"; fi
m=$(file_mode_uid "$env_file")
if [[ $m == "600 $me_uid" ]]; then ok "setup: .env is 0600"; else bad "setup: .env is 0600 (got '$m')"; fi

cp "$jwt_r" "$tmp/jwt.first"
run_setup 0 "re-run (DATA_ROOT now from .env)"
if cmp -s "$jwt_r" "$tmp/jwt.first" && cmp -s "$jwt_l" "$tmp/jwt.first"; then ok "setup: a re-run keeps the secret"; else bad "setup: a re-run keeps the secret"; fi

chmod 0644 "$jwt_l"
run_setup 0 "re-run repairs a 0644 copy"
m=$(file_mode_uid "$jwt_l")
if [[ $m == "600 $me_uid" ]]; then ok "setup: the repaired copy is 0600"; else bad "setup: the repaired copy is 0600 (got '$m')"; fi

run_setup 0 "--rotate-jwt" --rotate-jwt
if ! cmp -s "$jwt_r" "$tmp/jwt.first" && cmp -s "$jwt_r" "$jwt_l" && is_secret "$jwt_l"; then
  ok "setup: --rotate-jwt writes a new secret to both copies"
else
  bad "setup: --rotate-jwt writes a new secret to both copies"
fi
cp "$jwt_r" "$tmp/jwt.rotated"

rm "$jwt_l"
run_setup 0 "a missing copy is restored from the other"
if cmp -s "$jwt_l" "$tmp/jwt.rotated"; then ok "setup: the restored copy is the same secret"; else bad "setup: the restored copy is the same secret"; fi

printf '%064d' 0 > "$jwt_l"
run_setup 1 "copies that differ are refused without --rotate-jwt"
if cmp -s "$jwt_r" "$tmp/jwt.rotated"; then ok "setup: a refused run changes nothing"; else bad "setup: a refused run changes nothing"; fi
printf 'nothex' > "$jwt_r"; printf 'nothex' > "$jwt_l"
run_setup 1 "equal copies that are not a 32-byte hex secret are refused"
run_setup 0 "--rotate-jwt replaces them" --rotate-jwt

# The secret never reaches stdout or stderr, in any run above.
for f in "$tmp/jwt.first" "$tmp/jwt.rotated" "$jwt_r"; do
  if grep -qF "$(cat "$f")" "$outs"; then bad "setup: a secret appears in the output" "$(cat "$outs")"; break; fi
done
if grep -Eq '[0-9a-f]{64}' "$outs"; then bad "setup: no 64-hex string in any output"; else ok "setup: no secret in any output"; fi

run_setup 2 "a relative --root is refused" --root relative/dir
rc=0; bash "$setup" --test-mode --env-file "$tmp/absent.env" --root "$root" >/dev/null 2>&1 || rc=$?
if ((rc == 2)); then ok "setup: a missing .env is refused"; else bad "setup: a missing .env is refused (exit $rc)"; fi
rc=0; bash "$setup" --frobnicate >/dev/null 2>&1 || rc=$?
if ((rc == 2)); then ok "setup: an unknown option is refused"; else bad "setup: an unknown option is refused (exit $rc)"; fi
if ((me_uid != 0)); then
  rc=0; bash "$setup" --env-file "$env_file" --root "$tmp/other" >/dev/null 2>&1 || rc=$?
  if ((rc == 2)) && [[ ! -e $tmp/other ]]; then ok "setup: without --test-mode it needs root"; else bad "setup: without --test-mode it needs root (exit $rc)"; fi
fi

# The JWT copies are staged in a root-only directory, never in the service-owned ones.
m=$(file_mode_uid "$root/.staging" 2>/dev/null || true)
if [[ $m == "700 $me_uid" && -z $(ls -A "$root/.staging") ]]; then ok "setup: .staging is 0700, ours, and empty after a run"; else bad "setup: .staging is 0700, ours, and empty (got '$m')"; fi
for svc in reth lighthouse; do
  got=''
  for f in "$root/$svc"/* "$root/$svc"/.[!.]*; do if [[ -e $f ]]; then got="$got${f##*/} "; fi; done
  if [[ $got == "data jwt.hex " ]]; then ok "setup: no temp file left in $svc/"; else bad "setup: no temp file left in $svc/ (got '$got')"; fi
done

refusal_cases --test-mode
fi

# --- stubs for preflight.sh and collect-run-log.sh ---------------------------------------------

# Every external command the two scripts call is a stub on PATH: curl serves fixture files by
# API path, ss and stat print canned output, docker answers image inspect and compose exec.
stubs="$tmp/stubs" http="$tmp/http"
mkdir -p "$stubs" "$http"
export STUB_DIR="$tmp"
cat > "$stubs/curl" <<'SH'
#!/usr/bin/env bash
# curl stub: the URL comes on stdin (--config -); the answer is $STUB_DIR/http/<API path with
# / as _>, the API path being everything from /eth/ or /lighthouse/ on. No file: exit 22.
out=
while (($# > 0)); do
  case $1 in --output) out=$2; shift 2 ;; *) shift ;; esac
done
url=$(sed -n 's/^url = "\(.*\)"$/\1/p')
printf '%s\n' "$url" >> "$STUB_DIR/curl.log"
case $url in
  */eth/*) api=/eth/${url#*/eth/} ;;
  */lighthouse/*) api=/lighthouse/${url#*/lighthouse/} ;;
  *) exit 22 ;;
esac
f="$STUB_DIR/http/$(printf '%s' "${api#/}" | tr '/' '_')"
[[ -n $out ]] || exit 22
if [[ -x $f.sh ]]; then "$f.sh" > "$out"; exit; fi   # a generated answer (reads the clock)
[[ -f $f ]] || exit 22
cat "$f" > "$out"
SH
cat > "$stubs/ss" <<'SH'
#!/usr/bin/env bash
cat "$STUB_DIR/ss.txt"
SH
cat > "$stubs/stat" <<'SH'
#!/usr/bin/env bash
# stat stub: `stat -c FORMAT PATH` prints the line for PATH in $STUB_DIR/stat.txt
# ("PATH<TAB>output"); no line: "No such file", exit 1.
line=$(awk -F '\t' -v p="${!#}" '$1 == p { print $2 }' "$STUB_DIR/stat.txt")
[[ -n $line ]] || { echo "stat: cannot statx '${!#}': No such file or directory" >&2; exit 1; }
printf '%s\n' "$line"
SH
cat > "$stubs/docker" <<'SH'
#!/usr/bin/env bash
# docker stub, answering from $STUB_DIR/docker/: <svc>.digests and <svc>.image-id for image
# inspect (<svc> is reth when the ref names reth), <svc>.ctr for compose ps -q (absent: not
# running), <ctr>.json (docker inspect) and <ctr>.top for a container. compose commands also
# warn on stderr the way compose does about a $ in .env, which must never reach the log.
d=$STUB_DIR/docker
svc_of() { case $1 in *reth*) echo reth ;; *) echo lighthouse ;; esac; }
last=${!#}
if [[ $1 == compose ]]; then
  echo 'WARN[0000] The "SECRETPART" variable is not set. Defaulting to a blank string.' >&2
fi
case "$*" in
  "image inspect --format {{range .RepoDigests}}"*) cat "$d/$(svc_of "$last").digests" ;;
  "image inspect --format {{.Id}} "*) cat "$d/$(svc_of "$last").image-id" ;;
  "inspect "*) cat "$d/$2.json" ;;
  "top "*) cat "$d/$2.top" ;;
  "compose "*" ps -q --status running "*) cat "$d/$last.ctr" 2>/dev/null || true ;;
  *" exec -T reth "*) echo "Reth Version: 2.7.0" ;;
  *" exec -T lighthouse "*) echo "Lighthouse v8.3.0-rc.0-0123abc" ;;
  *) echo "docker stub: unexpected: $*" >&2; exit 1 ;;
esac
SH
# date and sleep stubs: with $STUB_DIR/clock, a fake clock that sleep advances (so a 1 h run
# takes no time); without it, the real commands.
cat > "$stubs/date" <<'SH'
#!/usr/bin/env bash
clock=$STUB_DIR/clock
[[ -f $clock ]] || exec /bin/date "$@"
c=$(cat "$clock") fmt=+%s
for a in "$@"; do case $a in +*) fmt=$a ;; esac; done
if [[ $fmt == +%s ]]; then echo "$c"; exit; fi
/bin/date -u -r "$c" "$fmt" 2>/dev/null || /bin/date -u -d "@$c" "$fmt"
SH
cat > "$stubs/sleep" <<'SH'
#!/usr/bin/env bash
clock=$STUB_DIR/clock
[[ -f $clock ]] || exec /bin/sleep "$@"
echo $(($(cat "$clock") + $1)) > "$clock"
SH
chmod +x "$stubs"/*
# preflight.sh stats real files, so it gets only the curl stub.
mkdir -p "$tmp/stubs-curl" && cp "$stubs/curl" "$tmp/stubs-curl/"
# set_env <file> <key> <value>: replace or append KEY=value.
set_env() {
  awk -v k="$2" -v v="$3" 'index($0, k "=") == 1 { if (!done) print k "=" v; done = 1; next } { print }
    END { if (!done) print k "=" v }' "$1" > "$1.new" && mv "$1.new" "$1"
}

# --- preflight.sh (not as root) ---------------------------------------------------------------
if ((me_uid != 0)); then

preflight="$ref/preflight.sh"
cp "$tmp/real-spec.json" "$http/eth_v1_config_spec"
pf_env="$tmp/pf.env"
pf_base() {
  cp "$env_file" "$pf_env"
  set_env "$pf_env" CHECKPOINT_SYNC_URL "https://checkpoint.example.org"
  chmod 0600 "$jwt_r" "$jwt_l"
}
# pf_case <expect-exit> <description> <pattern> [preflight args]: preflight.sh --test-mode (the
# setup.sh --test-mode root has one uid for both services) against $pf_env and the stubs.
pf_case() {
  local expect=$1 desc=$2 pattern=$3
  shift 3
  check_out "$expect" "preflight: $desc" "$pattern" env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" "$@"
}
# pf_real <description> <pattern>: preflight.sh without --test-mode; it fails, with the line.
pf_real() {
  check_out 1 "preflight: $1" "$2" env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$pf_env"
}
pf_base
pf_case 0 "a set-up host and a matching endpoint pass" '^spec diff: empty \(8 fork versions'
pf_case 0 "the endpoint is named by scheme and host" '^checkpoint endpoint: https://checkpoint\.example\.org$'

set_env "$pf_env" CHECKPOINT_SYNC_URL "https://eth-sepolia.example.com/v2/KEY123secret/"
: > "$tmp/curl.log"
rc=0; out=$(PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if ((rc == 0)) && ! printf '%s' "$out" | grep -q KEY123secret && printf '%s\n' "$out" | grep -qF 'https://eth-sepolia.example.com/…'; then
  ok "preflight: a key in the URL path is never printed"
else
  bad "preflight: a key in the URL path is never printed (exit $rc)" "$out"
fi
if grep -qx 'https://eth-sepolia.example.com/v2/KEY123secret/eth/v1/config/spec' "$tmp/curl.log"; then
  ok "preflight: the spec is fetched under the URL's base path, URL on curl's stdin"
else
  bad "preflight: the spec is fetched under the URL's base path" "$(cat "$tmp/curl.log")"
fi

pf_base; set_env "$pf_env" RETH_IMAGE "ghcr.io/paradigmxyz/reth:v2.7.0"
pf_case 1 "a tag-only image is refused" '^RETH_IMAGE: not pinned as repo:tag@sha256:<64 hex>: FAIL$'
pf_base; set_env "$pf_env" LIGHTHOUSE_IMAGE "sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609"
pf_case 1 "a short digest is refused" '^LIGHTHOUSE_IMAGE: not pinned'
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL ""
pf_case 1 "an empty CHECKPOINT_SYNC_URL is refused" '^CHECKPOINT_SYNC_URL: empty: FAIL$'
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "http://checkpoint.example.org"
pf_case 1 "plain http to a remote host is refused" '^CHECKPOINT_SYNC_URL: http://checkpoint\.example\.org is not https:// \(or http:// to a loopback host\): FAIL$'
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "http://127.0.0.1:5052"
pf_case 0 "plain http to a loopback host passes" '^checkpoint endpoint: http://127\.0\.0\.1:5052$'
pf_base; set_env "$pf_env" TRUSTED_PEERS "16Uiu2HAm,not a peer"
pf_case 1 "a TRUSTED_PEERS entry that is not base58 is refused" '^TRUSTED_PEERS: .*FAIL$'
pf_base; set_env "$pf_env" TRUSTED_PEERS "$pid,$pid"
pf_case 0 "a comma-separated TRUSTED_PEERS list passes" '^TRUSTED_PEERS: 2 peer'
pf_base; set_env "$pf_env" RETH_UID ""
pf_case 1 "a missing RETH_UID is refused (setup.sh not run)" '^RETH_UID: not a number .*FAIL$'
pf_base; chmod 0644 "$jwt_l"
pf_case 1 "a 0644 JWT copy is refused" "lighthouse/jwt\.hex: 644 $me_uid \(want 600 $me_uid\): FAIL$"
pf_base; set_env "$pf_env" RETH_UID $((me_uid + 1))
pf_case 1 "a JWT copy owned by another user is refused" "reth/jwt\.hex: 600 $me_uid \(want 600 $((me_uid + 1))\): FAIL$"
pf_base; cp "$jwt_r" "$tmp/jwt.keep"; printf '%064d' 1 > "$jwt_r"
pf_case 1 "JWT copies that differ are refused" '^jwt: the two copies differ or are not a 32-byte hex secret: FAIL$'
cp "$tmp/jwt.keep" "$jwt_r"; chmod 0600 "$jwt_r"
pf_base; cp "$tmp/pre-gloas.json" "$http/eth_v1_config_spec"
pf_case 1 "an endpoint on a pre-Gloas config is refused, with the diff" '^- GLOAS_FORK_EPOCH: pinned 353024, node 18446744073709551615$'
rm "$http/eth_v1_config_spec"
pf_case 1 "an endpoint that does not answer is refused" '^spec: could not fetch /eth/v1/config/spec from https://checkpoint\.example\.org \(curl exit 22\): FAIL$'
cp "$tmp/real-spec.json" "$http/eth_v1_config_spec"
# The ids, outside --test-mode: never root, never shared, and the users setup.sh created.
pf_base; set_env "$pf_env" RETH_UID 0
pf_real "RETH_UID 0 (root) is refused" '^RETH_UID: 0 is root: FAIL$'
pf_base; set_env "$pf_env" LIGHTHOUSE_UID 0
pf_real "LIGHTHOUSE_UID 0 (root) is refused" '^LIGHTHOUSE_UID: 0 is root: FAIL$'
pf_base
pf_real "one uid for both services is refused" '^RETH_UID, LIGHTHOUSE_UID: the same uid for both services: FAIL$'
if ! id -u reth >/dev/null 2>&1; then
  pf_real "a missing reth user is refused" '^user reth: does not exist \(run setup.sh\): FAIL$'
fi
pf_base
pf_case 0 "--test-mode allows one uid for both services, and says it is no gate" '^preflight OK \(test mode: not a deployment gate\)$'
pf_base; set_env "$pf_env" RETH_UID 0
pf_case 1 "--test-mode still refuses uid 0" '^RETH_UID: 0 is root: FAIL$'
pf_base; set_env "$pf_env" LIGHTHOUSE_UID 0
pf_case 1 "--test-mode still refuses LIGHTHOUSE_UID 0" '^LIGHTHOUSE_UID: 0 is root: FAIL$'
pf_base; set_env "$pf_env" RETH_GID 0
pf_real "RETH_GID 0 is refused" '^RETH_GID: 0 is root.s group: FAIL$'
pf_base
pf_real "one gid for both services is refused" '^RETH_GID, LIGHTHOUSE_GID: the same gid for both services: FAIL$'
# .env lines compose reads differently are refused outright, naming the line, never the value.
for line in 'export RETH_UID=0' '  RETH_UID=0' 'RETH_UID=1' 'CHECKPOINT_SYNC_URL=https://x.example/$SECRETPART' 'TRUSTED_PEERS=`id`'; do
  pf_base; printf '%s\n' "$line" >> "$pf_env"
  rc=0; out=$(env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
  if ((rc == 2)) && printf '%s\n' "$out" | grep -q ' line [0-9]*: ' && ! printf '%s' "$out" | grep -q SECRETPART; then
    ok "preflight: .env line '${line%%=*}=…' is refused"
  else
    bad "preflight: .env line '$line' is refused (exit $rc)" "$out"
  fi
done

# A query or fragment would land after the API path (or hide it): refused, never printed.
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "https://cp.example.org/base?apikey=KEY123secret"
pf_case 1 "a checkpoint URL with a query is refused" '^CHECKPOINT_SYNC_URL: https://cp\.example\.org/… has a query or fragment \(put a key in the path\): FAIL$'
rc=0; out=$(PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if printf '%s' "$out" | grep -q KEY123secret; then bad "preflight: the query is never printed" "$out"; else ok "preflight: the query is never printed"; fi
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "https://cp.example.org/#frag"
pf_case 1 "a checkpoint URL with a fragment is refused" 'has a query or fragment .*FAIL$'

# compose lets the shell environment override .env: a differing value is refused (by name).
pf_base
check_out 1 "preflight: RETH_IMAGE overridden in the environment is refused" \
  '^RETH_IMAGE: set in the environment and differs from \.env \(compose would use it\): FAIL$' \
  env PATH="$tmp/stubs-curl:$PATH" RETH_IMAGE="ghcr.io/paradigmxyz/reth:v2.6.0@sha256:$d64" bash "$preflight" --test-mode --env-file "$pf_env"
check_out 1 "preflight: an empty CHECKPOINT_SYNC_URL in the environment is an override too" \
  '^CHECKPOINT_SYNC_URL: set in the environment and differs' \
  env PATH="$tmp/stubs-curl:$PATH" CHECKPOINT_SYNC_URL= bash "$preflight" --test-mode --env-file "$pf_env"
check_out 1 "preflight: DATA_ROOT overridden in the environment is refused" '^DATA_ROOT: set in the environment' \
  env PATH="$tmp/stubs-curl:$PATH" DATA_ROOT=/elsewhere bash "$preflight" --test-mode --env-file "$pf_env"
check_out 0 "preflight: an environment value equal to .env passes" '^preflight OK \(test mode' \
  env PATH="$tmp/stubs-curl:$PATH" RETH_UID="$me_uid" bash "$preflight" --test-mode --env-file "$pf_env"
rc=0; out=$(env PATH="$tmp/stubs-curl:$PATH" CHECKPOINT_SYNC_URL="https://other.example/KEY999secret" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if printf '%s' "$out" | grep -q KEY999secret; then bad "preflight: an overriding value is never printed" "$out"; else ok "preflight: an overriding value is never printed"; fi

check 2 "preflight: a missing .env is refused" bash "$preflight" --env-file "$tmp/absent.env"
check 2 "preflight: an unknown option is refused" bash "$preflight" --frobnicate

fi

# --- collect-run-log.sh against the stubs (not as root) ----------------------------------------
if ((me_uid != 0)); then

collect="$ref/collect-run-log.sh"
cl_env="$tmp/cl.env"
key_path="$root/lighthouse/data/beacon/network/key"
reth_digest=a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336
lh_digest=3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc
mkdir -p "$tmp/docker"
# cl_base: a healthy synced node on a fake clock; each case below breaks one thing.
cl_base() {
  cp "$env_file" "$cl_env"
  set_env "$cl_env" CHECKPOINT_SYNC_URL "https://eth-sepolia.example.com/v2/KEY123secret"
  set_env "$cl_env" TRUSTED_PEERS "$pid"
  set_env "$cl_env" RETH_UID 990; set_env "$cl_env" RETH_GID 990
  set_env "$cl_env" LIGHTHOUSE_UID 991; set_env "$cl_env" LIGHTHOUSE_GID 991
  echo 1790000000 > "$tmp/clock"
  echo $((1790000000 - 12 * 1000 - 6)) > "$tmp/genesis_time"
  printf '{"data":{"genesis_time":"%s","genesis_validators_root":"0xd8ea","genesis_fork_version":"0x90000069"}}\n' \
    "$(cat "$tmp/genesis_time")" > "$http/eth_v1_beacon_genesis"
  cl_syncing 0 false
  cp "$tmp/real-spec.json" "$http/eth_v1_config_spec"
  cl_finalized 10128
  printf '%s\n' '{"schema_version":31,"anchor":{"anchor_slot":"10000","oldest_block_slot":"10000","state_upper_limit":"10000","state_lower_limit":"0"}}' \
    > "$http/lighthouse_database_info"
  cl_identity "[\"/ip4/34.89.10.7/tcp/9000/p2p/$pid\",\"/ip4/34.89.10.7/udp/9001/quic-v1/p2p/$pid\"]" ',"custody_group_count":"4"'
  printf '%s\n' "$ss_head" "$ss_reth" "$ss_lh" "$ss_p2p" > "$tmp/ss.txt"
  printf '%s\t%s\n' "$jwt_r" "600 reth" "$jwt_l" "600 lighthouse" "$key_path" "600 lighthouse" > "$tmp/stat.txt"
  rm -f "$tmp/docker"/*
  cl_container reth "ghcr.io/paradigmxyz/reth@sha256:$reth_digest" sha256:1111 ctr-reth 990
  cl_container lighthouse "sigp/lighthouse@sha256:$lh_digest" sha256:2222 ctr-lh 991
}
# cl_container <svc> <repo digest> <image id> <container id> <uid>: a running container of the
# pinned image, as <uid>, hardened as compose.yaml asks (its docker inspect output).
cl_container() {
  printf '%s\n' "$2" > "$tmp/docker/$1.digests"
  echo "$3" > "$tmp/docker/$1.image-id"
  echo "$4" > "$tmp/docker/$1.ctr"
  python3 -I - "$tmp/docker/$4.json" "$1" "$3" "$5" "$root" <<'PY'
import json, sys
out, svc, image, uid, root = sys.argv[1:]
json.dump([{
    "Image": image,
    "Config": {"User": f"{uid}:{uid}"},
    "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": None,
                   "SecurityOpt": ["no-new-privileges:true"], "Privileged": False,
                   "NetworkMode": "host", "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=256m"}},
    "Mounts": [
        {"Type": "bind", "Source": f"{root}/{svc}/data", "Destination": "/data", "RW": True},
        {"Type": "bind", "Source": f"{root}/{svc}/jwt.hex", "Destination": "/secrets/jwt.hex", "RW": False},
    ],
}], open(out, "w"))
PY
  printf '%s\n' 'RUID EUID PID COMMAND' "$5 $5 812 $1" > "$tmp/docker/$4.top"
}
# cl_inspect <container id> <python statement on c, the inspect object>: loosen one setting.
cl_inspect() {
  python3 -I - "$tmp/docker/$1.json" "$2" <<'PY'
import json, sys
path, stmt = sys.argv[1:]
doc = json.load(open(path)); c = doc[0]
exec(stmt)
json.dump(doc, open(path, "w"))
PY
}
# cl_syncing <lag> <is_optimistic>: /eth/v1/node/syncing answers <lag> slots behind the clock.
cl_syncing() {
  cat > "$http/eth_v1_node_syncing.sh" <<SH
#!/usr/bin/env bash
c=\$(cat "\$STUB_DIR/clock") g=\$(cat "\$STUB_DIR/genesis_time")
printf '{"data":{"head_slot":"%s","sync_distance":"0","is_syncing":false,"is_optimistic":$2,"el_offline":false}}\n' \$(( (c - g) / 12 - $1 ))
SH
  chmod +x "$http/eth_v1_node_syncing.sh"
}
cl_finalized() {
  printf '{"data":{"root":"0xab","canonical":true,"header":{"message":{"slot":"%s"}}}}\n' "$1" > "$http/eth_v1_beacon_headers_finalized"
}
cl_identity() { # cl_identity <p2p_addresses JSON> <custody_group_count member> [peer id]
  printf '{"data":{"peer_id":"%s","enr":"enr:-Iu4QA","p2p_addresses":%s,"discovery_addresses":[],"metadata":{"seq_number":"7","attnets":"0x00","syncnets":"0x00"%s}}}\n' \
    "${3:-$pid}" "$1" "$2" > "$http/eth_v1_node_identity"
}
# cl_run <expect-exit> <description> [args...]: one run (the default 13 samples, 300 s apart,
# on the fake clock); the run log is its stdout, kept in $log, and its stderr in $log.err.
log=
cl_run() {
  local expect=$1 desc=$2 rc=0
  shift 2
  n_run=$((${n_run:-0} + 1)); log="$tmp/runlog$n_run.md"
  PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" "$@" > "$log" 2> "$log.err" || rc=$?
  if ((rc == expect)) && [[ -s $log ]]; then ok "run log: $desc"; else bad "run log: $desc (exit $rc, want $expect)" "$(cat "$log.err")"; fi
}
# cl_quick: one sample, no wait: a diagnostic run, so never an overall PASS (exit 1).
cl_quick() { cl_run 1 "$1" --samples 1 --interval 0; }
# verdict <criterion number> <PASS|FAIL|DIAGNOSTIC> <description>: the verdict table row.
verdict() {
  if [[ -n $log ]] && grep -Eq "^\| $1 \| .* \| $2 \|$" "$log"; then ok "run log: $3"; else bad "run log: $3 (criterion $1, want $2)" "$(cat "${log:-/dev/null}")"; fi
}
has() { # has <fixed string> <description>
  if [[ -n $log ]] && grep -qF -- "$1" "$log"; then ok "run log: $2"; else bad "run log: $2 (no '$1')" "$(cat "${log:-/dev/null}")"; fi
}

cl_base
cl_run 0 "a synced, hardened node passes (13 samples over 1 h)"
for c in 1 2 3 4 5 6 7 8; do verdict "$c" PASS "criterion $c passes on a healthy node"; done
has "- Overall: **PASS**" "the overall verdict is PASS"
has "13 sample(s) taken of 13, first to last 3600 s: acceptance" "the sync run is labelled acceptance"
has "Reth Version: 2.7.0" "records the reth --version output"
has "Lighthouse v8.3.0-rc.0-0123abc" "records the lighthouse --version output"
has "ghcr.io/paradigmxyz/reth@sha256:$reth_digest" "records reth's repo digest"
has "reth container ctr-reth: image sha256:1111, pinned image sha256:1111: PASS" "the running reth container runs the pinned image"
has "reth container ctr-reth: Config.User 990:990 (want 990): PASS" "records the reth container's configured user"
has "reth container ctr-reth: processes ruid/euid 990/990 (want 990): PASS" "records the reth container's process uids"
has "lighthouse container ctr-lh: ReadonlyRootfs true: PASS" "records the read-only root"
has "lighthouse container ctr-lh: mounts /data <- $root/lighthouse/data (bind, rw); /secrets/jwt.hex <- $root/lighthouse/jwt.hex (bind, ro): PASS" "records the mounts"
if grep -q SECRETPART "$log" "$log.err"; then bad "run log: compose's stderr never reaches the log"; else ok "run log: compose's stderr never reaches the log"; fi
if [[ $(tail -1 "$log.err") == "run log: PASS" ]]; then ok "run log: the verdict line is on stderr"; else bad "run log: the verdict line is on stderr" "$(cat "$log.err")"; fi
has "127.0.0.1:8551" "records the ss line for 8551"
has "$jwt_r: 600 reth: PASS" "records stat of reth's JWT copy"
has "$key_path: 600 lighthouse: PASS" "records stat of the node key"
has "spec diff: empty (8 fork versions, 7 fork epochs, 2 blob schedule entries)" "records the empty spec diff"
has "finalized slot 10128, oldest block slot 10000 (anchor.oldest_block_slot): 128 slots: PASS" "a 128-slot finalized range passes"
has "custody_group_count: 4" "records custody_group_count"
has "peer = \"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"" "writes the m2a-session peer line"
has 'trusted_by_reference = true' "TRUSTED_PEERS set: the session config is trusted_by_reference"
has 'sigp/lighthouse/releases/tag/v8.3.0-rc.0' "copies the release-note block from README.md"
if grep -q KEY123secret "$log" || grep -qF "$(cat "$jwt_r")" "$log"; then
  bad "run log: no secret (checkpoint key, JWT) in the run log"
else
  ok "run log: no secret (checkpoint key, JWT) in the run log"
fi

# Acceptance needs at least 12 samples spanning an hour; anything shorter is diagnostic.
cl_base
cl_run 1 "12 samples 300 s apart (55 min) are diagnostic" --samples 12
verdict 2 DIAGNOSTIC "a 55-minute run is not an acceptance PASS"
has "- Overall: **DIAGNOSTIC (not acceptance)**" "the overall verdict of a short run is not PASS"
has "12 sample(s) taken of 12, first to last 3300 s: diagnostic (not acceptance: needs 12 samples over 3600 s)" "says why it is diagnostic"
cl_base
cl_run 0 "12 samples 328 s apart (1 h) are acceptance" --samples 12 --interval 328
verdict 2 PASS "12 samples spanning an hour pass"
cl_base; cl_quick "one sample is diagnostic"
verdict 2 DIAGNOSTIC "--samples 1 --interval 0 is not an acceptance PASS"
cl_base
cl_run 1 "--interval 010 is decimal 10" --samples 3 --interval 010
has "Every 10s, 3 sample(s)" "a leading zero is not octal"
check 2 "run log: --samples 08 is refused" env PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --samples 08
check 2 "run log: --samples 0 is refused" env PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --samples 0
check 2 "run log: a non-numeric --interval is refused" env PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --interval 5m
check 2 "run log: a missing .env is refused" env PATH="$stubs:$PATH" bash "$collect" --env-file "$tmp/absent.env"
# The script writes no file: --out-dir is gone, and the operator's shell makes the log.
check 2 "run log: --out-dir is no longer an option" env PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --out-dir "$tmp"
for line in 'export RETH_UID=0' 'RETH_UID=1' 'TRUSTED_PEERS=$X'; do
  cl_base; printf '%s\n' "$line" >> "$cl_env"
  rc=0; out=$(PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0 2>/dev/null) || rc=$?
  if ((rc == 2)) && [[ -z $out ]]; then ok "run log: .env line '${line%%=*}=…' is refused, nothing printed"; else bad "run log: .env line '$line' is refused (exit $rc)"; fi
done

cl_base; cl_syncing 0 true
cl_run 1 "an optimistic head fails"
verdict 2 FAIL "is_optimistic true fails the sync criterion"
has "- Overall: **FAIL**" "a failed criterion makes the run FAIL"
cl_base; cl_syncing 5 false
cl_run 1 "a head 5 slots behind fails"
verdict 2 FAIL "a lagging head fails the sync criterion"
cl_base; cl_syncing 3 false
cl_run 1 "a head 3 slots behind fails"
verdict 2 FAIL "a 3-slot lag fails"
cl_base; cl_syncing 2 false
cl_run 0 "a head 2 slots behind passes"
verdict 2 PASS "a 2-slot lag passes"
cl_base; rm "$http/eth_v1_node_syncing.sh"
cl_quick "a node that does not answer /eth/v1/node/syncing fails"
has "GET /eth/v1/node/syncing failed: FAIL" "records the failed request"
verdict 2 FAIL "an unanswered sample fails the sync criterion"
cl_base; cl_quick "one sample"
if [[ $(grep -cE '^\| 1 \| [0-9]{4}-[0-9]{2}-[0-9]{2}T.* PASS \|$' "$log") == 1 ]]; then ok "run log: one row per sample"; else bad "run log: one row per sample" "$(cat "$log")"; fi

# The running containers: the pinned image, never root, the .env uid.
cl_base; cl_inspect ctr-reth 'c["Image"] = "sha256:9999"'
cl_quick "a reth container on another image fails"
verdict 1 FAIL "a container image that is not the pinned one fails criterion 1"
has "reth container ctr-reth: image sha256:9999, pinned image sha256:1111: FAIL" "records both image IDs"
cl_base; rm "$tmp/docker/lighthouse.ctr"
cl_quick "no running lighthouse container fails"
has "lighthouse: no running container: FAIL" "names the service that is not running"
verdict 1 FAIL "a stopped service fails criterion 1"
cl_base; cl_inspect ctr-reth 'c["Config"]["User"] = "0:0"'
cl_quick "a reth container configured as root fails"
has "Config.User 0:0" "records Config.User"
verdict 1 FAIL "Config.User root fails criterion 1"
cl_base; printf '%s\n' 'RUID EUID PID COMMAND' '990 0 812 reth' > "$tmp/docker/ctr-reth.top"
cl_quick "a reth process with euid 0 fails"
verdict 1 FAIL "a process running as root fails criterion 1"
cl_base; cl_inspect ctr-lh 'c["Config"]["User"] = "992:992"'
printf '%s\n' 'RUID EUID PID COMMAND' '992 992 901 lighthouse' > "$tmp/docker/ctr-lh.top"
cl_quick "a lighthouse container as another uid than LIGHTHOUSE_UID fails"
has "(want 991): FAIL" "names the expected uid"
# Every hardening setting compose.yaml makes, loosened one at a time (as an extra -f override
# file could), fails criterion 1.
hardening() { # hardening <description> <pattern> <python statement>
  cl_base; cl_inspect ctr-reth "$3"
  cl_quick "$1"
  verdict 1 FAIL "$1 fails criterion 1"
  has "$2" "records it: $2"
}
hardening "a writable root filesystem" "reth container ctr-reth: ReadonlyRootfs false: FAIL" 'c["HostConfig"]["ReadonlyRootfs"] = False'
hardening "no cap_drop ALL" 'reth container ctr-reth: CapDrop [], CapAdd []: FAIL' 'c["HostConfig"]["CapDrop"] = None'
hardening "an added capability" 'CapAdd ["NET_ADMIN"]: FAIL' 'c["HostConfig"]["CapAdd"] = ["NET_ADMIN"]'
hardening "no no-new-privileges" 'reth container ctr-reth: SecurityOpt []: FAIL' 'c["HostConfig"]["SecurityOpt"] = []'
hardening "a privileged container" 'reth container ctr-reth: Privileged true: FAIL' 'c["HostConfig"]["Privileged"] = True'
hardening "a bridge network" 'reth container ctr-reth: NetworkMode "bridge": FAIL' 'c["HostConfig"]["NetworkMode"] = "bridge"'
hardening "a writable JWT mount" '/secrets/jwt.hex <- '"$root"'/reth/jwt.hex (bind, rw): FAIL' 'c["Mounts"][1]["RW"] = True'
hardening "a data mount from elsewhere" '/data <- /srv/elsewhere/data (bind, rw)' 'c["Mounts"][0]["Source"] = "/srv/elsewhere/data"'
hardening "an extra mount" '/host <- / (bind, rw)' 'c["Mounts"].append({"Type": "bind", "Source": "/", "Destination": "/host", "RW": True})'
hardening "a missing JWT mount" 'reth container ctr-reth: mounts /data <- '"$root"'/reth/data (bind, rw): FAIL' 'c["Mounts"].pop()'
hardening "an extra tmpfs" 'tmpfs ["/run", "/tmp"]: FAIL' 'c["HostConfig"]["Tmpfs"]["/run"] = "rw"'
cl_base; cl_inspect ctr-reth 'c["Mounts"].append({"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True})'
cl_run 0 "a /tmp tmpfs listed among the mounts is fine"

cl_base; set_env "$cl_env" RETH_IMAGE "ghcr.io/paradigmxyz/reth:v9.9.9@sha256:$d64"
cl_container reth "ghcr.io/paradigmxyz/reth@sha256:$d64" sha256:1111 ctr-reth 990
cl_quick "an image whose release note README.md does not record fails"
verdict 1 FAIL "an unrecorded release fails the versions criterion"
has "v9.9.9: no release-note line in README.md" "names the release that lacks a note"
cl_base; printf '%s\n' "ghcr.io/paradigmxyz/reth@sha256:$d64" > "$tmp/docker/reth.digests"
cl_quick "a local image whose digest differs from .env fails"
verdict 1 FAIL "a digest mismatch fails the versions criterion"
cl_base
log="$tmp/runlog-env.md"
PATH="$stubs:$PATH" RETH_IMAGE="ghcr.io/paradigmxyz/reth:v2.6.0@sha256:$d64" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0 > "$log" 2>/dev/null || true
has "RETH_IMAGE: set in the environment and differs from .env (compose would use it): FAIL" "an environment override of a compose variable is recorded"
verdict 1 FAIL "an environment override fails criterion 1"

cl_base; printf '%s\n' "$ss_head" "$ss_reth" "${ss_lh/127.0.0.1/0.0.0.0}" > "$tmp/ss.txt"
cl_quick "the Beacon API on 0.0.0.0 fails"
verdict 3 FAIL "a public bind fails the localhost criterion"
cl_base; printf '%s\n' "$ss_head" "$ss_lh" > "$tmp/ss.txt"
cl_quick "no Engine API listener fails"
verdict 3 FAIL "a missing listener fails the localhost criterion"

cl_base; printf '%s\t%s\n' "$jwt_r" "600 reth" "$jwt_l" "600 lighthouse" "$key_path" "644 lighthouse" > "$tmp/stat.txt"
cl_quick "a 0644 node key fails"
verdict 4 FAIL "a 0644 node key fails the file-mode criterion"
cl_base; printf '%s\t%s\n' "$jwt_r" "600 root" "$jwt_l" "600 lighthouse" "$key_path" "600 lighthouse" > "$tmp/stat.txt"
cl_quick "a root-owned JWT copy fails"
verdict 4 FAIL "a JWT copy owned by root fails the file-mode criterion"
cl_base; printf '%s\t%s\n' "$jwt_r" "600 reth" "$jwt_l" "600 lighthouse" > "$tmp/stat.txt"
cl_quick "a missing node key fails"
has "$key_path: no such file (want 600 lighthouse): FAIL" "records the missing node key"

cl_base; cp "$tmp/pre-gloas.json" "$http/eth_v1_config_spec"
cl_quick "a node on a pre-Gloas config fails"
verdict 5 FAIL "a spec difference fails the spec criterion"
has "- GLOAS_FORK_EPOCH: pinned 353024, node 18446744073709551615" "records the spec diff"

cl_base; cl_finalized 10127
cl_quick "a 127-slot finalized range fails"
verdict 6 FAIL "127 slots fail the finalized-range criterion"
cl_base; printf '%s\n' '{"anchor":{"anchor_slot":"10000"}}' > "$http/lighthouse_database_info"
cl_quick "an anchor without oldest_block_slot fails"
verdict 6 FAIL "an unknown oldest block fails the finalized-range criterion"
cl_base; printf '%s\n' '{"schema_version":31,"anchor":null}' > "$http/lighthouse_database_info"
cl_quick "a null anchor fails"
verdict 6 FAIL "a null anchor fails closed"

cl_base; cl_identity "[\"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"]" ''
cl_quick "an identity without custody_group_count fails"
verdict 7 FAIL "a missing custody_group_count fails the identity criterion"
verdict 8 PASS "the session line still passes"
cl_base; cl_identity "[\"/ip4/34.89.10.7/tcp/9000\"]" ',"custody_group_count":"4"' not-a-peer-id
cl_quick "a peer ID that is not base58 fails"
verdict 7 FAIL "the helper's error line is not taken for a peer ID"
cl_base; cl_identity "[\"/ip4/10.0.0.5/tcp/9000/p2p/$pid\"]" ',"custody_group_count":"4"'
cl_quick "only a private address and no --public-ip fails"
verdict 8 FAIL "no public IP fails the session criterion"
has "error: no public IPv4 address in p2p_addresses; pass --public-ip" "records why there is no session line"
cl_run 0 "--public-ip supplies the address" --public-ip 34.89.10.8
has "peer = \"/ip4/34.89.10.8/tcp/9000/p2p/$pid\"" "the session line uses --public-ip"
cl_base; set_env "$cl_env" TRUSTED_PEERS ""
cl_run 0 "TRUSTED_PEERS empty still passes"
has 'trusted_by_reference = false' "TRUSTED_PEERS empty: the session config is not trusted_by_reference"

rm -f "$tmp/clock"

fi

# --- compose.yaml -------------------------------------------------------------------------------

compose_env() { # compose_env <file> <trusted peers>: .env.example with the required values set.
  cp "$ref/.env.example" "$1"
  set_env "$1" CHECKPOINT_SYNC_URL 'https://cp.example.org/v1/KEY?a=1&b=two words'
  set_env "$1" TRUSTED_PEERS "$2"
  for key in RETH_UID RETH_GID; do set_env "$1" "$key" 990; done
  for key in LIGHTHOUSE_UID LIGHTHOUSE_GID; do set_env "$1" "$key" 991; done
}
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "# skip - compose.yaml checks: docker compose is not installed"
else
  check_out 1 "compose: .env.example alone is refused until CHECKPOINT_SYNC_URL is set" \
    'CHECKPOINT_SYNC_URL is missing a value' \
    docker compose --env-file "$ref/.env.example" -f "$ref/compose.yaml" config --quiet
  check_out 1 "compose: .env.example alone is refused until setup.sh wrote the ids" \
    'RETH_UID is missing a value: run setup.sh' \
    docker compose --env-file "$ref/.env.example" -f "$ref/compose.yaml" config --quiet
  compose_env "$tmp/compose.env" ""
  check 0 "compose: config validates with the required values set" \
    docker compose --env-file "$tmp/compose.env" -f "$ref/compose.yaml" config --quiet
  docker compose --env-file "$tmp/compose.env" -f "$ref/compose.yaml" config --format json > "$tmp/compose.json"
  # compose_rule <description> <python expression over c (the config) and s (its services)>
  compose_rule() {
    check 0 "compose: $1" python3 -I -c '
import json, sys
c = json.load(open(sys.argv[1])); s = c["services"]
sys.exit(0 if eval(sys.argv[2]) else 1)' "$tmp/compose.json" "$2"
  }
  compose_rule "exactly the reth and lighthouse services" 'sorted(s) == ["lighthouse", "reth"]'
  compose_rule "host networking for both" 'all(v["network_mode"] == "host" for v in s.values())'
  compose_rule "read-only root, cap_drop ALL, no-new-privileges, /tmp tmpfs" \
    'all(v["read_only"] and v["cap_drop"] == ["ALL"] and v["security_opt"] == ["no-new-privileges:true"] and any(t.startswith("/tmp:") for t in v["tmpfs"]) for v in s.values())'
  compose_rule "restart unless-stopped, rotated json-file logs" \
    'all(v["restart"] == "unless-stopped" and v["logging"]["driver"] == "json-file" and {"max-size", "max-file"} <= set(v["logging"]["options"]) for v in s.values())'
  compose_rule "each service as its own user from .env" 's["reth"]["user"] == "990:990" and s["lighthouse"]["user"] == "991:991"'
  compose_rule "reth gets at least 5 minutes to stop" 's["reth"]["stop_grace_period"].startswith("5m")'
  compose_rule "pinned images from .env" 'all("@sha256:" in v["image"] for v in s.values())'
  compose_rule "each JWT copy mounted read-only from its own directory, no host path created" \
    'all(any(m["target"] == "/secrets/jwt.hex" and m.get("read_only") and m["source"].endswith(n + "/jwt.hex") for m in s[n]["volumes"]) and all(m["bind"]["create_host_path"] is False for m in s[n]["volumes"]) for n in s)'
  compose_rule "reth: Engine API on 127.0.0.1:8551 with the JWT, --full, Sepolia" \
    'all(a in s["reth"]["command"] for a in ["--authrpc.addr=127.0.0.1", "--authrpc.port=8551", "--authrpc.jwtsecret=/secrets/jwt.hex", "--full", "--chain=sepolia", "--ipcdisable"])'
  compose_rule "reth: no HTTP or WS RPC, metrics only if on loopback" \
    'not any(a.startswith(("--http", "--ws")) for a in s["reth"]["command"]) and all(a.startswith("--metrics=127.0.0.1:") for a in s["reth"]["command"] if a.startswith("--metrics"))'
  compose_rule "lighthouse starts after reth" '"reth" in s["lighthouse"]["depends_on"]'

  # The Lighthouse wrapper, run by bash as the container would, against a stub lighthouse that
  # prints its argv one per line.
  mkdir -p "$tmp/lh-bin"
  printf '#!/usr/bin/env bash\necho "umask $(umask)"\nprintf "%%s\\n" "$@"\n' > "$tmp/lh-bin/lighthouse"
  chmod +x "$tmp/lh-bin/lighthouse"
  # lh_argv <compose env file>: the argv the wrapper hands Lighthouse.
  lh_argv() {
    docker compose --env-file "$1" -f "$ref/compose.yaml" config --format json > "$tmp/lh.json"
    python3 -I - "$tmp/lh.json" "$tmp/lh-bin" <<'PY'
import json, os, subprocess, sys
svc = json.load(open(sys.argv[1]))["services"]["lighthouse"]
assert svc["entrypoint"] == ["/bin/bash", "-c"], svc["entrypoint"]
script = svc["command"][0].replace("$$", "$")  # compose re-escapes $ when it prints the config
env = {"PATH": sys.argv[2] + os.pathsep + os.environ["PATH"], **svc["environment"]}
sys.stdout.write(subprocess.run(["bash", "-c", script], env=env, check=True, capture_output=True, text=True).stdout)
PY
  }
  argv=$(lh_argv "$tmp/compose.env")
  want=$(printf '%s\n' 'umask 0077' bn --network sepolia --datadir /data --execution-endpoint http://127.0.0.1:8551 \
    --execution-jwt /secrets/jwt.hex --http --http-address 127.0.0.1 --http-port 5052 --port 9000 \
    --disable-upnp --checkpoint-sync-url 'https://cp.example.org/v1/KEY?a=1&b=two words')
  if [[ $argv == "$want" ]]; then ok "compose: lighthouse argv without TRUSTED_PEERS (umask 077, no --trusted-peers, URL intact)"; else bad "compose: lighthouse argv without TRUSTED_PEERS" "$argv"; fi
  compose_env "$tmp/compose-peers.env" "$pid,$pid"
  argv=$(lh_argv "$tmp/compose-peers.env")
  if [[ $argv == "$(printf '%s\n' "$want" --trusted-peers "$pid,$pid")" ]]; then ok "compose: TRUSTED_PEERS adds --trusted-peers <list>"; else bad "compose: TRUSTED_PEERS adds --trusted-peers <list>" "$argv"; fi
fi

# --- as root (ETHSWARM_ROOT_TESTS=1, a throwaway container) ------------------------------------

if ((me_uid == 0)); then
  preflight="$ref/preflight.sh" collect="$ref/collect-run-log.sh"
  real="$tmp/real" real_env="$tmp/real.env"
  cp "$ref/.env.example" "$real_env"
  rc=0; out=$(bash "$setup" --env-file "$real_env" --root "$real" 2>&1) || rc=$?
  if ((rc == 0)); then ok "root: setup.sh as root"; else bad "root: setup.sh as root (exit $rc)" "$out"; fi
  ru=$(id -u reth) lu=$(id -u lighthouse)
  for spec in "reth 700 $ru" "reth/data 700 $ru" "reth/jwt.hex 600 $ru" "lighthouse 700 $lu" \
    "lighthouse/data 700 $lu" "lighthouse/jwt.hex 600 $lu" ".staging 700 0" ". 755 0"; do
    read -r rel want_mode want_uid <<< "$spec"
    m=$(file_mode_uid "$real/$rel")
    if [[ $m == "$want_mode $want_uid" ]]; then ok "root: $rel is $m"; else bad "root: $rel (got '$m', want '$want_mode $want_uid')"; fi
  done
  shell=$(awk -F: '$1 == "reth" { print $7 }' /etc/passwd)
  if [[ $shell == */nologin ]]; then ok "root: reth has no login shell"; else bad "root: reth has no login shell (got '$shell')"; fi
  rc=0; out=$(bash "$setup" --env-file "$real_env" --root "$real" 2>&1) || rc=$?
  if ((rc == 0)); then ok "root: a re-run as root"; else bad "root: a re-run as root (exit $rc)" "$out"; fi

  # Every refusal, as real root, plus the ones only root can stage.
  refusal_cases
  mkdir -p "$tmp/oroot" && chown 65534 "$tmp/oroot" && chmod 0755 "$tmp/oroot"
  refuse_case "a root owned by another user" '[[ $(file_mode_uid "$tmp/oroot") == "755 65534" && -z $(ls -A "$tmp/oroot") ]]' --root "$tmp/oroot"
  mkdir -p "$tmp/oparent/node" && chown 65534 "$tmp/oparent" && chmod 0755 "$tmp/oparent" "$tmp/oparent/node"
  refuse_case "a directory above the root owned by another user" '[[ -z $(ls -A "$tmp/oparent/node") ]]' --root "$tmp/oparent/node"
  rc=0; bash "$setup" --test-mode --env-file "$real_env" --root "$tmp/tm-root" >/dev/null 2>&1 || rc=$?
  if ((rc == 2)) && [[ ! -e $tmp/tm-root ]]; then ok "root: setup.sh --test-mode as root is refused"; else bad "root: setup.sh --test-mode as root is refused (exit $rc)"; fi

  # hooked <n> <command>: a python3 on PATH that runs <command> (as the attacker would) just
  # before the n-th fsguard.py call of a setup.sh run, then the real python3.
  hooked() {
    mkdir -p "$tmp/hook"
    rm -f "$tmp/hook/count"
    cat > "$tmp/hook/python3" <<SH
#!/usr/bin/env bash
if [[ "\$*" == *fsguard.py* ]]; then
  n=\$((\$(cat "$tmp/hook/count" 2>/dev/null || echo 0) + 1)); echo \$n > "$tmp/hook/count"
  if ((n == $1)); then $2; fi
fi
exec $(command -v python3) "\$@"
SH
    chmod +x "$tmp/hook/python3"
  }
  # Regression (DATA_ROOT ancestor swap): another user owns a directory above DATA_ROOT and
  # swaps DATA_ROOT for a symlink to a victim tree once setup.sh starts; nothing outside
  # DATA_ROOT may change, and setup.sh must not report success.
  for n in 1 2; do
    a="$tmp/race2-$n/a" v="$tmp/race2-$n/victim"
    mkdir -p "$a/node" "$v/reth" && chown 65534 "$a" && chmod 0755 "$a" "$a/node" "$v/reth"
    hooked "$n" "mv '$a/node' '$a/saved' && ln -s '$v' '$a/node'"
    cp "$ref/.env.example" "$tmp/race2.env"
    rc=0; out=$(PATH="$tmp/hook:$PATH" bash "$setup" --env-file "$tmp/race2.env" --root "$a/node" 2>&1) || rc=$?
    if ((rc != 0)) && [[ $(file_mode_uid "$v/reth") == "755 0" && -z $(ls -A "$v/reth") && $(ls -A "$v") == reth ]]; then
      ok "root: regression: DATA_ROOT swapped for a symlink before fsguard call $n changes nothing outside it"
    else
      bad "root: regression: DATA_ROOT swapped before fsguard call $n (exit $rc, victim: $(find "$v" -exec stat -c '%a %U %n' {} \; 2>/dev/null | tr '\n' ' '))" "$out"
    fi
  done
  # A service user swaps its data dir for a symlink between the checks and the changes.
  r="$tmp/swap-data"
  cp "$ref/.env.example" "$tmp/swap.env"
  bash "$setup" --env-file "$tmp/swap.env" --root "$r" >/dev/null 2>&1
  hooked 2 "rm -rf '$r/reth/data' && ln -s '$tmp/decoy' '$r/reth/data'"
  rc=0; PATH="$tmp/hook:$PATH" bash "$setup" --env-file "$tmp/swap.env" --root "$r" >/dev/null 2>&1 || rc=$?
  if ((rc == 2)) && [[ $(file_mode_uid "$tmp/decoy") == "755 0" ]]; then ok "root: a data dir swapped after the checks is refused, its target untouched"; else bad "root: a data dir swapped after the checks (exit $rc, decoy $(file_mode_uid "$tmp/decoy"))"; fi

  # preflight.sh with the users setup.sh created: their ids pass, another uid is refused, and
  # --test-mode never lets uid 0 through.
  cp "$tmp/real-spec.json" "$http/eth_v1_config_spec"
  pf_env="$tmp/root-pf.env"
  cp "$real_env" "$pf_env"; set_env "$pf_env" CHECKPOINT_SYNC_URL "https://checkpoint.example.org"
  check_out 0 "root: preflight passes with the real users" '^preflight OK$' \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$pf_env"
  set_env "$pf_env" RETH_UID 4242
  check_out 1 "root: a RETH_UID that is not the reth user's is refused" "^RETH_UID: 4242 is not user reth's uid $ru: FAIL$" \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$pf_env"
  set_env "$pf_env" RETH_UID 0
  check_out 1 "root: preflight --test-mode refuses uid 0" '^RETH_UID: 0 is root: FAIL$' \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env"

  # Regression (run-log temp-file swap): run from a directory another user owns, who swaps any
  # run-log temp file for a symlink to a root-only file. The script writes no file at all.
  out_dir="$tmp/race3-out" victim="$tmp/race3-victim"
  mkdir -p "$out_dir" && chown 65534 "$out_dir" && chmod 0755 "$out_dir"
  printf 'SECRET\n' > "$victim" && chmod 0600 "$victim"
  mkdir -p "$tmp/hook3"
  cat > "$tmp/hook3/mktemp" <<SH
#!/usr/bin/env bash
out=\$($(command -v mktemp) "\$@") || exit
case \$out in *.run-log.*) rm -f "\$out" && ln -s "$victim" "\$out" ;; esac
echo "\$out"
SH
  chmod +x "$tmp/hook3/mktemp"
  cp "$pf_env" "$tmp/race3.env"; set_env "$tmp/race3.env" RETH_UID "$ru"
  (cd "$out_dir" && PATH="$tmp/hook3:$stubs:$PATH" bash "$collect" --env-file "$tmp/race3.env" --samples 1 --interval 0 >/dev/null 2>&1) || true
  if [[ $(cat "$victim") == SECRET && $(file_mode_uid "$victim") == "600 0" && -z $(ls -A "$out_dir") ]]; then
    ok "root: regression: a swapped run-log temp file cannot redirect root's write"
  else
    bad "root: regression: run-log temp-file swap (victim $(file_mode_uid "$victim"): $(head -1 "$victim"); out dir: $(find "$out_dir" -mindepth 1 | tr '\n' ' '))"
  fi
fi

if [[ -n $(find "$start_dir" "$tmp" -maxdepth 1 -name 'run-log-*.md') ]]; then bad "no run log written outside the tests' own files"; else ok "no run log written outside the tests' own files"; fi

echo "# $passed passed, $failed failed"
((failed == 0))
