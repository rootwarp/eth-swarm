#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted checks and stub bodies expand later, on purpose
# Offline tests for ops/ref-node. Run: bash ops/ref-node/tests/ref-node.test.sh
# Covers the spec-diff helper (fixtures and the real pinned Sepolia and Hoodi configs), the
# beacon API verdicts, the two-provider anchor comparison, the image pin and URL redaction
# rules, setup.sh in --test-mode under a temp root, preflight.sh and collect-run-log.sh end to
# end against stub curl/ss/docker commands for both networks, and the compose file when docker
# is installed. No network, no root. Works on bash 3.2.
# As root it runs only with ETHSWARM_ROOT_TESTS=1 (a throwaway container: it creates users),
# and then runs, besides the pure checks, the root-only part: setup.sh and preflight.sh for
# real (no --test-mode) for both networks side by side, every setup.sh refusal as real root,
# and the regression runs of the DATA_ROOT ancestor swap, the .env directory redirect and the
# run-log temp-file swap. The rest runs as a normal user. A FIFO planted at a checked path
# needs `timeout` to bound the run, so where it is missing (macOS) those cases are skipped.
set -euo pipefail
# The scripts refuse a compose or docker variable in the environment (another compose file,
# project or daemon than the one they check), and ignore TMPDIR, so the suite runs them without
# any. No Python bytecode is written into the checkout.
for name in $(compgen -e); do
  case $name in COMPOSE_* | DOCKER_*) unset "$name" ;; esac
done
export PYTHONDONTWRITEBYTECODE=1
here=$(cd "$(dirname "$0")" && pwd)
ref=$(cd "$here/.." && pwd)
repo=$(cd "$ref/../.." && pwd)
helper="$ref/lib/beacon.py"
pinned="$repo/crates/network-config/networks/sepolia/config.yaml"
pinned_hoodi="$repo/crates/network-config/networks/hoodi/config.yaml"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tmp=$(cd -P "$tmp" && pwd -P)   # setup.sh refuses a root reached through a symlink (macOS /var)
start_dir=$PWD
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout
# A fresh copy of the stack, which the Hoodi preflight and run-log cases run from, so the
# __pycache__ check at the end sees only what the scripts wrote. Its ../../crates reaches the
# real pinned configs.
copy_ref="$tmp/repo-copy/ops/ref-node"
mkdir -p "$tmp/repo-copy/ops" && cp -R "$ref" "$copy_ref" && ln -s "$repo/crates" "$tmp/repo-copy/crates"
rm -rf "$copy_ref/lib/__pycache__"
# The images Hoodi runs (.env.hoodi.example): dev builds pinned by digest, the only ones whose
# fork-schedule check README.md records for Hoodi. Sepolia keeps its release pins.
hoodi_reth=ghcr.io/paradigmxyz/reth:nightly@sha256:8765a1d57878bebd40362d71bbfc0834d231847952402f9a10848c14476b90d2
hoodi_lh=sigp/lighthouse:latest-unstable@sha256:be7fdbcd4a321647f0300ae8dc3a9542bf391129ecaf521892f0b27dfe2e9658
sepolia_reth=ghcr.io/paradigmxyz/reth:v2.7.0@sha256:a7f059d470878a5a59f3c575f3fc81b536d0d2d56d7a1cbed73e717a4f766336
sepolia_lh=sigp/lighthouse:v8.3.0-rc.0@sha256:3e5f0609c74b824d3cb1049920169114d99fd7bc9082b996b3adae3d4e9ef8dc

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
  if ((rc == expect)) && grep -Eq -- "$pattern" <<< "$out"; then
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
  check_out "$1" "spec-diff: $2" "$3" python3 -I -B "$helper" spec-diff "$tmp/pinned.yaml" "$tmp/spec.json"
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

# beacon.py reads at most 1 MiB of an answer, the bound lib/common.sh fetch puts on curl.
{ printf '{"data":{"pad":"'; head -c 1048576 /dev/zero | tr '\0' 'a'; printf '"}}\n'; } > "$tmp/huge.json"
check_out 2 "spec-diff: an answer over 1 MiB is an input error" 'huge\.json: larger than 1048576 bytes' \
  python3 -I -B "$helper" spec-diff "$tmp/pinned.yaml" "$tmp/huge.json"
if grep -q '^FETCH_MAX_BYTES=1048576$' "$ref/lib/common.sh" && grep -q '^MAX_ANSWER = 1048576 ' "$helper"; then
  ok "fetch and beacon.py share the 1 MiB bound"
else
  bad "fetch and beacon.py share the 1 MiB bound"
fi
printf 'not json' > "$tmp/garbage.json"
check 2 "spec-diff: an answer that is not JSON is an error" \
  python3 -I -B "$helper" spec-diff "$tmp/pinned.yaml" "$tmp/garbage.json"
check 2 "spec-diff: a missing pinned config is an error" \
  python3 -I -B "$helper" spec-diff "$tmp/absent.yaml" "$tmp/spec.json"
printf 'GLOAS_FORK_EPOCH: 1\nGLOAS_FORK_EPOCH: 2\nBLOB_SCHEDULE: []\n' > "$tmp/dup.yaml"
check 2 "spec-diff: a key twice in the pinned config is an error" \
  python3 -I -B "$helper" spec-diff "$tmp/dup.yaml" "$tmp/spec.json"
printf 'GLOAS_FORK_EPOCH: 1\n' > "$tmp/no-schedule.yaml"
check 2 "spec-diff: a pinned config without BLOB_SCHEDULE is an error" \
  python3 -I -B "$helper" spec-diff "$tmp/no-schedule.yaml" "$tmp/spec.json"
printf 'BLOB_SCHEDULE: []\nSECONDS_PER_SLOT: 12\n' > "$tmp/no-forks.yaml"
check 2 "spec-diff: a pinned config without fork keys is an error" \
  python3 -I -B "$helper" spec-diff "$tmp/no-forks.yaml" "$tmp/spec.json"
printf 'GLOAS_FORK_EPOCH: 1\nBLOB_SCHEDULE:\n  - EPOCH: 1\n    GAS: 2\n' > "$tmp/odd-entry.yaml"
check 2 "spec-diff: a pinned BLOB_SCHEDULE entry with other keys is an error" \
  python3 -I -B "$helper" spec-diff "$tmp/odd-entry.yaml" "$tmp/spec.json"

# The real pinned configs, against an answer built from their own fork lines and schedule.
# real_spec_json <out> [config YAML, default the Sepolia one]
real_spec_json() {
  local yaml=${2:-$pinned}
  {
    printf '{"data":{'
    grep -E '^[A-Z0-9_]+_FORK_(VERSION|EPOCH):' "$yaml" | sed -E 's/^([A-Z0-9_]+): *([^ #]+).*/"\1":"\2",/' | tr -d '\n'
    printf '"SECONDS_PER_SLOT":"12","BLOB_SCHEDULE":['
    awk '/^BLOB_SCHEDULE:/ {on = 1; next} on && /^[^ #-]/ {on = 0}
      on && /EPOCH:/ {e = $NF} on && /MAX_BLOBS_PER_BLOCK:/ {printf "%s{\"EPOCH\":\"%s\",\"MAX_BLOBS_PER_BLOCK\":\"%s\"}", sep, e, $NF; sep = ","}' "$yaml"
    printf ']}}\n'
  } > "$1"
}
real_spec_json "$tmp/real-spec.json"
check_out 0 "spec-diff: the real pinned config against its own answer" \
  '^spec diff: empty \(8 fork versions, 7 fork epochs, 2 blob schedule entries\)' \
  python3 -I -B "$helper" spec-diff "$pinned" "$tmp/real-spec.json"
sed 's/"GLOAS_FORK_EPOCH":"353024"/"GLOAS_FORK_EPOCH":"18446744073709551615"/' "$tmp/real-spec.json" > "$tmp/pre-gloas.json"
check_out 1 "spec-diff: the real pinned config against a pre-Gloas endpoint" \
  '^- GLOAS_FORK_EPOCH: pinned 353024, node 18446744073709551615$' \
  python3 -I -B "$helper" spec-diff "$pinned" "$tmp/pre-gloas.json"
# Hoodi: Gloas at epoch 132352 (2026-10-26 17:42:48 UTC), its own fork versions and schedule.
real_spec_json "$tmp/hoodi-spec.json" "$pinned_hoodi"
check_out 0 "spec-diff: the real pinned Hoodi config against its own answer" \
  '^spec diff: empty \(8 fork versions, 7 fork epochs, 2 blob schedule entries\)' \
  python3 -I -B "$helper" spec-diff "$pinned_hoodi" "$tmp/hoodi-spec.json"
if grep -q '"GLOAS_FORK_EPOCH":"132352"' "$tmp/hoodi-spec.json" && grep -q '"GLOAS_FORK_VERSION":"0x80000910"' "$tmp/hoodi-spec.json"; then
  ok "spec-diff: the Hoodi answer carries GLOAS_FORK_EPOCH 132352 and version 0x80000910"
else
  bad "spec-diff: the Hoodi answer carries GLOAS_FORK_EPOCH 132352" "$(cat "$tmp/hoodi-spec.json")"
fi
# A Hoodi node on a release that does not schedule Gloas (FAR_FUTURE_EPOCH) fails the diff.
sed 's/"GLOAS_FORK_EPOCH":"132352"/"GLOAS_FORK_EPOCH":"18446744073709551615"/' "$tmp/hoodi-spec.json" > "$tmp/hoodi-pre-gloas.json"
check_out 1 "spec-diff: the pinned Hoodi config against a node without Hoodi's Gloas epoch" \
  '^- GLOAS_FORK_EPOCH: pinned 132352, node 18446744073709551615$' \
  python3 -I -B "$helper" spec-diff "$pinned_hoodi" "$tmp/hoodi-pre-gloas.json"
check_out 1 "spec-diff: a Sepolia answer against the Hoodi config fails (the other network)" \
  '^- GENESIS_FORK_VERSION: pinned 0x10000910, node 0x90000069$' \
  python3 -I -B "$helper" spec-diff "$pinned_hoodi" "$tmp/real-spec.json"

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
    python3 -I -B "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/spec.json" "$now"
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
  python3 -I -B "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/spec.json" "$now"
syncing_case 1 'is_syncing "false" (a string) fails' 'is_syncing "false".*: FAIL$' 1000 '"false"'
printf '{"data":{"SECONDS_PER_SLOT":"0"}}\n' > "$tmp/zero-sps.json"
check 2 "syncing: SECONDS_PER_SLOT 0 is an error" \
  python3 -I -B "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/zero-sps.json" "$now"
printf '{"data":{"SLOT_DURATION_MS":"12000"}}\n' > "$tmp/ms-only.json"
check_out 1 "syncing: SLOT_DURATION_MS stands in for a missing SECONDS_PER_SLOT" 'wall-clock slot 1000 ' \
  python3 -I -B "$helper" syncing "$tmp/syncing.json" "$tmp/genesis.json" "$tmp/ms-only.json" "$now"

# finalized_case <expect-exit> <description> <pattern> <finalized slot> <database info JSON>
finalized_case() {
  printf '{"data":{"root":"0xab","canonical":true,"header":{"message":{"slot":"%s","proposer_index":"1"}}}}\n' \
    "$4" > "$tmp/finalized.json"
  printf '%s\n' "$5" > "$tmp/dbinfo.json"
  check_out "$1" "finalized: $2" "$3" python3 -I -B "$helper" finalized "$tmp/finalized.json" "$tmp/dbinfo.json"
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
  check_out "$1" "identity: $2" "$3" python3 -I -B "$helper" identity "$tmp/identity.json" "$4" "${8:-9000}"
}
identity_case 0 "the public address of the identity is used" \
  "^multiaddr: /ip4/34\.89\.10\.7/tcp/9000/p2p/$pid$" '' \
  "[\"/ip4/10.0.0.5/tcp/9000/p2p/$pid\",\"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"]"
identity_case 0 "--public-ip wins over the identity" "^multiaddr: /ip4/198\.51\.100\.9/tcp/9000/p2p/$pid$" \
  198.51.100.9 "[\"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"]"
identity_case 0 "custody_group_count is recorded" '^custody_group_count: 4$' '' "[\"/ip4/34.89.10.7/tcp/9000\"]"
identity_case 0 "the peer ID is recorded" "^peer_id: $pid$" '' "[\"/ip4/34.89.10.7/tcp/9000\"]"
# The multiaddr carries the configured Lighthouse p2p port (the second network's is not 9000).
identity_case 0 "the multiaddr uses the configured p2p TCP port" "^multiaddr: /ip4/34\.89\.10\.7/tcp/9002/p2p/$pid$" '' \
  "[\"/ip4/34.89.10.7/tcp/9002/p2p/$pid\"]" ',"custody_group_count":"4"' '' 9002
check_out 2 "identity: a p2p port that is not a port number is an error" '^ERROR: the p2p port is not a TCP port number$' \
  python3 -I -B "$helper" identity "$tmp/identity.json" '' 90a2
check_out 2 "identity: p2p port 0 is an error" '^ERROR: the p2p port is not a TCP port number$' \
  python3 -I -B "$helper" identity "$tmp/identity.json" '' 0
identity_case 1 "only private addresses and no --public-ip fails" '^error: no public IPv4' '' \
  "[\"/ip4/10.0.0.5/tcp/9000\",\"/ip4/127.0.0.1/tcp/9000\"]"
identity_case 1 "a --public-ip that is not an IPv4 address fails" '^error: --public-ip is not an IPv4 address' 'example.org' '[]'
identity_case 1 "a missing custody_group_count fails" '^error: custody_group_count is missing' '' \
  "[\"/ip4/34.89.10.7/tcp/9000\"]" ''
sed "s/$pid/not-a-peer-id/" "$tmp/identity.json" > "$tmp/bad-identity.json"
check_out 1 "identity: a peer ID that is not base58 fails" '^error: peer_id is not base58 or missing$' \
  python3 -I -B "$helper" identity "$tmp/bad-identity.json" '' 9000
out=$(python3 -I -B "$helper" identity "$tmp/bad-identity.json" '' 9000 2>&1 || true)
if grep -Eq '^(peer_id|custody_group_count|multiaddr): ' <<< "$out"; then
  bad "identity: an error is never printed as a value line" "$out"
else
  ok "identity: an error is never printed as a value line"
fi
check 2 "an unknown helper command is an error" python3 -I -B "$helper" frobnicate

# anchor-compare: provider 1's finalized header against provider 2's header at the same slot.
r1=0x$(printf 'ab%.0s' $(seq 1 32)) r2=0x$(printf 'cd%.0s' $(seq 1 32))
s1=0x$(printf '12%.0s' $(seq 1 32)) s2=0x$(printf '34%.0s' $(seq 1 32))
# header_json <file> <slot> <block root> <state root> [canonical]
header_json() {
  printf '{"execution_optimistic":false,"finalized":true,"data":{"root":"%s","canonical":%s,"header":{"message":{"slot":"%s","proposer_index":"7","parent_root":"0x00","state_root":"%s","body_root":"0x00"},"signature":"0x00"}}}\n' \
    "$3" "${5:-true}" "$2" "$4" > "$1"
}
anchor_case() { # anchor_case <expect-exit> <description> <pattern>
  check_out "$1" "anchor-compare: $2" "$3" python3 -I -B "$helper" anchor-compare "$tmp/anchor-a.json" "$tmp/anchor-b.json"
}
header_json "$tmp/anchor-a.json" 4235264 "$r1" "$s1"
header_json "$tmp/anchor-b.json" 4235264 "$r1" "$s1"
anchor_case 0 "the same slot, block root and state root on both providers pass" \
  "^anchor: slot 4235264, block root $r1, state root $s1, the same on both providers: PASS$"
header_json "$tmp/anchor-b.json" 4235264 "$r2" "$s1"
anchor_case 1 "another block root on provider 2 fails" "^anchor: slot 4235264: block root $r1 on provider 1, $r2 on provider 2: FAIL$"
header_json "$tmp/anchor-b.json" 4235264 "$r1" "$s2"
anchor_case 1 "another state root on provider 2 fails" "^anchor: slot 4235264: state root $s1 on provider 1, $s2 on provider 2: FAIL$"
header_json "$tmp/anchor-b.json" 4235263 "$r1" "$s1"
anchor_case 1 "another slot on provider 2 fails" '^anchor: slot 4235264 on provider 1, 4235263 on provider 2: FAIL$'
header_json "$tmp/anchor-b.json" 4235264 "$r1" "$s1" false
anchor_case 1 "a header provider 2 does not hold canonical fails" '^anchor: slot 4235264: not canonical on provider 2: FAIL$'
header_json "$tmp/anchor-a.json" 4235264 "$r1" "$s1" false
header_json "$tmp/anchor-b.json" 4235264 "$r1" "$s1"
anchor_case 1 "a header provider 1 does not hold canonical fails" '^anchor: slot 4235264: not canonical on provider 1: FAIL$'
header_json "$tmp/anchor-a.json" 4235264 "$r1" "$s1"
header_json "$tmp/anchor-a.json" 4235264 0xab "$s1"
anchor_case 2 "a block root that is not 32 bytes of hex is an error" '^ERROR: provider 1: the header answer has no 32-byte root$'
header_json "$tmp/anchor-a.json" 4235264 "$r1" "$s1"
printf '{"data":{"root":"%s"}}\n' "$r1" > "$tmp/anchor-b.json"
anchor_case 2 "a header without a slot is an error" '^ERROR: provider 2: the header answer has no header.message.slot$'
check_out 0 "header-slot: the slot of a header answer" '^4235264$' python3 -I -B "$helper" header-slot "$tmp/anchor-a.json"
check_out 2 "header-slot: a header without a slot is an error" 'no header.message.slot$' python3 -I -B "$helper" header-slot "$tmp/anchor-b.json"

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

# fetch runs the real curl as root: it must read no ~/.curlrc (a write-out there would print the
# URL, key and all) and go through no proxy from the environment (a proxy would see every URL
# in full, and preflight must reach the endpoint Lighthouse reaches). Against a loopback server.
if command -v curl >/dev/null 2>&1; then
  mkdir -p "$tmp/curlhome" && printf 'write-out = "WROTE %%{url_effective}\\n"\n' > "$tmp/curlhome/.curlrc"
  python3 -I -B -c '
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # /big: 2 MiB with a Content-Length; /bigstream: 2 MiB without one (read to the close).
        body = b"{" + b" " * (2 << 20) + b"}" if self.path.startswith("/big") else b"{}"
        self.send_response(200)
        if self.path != "/bigstream":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a):
        pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()' "$tmp/http.port" &
  http_pid=$!
  for _ in $(seq 1 100); do [[ -s $tmp/http.port ]] && break; sleep 0.1; done
  srv="http://127.0.0.1:$(cat "$tmp/http.port")"
  rc=0; out=$(HOME="$tmp/curlhome" fetch "$srv/eth/KEY555secret" "$tmp/fetched.json" 2>&1) || rc=$?
  if ((rc == 0)) && ! grep -q KEY555secret <<< "$out"; then ok "fetch: ~/.curlrc is not read (no write-out of the URL)"; else bad "fetch: ~/.curlrc is not read (exit $rc)" "$out"; fi
  rc=0; out=$(http_proxy=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
    fetch "$srv/eth/v1/node/syncing" "$tmp/fetched.json" 2>&1) || rc=$?
  if ((rc == 0)); then ok "fetch: no proxy from the environment is used"; else bad "fetch: no proxy from the environment is used (exit $rc)" "$out"; fi
  # No answer the scripts read comes near 1 MiB (/eth/v1/config/spec is about 20 KB), so a
  # larger one is refused and nothing of it is kept, with or without a Content-Length.
  for path in /big /bigstream; do
    printf 'stale' > "$tmp/fetched.json"
    rc=0; fetch "$srv$path" "$tmp/fetched.json" || rc=$?
    if ((rc != 0)) && [[ ! -s $tmp/fetched.json ]]; then ok "fetch: a 2 MiB answer ($path) is refused, nothing kept"; else bad "fetch: a 2 MiB answer ($path) is refused (exit $rc, $(wc -c < "$tmp/fetched.json") bytes kept)"; fi
  done
  # Every stage counts: a head that fails while writing the answer (ENOSPC: the disk under /tmp
  # is full) leaves part of it, which must not pass for the whole answer. A stand-in head writes
  # one byte, then fails as head does on a write error.
  mkdir -p "$tmp/fullhead"
  printf '#!/usr/bin/env bash\n%s -c 1\ncat > /dev/null\necho "head: write error: No space left on device" >&2\nexit 1\n' "$(command -v head)" > "$tmp/fullhead/head"
  chmod +x "$tmp/fullhead/head"
  printf 'stale' > "$tmp/fetched.json"
  rc=0; PATH="$tmp/fullhead:$PATH" fetch "$srv/eth/v1/node/syncing" "$tmp/fetched.json" 2>/dev/null || rc=$?
  if ((rc == 23)) && [[ ! -s $tmp/fetched.json ]]; then ok "fetch: a head that fails to write (ENOSPC) fails the fetch (exit 23), nothing kept"; else bad "fetch: a head that fails to write fails the fetch (exit $rc, want 23; $(wc -c < "$tmp/fetched.json") bytes kept)"; fi
  kill "$http_pid" 2>/dev/null || true
  wait "$http_pid" 2>/dev/null || true
else
  echo "# skip - fetch ignores ~/.curlrc and proxies: no curl"
fi

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
binds_on() { # binds_on <expect-exit> <description> <pattern> <ports> <ss lines...>: other API ports
  local expect=$1 desc=$2 pattern=$3 ports=$4
  shift 4
  # shellcheck disable=SC2086 # $ports is a list of port numbers
  check_out "$expect" "binds: $desc" "$pattern" check_binds "$(printf '%s\n' "$ss_head" "$@")" $ports
}
binds_on 0 "the second network's API ports on 127.0.0.1 pass" '^port 5053: 127\.0\.0\.1 only: PASS$' "8552 5053" \
  "${ss_reth/:8551/:8552}" "${ss_lh/:5052/:5053}"
binds_on 1 "the second network's API port on 0.0.0.0 fails" '^port 5053: listening on 0\.0\.0\.0:5053 .*FAIL$' "8552 5053" \
  "${ss_reth/:8551/:8552}" "${ss_lh/127.0.0.1:5052/0.0.0.0:5053}"

# check_listeners: every TCP listener a container's processes own is on loopback, or on one of
# that service's declared p2p ports; a listener of another process is not its business.
ss_rpc='LISTEN 0      1024         0.0.0.0:8545       0.0.0.0:*    users:(("reth-binary",pid=812,fd=120))'
ss_rpc6='LISTEN 0      1024            [::]:8546          [::]:*    users:(("reth-binary",pid=812,fd=121))'
ss_rp2p='LISTEN 0      1024               *:30303            *:*    users:(("reth-binary",pid=812,fd=30))'
ss_lp2p6='LISTEN 0      1024            [::]:9000          [::]:*    users:(("lighthouse",pid=901,fd=32))'
ss_lmet='LISTEN 0      1024       127.0.0.1:5054       0.0.0.0:*    users:(("lighthouse",pid=901,fd=50))'
ss_lmet6='LISTEN 0      1024           [::1]:5055          [::]:*    users:(("lighthouse",pid=901,fd=51))'
ss_ssh='LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=5,fd=3))'
ss_two='LISTEN 0      1024        10.0.0.5:7000       0.0.0.0:*    users:(("sshd",pid=5,fd=9),("reth-binary",pid=812,fd=99))'
listeners() { # listeners <expect-exit> <description> <pattern> <service> <pids> <ports> <ss lines...>
  local expect=$1 desc=$2 pattern=$3 svc=$4 pids=$5 ports=$6
  shift 6
  check_out "$expect" "listeners: $desc" "$pattern" check_listeners "$(printf '%s\n' "$ss_head" "$@")" "$svc" "$pids" "$ports"
}
listeners 0 "reth: the Engine API on loopback and p2p on * pass" \
  '^reth: no non-loopback TCP listener but p2p port 30303 \(pids 812\): PASS$' reth 812 30303 "$ss_reth" "$ss_rp2p" "$ss_lh" "$ss_ssh"
listeners 0 "reth: the p2p listener is recorded" '^reth: p2p listener \*:30303 \(pid 812\)$' reth 812 30303 "$ss_reth" "$ss_rp2p"
listeners 1 "reth: an HTTP RPC on 0.0.0.0 (an override's --http.addr) fails" \
  '^reth: listener 0\.0\.0\.0:8545 \(pid 812\) is neither on loopback nor a p2p port: FAIL$' reth 812 30303 "$ss_reth" "$ss_rp2p" "$ss_rpc"
listeners 1 "reth: a WS RPC on [::] fails" '^reth: listener \[::\]:8546 \(pid 812\) is neither' reth 812 30303 "$ss_rpc6"
listeners 1 "reth: a socket shared with another process still counts" '^reth: listener 10\.0\.0\.5:7000 \(pid 812\)' reth 812 30303 "$ss_two"
listeners 0 "lighthouse: p2p on [::], metrics on 127.0.0.1 and [::1] pass" '^lighthouse: no non-loopback TCP listener but p2p port 9000 \(pids 901\): PASS$' \
  lighthouse 901 9000 "$ss_lh" "$ss_p2p" "$ss_lp2p6" "$ss_lmet" "$ss_lmet6"
listeners 1 "lighthouse: another service's p2p port is not its own" '^lighthouse: listener \*:30303 \(pid 901\)' \
  lighthouse 901 9000 "${ss_rp2p/pid=812/pid=901}"
listeners 1 "lighthouse: the Beacon API on 0.0.0.0 fails here too" '^lighthouse: listener 0\.0\.0\.0:5052 \(pid 901\)' \
  lighthouse 901 9000 "${ss_lh/127.0.0.1/0.0.0.0}"
# A listener of another pid is not the service's; with none of its own it has no p2p listener.
listeners 1 "pid 81 is not pid 812 (nothing matched, no p2p listener)" '^reth: no p2p listener on port 30303 among pids 81: FAIL$' reth 81 30303 "$ss_rpc" "$ss_rp2p"
listeners 1 "a service whose p2p port has no listener fails" '^reth: no p2p listener on port 30303 among pids 812: FAIL$' reth 812 30303 "$ss_reth"
listeners 1 "an ss without process information fails" '^reth: ss -ltnp shows no process for any listener \(it needs root\): FAIL$' \
  reth 812 30303 "${ss_reth%%users:*}" "${ss_rp2p%%users:*}" "${ss_rpc%%users:*}"
listeners 1 "no container process to match fails" '^reth: no container process to match listeners to: FAIL$' reth '' 30303 "$ss_reth"
listeners 0 "several pids of one container" '^reth: no non-loopback TCP listener but p2p port 30303 \(pids 812 813\): PASS$' \
  reth "812 813" 30303 "${ss_rp2p/pid=812/pid=813}"
# A busy host lists thousands of sockets. The "does ss show processes" test reads all of them:
# a grep -q that stopped at the first one would leave printf writing into a closed pipe, which
# pipefail turned into "ss shows no process" (a false FAIL).
many_ss=$(for i in $(seq 1 4000); do printf 'LISTEN 0      128          0.0.0.0:%s         0.0.0.0:*    users:(("sshd",pid=5,fd=3))\n' $((20000 + i)); done)
listeners 0 "an ss listing of thousands of sockets is read whole (no SIGPIPE)" \
  '^reth: no non-loopback TCP listener but p2p port 30303 \(pids 812\): PASS$' reth 812 30303 "$ss_reth" "$many_ss" "$ss_rp2p"

# The network and its derived names: users, default DATA_ROOT, compose project, pinned config.
for spec in "sepolia reth reth" "sepolia lighthouse lighthouse" "hoodi reth reth-hoodi" "hoodi lighthouse lighthouse-hoodi"; do
  read -r net svc want <<< "$spec"
  got=$(service_user "$net" "$svc")
  if [[ $got == "$want" ]]; then ok "service_user: $net $svc is $want"; else bad "service_user: $net $svc (got '$got', want '$want')"; fi
done
for spec in "sepolia /srv/ethswarm-ref" "hoodi /srv/ethswarm-ref-hoodi"; do
  read -r net want <<< "$spec"
  got=$(default_data_root "$net")
  if [[ $got == "$want" ]]; then ok "default_data_root: $net is $want"; else bad "default_data_root: $net (got '$got', want '$want')"; fi
done
check 0 "network_known: sepolia" network_known sepolia
check 0 "network_known: hoodi" network_known hoodi
check 1 "network_known: mainnet is not a reference network here" network_known mainnet
check 1 "network_known: empty" network_known ''
check 1 "network_known: a path is not a network" network_known ../sepolia
# The two .env examples run side by side: other ports, another DATA_ROOT, and images README.md
# has a row for under each network.
sep_ex="$ref/.env.example" hoodi_ex="$ref/.env.hoodi.example"
check 0 "env examples: Sepolia's ports are valid and distinct" ports_check "$sep_ex"
check 0 "env examples: Hoodi's ports are valid and distinct" ports_check "$hoodi_ex"
clash=''
for k1 in $PORT_KEYS; do for k2 in $PORT_KEYS; do
  if [[ $(env_get "$sep_ex" "$k1") == "$(env_get "$hoodi_ex" "$k2")" ]]; then clash="$clash $k1/$k2"; fi
done; done
if [[ -z $clash ]]; then ok "env examples: no Hoodi port is a Sepolia port"; else bad "env examples: ports clash:$clash"; fi
if [[ $(env_get "$sep_ex" DATA_ROOT) == "$(default_data_root sepolia)" && $(env_get "$hoodi_ex" DATA_ROOT) == "$(default_data_root hoodi)" ]]; then
  ok "env examples: each DATA_ROOT is its network's default, and they differ"
else
  bad "env examples: each DATA_ROOT is its network's default"
fi
for spec in "$sep_ex sepolia" "$hoodi_ex hoodi"; do
  read -r ex net <<< "$spec"
  if [[ $(env_get "$ex" NETWORK) == "$net" ]]; then ok "env examples: ${ex##*/} sets NETWORK=$net"; else bad "env examples: ${ex##*/} sets NETWORK=$net"; fi
  for spec2 in "RETH_IMAGE reth" "LIGHTHOUSE_IMAGE lighthouse"; do
    read -r key client <<< "$spec2"
    row=$(release_row "$ref/README.md" "$net" "$client" "$(env_get "$ex" "$key")")
    if [[ $row == yes\|* || $row == no\|* ]]; then ok "release notes: README.md has a $net row for ${ex##*/} $key ($row)"; else bad "release notes: README.md has a $net row for ${ex##*/} $key (got '$row')"; fi
  done
done
# Hoodi runs exactly the two dev pins whose fork-schedule check README.md records; Sepolia keeps
# its releases, which do not schedule Hoodi's fork, and the dev pins have no Sepolia row.
for spec in "RETH_IMAGE $hoodi_reth" "LIGHTHOUSE_IMAGE $hoodi_lh"; do
  read -r key want <<< "$spec"
  if [[ $(env_get "$hoodi_ex" "$key") == "$want" ]]; then ok "env examples: Hoodi pins $key to the reviewed dev digest"; else bad "env examples: Hoodi $key (got '$(env_get "$hoodi_ex" "$key")', want '$want')"; fi
done
for spec in "RETH_IMAGE $sepolia_reth" "LIGHTHOUSE_IMAGE $sepolia_lh"; do
  read -r key want <<< "$spec"
  if [[ $(env_get "$sep_ex" "$key") == "$want" ]]; then ok "env examples: Sepolia keeps $key on its release pin"; else bad "env examples: Sepolia $key (got '$(env_get "$sep_ex" "$key")', want '$want')"; fi
done
# row_of <network> <client> <image> <want> <description>: release_row's output is exactly <want>.
row_of() {
  local got
  got=$(release_row "$ref/README.md" "$1" "$2" "$3")
  if [[ $got == "$4" ]]; then ok "release notes: $5"; else bad "release notes: $5 (got '$got', want '$4')"; fi
}
row_of hoodi reth "$hoodi_reth" 'yes|n/a (EL)' "the Hoodi reth nightly digest schedules Hoodi's fork"
row_of hoodi lighthouse "$hoodi_lh" 'yes|v1.7.0-beta.4' "the Hoodi Lighthouse unstable digest schedules Hoodi's fork and targets beta.4"
row_of hoodi reth "$sepolia_reth" 'no|n/a (EL)' "reth v2.7.0 does not schedule Hoodi's fork"
row_of hoodi lighthouse "$sepolia_lh" 'no|v1.7.0-beta.2' "Lighthouse v8.3.0-rc.0 does not schedule Hoodi's fork and targets beta.2"
row_of hoodi reth "ghcr.io/paradigmxyz/reth:nightly@sha256:$d64" '' "the nightly tag at another digest has no Hoodi row"
row_of hoodi lighthouse "sigp/lighthouse:latest-unstable@sha256:$d64" '' "the latest-unstable tag at another digest has no Hoodi row"
row_of hoodi lighthouse "sigp/lighthouse:latest@sha256:${hoodi_lh##*sha256:}" '' "the reviewed digest under another tag has no Hoodi row"
# A row counts only for its own client: one image pinned as the other service's (the two pins
# swapped) has no row for that service, and a reviewed digest under the other client's
# repository has no row at all. release_client names the client a row belongs to.
row_of hoodi reth "$hoodi_lh" '' "the Hoodi Lighthouse dev pin has no Hoodi reth row"
row_of hoodi lighthouse "$hoodi_reth" '' "the Hoodi reth dev pin has no Hoodi Lighthouse row"
row_of sepolia reth "$sepolia_lh" '' "the Sepolia Lighthouse release has no Sepolia reth row"
row_of sepolia lighthouse "$sepolia_reth" '' "the Sepolia reth release has no Sepolia Lighthouse row"
row_of hoodi reth "sigp/lighthouse:nightly@sha256:${hoodi_reth##*sha256:}" '' "reth's reviewed digest under Lighthouse's repository has no Hoodi row"
row_of hoodi lighthouse "ghcr.io/paradigmxyz/reth:latest-unstable@sha256:${hoodi_lh##*sha256:}" '' "Lighthouse's reviewed digest under reth's repository has no Hoodi row"
for spec in "hoodi $hoodi_reth reth" "hoodi $hoodi_lh lighthouse" "sepolia $sepolia_reth reth" "sepolia $sepolia_lh lighthouse" "sepolia $hoodi_lh -"; do
  read -r net image want <<< "$spec"
  if [[ $want == - ]]; then want=''; fi
  got=$(release_client "$ref/README.md" "$net" "$image")
  if [[ $got == "$want" ]]; then ok "release notes: $net row of ${image%@*} is ${want:-nobody}'s"; else bad "release notes: $net row of ${image%@*} (got '$got', want '$want')"; fi
done
# Every row of both tables names its client, and each client's images come from its own
# repository (repo_check, the rule both scripts apply), so the Client column cannot vouch for
# the other client's image.
for net in sepolia hoodi; do
  rows=$(release_notes "$ref/README.md" "$net" | awk -F '|' 'NR > 2 { gsub(/[ \t`]/, "", $2); gsub(/[ \t]/, "", $3); print $3, $2 }')
  wrong=$(while read -r client image; do repo_check "$net row" "$client" "$image" || true; done <<< "$rows")
  if [[ -n $rows && -z $wrong ]]; then ok "release notes: every $net row's client owns its image's repository"; else bad "release notes: $net rows whose client and repository differ" "${wrong:-(no rows)}"; fi
done
# repo_check <variable> <service> <image>: the image's repository, everything before the tag's
# ':' or the '@', is exactly the service's own (lib/common.sh service_repo). The scripts check
# it before they look up a row, so a hand-edited README.md row naming another client, or a
# lookalike repository, never vouches for an image.
for spec in "RETH_IMAGE reth $hoodi_reth" "RETH_IMAGE reth $sepolia_reth" \
  "LIGHTHOUSE_IMAGE lighthouse $hoodi_lh" "LIGHTHOUSE_IMAGE lighthouse $sepolia_lh"; do
  read -r key svc image <<< "$spec"
  check_out 0 "repo_check: $key ${image%@*} is from $svc's own repository" '^$' repo_check "$key" "$svc" "$image"
done
# repo_refused <service> <image> <its repository>: repo_check refuses it, naming the variable,
# the repository it wants and the one the image has.
repo_refused() {
  local key want got rc=0
  if [[ $1 == reth ]]; then key=RETH_IMAGE want=ghcr.io/paradigmxyz/reth; else key=LIGHTHOUSE_IMAGE want=sigp/lighthouse; fi
  got=$(repo_check "$key" "$1" "$2") || rc=$?
  if ((rc == 1)) && [[ $got == "$key: repository $3 is not $1's (want $want)" ]]; then
    ok "repo_check: $key $3 is refused"
  else
    bad "repo_check: $key $3 is refused (exit $rc, got '$got')"
  fi
}
hr=${hoodi_reth##*@} hl=${hoodi_lh##*@}
repo_refused lighthouse "$hoodi_reth" ghcr.io/paradigmxyz/reth
repo_refused lighthouse "$sepolia_reth" ghcr.io/paradigmxyz/reth
repo_refused reth "$hoodi_lh" sigp/lighthouse
repo_refused reth "$sepolia_lh" sigp/lighthouse
repo_refused reth "ghcr.io/paradigmxyz/reth-evil:nightly@$hr" ghcr.io/paradigmxyz/reth-evil
repo_refused reth "ghcr.io/paradigmxyz/reth/evil:nightly@$hr" ghcr.io/paradigmxyz/reth/evil
repo_refused reth "ghcr.io/paradigmxyz/rethx:nightly@$hr" ghcr.io/paradigmxyz/rethx
repo_refused reth "xghcr.io/paradigmxyz/reth:nightly@$hr" xghcr.io/paradigmxyz/reth
repo_refused reth "paradigmxyz/reth:nightly@$hr" paradigmxyz/reth
repo_refused reth "ghcr.io:443/paradigmxyz/reth:nightly@$hr" ghcr.io:443/paradigmxyz/reth
repo_refused lighthouse "sigp/lighthouse2:latest-unstable@$hl" sigp/lighthouse2
repo_refused lighthouse "sigp/lighthouse-evil:latest-unstable@$hl" sigp/lighthouse-evil
repo_refused lighthouse "docker.io/sigp/lighthouse:latest-unstable@$hl" docker.io/sigp/lighthouse
repo_refused lighthouse "ghcr.io/sigp/lighthouse:latest-unstable@$hl" ghcr.io/sigp/lighthouse
repo_refused lighthouse "localhost:5000/sigp/lighthouse:latest-unstable@$hl" localhost:5000/sigp/lighthouse
check_out 1 "repo_check: a service of no known repository is refused" '^NETHERMIND_IMAGE: nethermind has no known image repository$' \
  repo_check NETHERMIND_IMAGE nethermind "nethermind/nethermind:1.0@$hr"
# A copy of the stack whose README.md was edited by hand: rows whose Client cell names the other
# client for a reviewed image, rows for lookalike repositories, and a row for a reth-repository
# image under the lighthouse client. release_row alone would vouch for each of them.
edited_ref="$tmp/edited-copy/ops/ref-node"
mkdir -p "$tmp/edited-copy/ops" && cp -R "$ref" "$edited_ref" && ln -s "$repo/crates" "$tmp/edited-copy/crates"
rm -rf "$edited_ref/lib/__pycache__"
edited_row() { printf '| `%s` | %s | hand-edited | yes | %s | hand-edited row |\n' "$1" "$2" "$3"; }
{
  edited_row "$hoodi_reth" lighthouse v1.7.0-beta.4
  edited_row "$hoodi_lh" reth 'n/a (EL)'
  edited_row "ghcr.io/paradigmxyz/reth-evil:nightly@$hr" reth 'n/a (EL)'
  edited_row "sigp/lighthouse2:latest-unstable@$hl" lighthouse v1.7.0-beta.4
  edited_row "docker.io/sigp/lighthouse:latest-unstable@$hl" lighthouse v1.7.0-beta.4
  edited_row "ghcr.io/paradigmxyz/reth:edited@sha256:$d64" lighthouse v1.7.0-beta.4
} > "$tmp/edited-hoodi.rows"
{
  edited_row "$sepolia_reth" lighthouse v1.7.0-beta.2
  edited_row "$sepolia_lh" reth 'n/a (EL)'
} > "$tmp/edited-sepolia.rows"
EDIT_DIR=$tmp awk '
  $0 == "<!-- release-notes:hoodi:end -->" { f = ENVIRON["EDIT_DIR"] "/edited-hoodi.rows"; while ((getline l < f) > 0) print l }
  $0 == "<!-- release-notes:sepolia:end -->" { f = ENVIRON["EDIT_DIR"] "/edited-sepolia.rows"; while ((getline l < f) > 0) print l }
  { print }' "$ref/README.md" > "$edited_ref/README.md"
for spec in "hoodi lighthouse $hoodi_reth" "hoodi reth $hoodi_lh" "hoodi reth ghcr.io/paradigmxyz/reth-evil:nightly@$hr" \
  "hoodi lighthouse sigp/lighthouse2:latest-unstable@$hl" "hoodi lighthouse docker.io/sigp/lighthouse:latest-unstable@$hl" \
  "sepolia lighthouse $sepolia_reth" "sepolia reth $sepolia_lh"; do
  read -r net svc image <<< "$spec"
  got=$(release_row "$edited_ref/README.md" "$net" "$svc" "$image")
  if [[ $got == yes\|* ]]; then ok "release notes: the hand-edited README vouches for $svc ${image%@*} on $net"; else bad "release notes: the hand-edited $net row for $svc ${image%@*} (got '$got')"; fi
done
# README.md records, for the dev pins, where each digest was built from and how to leave them.
for spec in "e667968725ff553f65dfecf161e63f6eab96fcc2|the reth nightly source commit" \
  "c8ddac7b79d49812283873eb6625149ef0d27f95|the Lighthouse unstable source commit" \
  "https://blog.ethereum.org/en/2026/10/16/glamsterdam-hoodi-announcement|the EF Hoodi announcement" \
  "<!-- repin-to-releases:begin -->|the repin-to-releases checklist"; do
  if grep -qF -- "${spec%%|*}" "$ref/README.md"; then ok "README: records ${spec#*|}"; else bad "README: records ${spec#*|} (no '${spec%%|*}')"; fi
done
row_of sepolia reth "$hoodi_reth" '' "the Hoodi dev pins have no Sepolia row"
row_of sepolia lighthouse "$hoodi_lh" '' "the Hoodi Lighthouse dev pin has no Sepolia row"
check_out 0 "release notes: a row is matched by image digest, not by tag" '^$' \
  release_row "$ref/README.md" sepolia lighthouse "sigp/lighthouse:v8.3.0-rc.0@sha256:$d64"
# release_row reads the whole table: an awk that stopped at the first match would leave the
# one printing the table writing into a closed pipe, which pipefail turns into exit 141 (a false
# preflight FAIL). A long table with the row first makes that certain rather than rare.
{
  echo '<!-- release-notes:hoodi:begin -->'
  echo '| Image | Client | Release | Schedules | consensus-specs | Line |'
  echo "| \`ghcr.io/x/reth:v1@sha256:$d64\` | reth | v1 | yes | n/a | first |"
  for i in $(seq 1 3000); do echo "| \`ghcr.io/x/other:v$i@sha256:$d64\` | reth | v$i | no | n/a | padding padding padding padding |"; done
  echo '<!-- release-notes:hoodi:end -->'
} > "$tmp/long-readme.md"
sed "3 { p; s/| yes |/| no |/; }" "$tmp/long-readme.md" > "$tmp/twice-readme.md"
# row_is <description> <README> <want>: release_row's exit code is 0 and its output exactly <want>.
row_is() {
  local rc=0 got
  got=$(release_row "$2" hoodi reth "ghcr.io/x/reth:v1@sha256:$d64") || rc=$?
  if ((rc == 0)) && [[ $got == "$3" ]]; then ok "release notes: $1"; else bad "release notes: $1 (exit $rc, got '$got')"; fi
}
row_is "a row early in a long table is read under pipefail (no SIGPIPE)" "$tmp/long-readme.md" 'yes|n/a'
row_is "of two rows for one image, only the first counts" "$tmp/twice-readme.md" 'yes|n/a'
# README.md's migration note: a Sepolia .env from ops/sepolia-ref has no NETWORK, no
# CHECKPOINT_SYNC_URL_2 and no port keys. The lines it lists turn such a file into one with every
# key of .env.example, at .env.example's values, that the scripts accept.
old_env="$tmp/sepolia-ref.env" migrated="$tmp/migrated.env"
grep -Ev "^(NETWORK|CHECKPOINT_SYNC_URL_2|${PORT_KEYS// /|})=" "$sep_ex" > "$old_env"
awk '$0 == "<!-- migration:sepolia-ref:end -->" { on = 0 } on && /^[A-Z_][A-Z0-9_]*=/ { print } $0 == "<!-- migration:sepolia-ref:begin -->" { on = 1 }' \
  "$ref/README.md" > "$tmp/migration.lines"
cat "$old_env" "$tmp/migration.lines" > "$migrated"
keys_of() { sed -n 's/^\([A-Z_][A-Z0-9_]*\)=.*/\1/p' "$1" | sort; }
check 1 "migration: an ops/sepolia-ref .env has no NETWORK the scripts know" network_known "$(env_get "$old_env" NETWORK)"
if [[ -s $tmp/migration.lines ]] && [[ $(keys_of "$migrated") == "$(keys_of "$sep_ex")" ]]; then
  ok "migration: README.md's lines add every missing key of .env.example"
else
  bad "migration: README.md's lines add every missing key of .env.example" "$(cat "$tmp/migration.lines")"
fi
mismatch=''
while IFS= read -r key; do
  if [[ $(env_get "$migrated" "$key") != "$(env_get "$sep_ex" "$key")" ]]; then mismatch="$mismatch $key"; fi
done < <(keys_of "$tmp/migration.lines")
if [[ -z $mismatch ]]; then ok "migration: README.md's lines carry .env.example's Sepolia values"; else bad "migration: values differ from .env.example:$mismatch"; fi
check 0 "migration: the migrated .env reads as compose reads it" env_check "$migrated"
check 0 "migration: the migrated .env has valid, distinct ports" ports_check "$migrated"
for spec in "sepolia 1" "hoodi 2"; do
  read -r net want <<< "$spec"
  got=$(required_providers "$net")
  if [[ $got == "$want" ]]; then ok "required_providers: $net needs $want"; else bad "required_providers: $net (got '$got', want '$want')"; fi
done

# README.md's session run (steps 10 and 11, between the session-run markers) is the evidence
# procedure, so the lint does not parse shell or Markdown: it fails closed on any change. Every
# line of the block, blank lines included, must equal the expected list below, in order,
# indentation included. Not only the lines that name a command: emphasis (s*s*h), a link
# ([ss](#x)h) or a zero-width character can split a command word, and a new command need not
# be one of a list. So a new line wrap fails too: change the list with it. Each `got:` line
# names its README line. Placeholders such as <ref-host> and <BEACON_API_PORT> stay literal in
# both. A fence, an HTML comment, a tab, an indented code line, a code span that crosses a line
# break, a backslash (an escape such as m2a\-session), an HTML entity (&#45;) or inline HTML
# outside a code span (s<b></b>sh) fails too, with its own message. The evidence must name each
# value, step 10.6 must say what to do when ssh exits, and step 10.8 what to do when the tunnel
# stopped during the probe.
session_run_expected="$tmp/session-run.expected"
cat > "$session_run_expected" <<'EXPECTED'
10. **Run the session** on the test host (Sepolia):
    1. Replace `/etc/ethswarm/m2a-session.toml` of step 7 with the TOML block of the run log's
       "m2a-session config" section. Keep it owned by root with mode 0644. The probe needs the
       `reference_api_url` of that block.
    2. In the checkout at the commit of the fuzz gates, record the commit and the tree, then
       build and install the binary. Keep the output:
       - `git rev-parse HEAD`.
       - `git status --porcelain --untracked-files=no`. The output must be empty.
       - `git status --porcelain --ignored -- Cargo.toml Cargo.lock rust-toolchain.toml .cargo crates proto`.
         The output must be empty. This check also shows the untracked and ignored files that
         the build can read, for example a `.cargo/config.toml` or a `*.profraw` file.
       - `rustc -vV`. Its `release` must be the `channel` of `rust-toolchain.toml`.
       - `rustup which rustc`. The output must be the `bin/rustc` of the toolchain directory
         `<channel>-<host>` in the rustup home, with the `host` of `rustc -vV`. A build with
         another compiler is not clean.
       - `env | grep -E '^(((CC|CXX|AR|ARFLAGS|CFLAGS|CXXFLAGS)(_[^=]*)?|(TARGET|HOST)_[^=]*|CRATE_CC_[^=]*|PROTOC[^=]*|RUSTC[^=]*|RUSTFLAGS|RUSTUP_TOOLCHAIN|CARGO_BUILD_[^=]*|CARGO_TARGET_[^=]*|CARGO_PROFILE_[^=]*|CARGO_UNSTABLE_[^=]*|CARGO_ENCODED_RUSTFLAGS)=|CARGO_INCREMENTAL=1$)'`.
         The output must be empty. These variables change the compiler, its flags, the linker,
         the cargo profile, the unstable features of cargo, or the C and proto builds.
         `RUSTC_BOOTSTRAP` turns on the unstable features of a stable toolchain.
         `CARGO_INCREMENTAL=1` changes the code generation, but `CARGO_INCREMENTAL=0` does not.
         The command also shows `CARGO_TARGET_DIR` and `CARGO_BUILD_JOBS`. `CARGO_TARGET_DIR`
         puts the binary in another directory, but the install step reads `target/release`.
         `CARGO_BUILD_JOBS` does not change the binary. If the output is not empty, unset each
         variable that it shows. Then run the command again.
       - `d=$(pwd -P); while :; do ls -d "$d"/.cargo/config "$d"/.cargo/config.toml 2>/dev/null; [ "$d" = / ] && break; d=$(dirname "$d"); done; ls -d "${CARGO_HOME:-$HOME/.cargo}"/config "${CARGO_HOME:-$HOME/.cargo}"/config.toml 2>/dev/null`.
         The output must be empty. A cargo config in `$CARGO_HOME` or in a parent `.cargo` can
         change the build, and the build tree does not show it. Cargo looks in the parents of
         the physical directory, so the search starts at `pwd -P`.
       - `cargo build --release --locked -p cl-p2p --bin m2a-session`.
       - After the build, run the three `git` commands above again. The commit must be equal
         to the commit before the build, and the two `git status` outputs must be empty. The
         build reads the tree while it compiles, and a file can change before that time.
       - `sudo install -o root -g root -m 0755 /dev/stdin /usr/local/bin/m2a-session < target/release/m2a-session`.
       - `fuzz/check-gate1.sh fuzz/artifacts/gate1.json`. The check must pass.
    3. Install the m2a gate file from stdin, so that root does not follow a symlink in the
       checkout. Then, in the checkout, check the installed copy. Keep the output:
       - `sudo install -o root -g root -m 0644 /dev/stdin /etc/ethswarm/m2a-gate.json < fuzz/artifacts/m2a-gate.json`.
       - `fuzz/check-m2a-gate.sh /etc/ethswarm/m2a-gate.json`. The check must pass.

       If a gate check of step 10.2 or 10.3 fails, run that gate again at the commit of the
       checkout (`fuzz/run-gate1.sh` or `fuzz/run-m2a-gate.sh`).
    4. In the checkout, record the binary and the gate files. Keep the output:
       - `sha256sum target/release/m2a-session /usr/local/bin/m2a-session fuzz/artifacts/m2a-gate.json /etc/ethswarm/m2a-gate.json fuzz/artifacts/gate1.json`.
         The two hashes of the binary must be equal. The two hashes of the m2a gate file must
         be equal.
       - `sudo stat /usr/local/bin/m2a-session /etc/ethswarm /etc/ethswarm/m2a-gate.json`.
    5. Do a connection pre-check: `sudo -u m2a-session m2a-session --dial-only`. This mode dials
       the pinned peer, checks its peer ID and disconnects. It does not check the fuzz gate, and
       it writes no `m2a-summary` line. Thus its output is not evidence. If it does not exit 0,
       read the error on stderr and correct the cause before you continue.
    6. **Warning:** Stop the tunnel at step 10.8, also if step 10.7 fails. While the tunnel is
       open, every local account on the test host can use the beacon API of the reference node.

       Open the tunnel to the reference API with the line of the TOML block:
       `ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:<BEACON_API_PORT>:127.0.0.1:<BEACON_API_PORT> <ref-host>`.
       The forward listens on loopback only. `ssh -f` goes to the background only after the
       forward listens, so a host-key or passphrase prompt does not leave the port free. If
       another process holds the port, `ssh` exits with an error.
       If `ssh -f` does not exit 0, do not do step 10.7. A local account that holds the port
       can then give false reference values to the probe.

       After `ssh -f` returns, record the PID of the tunnel. Keep the output:
       `pgrep -u "$(id -u)" -f '^ssh .*-L 127[.]0[.]0[.]1:<BEACON_API_PORT>:'`. It must print one PID.
    7. Go to a directory outside the checkout (`cd ~`), so that the session file does not
       change the tree. Then run the Status probe, which gives the evidence:
       `sudo -u m2a-session m2a-session --gate-file /etc/ethswarm/m2a-gate.json > session-$(date -u +%Y%m%dT%H%M%SZ).jsonl`.
       The probe refuses to dial if the gate file does not pass for the decoders of the binary,
       or if the build of the binary was not clean.
       It writes one JSON line for each step on stdout, and the `m2a-summary` line last. The
       exit code is 0 only if every check passed.
    8. Immediately after step 10.7, run the `pgrep` command of step 10.6 again. Keep the
       output. It must print the same PID as in step 10.6. If it does not, the tunnel stopped
       during step 10.7, and another local account can have answered the probe on the free
       port. Then do not post the session file of step 10.7 as evidence.

       Then stop the tunnel with the PID of step 10.6: `kill <PID>`.
11. **Post the session evidence** on the issue:
    - The m2a and gate-1 gate files, and the output of steps 10.2, 10.3, 10.4, 10.6 and 10.8.
    - The output of `ls -l session-*.jsonl` and `grep -H m2a-summary session-*.jsonl` in the
      directory of step 10.7. Post every session file and every summary line, not only one
      passing line.
    - The `m2a-summary` line of the probe run of step 10.7. Below, `key: value` gives a JSON
      field of the line, and a pass for a check means that `checks.<check>.pass` is `true`. The
      line must show:
      - `pass: true` and `exit_code: 0`.
      - `test_build: false`, and a pass for `production_build`.
      - A `build_commit` equal to the `git rev-parse HEAD` output of step 10.2,
        `build_dirty: false`, and a pass for `clean_build`.
      - A `build_rustc_commit` equal to the `commit-hash` of the `rustc -vV` output of step 10.2.
      - A pass for `fuzz_gate`.
      - `os_user: "m2a-session"`, a non-zero `euid`, and a pass for `own_os_user`.
      - A `peer_id` equal to the peer ID of the pinned multiaddr. Also a pass for
        `pinned_peer_only`, with the detail
        `connected to 1 peer(s), 0 not pinned; 0 listen address(es)`.
    - The output of `collect-run-log.sh`, that is the run log of step 8.
    - The output of `id m2a-session` on the test host.
    - The output of `sudo stat /var/lib/m2a-session/node.key /etc/ethswarm/m2a-session.toml` on
      the test host. The key must be owned by `m2a-session` with mode 0600. The config must be
      owned by root with mode 0644.
EXPECTED
# The tunnel line of step 10.6.
tunnel_span='`ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:<BEACON_API_PORT>:127.0.0.1:<BEACON_API_PORT> <ref-host>`'
# session_run_lint <README>: prints each problem, exit 1 if there is one.
session_run_lint() {
  local readme=$1 n_begin n_end at_begin at_end text want rc=0
  n_begin=$(grep -c -x -- '<!-- session-run:begin -->' "$readme" || true)
  n_end=$(grep -c -x -- '<!-- session-run:end -->' "$readme" || true)
  if [[ $n_begin != 1 || $n_end != 1 ]]; then
    echo "want one session-run begin and one end marker (got $n_begin and $n_end)"
    return 1
  fi
  at_begin=$(grep -n -x -- '<!-- session-run:begin -->' "$readme" | cut -d: -f1)
  at_end=$(grep -n -x -- '<!-- session-run:end -->' "$readme" | cut -d: -f1)
  if ((at_end <= at_begin)); then echo "the session-run end marker is not after its begin marker"; return 1; fi
  # The form of the block: no fence, HTML comment, tab, backslash or HTML entity; no line
  # indented four or more past the content of its list item (an indented code block); no code
  # span that crosses a line break; no inline HTML outside a code span.
  awk -v b="$at_begin" -v e="$at_end" '
    NR <= b || NR >= e { next }
    {
      line = $0
      if (line ~ /\t/) { print "line " NR ": a tab"; bad = 1 }
      if (line ~ /^[ ]*(```|~~~)/) { print "line " NR ": a fence"; bad = 1 }
      if (line ~ /<!--|-->/) { print "line " NR ": an HTML comment"; bad = 1 }
      if (line ~ /\\/) { print "line " NR ": a backslash"; bad = 1 }
      if (line ~ /&(#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);/) { print "line " NR ": an HTML entity"; bad = 1 }
      ticks_before = ticks
      ticks += gsub(/`/, "`", line)
      if (ticks_before % 2 || ticks % 2) { print "line " NR ": a code span crosses a line break"; bad = 1 }
      else {
        prose = $0
        gsub(/`[^`]*`/, "", prose)
        if (prose ~ /<[A-Za-z\/!?]/) { print "line " NR ": inline HTML"; bad = 1 }
      }
      if (line ~ /^[ ]*$/) next
      match(line, /^ */); ind = RLENGTH
      if (ind >= content + 4) { print "line " NR ": an indented code line"; bad = 1 }
      if (match(line, /^ *([0-9]+\.|[-*+]) +/)) content = RLENGTH
    }
    END { if (ticks % 2) { print "an unclosed code span"; bad = 1 } exit bad }
  ' "$readme" || rc=1
  # Each line of the block with its README line number, then the lines alone.
  awk -v b="$at_begin" -v e="$at_end" 'NR > b && NR < e { print NR "\t" $0 }' "$readme" > "$tmp/session-run.numbered"
  cut -f2- "$tmp/session-run.numbered" > "$tmp/session-run.got"
  if ! diff "$session_run_expected" "$tmp/session-run.got" > "$tmp/session-run.diff"; then
    echo "the session-run commands differ from the expected list:"
    # A diff hunk header ("4a5,6", "7c7", "9d8") gives the first line of the got side.
    # FILENAME, not NR == FNR: with an empty block the first file has no line.
    awk 'FILENAME == ARGV[1] { n = $0; sub(/\t.*/, "", n); at_line[FNR] = n; next }
      /^[0-9]/ { r = $0; sub(/^[0-9,]*[acd]/, "", r); split(r, a, ","); at = a[1] + 0; next }
      /^< / { print "want: " substr($0, 3); next }
      /^> / { print "got:  line " at_line[at] ": " substr($0, 3); at++ }' \
      "$tmp/session-run.numbered" "$tmp/session-run.diff"
    rc=1
  fi
  text=$(awk -v b="$at_begin" -v e="$at_end" 'NR > b && NR < e { sub(/^[ ]+/, ""); printf "%s ", $0 }' "$readme")
  for want in 'writes no `m2a-summary` line' '`pass: true`' '`exit_code: 0`' '`test_build: false`' \
    '`production_build`' '`build_commit`' '`build_dirty: false`' '`clean_build`' '`fuzz_gate`' '`euid`' \
    '`pinned_peer_only`' '`connected to 1 peer(s), 0 not pinned; 0 listen address(es)`' '`collect-run-log.sh`' \
    '`build_rustc_commit`' 'If `ssh -f` does not exit 0, do not do step 10.7.' \
    "$tunnel_span" '`kill <PID>`' '`rustup which rustc`' '`CARGO_TARGET_DIR`' '`CARGO_BUILD_JOBS`' \
    'Then do not post the session file of step 10.7 as evidence.'; do
    if [[ $text != *"$want"* ]]; then echo "the evidence does not name $want"; rc=1; fi
  done
  return $rc
}
check 0 "session run: README.md holds exactly the expected session-run commands" session_run_lint "$ref/README.md"
# build_env_refused <README> <name>...: the `env | grep -E` of step 10.2 prints NAME=1 for each
# name, or the line itself for a NAME=VALUE. Prints each one that it does not print, exit 1 if
# there is one.
build_env_refused() {
  local readme=$1 line re name rc=0
  shift
  line=$(grep -F -- "- \`env | grep -E '" "$readme" || true)
  re=${line#*"env | grep -E '"}
  re=${re%%"'"*}
  if [[ -z $line || -z $re ]]; then echo "no env | grep -E of step 10.2"; return 1; fi
  for name in "$@"; do
    [[ $name == *=* ]] || name+="=1"
    if ! grep -E -- "$re" <<< "$name" > /dev/null; then echo "not refused: $name"; rc=1; fi
  done
  return $rc
}
# The variables that make the build unclean (crates/cl-p2p/build_support.rs): each one that the
# build script reads, and the cargo profile and unstable variables. Also CARGO_TARGET_DIR (the
# install step reads target/release) and CARGO_BUILD_JOBS, which step 10.2 names.
build_vars=(RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTC_LINKER
  RUSTC CARGO_BUILD_RUSTC RUSTUP_TOOLCHAIN CARGO_BUILD_RUSTC_WRAPPER
  CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
  CARGO_PROFILE_RELEASE_OPT_LEVEL CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS CARGO_PROFILE_RELEASE_PANIC
  CARGO_UNSTABLE_BUILD_STD CC CFLAGS_x86_64-unknown-linux-gnu TARGET_CC HOST_CXXFLAGS ARFLAGS
  CRATE_CC_NO_DEFAULTS PROTOC CARGO_TARGET_DIR CARGO_BUILD_JOBS RUSTC_BOOTSTRAP CARGO_INCREMENTAL=1)
check 0 "session run: step 10.2 refuses every variable that makes the build unclean" \
  build_env_refused "$ref/README.md" "${build_vars[@]}"
check_out 1 "session run: a harmless variable is not refused" '^not refused: CARGO_HOME=1$' \
  build_env_refused "$ref/README.md" CARGO_HOME
check_out 1 "session run: CARGO_INCREMENTAL=0 is not refused" '^not refused: CARGO_INCREMENTAL=0$' \
  build_env_refused "$ref/README.md" CARGO_INCREMENTAL=0
check_out 1 "session run: CARGO_INCREMENTAL=10 is not refused (cargo reads only 1 as on)" \
  '^not refused: CARGO_INCREMENTAL=10$' build_env_refused "$ref/README.md" CARGO_INCREMENTAL=10
sed 's/|CARGO_PROFILE_\[^=\]\*//' "$ref/README.md" > "$tmp/no-profile-readme.md"
check_out 1 "session run: a step 10.2 without CARGO_PROFILE_ fails" '^not refused: CARGO_PROFILE_RELEASE_OPT_LEVEL=1$' \
  build_env_refused "$tmp/no-profile-readme.md" "${build_vars[@]}"
# lint_readme <description> <pattern> <sed script>: a copy of README.md edited by the script fails
# the lint with a line that matches the pattern.
lint_readme() {
  sed "$3" "$ref/README.md" > "$tmp/session-readme.md"
  check_out 1 "session run: $1" "$2" session_run_lint "$tmp/session-readme.md"
}
gate_path=/etc/ethswarm/m2a-gate.json
dial_span='`sudo -u m2a-session m2a-session --dial-only`'
probe_span='`sudo -u m2a-session m2a-session --gate-file '"$gate_path"' > session-$(date -u +%Y%m%dT%H%M%SZ).jsonl`'
nl=$'\\\n'   # a line break in a sed replacement
# The probe run and the pre-check.
lint_readme "a probe run without --gate-file fails" '^got: .*m2a-session m2a-session > session-' \
  "s|m2a-session --gate-file $gate_path >|m2a-session >|"
lint_readme "--gate-file without a value fails" '^got: .*--gate-file > session-' \
  "s|--gate-file $gate_path >|--gate-file >|"
lint_readme "a flag the binary does not take fails" '^got: .*m2a-session --gate /etc' \
  "s|--gate-file $gate_path|--gate $gate_path|"
lint_readme "no probe run fails" '^want: .*--gate-file /etc/ethswarm/m2a-gate\.json > session-' \
  '/m2a-session --gate-file/d'
lint_readme "no --dial-only pre-check fails" '^got: .*m2a-session --print-peer-id`' \
  "s|$dial_span|\`sudo -u m2a-session m2a-session --print-peer-id\`|"
lint_readme "the modes of the pre-check and the probe swapped fail" '^got: .*m2a-session --dial-only > session-' \
  "s|m2a-session --dial-only\`|m2a-session --gate-file $gate_path\`|; s|m2a-session --gate-file $gate_path >|m2a-session --dial-only >|"
lint_readme "a probe run before the pre-check fails" '^got: .*pre-check: `sudo -u m2a-session m2a-session --gate-file' \
  "s|$dial_span|DIAL|; s|$probe_span|$dial_span|; s|DIAL|$probe_span|"
lint_readme "a --gate-file other than the installed copy fails" '^got: .*--gate-file /tmp/m2a-gate\.json' \
  "s|--gate-file $gate_path|--gate-file /tmp/m2a-gate.json|"
lint_readme "a repeated --dial-only fails" '^got: .*--dial-only --dial-only`' \
  "s|m2a-session --dial-only\`|m2a-session --dial-only --dial-only\`|"
lint_readme "--print-peer-id --dial-only fails" '^got: .*--print-peer-id --dial-only`' \
  "s|m2a-session --dial-only\`|m2a-session --print-peer-id --dial-only\`|"
lint_readme "a timeout that is not a number fails" '^got: .*--connect-timeout-secs x`' \
  "s|m2a-session --dial-only\`|m2a-session --dial-only --connect-timeout-secs x\`|"
lint_readme "an m2a-session invocation by its path fails" '^got: .*`/usr/local/bin/m2a-session --listen x`' \
  's|read the error on stderr|run `/usr/local/bin/m2a-session --listen x` and read the error on stderr|'
lint_readme "a command chained after m2a-session fails" '^got: .*--dial-only && --listen x`' \
  "s|m2a-session --dial-only\`|m2a-session --dial-only \\&\\& --listen x\`|"
lint_readme "a command split over two lines fails" 'a code span crosses a line break$' \
  "s|m2a-session --dial-only\`|m2a-session${nl}       --dial-only --bogus\`|"
# Commands that are not in an inline code span, or that run under another command.
lint_readme "a command in plain text fails" '^got:  line [0-9]+: +sudo -u m2a-session m2a-session --listen x$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1sudo -u m2a-session m2a-session --listen x|"
lint_readme "a command under timeout fails" '^got: .*`timeout 60 sudo -u m2a-session m2a-session --dial-only`' \
  "s|$dial_span|\`timeout 60 sudo -u m2a-session m2a-session --dial-only\`|"
lint_readme "a command in a subshell fails" '^got: .*`\(sudo -u m2a-session m2a-session --dial-only\)`' \
  "s|$dial_span|\`(sudo -u m2a-session m2a-session --dial-only)\`|"
lint_readme "a command in a command substitution fails" '^got: .*`echo \$\(sudo -u m2a-session m2a-session --dial-only\)`' \
  "s|$dial_span|\`echo \$(sudo -u m2a-session m2a-session --dial-only)\`|"
lint_readme "a code span from the line before into the probe fails" 'a code span crosses a line break$' \
  's|change the tree. Then run the Status probe, which gives the evidence:|change the tree. Then run `timeout 9|'
lint_readme "a fence fails" ': a fence$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}${nl}\1\`\`\`sh${nl}\1true${nl}\1\`\`\`|"
lint_readme "an HTML comment fails" ': an HTML comment$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1<!-- true -->|"
lint_readme "an indented code line fails" ': an indented code line$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}${nl}\1    true|"
lint_readme "a tab fails" ': a tab$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1	true|"
# The install source, owner and mode, the order of the steps and the session user.
lint_readme "a gate file copied by root through a path fails" '^got: .*-m 0644 fuzz/artifacts/m2a-gate\.json /etc/ethswarm/m2a-gate\.json`' \
  "s|/dev/stdin $gate_path < fuzz/artifacts/m2a-gate.json|fuzz/artifacts/m2a-gate.json $gate_path|"
lint_readme "a gate file owned by the session user fails" '^got: .*install -o m2a-session -g root -m 0644 /dev/stdin /etc' \
  "s|install -o root -g root -m 0644|install -o m2a-session -g root -m 0644|"
lint_readme "a gate file of mode 0666 fails" '^got: .*install -o root -g root -m 0666 /dev/stdin /etc' \
  "s|-m 0644 /dev/stdin|-m 0666 /dev/stdin|"
lint_readme "a binary installed through a path fails" '^got: .*-m 0755 target/release/m2a-session /usr/local/bin/m2a-session`' \
  "s|/dev/stdin /usr/local/bin/m2a-session < target/release/m2a-session|target/release/m2a-session /usr/local/bin/m2a-session|"
lint_readme "a check of the checkout copy only fails" '^got: .*`fuzz/check-m2a-gate\.sh fuzz/artifacts/m2a-gate\.json`' \
  "s|\`fuzz/check-m2a-gate.sh $gate_path\`|\`fuzz/check-m2a-gate.sh fuzz/artifacts/m2a-gate.json\`|"
lint_readme "the gate check before its install fails" '^(want|got): .*-m 0644 /dev/stdin /etc/ethswarm/m2a-gate\.json' \
  "/m2a-gate.json < fuzz\/artifacts\/m2a-gate.json\`/{h;d;}; /\`fuzz\/check-m2a-gate.sh \/etc/G"
lint_readme "the pre-check without the session user fails" '^got: .*`sudo m2a-session --dial-only`' \
  "s|$dial_span|\`sudo m2a-session --dial-only\`|"
lint_readme "the probe under another user fails" '^got: .*`sudo -u root m2a-session --gate-file' \
  "s|\`sudo -u m2a-session m2a-session --gate-file|\`sudo -u root m2a-session --gate-file|"
# Words that a shell parser could take for the same command are still a change.
lint_readme "a quoted --gate-file path fails" '^got: .*--gate-file "/etc/ethswarm/m2a-gate\.json" >' \
  "s|--gate-file $gate_path >|--gate-file \"$gate_path\" >|"
lint_readme "a 2>> redirect on the probe fails" '^got: .*\.jsonl 2>> session\.log`' \
  's|%SZ).jsonl`|%SZ).jsonl 2>> session.log`|'
# A new step that names no command of the old list, and text that shows a command it does not
# hold: an escape, an HTML entity or inline HTML.
lint_readme "a new sudo cp step in a code span fails" '^got:  line [0-9]+: +- `sudo cp target/release/m2a-session /usr/local/bin/`\.$' \
  "s|^\( *\)- \`cargo build --release.*|&${nl}\1- \`sudo cp target/release/m2a-session /usr/local/bin/\`.|"
lint_readme "a new sudo cp step in plain text fails" '^got:  line [0-9]+: +Then sudo cp a b\.$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Then sudo cp a b.|"
lint_readme "m2a-session written with escapes fails" ': a backslash$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run m2a\\\\-session --listen x.|"
lint_readme "m2a-session written with an HTML entity fails" ': an HTML entity$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run m2a\&#45;session --listen x.|"
lint_readme "inline HTML around ssh fails" ': inline HTML$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run s<b></b>sh -N -L 5052:127.0.0.1:5052 ref-host.|"
lint_readme "inline HTML code around a command fails" ': inline HTML$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run <code>m2a-ses</code>sion.|"
# Emphasis, a link or an invisible character inside a command word, and a command that the
# old list did not name: each line is compared, so each is a change.
lint_readme "emphasis inside ssh fails" '^got:  line [0-9]+: +Then run s\*s\*h -N -L 5052:127\.0\.0\.1:5052 ref-host\.$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Then run s*s*h -N -L 5052:127.0.0.1:5052 ref-host.|"
lint_readme "bold inside m2a-session fails" '^got:  line [0-9]+: +Run m2a-ses\*\*sion\*\* --listen x\.$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run m2a-ses**sion** --listen x.|"
lint_readme "a link inside ssh fails" '^got:  line [0-9]+: +Run \[ss\]\(#x\)h -N -L 5052:127\.0\.0\.1:5052 ref-host\.$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run [ss](#x)h -N -L 5052:127.0.0.1:5052 ref-host.|"
zero_width=$(printf '\342\200\213')   # U+200B, in UTF-8
lint_readme "a zero-width character inside ssh fails" '^got:  line [0-9]+: +Run ss.+h -N -L 5052' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Run ss${zero_width}h -N -L 5052:127.0.0.1:5052 ref-host.|"
lint_readme "a command that the old list did not name fails" '^got:  line [0-9]+: +Then run chmod 0777 /etc/ethswarm\.$' \
  "s|^\( *\)The forward listens on loopback only.*|&${nl}\1Then run chmod 0777 /etc/ethswarm.|"
lint_readme "an empty session run lists every wanted line" '^want: 10\. \*\*Run the session\*\* on the test host' \
  '/<!-- session-run:begin -->/,/<!-- session-run:end -->/{/<!-- session-run:/!d;}'
# Each got line names its line in the README.
dial_at=$(grep -n -F -- "$dial_span" "$ref/README.md" | cut -d: -f1)
lint_readme "a got line names its README line" "^got:  line $dial_at: .*--dial-only --dial-only\`" \
  "s|m2a-session --dial-only\`|m2a-session --dial-only --dial-only\`|"
lint_readme "a line wrap change of a compared line fails" '^got:  line [0-9]+: +`ssh -f` goes to the background only after the$' \
  "s|^\\( *\\)\\(The forward listens on loopback only.\\) \\(.*\\)|\\1\\2${nl}\\1\\3|"
# The tree check, the tunnel and the markers.
lint_readme "a tree check that lists untracked files fails" '^got: .*`git status --porcelain`' \
  's|`git status --porcelain --untracked-files=no`|`git status --porcelain`|'
lint_readme "a tunnel on every address fails" '^got: .*`ssh -f -N -L <BEACON_API_PORT>' \
  's|`ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:<BEACON_API_PORT>|`ssh -f -N -L <BEACON_API_PORT>|'
lint_readme "a tunnel step that does not stop on an ssh exit fails" 'does not name If `ssh -f` does not exit 0, do not do step 10\.7\.$' \
  's|If `ssh -f` does not exit 0, do not do step 10.7.|If `ssh` exits, open it again.|'
# The tunnel goes to the background only once the forward listens (ssh -f), and step 10.8 stops
# that process by its PID: a foreground ssh at a host-key or passphrase prompt has a PID but
# no forward yet, and Ctrl-C stops whatever runs in that terminal.
lint_readme "a tunnel without ssh -f fails" "does not name $(sed 's/[][\.*^$()|+?{}]/\\&/g' <<< "$tunnel_span")\$" \
  's|`ssh -f -N -o ExitOnForwardFailure=yes|`ssh -N -o ExitOnForwardFailure=yes|'
lint_readme "a tunnel stopped with Ctrl-C fails" 'does not name `kill <PID>`$' \
  's|`kill <PID>`|Ctrl-C|'
lint_readme "a tree check without the build variables fails" '^want: .*`env \| grep -E ' \
  '/`env | grep -E /d'
lint_readme "a cargo config search from the logical cwd fails" '^got:  line [0-9]+: .*`d=\$PWD; while' \
  's|`d=$(pwd -P); while|`d=$PWD; while|'
lint_readme "a probe whose tunnel stopped can still give evidence fails" 'does not name Then do not post the session file of step 10\.7 as evidence\.$' \
  's|Then do not post the session file of step 10.7 as evidence.|Then run it again.|'
lint_readme "a tunnel on a fixed port fails" '^got: .*-L 127\.0\.0\.1:5052:127\.0\.0\.1:5052 <ref-host>' \
  's|<BEACON_API_PORT>:127.0.0.1:<BEACON_API_PORT>|5052:127.0.0.1:5052|'
lint_readme "no end marker fails" '^want one session-run begin and one end marker \(got 1 and 0\)$' \
  '/<!-- session-run:end -->/d'
lint_readme "no begin marker fails" '^want one session-run begin and one end marker \(got 0 and 1\)$' \
  '/<!-- session-run:begin -->/d'
lint_readme "the end marker before the begin marker fails" '^the session-run end marker is not after its begin marker$' \
  's|<!-- session-run:begin -->|<!-- session-run:END -->|; s|<!-- session-run:end -->|<!-- session-run:begin -->|; s|<!-- session-run:END -->|<!-- session-run:end -->|'
# Each value that the evidence must name: drop it, and the lint names it.
for want in '`pass: true`' '`exit_code: 0`' '`build_dirty: false`' '`clean_build`' '`build_rustc_commit`' \
  '`connected to 1 peer(s), 0 not pinned; 0 listen address(es)`'; do
  # The README wraps the detail of pinned_peer_only, so drop the line that holds it.
  if [[ $want == '`connected to 1 peer(s)'* ]]; then script='/`connected to 1 peer(s), 0 not pinned/d'; else
    script="s|$(sed 's/[][\.*^$|]/\\&/g' <<< "$want")|DROPPED|g"; fi
  lint_readme "evidence without $want fails" "does not name $(sed 's/[][\.*^$()|+?{}]/\\&/g' <<< "$want")\$" "$script"
done
lint_readme "evidence without os_user fails" '^want: .*`os_user: "m2a-session"`' \
  's|`os_user: "m2a-session"`|the user|'

# tunnel_lint <root>: every SSH port forward that the files under <root> give (docs, code
# comments, scripts, ssh configs) listens on loopback only: the bind address of each -L (also
# in an option group such as -NL, and with the spec in the same word, -L5052:...) and of each
# LocalForward (also through -o) is 127.0.0.1. Each ssh with a forward also has
# -o ExitOnForwardFailure=yes, so that ssh exits if another process holds the port, and -f (also
# in an option group such as -fN), so that it goes to the background only once the forward
# listens. It is not put in the background with a trailing &. ssh is found as a word, also
# inside punctuation such as (ssh, **ssh or h;ssh, and autossh counts. The argv after ssh is
# read up to the remote command: OpenSSH also takes options after the host, but the words of the
# command are not options of ssh. Option keys compare without case, the first
# ExitOnForwardFailure value counts, and -o takes both the key=value and the "key value" form.
# Without these, a forward listens on every address, or a local account that holds the port
# serves the reference values. A line that ends with a backslash is read with the next line
# (its comment marker removed), as one shell command. A line that leaves a code span open is
# read with the next lines in two ways: the line break as a blank (Markdown) and as the end of
# the command (a shell). A fence line is never joined, so a forward in a fence does not take
# the options of a later line. Prints each problem as <file>:<line>: <problem>: <detail>. In a
# git checkout only tracked files count, so a copy elsewhere in the tree (a worktree, a build
# dir) does not. This test file holds bad forwards on purpose.
tunnel_py='
import os, re, shlex, sys
root, mode = sys.argv[1], sys.argv[2]
SELF = "ref-node.test.sh"
if mode == "git":
    paths = [p for p in sys.stdin.buffer.read().decode("utf-8", "surrogateescape").split("\0") if p]
else:
    paths = []
    for d, dirs, files in os.walk(root):
        dirs[:] = sorted(x for x in dirs if x not in ("target", ".git"))
        paths += [os.path.relpath(os.path.join(d, f), root) for f in sorted(files) if f != SELF]
# The ssh options that take an argument (ssh(1)).
ARG = set("BbcDEeFIiJLlmOoPpRSWw")
# ssh (or autossh) as a word: after a blank, a (, a ;, a * of emphasis or a /.
SSH = re.compile(r"(?<![A-Za-z0-9_.-])(?:auto)?ssh(?![A-Za-z0-9_-])")
# Where the command of an ssh ends: also a line break (below).
CUT = re.compile(r"&&|[|][|]|[;|)\n]")
COMMENT = re.compile(r"^\s*(//[/!]?|#|\*|--)?\s*")
# A fence line (after its comment marker): its backticks open no code span.
FENCE = re.compile(r"(```|~~~)")
forwards, problems = 0, []
def bind(spec):
    return spec.startswith("127.0.0.1:")
def report(rel, at, what, detail):
    problem = (rel, at, what, " ".join(detail.split()))
    if problem not in problems:
        problems.append(problem)
def fence(line):
    return FENCE.match(COMMENT.sub("", line, count=1)) is not None
def check(rel, at, text):
    # A code span that crosses a line break: Markdown shows the break as a blank, and a shell
    # ends the command there. Read the text both ways, and report what either reading finds.
    scan(rel, at, text.replace("\n", " "))
    scan(rel, at, text)
def scan(rel, at, text):
    global forwards
    for segment in text.split("`"):
        toks = [t.strip("\"'"'"'") for t in segment.split()]
        for k, t in enumerate(toks):
            m = re.fullmatch(r"(?i)localforward(?:=(.*))?", t)
            if not m or (k and toks[k - 1] == "-o"):
                continue  # -o LocalForward is read with the ssh options below
            spec = m.group(1) or (toks[k + 1] if k + 1 < len(toks) else "")
            if not spec:
                continue  # the name alone, in prose or a code span: no forward
            forwards += 1
            if not bind(spec):
                report(rel, at, "a forward without the bind address 127.0.0.1", spec)
        for found in SSH.finditer(segment):
            after = segment[found.end():]
            cut = CUT.search(after)
            words = after[:cut.start()] if cut else after
            command = found.group(0) + words
            try:
                argv = shlex.split(words)
            except ValueError:
                argv = words.split()
            specs, exit_values, fork, host, ended, j = [], [], False, False, False, 0
            background = any(x == "&" or (x.endswith("&") and not x.endswith("&&")) for x in argv)
            # OpenSSH reads the options before and after the host, up to the remote command:
            # the first word after the host that is not an option, or the word after the host
            # once -- ended the options. The words of the command are not options of ssh.
            while j < len(argv):
                x = argv[j]
                if x == "--" and not ended:
                    ended = True
                elif not ended and x.startswith("-") and len(x) > 1:
                    if x.startswith("--"):
                        j += 1
                        continue
                    for n, c in enumerate(x[1:], 1):
                        fork = fork or c == "f"
                        if c not in ARG:
                            continue
                        arg = x[n + 1:]
                        if not arg and j + 1 < len(argv):
                            j += 1
                            arg = argv[j]
                        if c == "L":
                            specs.append(arg)
                        elif c == "o":
                            key, _, value = arg.strip().partition("=") if "=" in arg else arg.strip().partition(" ")
                            key, value = key.strip().lower(), value.strip()
                            if key == "exitonforwardfailure":
                                exit_values.append(value.lower())
                            elif key == "localforward":
                                specs.append(value.split()[0] if value.split() else "")
                        break
                elif host:
                    break  # the remote command
                else:
                    host = True
                j += 1
            if not specs:
                continue
            forwards += len(specs)
            for spec in specs:
                if not bind(spec):
                    report(rel, at, "a forward without the bind address 127.0.0.1", spec)
            # ssh takes the first value of an option.
            if not exit_values or exit_values[0] != "yes":
                report(rel, at, "an ssh forward without -o ExitOnForwardFailure=yes", command)
            if not fork:
                report(rel, at, "an ssh forward without -f (it goes to the background once the forward listens)", command)
            if background:
                report(rel, at, "an ssh forward in the background with & (use ssh -f)", command)
for rel in paths:
    try:
        with open(os.path.join(root, rel), "rb") as f:
            data = f.read()
    except OSError:
        continue
    if b"\0" in data[:8192]:
        continue
    lines = data.decode("utf-8", "replace").split("\n")
    i = 0
    while i < len(lines):
        at, text = i + 1, lines[i]
        opens_span = not fence(text)
        i += 1
        # A backslash continues the shell command (a blank), an open code span continues on
        # the next line (a line break). A fence line is never joined.
        while i < len(lines) and not fence(lines[i]):
            if text.endswith("\\"):
                text = text[:-1] + " "
            elif opens_span and text.count("`") % 2:
                text += "\n"
            else:
                break
            text += COMMENT.sub("", lines[i], count=1)
            i += 1
        check(rel, at, text)
for rel, at, what, detail in problems:
    print("%s:%d: %s: %s" % (rel, at, what, detail))
if not forwards:
    print("no SSH port forward found under " + root)
sys.exit(1 if problems or not forwards else 0)
'
tunnel_lint() {
  local root=$1
  if git -C "$root" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    git -C "$root" ls-files -z -- . ':!ops/ref-node/tests/ref-node.test.sh' |
      (cd "$root" && python3 -I -c "$tunnel_py" "$root" git)
  else
    python3 -I -c "$tunnel_py" "$root" walk < /dev/null
  fi
}
check 0 "tunnel: every SSH port forward in the repository binds loopback and stops on a taken port" tunnel_lint "$repo"
mkdir -p "$tmp/tunnel/docs" "$tmp/tunnel-git/docs"
printf 'Tunnel: `ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:1:127.0.0.1:1 h`\n' > "$tmp/tunnel/docs/good.md"
cp "$tmp/tunnel/docs/good.md" "$tmp/tunnel-git/docs/good.md"
printf 'ssh -N -L 127.0.0.1:5053:127.0.0.1:5053 ref-host\n' > "$tmp/tunnel-git/docs/bad.md"
git -C "$tmp/tunnel-git" init -q && git -C "$tmp/tunnel-git" add -A
check_out 1 "tunnel: a forward without ExitOnForwardFailure fails (git checkout)" \
  '^docs/bad\.md:1: an ssh forward without -o ExitOnForwardFailure=yes: ssh -N -L 127' tunnel_lint "$tmp/tunnel-git"
check 0 "tunnel: a loopback forward with -f and ExitOnForwardFailure passes" tunnel_lint "$tmp/tunnel"
# tunnel_case <description> <pattern> <file content (printf format)>: one bad file next to the
# good one fails with a line that matches the pattern.
tunnel_case() {
  # shellcheck disable=SC2059 # the format is the case's own text
  printf "$3" > "$tmp/tunnel/docs/bad.txt"
  check_out 1 "tunnel: $1" "$2" tunnel_lint "$tmp/tunnel"
  rm "$tmp/tunnel/docs/bad.txt"
}
exit_on='-o ExitOnForwardFailure=yes'
tunnel_case "a forward on every address fails" \
  '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:127\.0\.0\.1:5052$' \
  "//! (\`ssh $exit_on -L 5052:127.0.0.1:5052 ref-host\`)\n"
tunnel_case "-NL (L in an option group) fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "ssh $exit_on -NL 5052:127.0.0.1:5052 ref-host\n"
tunnel_case "-L5052 (the spec in the same word) fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "ssh -N $exit_on -L5052:127.0.0.1:5052 ref-host\n"
tunnel_case "-o LocalForward= fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052$' \
  "ssh -N $exit_on -o LocalForward=5052 127.0.0.1:5052 ref-host\n"
tunnel_case "a LocalForward line of an ssh config fails" '^docs/bad\.txt:2: a forward without the bind address 127\.0\.0\.1: 5052$' \
  "Host ref\n  LocalForward 5052 127.0.0.1:5052\n"
tunnel_case "a forward split over two lines fails" '^docs/bad\.txt:1: an ssh forward without -o ExitOnForwardFailure=yes' \
  "ssh -N \\\\\n  -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\n"
tunnel_case "a forward split inside a code span fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "//! (\`ssh -N $exit_on\n//! -L 5052:127.0.0.1:5052 ref-host\`)\n"
tunnel_case "a second bad -L on a good line fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5053:' \
  "ssh -N $exit_on -L 127.0.0.1:5052:127.0.0.1:5052 -L 5053:127.0.0.1:5053 ref-host\n"
tunnel_case "a forward put in the background with & fails" '^docs/bad\.txt:1: an ssh forward in the background with &' \
  "ssh -N $exit_on -L 127.0.0.1:5053:127.0.0.1:5053 ref-host &\ncollector sse\n"
# Options after the host, a word boundary other than a blank, autossh, any case of the key,
# the first ExitOnForwardFailure value, and the "key value" form of -o.
tunnel_case "-L after the host fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "ssh -N $exit_on ref-host -L 5052:127.0.0.1:5052\n"
tunnel_case "ssh in a subshell fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "(ssh -N $exit_on -L 5052:127.0.0.1:5052 ref-host)\n"
tunnel_case "ssh in bold fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "**ssh -N $exit_on -L 5052:127.0.0.1:5052 ref-host**\n"
tunnel_case "ssh after a ; fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "h;ssh -N $exit_on -L 5052:127.0.0.1:5052 ref-host\n"
tunnel_case "autossh fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "autossh -M 0 -N $exit_on -L 5052:127.0.0.1:5052 ref-host\n"
tunnel_case "a lower-case localforward fails" '^docs/bad\.txt:2: a forward without the bind address 127\.0\.0\.1: 5052$' \
  "Host ref\n  localforward 5052 127.0.0.1:5052\n"
tunnel_case "a first ExitOnForwardFailure=no fails" '^docs/bad\.txt:1: an ssh forward without -o ExitOnForwardFailure=yes' \
  "ssh -N -o ExitOnForwardFailure=no $exit_on -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\n"
tunnel_case "a first \"ExitOnForwardFailure no\" fails" '^docs/bad\.txt:1: an ssh forward without -o ExitOnForwardFailure=yes' \
  "ssh -N -o \"ExitOnForwardFailure no\" $exit_on -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\n"
tunnel_case "\"ExitOnForwardFailure no\" with a bad forward fails" '^docs/bad\.txt:1: a forward without the bind address 127\.0\.0\.1: 5052:' \
  "ssh -N -o \"ExitOnForwardFailure no\" -L 5052:127.0.0.1:5052 ref-host\n"
# A fence line is not joined with the lines after it, and a line break ends an ssh command
# outside a code span: a forward does not take the ExitOnForwardFailure or the -f of a later
# ssh line of the same fence, or of the lines after an odd backtick in a script.
tunnel_case "a forward in a fence with a good ssh line after it fails" \
  '^docs/bad\.txt:2: an ssh forward without -o ExitOnForwardFailure=yes: ssh -f -N -L 127\.0\.0\.1:5052:127\.0\.0\.1:5052 ref-host$' \
  "\`\`\`sh\nssh -f -N -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\nssh -f $exit_on other-host\n\`\`\`\n"
tunnel_case "a forward in a commented fence with a good ssh line after it fails" \
  '^docs/bad\.txt:2: an ssh forward without -o ExitOnForwardFailure=yes' \
  "//! \`\`\`sh\n//! ssh -f -N -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\n//! ssh -f $exit_on h\n//! \`\`\`\n"
tunnel_case "a forward after an odd backtick with a good ssh line after it fails" \
  '^docs/bad\.txt:1: an ssh forward without -o ExitOnForwardFailure=yes: ssh -f -N -L 127\.0\.0\.1:5052' \
  "echo \"\\\`\" && ssh -f -N -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\nssh -f $exit_on h\n"
# The tunnel goes to the background with ssh -f, only once the forward listens: a foreground
# ssh at a host-key or passphrase prompt has no forward yet, and the port stays free.
tunnel_case "a forward without ssh -f fails" '^docs/bad\.txt:1: an ssh forward without -f' \
  "ssh -N $exit_on -L 127.0.0.1:5052:127.0.0.1:5052 ref-host\n"
tunnel_case "an -f after the forward's argument fails" '^docs/bad\.txt:1: an ssh forward without -f' \
  "ssh -N $exit_on -L 127.0.0.1:5052:127.0.0.1:5052f ref-host\n"
# ssh reads its options before and after the host, up to the remote command: an -f or an -L of
# the command is not an option of ssh.
tunnel_case "an -f of the remote command fails" '^docs/bad\.txt:1: an ssh forward without -f' \
  "ssh $exit_on -L 127.0.0.1:5052:127.0.0.1:5052 ref-host journalctl -f\n"
tunnel_case "an -f of the remote command after -- fails" '^docs/bad\.txt:1: an ssh forward without -f' \
  "ssh $exit_on -L 127.0.0.1:5052:127.0.0.1:5052 -- ref-host -f\n"
printf 'ssh -f -N %s -L 127.0.0.1:5053:127.0.0.1:5053 ref-host grep -L x y\n' "$exit_on" > "$tmp/tunnel/docs/f.txt"
check 0 "tunnel: an -L of the remote command is not a forward" tunnel_lint "$tmp/tunnel"
printf '```sh\nssh -fN %s -L 127.0.0.1:5053:127.0.0.1:5053 ref-host\n```\n' "$exit_on" > "$tmp/tunnel/docs/f.txt"
check 0 "tunnel: -fN (f in an option group) in a fence passes" tunnel_lint "$tmp/tunnel"
printf 'ssh -f -N -o "ExitOnForwardFailure yes" -L 127.0.0.1:5053:127.0.0.1:5053 ref-host &&\n  collector sse\n' > "$tmp/tunnel/docs/f.txt"
check 0 "tunnel: the \"key value\" form of -o passes" tunnel_lint "$tmp/tunnel"
printf 'ssh -f -N %s -L 127.0.0.1:5053:127.0.0.1:5053 ref-host &&\n  collector sse\n' "$exit_on" > "$tmp/tunnel/docs/f.txt"
check 0 "tunnel: ssh -f before && passes" tunnel_lint "$tmp/tunnel"
rm -r "$tmp/tunnel/docs"
check_out 1 "tunnel: no forward at all fails" '^no SSH port forward found' tunnel_lint "$tmp/tunnel"

check_out 0 "mode: 600 and the service user passes" '^/k: 600 reth: PASS$' check_mode_owner /k "600 reth" reth
check_out 1 "mode: 644 fails" '^/k: 644 reth \(want 600 reth\): FAIL$' check_mode_owner /k "644 reth" reth
check_out 1 "mode: another owner fails" '\(want 600 lighthouse\): FAIL$' check_mode_owner /k "600 reth" lighthouse
check_out 1 "mode: a missing file fails" '^/k: no such file \(want 600 reth\): FAIL$' check_mode_owner /k "" reth
check_out 1 "mode: 6000 is not 600" 'FAIL$' check_mode_owner /k "6000 reth" reth

# set_env <file> <key> <value>: replace or append KEY=value (taken from the environment, so awk
# decodes no backslash escape in it).
set_env() {
  SET_K=$2 SET_V=$3 awk 'BEGIN { k = ENVIRON["SET_K"]; v = ENVIRON["SET_V"] }
    index($0, k "=") == 1 { if (!done) print k "=" v; done = 1; next } { print }
    END { if (!done) print k "=" v }' "$1" > "$1.new" && mv "$1.new" "$1"
}

# env_check reads an .env the way compose's dotenv parser does only if nothing in it is
# parsed specially: compose keeps reading after a closing quote (DUMMY=''RETH_UID=0 sets
# RETH_UID too), cuts an inline comment, trims blanks and reads a CR. So the whole file is
# printable ASCII and LF, and a value holds no blank, quote, backslash, #, $ or backtick.
# envc_case <expect-exit> <description> <pattern or ''> <printf format of the extra lines>
envc_case() {
  cp "$ref/.env.example" "$tmp/envc.env"
  # shellcheck disable=SC2059 # the format is the case's own bytes
  printf "$4" >> "$tmp/envc.env"
  if [[ -n $3 ]]; then
    check_out "$1" "env_check: $2" "$3" env_check "$tmp/envc.env"
  else
    check "$1" "env_check: $2" env_check "$tmp/envc.env"
  fi
}
envc_case 0 "the Sepolia example (apostrophes and backticks in # comments) passes" '' ''
check 0 "env_check: the Hoodi example passes" env_check "$ref/.env.hoodi.example"
envc_case 1 "DUMMY=''RETH_UID=0 (a second assignment after a closing quote) is refused" \
  'line [0-9]+: DUMMY holds a blank, a quote, a backslash or a #' "DUMMY=''RETH_UID=0\n"
envc_case 1 'DUMMY="x"RETH_UID=0 is refused' 'line [0-9]+: DUMMY holds a blank, a quote' 'DUMMY="x"RETH_UID=0\n'
envc_case 1 "DUMMY='' RETH_UID=0 is refused" 'line [0-9]+: DUMMY holds a blank' "DUMMY='' RETH_UID=0\n"
envc_case 1 "an inline comment is refused" 'line [0-9]+: X holds a blank, a quote, a backslash or a #' 'X=1001 #c\n'
envc_case 1 "a # in a value is refused" 'line [0-9]+: X holds .* a #' 'X=a#b\n'
envc_case 1 "a trailing blank is refused" 'line [0-9]+: X holds a blank' 'X=1001 \n'
envc_case 1 "a backslash is refused" 'line [0-9]+: X holds .* a backslash' 'X=/srv/a\\b\n'
envc_case 1 "a CR is refused" 'line [0-9]+: a byte other than printable ASCII' 'X=1001\r\n'
envc_case 1 "a TAB is refused" 'line [0-9]+: a byte other than printable ASCII' 'X=\t1001\n'
envc_case 1 "a TAB in a comment is refused too" 'line [0-9]+: a byte other than printable ASCII' '#\tcomment\n'
envc_case 1 "a non-ASCII byte is refused" 'line [0-9]+: a byte other than printable ASCII' 'X=caf\303\251\n'
envc_case 1 "a NUL byte is refused" 'a byte other than printable ASCII' 'X=a\000b\n'
envc_case 1 "a quoted value is refused" 'line [0-9]+: X holds .* a quote' 'X="1001"\n'
printf 'X="v"\n' > "$tmp/envq.env"
check_out 0 "env_get: quotes are no longer stripped (env_check refuses them first)" '^"v"$' env_get "$tmp/envq.env" X
# env_value_ok: a value env_check would accept in an .env line, which setup.sh holds --root to
# before it writes DATA_ROOT there (a # would cut the line, a quote or $ make compose read it
# differently, and every later run would refuse the .env).
for value in /srv/ethswarm-ref-hoodi /srv/a.b_c-d:e@f+g%h=i,j /; do
  check 0 "env_value_ok: '$value' passes" env_value_ok "$value"
done
for value in '/srv/a b' '/srv/a#b' "/srv/a'b" '/srv/a"b' '/srv/a$b' '/srv/a`b' '/srv/a\b' $'/srv/caf\303\251' \
  $'/srv/a\tb' $'/srv/a\nb' $'/srv/a\rb' $'/srv/a\177b' $'/srv/a\033b'; do
  check 1 "env_value_ok: $(printf '%q' "$value") is refused" env_value_ok "$value"
done
# no_control_char: a path given on the command line (--env-file) holds no control character. A
# command substitution drops a trailing newline, so $'/x/node.env\n' would be checked, read and
# written as /x/node.env.
for value in /x/node.env $'/x/caf\303\251.env' '/x/a b.env'; do
  check 0 "no_control_char: $(printf '%q' "$value") passes" no_control_char "$value"
done
for value in $'/x/node.env\n' $'/x/\nnode.env' $'/x/a\tb' $'/x/a\rb' $'/x/\033[31m' $'/x/a\177b' $'/x/a\001b'; do
  check 1 "no_control_char: $(printf '%q' "$value") is refused" no_control_char "$value"
done

# docker reads its config (which daemon: the current context) and its CLI plugins (docker
# compose itself) from DOCKER_CONFIG, else from $HOME/.docker. sudo -E keeps the operator's
# HOME, so root's docker would run the operator's ~/.docker/cli-plugins/docker-compose.
# docker_config_pin points DOCKER_CONFIG at the .docker of the euid's own home, from the passwd
# database, whatever HOME says.
pw_home=$(python3 -I -B -c 'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)')
mkdir -p "$tmp/evilhome/.docker/cli-plugins"
printf '#!/bin/sh\ntouch "%s/evil-plugin-ran"\nexit 1\n' "$tmp" > "$tmp/evilhome/.docker/cli-plugins/docker-compose"
chmod +x "$tmp/evilhome/.docker/cli-plugins/docker-compose"
got=$(HOME="$tmp/evilhome" bash -c 'source "$1" && docker_config_pin && printf "%s" "$DOCKER_CONFIG"' _ "$ref/lib/common.sh" 2>&1) || got="(failed: $got)"
if [[ $got == "${pw_home%/}/.docker" ]]; then ok "docker_config_pin: DOCKER_CONFIG is the passwd home's .docker, not HOME's"; else bad "docker_config_pin: DOCKER_CONFIG (got '$got', want '${pw_home%/}/.docker')"; fi
# No passwd entry for the euid (a python3 that finds none stands in): refused, never HOME.
mkdir -p "$tmp/nopasswd" && printf '#!/bin/sh\nexit 1\n' > "$tmp/nopasswd/python3" && chmod +x "$tmp/nopasswd/python3"
check_out 1 "docker_config_pin: an euid without a passwd home is refused" '^ERROR: uid [0-9]+ has no home directory in the passwd database' \
  env PATH="$tmp/nopasswd:$PATH" bash -c 'source "$1" && docker_config_pin' _ "$ref/lib/common.sh"
# read_env refuses such a path itself too, before fsguard sees it.
printf 'NETWORK=sepolia\n' > "$tmp/ctl.env"
check_out 2 "read_env: an .env path ending in a newline is refused" '^ERROR: --env-file: the path holds a control character' \
  read_env "$ref/lib/fsguard.py" "$tmp/ctl.env"$'\n' "$tmp/ctl.copy"
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  # The real docker CLI, against a plugin planted under HOME: it runs without the pin (so the
  # check can see it), never with it.
  rm -f "$tmp/evil-plugin-ran"
  HOME="$tmp/evilhome" docker compose version >/dev/null 2>&1 || true
  if [[ -e $tmp/evil-plugin-ran ]]; then
    rm -f "$tmp/evil-plugin-ran"
    HOME="$tmp/evilhome" bash -c 'source "$1" && docker_config_pin && exec docker compose version' _ "$ref/lib/common.sh" >/dev/null 2>&1 || true
    if [[ ! -e $tmp/evil-plugin-ran ]]; then ok "docker_config_pin: docker runs no CLI plugin from HOME's .docker"; else bad "docker_config_pin: docker ran the CLI plugin under HOME"; fi
  else
    echo "# skip - docker_config_pin against the real docker: this docker loads no plugin from HOME"
  fi
else
  echo "# skip - docker_config_pin against the real docker: docker compose is not installed"
fi

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
  # A FIFO planted where a file is opened must be refused at once, never block setup.sh (a
  # bounded run: a hang is a failure, not a stuck suite).
  if [[ -n $bound ]]; then
    rmdir "$r/reth/jwt.hex" && mkfifo "$r/reth/jwt.hex"
    refuse_case --want 'reth/jwt\.hex: not a regular file' "a FIFO at a JWT path, without blocking" '[[ -p $r/reth/jwt.hex ]]' --root "$r"
    rm "$r/reth/jwt.hex"
    rmdir "$r/.staging" && mkfifo "$r/.staging"
    refuse_case --want '\.staging: a symlink or not a directory' "a FIFO at the staging path, without blocking" '[[ -p $r/.staging ]]' --root "$r"
    rm "$r/.staging" && mkdir -m 0700 "$r/.staging" && mkfifo "$r/.staging/jwt.reth.000000000000"
    refuse_case --want '\.staging: not empty' "a FIFO inside the staging dir, without blocking" '[[ -p $r/.staging/jwt.reth.000000000000 && ! -e $r/reth/jwt.hex ]]' --root "$r"
  else
    echo "# skip - setup refuses a planted FIFO: no timeout command to bound the run"
  fi
  # A backslash or a newline in DATA_ROOT: awk would decode an escape and record another root
  # (or an extra RETH_UID line) in .env.
  local root_rule='DATA_ROOT must be an absolute path of printable ASCII without a blank, a quote, a backslash, a #, a \$ or a backtick'
  refuse_case --want "$root_rule" "a backslash in --root" \
    '[[ -z $(find "$base" -maxdepth 1 -name "bs*") ]] && ! grep -q "^RETH_UID=0" "$refuse_env"' --root "$base/bs\nRETH_UID=0"
  refuse_case --want "$root_rule" "a newline in --root" \
    '[[ -z $(find "$base" -maxdepth 1 -name "nl*") ]]' --root "$base/nl"$'\n'"RETH_UID=0"
  # The rest of env_check's value rule: setup.sh writes the root into .env as DATA_ROOT, where a
  # # would cut the line, a quote or $ make compose read another value, and every later run
  # would refuse the .env. Refused before anything is created or written.
  cp "$refuse_env" "$base/refuse.env.before"
  local bad_root
  for bad_root in "$base/rt#x" "$base/rt'x" "$base/rt\"x" "$base/rt\$x" "$base/rt\`x" "$base/rt"$'\303\251' "$base/rt"$'\tx'; do
    refuse_case --want "$root_rule" "--root $(printf '%q' "${bad_root#"$base/"}")" \
      '[[ -z $(find "$base" -maxdepth 1 -name "rt*") ]] && cmp -s "$refuse_env" "$base/refuse.env.before"' --root "$bad_root"
  done
  # --env-file with a control character: a command substitution would drop a trailing newline
  # and check (and rewrite) the .env without it.
  mkdir -m 0700 "$base/ctl" && cp "$ref/.env.example" "$base/ctl/node.env"
  refuse_case --want '^ERROR: --env-file: the path holds a control character' "an --env-file path ending in a newline" \
    '[[ ! -e $base/ctl-root ]] && cmp -s "$base/ctl/node.env" "$ref/.env.example"' --env-file "$base/ctl/node.env"$'\n' --root "$base/ctl-root"
  set_env "$refuse_env" DATA_ROOT "$base/bs\\x"
  refuse_case --want 'DATA_ROOT holds a blank, a quote, a backslash or a #' "a backslash in DATA_ROOT from .env" '[[ -z $(find "$base" -maxdepth 1 -name "bs*") ]]'
  cp "$ref/.env.example" "$refuse_env"
  # The .env directory gets the same walk from / as DATA_ROOT: no symlink anywhere on its path,
  # every directory owned by root or the operator and closed to group and others.
  mkdir -m 0700 "$base/envreal" && cp "$ref/.env.example" "$base/envreal/.env" && ln -s "$base/envreal" "$base/envlink"
  cp "$base/envreal/.env" "$base/env.before"
  refuse_case --want 'envlink: a symlink or not a directory' "an .env reached through a symlinked directory" \
    '[[ ! -e $base/envdir-root ]] && cmp -s "$base/envreal/.env" "$base/env.before"' --env-file "$base/envlink/.env" --root "$base/envdir-root"
  mkdir -m 0700 "$base/envgw" && chmod 0770 "$base/envgw" && cp "$ref/.env.example" "$base/envgw/.env"
  refuse_case --want 'envgw: writable by group or others' "an .env in a group-writable directory" \
    '[[ ! -e $base/envdir-root ]] && cmp -s "$base/envgw/.env" "$base/env.before"' --env-file "$base/envgw/.env" --root "$base/envdir-root"
  mkdir -p "$base/envup/cfg" && chmod 0777 "$base/envup" && chmod 0700 "$base/envup/cfg" && cp "$ref/.env.example" "$base/envup/cfg/.env"
  refuse_case --want 'envup: writable by group or others' "an .env below a world-writable directory" \
    '[[ ! -e $base/envdir-root ]] && cmp -s "$base/envup/cfg/.env" "$base/env.before"' --env-file "$base/envup/cfg/.env" --root "$base/envdir-root"
  chmod 0755 "$base/envup"
  # The .env itself is read once, through fsguard: never through a symlink, a hard link or a
  # FIFO (which a read by path would follow, or block on). The file it points at stays as it was.
  mkdir -m 0700 "$base/envfile" && cp "$ref/.env.example" "$base/envfile.target"
  ln -s "$base/envfile.target" "$base/envfile/.env"
  refuse_case --want 'envfile/\.env: a symlink or unreadable' "an .env that is a symlink" \
    '[[ -L $base/envfile/.env && ! -e $base/envfile-root ]] && cmp -s "$base/envfile.target" "$ref/.env.example"' \
    --env-file "$base/envfile/.env" --root "$base/envfile-root"
  rm "$base/envfile/.env" && ln "$base/envfile.target" "$base/envfile/.env"
  refuse_case --want 'envfile/\.env: has 2 hard links' "an .env with a second hard link" \
    '[[ ! -e $base/envfile-root ]] && cmp -s "$base/envfile.target" "$ref/.env.example"' \
    --env-file "$base/envfile/.env" --root "$base/envfile-root"
  rm "$base/envfile/.env"
  if [[ -n $bound ]]; then
    mkfifo -m 0600 "$base/envfile/.env"
    refuse_case --want 'envfile/\.env: not a regular file' "an .env that is a FIFO, without blocking" \
      '[[ -p $base/envfile/.env && ! -e $base/envfile-root ]]' --env-file "$base/envfile/.env" --root "$base/envfile-root"
    rm "$base/envfile/.env"
  else
    echo "# skip - setup refuses a FIFO at the .env: no timeout command to bound the run"
  fi
  # setup.sh creates DATA_ROOT itself at most, never a missing directory above it (it would be
  # root's, mode 0755, wherever the operator mistyped).
  refuse_case --want 'noparent: no such directory' "a DATA_ROOT whose parent is missing" \
    '[[ ! -e $base/noparent ]]' --root "$base/noparent/srv"
  refuse_case --want 'noparent: no such directory' "a DATA_ROOT two missing levels down" \
    '[[ ! -e $base/noparent ]]' --root "$base/noparent/deep/srv"
  # .env lines compose reads differently: export (last one wins), indentation, a key twice,
  # $ or a backtick (expanded). Each case breaks one rule only (a $ or backtick replaces the
  # key's line rather than adding a second one), and the refusal names that rule. setup.sh
  # refuses before it creates anything.
  local line key
  for line in 'export RETH_UID=0' ' RETH_UID=0'; do
    cp "$ref/.env.example" "$refuse_env" && printf '%s\n' "$line" >> "$refuse_env"
    refuse_case --want 'line [0-9]+: not KEY=value' ".env line '${line%%=*}=…'" '[[ ! -e $base/env-root ]]' --root "$base/env-root"
  done
  cp "$ref/.env.example" "$refuse_env" && printf '%s\n' 'RETH_IMAGE=again' >> "$refuse_env"
  refuse_case --want 'line [0-9]+: RETH_IMAGE set twice' ".env line 'RETH_IMAGE=…' (a key twice)" '[[ ! -e $base/env-root ]]' --root "$base/env-root"
  for line in 'CHECKPOINT_SYNC_URL=https://x.example/$SECRETPART' 'TRUSTED_PEERS=`id`'; do
    key=${line%%=*}
    cp "$ref/.env.example" "$refuse_env" && set_env "$refuse_env" "$key" "${line#*=}"
    refuse_case --want "line [0-9]+: $key holds a \\$ or a backtick" ".env line '$key=…' (a \$ or a backtick)" \
      '[[ ! -e $base/env-root && $(grep -c "^$key=" "$refuse_env") == 1 ]] && ! grep -q "set twice" <<< "$out"' --root "$base/env-root"
  done
  cp "$ref/.env.example" "$refuse_env"
}
# refuse_case [--want <pattern>] <description> <check> [setup.sh args...]: setup.sh exits 2, the
# check holds (single-quoted: evaluated after the run, with the output in $out), and, with
# --want, an output line matches the extended regex <pattern>. Bounded by $bound when set.
refuse_case() {
  local want='' desc after rc=0 out
  if [[ $1 == --want ]]; then want=$2; shift 2; fi
  desc=$1 after=$2
  shift 2
  # shellcheck disable=SC2086 # $refuse_flags is empty or one flag; $bound is empty or a command
  out=$($bound bash "$setup" $refuse_flags --env-file "$refuse_env" "$@" 2>&1) || rc=$?
  if ((rc == 2)) && eval "$after" && { [[ -z $want ]] || grep -Eq -- "$want" <<< "$out"; }; then
    ok "setup refuses${refuse_flags:+ (test mode)}: $desc"
  else
    bad "setup refuses: $desc (exit $rc, check: $after${want:+, want /$want/})" "$out"
  fi
}
# bound: a prefix that kills a hung run (and its children) after 30 s, where timeout exists.
bound=
if command -v timeout >/dev/null 2>&1; then bound="timeout -k 5 30"; fi

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

# compose reads COMPOSE_* keys from .env (COMPOSE_PROJECT_NAME would pick another network's
# project), so setup.sh refuses them before it changes anything.
cp "$env_file" "$tmp/cpn.env"; printf 'COMPOSE_PROJECT_NAME=sepolia-ref\n' >> "$tmp/cpn.env"
check_out 2 "setup: COMPOSE_PROJECT_NAME in .env is refused" 'COMPOSE_PROJECT_NAME: compose reads COMPOSE_\* keys from \.env; none may be set' \
  bash "$setup" --test-mode --env-file "$tmp/cpn.env" --root "$tmp/cpn-root"
if [[ ! -e $tmp/cpn-root ]]; then ok "setup: a refused COMPOSE_ key creates nothing"; else bad "setup: a refused COMPOSE_ key creates nothing"; fi
# NETWORK picks the users and the default DATA_ROOT, so setup.sh refuses one it does not know.
for value in '' mainnet '../sepolia'; do
  cp "$env_file" "$tmp/net.env"; set_env "$tmp/net.env" NETWORK "$value"
  check_out 2 "setup: NETWORK '$value' is refused" '^ERROR: NETWORK must be sepolia or hoodi' \
    bash "$setup" --test-mode --env-file "$tmp/net.env" --root "$tmp/net-root"
done
if [[ ! -e $tmp/net-root ]]; then ok "setup: a refused NETWORK creates nothing"; else bad "setup: a refused NETWORK creates nothing"; fi
# Temp files never go where the caller's TMPDIR points (an operator-owned directory under
# sudo -E). A python3 spy first on PATH lists TMPDIR each time a script runs Python, which
# every script does while its temp directory exists.
mkdir -p "$tmp/pyspy"
cat > "$tmp/pyspy/python3" <<SH
#!/usr/bin/env bash
echo call >> "$tmp/optmp.calls"
ls -A "\$TMPDIR" >> "$tmp/optmp.log" 2>/dev/null
exec $(command -v python3) "\$@"
SH
chmod +x "$tmp/pyspy/python3"
# no_tmpdir <expect-exit> <description> <PATH prefix> <command...>: the command exits
# <expect-exit> with TMPDIR set to an empty directory, which stays empty whenever Python runs.
no_tmpdir() {
  local expect=$1 desc=$2 prefix=$3 rc=0 out
  shift 3
  rm -rf "$tmp/optmp" && mkdir -m 0700 "$tmp/optmp" && : > "$tmp/optmp.log" && : > "$tmp/optmp.calls"
  out=$(env PATH="$tmp/pyspy:$prefix$PATH" TMPDIR="$tmp/optmp" "$@" 2>&1) || rc=$?
  if ((rc == expect)) && [[ -s $tmp/optmp.calls && ! -s $tmp/optmp.log ]]; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect; in TMPDIR: $(tr '\n' ' ' < "$tmp/optmp.log"))" "$out"
  fi
}
cp "$ref/.env.example" "$tmp/tmpdir.env"
no_tmpdir 0 "setup: the caller's TMPDIR is not used" '' bash "$setup" --test-mode --env-file "$tmp/tmpdir.env" --root "$tmp/tmpdir-root"
cp "$ref/.env.hoodi.example" "$tmp/hoodi-setup.env"
check_out 0 "setup: the Hoodi .env example sets up its own root" '^setup OK$' \
  bash "$setup" --test-mode --env-file "$tmp/hoodi-setup.env" --root "$tmp/hoodi-root"
if grep -qx "DATA_ROOT=$tmp/hoodi-root" "$tmp/hoodi-setup.env" && grep -qx 'NETWORK=hoodi' "$tmp/hoodi-setup.env" &&
  grep -qx 'BEACON_API_PORT=5053' "$tmp/hoodi-setup.env"; then
  ok "setup: the Hoodi .env keeps NETWORK and its ports, and records its DATA_ROOT"
else
  bad "setup: the Hoodi .env keeps NETWORK and its ports" "$(cat "$tmp/hoodi-setup.env")"
fi
# A checkout reached through a symlinked directory (a symlinked home): the script's own
# directory and a relative --env-file resolve to the real path (cd -P, pwd -P), which the walk
# from / then checks, instead of being refused for the symlink.
mkdir -m 0700 "$tmp/realhome" && cp -R "$ref" "$tmp/realhome/ref-node" && ln -s "$tmp/realhome" "$tmp/linkhome"
cp "$ref/.env.example" "$tmp/realhome/ref-node/.env"
check_out 0 "setup: run through a symlinked checkout, the default .env is accepted" '^setup OK$' \
  bash "$tmp/linkhome/ref-node/setup.sh" --test-mode --root "$tmp/linkhome-root"
if grep -qx "DATA_ROOT=$tmp/linkhome-root" "$tmp/realhome/ref-node/.env"; then ok "setup: the checkout's .env was written through its real path"; else bad "setup: the checkout's .env was written"; fi
check_out 0 "setup: a relative --env-file from a symlinked working directory is accepted" '^setup OK$' \
  bash -c 'cd "$1" && bash "$2" --test-mode --env-file .env --root "$3"' _ "$tmp/linkhome/ref-node" "$setup" "$tmp/linkcwd-root"
check_out 2 "setup: a symlink inside a relative --env-file is still refused" 'linkhome: a symlink or not a directory' \
  bash -c 'cd "$1" && bash "$2" --test-mode --env-file linkhome/ref-node/.env --root "$3"' _ "$tmp" "$setup" "$tmp/linkrel-root"

# The JWT copies are staged in a root-only directory, never in the service-owned ones.
m=$(file_mode_uid "$root/.staging" 2>/dev/null || true)
if [[ $m == "700 $me_uid" && -z $(ls -A "$root/.staging") ]]; then ok "setup: .staging is 0700, ours, and empty after a run"; else bad "setup: .staging is 0700, ours, and empty (got '$m')"; fi
for svc in reth lighthouse; do
  got=''
  for f in "$root/$svc"/* "$root/$svc"/.[!.]*; do if [[ -e $f ]]; then got="$got${f##*/} "; fi; done
  if [[ $got == "data jwt.hex " ]]; then ok "setup: no temp file left in $svc/"; else bad "setup: no temp file left in $svc/ (got '$got')"; fi
done

refusal_cases --test-mode
# fsguard.py's .env-directory commands, called directly with what setup.sh never passes.
guard="$ref/lib/fsguard.py"
check_out 2 "fsguard: check-dir refuses a missing directory" 'absent: no such directory$' python3 -I -B "$guard" check-dir "$tmp/absent" "$me_uid" -1
check_out 2 "fsguard: check-dir refuses a relative directory" '^ERROR: the \.env directory must be an absolute path$' python3 -I -B "$guard" check-dir rel/dir "$me_uid" -1
check_out 2 "fsguard: an OPERATOR_UID that is not a uid is refused" "OPERATOR_UID 'x1' is not a uid or -1" python3 -I -B "$guard" check-dir "$tmp" "$me_uid" x1
check_out 2 "fsguard: check refuses a DATA_ROOT whose parent is missing" "^ERROR: $tmp/absent: no such directory" \
  python3 -I -B "$guard" check "$tmp/absent/srv" "$me_uid" "$me_uid" "$me_uid"
check_out 0 "fsguard: check accepts a missing DATA_ROOT whose parent exists" '^checks: ' \
  python3 -I -B "$guard" check "$tmp/absent" "$me_uid" "$me_uid" "$me_uid"
check_out 2 "fsguard: read-file refuses a missing file" "^ERROR: $tmp/absent\\.env: no such file" \
  python3 -I -B "$guard" read-file "$tmp" absent.env "$me_uid" -1
printf 'NETWORK=sepolia\n' > "$tmp/read.env"
check_out 0 "fsguard: read-file prints the file" '^NETWORK=sepolia$' python3 -I -B "$guard" read-file "$tmp" read.env "$me_uid" -1
head -c 70000 /dev/zero | tr '\0' '#' > "$tmp/big.env"
check_out 2 "fsguard: read-file refuses a file over 64 KiB" 'big\.env: larger than 65536 bytes' \
  python3 -I -B "$guard" read-file "$tmp" big.env "$me_uid" -1
check_out 2 "fsguard: write-file refuses a NAME that is not a file name" "'\.\.': not a file name" python3 -I -B "$guard" write-file "$tmp" .. "$me_uid" -1 < /dev/null
# inspect and same-secret: what preflight.sh and collect-run-log.sh read secrets and the node key
# through. The walk from / follows no symlink, and the file is opened non-blocking and fstat'ed
# before anything else, so only a regular file with one link is ever looked at.
fg="$tmp/fg" && mkdir -m 0700 "$fg"
printf '%s' "$(printf 'a%.0s' $(seq 1 64))" > "$fg/a" && printf '%s' "$(printf 'a%.0s' $(seq 1 64))" > "$fg/b"
printf '%s' "$(printf 'b%.0s' $(seq 1 64))" > "$fg/c" && printf 'nothex' > "$fg/d" && printf 'nothex' > "$fg/e"
chmod 0600 "$fg/a" "$fg/b" "$fg/c" && chmod 0640 "$fg/d"
mkdir -m 0700 "$fg/real" && cp "$fg/a" "$fg/real/k" && ln -s "$fg/real" "$fg/link" && ln -s "$fg/a" "$fg/sym"
cp "$fg/c" "$fg/f" && ln "$fg/c" "$fg/c2"
check_out 0 "fsguard: inspect prints the mode and owner uid" "^600 $me_uid$" python3 -I -B "$guard" inspect "$fg/a"
check_out 0 "fsguard: inspect keeps the mode as it is" "^640 $me_uid$" python3 -I -B "$guard" inspect "$fg/d"
check_out 2 "fsguard: inspect refuses a symlink" "^ERROR: $fg/sym: a symlink or unreadable" python3 -I -B "$guard" inspect "$fg/sym"
check_out 2 "fsguard: inspect refuses a symlinked directory on the way" "^ERROR: $fg/link: a symlink or not a directory" python3 -I -B "$guard" inspect "$fg/link/k"
check_out 2 "fsguard: inspect refuses a hard-linked file" "^ERROR: $fg/c: has 2 hard links$" python3 -I -B "$guard" inspect "$fg/c"
check_out 2 "fsguard: inspect refuses a directory" "^ERROR: $fg/real: not a regular file$" python3 -I -B "$guard" inspect "$fg/real"
check_out 2 "fsguard: inspect names a missing file" "^ERROR: $fg/absent: no such file$" python3 -I -B "$guard" inspect "$fg/absent"
check_out 2 "fsguard: inspect names a missing directory on the way" "^ERROR: $fg/absent/k: no such file$" python3 -I -B "$guard" inspect "$fg/absent/k"
check_out 2 "fsguard: inspect refuses a relative path" '^ERROR: the path must be an absolute path$' python3 -I -B "$guard" inspect rel/k
# inspect-dir: what preflight.sh checks the data directories through, by the same walk.
check_out 0 "fsguard: inspect-dir prints a directory's mode and owner uid" "^700 $me_uid$" python3 -I -B "$guard" inspect-dir "$fg/real"
check_out 2 "fsguard: inspect-dir refuses a symlink to a directory" "^ERROR: $fg/link: a symlink or not a directory" python3 -I -B "$guard" inspect-dir "$fg/link"
check_out 2 "fsguard: inspect-dir refuses a regular file" "^ERROR: $fg/a: a symlink or not a directory" python3 -I -B "$guard" inspect-dir "$fg/a"
check_out 2 "fsguard: inspect-dir refuses a symlinked directory on the way" "^ERROR: $fg/link: a symlink or not a directory" python3 -I -B "$guard" inspect-dir "$fg/link/sub"
check_out 2 "fsguard: inspect-dir names a missing directory" "^ERROR: $fg/absent: no such directory$" python3 -I -B "$guard" inspect-dir "$fg/absent"
check 0 "fsguard: same-secret: two copies of one 64-hex secret" python3 -I -B "$guard" same-secret "$fg/a" "$fg/b"
check 1 "fsguard: same-secret: two different secrets" python3 -I -B "$guard" same-secret "$fg/a" "$fg/f"
check 1 "fsguard: same-secret: equal copies that are not 64 hex characters" python3 -I -B "$guard" same-secret "$fg/d" "$fg/e"
check_out 2 "fsguard: same-secret refuses a symlink" "^ERROR: $fg/sym: a symlink" python3 -I -B "$guard" same-secret "$fg/a" "$fg/sym"
out=$(python3 -I -B "$guard" same-secret "$fg/a" "$fg/f" 2>&1 || true)
if grep -Eq '[0-9a-f]{64}' <<< "$out"; then bad "fsguard: same-secret never prints a secret" "$out"; else ok "fsguard: same-secret never prints a secret"; fi
if [[ -n $bound ]]; then
  mkfifo "$fg/fifo"
  # shellcheck disable=SC2086 # $bound is a command prefix
  check_out 2 "fsguard: inspect refuses a FIFO without blocking" "^ERROR: $fg/fifo: not a regular file$" $bound python3 -I -B "$guard" inspect "$fg/fifo"
  # shellcheck disable=SC2086 # $bound is a command prefix
  check_out 2 "fsguard: same-secret refuses a FIFO without blocking" "^ERROR: $fg/fifo: not a regular file$" $bound python3 -I -B "$guard" same-secret "$fg/a" "$fg/fifo"
else
  echo "# skip - fsguard inspect refuses a FIFO: no timeout command to bound the run"
fi
fi

# --- stubs for preflight.sh and collect-run-log.sh ---------------------------------------------

# Every external command the two scripts call is a stub on PATH: curl serves fixture files by
# API path, ss prints canned output, docker answers image inspect and compose exec.
stubs="$tmp/stubs" http="$tmp/http"
mkdir -p "$stubs" "$http"
export STUB_DIR="$tmp"
cat > "$stubs/curl" <<'SH'
#!/usr/bin/env bash
# curl stub: the URL comes on stdin (--config -); the answer is $STUB_DIR/http/<API path with
# / as _>, the API path being everything from /eth/ or /lighthouse/ on, or the same file under
# $STUB_DIR/http/<URL host>/ when that exists. No file: exit 22.
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
# A provider's own answer, $STUB_DIR/http/<host>/<file>, wins over the shared one.
host=${url#*://} && host=${host%%/*}
f="$STUB_DIR/http/$(printf '%s' "${api#/}" | tr '/' '_')"
if [[ -e $STUB_DIR/http/$host/${f##*/} || -e $STUB_DIR/http/$host/${f##*/}.sh ]]; then f="$STUB_DIR/http/$host/${f##*/}"; fi
# The answer goes to --output, or to stdout without it.
if [[ -n $out ]]; then exec > "$out"; fi
if [[ -x $f.sh ]]; then "$f.sh"; exit; fi   # a generated answer (reads the clock)
[[ -f $f ]] || exit 22
cat "$f"
SH
cat > "$stubs/ss" <<'SH'
#!/usr/bin/env bash
cat "$STUB_DIR/ss.txt"
SH
cat > "$stubs/docker" <<'SH'
#!/usr/bin/env bash
# docker stub, answering from $STUB_DIR/docker/: <svc>.digests and <svc>.image-id for image
# inspect (<svc> is reth when the ref names reth), <svc>.ctr for compose ps -q (absent: not
# running), <ctr>.json (docker inspect) and <ctr>.top for a container. Every call is logged in
# $STUB_DIR/docker.log. compose commands also
# warn on stderr the way compose does about a $ in .env, which must never reach the log.
d=$STUB_DIR/docker
printf '%s\n' "$*" >> "$STUB_DIR/docker.log"
printf '%s\n' "${DOCKER_CONFIG-(unset)}" >> "$STUB_DIR/docker-config.log"
svc_of() { case $1 in *reth*) echo reth ;; *) echo lighthouse ;; esac; }
last=${!#}
if [[ $1 == compose ]]; then
  echo 'WARN[0000] The "SECRETPART" variable is not set. Defaulting to a blank string.' >&2
fi
case "$*" in
  "image inspect --format {{range .RepoDigests}}"*) cat "$d/$(svc_of "$last").digests" ;;
  "image inspect --format {{.Id}} "*) cat "$d/$(svc_of "$last").image-id" ;;
  "inspect "*) cat "$d/$2.json" ;;
  # <ctr>.top.later, when it exists, answers every top after the first (a restarted container).
  "top "*) if [[ -f $d/$2.top.later && -f $d/$2.top.seen ]]; then cat "$d/$2.top.later"; else : > "$d/$2.top.seen"; cat "$d/$2.top"; fi ;;
  # <svc>.ctr.later, when it exists, answers every ps after the first, and <svc>.ctr.final every
  # ps after the second (a container recreated during the samples, or after the listener check).
  "compose "*" ps -q --status running "*)
    n=$(($(cat "$d/$last.ctr.n" 2>/dev/null || echo 0) + 1)); echo "$n" > "$d/$last.ctr.n"
    if [[ -f $d/$last.ctr.final ]] && ((n >= 3)); then cat "$d/$last.ctr.final"
    elif [[ -f $d/$last.ctr.later ]] && ((n >= 2)); then cat "$d/$last.ctr.later"
    else cat "$d/$last.ctr" 2>/dev/null || true; fi ;;
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
  check_out "$expect" "preflight: $desc" "$pattern" env PATH="$tmp/stubs-curl:$PATH" bash "${pf_script:-$preflight}" --test-mode --env-file "$pf_env" "$@"
}
# pf_real <description> <pattern>: preflight.sh without --test-mode; it fails, with the line.
pf_real() {
  check_out 1 "preflight: $1" "$2" env PATH="$tmp/stubs-curl:$PATH" bash "${pf_script:-$preflight}" --env-file "$pf_env"
}
pf_base
pf_case 0 "a set-up host and a matching endpoint pass" '^spec diff: empty \(8 fork versions'
pf_case 0 "the endpoint is named by scheme and host" '^checkpoint provider 1: https://checkpoint\.example\.org$'

# A checkpoint URL reaches Lighthouse's command line (compose.yaml), which any local user reads
# in ps, so one whose path may hold a provider key is refused, and never printed: more than one
# path segment, or one of 16 characters or more. A keyed provider goes behind a local proxy.
keyed=" has a path that may hold a provider key (more than one segment, or one of 16 or more characters; Lighthouse's command line shows it in ps): put the provider behind a local proxy (README.md): FAIL"
# url_case <expect-exit> <description> <key> <url> <fixed line or ''> <secret>: preflight.sh
# with <key> set to <url>; the line, if any, appears, and <secret> is never printed.
url_case() {
  local rc=0 out
  pf_base; set_env "$pf_env" "$3" "$4"
  out=$(PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
  if ((rc == $1)) && { [[ -z $5 ]] || grep -qxF -- "$5" <<< "$out"; } && ! grep -qF -- "$6" <<< "$out"; then
    ok "preflight: $2"
  else
    bad "preflight: $2 (exit $rc, want $1${5:+; want the line '$5'})" "$out"
  fi
}
url_case 1 "a key under a version path is refused" CHECKPOINT_SYNC_URL "https://eth-sepolia.example.com/v2/KEY123secret/" \
  "CHECKPOINT_SYNC_URL: https://eth-sepolia.example.com/…$keyed" KEY123secret
url_case 1 "a 16-character path segment is refused" CHECKPOINT_SYNC_URL "https://cp.example.org/0123456789abcdef" \
  "CHECKPOINT_SYNC_URL: https://cp.example.org/…$keyed" 0123456789abcdef
url_case 1 "provider 2's keyed path is refused too" CHECKPOINT_SYNC_URL_2 "https://cp2.example.net/v1/KEY777secret" \
  "CHECKPOINT_SYNC_URL_2: https://cp2.example.net/…$keyed" KEY777secret
url_case 1 "credentials in a checkpoint URL are refused" CHECKPOINT_SYNC_URL "https://user:KEY123secret@cp.example.org" \
  "CHECKPOINT_SYNC_URL: https://cp.example.org/… has credentials in it (Lighthouse's command line shows them in ps): put the provider behind a local proxy (README.md): FAIL" KEY123secret
url_case 0 "a 15-character path segment passes" CHECKPOINT_SYNC_URL "https://cp.example.org/0123456789abcde" '' 0123456789abcde
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "https://eth-sepolia.example.com/beacon/"
: > "$tmp/curl.log"
pf_case 0 "a one-segment base path passes, named by scheme and host" '^checkpoint provider 1: https://eth-sepolia\.example\.com/…$'
if grep -qx 'https://eth-sepolia.example.com/beacon/eth/v1/config/spec' "$tmp/curl.log"; then
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
pf_case 0 "plain http to a loopback host passes" '^checkpoint provider 1: http://127\.0\.0\.1:5052$'
pf_base; set_env "$pf_env" TRUSTED_PEERS "16Uiu2HAm,not-a-peer"
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
# A $ or backtick replaces the key's line, so the only rule it breaks is the $ rule.
for line in 'export RETH_UID=0' '  RETH_UID=0' 'RETH_UID=1' 'CHECKPOINT_SYNC_URL=https://x.example/$SECRETPART' 'TRUSTED_PEERS=`id`'; do
  pf_base
  case $line in
    *[\$\`]*) set_env "$pf_env" "${line%%=*}" "${line#*=}"; want="line [0-9]+: ${line%%=*} holds a \\$ or a backtick" ;;
    RETH_UID=*) printf '%s\n' "$line" >> "$pf_env"; want='line [0-9]+: RETH_UID set twice' ;;
    *) printf '%s\n' "$line" >> "$pf_env"; want='line [0-9]+: not KEY=value' ;;
  esac
  rc=0; out=$(env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
  if ((rc == 2)) && grep -Eq -- "$want" <<< "$out" &&
    { [[ $want == *'set twice' ]] || ! grep -q 'set twice' <<< "$out"; } &&
    ! grep -q SECRETPART <<< "$out"; then
    ok "preflight: .env line '${line%%=*}=…' is refused"
  else
    bad "preflight: .env line '$line' is refused (exit $rc)" "$out"
  fi
done

# A query or fragment would land after the API path (or hide it): refused, never printed.
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "https://cp.example.org/base?apikey=KEY123secret"
pf_case 1 "a checkpoint URL with a query is refused" '^CHECKPOINT_SYNC_URL: https://cp\.example\.org/… has a query or fragment \(the API path is appended to the URL; put a keyed provider behind a local proxy, README\.md\): FAIL$'
rc=0; out=$(PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if grep -q KEY123secret <<< "$out"; then bad "preflight: the query is never printed" "$out"; else ok "preflight: the query is never printed"; fi
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL "https://cp.example.org/#frag"
pf_case 2 "a checkpoint URL with a fragment is refused (a # in an .env value)" 'line [0-9]+: CHECKPOINT_SYNC_URL holds .* a #'

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
if grep -q KEY999secret <<< "$out"; then bad "preflight: an overriding value is never printed" "$out"; else ok "preflight: an overriding value is never printed"; fi

check 2 "preflight: a missing .env is refused" bash "$preflight" --env-file "$tmp/absent.env"
check 2 "preflight: an unknown option is refused" bash "$preflight" --frobnicate
# A command substitution drops a trailing newline: $'<.env>\n' would check <.env>.
pf_base
check_out 2 "preflight: an --env-file path ending in a newline is refused" '^ERROR: --env-file: the path holds a control character' \
  env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env"$'\n'
check_out 2 "preflight: an --env-file path with a TAB is refused" '^ERROR: --env-file: the path holds a control character' \
  env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$tmp/a"$'\t'"b.env"

# The JWT copies are opened through fsguard (no symlink, non-blocking, a regular file with one
# link), never read by cmp, wc or grep, so a link or a FIFO at a copy fails instead of
# blocking or reading another file.
pf_base; cp "$jwt_r" "$tmp/jwt.keep"; rm "$jwt_r"; ln -s "$tmp/jwt.keep" "$jwt_r"
pf_case 1 "a JWT copy that is a symlink is refused" "reth/jwt\.hex: a symlink or unreadable .*\(want 600 $me_uid\): FAIL$"
pf_case 1 "a symlinked JWT copy fails the secret comparison" '^jwt: .*FAIL$'
rm "$jwt_r"; ln "$tmp/jwt.keep" "$jwt_r"
pf_case 1 "a hard-linked JWT copy is refused" "reth/jwt\.hex: has 2 hard links \(want 600 $me_uid\): FAIL$"
rm "$jwt_r"; cp "$tmp/jwt.keep" "$jwt_r"
if [[ -n $bound ]]; then
  pf_base; rm "$jwt_l"; mkfifo "$jwt_l"
  # shellcheck disable=SC2086 # $bound is a command prefix
  check_out 1 "preflight: a FIFO at a JWT copy is refused without blocking" "lighthouse/jwt\.hex: not a regular file \(want 600 $me_uid\): FAIL$" \
    $bound env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env"
  rm "$jwt_l"; cp "$jwt_r" "$jwt_l"
else
  echo "# skip - preflight refuses a FIFO at a JWT copy: no timeout command to bound the run"
fi
pf_base
# The data directories are opened through fsguard too (inspect-dir: no symlink anywhere on the
# path, and a directory), so a 0700 file or a symlink to a 0700 directory there is no data dir.
mv "$root/reth/data" "$tmp/data.keep" && : > "$root/reth/data" && chmod 0700 "$root/reth/data"
pf_case 1 "a 0700 regular file at a data dir is refused" "^$root/reth/data: a symlink or not a directory .*\\(want 700 $me_uid\\): FAIL$"
rm "$root/reth/data" && ln -s "$tmp/data.keep" "$root/reth/data"
pf_case 1 "a symlink to a 0700 directory at a data dir is refused" "^$root/reth/data: a symlink or not a directory .*\\(want 700 $me_uid\\): FAIL$"
rm "$root/reth/data" && mv "$tmp/data.keep" "$root/reth/data"
pf_case 0 "a data dir that is a 0700 directory passes" "^$root/reth/data: 700 $me_uid: PASS$"

# NETWORK and the ports.
for value in '' mainnet; do
  pf_base; set_env "$pf_env" NETWORK "$value"
  check_out 2 "preflight: NETWORK '$value' is refused" '^ERROR: NETWORK must be sepolia or hoodi' \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env"
done
pf_base; set_env "$pf_env" BEACON_API_PORT abc
pf_case 1 "a port that is not a number is refused" '^BEACON_API_PORT: not a port number \(1-65535\): FAIL$'
pf_base; set_env "$pf_env" ENGINE_PORT 65536
pf_case 1 "port 65536 is refused" '^ENGINE_PORT: not a port number \(1-65535\): FAIL$'
pf_base; set_env "$pf_env" RETH_P2P_PORT 030303
pf_case 1 "a port with a leading zero is refused" '^RETH_P2P_PORT: not a port number'
pf_base; set_env "$pf_env" LIGHTHOUSE_QUIC_PORT 9000
pf_case 1 "two keys on one port are refused" '^LIGHTHOUSE_QUIC_PORT: 9000 is already another port of this node: FAIL$'
pf_base; set_env "$pf_env" ENGINE_PORT ''
pf_case 1 "a missing port is refused" '^ENGINE_PORT: not a port number'
pf_base
pf_case 0 "the configured ports are listed" '^ports: Engine API 127\.0\.0\.1:8551, Beacon API 127\.0\.0\.1:5052, p2p reth 30303 tcp/udp, lighthouse 9000 tcp/udp and 9001 udp$'
pf_case 0 "the free disk space under DATA_ROOT is shown" "^disk: $root: [0-9]+ GiB free$"
pf_base; set_env "$pf_env" RETH_IMAGE "ghcr.io/paradigmxyz/reth:v9.9.9@sha256:$d64"
pf_case 1 "an image README.md has no row for fails" \
  '^release notes: README\.md has no sepolia row for reth v9\.9\.9 at this digest: FAIL$'
pf_base
pf_case 0 "Sepolia: the README release notes say both pinned releases schedule the fork" \
  '^release notes: lighthouse v8\.3\.0-rc\.0 schedules sepolia.s Gloas / Amsterdam fork \(README\.md\): PASS$'

# Two checkpoint providers. Sepolia: the second one is optional, and checked when set.
pf_base
pf_case 0 "Sepolia: one provider is enough" '^CHECKPOINT_SYNC_URL_2: empty \(one checkpoint provider; a second one, run by another operator, cross-checks the anchor\)$'
anchor_fixture() { # anchor_fixture <host 1> <host 2> <spec JSON>: both serve <spec>, and the same finalized block
  rm -rf "${http:?}/$1" "${http:?}/$2"
  mkdir -p "$http/$1" "$http/$2"
  cp "$3" "$http/$1/eth_v1_config_spec" && cp "$3" "$http/$2/eth_v1_config_spec"
  header_json "$http/$1/eth_v1_beacon_headers_finalized" 4235200 "$r1" "$s1"
  header_json "$http/$2/eth_v1_beacon_headers_4235200" 4235200 "$r1" "$s1"
}
anchor_fixture cp1.example.org cp2.example.net "$tmp/real-spec.json"
pf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL https://cp1.example.org; set_env "$pf_env" CHECKPOINT_SYNC_URL_2 https://cp2.example.net/KEY777secret
pf_case 0 "Sepolia: a second provider is checked when set" "^anchor: slot 4235200, block root $r1, state root $s1, the same on both providers: PASS$"
pf_case 0 "Sepolia: the second provider's spec is checked" '^spec: https://cp2\.example\.net/… matches sepolia/config\.yaml: PASS$'
rc=0; out=$(env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if grep -q KEY777secret <<< "$out"; then bad "preflight: the second provider's key is never printed" "$out"; else ok "preflight: the second provider's key is never printed"; fi

# Hoodi: two providers, run by different operators, each on the pinned Hoodi config, and
# both holding provider 1's finalized block with the same block and state root.
hoodi_env="$tmp/hoodi-setup.env" hroot="$tmp/hoodi-root"
# The Hoodi cases run from the fresh copy of the stack, with the Hoodi example's dev pins.
hf_base() {
  pf_script="$copy_ref/preflight.sh"
  cp "$hoodi_env" "$pf_env"
  set_env "$pf_env" CHECKPOINT_SYNC_URL https://cp1.example.org/KEY111secret
  set_env "$pf_env" CHECKPOINT_SYNC_URL_2 https://cp2.example.net
  anchor_fixture cp1.example.org cp2.example.net "$tmp/hoodi-spec.json"
}
hf_base
pf_case 0 "Hoodi: two agreeing providers on the Hoodi config pass" '^preflight OK \(test mode: not a deployment gate\)$'
pf_case 0 "Hoodi: provider 1's spec is checked against the Hoodi config" '^spec: https://cp1\.example\.org/… matches hoodi/config\.yaml: PASS$'
pf_case 0 "Hoodi: provider 2's spec is checked against the Hoodi config" '^spec: https://cp2\.example\.net matches hoodi/config\.yaml: PASS$'
pf_case 0 "Hoodi: the providers are recorded" '^checkpoint provider 2: https://cp2\.example\.net$'
pf_case 0 "Hoodi: the anchor is compared" "^anchor: slot 4235200, block root $r1, state root $s1, the same on both providers: PASS$"
pf_case 0 "Hoodi: its own ports are listed" '^ports: Engine API 127\.0\.0\.1:8552, Beacon API 127\.0\.0\.1:5053, p2p reth 30304 tcp/udp, lighthouse 9002 tcp/udp and 9003 udp$'
# The reviewed dev pins pass: README.md records the fork-schedule check of exactly these
# digests. Anything else is refused: a tag alone, the tag at another digest (a re-push), the
# digest under another tag, and the Sepolia releases, which do not schedule Hoodi's fork.
pf_case 0 "Hoodi: the reth nightly pin is recorded as scheduling the fork" \
  '^release notes: reth nightly schedules hoodi.s Gloas / Amsterdam fork \(README\.md\): PASS$'
pf_case 0 "Hoodi: the Lighthouse latest-unstable pin is recorded as scheduling the fork" \
  '^release notes: lighthouse latest-unstable schedules hoodi.s Gloas / Amsterdam fork \(README\.md\): PASS$'
pf_script=
pf_case 0 "Hoodi: the dev pins pass from the checkout itself too" '^preflight OK \(test mode: not a deployment gate\)$'
hf_base; set_env "$pf_env" LIGHTHOUSE_IMAGE sigp/lighthouse:latest-unstable
pf_case 1 "Hoodi: the latest-unstable tag without a digest is refused" '^LIGHTHOUSE_IMAGE: not pinned as repo:tag@sha256:<64 hex>: FAIL$'
hf_base; set_env "$pf_env" RETH_IMAGE ghcr.io/paradigmxyz/reth:nightly
pf_case 1 "Hoodi: the nightly tag without a digest is refused" '^RETH_IMAGE: not pinned as repo:tag@sha256:<64 hex>: FAIL$'
hf_base; set_env "$pf_env" RETH_IMAGE "ghcr.io/paradigmxyz/reth:nightly@sha256:$d64"
pf_case 1 "Hoodi: the nightly tag at an unrecorded digest is refused" \
  '^release notes: README\.md has no hoodi row for reth nightly at this digest: FAIL$'
hf_base; set_env "$pf_env" LIGHTHOUSE_IMAGE "sigp/lighthouse:latest-unstable@sha256:$d64"
pf_case 1 "Hoodi: the latest-unstable tag at an unrecorded digest is refused" \
  '^release notes: README\.md has no hoodi row for lighthouse latest-unstable at this digest: FAIL$'
hf_base; set_env "$pf_env" LIGHTHOUSE_IMAGE "sigp/lighthouse:latest@sha256:${hoodi_lh##*sha256:}"
pf_case 1 "Hoodi: the reviewed digest under another tag is refused" \
  '^release notes: README\.md has no hoodi row for lighthouse latest at this digest: FAIL$'
hf_base; set_env "$pf_env" RETH_IMAGE "$sepolia_reth"; set_env "$pf_env" LIGHTHOUSE_IMAGE "$sepolia_lh"
pf_case 1 "Hoodi: the Sepolia release pins do not schedule Hoodi's fork, so preflight fails" \
  '^release notes: reth v2\.7\.0 does not schedule hoodi.s Gloas / Amsterdam fork \(README\.md\): replace it before starting: FAIL$'
pf_case 1 "Hoodi: the Sepolia Lighthouse release fails too" '^release notes: lighthouse v8\.3\.0-rc\.0 does not schedule hoodi.s'
# Each service takes only an image from its own repository, checked before any row: the two
# pins swapped between the services are refused on either network, though each has a row (the
# other client's), and so is a reviewed digest under the other client's repository.
pf_reth_repo='^RETH_IMAGE: repository sigp/lighthouse is not reth.s \(want ghcr\.io/paradigmxyz/reth\): FAIL$'
pf_lh_repo='^LIGHTHOUSE_IMAGE: repository ghcr\.io/paradigmxyz/reth is not lighthouse.s \(want sigp/lighthouse\): FAIL$'
hf_base; set_env "$pf_env" RETH_IMAGE "$hoodi_lh"; set_env "$pf_env" LIGHTHOUSE_IMAGE "$hoodi_reth"
pf_case 1 "Hoodi: the Lighthouse dev pin as RETH_IMAGE is refused" "$pf_reth_repo"
pf_case 1 "Hoodi: the reth dev pin as LIGHTHOUSE_IMAGE is refused" "$pf_lh_repo"
pf_base; set_env "$pf_env" RETH_IMAGE "$sepolia_lh"; set_env "$pf_env" LIGHTHOUSE_IMAGE "$sepolia_reth"
pf_case 1 "Sepolia: the Lighthouse release as RETH_IMAGE is refused" "$pf_reth_repo"
pf_case 1 "Sepolia: the reth release as LIGHTHOUSE_IMAGE is refused" "$pf_lh_repo"
hf_base; set_env "$pf_env" RETH_IMAGE "sigp/lighthouse:nightly@sha256:${hoodi_reth##*sha256:}"
pf_case 1 "Hoodi: reth's reviewed digest under Lighthouse's repository is refused" "$pf_reth_repo"
hf_base; set_env "$pf_env" LIGHTHOUSE_IMAGE "ghcr.io/paradigmxyz/reth:latest-unstable@sha256:${hoodi_lh##*sha256:}"
pf_case 1 "Hoodi: Lighthouse's reviewed digest under reth's repository is refused" "$pf_lh_repo"
# A README.md edited by hand on the host (the copy above): its rows vouch for the other client's
# image and for lookalike repositories, and the repository check refuses each of them anyway.
# The pins that belong pass from that copy too.
pf_edited() { # pf_edited <hf_base|pf_base> <key> <image> <description> <pattern>
  "$1"; pf_script="$edited_ref/preflight.sh"; set_env "$pf_env" "$2" "$3"
  pf_case 1 "hand-edited README: $4" "$5"
  pf_script=
}
pf_edited hf_base LIGHTHOUSE_IMAGE "$hoodi_reth" "Hoodi: the reth dev pin in a lighthouse row is refused as LIGHTHOUSE_IMAGE" "$pf_lh_repo"
pf_edited hf_base RETH_IMAGE "$hoodi_lh" "Hoodi: the Lighthouse dev pin in a reth row is refused as RETH_IMAGE" "$pf_reth_repo"
pf_edited pf_base LIGHTHOUSE_IMAGE "$sepolia_reth" "Sepolia: the reth release in a lighthouse row is refused as LIGHTHOUSE_IMAGE" "$pf_lh_repo"
pf_edited pf_base RETH_IMAGE "$sepolia_lh" "Sepolia: the Lighthouse release in a reth row is refused as RETH_IMAGE" "$pf_reth_repo"
pf_edited hf_base RETH_IMAGE "ghcr.io/paradigmxyz/reth-evil:nightly@$hr" "Hoodi: a reth-evil lookalike is refused" \
  '^RETH_IMAGE: repository ghcr\.io/paradigmxyz/reth-evil is not reth.s \(want ghcr\.io/paradigmxyz/reth\): FAIL$'
pf_edited hf_base LIGHTHOUSE_IMAGE "sigp/lighthouse2:latest-unstable@$hl" "Hoodi: a lighthouse2 lookalike is refused" \
  '^LIGHTHOUSE_IMAGE: repository sigp/lighthouse2 is not lighthouse.s \(want sigp/lighthouse\): FAIL$'
pf_edited hf_base LIGHTHOUSE_IMAGE "docker.io/sigp/lighthouse:latest-unstable@$hl" "Hoodi: docker.io/sigp/lighthouse, not the table's spelling, is refused" \
  '^LIGHTHOUSE_IMAGE: repository docker\.io/sigp/lighthouse is not lighthouse.s \(want sigp/lighthouse\): FAIL$'
# An image from the service's own repository whose only row names the other client is still
# refused by its row, with the client that row names.
pf_edited hf_base RETH_IMAGE "ghcr.io/paradigmxyz/reth:edited@sha256:$d64" "Hoodi: a reth image whose row says lighthouse is refused" \
  '^release notes: RETH_IMAGE is a lighthouse image in README\.md.s hoodi table, not reth.s: FAIL$'
hf_base; pf_script="$edited_ref/preflight.sh"
pf_case 0 "hand-edited README: Hoodi: the reviewed dev pins still pass" '^preflight OK \(test mode: not a deployment gate\)$'
pf_base; pf_script="$edited_ref/preflight.sh"
pf_case 0 "hand-edited README: Sepolia: the release pins still pass" '^preflight OK \(test mode: not a deployment gate\)$'
pf_script=
# And Sepolia never takes the Hoodi dev pins: README.md has no Sepolia row for them.
pf_base; set_env "$pf_env" LIGHTHOUSE_IMAGE "$hoodi_lh"
pf_case 1 "Sepolia: the Hoodi Lighthouse dev pin is refused" \
  '^release notes: README\.md has no sepolia row for lighthouse latest-unstable at this digest: FAIL$'
hf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL_2 ''
pf_case 1 "Hoodi: a single provider is refused" '^CHECKPOINT_SYNC_URL_2: empty \(hoodi needs 2 checkpoint providers, run by different operators\): FAIL$'
hf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL_2 https://cp1.example.org/other
pf_case 1 "Hoodi: two URLs on one host are refused" '^CHECKPOINT_SYNC_URL_2: the same host as CHECKPOINT_SYNC_URL \(want providers run by different operators\): FAIL$'
hf_base; set_env "$pf_env" CHECKPOINT_SYNC_URL_2 http://cp2.example.net
pf_case 1 "Hoodi: provider 2 over plain http is refused" '^CHECKPOINT_SYNC_URL_2: http://cp2\.example\.net is not https://'
hf_base; cp "$tmp/hoodi-pre-gloas.json" "$http/cp2.example.net/eth_v1_config_spec"
pf_case 1 "Hoodi: provider 2 without Hoodi's Gloas epoch is refused" '^spec: https://cp2\.example\.net differs from the pinned config: FAIL$'
pf_case 1 "Hoodi: the anchor is not compared after a failed spec" '^anchor: not compared \(a provider failed a check above\)$'
hf_base; cp "$tmp/real-spec.json" "$http/cp1.example.org/eth_v1_config_spec"
pf_case 1 "Hoodi: a provider on the Sepolia config is refused" '^- GENESIS_FORK_VERSION: pinned 0x10000910, node 0x90000069$'
hf_base; header_json "$http/cp2.example.net/eth_v1_beacon_headers_4235200" 4235200 "$r2" "$s1"
pf_case 1 "Hoodi: providers that disagree on the block root are refused" "^anchor: slot 4235200: block root $r1 on provider 1, $r2 on provider 2: FAIL$"
hf_base; header_json "$http/cp2.example.net/eth_v1_beacon_headers_4235200" 4235200 "$r1" "$s2"
pf_case 1 "Hoodi: providers that disagree on the state root are refused" "^anchor: slot 4235200: state root $s1 on provider 1, $s2 on provider 2: FAIL$"
hf_base; rm "$http/cp2.example.net/eth_v1_beacon_headers_4235200"
pf_case 1 "Hoodi: provider 2 without provider 1's finalized slot is refused" '^anchor: could not fetch slot 4235200 from https://cp2\.example\.net \(curl exit 22\): FAIL$'
hf_base; rm "$http/cp1.example.org/eth_v1_beacon_headers_finalized"
pf_case 1 "Hoodi: provider 1 without a finalized header is refused" '^anchor: could not fetch the finalized header from https://cp1\.example\.org/… \(curl exit 22\): FAIL$'
hf_base
rc=0; out=$(env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if grep -q KEY111secret <<< "$out"; then bad "preflight: Hoodi: provider 1's key is never printed" "$out"; else ok "preflight: Hoodi: provider 1's key is never printed"; fi
if ! id -u reth-hoodi >/dev/null 2>&1; then
  hf_base
  pf_real "Hoodi: the users are the network's own (reth-hoodi)" '^user reth-hoodi: does not exist \(run setup.sh\): FAIL$'
fi
pf_script=

# COMPOSE_* keys in .env and COMPOSE_PROJECT_NAME in the environment are refused: compose
# reads them, and COMPOSE_PROJECT_NAME=sepolia-ref would make the Hoodi `up` recreate the
# Sepolia services.
for line in 'COMPOSE_PROJECT_NAME=sepolia-ref' 'COMPOSE_FILE=/tmp/evil.yaml'; do
  pf_base; printf '%s\n' "$line" >> "$pf_env"
  check_out 2 "preflight: '${line%%=*}' in .env is refused" "line [0-9]+: ${line%%=*}: compose reads COMPOSE_\* keys from \.env; none may be set" \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env"
done
pf_base
check_out 2 "preflight: COMPOSE_PROJECT_NAME in the environment is refused" '^ERROR: COMPOSE_PROJECT_NAME is set in the environment' \
  env PATH="$tmp/stubs-curl:$PATH" COMPOSE_PROJECT_NAME=sepolia-ref bash "$preflight" --test-mode --env-file "$pf_env"
check_out 2 "preflight: an empty COMPOSE_PROJECT_NAME in the environment is refused too" '^ERROR: COMPOSE_PROJECT_NAME is set in the environment' \
  env PATH="$tmp/stubs-curl:$PATH" COMPOSE_PROJECT_NAME= bash "$preflight" --test-mode --env-file "$pf_env"
# Any other compose variable, or a docker one, is refused in the environment too: COMPOSE_FILE
# picks the file `up` reads, and DOCKER_HOST, DOCKER_CONTEXT, DOCKER_CONFIG and DOCKER_TLS*
# point docker at another daemon (or its config) than the one checked.
for assignment in COMPOSE_FILE=/tmp/evil.yaml COMPOSE_PROFILES=debug COMPOSE_ENV_FILES=/tmp/x.env \
  DOCKER_HOST=tcp://198.51.100.7:2375 DOCKER_CONTEXT=remote DOCKER_CONFIG=/tmp/dc DOCKER_TLS_VERIFY=1 DOCKER_TLS=1 DOCKER_HOST= \
  DOCKER_CERT_PATH=/tmp/certs DOCKER_DEFAULT_PLATFORM=linux/amd64 DOCKER_BUILDKIT=0 DOCKER_API_VERSION=1.24; do
  check_out 2 "preflight: '$assignment' in the environment is refused" "^ERROR: ${assignment%%=*} is set in the environment; unset it" \
    env PATH="$tmp/stubs-curl:$PATH" "$assignment" bash "$preflight" --test-mode --env-file "$pf_env"
done
for name in DOCKER_HOST DOCKER_CONTEXT; do
  check_out 2 "preflight: with two docker variables set, $name is named" "^ERROR: $name is set in the environment" \
    env PATH="$tmp/stubs-curl:$PATH" DOCKER_HOST=unix:///x DOCKER_CONTEXT=remote bash "$preflight" --test-mode --env-file "$pf_env"
done
check_out 0 "preflight: a docker-unrelated DOCKERFILE variable is not refused" '^preflight OK' \
  env PATH="$tmp/stubs-curl:$PATH" DOCKERFILE=x bash "$preflight" --test-mode --env-file "$pf_env"
# The start line is shell input the operator pastes: every word is quoted (printf %q), so an
# .env path with a blank, $(...) or "-p x" in it stays one argument and runs nothing.
weird="$tmp/a b \$(touch pwned) -p x"
mkdir -m 0700 "$weird" && cp "$pf_env" "$weird/pf.env"
out=$(env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$weird/pf.env" 2>&1) || true
start_line=$(printf '%s\n' "$out" | sed -n 's/^start: //p')
# shellcheck disable=SC2329 # docker is called by the eval'd start line
got=$(cd "$tmp" && docker() { printf '<%s>' "$@"; } && eval "$start_line") || got="(eval failed)"
if [[ $got == "<compose><-p><sepolia-ref><--env-file><$weird/pf.env><-f><$ref/compose.yaml><up><-d>" && ! -e $tmp/pwned ]]; then
  ok "preflight: the start line quotes an .env path with a blank, \$(...) and -p x"
else
  bad "preflight: the start line quotes a hostile .env path (got $got; pwned: $([[ -e $tmp/pwned ]] && echo yes || echo no))" "$start_line"
fi
rm -rf "$tmp/pwned" "$weird"
no_tmpdir 0 "preflight: the caller's TMPDIR is not used" "$tmp/stubs-curl:" bash "$preflight" --test-mode --env-file "$pf_env"
# The .env is read once, through fsguard read-file (the .env directory walk, then a regular
# file with one link, opened O_NOFOLLOW|O_NONBLOCK), like setup.sh reads it.
pfe="$tmp/pfe" && mkdir -m 0700 "$pfe" && cp "$pf_env" "$pfe/target.env" && ln -s target.env "$pfe/link.env"
ln "$pfe/target.env" "$pfe/hard.env"
mkdir -m 0770 "$tmp/pfe-gw" && cp "$pf_env" "$tmp/pfe-gw/.env"
for spec in "link.env|link\.env: a symlink or unreadable" "hard.env|hard\.env: has 2 hard links"; do
  check_out 2 "preflight: an .env ${spec#*|} is refused" "${spec#*|}" \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pfe/${spec%%|*}"
done
check_out 2 "preflight: an .env in a group-writable directory is refused" 'pfe-gw: writable by group or others' \
  env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$tmp/pfe-gw/.env"
if [[ -n $bound ]]; then
  mkfifo -m 0600 "$pfe/fifo.env"
  # shellcheck disable=SC2086 # $bound is a command prefix
  check_out 2 "preflight: an .env that is a FIFO is refused without blocking" 'fifo\.env: not a regular file' \
    $bound env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pfe/fifo.env"
else
  echo "# skip - preflight refuses a FIFO at the .env: no timeout command to bound the run"
fi
pf_case 0 "the start command names the project, the .env and the compose file" \
  "^start: docker compose -p sepolia-ref --env-file $pf_env -f $ref/compose\\.yaml up -d$"

# A DATA_ROOT is data, never program text: with | and ;e in it (GNU sed's e command would run
# the rest, here a script that leaves a file), a missing JWT copy is reported by its literal
# path and nothing runs.
printf '#!/bin/sh\ntouch "%s/pwned"\n' "$tmp" > "$tmp/pwn.sh" && chmod +x "$tmp/pwn.sh"
pf_base; evil_root="$tmp/m|x|;e$tmp/pwn.sh;"
set_env "$pf_env" DATA_ROOT "$evil_root"
rc=0; out=$(env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --test-mode --env-file "$pf_env" 2>&1) || rc=$?
if ((rc == 1)) && [[ ! -e $tmp/pwned ]] && grep -qxF "$evil_root/reth/jwt.hex: no such file (want 600 $me_uid): FAIL" <<< "$out"; then
  ok "preflight: a DATA_ROOT with | and ;e is reported literally and runs nothing"
else
  bad "preflight: a DATA_ROOT with | and ;e (exit $rc, pwned: $([[ -e $tmp/pwned ]] && echo yes || echo no))" "$out"
fi
rm -f "$tmp/pwned"

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
  # The JWT copies and the node key are real files (read through fsguard), so as a normal user
  # both services' ids are the caller's.
  set_env "$cl_env" RETH_UID "$me_uid"; set_env "$cl_env" RETH_GID "$me_gid"
  set_env "$cl_env" LIGHTHOUSE_UID "$me_uid"; set_env "$cl_env" LIGHTHOUSE_GID "$me_gid"
  chmod 0600 "$jwt_r" "$jwt_l"
  rm -rf "$root/lighthouse/data/beacon"; mkdir -p "$root/lighthouse/data/beacon/network"
  printf 'node-key' > "$key_path" && chmod 0600 "$key_path"
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
  printf '%s\n' "$ss_head" "$ss_reth" "$ss_lh" "$ss_p2p" "$ss_rp2p" "$ss_ssh" > "$tmp/ss.txt"
  rm -f "$tmp/docker"/*
  cl_container reth "ghcr.io/paradigmxyz/reth@sha256:$reth_digest" sha256:1111 ctr-reth "$me_uid" "$me_gid" 812
  cl_container lighthouse "sigp/lighthouse@sha256:$lh_digest" sha256:2222 ctr-lh "$me_uid" "$me_gid" 901
}
# cl_container <svc> <repo digest> <image id> <container id> <uid> <gid> <pid>: a running
# container of the pinned image, as <uid>:<gid>, hardened as compose.yaml asks (its docker
# inspect output, with the masked and read-only paths docker sets by default), its process
# <pid> on the host.
cl_container() {
  printf '%s\n' "$2" > "$tmp/docker/$1.digests"
  echo "$3" > "$tmp/docker/$1.image-id"
  echo "$4" > "$tmp/docker/$1.ctr"
  python3 -I -B - "$tmp/docker/$4.json" "$1" "$3" "$5" "$6" "$root" <<'PY'
import json, sys
out, svc, image, uid, gid, root = sys.argv[1:]
json.dump([{
    "Image": image,
    "Config": {"User": f"{uid}:{gid}"},
    "HostConfig": {"ReadonlyRootfs": True, "CapDrop": ["ALL"], "CapAdd": None,
                   "SecurityOpt": ["no-new-privileges:true"], "Privileged": False,
                   "NetworkMode": "host", "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=256m"},
                   "GroupAdd": None, "Devices": None, "PidMode": "", "IpcMode": "private",
                   "UTSMode": "", "CgroupnsMode": "private",
                   "MaskedPaths": ["/proc/acpi", "/proc/kcore", "/proc/keys", "/sys/firmware"],
                   "ReadonlyPaths": ["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"]},
    "Mounts": [
        {"Type": "bind", "Source": f"{root}/{svc}/data", "Destination": "/data", "RW": True},
        {"Type": "bind", "Source": f"{root}/{svc}/jwt.hex", "Destination": "/secrets/jwt.hex", "RW": False},
    ],
}], open(out, "w"))
PY
  printf '%s\n' 'RUID EUID PID COMMAND' "$5 $5 $7 $1" > "$tmp/docker/$4.top"
}
# cl_inspect <container id> <python statement on c, the inspect object>: loosen one setting.
cl_inspect() {
  python3 -I -B - "$tmp/docker/$1.json" "$2" <<'PY'
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
  PATH="$stubs:$PATH" bash "${collect_script:-$collect}" --env-file "$cl_env" "$@" > "$log" 2> "$log.err" || rc=$?
  if ((rc == expect)) && [[ -s $log ]]; then ok "run log: $desc"; else bad "run log: $desc (exit $rc, want $expect)" "$(cat "$log.err")"; fi
}
# cl_quick: one sample, no wait: a diagnostic run, so never an overall PASS (exit 1).
cl_quick() { local desc=$1; shift; cl_run 1 "$desc" --samples 1 --interval 0 "$@"; }
# verdict <criterion number> <PASS|FAIL|DIAGNOSTIC> <description>: the verdict table row.
verdict() {
  if [[ -n $log ]] && grep -Eq "^\| $1 \| .* \| $2 \|$" "$log"; then ok "run log: $3"; else bad "run log: $3 (criterion $1, want $2)" "$(cat "${log:-/dev/null}")"; fi
}
has() { # has <fixed string> <description>
  if [[ -n $log ]] && grep -qF -- "$1" "$log"; then ok "run log: $2"; else bad "run log: $2 (no '$1')" "$(cat "${log:-/dev/null}")"; fi
}

cl_base
cl_run 0 "a synced, hardened node passes (13 samples over 1 h)"
for c in 1 2 3 4 5 6 7 8 9; do verdict "$c" PASS "criterion $c passes on a healthy node"; done
has "- Overall: **PASS**" "the overall verdict is PASS"
has "13 sample(s) taken of 13, first to last 3600 s: acceptance" "the sync run is labelled acceptance"
has "Reth Version: 2.7.0" "records the reth --version output"
has "Lighthouse v8.3.0-rc.0-0123abc" "records the lighthouse --version output"
has "ghcr.io/paradigmxyz/reth@sha256:$reth_digest" "records reth's repo digest"
has "reth container ctr-reth: image sha256:1111, pinned image sha256:1111: PASS" "the running reth container runs the pinned image"
has "reth container ctr-reth: Config.User $me_uid:$me_gid (want $me_uid:$me_gid): PASS" "records the reth container's configured user and group"
has "reth container ctr-reth: processes ruid/euid $me_uid/$me_uid (want $me_uid): PASS" "records the reth container's process uids"
has "reth container ctr-reth: CgroupnsMode \"private\": PASS" "records the private cgroup namespace"
has "reth container ctr-reth: MaskedPaths 4, ReadonlyPaths 5: PASS" "records the masked and read-only paths"
has "lighthouse v8.3.0-rc.0 targets consensus-specs v1.7.0-beta.2 (README.md): spec version differs from ours (v1.7.0-beta.4); recorded, not a FAIL" \
  "records that Lighthouse's consensus-specs version differs from ours, without failing"
has "release notes: reth v2.7.0 schedules sepolia's Gloas / Amsterdam fork (README.md): PASS" "records that the pinned reth schedules the fork"
has "- Network: sepolia; checkpoint providers: https://eth-sepolia.example.com/…" "records the network and the providers, scheme and host only"
has "lighthouse container ctr-lh: ReadonlyRootfs true: PASS" "records the read-only root"
has "lighthouse container ctr-lh: mounts /data <- $root/lighthouse/data (bind, rw); /secrets/jwt.hex <- $root/lighthouse/jwt.hex (bind, ro): PASS" "records the mounts"
if grep -q SECRETPART "$log" "$log.err"; then bad "run log: compose's stderr never reaches the log"; else ok "run log: compose's stderr never reaches the log"; fi
if [[ $(tail -1 "$log.err") == "run log: PASS" ]]; then ok "run log: the verdict line is on stderr"; else bad "run log: the verdict line is on stderr" "$(cat "$log.err")"; fi
has "127.0.0.1:8551" "records the ss line for 8551"
has "$jwt_r: 600 $me_uid: PASS" "records the mode and owner of reth's JWT copy"
has "$key_path: 600 $me_uid: PASS" "records the mode and owner of the node key"
has "reth: no non-loopback TCP listener but p2p port 30303 (pids 812): PASS" "records reth's listeners"
has "reth: container ctr-reth, the one criterion 1 checked, still runs: PASS" "the container criterion 1 checked still runs at the end"
has "lighthouse: p2p listener 0.0.0.0:9000 (pid 901)" "records Lighthouse's p2p listener"
has "spec diff: empty (8 fork versions, 7 fork epochs, 2 blob schedule entries)" "records the empty spec diff"
has "finalized slot 10128, oldest block slot 10000 (anchor.oldest_block_slot): 128 slots: PASS" "a 128-slot finalized range passes"
has "custody_group_count: 4" "records custody_group_count"
has "peer = \"/ip4/34.89.10.7/tcp/9000/p2p/$pid\"" "writes the m2a-session peer line"
# The forward binds loopback only, and ssh exits if another local account holds the port.
has '# Over the tunnel: ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:5052:127.0.0.1:5052 <ref-host>' "the tunnel binds loopback, fails if the port is taken, and returns once it listens"
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
cl_base; printf '%s\n' 'RUID EUID PID COMMAND' "$me_uid 0 812 reth" > "$tmp/docker/ctr-reth.top"
cl_quick "a reth process with euid 0 fails"
verdict 1 FAIL "a process running as root fails criterion 1"
cl_base; cl_inspect ctr-lh 'c["Config"]["User"] = "992:992"'
printf '%s\n' 'RUID EUID PID COMMAND' '992 992 901 lighthouse' > "$tmp/docker/ctr-lh.top"
cl_quick "a lighthouse container as another uid than LIGHTHOUSE_UID fails"
has "(want $me_uid:$me_gid): FAIL" "names the expected uid and gid"
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
hardening "an extra tmpfs" 'tmpfs {"/run": "rw", "/tmp": "rw,noexec,nosuid,nodev,size=256m"}: FAIL' 'c["HostConfig"]["Tmpfs"]["/run"] = "rw"'
hardening "no tmpfs at all" 'reth container ctr-reth: tmpfs {}: FAIL' 'c["HostConfig"]["Tmpfs"] = None'
hardening "a /tmp tmpfs with exec, suid and dev" 'tmpfs {"/tmp": "rw,exec,suid,dev"}: FAIL' 'c["HostConfig"]["Tmpfs"]["/tmp"] = "rw,exec,suid,dev"'
hardening "a /tmp tmpfs without nodev" 'tmpfs {"/tmp": "rw,noexec,nosuid"}: FAIL' 'c["HostConfig"]["Tmpfs"]["/tmp"] = "rw,noexec,nosuid"'
hardening "a /tmp tmpfs whose later exec undoes noexec" 'tmpfs {"/tmp": "noexec,nosuid,nodev,exec"}: FAIL' 'c["HostConfig"]["Tmpfs"]["/tmp"] = "noexec,nosuid,nodev,exec"'
# The identity half of Config.User and every namespace or device that would let a service reach
# the host or another group's files.
hardening "Config.User with group 0" "Config.User $me_uid:0 (want $me_uid:$me_gid): FAIL" 'c["Config"]["User"] = c["Config"]["User"].split(":")[0] + ":0"'
hardening "Config.User with another group than RETH_GID" "Config.User $me_uid:$((me_gid + 1)) (want $me_uid:$me_gid): FAIL" 'c["Config"]["User"] = c["Config"]["User"].split(":")[0] + ":" + str(int(c["Config"]["User"].split(":")[1]) + 1)'
hardening "Config.User without a group" "Config.User $me_uid (want $me_uid:$me_gid): FAIL" 'c["Config"]["User"] = c["Config"]["User"].split(":")[0]'
hardening "a supplementary group" 'reth container ctr-reth: GroupAdd ["0"]: FAIL' 'c["HostConfig"]["GroupAdd"] = ["0"]'
hardening "a host device" 'reth container ctr-reth: Devices ["/dev/sda"]: FAIL' 'c["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm"}]'
hardening "the host PID namespace" 'reth container ctr-reth: PidMode "host": FAIL' 'c["HostConfig"]["PidMode"] = "host"'
hardening "another container's PID namespace" 'PidMode "container:ctr-lh": FAIL' 'c["HostConfig"]["PidMode"] = "container:ctr-lh"'
hardening "the host IPC namespace" 'reth container ctr-reth: IpcMode "host": FAIL' 'c["HostConfig"]["IpcMode"] = "host"'
hardening "the host UTS namespace" 'reth container ctr-reth: UTSMode "host": FAIL' 'c["HostConfig"]["UTSMode"] = "host"'
hardening "the host cgroup namespace" 'reth container ctr-reth: CgroupnsMode "host": FAIL' 'c["HostConfig"]["CgroupnsMode"] = "host"'
hardening "seccomp unconfined" 'SecurityOpt ["no-new-privileges:true", "seccomp=unconfined"]: FAIL' 'c["HostConfig"]["SecurityOpt"].append("seccomp=unconfined")'
hardening "AppArmor unconfined" 'SecurityOpt ["no-new-privileges:true", "apparmor=unconfined"]: FAIL' 'c["HostConfig"]["SecurityOpt"].append("apparmor=unconfined")'
# On a cgroup v1 host docker defaults the cgroup namespace to the host's; compose.yaml sets
# cgroup: private, so the engine reports "private", and anything else fails.
hardening "a cgroup v1 engine's default (CgroupnsMode host, no cgroup: private)" 'reth container ctr-reth: CgroupnsMode "host": FAIL' \
  'c["HostConfig"]["CgroupnsMode"] = "host"; c["HostConfig"]["Cgroup"] = ""'
hardening "no CgroupnsMode at all" 'reth container ctr-reth: CgroupnsMode (none): FAIL' 'del c["HostConfig"]["CgroupnsMode"]'
# security_opt systempaths=unconfined does not show in SecurityOpt: it empties the masked and
# read-only /proc and /sys paths instead.
hardening "systempaths=unconfined (no masked or read-only paths)" 'reth container ctr-reth: MaskedPaths 0, ReadonlyPaths 0: FAIL' \
  'c["HostConfig"]["MaskedPaths"] = []; c["HostConfig"]["ReadonlyPaths"] = []'
hardening "MaskedPaths null" 'MaskedPaths 0, ReadonlyPaths 5: FAIL' 'c["HostConfig"]["MaskedPaths"] = None'
hardening "no ReadonlyPaths" 'MaskedPaths 4, ReadonlyPaths 0: FAIL' 'del c["HostConfig"]["ReadonlyPaths"]'
cl_base; cl_inspect ctr-reth 'c["Mounts"].append({"Type": "tmpfs", "Source": "", "Destination": "/tmp", "RW": True})'
cl_run 0 "a /tmp tmpfs listed among the mounts is fine"

cl_base; set_env "$cl_env" RETH_IMAGE "ghcr.io/paradigmxyz/reth:v9.9.9@sha256:$d64"
cl_container reth "ghcr.io/paradigmxyz/reth@sha256:$d64" sha256:1111 ctr-reth "$me_uid" "$me_gid" 812
cl_quick "an image whose release note README.md does not record fails"
verdict 1 FAIL "an unrecorded release fails the versions criterion"
has "reth v9.9.9: no sepolia row in README.md's release notes for this image: FAIL" "names the release that lacks a note"
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
# Any other public TCP listener of a container's processes fails, whatever its port: an
# override adding reth --http --http.addr=0.0.0.0 opens 8545 on every address.
cl_base; printf '%s\n' "$ss_rpc" >> "$tmp/ss.txt"
cl_quick "reth's HTTP RPC on 0.0.0.0 fails"
verdict 3 FAIL "a public RPC listener fails the localhost criterion"
has "reth: listener 0.0.0.0:8545 (pid 812) is neither on loopback nor a p2p port: FAIL" "names the listener and its process"
cl_base; printf '%s\n' "${ss_rpc/pid=812/pid=901}" >> "$tmp/ss.txt"
cl_quick "a public listener of Lighthouse's process fails"
verdict 3 FAIL "Lighthouse's public listener fails the localhost criterion"
cl_base; printf '%s\n' "$ss_lmet" >> "$tmp/ss.txt"
cl_run 0 "a loopback-only extra listener (metrics) passes"
cl_base; printf '%s\n' 'RUID EUID PID COMMAND' > "$tmp/docker/ctr-reth.top"
cl_quick "a container without processes cannot be matched to its listeners"
has "reth: no container process to match listeners to: FAIL" "says why the listeners were not checked"
# The pids and the sockets are read together, right before the check: a container restarted
# during the hour of sync samples has new pids, and its public RPC must not slip through.
cl_base; printf '%s\n' 'RUID EUID PID COMMAND' "$me_uid $me_uid 1812 reth" > "$tmp/docker/ctr-reth.top.later"
printf '%s\n' "$ss_head" "$ss_reth" "$ss_lh" "$ss_p2p" "${ss_rp2p/pid=812/pid=1812}" "${ss_rpc/pid=812/pid=1812}" > "$tmp/ss.txt"
cl_quick "a container restarted during the run, now with a public RPC, fails"
verdict 3 FAIL "the restarted container's public RPC fails the listener criterion"
has "reth: listener 0.0.0.0:8545 (pid 1812) is neither on loopback nor a p2p port: FAIL" "matches the new pid"
cl_base; printf '%s\n' 'RUID EUID PID COMMAND' "$me_uid $me_uid 1812 reth" > "$tmp/docker/ctr-reth.top.later"
printf '%s\n' "$ss_head" "$ss_reth" "$ss_lh" "$ss_p2p" "${ss_rp2p/pid=812/pid=1812}" > "$tmp/ss.txt"
cl_run 0 "a container restarted during the run is checked by its new pids"
has "reth: no non-loopback TCP listener but p2p port 30303 (pids 1812): PASS" "records the new pids"
has "reth: container ctr-reth, the one criterion 1 checked, still runs: PASS" "a restart keeps the container criterion 1 checked"
# Criterion 1 checks the image, the hardening and the uid once, before the hour of samples; a
# container recreated in that hour (a new id, maybe without the hardening) fails here.
cl_base; echo ctr-reth2 > "$tmp/docker/reth.ctr.later"
cp "$tmp/docker/ctr-reth.json" "$tmp/docker/ctr-reth2.json" && cp "$tmp/docker/ctr-reth.top" "$tmp/docker/ctr-reth2.top"
cl_quick "a container recreated during the run fails"
verdict 3 FAIL "a recreated container fails criterion 3"
has "reth: container ctr-reth2 runs now, not ctr-reth, the one criterion 1 checked (recreated during the run; its image, hardening and uid are unchecked): FAIL" "names both container ids"
has "lighthouse: container ctr-lh, the one criterion 1 checked, still runs: PASS" "the other service's container is unchanged"
cl_base; : > "$tmp/docker/lighthouse.ctr.later"
cl_quick "a container gone by the end of the run fails"
verdict 3 FAIL "a container no longer running fails criterion 3"
has "lighthouse: container ctr-lh, the one criterion 1 checked, no longer runs: FAIL" "says the checked container is gone"
# The ids are compared once more after the last criterion: a container recreated or stopped
# while sections 4 to 8 ran fails too.
cl_base; echo ctr-reth3 > "$tmp/docker/reth.ctr.final"
cp "$tmp/docker/ctr-reth.json" "$tmp/docker/ctr-reth3.json" && cp "$tmp/docker/ctr-reth.top" "$tmp/docker/ctr-reth3.top"
cl_run 1 "a container recreated after the listener check fails the run"
verdict 3 PASS "the listener check still saw the checked container"
verdict 9 FAIL "a container recreated after the listener check fails criterion 9"
has "reth: container ctr-reth3 runs now, not ctr-reth, the one criterion 1 checked (recreated during the run; its image, hardening and uid are unchecked): FAIL" "names the late container"
has "- Overall: **FAIL**" "a late recreate makes the run FAIL"
cl_base; : > "$tmp/docker/lighthouse.ctr.final"
cl_run 1 "a container stopped after the listener check fails the run"
verdict 9 FAIL "a container stopped after the listener check fails criterion 9"
cl_base; sed 's/ *users:.*//' "$tmp/ss.txt" > "$tmp/ss.bare" && mv "$tmp/ss.bare" "$tmp/ss.txt"
cl_quick "an ss without process information fails"
verdict 3 FAIL "listeners that cannot be matched to a process fail"
has "reth: ss -ltnp shows no process for any listener (it needs root): FAIL" "says why"
cl_base; printf '%s\n' "$ss_head" "$ss_reth" "$ss_lh" "$ss_p2p" "$ss_ssh" > "$tmp/ss.txt"
cl_quick "a service none of whose listeners matched fails"
verdict 3 FAIL "reth without a p2p listener fails the listener criterion"
has "reth: no p2p listener on port 30303 among pids 812: FAIL" "names the missing p2p listener"

# compose runs as -p <network>-ref on every call, so COMPOSE_PROJECT_NAME can never pick
# another project, and the scripts refuse it anyway.
cl_base; : > "$tmp/docker.log"
cl_quick "one sample, for the compose calls"
if grep -q '^compose ' "$tmp/docker.log" && ! grep -vq '^compose -p sepolia-ref --env-file ' <<< "$(grep '^compose ' "$tmp/docker.log")"; then
  ok "run log: every compose call passes -p sepolia-ref"
else
  bad "run log: every compose call passes -p sepolia-ref" "$(cat "$tmp/docker.log")"
fi
cl_base; printf '%s\n' COMPOSE_PROJECT_NAME=sepolia-ref >> "$cl_env"
check_out 2 "run log: COMPOSE_PROJECT_NAME in .env is refused" 'COMPOSE_PROJECT_NAME: compose reads COMPOSE_\* keys' \
  env PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0
cl_base
check_out 2 "run log: COMPOSE_PROJECT_NAME in the environment is refused" '^ERROR: COMPOSE_PROJECT_NAME is set in the environment' \
  env PATH="$stubs:$PATH" COMPOSE_PROJECT_NAME=hoodi-ref bash "$collect" --env-file "$cl_env" --samples 1 --interval 0
for assignment in COMPOSE_FILE=/tmp/evil.yaml COMPOSE_PROFILES=debug DOCKER_HOST=tcp://198.51.100.7:2375 \
  DOCKER_CONTEXT=remote DOCKER_CONFIG=/tmp/dc DOCKER_TLS_VERIFY=1 DOCKER_TLS= DOCKER_CERT_PATH=/tmp/certs \
  DOCKER_DEFAULT_PLATFORM=linux/amd64; do
  : > "$tmp/docker.log"
  rc=0; out=$(env PATH="$stubs:$PATH" "$assignment" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0 2>&1) || rc=$?
  if ((rc == 2)) && grep -q "^ERROR: ${assignment%%=*} is set in the environment; unset it" <<< "$out" && [[ ! -s $tmp/docker.log ]]; then
    ok "run log: '$assignment' in the environment is refused before any docker call"
  else
    bad "run log: '$assignment' in the environment is refused (exit $rc)" "$out"
  fi
done
# The .env is read once through fsguard, and compose gets that private copy (--env-file), so
# a symlink, a hard link or a FIFO there is refused before any docker call.
cle="$tmp/cle" && mkdir -m 0700 "$cle" && cp "$cl_env" "$cle/target.env" && ln -s target.env "$cle/link.env"
ln "$cle/target.env" "$cle/hard.env"
[[ -n $bound ]] && mkfifo -m 0600 "$cle/fifo.env"
for spec in "link.env|link\.env: a symlink or unreadable" "hard.env|hard\.env: has 2 hard links" "fifo.env|fifo\.env: not a regular file"; do
  if [[ ${spec%%|*} == fifo.env && -z $bound ]]; then echo "# skip - run log refuses a FIFO at the .env: no timeout command"; continue; fi
  : > "$tmp/docker.log"
  # shellcheck disable=SC2086 # $bound is empty or a command prefix
  rc=0; out=$($bound env PATH="$stubs:$PATH" bash "$collect" --env-file "$cle/${spec%%|*}" --samples 1 --interval 0 2>&1) || rc=$?
  if ((rc == 2)) && grep -Eq "${spec#*|}" <<< "$out" && [[ ! -s $tmp/docker.log ]]; then
    ok "run log: an .env ${spec#*|} is refused before any docker call"
  else
    bad "run log: an .env ${spec#*|} is refused (exit $rc)" "$out"
  fi
done
cl_base; : > "$tmp/docker.log"
cl_quick "one sample, for compose's --env-file"
if grep -q -- "--env-file $cl_env " <<< "$(grep '^compose ' "$tmp/docker.log")"; then
  bad "run log: compose reads the private .env copy, never the .env by path" "$(cat "$tmp/docker.log")"
else
  ok "run log: compose reads the private .env copy, never the .env by path"
fi
cl_base
no_tmpdir 1 "run log: the caller's TMPDIR is not used" "$stubs:" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0
# sudo -E keeps the operator's HOME: every docker call gets DOCKER_CONFIG, the .docker of the
# euid's passwd home, so docker never reads its config or CLI plugins from HOME.
cl_base; : > "$tmp/docker-config.log"
rc=0; HOME="$tmp/evilhome" PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0 > /dev/null 2>&1 || rc=$?
if [[ -s $tmp/docker-config.log && $(sort -u "$tmp/docker-config.log") == "${pw_home%/}/.docker" ]]; then
  ok "run log: every docker call reads DOCKER_CONFIG=<passwd home>/.docker, whatever HOME is"
else
  bad "run log: every docker call reads DOCKER_CONFIG=<passwd home>/.docker (exit $rc)" "$(sort -u "$tmp/docker-config.log")"
fi
# A command substitution drops a trailing newline: $'<.env>\n' would check <.env>.
check_out 2 "run log: an --env-file path ending in a newline is refused" '^ERROR: --env-file: the path holds a control character' \
  env PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env"$'\n' --samples 1 --interval 0

# Values that reach a sed or awk program are data, never program text: a container id with &
# (sed's "the match") is printed as it is.
cl_base; mv "$tmp/docker/ctr-reth.json" "$tmp/docker/ctr&x.json"; mv "$tmp/docker/ctr-reth.top" "$tmp/docker/ctr&x.top"
echo 'ctr&x' > "$tmp/docker/reth.ctr"
cl_quick "a container id with & in it"
has "reth container ctr&x: image sha256:1111, pinned image sha256:1111: PASS" "prints a container id literally"

cl_base; chmod 0644 "$key_path"
cl_quick "a 0644 node key fails"
verdict 4 FAIL "a 0644 node key fails the file-mode criterion"
cl_base; set_env "$cl_env" RETH_UID $((me_uid + 1))
cl_quick "a JWT copy not owned by RETH_UID fails"
verdict 4 FAIL "a JWT copy owned by another uid fails the file-mode criterion"
has "$jwt_r: 600 $me_uid (want 600 $((me_uid + 1))): FAIL" "records the owner it found"
cl_base; rm "$key_path"
cl_quick "a missing node key fails"
has "$key_path: no such file (want 600 $me_uid): FAIL" "records the missing node key"
# The node key and the JWT copies are opened through fsguard: a symlink or a hard link there is
# refused (the collector checked mode and owner only, so a 0600 link passed), a FIFO too.
cl_base; mv "$key_path" "$tmp/key.elsewhere"; ln -s "$tmp/key.elsewhere" "$key_path"
cl_quick "a symlink at the node key fails"
has "$key_path: a symlink or unreadable" "records the refused symlink"
verdict 4 FAIL "a symlinked node key fails the file-mode criterion"
cl_base; ln "$key_path" "$tmp/key.link"
cl_quick "a hard-linked node key fails"
has "$key_path: has 2 hard links (want 600 $me_uid): FAIL" "records the extra link"
rm -f "$tmp/key.link" "$tmp/key.elsewhere"
if [[ -n $bound ]]; then
  cl_base; rm "$key_path"; mkfifo -m 0600 "$key_path"
  n_run=$((${n_run:-0} + 1)); log="$tmp/runlog$n_run.md"; rc=0
  PATH="$stubs:$PATH" $bound bash "$collect" --env-file "$cl_env" --samples 1 --interval 0 > "$log" 2> "$log.err" || rc=$?
  if ((rc == 1)); then ok "run log: a 0600 FIFO at the node key does not block the run"; else bad "run log: a FIFO at the node key (exit $rc)" "$(cat "$log.err")"; fi
  has "$key_path: not a regular file (want 600 $me_uid): FAIL" "records the FIFO"
  verdict 4 FAIL "a FIFO at the node key fails the file-mode criterion"
  rm -f "$key_path"
else
  echo "# skip - run log refuses a FIFO at the node key: no timeout command to bound the run"
fi

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

# NETWORK and the ports, refused before anything runs.
for line in 'NETWORK=mainnet' 'BEACON_API_PORT=5o52' 'LIGHTHOUSE_QUIC_PORT=9000'; do
  cl_base; set_env "$cl_env" "${line%%=*}" "${line#*=}"
  rc=0; out=$(PATH="$stubs:$PATH" bash "$collect" --env-file "$cl_env" --samples 1 --interval 0 2>&1 >/dev/null) || rc=$?
  if ((rc == 2)) && grep -q "^ERROR: " <<< "$out"; then ok "run log: '$line' is refused"; else bad "run log: '$line' is refused (exit $rc)" "$out"; fi
done

# Hoodi: the same stack under its own .env, root, ports and pinned config. The genesis time and
# the slot maths come from the node's own answers.
cl_hoodi() {
  cl_base
  cp "$hoodi_env" "$cl_env"
  set_env "$cl_env" CHECKPOINT_SYNC_URL "https://cp1.example.org/KEY111secret"
  set_env "$cl_env" CHECKPOINT_SYNC_URL_2 "https://cp2.example.net"
  set_env "$cl_env" RETH_UID "$me_uid"; set_env "$cl_env" RETH_GID "$me_gid"
  set_env "$cl_env" LIGHTHOUSE_UID "$me_uid"; set_env "$cl_env" LIGHTHOUSE_GID "$me_gid"
  chmod 0600 "$hroot/reth/jwt.hex" "$hroot/lighthouse/jwt.hex"
  rm -rf "$hroot/lighthouse/data/beacon"; mkdir -p "$hroot/lighthouse/data/beacon/network"
  printf 'node-key' > "$hroot/lighthouse/data/beacon/network/key" && chmod 0600 "$hroot/lighthouse/data/beacon/network/key"
  echo 1793036568 > "$tmp/clock"   # the fork's first slot, 4235264
  echo 1742213400 > "$tmp/genesis_time"
  printf '{"data":{"genesis_time":"1742213400","genesis_validators_root":"0x212f","genesis_fork_version":"0x10000910"}}\n' > "$http/eth_v1_beacon_genesis"
  cp "$tmp/hoodi-spec.json" "$http/eth_v1_config_spec"
  cl_identity "[\"/ip4/34.89.10.7/tcp/9002/p2p/$pid\"]" ',"custody_group_count":"4"'
  printf '%s\n' "$ss_head" "${ss_reth/:8551/:8552}" "${ss_lh/:5052/:5053}" "${ss_p2p/:9000/:9002}" "${ss_rp2p/:30303/:30304}" "$ss_ssh" > "$tmp/ss.txt"
  local saved=$root
  root=$hroot
  rm -f "$tmp/docker"/*
  cl_container reth "ghcr.io/paradigmxyz/reth@sha256:${hoodi_reth##*@sha256:}" sha256:1111 ctr-reth "$me_uid" "$me_gid" 812
  cl_container lighthouse "sigp/lighthouse@sha256:${hoodi_lh##*@sha256:}" sha256:2222 ctr-lh "$me_uid" "$me_gid" 901
  root=$saved
}
cl_hoodi; : > "$tmp/curl.log"; : > "$tmp/docker.log"
collect_script="$copy_ref/collect-run-log.sh"
cl_run 0 "Hoodi: a synced, hardened node on the reviewed dev pins passes" --config "$pinned_hoodi"
collect_script=
for c in 1 2 3 4 5 6 7 8 9; do verdict "$c" PASS "Hoodi: criterion $c passes on a healthy node"; done
has "# Hoodi reference node run log" "Hoodi: the title names the network"
if grep -q '^compose -p hoodi-ref --env-file ' "$tmp/docker.log" && ! grep -vq '^compose -p hoodi-ref ' <<< "$(grep '^compose ' "$tmp/docker.log")"; then
  ok "run log: Hoodi: every compose call passes -p hoodi-ref"
else
  bad "run log: Hoodi: every compose call passes -p hoodi-ref" "$(cat "$tmp/docker.log")"
fi
has "lighthouse latest-unstable targets consensus-specs v1.7.0-beta.4 (README.md), the same as ours" "Hoodi: a Lighthouse on our consensus-specs version is recorded as the same"
has "release notes: reth nightly schedules hoodi's Gloas / Amsterdam fork (README.md): PASS" "Hoodi: the reth dev pin is recorded as scheduling the fork"
has "ghcr.io/paradigmxyz/reth@sha256:${hoodi_reth##*@sha256:}" "Hoodi: records reth's repo digest"
has "- Network: hoodi; checkpoint providers: https://cp1.example.org/…, https://cp2.example.net" "Hoodi: records both providers"
has "head_slot 4235264, wall-clock slot 4235264 (lag 0)" "Hoodi: the wall-clock slot comes from the node's genesis time"
has "port 8552: 127.0.0.1 only: PASS" "Hoodi: the Engine API is checked on its own port"
has "port 5053: 127.0.0.1 only: PASS" "Hoodi: the Beacon API is checked on its own port"
has "lighthouse: no non-loopback TCP listener but p2p port 9002 (pids 901): PASS" "Hoodi: Lighthouse's own p2p port is the allowed one"
has "reth: no non-loopback TCP listener but p2p port 30304 (pids 812): PASS" "Hoodi: reth's own p2p port is the allowed one"
has "$hroot/lighthouse/data/beacon/network/key: 600 $me_uid: PASS" "Hoodi: the node key under its own DATA_ROOT"
has 'network = "hoodi"' "Hoodi: the session config names the network"
has "peer = \"/ip4/34.89.10.7/tcp/9002/p2p/$pid\"" "Hoodi: the multiaddr carries the configured p2p port"
has '# Over the tunnel: ssh -f -N -o ExitOnForwardFailure=yes -L 127.0.0.1:5053:127.0.0.1:5053 <ref-host>' "Hoodi: the tunnel uses the configured Beacon API port, on loopback only"
if grep -qx 'http://127.0.0.1:5053/eth/v1/node/syncing' "$tmp/curl.log" && ! grep -q ':5052/' "$tmp/curl.log"; then
  ok "run log: Hoodi: every Beacon API request goes to the configured port"
else
  bad "run log: Hoodi: every Beacon API request goes to the configured port" "$(cat "$tmp/curl.log")"
fi
if grep -q KEY111secret "$log"; then bad "run log: Hoodi: provider 1's key is never printed"; else ok "run log: Hoodi: provider 1's key is never printed"; fi
# The Sepolia releases on Hoodi: neither schedules Hoodi's fork, so the versions criterion fails.
cl_hoodi
set_env "$cl_env" RETH_IMAGE "$sepolia_reth"; set_env "$cl_env" LIGHTHOUSE_IMAGE "$sepolia_lh"
root_saved=$root root=$hroot
cl_container reth "ghcr.io/paradigmxyz/reth@sha256:$reth_digest" sha256:1111 ctr-reth "$me_uid" "$me_gid" 812
cl_container lighthouse "sigp/lighthouse@sha256:$lh_digest" sha256:2222 ctr-lh "$me_uid" "$me_gid" 901
root=$root_saved
cl_run 1 "Hoodi: releases whose notes do not schedule Hoodi's fork fail"
verdict 1 FAIL "Hoodi: a release that does not schedule the fork fails criterion 1"
verdict 5 PASS "Hoodi: the default pinned config is the network's own"
has "release notes: reth v2.7.0 does not schedule hoodi's Gloas / Amsterdam fork (README.md): FAIL" "Hoodi: names the reth release"
has "release notes: lighthouse v8.3.0-rc.0 does not schedule hoodi's Gloas / Amsterdam fork (README.md): FAIL" "Hoodi: names the Lighthouse release"
has 'Release notes (from ops/ref-node/README.md, hoodi):' "Hoodi: copies the Hoodi release-note table"
# cl_swapped: the two pins swapped between the services. Each image is pulled, and each
# container runs the image its service's variable names (the stub's ids: 1111 for the reth ref,
# 2222 for the Lighthouse one), so only the client check can fail criterion 1.
cl_swapped() {
  local image
  image=$(env_get "$cl_env" RETH_IMAGE)
  set_env "$cl_env" RETH_IMAGE "$(env_get "$cl_env" LIGHTHOUSE_IMAGE)"; set_env "$cl_env" LIGHTHOUSE_IMAGE "$image"
  cl_inspect ctr-reth 'c["Image"] = "sha256:2222"'; cl_inspect ctr-lh 'c["Image"] = "sha256:1111"'
}
cl_reth_repo="RETH_IMAGE: repository sigp/lighthouse is not reth's (want ghcr.io/paradigmxyz/reth): FAIL"
cl_lh_repo="LIGHTHOUSE_IMAGE: repository ghcr.io/paradigmxyz/reth is not lighthouse's (want sigp/lighthouse): FAIL"
cl_hoodi; cl_swapped
cl_quick "Hoodi: the two dev pins swapped between the services fail" --config "$pinned_hoodi"
verdict 1 FAIL "Hoodi: swapped pins fail criterion 1"
has "$cl_reth_repo" "Hoodi: names the Lighthouse repository pinned for reth"
has "$cl_lh_repo" "Hoodi: names the reth repository pinned for Lighthouse"
has "reth container ctr-reth: image sha256:2222, pinned image sha256:2222: PASS" "Hoodi: the swapped containers run the images their variables name"
cl_base; cl_swapped
cl_quick "Sepolia: the two release pins swapped between the services fail"
verdict 1 FAIL "Sepolia: swapped pins fail criterion 1"
has "$cl_reth_repo" "Sepolia: names the Lighthouse repository pinned for reth"
has "$cl_lh_repo" "Sepolia: names the reth repository pinned for Lighthouse"
cl_hoodi; set_env "$cl_env" RETH_IMAGE "sigp/lighthouse:nightly@sha256:${hoodi_reth##*sha256:}"
printf '%s\n' "sigp/lighthouse@sha256:${hoodi_reth##*sha256:}" >> "$tmp/docker/lighthouse.digests"
cl_quick "Hoodi: reth's reviewed digest under Lighthouse's repository fails" --config "$pinned_hoodi"
verdict 1 FAIL "Hoodi: a digest under the other client's repository fails criterion 1"
has "$cl_reth_repo" "Hoodi: names the repository that is not reth's"
# A README.md edited by hand on the host (the copy above): a row vouches for the reth dev pin as
# Lighthouse's, or for a lookalike repository. The container runs the image its variable names
# (the stub's ids: 1111 for a ref naming reth, 2222 otherwise) and every digest matches, so only
# the repository check can fail criterion 1; no row is consulted for that image.
collect_script="$edited_ref/collect-run-log.sh"
cl_hoodi; set_env "$cl_env" LIGHTHOUSE_IMAGE "$hoodi_reth"; cl_inspect ctr-lh 'c["Image"] = "sha256:1111"'
cl_quick "hand-edited README: Hoodi: the reth dev pin in a lighthouse row fails as LIGHTHOUSE_IMAGE" --config "$pinned_hoodi"
verdict 1 FAIL "hand-edited README: the reth dev pin as LIGHTHOUSE_IMAGE fails criterion 1"
has "$cl_lh_repo" "hand-edited README: names the reth repository pinned for Lighthouse"
has "lighthouse container ctr-lh: image sha256:1111, pinned image sha256:1111: PASS" "hand-edited README: the container runs the image LIGHTHOUSE_IMAGE names"
if grep -q "^release notes: lighthouse nightly " "$log"; then bad "run log: hand-edited README: no row is read for an image from the wrong repository" "$(cat "$log")"; else ok "run log: hand-edited README: no row is read for an image from the wrong repository"; fi
cl_sepolia_swap() { cl_base; set_env "$cl_env" RETH_IMAGE "$sepolia_lh"; cl_inspect ctr-reth 'c["Image"] = "sha256:2222"'; }
cl_sepolia_swap
cl_quick "hand-edited README: Sepolia: the Lighthouse release in a reth row fails as RETH_IMAGE"
verdict 1 FAIL "hand-edited README: the Lighthouse release as RETH_IMAGE fails criterion 1"
has "$cl_reth_repo" "hand-edited README: names the Lighthouse repository pinned for reth"
for spec in "RETH_IMAGE|ghcr.io/paradigmxyz/reth-evil:nightly@$hr|ghcr.io/paradigmxyz/reth-evil|reth|ghcr.io/paradigmxyz/reth" \
  "LIGHTHOUSE_IMAGE|sigp/lighthouse2:latest-unstable@$hl|sigp/lighthouse2|lighthouse|sigp/lighthouse" \
  "LIGHTHOUSE_IMAGE|docker.io/sigp/lighthouse:latest-unstable@$hl|docker.io/sigp/lighthouse|lighthouse|sigp/lighthouse"; do
  IFS='|' read -r key image got svc want <<< "$spec"
  cl_hoodi; set_env "$cl_env" "$key" "$image"
  cl_quick "hand-edited README: Hoodi: the lookalike $got fails" --config "$pinned_hoodi"
  verdict 1 FAIL "hand-edited README: the lookalike $got fails criterion 1"
  has "$key: repository $got is not $svc's (want $want): FAIL" "hand-edited README: names the lookalike $got"
done
cl_hoodi
cl_run 0 "hand-edited README: Hoodi: the reviewed dev pins still pass" --config "$pinned_hoodi"
collect_script=
cl_hoodi; cp "$tmp/hoodi-pre-gloas.json" "$http/eth_v1_config_spec"
cl_quick "Hoodi: a node without Hoodi's Gloas epoch fails" --config "$pinned_hoodi"
verdict 5 FAIL "Hoodi: a spec difference fails the spec criterion"
has "- GLOAS_FORK_EPOCH: pinned 132352, node 18446744073709551615" "Hoodi: records the spec diff"

rm -f "$tmp/clock"

fi

# --- compose.yaml -------------------------------------------------------------------------------

compose_env() { # compose_env <file> <trusted peers> [example]: an .env example with the required values set.
  local key
  cp "$ref/${3:-.env.example}" "$1"
  set_env "$1" CHECKPOINT_SYNC_URL 'https://cp.example.org/v1/KEY?a=1&b=two words'
  set_env "$1" TRUSTED_PEERS "$2"
  for key in RETH_UID RETH_GID; do set_env "$1" "$key" 990; done
  for key in LIGHTHOUSE_UID LIGHTHOUSE_GID; do set_env "$1" "$key" 991; done
}
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "# skip - compose.yaml checks: docker compose is not installed"
else
  # Compose stops at the first missing variable. In compose.yaml that is RETH_UID
  # (the service user), so the example file's error is the ids one, checked next.
  # With the ids filled in, the empty CHECKPOINT_SYNC_URL is what remains.
  cp "$ref/.env.example" "$tmp/compose-no-checkpoint.env"
  for key in RETH_UID RETH_GID; do set_env "$tmp/compose-no-checkpoint.env" "$key" 990; done
  for key in LIGHTHOUSE_UID LIGHTHOUSE_GID; do set_env "$tmp/compose-no-checkpoint.env" "$key" 991; done
  check_out 1 "compose: .env.example alone is refused until CHECKPOINT_SYNC_URL is set" \
    'CHECKPOINT_SYNC_URL is missing a value' \
    docker compose --env-file "$tmp/compose-no-checkpoint.env" -f "$ref/compose.yaml" config --quiet
  check_out 1 "compose: .env.example alone is refused until setup.sh wrote the ids" \
    'RETH_UID is missing a value: run setup.sh' \
    docker compose --env-file "$ref/.env.example" -f "$ref/compose.yaml" config --quiet
  compose_env "$tmp/compose.env" ""
  check 0 "compose: config validates with the required values set" \
    docker compose --env-file "$tmp/compose.env" -f "$ref/compose.yaml" config --quiet
  docker compose --env-file "$tmp/compose.env" -f "$ref/compose.yaml" config --format json > "$tmp/compose.json"
  # compose_rule <description> <python expression over c (the config) and s (its services)>
  compose_rule() {
    check 0 "compose: $1" python3 -I -B -c '
import json, sys
c = json.load(open(sys.argv[1])); s = c["services"]
sys.exit(0 if eval(sys.argv[2]) else 1)' "$tmp/compose.json" "$2"
  }
  compose_rule "exactly the reth and lighthouse services" 'sorted(s) == ["lighthouse", "reth"]'
  compose_rule "host networking for both" 'all(v["network_mode"] == "host" for v in s.values())'
  compose_rule "the project is named after the network" 'c["name"] == "sepolia-ref"'
  compose_rule "a private cgroup namespace for both (a cgroup v1 host defaults to the host's)" \
    'all(v.get("cgroup") == "private" for v in s.values())'
  compose_rule "read-only root, cap_drop ALL, no-new-privileges, /tmp tmpfs" \
    'all(v["read_only"] and v["cap_drop"] == ["ALL"] and v["security_opt"] == ["no-new-privileges:true"] and any(t.startswith("/tmp:") for t in v["tmpfs"]) for v in s.values())'
  compose_rule "restart unless-stopped, rotated json-file logs" \
    'all(v["restart"] == "unless-stopped" and v["logging"]["driver"] == "json-file" and {"max-size", "max-file"} <= set(v["logging"]["options"]) for v in s.values())'
  compose_rule "each service as its own user from .env" 's["reth"]["user"] == "990:990" and s["lighthouse"]["user"] == "991:991"'
  compose_rule "reth gets at least 5 minutes to stop" 's["reth"]["stop_grace_period"].startswith("5m")'
  compose_rule "pinned images from .env" 'all("@sha256:" in v["image"] for v in s.values())'
  compose_rule "each JWT copy mounted read-only from its own directory, no host path created" \
    'all(any(m["target"] == "/secrets/jwt.hex" and m.get("read_only") and m["source"].endswith(n + "/jwt.hex") for m in s[n]["volumes"]) and all((m.get("bind") or {}).get("create_host_path", False) is False for m in s[n]["volumes"]) for n in s)'
  compose_rule "reth: Engine API on 127.0.0.1:8551 with the JWT, --full, Sepolia" \
    'all(a in s["reth"]["command"] for a in ["--authrpc.addr=127.0.0.1", "--authrpc.port=8551", "--authrpc.jwtsecret=/secrets/jwt.hex", "--full", "--chain=sepolia", "--ipcdisable"])'
  compose_rule "reth: p2p and discovery on RETH_P2P_PORT" \
    'all(a in s["reth"]["command"] for a in ["--port=30303", "--discovery.port=30303"])'
  compose_rule "the data and JWT mounts come from DATA_ROOT" \
    'all(m["source"].startswith("/srv/ethswarm-ref/" + n + "/") for n in s for m in s[n]["volumes"])'
  compose_rule "reth: no HTTP or WS RPC, metrics only if on loopback" \
    'not any(a.startswith(("--http", "--ws")) for a in s["reth"]["command"]) and all(a.startswith("--metrics=127.0.0.1:") for a in s["reth"]["command"] if a.startswith("--metrics"))'
  compose_rule "lighthouse starts after reth" '"reth" in s["lighthouse"]["depends_on"]'

  # compose and the scripts read an .env env_check accepts the same way: every value compose
  # renders is the one env_get returns. A line env_check refuses shows why: compose keeps reading
  # after a closing quote and takes a second assignment the scripts never see.
  cp "$ref/.env.example" "$tmp/agree.env"
  set_env "$tmp/agree.env" CHECKPOINT_SYNC_URL https://cp.example.org/v1
  set_env "$tmp/agree.env" TRUSTED_PEERS "$pid,$pid"
  for key in RETH_UID RETH_GID; do set_env "$tmp/agree.env" "$key" 990; done
  for key in LIGHTHOUSE_UID LIGHTHOUSE_GID; do set_env "$tmp/agree.env" "$key" 991; done
  check 0 "compose: the agreement .env passes env_check" env_check "$tmp/agree.env"
  # agree <env file> <description>: compose config against env_get, key by key.
  agree() {
    local want
    want=$(for key in NETWORK RETH_IMAGE LIGHTHOUSE_IMAGE CHECKPOINT_SYNC_URL TRUSTED_PEERS DATA_ROOT RETH_UID RETH_GID LIGHTHOUSE_UID LIGHTHOUSE_GID $PORT_KEYS; do
      printf '%s=%s\n' "$key" "$(env_get "$1" "$key")"; done)
    docker compose --env-file "$1" -f "$ref/compose.yaml" config --format json > "$tmp/agree.json" 2>/dev/null
    python3 -I -B - "$tmp/agree.json" > "$tmp/agree.got" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))["services"]
r, l = s["reth"], s["lighthouse"]
e = l["environment"]
ru, rg = r["user"].split(":"); lu, lg = l["user"].split(":")
root = r["volumes"][0]["source"][: -len("/reth/data")]
got = {"NETWORK": e["NETWORK"], "RETH_IMAGE": r["image"], "LIGHTHOUSE_IMAGE": l["image"],
       "CHECKPOINT_SYNC_URL": e["CHECKPOINT_SYNC_URL"], "TRUSTED_PEERS": e.get("TRUSTED_PEERS") or "",
       "DATA_ROOT": root, "RETH_UID": ru, "RETH_GID": rg, "LIGHTHOUSE_UID": lu, "LIGHTHOUSE_GID": lg,
       "ENGINE_PORT": e["ENGINE_PORT"], "BEACON_API_PORT": e["BEACON_API_PORT"],
       "RETH_P2P_PORT": next(a.split("=", 1)[1] for a in r["command"] if a.startswith("--port=")),
       "LIGHTHOUSE_P2P_PORT": e["LIGHTHOUSE_P2P_PORT"], "LIGHTHOUSE_QUIC_PORT": e["LIGHTHOUSE_QUIC_PORT"]}
for k, v in got.items():
    print(f"{k}={v}")
PY
    if [[ $(cat "$tmp/agree.got") == "$want" ]]; then ok "compose: $2"; else bad "compose: $2" "$(diff <(printf '%s\n' "$want") "$tmp/agree.got")"; fi
  }
  agree "$tmp/agree.env" "renders every value env_get reads from an accepted .env"
  cp "$tmp/agree.env" "$tmp/smuggle.env" && printf "%s\n" "DUMMY=''RETH_UID=0" >> "$tmp/smuggle.env"
  docker compose --env-file "$tmp/smuggle.env" -f "$ref/compose.yaml" config --format json > "$tmp/smuggle.json" 2>/dev/null
  if python3 -I -B -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1]))["services"]["reth"]["user"].startswith("0:") else 1)' "$tmp/smuggle.json" &&
    [[ $(env_get "$tmp/smuggle.env" RETH_UID) == 990 ]] && ! env_check "$tmp/smuggle.env" >/dev/null; then
    ok "compose: DUMMY=''RETH_UID=0 would run reth as uid 0 under compose, and env_check refuses it"
  else
    bad "compose: DUMMY=''RETH_UID=0 (compose user $(python3 -I -B -c 'import json, sys; print(json.load(open(sys.argv[1]))["services"]["reth"]["user"])' "$tmp/smuggle.json" 2>&1))"
  fi

  # The Lighthouse wrapper, run by bash as the container would, against a stub lighthouse that
  # prints its argv one per line.
  mkdir -p "$tmp/lh-bin"
  printf '#!/usr/bin/env bash\necho "umask $(umask)"\nprintf "%%s\\n" "$@"\n' > "$tmp/lh-bin/lighthouse"
  chmod +x "$tmp/lh-bin/lighthouse"
  # lh_argv <compose env file>: the argv the wrapper hands Lighthouse.
  lh_argv() {
    docker compose --env-file "$1" -f "$ref/compose.yaml" config --format json > "$tmp/lh.json"
    python3 -I -B - "$tmp/lh.json" "$tmp/lh-bin" <<'PY'
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
    --execution-jwt /secrets/jwt.hex --http --http-address 127.0.0.1 --http-port 5052 --port 9000 --quic-port 9001 \
    --disable-upnp --checkpoint-sync-url 'https://cp.example.org/v1/KEY?a=1&b=two words')
  if [[ $argv == "$want" ]]; then ok "compose: lighthouse argv without TRUSTED_PEERS (umask 077, no --trusted-peers, URL intact)"; else bad "compose: lighthouse argv without TRUSTED_PEERS" "$argv"; fi
  compose_env "$tmp/compose-peers.env" "$pid,$pid"
  argv=$(lh_argv "$tmp/compose-peers.env")
  if [[ $argv == "$(printf '%s\n' "$want" --trusted-peers "$pid,$pid")" ]]; then ok "compose: TRUSTED_PEERS adds --trusted-peers <list>"; else bad "compose: TRUSTED_PEERS adds --trusted-peers <list>" "$argv"; fi

  # Every compose variable without a default must be set: NETWORK, DATA_ROOT and the ports.
  for key in NETWORK DATA_ROOT ENGINE_PORT BEACON_API_PORT RETH_P2P_PORT LIGHTHOUSE_P2P_PORT LIGHTHOUSE_QUIC_PORT; do
    compose_env "$tmp/compose-missing.env" ""
    set_env "$tmp/compose-missing.env" "$key" ""
    check_out 1 "compose: an empty $key is refused" "$key is missing a value" \
      docker compose --env-file "$tmp/compose-missing.env" -f "$ref/compose.yaml" config --quiet
  done

  # Hoodi, from its own example: its project, chain, ports and DATA_ROOT, nothing of Sepolia's.
  compose_env "$tmp/compose-hoodi.env" "" .env.hoodi.example
  check 0 "compose: the Hoodi example validates with the required values set" \
    docker compose --env-file "$tmp/compose-hoodi.env" -f "$ref/compose.yaml" config --quiet
  docker compose --env-file "$tmp/compose-hoodi.env" -f "$ref/compose.yaml" config --format json > "$tmp/compose.json"
  compose_rule "Hoodi: the project is hoodi-ref" 'c["name"] == "hoodi-ref"'
  compose_rule "Hoodi: reth on the Hoodi chain, Engine API 127.0.0.1:8552, p2p 30304" \
    'all(a in s["reth"]["command"] for a in ["--chain=hoodi", "--authrpc.addr=127.0.0.1", "--authrpc.port=8552", "--port=30304", "--discovery.port=30304"])'
  compose_rule "Hoodi: the mounts come from its own DATA_ROOT" \
    'all(m["source"].startswith("/srv/ethswarm-ref-hoodi/" + n + "/") for n in s for m in s[n]["volumes"])'
  compose_rule "Hoodi: a private cgroup namespace too" 'all(v.get("cgroup") == "private" for v in s.values())'
  argv=$(lh_argv "$tmp/compose-hoodi.env")
  want_hoodi=$(printf '%s\n' 'umask 0077' bn --network hoodi --datadir /data --execution-endpoint http://127.0.0.1:8552 \
    --execution-jwt /secrets/jwt.hex --http --http-address 127.0.0.1 --http-port 5053 --port 9002 --quic-port 9003 \
    --disable-upnp --checkpoint-sync-url 'https://cp.example.org/v1/KEY?a=1&b=two words')
  if [[ $argv == "$want_hoodi" ]]; then ok "compose: Hoodi: lighthouse argv (network, Engine and Beacon API ports, p2p and QUIC ports)"; else bad "compose: Hoodi: lighthouse argv" "$argv"; fi
  # A port value reaches Lighthouse's bash wrapper only as one quoted word, never as code.
  set_env "$tmp/compose-hoodi.env" BEACON_API_PORT '5053;touch /tmp/pwned'
  argv=$(lh_argv "$tmp/compose-hoodi.env")
  if grep -qx -- '5053;touch /tmp/pwned' <<< "$argv" && [[ ! -e /tmp/pwned ]]; then
    ok "compose: a port value is passed to Lighthouse as one word, not run"
  else
    bad "compose: a port value is passed to Lighthouse as one word" "$argv"
  fi
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
  # The .env must be owned by root, the euid or the sudo user: another user's file there is
  # refused (read-file), even in a root-owned directory.
  mkdir -m 0700 "$tmp/foreign-env" && cp "$ref/.env.example" "$tmp/foreign-env/.env" && chown 65534 "$tmp/foreign-env/.env"
  check_out 2 "root: setup refuses an .env owned by another user" 'foreign-env/\.env: owned by uid 65534' \
    env -u SUDO_UID bash "$setup" --env-file "$tmp/foreign-env/.env" --root "$tmp/foreign-root"
  check_out 2 "root: fsguard read-file refuses a file owned by another uid" 'owned by uid 65534' \
    python3 -I -B "$ref/lib/fsguard.py" read-file "$tmp/foreign-env" .env 0 -1
  check_out 0 "root: fsguard read-file accepts the sudo user's file" '^NETWORK=sepolia$' \
    python3 -I -B "$ref/lib/fsguard.py" read-file "$tmp/foreign-env" .env 0 65534
  check_out 2 "root: preflight refuses an .env owned by another user" 'owned by uid 65534' \
    env -u SUDO_UID PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$tmp/foreign-env/.env"
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
  # setup.sh's fsguard.py calls, in order: 1 read-file (.env), 2 check (DATA_ROOT), 3 check-dir
  # (the .env directory), 4 install, 5 write-file (.env).
  # Regression (DATA_ROOT ancestor swap): DATA_ROOT is swapped for a symlink to a victim tree
  # just before fsguard call n; nothing outside DATA_ROOT may change, and setup.sh must not
  # report success. At call 2 another user owns the directory above DATA_ROOT (the attacker
  # who can swap it). At calls 3 and 4 that directory is root's, so the check passes and the
  # swap lands between it and install's own walk, which must not follow the symlink. Every
  # case proves the swap ran.
  for spec in "2 65534" "3 0" "4 0"; do
    read -r n owner <<< "$spec"
    a="$tmp/race2-$n/a" v="$tmp/race2-$n/victim"
    mkdir -p "$a/node" "$v/reth" && chown "$owner" "$a" && chmod 0755 "$a" "$a/node" "$v/reth"
    hooked "$n" "mv '$a/node' '$a/saved' && ln -s '$v' '$a/node'"
    cp "$ref/.env.example" "$tmp/race2.env"
    rc=0; out=$(PATH="$tmp/hook:$PATH" bash "$setup" --env-file "$tmp/race2.env" --root "$a/node" 2>&1) || rc=$?
    if ((rc != 0)) && [[ -L $a/node && $(cat "$tmp/hook/count") -ge $n ]] &&
      [[ $(file_mode_uid "$v/reth") == "755 0" && -z $(ls -A "$v/reth") && $(ls -A "$v") == reth ]]; then
      ok "root: regression: DATA_ROOT swapped for a symlink before fsguard call $n changes nothing outside it"
    else
      bad "root: regression: DATA_ROOT swapped before fsguard call $n (exit $rc, calls $(cat "$tmp/hook/count" 2>/dev/null), victim: $(find "$v" -exec stat -c '%a %U %n' {} \; 2>/dev/null | tr '\n' ' '))" "$out"
    fi
  done
  # A service user swaps its data dir for a symlink between the checks and the changes.
  r="$tmp/swap-data"
  cp "$ref/.env.example" "$tmp/swap.env"
  bash "$setup" --env-file "$tmp/swap.env" --root "$r" >/dev/null 2>&1
  hooked 4 "rm -rf '$r/reth/data' && ln -s '$tmp/decoy' '$r/reth/data'"
  rc=0; PATH="$tmp/hook:$PATH" bash "$setup" --env-file "$tmp/swap.env" --root "$r" >/dev/null 2>&1 || rc=$?
  if ((rc == 2)) && [[ $(file_mode_uid "$tmp/decoy") == "755 0" ]]; then ok "root: a data dir swapped after the checks is refused, its target untouched"; else bad "root: a data dir swapped after the checks (exit $rc, decoy $(file_mode_uid "$tmp/decoy"))"; fi

  # Regression (.env directory redirect): the --env-file directory belongs to another user,
  # who swaps it for a symlink to a root-owned directory; root must never replace the .env
  # there. Without SUDO_UID only root may own the path; with it, the sudo user may too, and
  # the symlink is still refused. A sticky world-writable parent (/var/tmp) changes nothing.
  id -u envop >/dev/null 2>&1 || useradd -m -d /home/envop -s /usr/sbin/nologin envop
  op=$(id -u envop) vd="$tmp/victimdir"
  mkdir -m 0755 "$vd"
  # envswap <dir>: an envop-owned <dir> with an .env, then <dir> swapped for a symlink to $vd.
  envswap() {
    rm -rf "$1" "$1.saved" && mkdir -m 0700 "$1" && cp "$ref/.env.example" "$1/.env" && chown -R envop "$1"
    mv "$1" "$1.saved" && ln -s "$vd" "$1" && chown -h envop "$1"
  }
  # env_redirect <description> <env dir> <SUDO_UID or ''>: setup.sh refuses (exit 2) before it
  # creates DATA_ROOT, and the victim .env is unchanged.
  env_redirect() {
    local rc=0 out dr="$tmp/envredir-root"
    printf 'FOO=1\n' > "$vd/.env" && chmod 0644 "$vd/.env"
    out=$(env -u SUDO_UID ${3:+SUDO_UID=$3} bash "$setup" --env-file "$2/.env" --root "$dr" 2>&1) || rc=$?
    if ((rc == 2)) && [[ ! -e $dr && $(cat "$vd/.env") == FOO=1 && $(file_mode_uid "$vd/.env") == "644 0" ]]; then
      ok "root: regression: $1"
    else
      bad "root: regression: $1 (exit $rc, victim $(file_mode_uid "$vd/.env"): $(head -1 "$vd/.env"))" "$out"
    fi
  }
  envswap /home/envop/cfg
  env_redirect "an .env directory another user swapped for a symlink is refused" /home/envop/cfg ''
  env_redirect "an .env directory the sudo user swapped for a symlink is refused" /home/envop/cfg "$op"
  envswap /var/tmp/envop-ref
  env_redirect "an .env directory swapped for a symlink in sticky /var/tmp is refused" /var/tmp/envop-ref ''
  env_redirect "an .env directory swapped in sticky /var/tmp is refused for the sudo user too" /var/tmp/envop-ref "$op"
  rm -rf /var/tmp/envop-ref /var/tmp/envop-ref.saved
  # Not swapped: the sudo user's own .env directory is accepted, and refused without SUDO_UID.
  mkdir -m 0700 /home/envop/ok && cp "$ref/.env.example" /home/envop/ok/.env && chown -R envop /home/envop/ok
  check_out 2 "root: an .env directory owned by another user is refused without SUDO_UID" "/home/envop: owned by uid $op" \
    env -u SUDO_UID bash "$setup" --env-file /home/envop/ok/.env --root "$tmp/envop-root"
  check_out 0 "root: the sudo user's own .env directory is accepted" '^setup OK$' \
    env SUDO_UID="$op" bash "$setup" --env-file /home/envop/ok/.env --root "$tmp/envop-root"
  if grep -qx "DATA_ROOT=$tmp/envop-root" /home/envop/ok/.env && [[ $(file_mode_uid /home/envop/ok/.env) == "600 0" ]]; then
    ok "root: the sudo user's .env is rewritten in place, 0600"
  else
    bad "root: the sudo user's .env is rewritten in place, 0600 (got $(file_mode_uid /home/envop/ok/.env))"
  fi
  # An .env directly in a root-owned sticky directory (like /tmp) is accepted.
  mkdir -m 1777 "$tmp/sticky" && cp "$ref/.env.example" "$tmp/sticky/.env"
  check_out 0 "root: an .env in a root-owned sticky directory is accepted" '^setup OK$' \
    env -u SUDO_UID bash "$setup" --env-file "$tmp/sticky/.env" --root "$tmp/sticky-root"
  # The swap between the checks and the write: a root-owned .env directory swapped for a
  # symlink just before write-file (fsguard call 5). The write's own walk refuses it.
  e="$tmp/envrace"
  mkdir -m 0700 "$e" "$e/cfg" && cp "$ref/.env.example" "$e/cfg/.env"
  printf 'FOO=1\n' > "$vd/.env" && chmod 0644 "$vd/.env"
  hooked 5 "mv '$e/cfg' '$e/cfg.saved' && ln -s '$vd' '$e/cfg'"
  rc=0; out=$(PATH="$tmp/hook:$PATH" bash "$setup" --env-file "$e/cfg/.env" --root "$tmp/envrace-root" 2>&1) || rc=$?
  if ((rc == 2)) && [[ -L $e/cfg && $(cat "$tmp/hook/count") == 5 && $(cat "$vd/.env") == FOO=1 && $(file_mode_uid "$vd/.env") == "644 0" && -z $(find "$vd" -mindepth 1 ! -name .env) ]]; then
    ok "root: regression: an .env directory swapped for a symlink before the write is refused, its target untouched"
  else
    bad "root: regression: .env directory swapped before the write (exit $rc, calls $(cat "$tmp/hook/count")): $(find "$vd" -mindepth 1 | tr '\n' ' ')" "$out"
  fi

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

  # Hoodi next to Sepolia on the same host: its own users, root and secret.
  hreal="$tmp/hoodi-real" hreal_env="$tmp/hoodi-real.env"
  cp "$ref/.env.hoodi.example" "$hreal_env"
  check_out 0 "root: setup.sh for Hoodi next to Sepolia" '^user reth-hoodi: created$' bash "$setup" --env-file "$hreal_env" --root "$hreal"
  hru=$(id -u reth-hoodi 2>/dev/null || echo none) hlu=$(id -u lighthouse-hoodi 2>/dev/null || echo none)
  if [[ $(printf '%s\n' "$ru" "$lu" "$hru" "$hlu" | sort -u | wc -l | tr -d ' ') == 4 && $hru != none && $hlu != none ]]; then
    ok "root: four distinct service uids for the two networks"
  else
    bad "root: four distinct service uids (reth $ru, lighthouse $lu, reth-hoodi $hru, lighthouse-hoodi $hlu)"
  fi
  for spec in "reth/jwt.hex 600 $hru" "lighthouse/jwt.hex 600 $hlu" "reth/data 700 $hru"; do
    read -r rel want_mode want_uid <<< "$spec"
    m=$(file_mode_uid "$hreal/$rel")
    if [[ $m == "$want_mode $want_uid" ]]; then ok "root: Hoodi $rel is $m"; else bad "root: Hoodi $rel (got '$m', want '$want_mode $want_uid')"; fi
  done
  if ! cmp -s "$hreal/reth/jwt.hex" "$real/reth/jwt.hex"; then ok "root: the Hoodi node has its own JWT secret"; else bad "root: the Hoodi node has its own JWT secret"; fi
  if grep -qx "RETH_UID=$hru" "$hreal_env"; then ok "root: the Hoodi .env records reth-hoodi's uid"; else bad "root: the Hoodi .env records reth-hoodi's uid" "$(cat "$hreal_env")"; fi
  mkdir -p "$http/cp1.example.org" "$http/cp2.example.net"
  cp "$tmp/hoodi-spec.json" "$http/cp1.example.org/eth_v1_config_spec" && cp "$tmp/hoodi-spec.json" "$http/cp2.example.net/eth_v1_config_spec"
  header_json "$http/cp1.example.org/eth_v1_beacon_headers_finalized" 4235200 "$r1" "$s1"
  header_json "$http/cp2.example.net/eth_v1_beacon_headers_4235200" 4235200 "$r1" "$s1"
  set_env "$hreal_env" CHECKPOINT_SYNC_URL https://cp1.example.org; set_env "$hreal_env" CHECKPOINT_SYNC_URL_2 https://cp2.example.net
  check_out 0 "root: Hoodi preflight passes with its real users, two providers and the dev pins" '^preflight OK$' \
    env PATH="$tmp/stubs-curl:$PATH" bash "$copy_ref/preflight.sh" --env-file "$hreal_env"
  cp "$hreal_env" "$tmp/hoodi-releases.env"
  set_env "$tmp/hoodi-releases.env" RETH_IMAGE "$sepolia_reth"; set_env "$tmp/hoodi-releases.env" LIGHTHOUSE_IMAGE "$sepolia_lh"
  check_out 1 "root: Hoodi preflight fails on the Sepolia release pins" '^release notes: reth v2\.7\.0 does not schedule hoodi.s' \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$tmp/hoodi-releases.env"
  cp "$hreal_env" "$tmp/hoodi-cross.env"; set_env "$tmp/hoodi-cross.env" RETH_UID "$ru"
  check_out 1 "root: Hoodi preflight refuses the Sepolia reth uid" "^RETH_UID: $ru is not user reth-hoodi's uid $hru: FAIL$" \
    env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$tmp/hoodi-cross.env"
  if [[ -n $bound ]]; then
    mv "$hreal/lighthouse/jwt.hex" "$tmp/hoodi-jwt.keep" && mkfifo -m 0600 "$hreal/lighthouse/jwt.hex" && chown lighthouse-hoodi "$hreal/lighthouse/jwt.hex"
    # shellcheck disable=SC2086 # $bound is a command prefix
    check_out 1 "root: a 0600 FIFO owned by the service at a JWT copy is refused without blocking" \
      "lighthouse/jwt\.hex: not a regular file \(want 600 $hlu\): FAIL$" $bound env PATH="$tmp/stubs-curl:$PATH" bash "$preflight" --env-file "$hreal_env"
    rm "$hreal/lighthouse/jwt.hex" && mv "$tmp/hoodi-jwt.keep" "$hreal/lighthouse/jwt.hex"
  fi

  # sudo -E as the operator envop: root keeps envop's HOME, whose .docker holds a planted
  # docker-compose plugin. Every docker call the run log makes reads root's own .docker.
  mkdir -p /home/envop/.docker/cli-plugins && cp "$tmp/evilhome/.docker/cli-plugins/docker-compose" /home/envop/.docker/cli-plugins/
  chown -R envop /home/envop/.docker
  cp "$pf_env" "$tmp/sudo-e.env"; set_env "$tmp/sudo-e.env" RETH_UID "$ru"
  : > "$tmp/docker-config.log"
  (HOME=/home/envop SUDO_UID="$op" PATH="$stubs:$PATH" bash "$collect" --env-file "$tmp/sudo-e.env" --samples 1 --interval 0 >/dev/null 2>&1) || true
  root_home=$(python3 -I -B -c 'import pwd; print(pwd.getpwuid(0).pw_dir)')
  if [[ -s $tmp/docker-config.log && $(sort -u "$tmp/docker-config.log") == "${root_home%/}/.docker" ]]; then
    ok "root: under sudo -E (the operator's HOME) every docker call reads root's own .docker"
  else
    bad "root: under sudo -E every docker call reads root's own .docker" "$(sort -u "$tmp/docker-config.log")"
  fi
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

# Python bytecode never lands in the stack: the scripts run python3 -B, and __pycache__/ is
# ignored should anything else write it.
if [[ -z $(find "$copy_ref" -name __pycache__) ]]; then ok "no __pycache__ written by the scripts"; else bad "no __pycache__ written by the scripts" "$(find "$copy_ref" -name __pycache__)"; fi
if command -v git >/dev/null 2>&1 && git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  check 0 "ops/ref-node ignores __pycache__/" git -C "$repo" check-ignore -q ops/ref-node/lib/__pycache__/fsguard.cpython-312.pyc
else
  echo "# skip - __pycache__ is git-ignored: no git work tree"
fi
if [[ -n $(find "$start_dir" "$tmp" -maxdepth 1 -name 'run-log-*.md') ]]; then bad "no run log written outside the tests' own files"; else ok "no run log written outside the tests' own files"; fi

echo "# $passed passed, $failed failed"
((failed == 0))
