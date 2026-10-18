#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted stub bodies expand when the stubs run, on purpose
# Offline tests for testing/kurtosis/check-devnet.sh. Run: bash testing/kurtosis/tests/check-devnet.test.sh
# kurtosis and curl are stubs on PATH: `kurtosis enclave inspect` prints a canned service table,
# `kurtosis port print` a canned URL per service, and curl serves fixture files per host:port and
# API path (a numbered file per call, for answers that change between polls). No network, no
# Kurtosis, no Docker. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../check-devnet.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"   # a stray relative write lands in the temp dir, never in the checkout

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() {
  failed=$((failed + 1)); echo "FAIL - $1"
  if [[ -n ${2:-} ]]; then printf '%s\n' "$2" | sed 's/^/       /'; fi
}

# --- stubs ---------------------------------------------------------------------------------------

stubs="$tmp/stubs"
mkdir -p "$stubs"
export STUB_DIR="$tmp/stub"

cat > "$stubs/kurtosis" <<'SH'
#!/usr/bin/env bash
# kurtosis stub. `enclave inspect E`: $STUB_DIR/inspect.<E> (none: exit 1). `port print E S P`:
# $STUB_DIR/port.<S>.<P> (none: exit 1).
printf '%s\n' "$*" >> "$STUB_DIR/kurtosis.log"
case "$1 $2" in
  "enclave inspect") f="$STUB_DIR/inspect.$3" ;;
  "port print") f="$STUB_DIR/port.$4.$5" ;;
  *) exit 64 ;;
esac
[[ -f $f ]] || { echo "stub: no $f" >&2; exit 1; }
cat "$f"
SH
cat > "$stubs/curl" <<'SH'
#!/usr/bin/env bash
# curl stub: serves $STUB_DIR/http/<host:port>/<API path, / as _>; when <file>.<n> exists it
# serves that on the n-th request for the path, and the plain file once the numbered ones run out.
# No file: exit 22 (what curl -f does on an HTTP error).
out= url=
while (($# > 0)); do
  case $1 in
    -o|--output) out=$2; shift 2 ;;
    http://*|https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$STUB_DIR/curl.log"
[[ -n $out && -n $url ]] || exit 2
rest=${url#*://}
hostport=${rest%%/*}
api=${rest#"$hostport"/}
f="$STUB_DIR/http/$hostport/$(printf '%s' "$api" | tr '/' '_')"
counter="$f.count"
n=$(( $(cat "$counter" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$counter"
if [[ -f $f.$n ]]; then cat "$f.$n" > "$out"; exit 0; fi
[[ -f $f ]] || exit 22
cat "$f" > "$out"
SH
chmod +x "$stubs/kurtosis" "$stubs/curl"

# enr <4-byte fork digest hex, no 0x>: an ENR text whose eth2 entry carries that digest (the RLP
# list [signature, seq, "eth2", ENRForkID, "id", "v4"]; the signature is not checked).
enr() {
  python3 -I -c '
import base64, sys
def item(b):
    if len(b) == 1 and b[0] < 0x80: return b
    if len(b) < 56: return bytes([0x80 + len(b)]) + b
    n = len(b).to_bytes((len(b).bit_length() + 7) // 8, "big")
    return bytes([0xb7 + len(n)]) + n + b
def lst(items):
    body = b"".join(items)
    if len(body) < 56: return bytes([0xc0 + len(body)]) + body
    n = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([0xf7 + len(n)]) + n + body
fork_id = bytes.fromhex(sys.argv[1]) + bytes.fromhex("80000038") + (2**64 - 1).to_bytes(8, "little")
rlp = lst([item(b"\x01" * 64), item(b"\x07"), item(b"eth2"), item(fork_id), item(b"id"), item(b"v4")])
print("enr:" + base64.urlsafe_b64encode(rlp).decode().rstrip("="))
' "$1"
}

GVR=0x$(printf '11%.0s' {1..32})
BLOCK=0x$(printf '22%.0s' {1..32})
STATE=0x$(printf '33%.0s' {1..32})
FIN=0x$(printf '44%.0s' {1..32})
FAR=18446744073709551615

# cl <service> <port>: a CL whose every answer is the passing one.
cl() {
  local d="$STUB_DIR/http/127.0.0.1:$2"
  mkdir -p "$d"
  printf 'http://127.0.0.1:%s\n' "$2" > "$STUB_DIR/port.$1.http"
  printf '{"data":{"genesis_time":"1790000000","genesis_validators_root":"%s","genesis_fork_version":"0x10000038"}}\n' \
    "$GVR" > "$d/eth_v1_beacon_genesis"
  printf '{"execution_optimistic":false,"finalized":true,"data":{"root":"%s","canonical":true,"header":{"message":{"slot":"0","proposer_index":"0","parent_root":"0x%064d","state_root":"%s","body_root":"0x%064d"},"signature":"0x%0192d"}}}\n' \
    "$BLOCK" 0 "$STATE" 0 0 > "$d/eth_v1_beacon_headers_genesis"
  printf '{"data":[%s]}\n' \
    '{"previous_version":"0x10000038","current_version":"0x10000038","epoch":"0"},{"previous_version":"0x10000038","current_version":"0x20000038","epoch":"0"},{"previous_version":"0x50000038","current_version":"0x60000038","epoch":"0"},{"previous_version":"0x60000038","current_version":"0x70000038","epoch":"0"},{"previous_version":"0x70000038","current_version":"0x80000038","epoch":"'"$FAR"'"}' \
    > "$d/eth_v1_config_fork_schedule"
  printf '{"data":{"PRESET_BASE":"minimal","FULU_FORK_EPOCH":"0","GLOAS_FORK_VERSION":"0x70000038","GLOAS_FORK_EPOCH":"0"}}\n' \
    > "$d/eth_v1_config_spec"
  printf '{"data":{"peer_id":"16Uiu2HAm","enr":"%s","p2p_addresses":["/ip4/172.16.0.10/tcp/9000/p2p/16Uiu2HAm"],"discovery_addresses":[],"metadata":{"seq_number":"1"}}}\n' \
    "$(enr 01020304)" > "$d/eth_v1_node_identity"
  finalized "$1" 4 "$FIN"
}

# port_of <service>
port_of() { sed 's/.*://' "$STUB_DIR/port.$1.http"; }

# finalized <service> <epoch> <root> [n]: the finality answer (the n-th poll's, with n).
finalized() {
  local d="$STUB_DIR/http/127.0.0.1:$(port_of "$1")" suffix=${4:+.$4}
  printf '{"execution_optimistic":false,"finalized":false,"data":{"previous_justified":{"epoch":"%s","root":"%s"},"current_justified":{"epoch":"%s","root":"%s"},"finalized":{"epoch":"%s","root":"%s"}}}\n' \
    "$(($2 + 1))" "$3" "$(($2 + 2))" "$3" "$2" "$3" > "$d/eth_v1_beacon_states_head_finality_checkpoints$suffix"
}

# edit <service> <file> <sed expression>
edit() {
  local f="$STUB_DIR/http/127.0.0.1:$(port_of "$1")/$2"
  sed -e "$3" "$f" > "$f.new" && mv "$f.new" "$f"
}

# base: an enclave ethswarm-gloas with two passing CLs, a VC, an EL and buildoor.
base() {
  rm -rf "$STUB_DIR"; mkdir -p "$STUB_DIR"
  cat > "$STUB_DIR/inspect.ethswarm-gloas" <<'TXT'
Name:            ethswarm-gloas
Status:          RUNNING

========================================= User Services =========================================
UUID           Name                         Ports                                         Status
1a2b3c4d5e6f   buildoor-lighthouse-geth-1   http: 8080/tcp -> http://127.0.0.1:33001      RUNNING
2b3c4d5e6f7a   cl-1-lighthouse-geth         http: 4000/tcp -> http://127.0.0.1:32801      RUNNING
                                            metrics: 5054/tcp -> http://127.0.0.1:32802
                                            tcp-discovery: 9000/tcp -> 127.0.0.1:32803
3c4d5e6f7a8b   cl-2-lodestar-geth           http: 4000/tcp -> http://127.0.0.1:32811      RUNNING
4d5e6f7a8b9c   el-1-geth-lighthouse         rpc: 8545/tcp -> 127.0.0.1:32821              RUNNING
5e6f7a8b9c0d   vc-1-geth-lighthouse         metrics: 8080/tcp -> http://127.0.0.1:32831   RUNNING
TXT
  cl cl-1-lighthouse-geth 32801
  cl cl-2-lodestar-geth 32811
}

# run <expect-exit> <description> <pattern...> -- <args...>: runs the script (fast polls) and
# wants the exit code and a line matching each extended regex.
run() {
  local expect=$1 desc=$2 rc=0 out p missing=
  shift 2
  local patterns=()
  while (($# > 0)) && [[ $1 != -- ]]; do patterns+=("$1"); shift; done
  shift
  out=$(PATH="$stubs:$PATH" bash "$script" --interval 0 --attempts 3 "$@" 2>&1) || rc=$?
  for p in ${patterns[@]+"${patterns[@]}"}; do
    printf '%s\n' "$out" | grep -Eq -- "$p" || missing="$missing /$p/"
  done
  if ((rc == expect)) && [[ -z $missing ]]; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect${missing:+; no line matching$missing})" "$out"
  fi
}

# --- all pass ------------------------------------------------------------------------------------

base
run 0 "two agreeing CLs at finalized epoch 4 pass every criterion" \
  '^devnet ethswarm-gloas: 2 CL services: cl-1-lighthouse-geth cl-2-lodestar-geth$' \
  '^genesis: PASS' '^fork_schedule: PASS' '^finality: PASS' '^verdict: PASS \(3/3 criteria\)$' \
  "^cl-2-lodestar-geth: genesis_state_root $STATE$" \
  '^cl-1-lighthouse-geth: fork_digest 0x01020304$' \
  "^cl-1-lighthouse-geth: finalized epoch 4 root $FIN$" \
  -- ethswarm-gloas
if grep -q '^enclave inspect ethswarm-gloas$' "$STUB_DIR/kurtosis.log" &&
   grep -q '^port print ethswarm-gloas cl-2-lodestar-geth http$' "$STUB_DIR/kurtosis.log"; then
  ok "services come from kurtosis enclave inspect, URLs from kurtosis port print <svc> http"
else
  bad "services come from kurtosis enclave inspect" "$(cat "$STUB_DIR/kurtosis.log")"
fi
if ! grep -q 'buildoor\|vc-1\|el-1' "$STUB_DIR/kurtosis.log"; then ok "only cl-<n>-* services are queried"; else bad "only cl-<n>-* services are queried" "$(cat "$STUB_DIR/kurtosis.log")"; fi

base
run 0 "--services picks the CLs instead of enclave inspect" '^devnet ethswarm-gloas: 1 CL services: cl-2-lodestar-geth$' \
  -- --services cl-2-lodestar-geth ethswarm-gloas
if ! grep -q '^enclave inspect' "$STUB_DIR/kurtosis.log"; then ok "--services skips enclave inspect"; else bad "--services skips enclave inspect"; fi

base
printf '127.0.0.1:32811\n' > "$STUB_DIR/port.cl-2-lodestar-geth.http"
run 0 "a port print answer without a scheme is read as http://" '^cl-2-lodestar-geth: http://127.0.0.1:32811$' -- ethswarm-gloas

# --- genesis: record and reference ---------------------------------------------------------------

base
run 0 "--record writes the genesis record" "^genesis: record written to $tmp/run-a.json$" -- --record "$tmp/run-a.json" ethswarm-gloas
want="{\"genesis_block_root\": \"$BLOCK\", \"genesis_fork_version\": \"0x10000038\", \"genesis_state_root\": \"$STATE\", \"genesis_time\": \"1790000000\", \"genesis_validators_root\": \"$GVR\"}"
if [[ -f $tmp/run-a.json && $(cat "$tmp/run-a.json") == "$want" ]]; then ok "the record holds the five genesis fields"; else bad "the record holds the five genesis fields" "$(cat "$tmp/run-a.json" 2>&1)"; fi

base
run 0 "a second run with the same genesis matches the reference" '^genesis: PASS .*matches the reference run' \
  -- --reference "$tmp/run-a.json" ethswarm-gloas

base
for svc in cl-1-lighthouse-geth cl-2-lodestar-geth; do edit $svc eth_v1_beacon_headers_genesis "s/$STATE/0x$(printf '55%.0s' {1..32})/"; done
run 1 "a second run with another genesis state root fails against the reference" \
  "^- genesis_state_root: reference $STATE, this run 0x5555" '^genesis: FAIL' '^verdict: FAIL \(genesis\)$' \
  -- --reference "$tmp/run-a.json" ethswarm-gloas

base
for svc in cl-1-lighthouse-geth cl-2-lodestar-geth; do edit $svc eth_v1_beacon_genesis 's/"1790000000"/"1790000600"/'; done
run 1 "another genesis_time fails against the reference" '^- genesis_time: reference 1790000000, this run 1790000600$' \
  -- --reference "$tmp/run-a.json" ethswarm-gloas

base
printf '{"genesis_time": "1790000000"}\n' > "$tmp/partial.json"
run 1 "a reference without every field fails" '^- genesis_state_root: missing from the reference' -- --reference "$tmp/partial.json" ethswarm-gloas
printf 'not json\n' > "$tmp/garbage.json"
run 1 "a reference that is not JSON fails" '^genesis: FAIL' -- --reference "$tmp/garbage.json" ethswarm-gloas
run 2 "a missing reference file is a usage error" 'no such file' -- --reference "$tmp/absent.json" ethswarm-gloas

base
edit cl-2-lodestar-geth eth_v1_beacon_headers_genesis "s/$BLOCK/0x$(printf '66%.0s' {1..32})/"
rm -f "$tmp/run-b.json"
run 1 "CLs that disagree on the genesis block root fail" \
  '^- genesis_block_root: CLs disagree: cl-1-lighthouse-geth '"$BLOCK"', cl-2-lodestar-geth 0x6666' '^genesis: FAIL' \
  -- --record "$tmp/run-b.json" ethswarm-gloas
if [[ ! -e $tmp/run-b.json ]]; then ok "no record is written when the CLs disagree"; else bad "no record is written when the CLs disagree"; fi

base
edit cl-1-lighthouse-geth eth_v1_beacon_genesis "s/$GVR/0x$(printf '77%.0s' {1..32})/"
run 1 "CLs that disagree on genesis_validators_root fail" '^- genesis_validators_root: CLs disagree' -- ethswarm-gloas

base
rm "$STUB_DIR/http/127.0.0.1:32811/eth_v1_beacon_headers_genesis"
run 1 "a CL that does not answer the genesis header fails genesis" \
  '^cl-2-lodestar-geth: GET /eth/v1/beacon/headers/genesis failed' '^genesis: FAIL' -- ethswarm-gloas

base
edit cl-1-lighthouse-geth eth_v1_beacon_genesis 's/"genesis_time":"1790000000",//'
run 1 "a genesis answer without genesis_time fails" '^- cl-1-lighthouse-geth: genesis_time missing' '^genesis: FAIL' -- ethswarm-gloas

base
edit cl-1-lighthouse-geth eth_v1_beacon_genesis "s/$GVR/0x1234/"
run 1 "a genesis_validators_root that is not 32 bytes fails" '^- cl-1-lighthouse-geth: genesis_validators_root "0x1234" is not 32-byte hex' -- ethswarm-gloas

# --- fork schedule -------------------------------------------------------------------------------

base
edit cl-2-lodestar-geth eth_v1_config_fork_schedule 's/"current_version":"0x70000038","epoch":"0"/"current_version":"0x70000038","epoch":"1"/'
run 1 "Gloas at epoch 1 on one CL fails" '^- cl-2-lodestar-geth: Gloas \(0x70000038\) at epoch 1, not 0$' '^fork_schedule: FAIL' -- ethswarm-gloas

base
edit cl-1-lighthouse-geth eth_v1_config_fork_schedule 's/{"previous_version":"0x60000038","current_version":"0x70000038","epoch":"0"},//'
run 1 "a schedule without the Gloas version fails" '^- cl-1-lighthouse-geth: Gloas \(0x70000038\) is not in the fork schedule$' -- ethswarm-gloas

base
edit cl-1-lighthouse-geth eth_v1_config_fork_schedule 's/"current_version":"0x80000038","epoch":"'"$FAR"'"/"current_version":"0x80000038","epoch":"0"/'
run 1 "a later fork also at epoch 0 (Gloas not in force) fails" '^- cl-1-lighthouse-geth: the fork in force at epoch 0 is 0x80000038, not Gloas \(0x70000038\)$' -- ethswarm-gloas

base
edit cl-2-lodestar-geth eth_v1_config_spec 's/"GLOAS_FORK_EPOCH":"0"/"GLOAS_FORK_EPOCH":"8"/'
run 1 "a spec with GLOAS_FORK_EPOCH 8 fails" '^- cl-2-lodestar-geth: GLOAS_FORK_EPOCH 8, not 0$' -- ethswarm-gloas

base
edit cl-2-lodestar-geth eth_v1_config_spec 's/"GLOAS_FORK_VERSION":"0x70000038",//'
run 1 "a spec without GLOAS_FORK_VERSION fails" '^- cl-2-lodestar-geth: GLOAS_FORK_VERSION missing from /eth/v1/config/spec$' -- ethswarm-gloas

base
edit cl-2-lodestar-geth eth_v1_config_fork_schedule 's/"previous_version":"0x10000038","current_version":"0x20000038"/"previous_version":"0x10000038","current_version":"0x20000039"/'
run 1 "CLs whose fork schedules differ fail" '^- fork schedules differ: cl-1-lighthouse-geth and cl-2-lodestar-geth$' -- ethswarm-gloas

base
edit cl-2-lodestar-geth eth_v1_config_fork_schedule 's/0X/0x/; s/"0x70000038"/"0X70000038"/g'
edit cl-2-lodestar-geth eth_v1_config_spec 's/"0x70000038"/"0X70000038"/'
run 0 "fork versions compare case-insensitively" '^fork_schedule: PASS' -- ethswarm-gloas

base
printf '{"data":{"peer_id":"x","enr":"%s"}}\n' "$(enr 0a0b0c0d)" > "$STUB_DIR/http/127.0.0.1:32811/eth_v1_node_identity"
run 1 "CLs whose ENR fork digests differ fail" \
  '^- fork digests differ: cl-1-lighthouse-geth 0x01020304, cl-2-lodestar-geth 0x0a0b0c0d$' '^fork_schedule: FAIL' -- ethswarm-gloas

base
printf '{"data":{"peer_id":"x","enr":"enr:-AAA"}}\n' > "$STUB_DIR/http/127.0.0.1:32811/eth_v1_node_identity"
run 1 "an ENR that is not RLP fails" '^- cl-2-lodestar-geth: ENR: ' -- ethswarm-gloas

base
printf '{"data":{"peer_id":"x","enr":"not-an-enr"}}\n' > "$STUB_DIR/http/127.0.0.1:32811/eth_v1_node_identity"
run 1 "an identity answer without an enr: text fails" '^- cl-2-lodestar-geth: ENR: does not start with enr:' -- ethswarm-gloas

base
noeth2=$(python3 -I -c '
import base64
body = bytes([0xb8, 64]) + b"\x01" * 64 + b"\x07" + bytes([0x82]) + b"id" + bytes([0x82]) + b"v4"
rlp = bytes([0xf8, len(body)]) + body
print("enr:" + base64.urlsafe_b64encode(rlp).decode().rstrip("="))')
printf '{"data":{"peer_id":"x","enr":"%s"}}\n' "$noeth2" > "$STUB_DIR/http/127.0.0.1:32811/eth_v1_node_identity"
run 1 "an ENR without an eth2 entry fails" '^- cl-2-lodestar-geth: ENR: no eth2 entry$' -- ethswarm-gloas

# --- finality ------------------------------------------------------------------------------------

base
finalized cl-1-lighthouse-geth 2 "$FIN"; finalized cl-2-lodestar-geth 2 "$FIN"
run 1 "finalized epoch 2 on every poll fails" '^cl-1-lighthouse-geth: finalized epoch 2 root ' \
  '^- finalized epoch 2 is below 3 on cl-1-lighthouse-geth$' '^finality: FAIL after 3 polls$' '^verdict: FAIL \(finality\)$' -- ethswarm-gloas
n=$(grep -c 'finality_checkpoints$' "$STUB_DIR/curl.log" 2>/dev/null || true)
if ((n == 6)); then ok "finality is polled --attempts times per CL"; else bad "finality is polled --attempts times per CL (got $n requests)"; fi

base
finalized cl-1-lighthouse-geth 2 "$FIN" 1; finalized cl-2-lodestar-geth 2 "$FIN" 1
run 0 "finality that reaches epoch 4 on the second poll passes" '^finality: PASS on poll 2 of 3' -- ethswarm-gloas

base
run 1 "--min-finalized-epoch 5 fails at epoch 4" '^- finalized epoch 4 is below 5 on cl-1-lighthouse-geth$' -- --min-finalized-epoch 5 ethswarm-gloas

base
finalized cl-2-lodestar-geth 4 "0x$(printf '88%.0s' {1..32})"
run 1 "CLs on different finalized roots at the same epoch fail" \
  '^- finalized checkpoints differ: cl-1-lighthouse-geth 4/'"$FIN"', cl-2-lodestar-geth 4/0x8888' -- ethswarm-gloas

base
finalized cl-2-lodestar-geth 5 "0x$(printf '88%.0s' {1..32})"
run 1 "CLs at different finalized epochs on every poll fail" '^- finalized checkpoints differ' '^finality: FAIL after 3 polls$' -- ethswarm-gloas

base
finalized cl-2-lodestar-geth 5 "0x$(printf '88%.0s' {1..32})" 1
run 0 "CLs that converge on the next poll pass" '^finality: PASS on poll 2 of 3' -- ethswarm-gloas

base
rm "$STUB_DIR/http/127.0.0.1:32811/eth_v1_beacon_states_head_finality_checkpoints"
run 1 "a CL that never answers finality_checkpoints fails" \
  '^cl-2-lodestar-geth: GET /eth/v1/beacon/states/head/finality_checkpoints failed' '^finality: FAIL after 3 polls$' -- ethswarm-gloas

base
edit cl-1-lighthouse-geth eth_v1_beacon_states_head_finality_checkpoints 's/"finalized":{"epoch":"4"/"finalized":{"epoch":"four"/'
run 1 "a finalized epoch that is not an integer fails" '^- cl-1-lighthouse-geth: finalized epoch "four" is not an integer$' -- ethswarm-gloas

# --- several criteria at once, setup and usage errors ----------------------------------------------

base
edit cl-2-lodestar-geth eth_v1_config_spec 's/"GLOAS_FORK_EPOCH":"0"/"GLOAS_FORK_EPOCH":"8"/'
finalized cl-1-lighthouse-geth 1 "$FIN"; finalized cl-2-lodestar-geth 1 "$FIN"
run 1 "every failed criterion is named in the verdict" '^genesis: PASS' '^verdict: FAIL \(fork_schedule finality\)$' -- ethswarm-gloas

base
run 2 "an unknown enclave is a setup error" '^ERROR: kurtosis enclave inspect other failed' -- other

base
sed -i.bak '/cl-[12]-/d' "$STUB_DIR/inspect.ethswarm-gloas"
run 2 "an enclave without CL services is a setup error" '^ERROR: no cl-<n>-\* service in enclave ethswarm-gloas' -- ethswarm-gloas

base
rm "$STUB_DIR/port.cl-2-lodestar-geth.http"
run 2 "a CL without an http port is a setup error" '^ERROR: kurtosis port print ethswarm-gloas cl-2-lodestar-geth http failed' -- ethswarm-gloas

base
printf 'http://127.0.0.1:32811/$(id)\n' > "$STUB_DIR/port.cl-2-lodestar-geth.http"
run 2 "a port print answer that is not a bare URL is refused" '^ERROR: kurtosis port print .* is not an http://host:port URL' -- ethswarm-gloas

base
run 2 "no enclave is a usage error" '^usage: ' --
run 2 "two enclaves are a usage error" '^usage: ' -- a b
run 2 "an unknown option is a usage error" '^usage: ' -- --frobnicate ethswarm-gloas
run 2 "a non-integer --min-finalized-epoch is a usage error" 'min-finalized-epoch' -- --min-finalized-epoch x ethswarm-gloas
run 2 "a non-integer --attempts is a usage error" 'attempts' -- --attempts 0 ethswarm-gloas
run 2 "a service name that is not a CL name is refused" 'not a cl-<n>-\* service name' -- --services 'cl-1;id' ethswarm-gloas

rc=0; out=$(PATH="/usr/bin:/bin" bash "$script" ethswarm-gloas 2>&1) || rc=$?
if ((rc == 2)) && printf '%s\n' "$out" | grep -q '^ERROR: kurtosis not found'; then ok "a missing kurtosis CLI is a setup error"; else bad "a missing kurtosis CLI is a setup error (exit $rc)" "$out"; fi

echo "# $passed passed, $failed failed"
((failed == 0))
