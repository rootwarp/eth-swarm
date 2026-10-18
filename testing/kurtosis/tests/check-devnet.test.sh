#!/usr/bin/env bash
# shellcheck disable=SC2016 # single-quoted stub bodies expand when the stubs run, on purpose
# Offline tests for testing/kurtosis/check-devnet.sh (one enclave, and a --pair of two). Run: bash testing/kurtosis/tests/check-devnet.test.sh
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
# $STUB_DIR/port.<E>.<S>.<P>, else $STUB_DIR/port.<S>.<P> (neither: exit 1). With $STUB_DIR/stderr, every call first prints that
# file to stderr (Kurtosis 1.22.1 on Docker Desktop prints an OpenTelemetry WARN on every call).
# With $STUB_DIR/hang.enclave.<E> (an inspect) or $STUB_DIR/hang.port.<E> (a port print) the call
# hangs for 30 s instead (its pid in $STUB_DIR/hang.pid); with $STUB_DIR/hang-child.enclave.<E> it
# first starts a child that keeps its stdout open for 30 s (its pid in $STUB_DIR/hang-child.pid).
printf '%s\n' "$*" >> "$STUB_DIR/kurtosis.log"
if [[ -f $STUB_DIR/stderr ]]; then cat "$STUB_DIR/stderr" >&2; fi
if [[ -f $STUB_DIR/hang-child.$1.$3 ]]; then
  /bin/sleep 30 &
  echo $! > "$STUB_DIR/hang-child.pid"
  echo $$ > "$STUB_DIR/hang.pid"; exec /bin/sleep 30
fi
if [[ -f $STUB_DIR/hang.$1.$3 ]]; then echo $$ > "$STUB_DIR/hang.pid"; exec /bin/sleep 30; fi
case "$1 $2" in
  "enclave inspect") f="$STUB_DIR/inspect.$3" ;;
  "port print") f="$STUB_DIR/port.$3.$4.$5"; [[ -f $f ]] || f="$STUB_DIR/port.$4.$5" ;;
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
# wants the exit code and a line matching each extended regex; a pattern `!<regex>` wants no
# line matching <regex>. (Here-strings, not `printf | grep -q`: under pipefail, grep -q exiting
# early fails the printf.)
run() {
  local expect=$1 desc=$2 rc=0 out p missing= unwanted=
  shift 2
  local patterns=()
  while (($# > 0)) && [[ $1 != -- ]]; do patterns+=("$1"); shift; done
  shift
  out=$(PATH="$stubs:$PATH" bash "$script" --interval 0 --attempts 3 "$@" 2>&1) || rc=$?
  for p in ${patterns[@]+"${patterns[@]}"}; do
    if [[ $p == !* ]]; then
      ! grep -Eq -- "${p#!}" <<<"$out" || unwanted="$unwanted /${p#!}/"
    else
      grep -Eq -- "$p" <<<"$out" || missing="$missing /$p/"
    fi
  done
  if ((rc == expect)) && [[ -z $missing && -z $unwanted ]]; then
    ok "$desc"
  else
    bad "$desc (exit $rc, want $expect${missing:+; no line matching$missing}${unwanted:+; a line matching$unwanted})" "$out"
  fi
}

# --- all pass ------------------------------------------------------------------------------------

base
run 0 "two agreeing CLs at finalized epoch 4 pass every criterion" \
  '^devnet ethswarm-gloas: 2 CL services: cl-1-lighthouse-geth cl-2-lodestar-geth$' \
  '^genesis: PASS' '^fork_schedule: PASS' '^finality: PASS' '^verdict: PASS \(3/3 criteria\)$' \
  "^cl-2-lodestar-geth: genesis_state_root $STATE$" \
  '^cl-1-lighthouse-geth: fork_digest 0x01020304$' \
  "^cl-1-lighthouse-geth: finalized epoch 4 root $FIN$" '!^diagnostic:' \
  -- ethswarm-gloas
if grep -q '^enclave inspect ethswarm-gloas$' "$STUB_DIR/kurtosis.log" &&
   grep -q '^port print ethswarm-gloas cl-2-lodestar-geth http$' "$STUB_DIR/kurtosis.log"; then
  ok "services come from kurtosis enclave inspect, URLs from kurtosis port print <svc> http"
else
  bad "services come from kurtosis enclave inspect" "$(cat "$STUB_DIR/kurtosis.log")"
fi
if ! grep -q 'buildoor\|vc-1\|el-1' "$STUB_DIR/kurtosis.log"; then ok "only cl-<n>-* services are queried"; else bad "only cl-<n>-* services are queried" "$(cat "$STUB_DIR/kurtosis.log")"; fi

# --- which CLs: the enclave's full set, at least two -------------------------------------------

base
run 3 "a --services subset is a DIAGNOSTIC run, never an acceptance PASS" \
  '^devnet ethswarm-gloas: 1 CL services: cl-2-lodestar-geth$' \
  '^diagnostic: --services checks 1 of the enclave.s 2 CLs \(not checked: cl-1-lighthouse-geth\)$' \
  '^verdict: DIAGNOSTIC \(3/3 criteria passed; not an acceptance run\)$' '!^verdict: PASS' \
  -- --services cl-2-lodestar-geth ethswarm-gloas
if grep -q '^enclave inspect ethswarm-gloas$' "$STUB_DIR/kurtosis.log"; then ok "--services is checked against enclave inspect"; else bad "--services is checked against enclave inspect" "$(cat "$STUB_DIR/kurtosis.log")"; fi

base
run 0 "--services naming the enclave's every CL is an acceptance run" \
  '^devnet ethswarm-gloas: 2 CL services: cl-2-lodestar-geth cl-1-lighthouse-geth$' \
  '^verdict: PASS \(3/3 criteria\)$' '!^diagnostic:' \
  -- --services 'cl-2-lodestar-geth cl-1-lighthouse-geth' ethswarm-gloas

base
run 3 "a CL named twice counts once" '^devnet ethswarm-gloas: 1 CL services: cl-1-lighthouse-geth$' \
  '^diagnostic: only 1 distinct CL; an acceptance run needs at least 2$' '!^verdict: PASS' \
  -- --services 'cl-1-lighthouse-geth cl-1-lighthouse-geth' ethswarm-gloas

base
run 2 "a --services CL that the enclave does not run is a setup error" \
  '^ERROR: cl-3-teku-geth: not a CL service of enclave ethswarm-gloas' \
  -- --services 'cl-1-lighthouse-geth cl-3-teku-geth' ethswarm-gloas

base
sed -i.bak '/cl-2-/d' "$STUB_DIR/inspect.ethswarm-gloas"
run 3 "a one-CL enclave is a DIAGNOSTIC run, never an acceptance PASS" \
  '^devnet ethswarm-gloas: 1 CL services: cl-1-lighthouse-geth$' \
  '^diagnostic: only 1 distinct CL; an acceptance run needs at least 2$' \
  '^verdict: DIAGNOSTIC \(3/3 criteria passed; not an acceptance run\)$' '!^verdict: PASS' \
  -- ethswarm-gloas

base
sed -i.bak '/cl-2-/d' "$STUB_DIR/inspect.ethswarm-gloas"
edit cl-1-lighthouse-geth eth_v1_config_spec 's/"GLOAS_FORK_EPOCH":"0"/"GLOAS_FORK_EPOCH":"8"/'
run 1 "a failed criterion on a DIAGNOSTIC run is still a FAIL" '^verdict: FAIL \(fork_schedule\)$' '!^verdict: (PASS|DIAGNOSTIC)' \
  -- ethswarm-gloas

base
printf '127.0.0.1:32811\n' > "$STUB_DIR/port.cl-2-lodestar-geth.http"
run 0 "a port print answer without a scheme is read as http://" '^cl-2-lodestar-geth: http://127.0.0.1:32811$' -- ethswarm-gloas

# kurtosis' stderr is never read as its answer: the WARN Kurtosis 1.22.1 prints on Docker Desktop
# (macOS) on every call, with a cl-<n>-* looking name in it so a parsed stderr would show.
warn() {
  printf '%s\n' \
    '[33mWARN[0m[2026-10-18T23:04:17+09:00] Failed to start the OpenTelemetry side containers; continuing without them. Error:' \
    'Caused by: Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running? container cl-9-otel-geth not started' \
    > "$STUB_DIR/stderr"
}

base
warn
run 0 "a WARN on kurtosis' stderr does not reach the URL or the service list" \
  '^devnet ethswarm-gloas: 2 CL services: cl-1-lighthouse-geth cl-2-lodestar-geth$' \
  '^cl-1-lighthouse-geth: http://127.0.0.1:32801$' '^cl-2-lodestar-geth: http://127.0.0.1:32811$' \
  '^verdict: PASS \(3/3 criteria\)$' '!WARN' '!cl-9-otel-geth' -- ethswarm-gloas

base
warn
rm "$STUB_DIR/port.cl-2-lodestar-geth.http"
run 2 "a failed port print shows its stderr in the error" \
  '^ERROR: kurtosis port print ethswarm-gloas cl-2-lodestar-geth http failed: ' \
  'stub: no .*/port\.cl-2-lodestar-geth\.http' 'Cannot connect to the Docker daemon' -- ethswarm-gloas

base
warn
run 2 "a failed enclave inspect shows its stderr in the error" \
  '^ERROR: kurtosis enclave inspect other failed: ' 'stub: no .*/inspect\.other' 'OpenTelemetry' -- other

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

# The first devnet run's own answers (fixtures/run-a/<service>/: fork_schedule, the spec fields
# the check reads, identity). Lodestar lists the unscheduled Heze fork at FAR_FUTURE_EPOCH
# (current_version 0x90000038) and Lighthouse does not, so the raw schedules have 9 and 8 entries.
fixtures="$here/fixtures/run-a"
real_forks() {
  local svc
  for svc in cl-1-lighthouse-geth cl-2-lodestar-geth; do
    for name in fork_schedule spec identity; do
      cp "$fixtures/$svc/$name.json" "$STUB_DIR/http/127.0.0.1:$(port_of $svc)/eth_v1_config_$name"
    done
    mv "$STUB_DIR/http/127.0.0.1:$(port_of $svc)/eth_v1_config_identity" \
      "$STUB_DIR/http/127.0.0.1:$(port_of $svc)/eth_v1_node_identity"
  done
}

base
real_forks
run 0 "the first run's schedules agree once Lodestar's unscheduled Heze entry is dropped" \
  '^cl-1-lighthouse-geth: fork_schedule 8 scheduled entries$' \
  '^cl-2-lodestar-geth: fork_schedule 8 scheduled entries \(1 at FAR_FUTURE_EPOCH ignored\)$' \
  '^cl-2-lodestar-geth: gloas_fork_version 0x80000038$' \
  '^fork_schedule: PASS \(2 CLs: Gloas at epoch 0, fork digest 0x6c29705f\)$' '!fork schedules differ' \
  -- ethswarm-gloas

base
real_forks
edit cl-2-lodestar-geth eth_v1_config_fork_schedule 's/"current_version": "0x70000038", "epoch": "0"/"current_version": "0x70000038", "epoch": "1"/'
run 1 "the first run's schedules with a scheduled fork moved on one CL still differ" \
  '^- fork schedules differ: cl-1-lighthouse-geth and cl-2-lodestar-geth$' '^fork_schedule: FAIL' -- ethswarm-gloas

# Only FAR_FUTURE_EPOCH entries are dropped: a fork one CL schedules at a real epoch while the
# other leaves it unscheduled is a schedule difference.
base
real_forks
edit cl-2-lodestar-geth eth_v1_config_fork_schedule 's/"current_version": "0x90000038", "epoch": "18446744073709551615"/"current_version": "0x90000038", "epoch": "10"/'
run 1 "Heze scheduled at epoch 10 on Lodestar and not listed by Lighthouse fails" \
  '^cl-2-lodestar-geth: fork_schedule 9 scheduled entries$' '^cl-1-lighthouse-geth: fork_schedule 8 scheduled entries$' \
  '^- fork schedules differ: cl-1-lighthouse-geth and cl-2-lodestar-geth$' '^fork_schedule: FAIL' -- ethswarm-gloas

base
real_forks
edit cl-2-lodestar-geth eth_v1_config_fork_schedule 's/"current_version": "0x90000038", "epoch": "18446744073709551615"/"current_version": "0x90000038", "epoch": "10"/'
edit cl-1-lighthouse-geth eth_v1_config_fork_schedule 's/"epoch": "0"}]}/"epoch": "0"}, {"previous_version": "0x80000038", "current_version": "0x90000038", "epoch": "18446744073709551615"}]}/'
run 1 "Heze at epoch 10 on Lodestar and at FAR_FUTURE_EPOCH on Lighthouse fails" \
  '^cl-1-lighthouse-geth: fork_schedule 8 scheduled entries \(1 at FAR_FUTURE_EPOCH ignored\)$' \
  '^- fork schedules differ: cl-1-lighthouse-geth and cl-2-lodestar-geth$' '^fork_schedule: FAIL' -- ethswarm-gloas

base
real_forks
edit cl-1-lighthouse-geth eth_v1_config_fork_schedule 's/"current_version": "0x80000038", "epoch": "0"/"current_version": "0x80000038", "epoch": "18446744073709551615"/'
edit cl-1-lighthouse-geth eth_v1_config_spec 's/"GLOAS_FORK_EPOCH": "0"/"GLOAS_FORK_EPOCH": "18446744073709551615"/'
run 1 "Gloas at FAR_FUTURE_EPOCH is not dropped as unscheduled: it fails" \
  '^- cl-1-lighthouse-geth: Gloas \(0x80000038\) at epoch 18446744073709551615, not 0$' '^fork_schedule: FAIL' -- ethswarm-gloas

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
for n in 0 2; do
  run 3 "--min-finalized-epoch $n (below 3) is a DIAGNOSTIC run, never an acceptance PASS" \
    "^diagnostic: --min-finalized-epoch $n is below 3, the acceptance threshold$" \
    "^finality: PASS on poll 1 of 3 \(finalized epoch >= $n" \
    '^verdict: DIAGNOSTIC \(3/3 criteria passed; not an acceptance run\)$' '!^verdict: PASS' \
    -- --min-finalized-epoch "$n" ethswarm-gloas
done
run 0 "--min-finalized-epoch 3 is an acceptance run" '^verdict: PASS \(3/3 criteria\)$' '!^diagnostic:' \
  -- --min-finalized-epoch 3 ethswarm-gloas

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

# --- a concurrent pair: two enclaves, one genesis -------------------------------------------------

# pair_base: enclaves ethswarm-gloas-a (the CLs of base, ports 32801/32811) and ethswarm-gloas-b
# (the same CLs on ports 32901/32911), both passing, on one genesis.
pair_base() {
  local e svc port
  base
  for e in ethswarm-gloas-a ethswarm-gloas-b; do
    sed "s/ethswarm-gloas/$e/" "$STUB_DIR/inspect.ethswarm-gloas" > "$STUB_DIR/inspect.$e"
  done
  for svc in cl-1-lighthouse-geth:32901 cl-2-lodestar-geth:32911; do
    port=${svc#*:} svc=${svc%:*}
    cp "$STUB_DIR/port.$svc.http" "$STUB_DIR/port.$svc.http.a"
    cl "$svc" "$port"
    mv "$STUB_DIR/port.$svc.http" "$STUB_DIR/port.ethswarm-gloas-b.$svc.http"
    mv "$STUB_DIR/port.$svc.http.a" "$STUB_DIR/port.$svc.http"
  done
}
B1="$STUB_DIR/http/127.0.0.1:32901" B2="$STUB_DIR/http/127.0.0.1:32911"

pair_base
run 0 "a pair on one genesis, each passing, is a pair PASS" \
  '^== ethswarm-gloas-a$' '^devnet ethswarm-gloas-a: 2 CL services: ' '^cl-1-lighthouse-geth: http://127.0.0.1:32801$' \
  '^== ethswarm-gloas-b$' '^devnet ethswarm-gloas-b: 2 CL services: ' '^cl-1-lighthouse-geth: http://127.0.0.1:32901$' \
  "^pair: genesis_block_root $BLOCK \(both enclaves\)$" "^pair: genesis_state_root $STATE \(both enclaves\)$" \
  "^pair: genesis_validators_root $GVR \(both enclaves\)$" \
  '^pair genesis: PASS \(ethswarm-gloas-a and ethswarm-gloas-b: one genesis\)$' \
  '^pair verdict: PASS \(2 enclaves: 3/3 criteria each, one genesis\)$' \
  -- --pair ethswarm-gloas-a ethswarm-gloas-b
if grep -q '^port print ethswarm-gloas-b cl-2-lodestar-geth http$' "$STUB_DIR/kurtosis.log" &&
   grep -q '127.0.0.1:32911/eth/v1/beacon/states/head/finality_checkpoints$' "$STUB_DIR/curl.log"; then
  ok "a pair checks the second enclave's own CLs"
else
  bad "a pair checks the second enclave's own CLs" "$(cat "$STUB_DIR/kurtosis.log")"
fi

pair_base
for f in "$B1" "$B2"; do sed "s/$STATE/0x$(printf '55%.0s' {1..32})/" "$f/eth_v1_beacon_headers_genesis" > "$f/h" && mv "$f/h" "$f/eth_v1_beacon_headers_genesis"; done
run 1 "a pair whose genesis state roots differ fails" \
  "^- genesis_state_root: ethswarm-gloas-a $STATE, ethswarm-gloas-b 0x5555" '^pair genesis: FAIL$' \
  '^pair verdict: FAIL \(pair genesis\)$' '!^pair verdict: PASS' \
  -- --pair ethswarm-gloas-a ethswarm-gloas-b

pair_base
for f in "$B1" "$B2"; do sed "s/$GVR/0x$(printf '77%.0s' {1..32})/" "$f/eth_v1_beacon_genesis" > "$f/g" && mv "$f/g" "$f/eth_v1_beacon_genesis"; done
run 1 "a pair whose genesis_validators_root differs fails" \
  "^- genesis_validators_root: ethswarm-gloas-a $GVR, ethswarm-gloas-b 0x7777" '^pair genesis: FAIL$' \
  -- --pair ethswarm-gloas-a ethswarm-gloas-b

pair_base
for f in "$B1" "$B2"; do sed 's/"finalized":{"epoch":"4"/"finalized":{"epoch":"0"/' "$f/eth_v1_beacon_states_head_finality_checkpoints" > "$f/c" && mv "$f/c" "$f/eth_v1_beacon_states_head_finality_checkpoints"; done
run 1 "a pair whose second enclave does not finalize fails, naming it" \
  '^== ethswarm-gloas-b: exit 1$' '^pair genesis: PASS' '^pair verdict: FAIL \(ethswarm-gloas-b\)$' \
  -- --pair ethswarm-gloas-a ethswarm-gloas-b

pair_base
sed "s/$BLOCK/0x$(printf '66%.0s' {1..32})/" "$B2/eth_v1_beacon_headers_genesis" > "$B2/h" && mv "$B2/h" "$B2/eth_v1_beacon_headers_genesis"
run 1 "a pair whose second enclave's CLs disagree on genesis has no genesis to compare" \
  '^- ethswarm-gloas-b: no genesis record \(its genesis check failed\)$' '^pair genesis: FAIL$' \
  '^pair verdict: FAIL \(ethswarm-gloas-b; pair genesis\)$' \
  -- --pair ethswarm-gloas-a ethswarm-gloas-b

pair_base
rm "$STUB_DIR/inspect.ethswarm-gloas-b"
run 2 "a pair with an enclave that does not exist is a setup error" \
  '^ERROR: kurtosis enclave inspect ethswarm-gloas-b failed: ' '^pair verdict: ERROR \(setup error in ethswarm-gloas-b\)$' \
  -- --pair ethswarm-gloas-a ethswarm-gloas-b

pair_base
run 3 "a pair of DIAGNOSTIC runs is a pair DIAGNOSTIC, never a PASS" \
  '^pair genesis: PASS' '^pair verdict: DIAGNOSTIC \(not an acceptance run: ethswarm-gloas-a ethswarm-gloas-b\)$' '!^pair verdict: PASS' \
  -- --pair --min-finalized-epoch 2 ethswarm-gloas-a ethswarm-gloas-b

pair_base
rm -f "$tmp/pair.json"
run 0 "--record on a pair writes the pair's one genesis" "^pair genesis: record written to $tmp/pair.json$" \
  -- --pair --record "$tmp/pair.json" ethswarm-gloas-a ethswarm-gloas-b
if [[ -f $tmp/pair.json && $(cat "$tmp/pair.json") == "$want" ]]; then ok "the pair record holds the five genesis fields"; else bad "the pair record holds the five genesis fields" "$(cat "$tmp/pair.json" 2>&1)"; fi

pair_base
for f in "$B1" "$B2"; do sed "s/$STATE/0x$(printf '55%.0s' {1..32})/" "$f/eth_v1_beacon_headers_genesis" > "$f/h" && mv "$f/h" "$f/eth_v1_beacon_headers_genesis"; done
rm -f "$tmp/pair-bad.json"
run 1 "--record on a pair that differs writes nothing" '^pair genesis: FAIL$' -- --pair --record "$tmp/pair-bad.json" ethswarm-gloas-a ethswarm-gloas-b
if [[ ! -e $tmp/pair-bad.json ]]; then ok "no pair record is written when the enclaves differ"; else bad "no pair record is written when the enclaves differ"; fi

pair_base
run 0 "--reference on a pair checks both enclaves against it" '^== ethswarm-gloas-b$' '^genesis: PASS .*matches the reference run' \
  '^pair verdict: PASS' -- --pair --reference "$tmp/run-a.json" ethswarm-gloas-a ethswarm-gloas-b
n=$(grep -c "matches the reference run" <<<"$(PATH="$stubs:$PATH" bash "$script" --interval 0 --attempts 1 --pair --reference "$tmp/run-a.json" ethswarm-gloas-a ethswarm-gloas-b 2>&1)" || true)
if ((n == 2)); then ok "both enclaves of a pair match the reference"; else bad "both enclaves of a pair match the reference (got $n)"; fi

pair_base
run 0 "--services on a pair applies to both enclaves" '^devnet ethswarm-gloas-b: 2 CL services: cl-2-lodestar-geth cl-1-lighthouse-geth$' \
  -- --pair --services 'cl-2-lodestar-geth cl-1-lighthouse-geth' ethswarm-gloas-a ethswarm-gloas-b

# helper_pair <expect-exit> <description> <pattern> -- <pair args...>: lib/devnet.py pair directly,
# for records check-devnet.sh itself never writes.
helper_pair() {
  local expect=$1 desc=$2 pattern=$3 rc=0 out
  shift 4
  out=$(python3 -I "$here/../lib/devnet.py" pair "$@" 2>&1) || rc=$?
  if ((rc == expect)) && grep -Eq -- "$pattern" <<<"$out"; then ok "$desc"; else bad "$desc (exit $rc, want $expect)" "$out"; fi
}
helper_pair 1 "a pair record that is not JSON fails" '^- A: genesis record .* is not JSON' -- A "$tmp/garbage.json" B "$tmp/run-a.json"
helper_pair 1 "a pair record without every field fails" '^- A: genesis record .* has no genesis_block_root, genesis_fork_version, genesis_state_root, genesis_validators_root$' \
  -- A "$tmp/partial.json" B "$tmp/run-a.json"
printf '[]\n' > "$tmp/list.json"
helper_pair 1 "a pair record that is not an object fails" '^- B: genesis record .* is not a JSON object$' -- A "$tmp/run-a.json" B "$tmp/list.json"

pair_base
run 2 "--pair with one enclave is a usage error" '^usage: ' -- --pair ethswarm-gloas-a
run 2 "--pair with three enclaves is a usage error" '^usage: ' -- --pair a b c
run 2 "--pair naming one enclave twice is a usage error" 'two different enclaves' -- --pair ethswarm-gloas-a ethswarm-gloas-a

# --- every kurtosis call is bounded (--kurtosis-timeout) -------------------------------------------

# hung_stopped <description>: the hung stub call ($STUB_DIR/hang.pid) is gone.
hung_stopped() {
  local p stat
  if [[ ! -f $STUB_DIR/hang.pid ]]; then bad "$1 (no hang.pid: the call never hung)"; return; fi
  p=$(cat "$STUB_DIR/hang.pid")
  stat=$(ps -o stat= -p "$p" 2>/dev/null || true)
  if [[ -z $stat || $stat == Z* ]]; then
    ok "$1"
  else
    bad "$1 (pid $p still runs)"
    kill -KILL "$p" 2>/dev/null || true
  fi
}
base
touch "$STUB_DIR/hang.enclave.ethswarm-gloas"
SECONDS=0
run 2 "an enclave inspect that hangs is stopped at --kurtosis-timeout, a setup error" \
  '^ERROR: kurtosis enclave inspect ethswarm-gloas timed out after 1 s$' -- --kurtosis-timeout 1 ethswarm-gloas
if ((SECONDS < 10)); then ok "the hung enclave inspect takes about 1 s"; else bad "the hung enclave inspect takes about 1 s (${SECONDS} s)"; fi
hung_stopped "the hung enclave inspect is stopped"
base
touch "$STUB_DIR/hang.port.ethswarm-gloas"
run 2 "a port print that hangs is stopped at --kurtosis-timeout, a setup error" \
  '^ERROR: kurtosis port print ethswarm-gloas cl-1-lighthouse-geth http timed out after 1 s$' -- --kurtosis-timeout 1 ethswarm-gloas
hung_stopped "the hung port print is stopped"
pair_base
touch "$STUB_DIR/hang.enclave.ethswarm-gloas-b"
run 2 "--pair passes --kurtosis-timeout to both enclaves' runs" \
  '^ERROR: kurtosis enclave inspect ethswarm-gloas-b timed out after 1 s$' '^pair verdict: ERROR \(setup error in ethswarm-gloas-b\)$' \
  -- --pair --kurtosis-timeout 1 ethswarm-gloas-a ethswarm-gloas-b
hung_stopped "the hung enclave inspect of a pair is stopped"
# A child that keeps the call's stdout open must not hold the run past the limit either.
base
touch "$STUB_DIR/hang-child.enclave.ethswarm-gloas"
SECONDS=0
run 2 "an enclave inspect whose child keeps its stdout open still stops at --kurtosis-timeout" \
  '^ERROR: kurtosis enclave inspect ethswarm-gloas timed out after 1 s$' -- --kurtosis-timeout 1 ethswarm-gloas
if ((SECONDS < 10)); then ok "the open stdout does not hold the run (${SECONDS} s)"; else bad "the open stdout does not hold the run (${SECONDS} s)"; fi
hung_stopped "the hung enclave inspect with an open child is stopped"
kill -KILL "$(cat "$STUB_DIR/hang-child.pid")" 2>/dev/null || true
base
run 0 "a kurtosis call within the limit passes" '^verdict: PASS' -- --kurtosis-timeout 5 ethswarm-gloas
run 2 "a --kurtosis-timeout of 0 is a usage error" 'kurtosis-timeout must be an integer >= 1' -- --kurtosis-timeout 0 ethswarm-gloas
run 2 "a non-integer --kurtosis-timeout is a usage error" 'kurtosis-timeout must be an integer >= 1' -- --kurtosis-timeout soon ethswarm-gloas

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
run 2 "a CL without an http port is a setup error" '^ERROR: kurtosis port print ethswarm-gloas cl-2-lodestar-geth http failed: stub: no ' -- ethswarm-gloas

base
printf 'http://127.0.0.1:32811/$(id)\n' > "$STUB_DIR/port.cl-2-lodestar-geth.http"
run 2 "a port print answer that is not a bare URL is refused" '^ERROR: kurtosis port print .* is not an http://host:port URL' -- ethswarm-gloas

base
run 2 "no enclave is a usage error" '^usage: ' --
run 2 "two enclaves without --pair are a usage error" '^usage: ' -- a b
run 2 "an unknown option is a usage error" '^usage: ' -- --frobnicate ethswarm-gloas
run 2 "a non-integer --min-finalized-epoch is a usage error" 'min-finalized-epoch' -- --min-finalized-epoch x ethswarm-gloas
run 2 "a non-integer --attempts is a usage error" 'attempts' -- --attempts 0 ethswarm-gloas
run 2 "a service name that is not a CL name is refused" 'not a cl-<n>-\* service name' -- --services 'cl-1;id' ethswarm-gloas

rc=0; out=$(PATH="/usr/bin:/bin" bash "$script" ethswarm-gloas 2>&1) || rc=$?
if ((rc == 2)) && grep -q '^ERROR: kurtosis not found' <<<"$out"; then ok "a missing kurtosis CLI is a setup error"; else bad "a missing kurtosis CLI is a setup error (exit $rc)" "$out"; fi

echo "# $passed passed, $failed failed"
((failed == 0))
