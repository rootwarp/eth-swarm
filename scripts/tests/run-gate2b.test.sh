#!/usr/bin/env bash
# Tests for fuzz/run-gate2b.sh (fuzz/run-m2a-gate.sh --gate gate2b). Run:
# bash scripts/tests/run-gate2b.test.sh
# Offline: the fake cargo-fuzz and rustc of fuzz-gate-fixture.sh, in a throwaway git repo
# holding gate 2b's keyed paths and a copy of the scripts. Every run starts from an empty
# environment (env -i). What the m2a runner tests cover for the shared engine (the environment
# and cargo config refusals, the tool overrides, the toolchain pins, the lockfile checks) is not
# repeated here; these cases are gate 2b's own: its target, limits, floor, key, file and work
# directory.
# Needs git and python3. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source=fuzz-gate-fixture.sh
. "$here/fuzz-gate-fixture.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() { failed=$((failed + 1)); echo "FAIL - $1"; [[ -z ${2:-} ]] || printf '%s\n' "$2" | sed 's/^/       /'; }

g() { git -C "$fx" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }

gate2b_targets="column_contract"
fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" "$fx/crates/p2p-wire" "$fx/crates/consensus-types" \
  "$fx/crates/cl-p2p/src/rpc" "$fx/crates/cl-p2p/src/gossip" "$fx/crates/cl-discv5/src" \
  "$fx/crates/network-config/src" "$fx/crates/cl-chain/src/probe" "$fx/crates/cl-chain-columns/src" \
  "$fx/crates/ethswarm-proto/src" "$fx/crates/ipc/src" "$fx/proto/ethswarm/chain/v1" "$fx/scripts"
for t in $gate2b_targets data_column_sidecar columns_by_range_req columns_by_root_req rpc_chunk \
  gossip_transform message_id enr_fields status_v2 metadata_v3 ping_goodbye blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo"/fuzz/{m2a-common.sh,build-m2a.sh,run-m2a-gate.sh,check-m2a-gate.sh,run-gate1.sh,check-gate1.sh,run-gate2a.sh,check-gate2a.sh,run-gate2b.sh,check-gate2b.sh} "$fx/fuzz/"
cp "$repo/scripts/check-fuzz-lock.sh" "$fx/scripts/"
for f in crates/p2p-wire/lib.rs crates/consensus-types/lib.rs crates/cl-p2p/src/rpc/codec.rs \
  crates/cl-p2p/src/rpc/mod.rs crates/cl-p2p/src/rpc/limits.rs crates/cl-p2p/src/rpc/metrics.rs \
  crates/cl-p2p/src/rpc/unsupported.rs crates/cl-p2p/src/rpc/columns.rs \
  crates/cl-p2p/src/gossip/mod.rs crates/cl-p2p/src/gossip/config.rs crates/cl-chain/src/reqresp.rs \
  crates/cl-chain/src/probe/ingest.rs crates/cl-chain-columns/src/lib.rs \
  crates/ethswarm-proto/src/lib.rs crates/ipc/src/lib.rs proto/ethswarm/chain/v1/reqresp.proto \
  crates/cl-discv5/src/enr.rs crates/network-config/src/lib.rs fuzz/src/lib.rs \
  fuzz/fuzz_targets/column_contract.rs; do
  echo 'x' > "$fx/$f"
done
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo '[package]' > "$fx/crates/cl-discv5/Cargo.toml"
echo '[package]' > "$fx/crates/cl-chain/Cargo.toml"
echo '[workspace]' > "$fx/Cargo.toml"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
echo 'version = 4' > "$fx/Cargo.lock"
printf 'target\nartifacts\n' > "$fx/fuzz/.gitignore"
# The modules the keyed files import, which the keys hold too (fuzz/m2a-common.sh).
for f in crates/cl-p2p/src/transport.rs crates/cl-p2p/src/transport/quota.rs \
  crates/cl-p2p/src/behaviour.rs crates/cl-p2p/src/peer_caps.rs crates/cl-p2p/src/gossip/mod.rs \
  crates/cl-chain/src/probe.rs crates/cl-chain/src/probe/ingest.rs crates/cl-chain/src/da/custody.rs \
  crates/cl-chain/src/verify/client.rs crates/cl-chain/src/lib.rs \
  crates/cl-p2p/src/lib.rs crates/cl-p2p/src/custody.rs crates/cl-p2p/src/identity.rs \
  crates/cl-p2p/src/m2a_session.rs crates/cl-p2p/src/m2a_session/config.rs crates/cl-p2p/src/peers/mod.rs \
  crates/cl-p2p/src/testkit.rs crates/cl-discv5/src/lib.rs crates/cl-discv5/src/enr.rs \
  crates/cl-discv5/src/metrics.rs crates/cl-discv5/src/service.rs crates/cl-chain-columns/src/lib.rs \
  crates/ethswarm-proto/src/lib.rs crates/ipc/src/lib.rs proto/ethswarm/chain/v1/reqresp.proto; do
  mkdir -p "$(dirname "$fx/$f")"
  [[ -e $fx/$f ]] || echo 'x' > "$fx/$f"
done
git init -q "$fx"
g add -A
g commit -q -m fixture

bin="$tmp/bin"
mkdir -p "$bin" "$tmp/home" "$tmp/cargo-home"
fake_fuzz_tools "$bin"
CALLS="$tmp/calls"
runner="$fx/fuzz/run-gate2b.sh"

# gate_run [VAR=value...] -- <script> [args...]: the script in an empty environment plus the fakes.
gate_run() {
  local vars=()
  while [[ $1 != -- ]]; do vars+=("$1"); shift; done
  shift
  env -i PATH="$bin:$(dirname "$(command -v python3)"):$(dirname "$(command -v git)"):/usr/bin:/bin:/usr/sbin:/sbin" \
    HOME="$tmp/home" CARGO_HOME="$tmp/cargo-home" CALLS="$CALLS" TMPDIR="$tmp" \
    ${vars[@]+"${vars[@]}"} bash "$@"
}

# field <gate.json> <python expression over `gate`>
field() { python3 -I -c 'import json,sys; gate=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }

# --- the target clean, into the default gate file ---
: > "$CALLS"
rc=0 out=$(gate_run -- "$runner" --seconds 3 2>&1) || rc=$?
file="$fx/fuzz/artifacts/gate2b.json"
if ((rc == 0)) && [[ -f $file ]]; then ok "a clean run exits 0 and writes fuzz/artifacts/gate2b.json"; else bad "clean run (exit $rc)" "$out"; fi
[[ -f $fx/fuzz/artifacts/gate2b.log ]] && ok "the log is gate2b.log beside it" || bad "no gate2b.log"
[[ ! -e $fx/fuzz/artifacts/m2a-gate.json && ! -e $fx/fuzz/artifacts/gate1.json && ! -e $fx/fuzz/artifacts/gate2a.json ]] \
  && ok "no m2a, gate-1 or gate-2a file is written" || bad "another gate's file was written"
[[ $(field "$file" "(gate['gate'], gate['format'], gate['dirty'], gate['requested_seconds'])") == "('gate2b-fuzz', 1, False, 3)" ]] \
  && ok "gate2b-fuzz, format 1, clean tree, requested seconds" || bad "header" "$(field "$file" "gate")"
[[ $(field "$file" "gate['head']") == "$(g rev-parse HEAD)" ]] && ok "the commit SHA is recorded" || bad "head"
[[ $(field "$file" "' '.join(t['target'] for t in gate['targets'])") == "$gate2b_targets" ]] \
  && ok "the one gate-2b target" || bad "targets" "$(field "$file" "[t['target'] for t in gate['targets']]")"
[[ $(field "$file" "sorted(set((t['seconds'], t['crashes'], t['ooms'], t['timeouts'], t['completed'], t['exercised']) for t in gate['targets']))") \
  == "[(4, 0, 0, 0, True, True)]" ]] && ok "duration, 0 crashes, 0 OOMs, 0 timeouts" || bad "per-target fields" "$(field "$file" "gate['targets']")"
expected=$(gate_run -- "$fx/fuzz/check-gate2b.sh" --print-expected)
[[ $(field "$file" "{t['target']: t['corpus_sha256'] for t in gate['targets']}") \
  == $(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["corpus_sha256"])' "$expected") ]] \
  && ok "the seed-corpus sha256 is the checker's" || bad "corpus sha256"
[[ $(field "$file" "gate['limits']['max_len']") == "{'column_contract': 262144}" ]] \
  && ok "gate 2b's -max_len" || bad "max_len" "$(field "$file" "gate['limits']")"
[[ $(field "$file" "(gate['limits']['rss_limit_mb'], gate['limits']['malloc_limit_mb'], gate['limits']['timeout_s'], gate['limits']['build_flags'])") == "(2048, 128, 10, ['-O', '-a'])" ]] \
  && ok "the shared RSS, malloc and time limits and build flags" || bad "limits"
grep -q -- "fuzz run -O -a column_contract $fx/fuzz/target/gate2b/column_contract/corpus $fx/fuzz/corpus/column_contract -- -max_total_time=3 -rss_limit_mb=2048 -malloc_limit_mb=128 -timeout=10 -max_len=262144 " "$CALLS" \
  && ok "the target runs from fuzz/target/gate2b/column_contract with the time, RSS, malloc and -max_len limits" \
  || bad "fuzz run" "$(grep "fuzz run" "$CALLS")"
others=""
for t in data_column_sidecar columns_by_range_req columns_by_root_req rpc_chunk gossip_transform \
  message_id enr_fields status_v2 metadata_v3 ping_goodbye blocks_by_range_resp; do
  ! grep -q "fuzz run -O -a $t " "$CALLS" || others="$others $t"
done
[[ -z $others ]] && ok "no other gate's target is run" || bad "ran:$others"
key=$(gate_run -- "$fx/fuzz/check-gate2b.sh" --print-key)
missing=""
for path in crates/cl-chain/Cargo.toml crates/cl-chain/src crates/cl-chain-columns crates/ethswarm-proto \
  proto/ethswarm crates/ipc crates/network-config crates/p2p-wire crates/cl-p2p/src/rpc \
  fuzz/src fuzz/corpus fuzz/run-gate2b.sh fuzz/m2a-common.sh; do
  grep -q "\"$path\"" <<<"$key" || missing="$missing $path"
done
[[ -z $missing ]] && ok "gate 2b's key holds cl-chain, the column env, the chain.v1 contract and the shared fuzz sources" \
  || bad "key lacks$missing" "$key"
! grep -q '"crates/cl-discv5/src/enr.rs"' <<<"$key" && ! grep -q '"fuzz/run-gate2a.sh"' <<<"$key" \
  && ! grep -q '"crates/cl-chain/src/reqresp.rs"' <<<"$key" \
  && ok "gate 2b's key leaves out the other gates' own paths" || bad "key" "$key"
[[ $(field "$file" "json.dumps(gate['decoder_key'], sort_keys=True)") \
  == $(python3 -I -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True))' "$key") ]] \
  && ok "the decoder key is check-gate2b.sh --print-key" || bad "decoder key"

# A full-length clean run passes check-gate2b.sh, and only it.
gate_run -- "$runner" --seconds 3600 --out "$tmp/full.json" >/dev/null 2>&1 || true
if out=$(gate_run -- "$fx/fuzz/check-gate2b.sh" "$tmp/full.json" 2>&1) && grep -q "gate 2b OK" <<<"$out"; then
  ok "a full clean run passes check-gate2b.sh"
else
  bad "full run check" "$out"
fi
rc=0 out=$(gate_run -- "$fx/fuzz/check-gate2a.sh" "$tmp/full.json" 2>&1) || rc=$?
((rc == 1)) && grep -q "want gate2a-fuzz" <<<"$out" && ok "check-gate2a.sh refuses a gate-2b file" || bad "gate-2a check of a gate-2b file (exit $rc)" "$out"
# A short clean run is a smoke run, which the checker refuses.
rc=0 out=$(gate_run -- "$fx/fuzz/check-gate2b.sh" "$file" 2>&1) || rc=$?
((rc == 1)) && grep -q "a smoke run is not a gate" <<<"$out" && ok "check-gate2b.sh refuses a smoke run" || bad "smoke run check (exit $rc)" "$out"

# --- findings ---
fail_case() {
  local desc=$1 env=$2 expr=$3 want=$4 rc=0 out
  out=$(gate_run "$env" -- "$runner" --seconds 3 --out "$tmp/f.json" 2>&1) || rc=$?
  if ((rc == 1)) && [[ $(field "$tmp/f.json" "$expr") == "$want" ]]; then ok "$desc"; else bad "$desc (exit $rc)" "$out"; fi
}
fail_case "a crash (an invariant failure) fails the gate" FAKE_column_contract=crash \
  "[(t['target'], t['crashes'], t['artifacts']) for t in gate['targets'] if t['crashes']]" \
  "[('column_contract', 1, ['crash-abc'])]"
fail_case "an OOM fails the gate" FAKE_column_contract=oom \
  "[(t['target'], t['ooms']) for t in gate['targets'] if t['ooms']]" "[('column_contract', 1)]"
fail_case "a timeout fails the gate" FAKE_column_contract=timeout \
  "[(t['target'], t['timeouts']) for t in gate['targets'] if t['timeouts']]" "[('column_contract', 1)]"
fail_case "a run that runs no code fails the gate" FAKE_column_contract=noop \
  "[(t['target'], t['exercised']) for t in gate['targets'] if not t['exercised']]" "[('column_contract', False)]"
fail_case "a run cut short fails the gate" FAKE_column_contract=cut \
  "[(t['target'], t['completed']) for t in gate['targets'] if not t['completed']]" "[('column_contract', False)]"

# --- refusals ---
for args in "--gate bogus" "--gate gate2a" "--seconds 0" "--bogus"; do
  rc=0 out=$(gate_run -- "$runner" $args 2>&1) || rc=$?
  ((rc == 2)) && ok "usage error: run-gate2b.sh $args" || bad "usage error: $args (exit $rc)" "$out"
done
rc=0 out=$(gate_run -- "$fx/fuzz/run-m2a-gate.sh" --gate gate3 2>&1) || rc=$?
((rc == 2)) && grep -q "m2a, gate1, gate2a or gate2b" <<<"$out" && ok "run-m2a-gate.sh refuses an unknown gate" || bad "unknown gate (exit $rc)" "$out"
head -c 262145 /dev/zero > "$fx/fuzz/corpus/column_contract/too-long"
g add -A && g commit -q -m "long seed"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/s.json" 2>&1) || rc=$?
((rc == 2)) && grep -q 'column_contract/too-long' <<<"$out" && ok "a seed over its -max_len stops the run" || bad "seed over max_len (exit $rc)" "$out"
g reset -q --hard HEAD~1
head -c 262144 /dev/zero > "$fx/fuzz/corpus/column_contract/at-max-len"
g add -A && g commit -q -m "seed at max_len"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/s.json" 2>&1) || rc=$?
((rc == 0)) && ok "a seed at its -max_len runs" || bad "seed at max_len (exit $rc)" "$out"
g reset -q --hard HEAD~1
# The path only gate 2b keys: dirty for gate 2b, not for gate 2a.
echo '# edit' >> "$fx/fuzz/run-gate2b.sh"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/d.json" 2>&1) || rc=$?
((rc == 2)) && grep -q 'fuzz/run-gate2b.sh' <<<"$out" && ok "an edit to a gate-2b keyed path stops the gate-2b run" || bad "dirty (exit $rc)" "$out"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --allow-dirty --out "$tmp/d.json" 2>&1) || rc=$?
((rc == 0)) && [[ $(field "$tmp/d.json" "gate['dirty']") == True ]] && ok "--allow-dirty runs it and records dirty" || bad "allow-dirty (exit $rc)" "$out"
rc=0 out=$(gate_run -- "$fx/fuzz/run-gate2a.sh" --seconds 3 --out "$tmp/m.json" 2>&1) || rc=$?
((rc == 0)) && [[ $(field "$tmp/m.json" "(gate['gate'], gate['dirty'], len(gate['targets']))") == "('gate2a-fuzz', False, 3)" ]] \
  && ok "the same edit leaves gate 2a clean (outside its key)" || bad "gate-2a run with a gate-2b edit (exit $rc)" "$out"
g checkout -q -- fuzz/run-gate2b.sh

echo "# $passed passed, $failed failed"
((failed == 0))
