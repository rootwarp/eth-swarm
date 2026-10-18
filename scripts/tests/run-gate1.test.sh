#!/usr/bin/env bash
# Tests for fuzz/run-gate1.sh (fuzz/run-m2a-gate.sh --gate gate1). Run:
# bash scripts/tests/run-gate1.test.sh
# Offline: the fake cargo-fuzz and rustc of fuzz-gate-fixture.sh, in a throwaway git repo
# holding gate 1's keyed paths and a copy of the scripts. Every run starts from an empty
# environment (env -i). What the m2a runner tests cover for the shared engine (the environment
# and cargo config refusals, the tool overrides, the toolchain pins, the lockfile checks) is not
# repeated here; these cases are gate 1's own: its targets, limits, key, file and work directory.
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

gate1_targets="rpc_chunk gossip_transform message_id enr_fields status_v2 metadata_v3 ping_goodbye"
fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" "$fx/crates/p2p-wire" "$fx/crates/consensus-types" \
  "$fx/crates/cl-p2p/src/rpc" "$fx/crates/cl-p2p/src/gossip" "$fx/crates/cl-discv5/src" \
  "$fx/crates/network-config/src" "$fx/scripts"
for t in $gate1_targets blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo"/fuzz/{m2a-common.sh,build-m2a.sh,run-m2a-gate.sh,check-m2a-gate.sh,run-gate1.sh,check-gate1.sh} "$fx/fuzz/"
cp "$repo/scripts/check-fuzz-lock.sh" "$fx/scripts/"
for f in crates/p2p-wire/lib.rs crates/consensus-types/lib.rs crates/cl-p2p/src/rpc/codec.rs \
  crates/cl-p2p/src/rpc/mod.rs crates/cl-p2p/src/rpc/limits.rs crates/cl-p2p/src/rpc/metrics.rs \
  crates/cl-p2p/src/gossip/mod.rs crates/cl-p2p/src/gossip/config.rs \
  crates/cl-discv5/src/enr.rs crates/network-config/src/lib.rs fuzz/src/lib.rs \
  fuzz/fuzz_targets/rpc_chunk.rs; do
  echo 'x' > "$fx/$f"
done
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo '[package]' > "$fx/crates/cl-discv5/Cargo.toml"
echo '[workspace]' > "$fx/Cargo.toml"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
echo 'version = 4' > "$fx/Cargo.lock"
printf 'target\nartifacts\n' > "$fx/fuzz/.gitignore"
git init -q "$fx"
g add -A
g commit -q -m fixture

bin="$tmp/bin"
mkdir -p "$bin" "$tmp/home" "$tmp/cargo-home"
fake_fuzz_tools "$bin"
CALLS="$tmp/calls"
runner="$fx/fuzz/run-gate1.sh"

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

# --- every target clean, into the default gate file ---
: > "$CALLS"
rc=0 out=$(gate_run -- "$runner" --seconds 3 2>&1) || rc=$?
file="$fx/fuzz/artifacts/gate1.json"
if ((rc == 0)) && [[ -f $file ]]; then ok "a clean run exits 0 and writes fuzz/artifacts/gate1.json"; else bad "clean run (exit $rc)" "$out"; fi
[[ -f $fx/fuzz/artifacts/gate1.log ]] && ok "the log is gate1.log beside it" || bad "no gate1.log"
[[ ! -e $fx/fuzz/artifacts/m2a-gate.json ]] && ok "no m2a gate file is written" || bad "an m2a gate file was written"
[[ $(field "$file" "(gate['gate'], gate['format'], gate['dirty'], gate['requested_seconds'])") == "('gate1-fuzz', 1, False, 3)" ]] \
  && ok "gate1-fuzz, format 1, clean tree, requested seconds" || bad "header" "$(field "$file" "gate")"
[[ $(field "$file" "gate['head']") == "$(g rev-parse HEAD)" ]] && ok "the commit SHA is recorded" || bad "head"
[[ $(field "$file" "' '.join(t['target'] for t in gate['targets'])") == "$gate1_targets" ]] \
  && ok "the seven gate-1 targets, in order" || bad "targets" "$(field "$file" "[t['target'] for t in gate['targets']]")"
[[ $(field "$file" "sorted(set((t['seconds'], t['crashes'], t['ooms'], t['timeouts'], t['completed'], t['exercised']) for t in gate['targets']))") \
  == "[(4, 0, 0, 0, True, True)]" ]] && ok "durations, 0 crashes, 0 OOMs, 0 timeouts, each" || bad "per-target fields" "$(field "$file" "gate['targets']")"
expected=$(gate_run -- "$fx/fuzz/check-gate1.sh" --print-expected)
[[ $(field "$file" "{t['target']: t['corpus_sha256'] for t in gate['targets']}") \
  == $(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["corpus_sha256"])' "$expected") ]] \
  && ok "each target's seed-corpus sha256 is the checker's" || bad "corpus sha256"
[[ $(field "$file" "gate['limits']['max_len']") \
  == "{'rpc_chunk': 1048576, 'gossip_transform': 2097152, 'message_id': 2097152, 'enr_fields': 4096, 'status_v2': 4096, 'metadata_v3': 4096, 'ping_goodbye': 4096}" ]] \
  && ok "gate 1's -max_len per target" || bad "max_len" "$(field "$file" "gate['limits']")"
[[ $(field "$file" "(gate['limits']['rss_limit_mb'], gate['limits']['malloc_limit_mb'], gate['limits']['timeout_s'])") == "(2048, 128, 10)" ]] \
  && ok "the m2a gate's RSS, malloc and time limits" || bad "limits"
missing=""
for t in $gate1_targets; do
  grep -q -- "fuzz run -O -a $t $fx/fuzz/target/gate1/$t/corpus $fx/fuzz/corpus/$t -- -max_total_time=3 -rss_limit_mb=2048 -malloc_limit_mb=128 -timeout=10 -max_len=$(gate_run -- -c ". $fx/fuzz/m2a-common.sh && m2a_max_len $t") " "$CALLS" \
    || missing="$missing $t"
done
[[ -z $missing ]] && ok "every target runs from fuzz/target/gate1/<target> with the time, RSS, malloc and -max_len limits" \
  || bad "fuzz run of$missing" "$(grep "fuzz run" "$CALLS")"
! grep -q "fuzz run -O -a blocks_by_range_resp" "$CALLS" && ok "the m2a-only target is not run" || bad "blocks_by_range_resp ran"
key=$(gate_run -- "$fx/fuzz/check-gate1.sh" --print-key)
grep -q '"crates/cl-discv5/src/enr.rs"' <<<"$key" && grep -q '"crates/cl-p2p/src/gossip/config.rs"' <<<"$key" \
  && grep -q '"fuzz/run-gate1.sh"' <<<"$key" && grep -q '"crates/network-config"' <<<"$key" \
  && ok "gate 1's key holds the gossip, ENR and network-config paths" || bad "key" "$key"
[[ $(field "$file" "json.dumps(gate['decoder_key'], sort_keys=True)") \
  == $(python3 -I -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True))' "$key") ]] \
  && ok "the decoder key is check-gate1.sh --print-key" || bad "decoder key"

# A full-length clean run passes check-gate1.sh, and only it.
gate_run -- "$runner" --seconds 3600 --out "$tmp/full.json" >/dev/null 2>&1 || true
if out=$(gate_run -- "$fx/fuzz/check-gate1.sh" "$tmp/full.json" 2>&1) && grep -q "gate 1 OK" <<<"$out"; then
  ok "a full clean run passes check-gate1.sh"
else
  bad "full run check" "$out"
fi
rc=0 out=$(gate_run -- "$fx/fuzz/check-m2a-gate.sh" "$tmp/full.json" 2>&1) || rc=$?
((rc == 1)) && grep -q "want m2a-fuzz" <<<"$out" && ok "check-m2a-gate.sh refuses a gate-1 file" || bad "m2a check of a gate-1 file (exit $rc)" "$out"

# --- findings ---
fail_case() {
  local desc=$1 env=$2 expr=$3 want=$4 rc=0 out
  out=$(gate_run "$env" -- "$runner" --seconds 3 --out "$tmp/f.json" 2>&1) || rc=$?
  if ((rc == 1)) && [[ $(field "$tmp/f.json" "$expr") == "$want" ]]; then ok "$desc"; else bad "$desc (exit $rc)" "$out"; fi
}
fail_case "a crash in enr_fields fails the gate" FAKE_enr_fields=crash \
  "[(t['target'], t['crashes'], t['artifacts']) for t in gate['targets'] if t['crashes']]" \
  "[('enr_fields', 1, ['crash-abc'])]"
fail_case "an OOM in gossip_transform fails the gate" FAKE_gossip_transform=oom \
  "[(t['target'], t['ooms']) for t in gate['targets'] if t['ooms']]" "[('gossip_transform', 1)]"
fail_case "a timeout in rpc_chunk fails the gate" FAKE_rpc_chunk=timeout \
  "[(t['target'], t['timeouts']) for t in gate['targets'] if t['timeouts']]" "[('rpc_chunk', 1)]"
fail_case "a message_id run that runs no code fails the gate" FAKE_message_id=noop \
  "[(t['target'], t['exercised']) for t in gate['targets'] if not t['exercised']]" "[('message_id', False)]"

# --- refusals ---
for args in "--gate bogus" "--gate m2a" "--seconds 0" "--bogus"; do
  rc=0 out=$(gate_run -- "$runner" $args 2>&1) || rc=$?
  ((rc == 2)) && ok "usage error: run-gate1.sh $args" || bad "usage error: $args (exit $rc)" "$out"
done
rc=0 out=$(gate_run -- "$fx/fuzz/run-m2a-gate.sh" --gate bogus 2>&1) || rc=$?
((rc == 2)) && grep -q "m2a or gate1" <<<"$out" && ok "run-m2a-gate.sh refuses an unknown gate" || bad "unknown gate (exit $rc)" "$out"
head -c 4097 /dev/zero > "$fx/fuzz/corpus/enr_fields/too-long"
g add -A && g commit -q -m "long seed"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/s.json" 2>&1) || rc=$?
((rc == 2)) && grep -q 'enr_fields/too-long' <<<"$out" && ok "a seed over its -max_len stops the run" || bad "seed over max_len (exit $rc)" "$out"
g reset -q --hard HEAD~1
# A path only gate 1 keys: dirty for gate 1, not for the m2a gate.
echo '// edit' >> "$fx/crates/cl-discv5/src/enr.rs"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/d.json" 2>&1) || rc=$?
((rc == 2)) && grep -q 'crates/cl-discv5/src/enr.rs' <<<"$out" && ok "an edit to a gate-1 keyed path stops the gate-1 run" || bad "dirty (exit $rc)" "$out"
rc=0 out=$(gate_run -- "$fx/fuzz/run-m2a-gate.sh" --seconds 3 --out "$tmp/m.json" 2>&1) || rc=$?
((rc == 0)) && [[ $(field "$tmp/m.json" "(gate['gate'], gate['dirty'], len(gate['targets']))") == "('m2a-fuzz', False, 4)" ]] \
  && ok "the same edit leaves the m2a gate clean (outside its key)" || bad "m2a run with a gate-1 edit (exit $rc)" "$out"
g checkout -q -- crates/cl-discv5/src/enr.rs

echo "# $passed passed, $failed failed"
((failed == 0))
