#!/usr/bin/env bash
# Tests for fuzz/check-gate2b.sh (fuzz/check-m2a-gate.sh --gate gate2b). Run:
# bash scripts/tests/check-gate2b.test.sh
# Each case checks a gate-2b file against a throwaway git repo holding gate 2b's keyed paths and
# a copy of the scripts. The rules every gate shares (the scrubbed git, the byte comparison of
# keyed files, assume-unchanged and skip-worktree, the bounded read) are the m2a and gate-1
# checker tests'; these cases are gate 2b's own: its gate name, target, limits, floor and key,
# and that its files and key stay apart from the other gates'. Needs git and python3. Works on
# bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
# shellcheck source=fuzz-gate-fixture.sh
. "$here/fuzz-gate-fixture.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() { failed=$((failed + 1)); echo "FAIL - $1"; }
# check <expect: pass|fail> <description> <want in output or ""> <command...>; with $unwanted
# set, the output must not hold it either.
unwanted=""
check() {
  local expect=$1 desc=$2 want=$3 rc=0 out ok=0
  shift 3
  out=$("$@" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)) && [[ -n $unwanted ]] && grep -qF -- "$unwanted" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

# check_clean: check, and the output holds no Python traceback (every refusal is a message).
check_clean() { unwanted=Traceback check "$@"; }

g() { git -C "$fx" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }

gate2b_targets=(column_contract)
fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" "$fx/crates/p2p-wire/src" \
  "$fx/crates/consensus-types/src" "$fx/crates/cl-p2p/src/rpc" "$fx/crates/cl-p2p/src/gossip" \
  "$fx/crates/cl-discv5/src" "$fx/crates/network-config/src" "$fx/crates/cl-chain/src/probe" \
  "$fx/crates/cl-chain-columns/src" "$fx/crates/ethswarm-proto/src" "$fx/crates/ipc/src" \
  "$fx/proto/ethswarm/chain/v1"
for t in "${gate2b_targets[@]}" data_column_sidecar columns_by_range_req columns_by_root_req \
  rpc_chunk gossip_transform message_id enr_fields status_v2 metadata_v3 ping_goodbye \
  blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo"/fuzz/{m2a-common.sh,check-m2a-gate.sh,check-gate1.sh,check-gate2a.sh,check-gate2b.sh} "$fx/fuzz/"
echo '# run' > "$fx/fuzz/run-m2a-gate.sh"
echo '# run gate 1' > "$fx/fuzz/run-gate1.sh"
echo '# run gate 2a' > "$fx/fuzz/run-gate2a.sh"
echo '# run gate 2b' > "$fx/fuzz/run-gate2b.sh"
echo '# build' > "$fx/fuzz/build-m2a.sh"
echo '[workspace]' > "$fx/Cargo.toml"
for f in crates/p2p-wire/src/lib.rs crates/consensus-types/src/lib.rs crates/cl-p2p/src/rpc/mod.rs \
  crates/cl-p2p/src/rpc/codec.rs crates/cl-p2p/src/rpc/limits.rs crates/cl-p2p/src/rpc/metrics.rs \
  crates/cl-p2p/src/rpc/unsupported.rs crates/cl-p2p/src/rpc/columns.rs \
  crates/cl-p2p/src/gossip/mod.rs crates/cl-p2p/src/gossip/config.rs crates/cl-chain/src/reqresp.rs \
  crates/cl-chain/src/probe/ingest.rs crates/cl-chain-columns/src/lib.rs \
  crates/ethswarm-proto/src/lib.rs crates/ipc/src/lib.rs proto/ethswarm/chain/v1/reqresp.proto \
  crates/cl-discv5/src/enr.rs crates/network-config/src/lib.rs fuzz/src/lib.rs \
  fuzz/fuzz_targets/column_contract.rs; do
  echo "// $f" > "$fx/$f"
done
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo '[package]' > "$fx/crates/cl-discv5/Cargo.toml"
echo '[package]' > "$fx/crates/cl-chain/Cargo.toml"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
echo 'version = 4' > "$fx/Cargo.lock"
# More files of the keyed crates (fuzz/m2a-common.sh keys each crate whole).
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
fixture_key_dirs "$fx"
git init -q "$fx"
g add -A
g commit -q -m fixture
# The commit before the keyed commit: a keyed file differs there, so its decoder key does too.
before_key=$(g rev-parse HEAD)
echo '// keyed change' >> "$fx/crates/cl-chain/src/probe/ingest.rs"
g commit -q -am "keyed change"
checker="$fx/fuzz/check-gate2b.sh"
gate2a_checker="$fx/fuzz/check-gate2a.sh"
gate1_checker="$fx/fuzz/check-gate1.sh"
m2a_checker="$fx/fuzz/check-m2a-gate.sh"

# gate <gate2b|gate2a|gate1|m2a> <file> [python statements editing `gate`]: writes a passing gate
# file of that gate for the fixture, then applies the edits.
gate() {
  local which=$1 file=$2 expected
  shift 2
  case $which in
    gate2b) expected=$(bash "$checker" --print-expected) ;;
    gate2a) expected=$(bash "$gate2a_checker" --print-expected) ;;
    gate1) expected=$(bash "$gate1_checker" --print-expected) ;;
    *) expected=$(bash "$m2a_checker" --print-expected) ;;
  esac
  EXPECTED=$expected WHICH=$which HEAD_SHA=$(g rev-parse HEAD) python3 -I - "$file" "$@" <<'PY'
import json, os, sys
want = json.loads(os.environ["EXPECTED"])
targets = list(want["corpus_sha256"])
gate = {
    "gate": {"gate2b": "gate2b-fuzz", "gate2a": "gate2a-fuzz", "gate1": "gate1-fuzz"}.get(os.environ["WHICH"], "m2a-fuzz"),
    "format": 1,
    "requested_seconds": 3600,
    "head": os.environ["HEAD_SHA"],
    "dirty": False,
    "decoder_key": want["decoder_key"],
    "limits": want["limits"],
    "toolchain": dict(want["toolchain"], rustc="rustc 1.101.0-nightly (5d8fec066 2026-10-16)"),
    "cargo_fuzz": want["cargo_fuzz"],
    "overrides": {},
    "targets": [
        {"target": t, "seconds": 3601, "execs": 1000, "crashes": 0, "ooms": 0, "timeouts": 0,
         "completed": True, "exercised": True, "exit_code": 0,
         "seed_ft": want["min_seed_ft"][t], "final_ft": want["min_seed_ft"][t] + 1,
         "corpus_sha256": want["corpus_sha256"][t]}
        for t in targets
    ],
}
for stmt in sys.argv[2:]:
    exec(stmt)
with open(sys.argv[1], "w") as f:
    json.dump(gate, f)
PY
  echo "$file"
}

expected=$(bash "$checker" --print-expected)
[[ $(python3 -I -c 'import json,sys; print(" ".join(json.loads(sys.argv[1])["corpus_sha256"]))' "$expected") == "${gate2b_targets[*]}" ]] \
  && ok "the expected values cover gate 2b's one target" || bad "expected targets: $expected"
python3 -I -c 'import json,sys; m=json.loads(sys.argv[1])["limits"]["max_len"]; sys.exit(not (m == {"column_contract": 262144}))' "$expected" \
  && ok "gate 2b's -max_len policy, and only its target" || bad "max_len: $expected"
python3 -I -c 'import json,sys; m=json.loads(sys.argv[1])["min_seed_ft"]; sys.exit(not (m == {"column_contract": 5000}))' "$expected" \
  && ok "gate 2b's coverage floor" || bad "min_seed_ft: $expected"

ok2b="$tmp/ok.json"
check pass "a complete gate-2b file for this tree" "gate 2b OK: 1 targets" bash "$checker" "$(gate gate2b "$ok2b")"
check pass "the gate-2a checker still takes a complete gate-2a file" "gate 2a OK: 3 targets" bash "$gate2a_checker" "$(gate gate2a "$tmp/gate2a.json")"
check pass "the gate-1 checker still takes a complete gate-1 file" "gate 1 OK: 7 targets" bash "$gate1_checker" "$(gate gate1 "$tmp/gate1.json")"
check pass "the m2a checker still takes a complete m2a file" "m2a gate OK: 4 targets" bash "$m2a_checker" "$(gate m2a "$tmp/m2a.json")"
check fail "an m2a file is not a gate-2b file" "want gate2b-fuzz" bash "$checker" "$tmp/m2a.json"
check fail "a gate-2a file is not a gate-2b file" "want gate2b-fuzz" bash "$checker" "$tmp/gate2a.json"
check fail "a gate-2b file is not a gate-2a file" "want gate2a-fuzz" bash "$gate2a_checker" "$ok2b"
check fail "a gate-2b file is not an m2a file" "want m2a-fuzz" bash "$m2a_checker" "$ok2b"
check fail "a gate-2b file named gate2a-fuzz still lacks the gate-2a key and targets" "decoder key stale" bash "$gate2a_checker" \
  "$(gate gate2b "$tmp/renamed.json" 'gate["gate"] = "gate2a-fuzz"')"
check fail "gate 2b without its target" "want exactly" bash "$checker" \
  "$(gate gate2b "$tmp/none.json" 'gate["targets"] = []')"
check fail "an extra target" "want exactly" bash "$checker" \
  "$(gate gate2b "$tmp/extra.json" 'gate["targets"].append(dict(gate["targets"][0], target="data_column_sidecar"))')"
check fail "the target listed twice" "want exactly" bash "$checker" \
  "$(gate gate2b "$tmp/twice.json" 'gate["targets"].append(dict(gate["targets"][0]))')"
check fail "column_contract ran 3599 s" "column_contract: 3599 s < 3600 s" bash "$checker" \
  "$(gate gate2b "$tmp/short.json" 'gate["targets"][0]["seconds"] = 3599')"
check fail "a smoke run" "requested_seconds" bash "$checker" \
  "$(gate gate2b "$tmp/smoke.json" 'gate["requested_seconds"] = 60')"
check fail "a crash (an invariant failure)" "column_contract: crashes 1" bash "$checker" \
  "$(gate gate2b "$tmp/crash.json" 'gate["targets"][0]["crashes"] = 1')"
check fail "an OOM" "column_contract: ooms 1" bash "$checker" \
  "$(gate gate2b "$tmp/oom.json" 'gate["targets"][0]["ooms"] = 1')"
check fail "a timeout" "column_contract: timeouts 1" bash "$checker" \
  "$(gate gate2b "$tmp/timeout.json" 'gate["targets"][0]["timeouts"] = 1')"
check fail "no executions" "column_contract: execs 0" bash "$checker" \
  "$(gate gate2b "$tmp/noexec.json" 'gate["targets"][0]["execs"] = 0')"
check fail "an incomplete run" "completed False" bash "$checker" \
  "$(gate gate2b "$tmp/incomplete.json" 'gate["targets"][0]["completed"] = False')"
check fail "a dirty run" "dirty" bash "$checker" "$(gate gate2b "$tmp/dirty.json" 'gate["dirty"] = True')"
check fail "the default -max_len" "limits" bash "$checker" \
  "$(gate gate2b "$tmp/maxlen.json" 'gate["limits"]["max_len"]["column_contract"] = 4096')"
check fail "a weaker RSS limit" "limits" bash "$checker" \
  "$(gate gate2b "$tmp/rss.json" 'gate["limits"]["rss_limit_mb"] = 8192')"
check fail "a weaker malloc limit" "limits" bash "$checker" \
  "$(gate gate2b "$tmp/malloc.json" 'gate["limits"]["malloc_limit_mb"] = 2048')"
check fail "column_contract under its coverage floor" "column_contract: seed_ft 4999 under the floor" bash "$checker" \
  "$(gate gate2b "$tmp/ft.json" 'gate["targets"][0]["seed_ft"] = 4999; gate["targets"][0]["final_ft"] = 4999')"
check fail "another seed corpus" "corpus_sha256" bash "$checker" \
  "$(gate gate2b "$tmp/corpus.json" 'gate["targets"][0]["corpus_sha256"] = "0" * 64')"
check fail "a tool override" "overrides" bash "$checker" \
  "$(gate gate2b "$tmp/ov.json" 'gate["overrides"] = {"RUSTC": "rustc"}')"
check fail "another toolchain" "toolchain channel" bash "$checker" \
  "$(gate gate2b "$tmp/tc.json" 'gate["toolchain"]["channel"] = "nightly"')"
# The commit the file names.
check fail "no head" "head: missing" bash "$checker" "$(gate gate2b "$tmp/nohead.json" 'del gate["head"]')"
check fail "a malformed head" "is not a 40-character lowercase hex commit id" bash "$checker" \
  "$(gate gate2b "$tmp/badhead.json" "gate['head'] = '${before_key:0:39}'")"
check fail "an unknown head" "is not a commit of this repository" bash "$checker" \
  "$(gate gate2b "$tmp/unknownhead.json" 'gate["head"] = "1234567" * 5 + "12345"')"
check fail "a head whose decoder key is not the file's" "the decoder key at $before_key is not the file's" \
  bash "$checker" "$(gate gate2b "$tmp/oldhead.json" "gate['head'] = '$before_key'")"
fuzzed=$(g rev-parse HEAD)
echo 'notes' > "$fx/NOTES.md"
g add NOTES.md
g commit -q -m "outside the key"
check pass "a head behind HEAD with the same key" "gate 2b OK" bash "$checker" \
  "$(gate gate2b "$tmp/behind.json" "gate['head'] = '$fuzzed'")"
g reset -q --hard HEAD~1
check fail "no argument" "Usage" bash "$checker"
check fail "two files" "Usage" bash "$checker" "$ok2b" "$ok2b"
mkdir -p "$tmp/sizes"
gate_file_size_cases "$ok2b" "$tmp/sizes"
check pass "a valid file padded to exactly 1 MiB" "gate 2b OK" bash "$checker" "$tmp/sizes/at-limit.json"
check fail "a valid file padded past 1 MiB" "not a regular file of at most 1048576 bytes" \
  bash "$checker" "$tmp/sizes/over-limit.json"
mkfifo "$tmp/sizes/fifo.json"
check fail "a FIFO with no writer, refused without blocking" "not a regular file" \
  deadline 30 bash "$checker" "$tmp/sizes/fifo.json"
check fail "an unknown gate" "m2a, gate1, gate2a or gate2b" bash "$m2a_checker" --gate gate3 "$ok2b"

# The path only gate 2b keys makes a gate-2b file stale and leaves the gate-2a, gate-1 and m2a
# files valid; cl-chain, the column env, the chain.v1 contract, ipc, cl-discv5 and
# network-config are in the closure of the harness, which every gate keys.
gate2a_ok="$tmp/gate2a.json"
gate1_ok="$tmp/gate1.json"
m2a_ok="$tmp/m2a.json"
for path in fuzz/run-gate2b.sh; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "gate 2b stale after a commit to $path" "stale" bash "$checker" "$ok2b"
  check pass "gate 2a holds after a commit to $path" "" bash "$gate2a_checker" "$gate2a_ok"
  check pass "gate 1 holds after a commit to $path" "" bash "$gate1_checker" "$gate1_ok"
  check pass "the m2a gate holds after a commit to $path" "" bash "$m2a_checker" "$m2a_ok"
  g reset -q --hard HEAD~1
done
for path in fuzz/run-gate2a.sh fuzz/run-gate1.sh; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check pass "gate 2b holds after a commit to $path (another gate's only)" "" bash "$checker" "$ok2b"
  g reset -q --hard HEAD~1
done
for path in crates/cl-chain/Cargo.toml crates/cl-chain/src/reqresp.rs crates/cl-chain/src/probe/ingest.rs \
  crates/cl-chain/src/lib.rs crates/cl-chain-columns/src/lib.rs crates/ethswarm-proto/src/lib.rs \
  proto/ethswarm/chain/v1/reqresp.proto crates/ipc/src/lib.rs crates/cl-discv5/src/enr.rs \
  crates/p2p-wire/src/lib.rs crates/network-config/src/lib.rs crates/cl-p2p/src/rpc/codec.rs crates/cl-p2p/src/rpc/columns.rs \
  crates/cl-p2p/src/gossip/mod.rs fuzz/m2a-common.sh fuzz/run-m2a-gate.sh \
  fuzz/src/lib.rs fuzz/fuzz_targets/column_contract.rs fuzz/corpus/column_contract/valid \
  fuzz/corpus/status_v2/valid Cargo.lock; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "gate 2b stale after a commit to $path" "stale" bash "$checker" "$ok2b"
  check fail "gate 2a stale after a commit to $path" "stale" bash "$gate2a_checker" "$gate2a_ok"
  check fail "the m2a gate stale after a commit to $path" "stale" bash "$m2a_checker" "$m2a_ok"
  g reset -q --hard HEAD~1
done
check pass "valid again at the keyed commit" "" bash "$checker" "$ok2b"
echo '# local edit' >> "$fx/fuzz/run-gate2b.sh"
check fail "an uncommitted edit to a gate-2b keyed path" "fuzz/run-gate2b.sh" bash "$checker" "$ok2b"
check pass "gate 2a does not look at it" "" bash "$gate2a_checker" "$gate2a_ok"
g checkout -q -- fuzz/run-gate2b.sh

check pass "the real repo's gate-2b key prints" '"crates/cl-chain-columns"' bash "$repo/fuzz/check-gate2b.sh" --print-key
check pass "the real repo's gate-2b expected values print" '"column_contract"' bash "$repo/fuzz/check-gate2b.sh" --print-expected

echo "# $passed passed, $failed failed"
((failed == 0))
