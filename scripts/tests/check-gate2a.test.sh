#!/usr/bin/env bash
# Tests for fuzz/check-gate2a.sh (fuzz/check-m2a-gate.sh --gate gate2a). Run:
# bash scripts/tests/check-gate2a.test.sh
# Each case checks a gate-2a file against a throwaway git repo holding gate 2a's keyed paths and
# a copy of the scripts. The rules every gate shares (the scrubbed git, the byte comparison of
# keyed files, assume-unchanged and skip-worktree, the bounded read) are the m2a and gate-1
# checker tests'; these cases are gate 2a's own: its gate name, targets, limits, floors and key,
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

gate2a_targets=(data_column_sidecar columns_by_range_req columns_by_root_req)
fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" "$fx/crates/p2p-wire/src" \
  "$fx/crates/consensus-types/src" "$fx/crates/cl-p2p/src/rpc" "$fx/crates/cl-p2p/src/gossip" \
  "$fx/crates/cl-discv5/src" "$fx/crates/network-config/src" "$fx/crates/cl-chain/src"
for t in "${gate2a_targets[@]}" rpc_chunk gossip_transform message_id enr_fields status_v2 \
  metadata_v3 ping_goodbye blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo"/fuzz/{m2a-common.sh,check-m2a-gate.sh,check-gate1.sh,check-gate2a.sh} "$fx/fuzz/"
echo '# run' > "$fx/fuzz/run-m2a-gate.sh"
echo '# run gate 1' > "$fx/fuzz/run-gate1.sh"
echo '# run gate 2a' > "$fx/fuzz/run-gate2a.sh"
echo '# build' > "$fx/fuzz/build-m2a.sh"
echo '[workspace]' > "$fx/Cargo.toml"
for f in crates/p2p-wire/src/lib.rs crates/consensus-types/src/lib.rs crates/cl-p2p/src/rpc/mod.rs \
  crates/cl-p2p/src/rpc/codec.rs crates/cl-p2p/src/rpc/limits.rs crates/cl-p2p/src/rpc/metrics.rs \
  crates/cl-p2p/src/rpc/unsupported.rs crates/cl-p2p/src/rpc/columns.rs \
  crates/cl-p2p/src/gossip/mod.rs crates/cl-p2p/src/gossip/config.rs crates/cl-chain/src/reqresp.rs \
  crates/cl-discv5/src/enr.rs crates/network-config/src/lib.rs fuzz/src/lib.rs \
  fuzz/fuzz_targets/data_column_sidecar.rs; do
  echo "// $f" > "$fx/$f"
done
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo '[package]' > "$fx/crates/cl-discv5/Cargo.toml"
echo '[package]' > "$fx/crates/cl-chain/Cargo.toml"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
echo 'version = 4' > "$fx/Cargo.lock"
git init -q "$fx"
g add -A
g commit -q -m fixture
# The commit before the keyed commit: a keyed file differs there, so its decoder key does too.
before_key=$(g rev-parse HEAD)
echo '// keyed change' >> "$fx/crates/cl-chain/src/reqresp.rs"
g commit -q -am "keyed change"
checker="$fx/fuzz/check-gate2a.sh"
gate1_checker="$fx/fuzz/check-gate1.sh"
m2a_checker="$fx/fuzz/check-m2a-gate.sh"

# gate <gate2a|gate1|m2a> <file> [python statements editing `gate`]: writes a passing gate file
# of that gate for the fixture, then applies the edits.
gate() {
  local which=$1 file=$2 expected
  shift 2
  case $which in
    gate2a) expected=$(bash "$checker" --print-expected) ;;
    gate1) expected=$(bash "$gate1_checker" --print-expected) ;;
    *) expected=$(bash "$m2a_checker" --print-expected) ;;
  esac
  EXPECTED=$expected WHICH=$which HEAD_SHA=$(g rev-parse HEAD) python3 -I - "$file" "$@" <<'PY'
import json, os, sys
want = json.loads(os.environ["EXPECTED"])
targets = list(want["corpus_sha256"])
gate = {
    "gate": {"gate2a": "gate2a-fuzz", "gate1": "gate1-fuzz"}.get(os.environ["WHICH"], "m2a-fuzz"),
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
[[ $(python3 -I -c 'import json,sys; print(" ".join(json.loads(sys.argv[1])["corpus_sha256"]))' "$expected") == "${gate2a_targets[*]}" ]] \
  && ok "the expected values cover gate 2a's three targets" || bad "expected targets: $expected"
python3 -I -c 'import json,sys; m=json.loads(sys.argv[1])["limits"]["max_len"]; sys.exit(not (m == {"data_column_sidecar": 1048576, "columns_by_range_req": 4096, "columns_by_root_req": 262144}))' "$expected" \
  && ok "gate 2a's -max_len policy, and only its targets" || bad "max_len: $expected"
python3 -I -c 'import json,sys; m=json.loads(sys.argv[1])["min_seed_ft"]; sys.exit(not (m == {"data_column_sidecar": 1500, "columns_by_range_req": 600, "columns_by_root_req": 800}))' "$expected" \
  && ok "gate 2a's coverage floors" || bad "min_seed_ft: $expected"

ok2a="$tmp/ok.json"
check pass "a complete gate-2a file for this tree" "gate 2a OK: 3 targets" bash "$checker" "$(gate gate2a "$ok2a")"
check pass "the gate-1 checker still takes a complete gate-1 file" "gate 1 OK: 7 targets" bash "$gate1_checker" "$(gate gate1 "$tmp/gate1.json")"
check pass "the m2a checker still takes a complete m2a file" "m2a gate OK: 4 targets" bash "$m2a_checker" "$(gate m2a "$tmp/m2a.json")"
check fail "an m2a file is not a gate-2a file" "want gate2a-fuzz" bash "$checker" "$tmp/m2a.json"
check fail "a gate-1 file is not a gate-2a file" "want gate2a-fuzz" bash "$checker" "$tmp/gate1.json"
check fail "a gate-2a file is not a gate-1 file" "want gate1-fuzz" bash "$gate1_checker" "$ok2a"
check fail "a gate-2a file is not an m2a file" "want m2a-fuzz" bash "$m2a_checker" "$ok2a"
check fail "a gate-2a file named gate1-fuzz still lacks the gate-1 key and targets" "decoder key stale" bash "$gate1_checker" \
  "$(gate gate2a "$tmp/renamed.json" 'gate["gate"] = "gate1-fuzz"')"
for t in "${gate2a_targets[@]}"; do
  check fail "gate 2a without $t" "want exactly" bash "$checker" \
    "$(gate gate2a "$tmp/no-$t.json" "gate['targets'] = [x for x in gate['targets'] if x['target'] != '$t']")"
done
check fail "an extra target" "want exactly" bash "$checker" \
  "$(gate gate2a "$tmp/extra.json" 'gate["targets"].append(dict(gate["targets"][0], target="rpc_chunk"))')"
check fail "a target listed twice" "want exactly" bash "$checker" \
  "$(gate gate2a "$tmp/twice.json" 'gate["targets"][2] = dict(gate["targets"][1])')"
check fail "columns_by_root_req ran 3599 s" "columns_by_root_req: 3599 s < 3600 s" bash "$checker" \
  "$(gate gate2a "$tmp/short.json" 'gate["targets"][2]["seconds"] = 3599')"
check fail "a smoke run" "requested_seconds" bash "$checker" \
  "$(gate gate2a "$tmp/smoke.json" 'gate["requested_seconds"] = 60')"
check fail "a crash in data_column_sidecar" "data_column_sidecar: crashes 1" bash "$checker" \
  "$(gate gate2a "$tmp/crash.json" 'gate["targets"][0]["crashes"] = 1')"
check fail "an OOM in columns_by_root_req" "columns_by_root_req: ooms 1" bash "$checker" \
  "$(gate gate2a "$tmp/oom.json" 'gate["targets"][2]["ooms"] = 1')"
check fail "a timeout in columns_by_range_req" "columns_by_range_req: timeouts 1" bash "$checker" \
  "$(gate gate2a "$tmp/timeout.json" 'gate["targets"][1]["timeouts"] = 1')"
check fail "no executions" "columns_by_range_req: execs 0" bash "$checker" \
  "$(gate gate2a "$tmp/noexec.json" 'gate["targets"][1]["execs"] = 0')"
check fail "an incomplete run" "completed False" bash "$checker" \
  "$(gate gate2a "$tmp/incomplete.json" 'gate["targets"][0]["completed"] = False')"
check fail "a dirty run" "dirty" bash "$checker" "$(gate gate2a "$tmp/dirty.json" 'gate["dirty"] = True')"
check fail "the default -max_len for data_column_sidecar" "limits" bash "$checker" \
  "$(gate gate2a "$tmp/maxlen.json" 'gate["limits"]["max_len"]["data_column_sidecar"] = 4096')"
check fail "a weaker malloc limit" "limits" bash "$checker" \
  "$(gate gate2a "$tmp/malloc.json" 'gate["limits"]["malloc_limit_mb"] = 2048')"
check fail "data_column_sidecar under its coverage floor" "data_column_sidecar: seed_ft 200 under the floor" bash "$checker" \
  "$(gate gate2a "$tmp/ft.json" 'gate["targets"][0]["seed_ft"] = 200; gate["targets"][0]["final_ft"] = 200')"
check fail "another seed corpus for columns_by_root_req" "corpus_sha256" bash "$checker" \
  "$(gate gate2a "$tmp/corpus.json" 'gate["targets"][2]["corpus_sha256"] = "0" * 64')"
check fail "a tool override" "overrides" bash "$checker" \
  "$(gate gate2a "$tmp/ov.json" 'gate["overrides"] = {"RUSTC": "rustc"}')"
check fail "another toolchain" "toolchain channel" bash "$checker" \
  "$(gate gate2a "$tmp/tc.json" 'gate["toolchain"]["channel"] = "nightly"')"
# The commit the file names.
check fail "no head" "head: missing" bash "$checker" "$(gate gate2a "$tmp/nohead.json" 'del gate["head"]')"
check fail "a malformed head" "is not a 40-character lowercase hex commit id" bash "$checker" \
  "$(gate gate2a "$tmp/badhead.json" "gate['head'] = '${before_key:0:39}'")"
check fail "an unknown head" "is not a commit of this repository" bash "$checker" \
  "$(gate gate2a "$tmp/unknownhead.json" 'gate["head"] = "1234567" * 5 + "12345"')"
check fail "a head whose decoder key is not the file's" "the decoder key at $before_key is not the file's" \
  bash "$checker" "$(gate gate2a "$tmp/oldhead.json" "gate['head'] = '$before_key'")"
fuzzed=$(g rev-parse HEAD)
echo 'notes' > "$fx/NOTES.md"
g add NOTES.md
g commit -q -m "outside the key"
check pass "a head behind HEAD with the same key" "gate 2a OK" bash "$checker" \
  "$(gate gate2a "$tmp/behind.json" "gate['head'] = '$fuzzed'")"
g reset -q --hard HEAD~1
check fail "no argument" "Usage" bash "$checker"
check fail "two files" "Usage" bash "$checker" "$ok2a" "$ok2a"
mkdir -p "$tmp/sizes"
gate_file_size_cases "$ok2a" "$tmp/sizes"
check pass "a valid file padded to exactly 1 MiB" "gate 2a OK" bash "$checker" "$tmp/sizes/at-limit.json"
check fail "a valid file padded past 1 MiB" "not a regular file of at most 1048576 bytes" \
  bash "$checker" "$tmp/sizes/over-limit.json"
mkfifo "$tmp/sizes/fifo.json"
check fail "a FIFO with no writer, refused without blocking" "not a regular file" \
  deadline 30 bash "$checker" "$tmp/sizes/fifo.json"
check fail "an unknown gate" "m2a, gate1, gate2a or gate2b" bash "$m2a_checker" --gate gate3 "$ok2a"

# Every path only gate 2a keys makes a gate-2a file stale and leaves the gate-1 and m2a files
# valid (network-config is gate 1's too); a path every gate keys makes all three stale.
gate1_ok="$tmp/gate1.json"
m2a_ok="$tmp/m2a.json"
for path in crates/cl-p2p/src/rpc/columns.rs crates/cl-chain/Cargo.toml crates/cl-chain/src/reqresp.rs \
  fuzz/run-gate2a.sh; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "gate 2a stale after a commit to $path" "stale" bash "$checker" "$ok2a"
  check pass "gate 1 holds after a commit to $path" "" bash "$gate1_checker" "$gate1_ok"
  check pass "the m2a gate holds after a commit to $path" "" bash "$m2a_checker" "$m2a_ok"
  g reset -q --hard HEAD~1
done
echo '# changed' >> "$fx/crates/network-config/src/lib.rs"
g commit -q -am "change network-config"
check fail "gate 2a stale after a commit to network-config" "stale" bash "$checker" "$ok2a"
check pass "the m2a gate holds after a commit to network-config" "" bash "$m2a_checker" "$m2a_ok"
g reset -q --hard HEAD~1
for path in crates/cl-p2p/src/gossip/mod.rs crates/cl-discv5/src/enr.rs fuzz/run-gate1.sh; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check pass "gate 2a holds after a commit to $path (gate 1 only)" "" bash "$checker" "$ok2a"
  g reset -q --hard HEAD~1
done
for path in crates/p2p-wire/src/lib.rs crates/cl-p2p/src/rpc/codec.rs fuzz/m2a-common.sh fuzz/run-m2a-gate.sh \
  fuzz/src/lib.rs fuzz/fuzz_targets/data_column_sidecar.rs fuzz/corpus/columns_by_root_req/valid \
  fuzz/corpus/status_v2/valid Cargo.lock; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "gate 2a stale after a commit to $path" "stale" bash "$checker" "$ok2a"
  check fail "gate 1 stale after a commit to $path" "stale" bash "$gate1_checker" "$gate1_ok"
  check fail "the m2a gate stale after a commit to $path" "stale" bash "$m2a_checker" "$m2a_ok"
  g reset -q --hard HEAD~1
done
check pass "valid again at the keyed commit" "" bash "$checker" "$ok2a"
echo '// local edit' >> "$fx/crates/cl-chain/src/reqresp.rs"
check fail "an uncommitted edit to a gate-2a keyed path" "crates/cl-chain/src/reqresp.rs" bash "$checker" "$ok2a"
check pass "gate 1 does not look at it" "" bash "$gate1_checker" "$gate1_ok"
g checkout -q -- crates/cl-chain/src/reqresp.rs

check pass "the real repo's gate-2a key prints" '"crates/cl-chain/src/reqresp.rs"' bash "$repo/fuzz/check-gate2a.sh" --print-key
check pass "the real repo's gate-2a expected values print" '"columns_by_root_req"' bash "$repo/fuzz/check-gate2a.sh" --print-expected

echo "# $passed passed, $failed failed"
((failed == 0))
