#!/usr/bin/env bash
# Tests for fuzz/check-gate1.sh (fuzz/check-m2a-gate.sh --gate gate1). Run:
# bash scripts/tests/check-gate1.test.sh
# Each case checks a gate-1 file against a throwaway git repo holding gate 1's keyed paths and a
# copy of the scripts. The rules the two gates share (the scrubbed git, the byte comparison of
# keyed files, assume-unchanged and skip-worktree) are the m2a checker tests'; these cases are
# gate 1's own: its gate name, targets, limits and key, and that the two gates' files and keys
# stay apart. Needs git and python3. Works on bash 3.2.
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

gate1_targets=(rpc_chunk gossip_transform message_id enr_fields status_v2 metadata_v3 ping_goodbye)
fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" "$fx/crates/p2p-wire/src" \
  "$fx/crates/consensus-types/src" "$fx/crates/cl-p2p/src/rpc" "$fx/crates/cl-p2p/src/gossip" \
  "$fx/crates/cl-discv5/src" "$fx/crates/network-config/src"
for t in "${gate1_targets[@]}" blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo"/fuzz/{m2a-common.sh,check-m2a-gate.sh,check-gate1.sh} "$fx/fuzz/"
echo '# run' > "$fx/fuzz/run-m2a-gate.sh"
echo '# run gate 1' > "$fx/fuzz/run-gate1.sh"
echo '# build' > "$fx/fuzz/build-m2a.sh"
echo '[workspace]' > "$fx/Cargo.toml"
for f in crates/p2p-wire/src/lib.rs crates/consensus-types/src/lib.rs crates/cl-p2p/src/rpc/mod.rs \
  crates/cl-p2p/src/rpc/codec.rs crates/cl-p2p/src/rpc/limits.rs crates/cl-p2p/src/rpc/metrics.rs \
  crates/cl-p2p/src/rpc/unsupported.rs crates/cl-p2p/src/gossip/mod.rs crates/cl-p2p/src/gossip/config.rs \
  crates/cl-discv5/src/enr.rs crates/network-config/src/lib.rs fuzz/src/lib.rs \
  fuzz/fuzz_targets/enr_fields.rs; do
  echo "// $f" > "$fx/$f"
done
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo '[package]' > "$fx/crates/cl-discv5/Cargo.toml"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
echo 'version = 4' > "$fx/Cargo.lock"
# The modules the keyed files import, which the keys hold too (fuzz/m2a-common.sh).
for f in crates/cl-p2p/src/transport.rs crates/cl-p2p/src/transport/quota.rs \
  crates/cl-p2p/src/behaviour.rs crates/cl-p2p/src/peer_caps.rs crates/cl-p2p/src/gossip/mod.rs \
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
# The commit before the keyed commit: a keyed file differs there, so its decoder key does too.
before_key=$(g rev-parse HEAD)
echo '// keyed change' >> "$fx/crates/cl-discv5/src/enr.rs"
g commit -q -am "keyed change"
checker="$fx/fuzz/check-gate1.sh"
m2a_checker="$fx/fuzz/check-m2a-gate.sh"

# gate <gate1|m2a> <file> [python statements editing `gate`]: writes a passing gate file of that
# gate for the fixture, then applies the edits.
gate() {
  local which=$1 file=$2 expected
  shift 2
  if [[ $which == gate1 ]]; then expected=$(bash "$checker" --print-expected); else expected=$(bash "$m2a_checker" --print-expected); fi
  EXPECTED=$expected WHICH=$which HEAD_SHA=$(g rev-parse HEAD) python3 -I - "$file" "$@" <<'PY'
import json, os, sys
want = json.loads(os.environ["EXPECTED"])
gate1 = os.environ["WHICH"] == "gate1"
targets = list(want["corpus_sha256"])
gate = {
    "gate": "gate1-fuzz" if gate1 else "m2a-fuzz",
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
[[ $(python3 -I -c 'import json,sys; print(" ".join(json.loads(sys.argv[1])["corpus_sha256"]))' "$expected") == "${gate1_targets[*]}" ]] \
  && ok "the expected values cover gate 1's seven targets" || bad "expected targets: $expected"
python3 -I -c 'import json,sys; m=json.loads(sys.argv[1])["limits"]["max_len"]; sys.exit(not (m["rpc_chunk"] == 1048576 and m["gossip_transform"] == 2097152 and m["message_id"] == 2097152 and m["enr_fields"] == 4096 and "blocks_by_range_resp" not in m))' "$expected" \
  && ok "gate 1's -max_len policy, without the m2a-only target" || bad "max_len: $expected"

ok1="$tmp/ok.json"
check pass "a complete gate-1 file for this tree" "gate 1 OK: 7 targets" bash "$checker" "$(gate gate1 "$ok1")"
check pass "the m2a checker still takes a complete m2a file" "m2a gate OK: 4 targets" bash "$m2a_checker" "$(gate m2a "$tmp/m2a.json")"
check fail "an m2a file is not a gate-1 file" "want gate1-fuzz" bash "$checker" "$tmp/m2a.json"
check fail "a gate-1 file is not an m2a file" "want m2a-fuzz" bash "$m2a_checker" "$ok1"
check fail "a gate-1 file named m2a-fuzz still lacks the m2a key and targets" "decoder key stale" bash "$m2a_checker" \
  "$(gate gate1 "$tmp/renamed.json" 'gate["gate"] = "m2a-fuzz"')"
check fail "the m2a targets in a gate-1 file" "want exactly" bash "$checker" \
  "$(gate gate1 "$tmp/m2a-targets.json" 'gate["targets"] = [t for t in gate["targets"] if t["target"] in ("status_v2", "metadata_v3", "ping_goodbye")]')"
for t in "${gate1_targets[@]}"; do
  check fail "gate 1 without $t" "want exactly" bash "$checker" \
    "$(gate gate1 "$tmp/no-$t.json" "gate['targets'] = [x for x in gate['targets'] if x['target'] != '$t']")"
done
check fail "an extra target" "want exactly" bash "$checker" \
  "$(gate gate1 "$tmp/extra.json" 'gate["targets"].append(dict(gate["targets"][0], target="blocks_by_range_resp"))')"
check fail "enr_fields ran 3599 s" "enr_fields: 3599 s < 3600 s" bash "$checker" \
  "$(gate gate1 "$tmp/short.json" 'gate["targets"][3]["seconds"] = 3599')"
check fail "a smoke run" "requested_seconds" bash "$checker" \
  "$(gate gate1 "$tmp/smoke.json" 'gate["requested_seconds"] = 120')"
check fail "a crash in gossip_transform" "gossip_transform: crashes 1" bash "$checker" \
  "$(gate gate1 "$tmp/crash.json" 'gate["targets"][1]["crashes"] = 1')"
check fail "an OOM in rpc_chunk" "rpc_chunk: ooms 1" bash "$checker" \
  "$(gate gate1 "$tmp/oom.json" 'gate["targets"][0]["ooms"] = 1')"
check fail "a timeout in message_id" "message_id: timeouts 1" bash "$checker" \
  "$(gate gate1 "$tmp/timeout.json" 'gate["targets"][2]["timeouts"] = 1')"
check fail "a dirty run" "dirty" bash "$checker" "$(gate gate1 "$tmp/dirty.json" 'gate["dirty"] = True')"
check fail "the m2a -max_len of rpc_chunk" "limits" bash "$checker" \
  "$(gate gate1 "$tmp/maxlen.json" 'gate["limits"]["max_len"]["rpc_chunk"] = 4096')"
check fail "enr_fields under its coverage floor" "enr_fields: seed_ft 200 under the floor" bash "$checker" \
  "$(gate gate1 "$tmp/ft.json" 'gate["targets"][3]["seed_ft"] = 200; gate["targets"][3]["final_ft"] = 200')"
check fail "another seed corpus for enr_fields" "corpus_sha256" bash "$checker" \
  "$(gate gate1 "$tmp/corpus.json" 'gate["targets"][3]["corpus_sha256"] = "0" * 64')"
check fail "a tool override" "overrides" bash "$checker" \
  "$(gate gate1 "$tmp/ov.json" 'gate["overrides"] = {"FUZZ_TOOLCHAIN": "nightly"}')"
# The commit the file names: a commit of this repository, an ancestor of HEAD, whose decoder key
# is the file's (it was fuzzed at that commit; HEAD may have moved on outside the key).
check fail "no head" "head: missing" bash "$checker" "$(gate gate1 "$tmp/nohead.json" 'del gate["head"]')"
check fail "a head that is not a string" "head: missing" bash "$checker" \
  "$(gate gate1 "$tmp/inthead.json" 'gate["head"] = 7')"
for bad in "" abc "${before_key:0:39}" "${before_key}0" "$(tr '[:lower:]' '[:upper:]' <<<"$before_key")" \
  "${before_key:0:39}g" "$before_key "; do
  check fail "a malformed head '$bad'" "is not a 40-character lowercase hex commit id" bash "$checker" \
    "$(gate gate1 "$tmp/badhead.json" "gate['head'] = '$bad'")"
done
check fail "the all-zero head" "is not a commit of this repository" bash "$checker" \
  "$(gate gate1 "$tmp/zerohead.json" 'gate["head"] = "0" * 40')"
check fail "an unknown head" "is not a commit of this repository" bash "$checker" \
  "$(gate gate1 "$tmp/unknownhead.json" 'gate["head"] = "1234567" * 5 + "12345"')"
tree=$(g rev-parse 'HEAD^{tree}')
check fail "a head that names a tree, not a commit" "is not a commit of this repository" bash "$checker" \
  "$(gate gate1 "$tmp/treehead.json" "gate['head'] = '$tree'")"
# An annotated tag of HEAD names HEAD's commit, but is not one.
g tag -a -m annotated annotated HEAD
tag=$(g rev-parse annotated)
g tag -d annotated >/dev/null
check fail "a head that names an annotated tag, not a commit" "is not a commit of this repository" bash "$checker" \
  "$(gate gate1 "$tmp/taghead.json" "gate['head'] = '$tag'")"
g checkout -q -b side
echo 'side' > "$fx/side.txt"
g add side.txt
g commit -q -m side
side=$(g rev-parse HEAD)
g checkout -q -
g branch -q -D side
check fail "a head off this branch (not an ancestor of HEAD)" "is not an ancestor of HEAD" bash "$checker" \
  "$(gate gate1 "$tmp/sidehead.json" "gate['head'] = '$side'")"
check fail "a head whose decoder key is not the file's" "the decoder key at $before_key is not the file's" \
  bash "$checker" "$(gate gate1 "$tmp/oldhead.json" "gate['head'] = '$before_key'")"
# An ancestor that lacks a keyed path: its key cannot be computed, and git's reason is the error.
g rm -q fuzz/run-gate1.sh
g commit -q -m "drop a keyed path"
dropped=$(g rev-parse HEAD)
g checkout -q HEAD~1 -- fuzz/run-gate1.sh
g commit -q -m "restore it"
check pass "the file holds again once the keyed path is back" "gate 1 OK" bash "$checker" "$ok1"
check_clean fail "a head whose decoder key cannot be computed" \
  "head: the decoder key at $dropped cannot be computed: ERROR: fuzz/run-gate1.sh is not in $dropped" \
  bash "$checker" "$(gate gate1 "$tmp/drophead.json" "gate['head'] = '$dropped'")"
g reset -q --hard HEAD~2
# git's stderr is not part of the key: a warning leaves a valid file valid.
fake_git "$tmp/warn-bin" 'echo "warning: a harmless git warning" >&2'
check_clean pass "a git that warns on stderr" "gate 1 OK" env PATH="$tmp/warn-bin:$PATH" bash "$checker" "$ok1"
# A key that is not JSON is an error, not a traceback.
fake_git "$tmp/garble-bin" "for a in \"\$@\"; do [[ \$a != $before_key:Cargo.toml ]] || echo '\"'; done"
check_clean fail "a decoder key at head that does not parse" "head: the decoder key at $before_key" \
  env PATH="$tmp/garble-bin:$PATH" bash "$checker" "$(gate gate1 "$tmp/garble.json" "gate['head'] = '$before_key'")"
# The file is read once: one swapped for another between the head check and the other rules is
# not seen, and the report names the head that was checked.
cp "$ok1" "$tmp/swap.json"
gate gate1 "$tmp/swapped.json" 'gate["head"] = "0" * 40' >/dev/null
fake_git "$tmp/swap-bin" "for a in \"\$@\"; do [[ \$a != merge-base ]] || cp $(printf %q "$tmp/swapped.json") $(printf %q "$tmp/swap.json"); done"
check pass "a file swapped during the check is checked as first read" "fuzzed at $(g rev-parse HEAD)" \
  env PATH="$tmp/swap-bin:$PATH" bash "$checker" "$tmp/swap.json"
if cmp -s "$tmp/swap.json" "$tmp/swapped.json"; then ok "(the swap took place)"; else bad "the swap did not take place"; fi
# HEAD moves on outside the key: the file still names the commit it was fuzzed at.
fuzzed=$(g rev-parse HEAD)
echo 'notes' > "$fx/NOTES.md"
g add NOTES.md
g commit -q -m "outside the key"
check pass "a head behind HEAD with the same key" "gate 1 OK" bash "$checker" \
  "$(gate gate1 "$tmp/behind.json" "gate['head'] = '$fuzzed'")"
g reset -q --hard HEAD~1
check fail "no argument" "Usage" bash "$checker"
# The file is read through one bounded open (the m2a checker tests have the rest of the cases).
mkdir -p "$tmp/sizes"
gate_file_size_cases "$ok1" "$tmp/sizes"
check pass "a valid file padded to exactly 1 MiB" "gate 1 OK" bash "$checker" "$tmp/sizes/at-limit.json"
check fail "a valid file padded past 1 MiB" "not a regular file of at most 1048576 bytes" \
  bash "$checker" "$tmp/sizes/over-limit.json"
mkfifo "$tmp/sizes/fifo.json"
check fail "a FIFO with no writer, refused without blocking" "not a regular file" \
  deadline 30 bash "$checker" "$tmp/sizes/fifo.json"
check fail "two files" "Usage" bash "$checker" "$ok1" "$ok1"
check fail "an unknown gate" "m2a, gate1, gate2a or gate2b" bash "$m2a_checker" --gate gate2 "$ok1"

# Every path only gate 1 keys makes a gate-1 file stale, and leaves the m2a file valid; a path
# both key makes both stale (the m2a key holds all of fuzz/corpus, the gate-1 seeds too).
m2a_ok="$tmp/m2a.json"
for path in crates/cl-discv5/Cargo.toml crates/cl-discv5/src/enr.rs fuzz/run-gate1.sh; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "gate 1 stale after a commit to $path" "stale" bash "$checker" "$ok1"
  check pass "the m2a gate holds after a commit to $path" "" bash "$m2a_checker" "$m2a_ok"
  g reset -q --hard HEAD~1
done
for path in crates/p2p-wire/src/lib.rs crates/network-config/src/lib.rs crates/cl-p2p/src/rpc/codec.rs \
  crates/cl-p2p/src/rpc/limits.rs \
  crates/cl-p2p/src/rpc/metrics.rs crates/cl-p2p/src/rpc/unsupported.rs crates/cl-p2p/src/gossip/mod.rs \
  crates/cl-p2p/src/gossip/config.rs crates/cl-p2p/src/transport.rs fuzz/m2a-common.sh fuzz/run-m2a-gate.sh \
  fuzz/src/lib.rs fuzz/corpus/status_v2/valid fuzz/corpus/enr_fields/valid Cargo.lock; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "gate 1 stale after a commit to $path" "stale" bash "$checker" "$ok1"
  check fail "the m2a gate stale after a commit to $path" "stale" bash "$m2a_checker" "$m2a_ok"
  g reset -q --hard HEAD~1
done
check pass "valid again at the keyed commit" "" bash "$checker" "$ok1"
echo '// local edit' >> "$fx/crates/cl-discv5/src/enr.rs"
check fail "an uncommitted edit to a gate-1 keyed path" "crates/cl-discv5/src/enr.rs" bash "$checker" "$ok1"
check pass "the m2a gate does not look at it" "" bash "$m2a_checker" "$m2a_ok"
g checkout -q -- crates/cl-discv5/src/enr.rs

check pass "the real repo's gate-1 key prints" '"crates/cl-discv5/src/enr.rs"' bash "$repo/fuzz/check-gate1.sh" --print-key
check pass "the real repo's gate-1 expected values print" '"enr_fields"' bash "$repo/fuzz/check-gate1.sh" --print-expected

echo "# $passed passed, $failed failed"
((failed == 0))
