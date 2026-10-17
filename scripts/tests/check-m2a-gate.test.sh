#!/usr/bin/env bash
# Tests for fuzz/check-m2a-gate.sh. Run: bash scripts/tests/check-m2a-gate.test.sh
# Each case checks a gate file against a throwaway git repo holding the keyed paths and a copy of
# the scripts; one prints the real repo's key. Needs git and python3. Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
# check <expect: pass|fail> <description> <want in output or ""> <command...>
check() {
  local expect=$1 desc=$2 want=$3 rc=0 out ok=0
  shift 3
  out=$("$@" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

g() { git -C "$fx" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }

# The fixture repo: every keyed path, the scripts, one commit.
fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" \
  "$fx/crates/p2p-wire/src" "$fx/crates/consensus-types/src" "$fx/crates/cl-p2p/src/rpc"
for t in status_v2 metadata_v3 ping_goodbye blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo/fuzz/m2a-common.sh" "$repo/fuzz/check-m2a-gate.sh" "$fx/fuzz/"
echo '# run' > "$fx/fuzz/run-m2a-gate.sh"
echo '# build' > "$fx/fuzz/build-m2a.sh"
echo '[workspace]' > "$fx/Cargo.toml"
echo 'pub fn decode() {}' > "$fx/crates/p2p-wire/src/lib.rs"
echo 'pub struct Block;' > "$fx/crates/consensus-types/src/lib.rs"
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo 'pub mod codec;' > "$fx/crates/cl-p2p/src/rpc/mod.rs"
echo 'pub fn read() {}' > "$fx/crates/cl-p2p/src/rpc/codec.rs"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'pub fn run() {}' > "$fx/fuzz/src/lib.rs"
echo '#![no_main]' > "$fx/fuzz/fuzz_targets/status_v2.rs"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
git init -q "$fx"
g add -A
g commit -q -m fixture
checker="$fx/fuzz/check-m2a-gate.sh"

expected=$(bash "$checker" --print-expected)

# gate <file> [python statements editing `gate`]: writes a passing gate file for the fixture,
# then applies the edits.
gate() {
  local file=$1
  shift
  EXPECTED=$expected python3 -I - "$file" "$@" <<'PY'
import json, os, sys
want = json.loads(os.environ["EXPECTED"])
targets = ["status_v2", "metadata_v3", "ping_goodbye", "blocks_by_range_resp"]
gate = {
    "gate": "m2a-fuzz",
    "format": 1,
    "requested_seconds": 3600,
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

check pass "a complete gate for this tree" "m2a gate OK" bash "$checker" "$(gate "$tmp/ok.json")"
check pass "exactly 3600 s is enough" "" bash "$checker" \
  "$(gate "$tmp/exact.json" 'for t in gate["targets"]: t["seconds"] = 3600')"
check fail "3599 s is not" "3599 s < 3600 s" bash "$checker" \
  "$(gate "$tmp/short.json" 'gate["targets"][2]["seconds"] = 3599')"
check fail "a smoke run (requested 60 s)" "requested_seconds" bash "$checker" \
  "$(gate "$tmp/smoke.json" 'gate["requested_seconds"] = 60')"
check fail "a crash" "crashes" bash "$checker" \
  "$(gate "$tmp/crash.json" 'gate["targets"][0]["crashes"] = 1')"
check fail "an OOM" "ooms" bash "$checker" \
  "$(gate "$tmp/oom.json" 'gate["targets"][3]["ooms"] = 1')"
check fail "a timeout" "timeouts" bash "$checker" \
  "$(gate "$tmp/timeout.json" 'gate["targets"][1]["timeouts"] = 1')"
check fail "a run that did not complete" "completed" bash "$checker" \
  "$(gate "$tmp/incomplete.json" 'gate["targets"][1]["completed"] = False')"
check fail "a non-zero exit" "exit_code" bash "$checker" \
  "$(gate "$tmp/exit.json" 'gate["targets"][1]["exit_code"] = 1')"
check fail "no executions" "execs" bash "$checker" \
  "$(gate "$tmp/noexec.json" 'gate["targets"][1]["execs"] = 0')"
check fail "three targets" "want exactly" bash "$checker" \
  "$(gate "$tmp/three.json" 'gate["targets"].pop()')"
check fail "a target twice" "want exactly" bash "$checker" \
  "$(gate "$tmp/twice.json" 'gate["targets"][3] = dict(gate["targets"][0])')"
check fail "an unknown target" "want exactly" bash "$checker" \
  "$(gate "$tmp/unknown.json" 'gate["targets"][3]["target"] = "status_v1"')"
check fail "a run from a dirty tree" "dirty" bash "$checker" \
  "$(gate "$tmp/dirty.json" 'gate["dirty"] = True')"
check fail "another gate format" "format" bash "$checker" \
  "$(gate "$tmp/format.json" 'gate["format"] = 2')"
check fail "a seconds value that is not a number" "seconds" bash "$checker" \
  "$(gate "$tmp/str.json" 'gate["targets"][0]["seconds"] = "3601"')"
check fail "a key entry missing" "stale" bash "$checker" \
  "$(gate "$tmp/nokey.json" 'del gate["decoder_key"]["git"]["crates/consensus-types"]')"
# Every policy field: the limits, build flags, toolchain, cargo-fuzz and the seed corpus.
for edit in \
  'gate["limits"]["malloc_limit_mb"] = 4096' \
  'del gate["limits"]["malloc_limit_mb"]' \
  'gate["limits"]["rss_limit_mb"] = 4096' \
  'gate["limits"]["timeout_s"] = 1200' \
  'gate["limits"]["max_len"]["blocks_by_range_resp"] = 49379' \
  'del gate["limits"]["max_len"]["status_v2"]' \
  'gate["limits"]["build_flags"] = ["-O"]' \
  'del gate["limits"]'; do
  check fail "limits: $edit" "limits" bash "$checker" "$(gate "$tmp/limits.json" "$edit")"
done
check fail "another toolchain channel" "toolchain" bash "$checker" \
  "$(gate "$tmp/tc.json" 'gate["toolchain"]["channel"] = "nightly"')"
check fail "another rustc" "toolchain" bash "$checker" \
  "$(gate "$tmp/rustc.json" 'gate["toolchain"]["rustc_commit"] = "0" * 40')"
check fail "no toolchain" "toolchain" bash "$checker" \
  "$(gate "$tmp/notc.json" 'del gate["toolchain"]')"
check fail "another cargo-fuzz" "cargo_fuzz" bash "$checker" \
  "$(gate "$tmp/cf.json" 'gate["cargo_fuzz"] = "cargo-fuzz 0.12.0"')"
check fail "another seed corpus" "corpus_sha256" bash "$checker" \
  "$(gate "$tmp/corpus.json" 'gate["targets"][3]["corpus_sha256"] = "0" * 64')"
check fail "no seed corpus digest" "corpus_sha256" bash "$checker" \
  "$(gate "$tmp/nocorpus.json" 'del gate["targets"][0]["corpus_sha256"]')"
# Proof the targets ran: coverage features and the exercised flag.
check fail "seed features under the floor (a target that returns at once)" "seed_ft" bash "$checker" \
  "$(gate "$tmp/ft.json" 'gate["targets"][0]["seed_ft"] = 66; gate["targets"][0]["final_ft"] = 66')"
check fail "features that shrank" "final_ft" bash "$checker" \
  "$(gate "$tmp/shrink.json" 'gate["targets"][3]["final_ft"] = gate["targets"][3]["seed_ft"] - 1')"
check fail "no feature counts" "seed_ft" bash "$checker" \
  "$(gate "$tmp/noft.json" 'del gate["targets"][2]["seed_ft"]')"
check fail "a target marked not exercised" "exercised" bash "$checker" \
  "$(gate "$tmp/exer.json" 'gate["targets"][1]["exercised"] = False')"
# Tool overrides belong to smoke runs only.
check fail "a run with a CARGO override" "overrides" bash "$checker" \
  "$(gate "$tmp/ov.json" 'gate["overrides"] = {"CARGO": "/tmp/wrapper"}')"
check fail "a run with a FUZZ_TOOLCHAIN override" "overrides" bash "$checker" \
  "$(gate "$tmp/ov2.json" 'gate["overrides"] = {"FUZZ_TOOLCHAIN": "nightly"}')"
check fail "no overrides field" "overrides" bash "$checker" \
  "$(gate "$tmp/noov.json" 'del gate["overrides"]')"
printf 'not json' > "$tmp/bad.json"
check fail "not JSON" "not valid JSON" bash "$checker" "$tmp/bad.json"
check fail "no such file" "" bash "$checker" "$tmp/missing.json"
check fail "no argument" "Usage" bash "$checker"

ok="$tmp/ok.json"
# Every keyed path, once changed and committed, makes the old gate stale.
for path in Cargo.toml crates/p2p-wire/src/lib.rs crates/consensus-types/src/lib.rs \
  crates/cl-p2p/Cargo.toml crates/cl-p2p/src/rpc/mod.rs crates/cl-p2p/src/rpc/codec.rs \
  fuzz/Cargo.toml fuzz/rust-toolchain.toml fuzz/src/lib.rs fuzz/fuzz_targets/status_v2.rs \
  fuzz/corpus/status_v2/valid fuzz/corpus-slow/blocks_by_range_resp/slow-seed fuzz/m2a-common.sh fuzz/build-m2a.sh fuzz/run-m2a-gate.sh; do
  echo '# changed' >> "$fx/$path"
  g commit -q -am "change $path"
  check fail "stale after a commit to $path" "stale" bash "$checker" "$ok"
  g reset -q --hard HEAD~1
done
check pass "valid again at the keyed commit" "" bash "$checker" "$ok"

# A change outside the key does not.
echo 'pub fn other() {}' > "$fx/crates/cl-p2p/src/lib.rs"
g add -A
g commit -q -m "outside the key"
check pass "a commit outside the key keeps the gate" "" bash "$checker" "$ok"

# The lockfile is keyed by its sha256, committed or not.
echo '# edited' >> "$fx/fuzz/Cargo.lock"
check fail "an edited fuzz/Cargo.lock" "fuzz/Cargo.lock" bash "$checker" "$ok"
g checkout -q -- fuzz/Cargo.lock

# An uncommitted change to a keyed path: HEAD's key would match, the built tree would not.
echo '// local edit' >> "$fx/crates/p2p-wire/src/lib.rs"
check fail "uncommitted change under a keyed path" "uncommitted" bash "$checker" "$ok"
g checkout -q -- crates/p2p-wire/src/lib.rs
touch "$fx/fuzz/corpus/status_v2/new-seed"
check fail "untracked file under a keyed path" "uncommitted" bash "$checker" "$ok"
rm "$fx/fuzz/corpus/status_v2/new-seed"
check pass "clean again" "" bash "$checker" "$ok"

check pass "the real repo's key prints" '"crates/p2p-wire"' bash "$repo/fuzz/check-m2a-gate.sh" --print-key
check pass "the real repo's expected values print" '"max_len"' bash "$repo/fuzz/check-m2a-gate.sh" --print-expected

echo "# $passed passed, $failed failed"
((failed == 0))
