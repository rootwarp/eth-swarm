#!/usr/bin/env bash
# Tests for fuzz/run-m2a-gate.sh and fuzz/build-m2a.sh. Run: bash scripts/tests/run-m2a-gate.test.sh
# Offline: a fake `cargo` and `rustc` (first on PATH) stand in for cargo-fuzz and the compiler and
# print libFuzzer's output (FAKE_<target> picks ok, crash, oom, timeout, cut or noop), in a
# throwaway git repo holding the keyed paths and a copy of the scripts. Every run starts from an
# empty environment (env -i), so nothing the caller has set leaks in. Needs git and python3.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
ok() { passed=$((passed + 1)); echo "ok   - $1"; }
bad() { failed=$((failed + 1)); echo "FAIL - $1"; [[ -z ${2:-} ]] || printf '%s\n' "$2" | sed 's/^/       /'; }

g() { git -C "$fx" -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }

fx="$tmp/repo"
mkdir -p "$fx/fuzz/src" "$fx/fuzz/fuzz_targets" "$fx/crates/p2p-wire" \
  "$fx/crates/consensus-types" "$fx/crates/cl-p2p/src/rpc"
for t in status_v2 metadata_v3 ping_goodbye blocks_by_range_resp; do
  mkdir -p "$fx/fuzz/corpus/$t"
  printf 'seed-%s' "$t" > "$fx/fuzz/corpus/$t/valid"
done
mkdir -p "$fx/fuzz/corpus-slow/blocks_by_range_resp"
printf 'slow' > "$fx/fuzz/corpus-slow/blocks_by_range_resp/slow-seed"
cp "$repo"/fuzz/{m2a-common.sh,build-m2a.sh,run-m2a-gate.sh,check-m2a-gate.sh} "$fx/fuzz/"
echo 'x' > "$fx/crates/p2p-wire/lib.rs"
echo 'x' > "$fx/crates/consensus-types/lib.rs"
echo 'x' > "$fx/crates/cl-p2p/src/rpc/codec.rs"
echo 'x' > "$fx/crates/cl-p2p/src/rpc/mod.rs"
echo '[package]' > "$fx/crates/cl-p2p/Cargo.toml"
echo '[workspace]' > "$fx/Cargo.toml"
echo '[package]' > "$fx/fuzz/Cargo.toml"
printf '[toolchain]\nchannel = "nightly-2026-10-17"\n' > "$fx/fuzz/rust-toolchain.toml"
echo 'x' > "$fx/fuzz/src/lib.rs"
echo 'x' > "$fx/fuzz/fuzz_targets/status_v2.rs"
echo 'version = 4' > "$fx/fuzz/Cargo.lock"
printf 'target\nartifacts\n' > "$fx/fuzz/.gitignore"
git init -q "$fx"
g add -A
g commit -q -m fixture

bin="$tmp/bin"
mkdir -p "$bin" "$tmp/home" "$tmp/cargo-home"
# The fake cargo: logs each call to $CALLS, then acts like cargo / cargo-fuzz.
cat > "$bin/cargo" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$CALLS"
[[ ${1:-} == +* ]] && shift
case "$1 ${2:-}" in
  "metadata "*) echo '{}'; exit "${FAKE_METADATA_RC:-0}" ;;
  "fuzz --version") echo "cargo-fuzz ${FAKE_CARGO_FUZZ:-0.13.2}"; exit 0 ;;
  "fuzz build") echo "Finished"; exit 0 ;;
  "fuzz run") ;;
  *) echo "fake cargo: unexpected $*" >&2; exit 99 ;;
esac
shift 2
flags=() target="" corpus=""
while (($#)); do
  case $1 in
    -O|-a) flags+=("$1") ;;
    --) shift; break ;;
    *) if [[ -z $target ]]; then target=$1; elif [[ -z $corpus ]]; then corpus=$1; fi ;;
  esac
  shift
done
# A unit "found" in the work corpus, so the largest input can be reported.
printf '0123456789' > "$corpus/found-unit"
secs=0
for a in "$@"; do case $a in -max_total_time=*) secs=${a#*=} ;; esac; done
var="FAKE_$target"
outcome=${!var:-ok}
seed_ft=6000 final_ft=7000
if [[ $outcome == noop ]]; then seed_ft=66 final_ft=66; fi
if [[ $outcome == shrink ]]; then final_ft=5000; fi
echo "INFO: Seed: 1"
echo "#2	INITED cov: 3000 ft: $seed_ft corp: 1/4b exec/s: 0 rss: 30Mb"
case $outcome in
  ok|noop|shrink)
    echo "#4242	DONE   cov: 3100 ft: $final_ft corp: 3/12b lim: 4096 exec/s: 42 rss: 99Mb"
    echo "Done 4242 runs in $((secs + 1)) second(s)"
    printf 'stat::number_of_executed_units: 4242\nstat::average_exec_per_sec:     42\n'
    printf 'stat::new_units_added:          7\nstat::slowest_unit_time_sec:    0\nstat::peak_rss_mb:              99\n'
    exit 0 ;;
  crash)
    echo "thread '<unnamed>' panicked at src/lib.rs:1:1:"
    echo "==1== ERROR: libFuzzer: deadly signal"
    printf 'stat::number_of_executed_units: 17\nstat::peak_rss_mb:              50\n'
    mkdir -p artifacts/"$target" && printf 'boom' > artifacts/"$target"/crash-abc
    echo "artifact_prefix='artifacts/$target/'; Test unit written to artifacts/$target/crash-abc"
    exit 77 ;;
  oom)
    echo "==1== ERROR: libFuzzer: out-of-memory (malloc(200000000))"
    exit 71 ;;
  timeout)
    echo "==1== ERROR: libFuzzer: timeout after 10 seconds"
    exit 70 ;;
  cut)
    echo "#100	pulse  cov: 10 ft: 10 corp: 1/4b exec/s: 0 rss: 30Mb"
    exit 0 ;;
esac
EOF
cat > "$bin/rustc" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} == +* ]] && shift
case ${1:-} in
  -V) echo "rustc 0.0.0-fake" ;;
  -vV) printf 'rustc 0.0.0-fake\ncommit-hash: %s\nhost: fake\n' "${FAKE_RUSTC_COMMIT:-5d8fec0669a64607db9ccbf663e7c23125bf4748}" ;;
esac
EOF
chmod +x "$bin/cargo" "$bin/rustc"
CALLS="$tmp/calls"
runner="$fx/fuzz/run-m2a-gate.sh"
builder="$fx/fuzz/build-m2a.sh"

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
by() { echo "{t['target']: t['$1'] for t in gate['targets']}"; }

# --- every target clean ---
: > "$CALLS"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/ok.json" 2>&1) || rc=$?
if ((rc == 0)); then ok "clean run exits 0"; else bad "clean run exits 0 (exit $rc)" "$out"; fi
want="{'status_v2': 0, 'metadata_v3': 0, 'ping_goodbye': 0, 'blocks_by_range_resp': 0}"
[[ $(field "$tmp/ok.json" "$(by crashes)") == "$want" ]] && ok "0 crashes each" || bad "0 crashes each"
[[ $(field "$tmp/ok.json" "sorted(set(t['execs'] for t in gate['targets']))") == "[4242]" ]] \
  && ok "execs from stat::number_of_executed_units" || bad "execs"
[[ $(field "$tmp/ok.json" "sorted(set(t['seconds'] for t in gate['targets']))") == "[4]" ]] \
  && ok "seconds from libFuzzer's Done line" || bad "seconds"
[[ $(field "$tmp/ok.json" "sorted(set((t['seed_ft'], t['final_ft'], t['final_cov']) for t in gate['targets']))") \
  == "[(6000, 7000, 3100)]" ]] && ok "features from the INITED and DONE lines" || bad "ft/cov" "$(field "$tmp/ok.json" "gate['targets']")"
[[ $(field "$tmp/ok.json" "(gate['requested_seconds'], gate['dirty'], gate['toolchain'], gate['cargo_fuzz'], gate['overrides'])") \
  == "(3, False, {'channel': 'nightly-2026-10-17', 'rustc_commit': '5d8fec0669a64607db9ccbf663e7c23125bf4748', 'rustc': 'rustc 0.0.0-fake'}, 'cargo-fuzz 0.13.2', {})" ]] \
  && ok "requested seconds, clean tree, toolchain, cargo-fuzz, no overrides" || bad "header fields" "$(field "$tmp/ok.json" "gate")"
want_limits=$(gate_run -- "$fx/fuzz/check-m2a-gate.sh" --print-expected | python3 -I -c 'import json,sys; print(json.loads(sys.stdin.read())["limits"])')
[[ $(field "$tmp/ok.json" "gate['limits']") == "$want_limits" ]] \
  && ok "limits recorded as the policy" || bad "limits" "$(field "$tmp/ok.json" "gate['limits']")"
key=$(gate_run -- "$fx/fuzz/check-m2a-gate.sh" --print-key)
[[ $(field "$tmp/ok.json" "json.dumps(gate['decoder_key'], sort_keys=True)") \
  == $(python3 -I -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True))' "$key") ]] \
  && ok "decoder key is check-m2a-gate.sh --print-key" || bad "decoder key"
corpus_sha=$(field "$tmp/ok.json" "gate['targets'][0]['corpus_sha256']")
[[ $corpus_sha =~ ^[0-9a-f]{64}$ ]] && ok "corpus sha256 recorded" || bad "corpus sha256: $corpus_sha"
grep -q -- '-max_total_time=3 -rss_limit_mb=2048 -malloc_limit_mb=' "$CALLS" \
  && ok "libFuzzer gets the time, RSS and malloc limits" || bad "libFuzzer limits" "$(cat "$CALLS")"
grep -q -- "fuzz run -O -a blocks_by_range_resp .* -- .*-max_len=2097152" "$CALLS" \
  && grep -q -- "fuzz run -O -a status_v2 .* -- .*-max_len=4096" "$CALLS" \
  && ok "each target gets its -max_len" || bad "-max_len" "$(cat "$CALLS")"
[[ $(field "$tmp/ok.json" "sorted(set(t['largest_found_input'] for t in gate['targets']))") == "[10]" ]] \
  && ok "largest found input recorded" || bad "largest_found_input"
grep -q -- "fuzz run -O -a status_v2 .*/fuzz/corpus/status_v2 --" "$CALLS" \
  && ok "runs with the build flags over the committed seeds" || bad "run arguments" "$(cat "$CALLS")"
! grep -q -- "corpus-slow" "$CALLS" && ok "the slow seeds are not fuzzed from" || bad "corpus-slow passed to libFuzzer" "$(cat "$CALLS")"
grep -q -- "metadata --locked" "$CALLS" && grep -q -- "fuzz build -O -a" "$CALLS" \
  && ok "builds after checking the lockfile" || bad "build" "$(cat "$CALLS")"
log="$tmp/ok.log"
if [[ -f $log ]] && [[ $(grep -c '^stat::number_of_executed_units: 4242' "$log") == 4 ]] \
  && grep -q '^Done 4242 runs' "$log" && [[ $(grep -c 'DONE   cov: 3100 ft: 7000' "$log") == 4 ]]; then
  ok "final stats and DONE lines kept in the log"
else
  bad "log" "$(cat "$log" 2>/dev/null)"
fi
[[ -z $(g status --porcelain) ]] && ok "the committed corpus is not written to" || bad "tree dirtied" "$(g status --porcelain)"

# A full-length clean run passes the checker.
gate_run -- "$runner" --seconds 3600 --out "$tmp/full.json" >/dev/null 2>&1 || true
if out=$(gate_run -- "$fx/fuzz/check-m2a-gate.sh" "$tmp/full.json" 2>&1); then ok "a full clean run passes check-m2a-gate.sh"; else bad "full run check" "$out"; fi

# --- failures ---
fail_case() {
  local desc=$1 env=$2 expr=$3 want=$4 rc=0 out
  out=$(gate_run "$env" -- "$runner" --seconds 3 --out "$tmp/f.json" 2>&1) || rc=$?
  if ((rc == 1)) && [[ $(field "$tmp/f.json" "$expr") == "$want" ]]; then ok "$desc"; else bad "$desc (exit $rc)" "$out"; fi
}
fail_case "a crash fails the gate" FAKE_ping_goodbye=crash \
  "[(t['target'], t['crashes'], t['artifacts']) for t in gate['targets'] if t['crashes']]" \
  "[('ping_goodbye', 1, ['crash-abc'])]"
fail_case "an OOM fails the gate" FAKE_blocks_by_range_resp=oom \
  "[(t['target'], t['ooms'], t['crashes']) for t in gate['targets'] if t['ooms']]" \
  "[('blocks_by_range_resp', 1, 0)]"
fail_case "a timeout fails the gate" FAKE_status_v2=timeout \
  "[(t['target'], t['timeouts'], t['crashes']) for t in gate['targets'] if t['timeouts']]" \
  "[('status_v2', 1, 0)]"
fail_case "a run cut short fails the gate" FAKE_metadata_v3=cut \
  "[(t['target'], t['completed']) for t in gate['targets'] if not t['completed']]" \
  "[('metadata_v3', False)]"
fail_case "a target that runs no code (seed features under the floor) fails the gate" FAKE_status_v2=noop \
  "[(t['target'], t['exercised'], t['seed_ft']) for t in gate['targets'] if not t['exercised']]" \
  "[('status_v2', False, 66)]"
fail_case "features that shrank during the run fail the gate" FAKE_blocks_by_range_resp=shrink \
  "[(t['target'], t['exercised']) for t in gate['targets'] if not t['exercised']]" \
  "[('blocks_by_range_resp', False)]"

rc=0 out=$(gate_run FAKE_status_v2=crash -- "$runner" --sequential --seconds 3 --out "$tmp/seq.json" 2>&1) || rc=$?
((rc == 1)) && [[ $(field "$tmp/seq.json" "len(gate['targets'])") == 4 ]] \
  && ok "--sequential runs every target, even after a crash" || bad "--sequential (exit $rc)" "$out"
grep -q 'deadly signal' "$tmp/seq.log" && ok "the crash report is in the log" || bad "crash in log" "$(cat "$tmp/seq.log")"

# --- an environment that would change the build or the run ---
# refused <description> <script> <VAR=value...>: exit 2 naming the variable, and nothing built.
refused() {
  local desc=$1 script=$2 rc=0 out name
  shift 2
  name=${1%%=*}
  : > "$CALLS"
  out=$(gate_run "$@" -- "$script" --seconds 3 --out "$tmp/env.json" 2>&1) || rc=$?
  if ((rc == 2)) && grep -qF -- "$name" <<<"$out" && ! grep -q "fuzz build" "$CALLS"; then
    ok "$desc"
  else
    bad "$desc (exit $rc)" "$out"
  fi
}
for var in \
  'RUSTFLAGS=-Cdebug-assertions=no -Coverflow-checks=no' \
  'RUSTFLAGS=' \
  'CARGO_ENCODED_RUSTFLAGS=' \
  'CARGO_BUILD_RUSTFLAGS=-Cdebug-assertions=no' \
  'CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS=-Coverflow-checks=no' \
  'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=-Coverflow-checks=no' \
  'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=/bin/true' \
  'CARGO_TARGET_DIR=/tmp/elsewhere' \
  'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false' \
  'CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=false' \
  'CARGO_BUILD_RUSTC_WRAPPER=/bin/echo' \
  'CARGO_UNSTABLE_BUILD_STD=std' \
  'RUSTC_WRAPPER=/bin/echo' \
  'RUSTC_WORKSPACE_WRAPPER=/bin/echo' \
  'RUSTDOCFLAGS=-Z' \
  'CARGO_ENCODED_RUSTDOCFLAGS=' \
  'RUST_LIBFUZZER_DEBUG_PATH=/tmp/x' \
  'ASAN_OPTIONS=detect_leaks=0' \
  'UBSAN_OPTIONS=halt_on_error=0' \
  'LSAN_OPTIONS=detect_leaks=0' \
  'MSAN_OPTIONS=x=1' \
  'LD_PRELOAD=/tmp/malloc.so' \
  'LD_AUDIT=/tmp/audit.so'; do
  # (DYLD_INSERT_LIBRARIES is refused too, but macOS strips it before a protected binary such
  # as /usr/bin/env passes it on, so it cannot be set up here.)
  refused "run refuses ${var%%=*}" "$runner" "$var"
done
refused "build refuses RUSTFLAGS" "$builder" 'RUSTFLAGS=-Coverflow-checks=no'
refused "build refuses RUST_LIBFUZZER_DEBUG_PATH" "$builder" 'RUST_LIBFUZZER_DEBUG_PATH=/tmp/x'
refused "build refuses CARGO_ENCODED_RUSTFLAGS" "$builder" 'CARGO_ENCODED_RUSTFLAGS='

# Cargo config files cargo would read: fuzz/.cargo, the repo's, any ancestor's, CARGO_HOME's.
config_case() {
  local desc=$1 file=$2 body=$3 rc=0 out
  mkdir -p "$(dirname "$file")"
  printf '%s\n' "$body" > "$file"
  : > "$CALLS"
  out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/cfg.json" 2>&1) || rc=$?
  if ((rc == 2)) && grep -qF -- "$file" <<<"$out" && ! grep -q "fuzz build" "$CALLS"; then
    ok "$desc"
  else
    bad "$desc (exit $rc)" "$out"
  fi
  rm -f "$file"
}
config_case "fuzz/.cargo/config.toml with build.rustflags" "$fx/fuzz/.cargo/config.toml" \
  $'[build]\nrustflags = ["-Cdebug-assertions=no"]'
config_case "fuzz/.cargo/config (no extension) with [profile]" "$fx/fuzz/.cargo/config" \
  $'[profile.release]\noverflow-checks = false'
config_case "the repo's .cargo/config.toml with target rustflags" "$fx/.cargo/config.toml" \
  $'[target.aarch64-apple-darwin]\nrustflags = ["-Coverflow-checks=no"]'
config_case "an ancestor's .cargo/config.toml with a runner" "$tmp/.cargo/config.toml" \
  $'[target.x86_64-unknown-linux-gnu]\nrunner = "/bin/true"'
config_case "CARGO_HOME/config.toml with [env]" "$tmp/cargo-home/config.toml" \
  $'[env]\nRUST_LIBFUZZER_DEBUG_PATH = "/tmp/x"'
config_case "a config with a rustc wrapper" "$fx/.cargo/config.toml" \
  $'[build]\nrustc-wrapper = "/bin/echo"'
config_case "a config with [unstable]" "$fx/fuzz/.cargo/config.toml" \
  $'[unstable]\nbuild-std = ["std"]'
config_case "a config that does not parse" "$fx/fuzz/.cargo/config.toml" 'rustflags = ['
mkdir -p "$fx/fuzz/.cargo"
printf '[net]\nretry = 3\n' > "$fx/fuzz/.cargo/config.toml"
rc=0 out=$(gate_run -- "$runner" --allow-dirty --seconds 3 --out "$tmp/net.json" 2>&1) || rc=$?
((rc == 0)) && ok "a config that changes nothing the build or run uses is allowed" || bad "harmless config (exit $rc)" "$out"
rm -rf "$fx/fuzz/.cargo"

# --- tool overrides: smoke runs only, and recorded ---
for var in "FUZZ_TOOLCHAIN=nightly" "CARGO=$bin/cargo" "RUSTC=$bin/rustc" "RUSTUP_TOOLCHAIN=nightly"; do
  name=${var%%=*}
  rc=0 out=$(gate_run "$var" -- "$runner" --seconds 3600 --out "$tmp/o.json" 2>&1) || rc=$?
  ((rc == 2)) && grep -q "$name" <<<"$out" && [[ ! -f $tmp/o.json ]] \
    && ok "a full-length run refuses $name" || bad "full-length $name (exit $rc)" "$out"
  rc=0 out=$(gate_run "$var" -- "$runner" --seconds 3 --out "$tmp/o.json" 2>&1) || rc=$?
  ((rc == 0)) && [[ $(field "$tmp/o.json" "gate['overrides']") == "{'$name': '${var#*=}'}" ]] \
    && ok "a smoke run records $name" || bad "smoke $name (exit $rc)" "$out"
  rm -f "$tmp/o.json"
done

# --- refusals ---
rc=0 out=$(gate_run FAKE_RUSTC_COMMIT=0000000000000000000000000000000000000000 -- "$runner" --seconds 3 --out "$tmp/r.json" 2>&1) || rc=$?
((rc == 2)) && [[ ! -f $tmp/r.json ]] && grep -q 'rustc commit' <<<"$out" \
  && ok "another rustc stops the build" || bad "rustc pin (exit $rc)" "$out"
rc=0 out=$(gate_run FAKE_CARGO_FUZZ=0.12.0 -- "$runner" --seconds 3 --out "$tmp/c.json" 2>&1) || rc=$?
((rc == 2)) && [[ ! -f $tmp/c.json ]] && grep -q 'cargo-fuzz' <<<"$out" \
  && ok "another cargo-fuzz stops the build" || bad "cargo-fuzz pin (exit $rc)" "$out"
head -c 4097 /dev/zero > "$fx/fuzz/corpus/metadata_v3/too-long"
g add -A && g commit -q -m "long seed"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/s.json" 2>&1) || rc=$?
((rc == 2)) && grep -q 'too-long' <<<"$out" && ok "a seed over -max_len stops the run" || bad "seed over max_len (exit $rc)" "$out"
g reset -q --hard HEAD~1
rc=0 out=$(gate_run FAKE_METADATA_RC=101 -- "$runner" --seconds 3 --out "$tmp/l.json" 2>&1) || rc=$?
((rc != 0)) && [[ ! -f $tmp/l.json ]] && ok "a stale fuzz/Cargo.lock stops the run" || bad "stale lock (exit $rc)" "$out"
echo '// edit' >> "$fx/crates/p2p-wire/lib.rs"
rc=0 out=$(gate_run -- "$runner" --seconds 3 --out "$tmp/d.json" 2>&1) || rc=$?
((rc == 2)) && grep -q 'uncommitted' <<<"$out" && ok "a dirty keyed path stops the run" || bad "dirty (exit $rc)" "$out"
rc=0 out=$(gate_run -- "$runner" --allow-dirty --seconds 3 --out "$tmp/d.json" 2>&1) || rc=$?
((rc == 0)) && [[ $(field "$tmp/d.json" "gate['dirty']") == True ]] \
  && ok "--allow-dirty runs and marks the file dirty" || bad "--allow-dirty (exit $rc)" "$out"
g checkout -q -- crates/p2p-wire/lib.rs
for args in "--seconds 0" "--seconds x" "--seconds" "--bogus"; do
  rc=0 out=$(gate_run -- "$runner" $args 2>&1) || rc=$?
  ((rc == 2)) && ok "usage error: $args" || bad "usage error: $args (exit $rc)" "$out"
done

echo "# $passed passed, $failed failed"
((failed == 0))
