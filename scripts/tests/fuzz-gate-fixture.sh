# Shared by the fuzz gate script tests (run-m2a-gate, run-gate1): offline stand-ins for
# cargo-fuzz and the compiler. Source it. Works on bash 3.2.

# fake_fuzz_tools <bin dir>: writes a fake `cargo` and `rustc` there (put it first on PATH).
#   - cargo logs each call to $CALLS (an offline call once more, as "offline: <args>"), then
#     acts like cargo / cargo-fuzz: `fuzz run` prints libFuzzer's output for the outcome
#     FAKE_<target> picks (ok, crash, oom, timeout, cut, noop or shrink; default ok) and writes
#     a unit to the work corpus; FAKE_METADATA_RC and FAKE_CARGO_FUZZ change `metadata` and
#     `fuzz --version`;
#   - rustc prints a version, and FAKE_RUSTC_COMMIT (default the pinned commit) as its commit.
# The heredocs stay at column 0: their bodies are the scripts.
fake_fuzz_tools() {
  cat > "$1/cargo" <<'EOF'
#!/usr/bin/env bash
echo "$*" >> "$CALLS"
[[ ${CARGO_NET_OFFLINE:-} != true ]] || echo "offline: $*" >> "$CALLS"
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
  cat > "$1/rustc" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} == +* ]] && shift
case ${1:-} in
  -V) echo "rustc 0.0.0-fake" ;;
  -vV) printf 'rustc 0.0.0-fake\ncommit-hash: %s\nhost: fake\n' "${FAKE_RUSTC_COMMIT:-5d8fec0669a64607db9ccbf663e7c23125bf4748}" ;;
esac
EOF
  chmod +x "$1/cargo" "$1/rustc"
}
