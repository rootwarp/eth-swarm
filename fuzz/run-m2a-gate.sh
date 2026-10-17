#!/usr/bin/env bash
# The m2a fuzz gate: runs the four response-decoder targets under cargo-fuzz and writes the gate
# file that fuzz/check-m2a-gate.sh verifies.
#
# Builds with fuzz/build-m2a.sh, then runs every target (in parallel unless --sequential) as
#   cargo fuzz run -O -a <target> <work corpus> fuzz/corpus/<target> -- \
#     -max_total_time=<seconds> -rss_limit_mb=2048 -malloc_limit_mb=128 -timeout=10 \
#     -max_len=<2 MiB for blocks_by_range_resp, 4096 B otherwise> -print_final_stats=1
# The limits, -max_len and the build flags are the policy in fuzz/m2a-common.sh, which explains
# each value; fuzz/check-m2a-gate.sh refuses a file with any other. A seed longer than its
# target's -max_len stops the run (libFuzzer would cut it silently).
# fuzz/corpus-slow is not fuzzed from: its seeds take seconds per execution (the ResponseTooLarge
# byte budget) and would starve the run; fuzz/coverage-m2a.sh and the tests run them.
# New inputs go to the work corpus under fuzz/target/m2a-gate/<target>/, so the committed seeds
# stay as they are; crash, OOM and timeout inputs land in fuzz/artifacts/<target>/.
#
# The gate file (default fuzz/artifacts/m2a-gate.json) holds, per target: seconds (libFuzzer's
# "Done ... in N second(s)"), execs (stat::number_of_executed_units), crashes, ooms, timeouts,
# whether the run completed, the exit code, the crash inputs, the sha256 of the seed corpus and
# the largest input the run kept; plus the decoder key (fuzz/check-m2a-gate.sh --print-key), the
# toolchain (channel, rustc commit), cargo-fuzz and the limits. The log (default: the gate file
# with .log) keeps libFuzzer's seed-corpus and final stats lines and any error report; each
# run's full output is in fuzz/target/m2a-gate/<target>/run.log.
#
# Usage: fuzz/run-m2a-gate.sh [--seconds N] [--out FILE] [--log FILE] [--sequential]
#                             [--allow-dirty]
#   --seconds N    per target (default 3600; less is a smoke run, which the checker refuses)
#   --allow-dirty  run although a keyed path has uncommitted changes (the file says dirty: true)
# Exit: 0 every target clean, 1 a crash, OOM, timeout, incomplete run or a target that did not
# exercise its decoder, 2 usage or setup error.
#
# Refuses (exit 2) any environment variable or cargo config file that would change the build or
# the run behind the recorded policy (m2a_require_clean_env in fuzz/m2a-common.sh lists them),
# and lockfiles that disagree (scripts/check-fuzz-lock.sh, offline, before anything is built).
# The dirty check and the key read git through m2a_git (no inherited GIT_* variable, no global
# or system config) and compare the keyed files with HEAD byte for byte (m2a_worktree_diff).
# The tool overrides CARGO, RUSTC, FUZZ_TOOLCHAIN and RUSTUP_TOOLCHAIN are allowed only for a
# smoke run (--seconds under 3600), and the gate file records them in `overrides`.
#
# A target counts as exercised when libFuzzer's coverage features once the seeds are loaded (ft:
# on the INITED line) reach its floor (m2a_min_seed_ft) and the final count (the DONE line) is no
# lower. Both are recorded per target, with the final cov:.
# Needs git and python3 >= 3.11.
# Works on bash 3.2.
set -euo pipefail
# shellcheck source=m2a-common.sh
. "$(dirname "$0")/m2a-common.sh"

usage() {
  echo "Usage: fuzz/run-m2a-gate.sh [--seconds N] [--out FILE] [--log FILE] [--sequential] [--allow-dirty]"
  exit 2
}

seconds=$M2A_REQUIRED_SECONDS
out="$fuzz_dir/artifacts/m2a-gate.json"
log=""
parallel=1
allow_dirty=0
while (($#)); do
  case $1 in
    --seconds) (($# >= 2)) || usage; seconds=$2; shift 2 ;;
    --out) (($# >= 2)) || usage; out=$2; shift 2 ;;
    --log) (($# >= 2)) || usage; log=$2; shift 2 ;;
    --sequential) parallel=0; shift ;;
    --allow-dirty) allow_dirty=1; shift ;;
    *) usage ;;
  esac
done
[[ $seconds =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: --seconds wants a positive integer"; usage; }

m2a_require_clean_env
overrides=()
for name in "${M2A_OVERRIDE_VARS[@]}"; do
  if [[ -n ${!name+set} ]]; then overrides+=("$name"); fi
done
if ((${#overrides[@]})) && ((seconds >= M2A_REQUIRED_SECONDS)); then
  echo "ERROR: ${overrides[*]} set: tool overrides are for smoke runs (--seconds under $M2A_REQUIRED_SECONDS) only"
  exit 2
fi
overrides_json='{'
sep=''
for name in ${overrides[@]+"${overrides[@]}"}; do
  overrides_json="$overrides_json$sep$(OVERRIDE_NAME=$name OVERRIDE_VALUE=${!name} python3 -I -c \
    'import json, os; print(json.dumps(os.environ["OVERRIDE_NAME"]) + ": " + json.dumps(os.environ["OVERRIDE_VALUE"]))')"
  sep=', '
done
overrides_json="$overrides_json}"
# The two lockfiles agree (scripts/check-fuzz-lock.sh, offline), or no gate is written.
m2a_lock_preflight
[[ $out == /* ]] || out="$PWD/$out"
[[ -n $log ]] || log="${out%.json}.log"
[[ $log == /* ]] || log="$PWD/$log"

dirty_paths=$(m2a_dirty_paths)
dirty=false
if [[ -n $dirty_paths ]]; then
  if ((!allow_dirty)); then
    echo "ERROR: keyed paths have uncommitted changes (commit them, or --allow-dirty for a smoke run):"
    printf '%s\n' "$dirty_paths" | sed 's/^/  /'
    exit 2
  fi
  dirty=true
fi
key=$(m2a_key_json) || exit 2

for target in "${M2A_TARGETS[@]}"; do
  max=$(m2a_max_len "$target")
  for seed in "$fuzz_dir/corpus/$target"/*; do
    size=$(wc -c < "$seed" | tr -d ' ')
    if ((size > max)); then
      echo "ERROR: fuzz/corpus/$target/${seed##*/} is $size B, over its -max_len of $max B"
      exit 2
    fi
  done
done

bash "$fuzz_dir/build-m2a.sh" || { echo "ERROR: build failed"; exit 2; }
channel=${FUZZ_TOOLCHAIN:-${RUSTUP_TOOLCHAIN:-$(m2a_toolchain_pin)}}
floors='{'
sep=''
for target in "${M2A_TARGETS[@]}"; do floors="$floors$sep\"$target\": $(m2a_min_seed_ft "$target")"; sep=', '; done
floors="$floors}"
rustc_commit=$(m2a_rustc -vV | sed -n 's/^commit-hash: //p')
rustc_version=$(m2a_rustc -V)
cargo_fuzz=$(m2a_cargo fuzz --version 2>/dev/null || echo unknown)
limits=$(m2a_limits_json)

work="$fuzz_dir/target/m2a-gate"
run_one() {
  local target=$1 dir="$work/$1" rc=0
  rm -rf "$dir"
  mkdir -p "$dir/corpus"
  m2a_corpus_sha256 "$fuzz_dir/corpus/$target" > "$dir/seed_sha256"
  date +%s > "$dir/start"
  m2a_cargo fuzz run "${M2A_BUILD_FLAGS[@]}" "$target" "$dir/corpus" "$fuzz_dir/corpus/$target" -- \
    -max_total_time="$seconds" -rss_limit_mb=$M2A_RSS_LIMIT_MB \
    -malloc_limit_mb=$M2A_MALLOC_LIMIT_MB -timeout=$M2A_TIMEOUT_S -max_len="$(m2a_max_len "$target")" \
    -print_final_stats=1 > "$dir/run.log" 2>&1 || rc=$?
  date +%s > "$dir/end"
  echo "$rc" > "$dir/exit"
}

echo "fuzzing ${M2A_TARGETS[*]} for $seconds s each ($([[ $parallel == 1 ]] && echo parallel || echo sequential))"
if ((parallel)); then
  pids=()
  for target in "${M2A_TARGETS[@]}"; do
    run_one "$target" &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" || true; done
else
  for target in "${M2A_TARGETS[@]}"; do run_one "$target"; done
fi

mkdir -p "$(dirname "$out")" "$(dirname "$log")"
KEY=$key DIRTY=$dirty SECONDS_REQ=$seconds CARGO_FUZZ=$cargo_fuzz LIMITS=$limits \
  OVERRIDES=$overrides_json FLOORS=$floors \
  CHANNEL=$channel RUSTC_COMMIT=$rustc_commit RUSTC_VERSION=$rustc_version \
  HEAD_SHA=$(m2a_git rev-parse HEAD) TARGETS="${M2A_TARGETS[*]}" \
  python3 -I - "$work" "$fuzz_dir" "$out" "$log" <<'PY'
import json, os, re, sys

work, fuzz_dir, out, log_path = sys.argv[1:5]
env = os.environ

def files(d):
    return sorted(f for f in os.listdir(d) if os.path.isfile(os.path.join(d, f)))

def stat(text, name):
    m = re.findall(rf"^stat::{name}:\s*(\d+)", text, re.M)
    return int(m[-1]) if m else None

floors = json.loads(env["FLOORS"])
targets, log = [], []
for name in env["TARGETS"].split():
    d = os.path.join(work, name)
    with open(os.path.join(d, "run.log"), errors="replace") as f:
        text = f.read()
    rc = int(open(os.path.join(d, "exit")).read())
    start = int(open(os.path.join(d, "start")).read())
    end = int(open(os.path.join(d, "end")).read())
    done = re.findall(r"^Done (\d+) runs in (\d+) second", text, re.M)
    oom = "ERROR: libFuzzer: out-of-memory" in text
    timed_out = "ERROR: libFuzzer: timeout" in text
    crashed = not oom and not timed_out and (
        rc != 0 or re.search(r"ERROR: (libFuzzer: deadly signal|AddressSanitizer|LeakSanitizer)|panicked at", text) is not None)
    completed = bool(done) and rc == 0 and not (oom or timed_out or crashed)
    inited = re.findall(r"^#\d+\s+INITED\s+cov: (\d+) ft: (\d+)", text, re.M)
    final = re.findall(r"^#\d+\s+DONE\s+cov: (\d+) ft: (\d+)", text, re.M)
    seed_ft = int(inited[-1][1]) if inited else 0
    final_cov, final_ft = (int(final[-1][0]), int(final[-1][1])) if final else (0, 0)
    exercised = seed_ft >= floors[name] and final_ft >= seed_ft
    execs = stat(text, "number_of_executed_units")
    if execs is None:
        pulses = re.findall(r"^#(\d+)\s", text, re.M)
        execs = int(pulses[-1]) if pulses else 0
    art_dir = os.path.join(fuzz_dir, "artifacts", name)
    artifacts = sorted(
        a for a in (os.listdir(art_dir) if os.path.isdir(art_dir) else [])
        if os.path.getmtime(os.path.join(art_dir, a)) >= start - 1)
    seed_sha = open(os.path.join(d, "seed_sha256")).read().strip()
    seed_files = len(files(os.path.join(fuzz_dir, "corpus", name)))
    found_dir = os.path.join(d, "corpus")
    found = len(files(found_dir))
    largest = max((os.path.getsize(os.path.join(found_dir, f)) for f in files(found_dir)), default=0)
    targets.append({
        "target": name,
        "seconds": int(done[-1][1]) if done else end - start,
        "execs": execs,
        "crashes": int(crashed),
        "ooms": int(oom),
        "timeouts": int(timed_out),
        "completed": completed,
        "exercised": exercised,
        "seed_ft": seed_ft,
        "final_ft": final_ft,
        "final_cov": final_cov,
        "exit_code": rc,
        "peak_rss_mb": stat(text, "peak_rss_mb"),
        "new_units": stat(text, "new_units_added"),
        "artifacts": artifacts,
        "corpus_sha256": seed_sha,
        "corpus_files": seed_files,
        "found_corpus_files": found,
        "largest_found_input": largest,
    })
    keep = [l for l in text.splitlines()
            if l.startswith(("stat::", "Done ", "INFO: seed corpus")) or re.match(r"#\d+\s+(INITED|DONE)\s", l) or "ERROR: " in l or "SUMMARY:" in l
            or "panicked at" in l or "Test unit written to" in l]
    status = ("clean" if exercised else f"not exercised (seed ft {seed_ft} < floor {floors[name]} or final ft {final_ft} < seed ft)") if completed \
        else ("OOM" if oom else "timeout" if timed_out else "crash" if crashed else "incomplete")
    log.append(f"== {name}: {status}, exit {rc}, {targets[-1]['seconds']} s\n" + "\n".join(keep) + "\n")
    if not (completed and exercised):
        log.append(f"-- last lines of {d}/run.log --\n" + "\n".join(text.splitlines()[-40:]) + "\n")

gate = {
    "gate": "m2a-fuzz",
    "format": 1,
    "requested_seconds": int(env["SECONDS_REQ"]),
    "head": env["HEAD_SHA"],
    "dirty": env["DIRTY"] == "true",
    "decoder_key": json.loads(env["KEY"]),
    "toolchain": {"channel": env["CHANNEL"], "rustc_commit": env["RUSTC_COMMIT"], "rustc": env["RUSTC_VERSION"]},
    "cargo_fuzz": env["CARGO_FUZZ"],
    "limits": json.loads(env["LIMITS"]),
    "overrides": json.loads(env["OVERRIDES"]),
    "targets": targets,
}
with open(out, "w") as f:
    json.dump(gate, f, indent=2)
    f.write("\n")
with open(log_path, "w") as f:
    f.write("\n".join(log))
for t in targets:
    print(f"{t['target']:22} {t['seconds']:>6} s {t['execs']:>12} execs  crashes {t['crashes']} "
          f"ooms {t['ooms']} timeouts {t['timeouts']}  largest kept input {t['largest_found_input']} B"
          f"  ft {t['seed_ft']}->{t['final_ft']}{'' if t['completed'] and t['exercised'] else '  NOT CLEAN'}")
print(f"wrote {out} and {log_path}")
sys.exit(0 if all(t["completed"] and t["exercised"] for t in targets) else 1)
PY
