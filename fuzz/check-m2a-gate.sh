#!/usr/bin/env bash
# Verifies an m2a fuzz gate file (fuzz/run-m2a-gate.sh) against this tree.
#
# The gate holds when the file lists exactly the four targets (status_v2, metadata_v3,
# ping_goodbye, blocks_by_range_resp), each run to completion for >= 3600 s with executions,
# exit 0 and 0 crashes, 0 OOMs and 0 timeouts, from a clean tree, and:
#   - its decoder key equals this tree's: `git rev-parse HEAD:<path>` of every keyed path and the
#     sha256 of Cargo.lock and fuzz/Cargo.lock (fuzz/m2a-common.sh lists them). A keyed path with
#     uncommitted changes fails too, and so does one git is told not to look at (assume-unchanged
#     or skip-worktree): HEAD's key would match while the binary would be built from other
#     sources. The keyed files are compared with HEAD's blobs byte for byte, and a file on disk
#     HEAD lacks counts, ignored or not (m2a_worktree_diff), so no git config, filter, ignore
#     rule or stale index stat cache can hide an edit; git runs scrubbed (m2a_git);
#   - its limits are exactly the policy in fuzz/m2a-common.sh: -malloc_limit_mb, -rss_limit_mb,
#     -timeout, each target's -max_len and the build flags (-O -a);
#   - it ran on the fuzz/rust-toolchain.toml channel with the pinned rustc commit, and with the
#     pinned cargo-fuzz;
#   - each target's corpus_sha256 equals that of fuzz/corpus/<target> now;
#   - each target exercised its decoder: its coverage features once the seeds were loaded
#     (seed_ft) reach its floor (m2a_min_seed_ft) and the final count is no lower;
#   - no tool override (CARGO, RUSTC, FUZZ_TOOLCHAIN, RUSTUP_TOOLCHAIN) was in use: `overrides`
#     is empty. fuzz/run-m2a-gate.sh refuses the environment variables and cargo config that
#     would change the build or run, so a file it wrote holds only for a clean environment.
#
# Usage: fuzz/check-m2a-gate.sh <gate.json>      verify the gate file
#        fuzz/check-m2a-gate.sh --print-key        print this tree's decoder key as JSON
#        fuzz/check-m2a-gate.sh --print-expected   print every value a gate file must hold
# Exit: 0 valid, 1 invalid or stale, 2 usage error or the key cannot be computed.
# Needs git and python3. Works on bash 3.2.
set -euo pipefail
# shellcheck source=m2a-common.sh
. "$(dirname "$0")/m2a-common.sh"

usage() {
  echo "Usage: fuzz/check-m2a-gate.sh <gate.json> | --print-key | --print-expected"
  exit 2
}

# Every value a gate file of this tree must hold, as one JSON object.
expected_json() {
  local key t sep='' corpus='{' floors='{'
  key=$(m2a_key_json) || return 1
  for t in "${M2A_TARGETS[@]}"; do
    [[ -d $fuzz_dir/corpus/$t ]] || { echo "ERROR: fuzz/corpus/$t missing" >&2; return 1; }
    corpus="$corpus$sep\"$t\": \"$(m2a_corpus_sha256 "$fuzz_dir/corpus/$t")\""
    floors="$floors$sep\"$t\": $(m2a_min_seed_ft "$t")"
    sep=', '
  done
  printf '{"decoder_key": %s, "limits": %s, "toolchain": {"channel": "%s", "rustc_commit": "%s"}, "cargo_fuzz": "cargo-fuzz %s", "corpus_sha256": %s}, "min_seed_ft": %s}}\n' \
    "$key" "$(m2a_limits_json)" "$(m2a_toolchain_pin)" "$M2A_RUSTC_COMMIT" \
    "$M2A_CARGO_FUZZ_VERSION" "$corpus" "$floors"
}

(($# == 1)) || usage
case $1 in
  --print-key)
    m2a_key_json || exit 2
    exit 0
    ;;
  --print-expected)
    expected_json || exit 2
    exit 0
    ;;
  -*) usage ;;
esac
file=$1
[[ -f $file ]] || { echo "ERROR: $file: no such file"; exit 2; }

expected=$(expected_json) || exit 2
dirty=$(m2a_dirty_paths)
if [[ -n $dirty ]]; then
  echo "ERROR: keyed paths have uncommitted changes; the gate cannot vouch for this tree:"
  printf '%s\n' "$dirty" | sed 's/^/  /'
  exit 1
fi

EXPECTED=$expected REQUIRED=$M2A_REQUIRED_SECONDS TARGETS="${M2A_TARGETS[*]}" python3 -I - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
required = int(os.environ["REQUIRED"])
want_targets = os.environ["TARGETS"].split()
want = json.loads(os.environ["EXPECTED"])
key = want["decoder_key"]
errors = []

try:
    with open(path) as f:
        gate = json.load(f)
except (OSError, ValueError) as e:
    print(f"ERROR: {path}: not valid JSON: {e}")
    sys.exit(1)

def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)

if not isinstance(gate, dict):
    print(f"ERROR: {path}: not a JSON object")
    sys.exit(1)
if gate.get("gate") != "m2a-fuzz" or gate.get("format") != 1:
    errors.append(f"gate/format: want m2a-fuzz format 1, got {gate.get('gate')!r} format {gate.get('format')!r}")
req = gate.get("requested_seconds")
if not is_int(req) or req < required:
    errors.append(f"requested_seconds: {req!r} < {required} (a smoke run is not a gate)")
if gate.get("dirty") is not False:
    errors.append(f"dirty: {gate.get('dirty')!r}: the run was not from a clean tree")
if gate.get("decoder_key") != key:
    got = gate.get("decoder_key") if isinstance(gate.get("decoder_key"), dict) else {}
    for kind in sorted(set(key) | set(got)):
        mine, theirs = key.get(kind, {}), got.get(kind, {}) if isinstance(got.get(kind), dict) else {}
        for p in sorted(set(mine) | set(theirs)):
            if mine.get(p) != theirs.get(p):
                errors.append(f"decoder key stale: {kind} {p}: gate {theirs.get(p)!r}, tree {mine.get(p)!r}")
    if not errors or not any("stale" in e for e in errors):
        errors.append("decoder key stale")

if gate.get("limits") != want["limits"]:
    errors.append(f"limits: {json.dumps(gate.get('limits'), sort_keys=True)}, want {json.dumps(want['limits'], sort_keys=True)}")
tc = gate.get("toolchain") if isinstance(gate.get("toolchain"), dict) else {}
for field in ("channel", "rustc_commit"):
    if tc.get(field) != want["toolchain"][field]:
        errors.append(f"toolchain {field}: {tc.get(field)!r}, want {want['toolchain'][field]!r}")
if gate.get("overrides") != {}:
    errors.append(f"overrides: {gate.get('overrides')!r}: a gate run uses no tool override (smoke runs only)")
if gate.get("cargo_fuzz") != want["cargo_fuzz"]:
    errors.append(f"cargo_fuzz: {gate.get('cargo_fuzz')!r}, want {want['cargo_fuzz']!r}")

targets = gate.get("targets")
names = [t.get("target") for t in targets if isinstance(t, dict)] if isinstance(targets, list) else []
if sorted(names) != sorted(want_targets) or len(names) != len(targets or []):
    errors.append(f"targets: want exactly {want_targets}, got {names}")
for t in targets if isinstance(targets, list) else []:
    if not isinstance(t, dict):
        continue
    name = t.get("target")
    secs = t.get("seconds")
    if not is_int(secs):
        errors.append(f"{name}: seconds {secs!r} is not an integer")
    elif secs < required:
        errors.append(f"{name}: {secs} s < {required} s")
    execs = t.get("execs")
    if not is_int(execs) or execs <= 0:
        errors.append(f"{name}: execs {execs!r}")
    for field in ("crashes", "ooms", "timeouts", "exit_code"):
        if t.get(field) != 0:
            errors.append(f"{name}: {field} {t.get(field)!r}, want 0")
    if name in want["corpus_sha256"] and t.get("corpus_sha256") != want["corpus_sha256"][name]:
        errors.append(f"{name}: corpus_sha256 {t.get('corpus_sha256')!r} is not fuzz/corpus/{name} ({want['corpus_sha256'][name]})")
    seed_ft, final_ft = t.get("seed_ft"), t.get("final_ft")
    floor = want["min_seed_ft"].get(name)
    if not is_int(seed_ft) or floor is None or seed_ft < floor:
        errors.append(f"{name}: seed_ft {seed_ft!r} under the floor {floor}: the target did not run its decoder")
    if not is_int(final_ft) or (is_int(seed_ft) and final_ft < seed_ft):
        errors.append(f"{name}: final_ft {final_ft!r} below seed_ft {seed_ft!r}")
    if t.get("exercised") is not True:
        errors.append(f"{name}: exercised {t.get('exercised')!r}")
    if t.get("completed") is not True:
        errors.append(f"{name}: completed {t.get('completed')!r}: libFuzzer did not finish its run")

if errors:
    for e in errors:
        print(f"ERROR {path}: {e}")
    sys.exit(1)
print(f"m2a gate OK: {len(names)} targets x >= {required} s, 0 crashes/OOMs/timeouts, key, limits, toolchain and seeds match HEAD")
PY
