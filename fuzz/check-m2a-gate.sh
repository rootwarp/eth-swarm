#!/usr/bin/env bash
# Verifies an m2a fuzz gate file (fuzz/run-m2a-gate.sh) against this tree. With --gate gate1
# (fuzz/check-gate1.sh) it verifies a gate-1 file (fuzz/run-gate1.sh) instead: the same rules
# over gate 1's targets and key (gate_select in fuzz/m2a-common.sh), and "gate": "gate1-fuzz".
#
# The gate holds when the file is of this gate and lists exactly its targets (m2a: status_v2,
# metadata_v3, ping_goodbye, blocks_by_range_resp), each run to completion for >= 3600 s with
# executions, exit 0 and 0 crashes, 0 OOMs and 0 timeouts, from a clean tree, and:
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
#   - `head` is the full lowercase hex id of a commit of this repository (a commit object, not a
#     tag that points at one), an ancestor of HEAD, and the decoder key at that commit (from git,
#     not the working tree) is the file's, so the file names a commit that was fuzzed. The
#     m2a-session binary mirrors the m2a rules; having no git at run time, it holds `head` to
#     the `heads` of --print-expected (m2a_key_heads: HEAD and its ancestors with HEAD's key),
#     embedded when it was built;
#   - no tool override (CARGO, RUSTC, FUZZ_TOOLCHAIN, RUSTUP_TOOLCHAIN) was in use: `overrides`
#     is empty. fuzz/run-m2a-gate.sh refuses the environment variables and cargo config that
#     would change the build or run, so a file it wrote holds only for a clean environment.
# The file is read once, into a private copy every rule is checked against, so a file replaced
# while the checks run is not half seen. That read is one non-blocking open, and the open file
# must be a regular file of at most 1 MiB (GATE_MAX_BYTES, the binary's bound): a FIFO is
# refused, not waited on, and at most 1 MiB + 1 byte is copied.
#
# Usage: fuzz/check-m2a-gate.sh [--gate m2a|gate1] <gate.json>      verify the gate file
#        fuzz/check-m2a-gate.sh [--gate m2a|gate1] --print-key        print this tree's decoder key
#        fuzz/check-m2a-gate.sh [--gate m2a|gate1] --print-expected   print every value a gate file
#                                                                     must hold
# Exit: 0 valid, 1 invalid, stale or over the size bound, 2 usage error, a file that cannot be
# opened or is not a regular file, or the key cannot be computed.
# Needs git and python3. Works on bash 3.2.
set -euo pipefail
# shellcheck source=m2a-common.sh
. "$(dirname "$0")/m2a-common.sh"

# A gate file larger than this is not one run-m2a-gate.sh wrote; the m2a-session binary
# (MAX_GATE_BYTES in crates/cl-p2p/src/bin/m2a-session/gate.rs) holds files to the same bound.
GATE_MAX_BYTES=1048576

usage() {
  echo "Usage: fuzz/check-m2a-gate.sh [--gate m2a|gate1] <gate.json> | --print-key | --print-expected"
  exit 2
}

# Every value a gate file of this tree must hold, as one JSON object.
expected_json() {
  local key heads t sep='' corpus='{' floors='{'
  key=$(m2a_key_json) || return 1
  heads=$(m2a_key_heads) || return 1
  for t in "${GATE_TARGETS[@]}"; do
    [[ -d $fuzz_dir/corpus/$t ]] || { echo "ERROR: fuzz/corpus/$t missing" >&2; return 1; }
    corpus="$corpus$sep\"$t\": \"$(m2a_corpus_sha256 "$fuzz_dir/corpus/$t")\""
    floors="$floors$sep\"$t\": $(m2a_min_seed_ft "$t")"
    sep=', '
  done
  printf '{"decoder_key": %s, "limits": %s, "toolchain": {"channel": "%s", "rustc_commit": "%s"}, "cargo_fuzz": "cargo-fuzz %s", "corpus_sha256": %s}, "min_seed_ft": %s}, "heads": %s}\n' \
    "$key" "$(m2a_limits_json)" "$(m2a_toolchain_pin)" "$M2A_RUSTC_COMMIT" \
    "$M2A_CARGO_FUZZ_VERSION" "$corpus" "$floors" "$heads"
}

if (($# == 3)) && [[ $1 == --gate ]]; then
  gate_select "$2" || { echo "ERROR: --gate wants m2a or gate1, not '$2'"; usage; }
  shift 2
fi
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
# Every check reads this copy, taken once (mktemp -d: mode 0700); the expected values and the
# stderr of the key computation land next to it.
work=$(mktemp -d) || exit 2
trap 'rm -rf "$work"' EXIT
gate_copy=$work/gate.json
# One open of the file (O_NONBLOCK: a FIFO with no writer opens at once), and on that descriptor
# the checks the m2a-session binary makes: a regular file (fstat) of at most GATE_MAX_BYTES, of
# which at most GATE_MAX_BYTES + 1 bytes are read, so a file that grows past the bound after the
# fstat is refused too. Exit 2 if it cannot be opened or is not a regular file, 1 if it is over
# the bound.
python3 -I - "$file" "$gate_copy" "$GATE_MAX_BYTES" <<'PY' || exit $?
import os, stat, sys
path, copy, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
refused = f"ERROR: {path}: not a regular file of at most {limit} bytes"
try:
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
except OSError as e:
    print(f"ERROR: {path}: cannot be opened: {e.strerror}")
    sys.exit(2)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        print(refused)
        sys.exit(2)
    data = bytearray()
    while st.st_size <= limit and len(data) <= limit:
        chunk = os.read(fd, limit + 1 - len(data))
        if not chunk:
            break
        data += chunk
except OSError as e:
    print(f"ERROR: {path}: cannot be read: {e.strerror}")
    sys.exit(2)
finally:
    os.close(fd)
if st.st_size > limit or len(data) > limit:
    print(refused)
    sys.exit(1)
with open(copy, "xb") as out:
    out.write(data)
PY

# The expected values go to Python as a file: `heads` grows with the history, and one
# environment string is capped (128 KiB on Linux).
expected_json >"$work/expected.json" || exit 2
dirty=$(m2a_dirty_paths)
if [[ -n $dirty ]]; then
  echo "ERROR: keyed paths have uncommitted changes; the gate cannot vouch for this tree:"
  printf '%s\n' "$dirty" | sed 's/^/  /'
  exit 1
fi

# The commit the file names must be the one it vouches for. Sets head_error to why `head` cannot
# be, or head_key to the decoder key at it, which the checks below hold to the file's: `head` is
# the full lowercase hex id of a commit object of this repository (git cat-file -t: an annotated
# tag's id, which ^{commit} would peel, is not one), an ancestor of HEAD (the tree may
# have moved on since, outside the key), and the key computed at it from git (m2a_key_json
# <commit>, which reads no file of the working tree) is the file's. The key is m2a_key_json's
# stdout only; its stderr (git's warnings, or why it failed) is passed on, or is the error.
head_error="" head_key=""
check_head() {
  local head len format
  head=$(python3 -I -c '
import json, sys
try:
    gate = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(1)
head = gate.get("head") if isinstance(gate, dict) else None
if not isinstance(head, str):
    sys.exit(1)
print(head.encode("unicode_escape").decode("ascii"))
' "$gate_copy") || {
    head_error="head: missing, or not a string"
    return 0
  }
  format=$(m2a_git rev-parse --show-object-format) || {
    head_error="head: git rev-parse --show-object-format failed"
    return 0
  }
  len=40
  [[ $format != sha256 ]] || len=64
  if ! [[ $head =~ ^[0-9a-f]+$ ]] || ((${#head} != len)); then
    head_error="head: '${head:0:80}' is not a $len-character lowercase hex commit id"
  elif [[ $(m2a_git cat-file -t "$head" 2>/dev/null) != commit ]]; then
    head_error="head: $head is not a commit of this repository"
  elif ! m2a_git merge-base --is-ancestor "$head" HEAD 2>/dev/null; then
    head_error="head: $head is not an ancestor of HEAD"
  elif ! head_key=$(m2a_key_json "$head" 2>"$work/key.err"); then
    head_error="head: the decoder key at $head cannot be computed: $(<"$work/key.err")"
    head_key=""
  elif [[ -s $work/key.err ]]; then
    cat "$work/key.err" >&2
  fi
}
check_head

REQUIRED=$M2A_REQUIRED_SECONDS TARGETS="${GATE_TARGETS[*]}" \
  GATE_ID=$GATE_ID GATE_LABEL=$GATE_LABEL HEAD_ERROR=$head_error \
  HEAD_KEY=$head_key python3 -I - "$file" "$gate_copy" "$work/expected.json" <<'PY'
import json, os, sys

path, copy = sys.argv[1], sys.argv[2]
gate_id, label = os.environ["GATE_ID"], os.environ["GATE_LABEL"]
required = int(os.environ["REQUIRED"])
want_targets = os.environ["TARGETS"].split()
with open(sys.argv[3]) as f:
    want = json.load(f)
key = want["decoder_key"]
errors = []

try:
    with open(copy) as f:
        gate = json.load(f)
except (OSError, ValueError) as e:
    print(f"ERROR: {path}: not valid JSON: {e}")
    sys.exit(1)

def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)

if not isinstance(gate, dict):
    print(f"ERROR: {path}: not a JSON object")
    sys.exit(1)
if gate.get("gate") != gate_id or gate.get("format") != 1:
    errors.append(f"gate/format: want {gate_id} format 1, got {gate.get('gate')!r} format {gate.get('format')!r}")
req = gate.get("requested_seconds")
if not is_int(req) or req < required:
    errors.append(f"requested_seconds: {req!r} < {required} (a smoke run is not a gate)")
if gate.get("dirty") is not False:
    errors.append(f"dirty: {gate.get('dirty')!r}: the run was not from a clean tree")
if os.environ["HEAD_ERROR"]:
    errors.append(os.environ["HEAD_ERROR"])
else:
    try:
        head_key = json.loads(os.environ["HEAD_KEY"])
    except ValueError as e:
        errors.append(f"head: the decoder key at {gate.get('head')} is not valid JSON ({e}): {os.environ['HEAD_KEY'][:200]!r}")
    else:
        if gate.get("decoder_key") != head_key:
            errors.append(f"head: the decoder key at {gate.get('head')} is not the file's: it was not fuzzed at that commit")
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
print(f"{label} OK: {len(names)} targets x >= {required} s, 0 crashes/OOMs/timeouts, key, limits, toolchain and seeds match HEAD, fuzzed at {gate.get('head')}")
PY
