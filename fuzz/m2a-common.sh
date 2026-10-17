# Shared by fuzz/build-m2a.sh, fuzz/run-m2a-gate.sh, fuzz/check-m2a-gate.sh and
# fuzz/coverage-m2a.sh. Source it; it sets `repo` and `fuzz_dir` from its own location.
# Works on bash 3.2.

fuzz_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$fuzz_dir/.." && pwd)

# The four response decoders the m2a-session binary runs on peer bytes.
M2A_TARGETS=(status_v2 metadata_v3 ping_goodbye blocks_by_range_resp)

# Release, with debug assertions and overflow checks (an overflow is a crash, not a wrap), and
# AddressSanitizer (cargo-fuzz's default). The gate runs exactly what build-m2a.sh builds.
M2A_BUILD_FLAGS=(-O -a)

# The gate's decoder key: what the fuzzed decoder and its harness are built and run from. A
# change to any of these makes a gate file stale. `git rev-parse HEAD:<path>` of each path, plus
# the sha256 of both lockfiles. network-config is outside the key: none of its code runs on
# peer bytes (the ContextTable is injected). The manifests are in it because features (root
# [workspace.dependencies] included) change the build without changing the lockfile; the
# harness, seeds and these scripts (limits, build flags) because a weaker run must not keep an
# old gate. fuzz/Cargo.lock is what the targets link; the root Cargo.lock is what the session
# binary links, so a root bump (snap, say) makes the gate stale before fuzz/Cargo.lock follows
# it (scripts/check-fuzz-lock.sh keeps the two alike).
M2A_KEY_PATHS=(
  Cargo.toml
  crates/p2p-wire
  crates/consensus-types
  crates/cl-p2p/Cargo.toml
  crates/cl-p2p/src/rpc/mod.rs
  crates/cl-p2p/src/rpc/codec.rs
  fuzz/Cargo.toml
  fuzz/rust-toolchain.toml
  fuzz/src
  fuzz/fuzz_targets
  fuzz/corpus
  fuzz/corpus-slow
  fuzz/m2a-common.sh
  fuzz/build-m2a.sh
  fuzz/run-m2a-gate.sh
)
M2A_KEY_FILES=(Cargo.lock fuzz/Cargo.lock)

# A gate needs this long per target.
M2A_REQUIRED_SECONDS=3600

# libFuzzer limits of a gate run; fuzz/check-m2a-gate.sh refuses a file with any other value.
#
# -malloc_limit_mb=128 is the declared allocation bound. One chunk's receive buffer is at most
# 1 + 4 + 10 + max_compressed_len(10 MiB) (about 11.7 MiB), its SSZ at most MAX_PAYLOAD_SIZE
# (10 MiB), and a decoded block's largest vector at most 6 x its SSZ (24-byte list entries per
# 4-byte offset), so any single allocation of 128 MiB or more is sized by something other than
# a checked length. -rss_limit_mb=2048 bounds the whole process. -timeout=10 s per input.
#
# -max_len (m2a_max_len): without it libFuzzer caps inputs at the largest seed (49,379 B), and
# a BlocksByRange stream could never grow past that. blocks_by_range_resp gets 2 MiB: room for
# multi-block responses and blocks well into their bound, and at most ~21 x that (snappy's best
# ratio, ~42 MiB) decompressed per input, under the malloc limit per allocation. The
# single-chunk targets get 4096 B: their largest valid chunk is an error chunk of 1 + 2 +
# max_compressed_len(256) = 333 B (a Status is 132 B), so 4096 B is over 12 x any valid chunk,
# past every max_compressed_len cut-off they have, and holds the 3,098 B snappy-bomb seed.
M2A_RSS_LIMIT_MB=2048
M2A_MALLOC_LIMIT_MB=128
M2A_TIMEOUT_S=10
m2a_max_len() {
  case $1 in
    blocks_by_range_resp) echo 2097152 ;;
    *) echo 4096 ;;
  esac
}

# The coverage-feature floor (libFuzzer's `ft:` once the seed corpus is loaded, the INITED line)
# a target must reach, so a run whose target body never executes cannot pass. Measured on the
# committed seeds (rustc 5d8fec066): status_v2 495, metadata_v3 481, ping_goodbye 459,
# blocks_by_range_resp 5,131; a target that returns at once (RUST_LIBFUZZER_DEBUG_PATH set) has
# 66-80. The floors sit at well under half of the real values and well over the no-op ones.
m2a_min_seed_ft() {
  case $1 in
    blocks_by_range_resp) echo 2000 ;;
    *) echo 200 ;;
  esac
}

# The cargo-fuzz release, and the rustc commit of the fuzz/rust-toolchain.toml channel
# (nightly-2026-10-17 is rustc 1.101.0-nightly 5d8fec066 2026-10-16). Change them with the pin;
# build-m2a.sh refuses to build with anything else, so CI catches a drift.
M2A_CARGO_FUZZ_VERSION=0.13.2
M2A_RUSTC_COMMIT=5d8fec0669a64607db9ccbf663e7c23125bf4748

# Tool overrides: a fuzz run may use them only for a smoke run (under M2A_REQUIRED_SECONDS), and
# the gate file records them; fuzz/check-m2a-gate.sh refuses a file that records any.
M2A_OVERRIDE_VARS=(CARGO RUSTC FUZZ_TOOLCHAIN RUSTUP_TOOLCHAIN)

# m2a_require_python: exit 2 unless python3 is 3.11 or later (tomllib, which the guard below
# needs). macOS's /usr/bin/python3 is 3.9.
m2a_require_python() {
  local version re='^Python ([0-9]+)\.([0-9]+)'
  version=$(python3 -V 2>&1) || version=${version:-no python3}
  if [[ $version =~ $re ]] &&
    { ((BASH_REMATCH[1] > 3)) || { ((BASH_REMATCH[1] == 3)) && ((BASH_REMATCH[2] >= 11)); }; }; then
    return 0
  fi
  echo "ERROR: python3 >= 3.11 needed (tomllib); python3 -V says: ${version:-nothing}"
  exit 2
}

# m2a_require_clean_env: exit 2 unless nothing in the environment or a cargo config file can
# change how the targets are built or run behind the recorded policy:
#   - compiler and linker flags, wrappers and profiles: RUSTFLAGS, RUSTDOCFLAGS,
#     CARGO_ENCODED_RUSTFLAGS, CARGO_ENCODED_RUSTDOCFLAGS (set, even empty, it replaces
#     RUSTFLAGS and so drops cargo-fuzz's sanitizer and coverage flags), RUSTC_WRAPPER,
#     RUSTC_WORKSPACE_WRAPPER and every CARGO_BUILD_*, CARGO_TARGET_* (per-target rustflags,
#     runner, linker, and the target dir), CARGO_HOST_*, CARGO_PROFILE_*, CARGO_UNSTABLE_*;
#   - which command `cargo fuzz` is: every CARGO_ALIAS_* (CARGO_ALIAS_FUZZ would run instead of
#     cargo-fuzz), and an alias named fuzz in a cargo config file (below);
#   - how libFuzzer itself is built (libfuzzer-sys 0.4.13's build.rs, through the cc crate):
#     CUSTOM_LIBFUZZER_PATH and CUSTOM_LIBFUZZER_STD_CXX (link that library instead of the
#     bundled libFuzzer), every LIBFUZZER_*, and cc's compiler, archiver and flags variables in
#     all four of cc's spellings (CC, CC_<target>, CC_<target_with_underscores>, HOST_CC or
#     TARGET_CC): CC, CXX, CFLAGS, CXXFLAGS, AR, ARFLAGS, RANLIB, RANLIBFLAGS, NVCC, CXXSTDLIB,
#     CXXSTDLIB_STATIC, every CC_* (CC_FORCE_DISABLE, CC_SHELL_ESCAPED_FLAGS, ...), plus
#     CRATE_CC_NO_DEFAULTS, CROSS_COMPILE and SDKROOT. The <target> forms hold '-' and '.', so
#     they are no shell identifiers and bash does not list them: the names come from python;
#   - the run itself: RUST_LIBFUZZER_DEBUG_PATH (libfuzzer-sys then writes each input to that
#     file and returns before the target body runs), the sanitizer options (ASAN_OPTIONS,
#     UBSAN_OPTIONS, LSAN_OPTIONS, MSAN_OPTIONS, TSAN_OPTIONS, HWASAN_OPTIONS; none is set by
#     these scripts, so none is allowed), and library interposition (LD_PRELOAD, LD_AUDIT,
#     DYLD_INSERT_LIBRARIES), which could replace the allocator the malloc limit watches;
#   - a CARGO_HOME that is not an absolute path (cargo runs in fuzz/, so a relative one names
#     another directory than the one checked here);
#   - cargo config files cargo reads for a command run in fuzz/: .cargo/config and
#     .cargo/config.toml in fuzz/ and every directory above it, and in CARGO_HOME (default
#     ~/.cargo). Only tables that change neither the build nor the run are allowed (alias, doc,
#     http, net, registries, registry, term, cargo-new, credential-alias,
#     future-incompat-report, install, cache, and build.jobs), and alias without a fuzz key.
# Needs python3 >= 3.11 (m2a_require_python runs first).
m2a_require_clean_env() {
  if [[ -n ${CARGO_HOME+set} && $CARGO_HOME != /* ]]; then
    echo "ERROR: CARGO_HOME='$CARGO_HOME' is not an absolute path; cargo would read it from fuzz/"
    exit 2
  fi
  m2a_require_python
  local name names bad=()
  names=$(python3 -I -c 'import os; print("\n".join(sorted(os.environ)))') || exit 2
  while IFS= read -r name; do
    case $name in
      RUSTFLAGS | RUSTDOCFLAGS | CARGO_ENCODED_RUSTFLAGS | CARGO_ENCODED_RUSTDOCFLAGS | \
        RUSTC_WRAPPER | RUSTC_WORKSPACE_WRAPPER | CARGO_BUILD_* | CARGO_TARGET_* | \
        CARGO_HOST_* | CARGO_PROFILE_* | CARGO_UNSTABLE_* | CARGO_ALIAS_* | \
        RUST_LIBFUZZER_DEBUG_PATH | \
        ASAN_OPTIONS | UBSAN_OPTIONS | LSAN_OPTIONS | MSAN_OPTIONS | TSAN_OPTIONS | \
        HWASAN_OPTIONS | LD_PRELOAD | LD_AUDIT | DYLD_INSERT_LIBRARIES | \
        CUSTOM_LIBFUZZER_* | LIBFUZZER_* | \
        CC | CC_* | CXX | CXX_* | CFLAGS | CFLAGS_* | CXXFLAGS | CXXFLAGS_* | CXXSTDLIB* | \
        AR | AR_* | ARFLAGS | ARFLAGS_* | RANLIB* | NVCC | NVCC_* | \
        HOST_CC* | HOST_CXX* | HOST_CFLAGS | HOST_AR* | HOST_RANLIB* | HOST_NVCC | \
        TARGET_CC* | TARGET_CXX* | TARGET_CFLAGS | TARGET_AR* | TARGET_RANLIB* | TARGET_NVCC | \
        CRATE_CC_NO_DEFAULTS | CROSS_COMPILE | SDKROOT)
        bad+=("$name")
        ;;
    esac
  done <<<"$names"
  if ((${#bad[@]})); then
    echo "ERROR: the environment would change the fuzz build or run; unset: ${bad[*]}"
    exit 2
  fi
  local dir=$fuzz_dir configs=()
  while :; do
    configs+=("$dir/.cargo/config" "$dir/.cargo/config.toml")
    [[ $dir == / ]] && break
    dir=$(dirname "$dir")
  done
  local home=${CARGO_HOME:-$HOME/.cargo}
  configs+=("$home/config" "$home/config.toml")
  python3 -I - "${configs[@]}" <<'PY' || exit 2
import sys, tomllib
ALLOWED = {"alias", "doc", "http", "net", "registries", "registry", "term", "cargo-new",
           "credential-alias", "future-incompat-report", "install", "cache"}
errors = []
for path in sys.argv[1:]:
    try:
        with open(path, "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        continue
    except (OSError, tomllib.TOMLDecodeError) as e:
        errors.append(f"{path}: does not parse ({e})")
        continue
    for key, value in config.items():
        if key == "build" and isinstance(value, dict) and set(value) <= {"jobs"}:
            continue
        if key == "alias" and not isinstance(value, dict):
            errors.append(f"{path}: alias is not a table")
            continue
        if key == "alias" and "fuzz" in value:
            errors.append(f"{path}: [alias] fuzz would run instead of cargo-fuzz")
            continue
        if key not in ALLOWED:
            what = f"{key}.{', '.join(sorted(value))}" if key == "build" and isinstance(value, dict) else key
            errors.append(f"{path}: [{what}] would change the fuzz build or run")
for e in errors:
    print(f"ERROR: {e}")
sys.exit(1 if errors else 0)
PY
}

# The channel fuzz/rust-toolchain.toml pins.
m2a_toolchain_pin() {
  sed -n 's/^channel = "\(.*\)"$/\1/p' "$fuzz_dir/rust-toolchain.toml"
}

# The limits a gate run must use, as one JSON object.
m2a_limits_json() {
  local t out sep=''
  out="{\"rss_limit_mb\": $M2A_RSS_LIMIT_MB, \"malloc_limit_mb\": $M2A_MALLOC_LIMIT_MB"
  out="$out, \"timeout_s\": $M2A_TIMEOUT_S, \"build_flags\": ["
  for t in "${M2A_BUILD_FLAGS[@]}"; do out="$out$sep\"$t\""; sep=', '; done
  out="$out], \"max_len\": {"
  sep=''
  for t in "${M2A_TARGETS[@]}"; do out="$out$sep\"$t\": $(m2a_max_len "$t")"; sep=', '; done
  printf '%s}}\n' "$out"
}

# m2a_sha256 <file|->: the hex sha256 of a file, or of stdin.
m2a_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# m2a_corpus_sha256 <dir>: sha256 over "<sha256 of file>  <name>" lines of every file in dir,
# sorted by name (C locale).
m2a_corpus_sha256() {
  local name
  (
    cd "$1"
    LC_ALL=C ls -A | while IFS= read -r name; do
      if [[ -f $name ]]; then printf '%s  %s\n' "$(m2a_sha256 "$name")" "$name"; fi
    done
  ) | m2a_sha256 -
}

# cargo in fuzz/, so fuzz/rust-toolchain.toml picks the nightly; FUZZ_TOOLCHAIN overrides it.
m2a_cargo() {
  (cd "$fuzz_dir" && "${CARGO:-cargo}" ${FUZZ_TOOLCHAIN:+"+$FUZZ_TOOLCHAIN"} "$@")
}

m2a_rustc() {
  (cd "$fuzz_dir" && "${RUSTC:-rustc}" ${FUZZ_TOOLCHAIN:+"+$FUZZ_TOOLCHAIN"} "$@")
}

# Prints the keyed paths that differ from HEAD (modified, staged or untracked), if any, and the
# keyed files git is told not to look at: assume-unchanged (`git ls-files -v` prints the tag in
# lowercase) or skip-worktree (tag S). `git status` skips an edit to either, so the flag itself
# counts as dirty, edited or not. Fails (status 1, message on stderr) if git does.
m2a_dirty_paths() {
  local status listed tag path
  status=$(git -C "$repo" status --porcelain --untracked-files=all -- \
    "${M2A_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}") || {
    echo "ERROR: git status failed" >&2
    return 1
  }
  listed=$(git -C "$repo" ls-files -v -- "${M2A_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}") || {
    echo "ERROR: git ls-files failed" >&2
    return 1
  }
  [[ -z $status ]] || printf '%s\n' "$status"
  while IFS= read -r tag; do
    path=${tag#* }
    case ${tag%% *} in
      S) echo "skip-worktree: $path" ;;
      s) printf 'skip-worktree: %s\nassume-unchanged: %s\n' "$path" "$path" ;;
      # Spelled out: [a-z] follows the locale's collation in bash 3.2 and can match H.
      [abcdefghijklmnopqrstuvwxyz]) echo "assume-unchanged: $path" ;;
    esac
  done <<<"$listed"
}

# Prints the decoder key of HEAD as one JSON object; fails if a keyed path is not in HEAD.
m2a_key_json() {
  local path sha out='{"git": {'
  local sep=''
  for path in "${M2A_KEY_PATHS[@]}"; do
    sha=$(git -C "$repo" rev-parse --verify --quiet "HEAD:$path") || {
      echo "ERROR: $path is not in HEAD" >&2
      return 1
    }
    out="$out$sep\"$path\": \"$sha\""
    sep=', '
  done
  out="$out}, \"sha256\": {"
  sep=''
  for path in "${M2A_KEY_FILES[@]}"; do
    [[ -f $repo/$path ]] || {
      echo "ERROR: $path missing" >&2
      return 1
    }
    out="$out$sep\"$path\": \"$(m2a_sha256 "$repo/$path")\""
    sep=', '
  done
  printf '%s}}\n' "$out"
}
