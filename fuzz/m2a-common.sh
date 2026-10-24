# Shared by fuzz/build-m2a.sh, fuzz/run-m2a-gate.sh, fuzz/check-m2a-gate.sh and
# fuzz/coverage-m2a.sh (and so by fuzz/run-gate1.sh and fuzz/check-gate1.sh, which run the gate
# scripts with --gate gate1, fuzz/run-gate2a.sh and fuzz/check-gate2a.sh, with --gate gate2a, and
# fuzz/run-gate2b.sh and fuzz/check-gate2b.sh, with --gate gate2b).
# Source it; it sets `repo` and `fuzz_dir` from its own location, and
# selects the m2a gate (gate_select below). Every git call goes through m2a_git (a scrubbed
# environment and config).
# Works on bash 3.2.

fuzz_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$fuzz_dir/.." && pwd)

# The four response decoders the m2a-session binary runs on peer bytes.
M2A_TARGETS=(status_v2 metadata_v3 ping_goodbye blocks_by_range_resp)

# Gate 1: the probe's control decoders in both directions (Status, MetaData, Ping and Goodbye
# through the timed codec), one req/resp chunk of any protocol, the gossip transform with the
# Gloas block decode, the message-id, and the ENR fields.
GATE1_TARGETS=(rpc_chunk gossip_transform message_id enr_fields status_v2 metadata_v3 ping_goodbye)

# Gate 2a: the column decoders. The Gloas DataColumnSidecar as gossip (the snappy transform, then
# the bounded decode) and as a response chunk of both column protocols (the chunk decoder, the
# scanners and the timed codec), on the pinned Sepolia blob schedule's caps; and the two column
# requests (DataColumnSidecarsByRange v1, DataColumnSidecarsByRoot v1) through the timed codec
# and the request decoder, then the admission check.
GATE2A_TARGETS=(data_column_sidecar columns_by_range_req columns_by_root_req)

# Gate 2b: the column handlers. cl-chain's storage contract and column store (ColumnIngest on a
# temp column env, a stub reference and a stub cl-verify) and its column RPCs (ReqRespServer),
# driven with sequences of gossip sidecars and range and root requests.
GATE2B_TARGETS=(column_contract)

# Release, with debug assertions and overflow checks (an overflow is a crash, not a wrap), and
# AddressSanitizer (cargo-fuzz's default). The gate runs exactly what build-m2a.sh builds.
M2A_BUILD_FLAGS=(-O -a)

# The gate's decoder key: what the fuzzed decoder and its harness are built and run from. A
# change to any of these makes a gate file stale. `git rev-parse HEAD:<path>` of each path, plus
# the sha256 of both lockfiles. network-config is keyed: consensus-types' by-slot decoders map a
# peer's slot through its ForkSchedule, and the caps come from its pinned configs. cl-p2p's
# library is keyed from its crate root
# (lib.rs, so a #[path] or mod edit there makes the gate stale) through every module a keyed
# file imports, transitively: the rpc directory whole, transport (metrics imports its
# Direction) and its child modules, behaviour and peer_caps (the swarm builder imports them),
# gossip, and the modules lib.rs declares. Its binaries (main.rs, src/bin) are not keyed.
# crates/ci-checks/tests/fuzz_keys.rs fails if a keyed file imports a module (crate::, super::,
# self::, a child mod) that no key holds, if a keyed module's crate root is not keyed, or if
# keyed code imports a workspace path crate that the gate neither keys nor allows for that
# importing file with a reason (its ALLOWED list: ethswarm-proto, ipc, node-key and the crates
# only other gates' targets import). The manifests are in it
# because features (root [workspace.dependencies] included) change the build without changing
# the lockfile; the harness, seeds and these scripts (limits, build flags) because a weaker run
# must not keep an old gate. fuzz/Cargo.lock is what the targets link; the root Cargo.lock is
# what the session binary links, so a root bump (snap, say) makes the gate stale before
# fuzz/Cargo.lock follows it (scripts/check-fuzz-lock.sh keeps the two alike).
M2A_KEY_PATHS=(
  Cargo.toml
  crates/p2p-wire
  crates/consensus-types
  crates/network-config
  crates/cl-p2p/Cargo.toml
  crates/cl-p2p/src/lib.rs
  crates/cl-p2p/src/rpc
  crates/cl-p2p/src/transport.rs
  crates/cl-p2p/src/transport
  crates/cl-p2p/src/behaviour.rs
  crates/cl-p2p/src/peer_caps.rs
  crates/cl-p2p/src/gossip
  crates/cl-p2p/src/custody.rs
  crates/cl-p2p/src/identity.rs
  crates/cl-p2p/src/m2a_session.rs
  crates/cl-p2p/src/m2a_session
  crates/cl-p2p/src/peers
  crates/cl-p2p/src/testkit.rs
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

# Gate 1's key: the m2a key (which holds cl-p2p's gossip module: the gossip transform and the
# message-id hook), plus what its targets add: the record reader (cl-discv5's library, from its
# crate root through the enr, metrics and service modules it declares, and its manifest; not
# its main.rs) and fuzz/run-gate1.sh. network-config (the gossip caps and the ENR seeds come
# from the pinned Sepolia schedules) is in the m2a key. Both lockfiles are keyed as for m2a.
GATE1_KEY_PATHS=(
  "${M2A_KEY_PATHS[@]}"
  crates/cl-discv5/Cargo.toml
  crates/cl-discv5/src/lib.rs
  crates/cl-discv5/src/enr.rs
  crates/cl-discv5/src/metrics.rs
  crates/cl-discv5/src/service.rs
  fuzz/run-gate1.sh
)

# Gate 2a's key: the m2a key (p2p-wire holds the column protocols, their request and sidecar
# bounds and column_request_error, the check cl-p2p admits a column request with; cl-p2p's rpc
# codec reads the column responses and requests, and its rpc directory holds the column answers,
# rpc/columns.rs: what a request names, how an answer is cut; consensus-types holds
# NUMBER_OF_COLUMNS), plus cl-chain's request bounds (reqresp.rs), which the request targets run
# on every decoded request: cl-chain's source whole (its crate root declares every module) and
# manifest, and the workspace crates it imports (cl-chain-columns, the chain.v1 messages in
# ethswarm-proto and their sources in proto/ethswarm, the contract layer ipc); and
# fuzz/run-gate2a.sh. network-config (the column caps and the fork schedule a sidecar's slot is
# mapped through) is in the m2a key. Both lockfiles are keyed as for m2a.
GATE2A_KEY_PATHS=(
  "${M2A_KEY_PATHS[@]}"
  crates/cl-chain/Cargo.toml
  crates/cl-chain/src
  crates/cl-chain-columns
  crates/ethswarm-proto
  proto/ethswarm
  crates/ipc
  fuzz/run-gate2a.sh
)

# Gate 2b's key: the m2a key (the gossip transform and the column request decoders are
# p2p-wire's, the sidecar and block types consensus-types', the timed request codec cl-p2p's),
# plus everything column_contract runs past them: cl-chain's source and manifest (the probe's
# storage contract, reference view, root wait and column store, the custody record, the
# verify.v1 client's trait and the column RPCs), the column env (cl-chain-columns, its MDBX
# binding pinned in the lockfiles), the chain.v1 messages and their sources (ethswarm-proto,
# proto/ethswarm), the contract layer the RPCs and the harness hold every stream to (ipc), and
# fuzz/run-gate2b.sh. network-config (the Sepolia schedule and caps) is in the m2a key. Both
# lockfiles are keyed as for m2a.
GATE2B_KEY_PATHS=(
  "${M2A_KEY_PATHS[@]}"
  crates/cl-chain/Cargo.toml
  crates/cl-chain/src
  crates/cl-chain-columns
  crates/ethswarm-proto
  proto/ethswarm
  crates/ipc
  fuzz/run-gate2b.sh
)

# gate_select <m2a|gate1|gate2a|gate2b>: the gate the scripts run and check. Sets GATE_ID (the gate file's
# "gate"), GATE_LABEL (for messages), GATE_TARGETS, GATE_KEY_PATHS (the files are M2A_KEY_FILES
# for every gate), GATE_FILE (the default gate file under fuzz/artifacts/), GATE_WORK (the run's work
# directory under fuzz/target/), and GATE_RUNNER and GATE_CHECKER (the scripts, for messages).
# Status 1 for another name.
gate_select() {
  case $1 in
    m2a)
      GATE_ID=m2a-fuzz GATE_LABEL="m2a gate" GATE_FILE=m2a-gate.json GATE_WORK=m2a-gate
      GATE_RUNNER=fuzz/run-m2a-gate.sh GATE_CHECKER=fuzz/check-m2a-gate.sh
      GATE_TARGETS=("${M2A_TARGETS[@]}")
      GATE_KEY_PATHS=("${M2A_KEY_PATHS[@]}")
      ;;
    gate1)
      GATE_ID=gate1-fuzz GATE_LABEL="gate 1" GATE_FILE=gate1.json GATE_WORK=gate1
      GATE_RUNNER=fuzz/run-gate1.sh GATE_CHECKER=fuzz/check-gate1.sh
      GATE_TARGETS=("${GATE1_TARGETS[@]}")
      GATE_KEY_PATHS=("${GATE1_KEY_PATHS[@]}")
      ;;
    gate2a)
      GATE_ID=gate2a-fuzz GATE_LABEL="gate 2a" GATE_FILE=gate2a.json GATE_WORK=gate2a
      GATE_RUNNER=fuzz/run-gate2a.sh GATE_CHECKER=fuzz/check-gate2a.sh
      GATE_TARGETS=("${GATE2A_TARGETS[@]}")
      GATE_KEY_PATHS=("${GATE2A_KEY_PATHS[@]}")
      ;;
    gate2b)
      GATE_ID=gate2b-fuzz GATE_LABEL="gate 2b" GATE_FILE=gate2b.json GATE_WORK=gate2b
      GATE_RUNNER=fuzz/run-gate2b.sh GATE_CHECKER=fuzz/check-gate2b.sh
      GATE_TARGETS=("${GATE2B_TARGETS[@]}")
      GATE_KEY_PATHS=("${GATE2B_KEY_PATHS[@]}")
      ;;
    *) return 1 ;;
  esac
}
gate_select m2a

# A gate needs this long per target.
M2A_REQUIRED_SECONDS=3600

# libFuzzer limits of a gate run, the same for every gate; the checkers refuse a file with any
# other value.
#
# -malloc_limit_mb=128 is the declared allocation bound. One chunk's receive buffer is at most
# 1 + 4 + 10 + max_compressed_len(10 MiB) (about 11.7 MiB), its SSZ at most MAX_PAYLOAD_SIZE
# (10 MiB), and a decoded block's largest vector at most 6 x its SSZ (24-byte list entries per
# 4-byte offset), so any single allocation of 128 MiB or more is sized by something other than
# a checked length. The gossip targets hold the same: a message decompresses to at most its
# topic's cap (at most MAX_PAYLOAD_SIZE), checked from its header before decompressing, and the
# block it may hold decodes as above; a node record is at most 300 bytes. The column targets hold
# it too: a sidecar's SSZ is at most its fork's cap (Gloas: compute_max_data_column_sidecar_size()
# of the Sepolia schedule, 44,072 B; Fulu: its type bound, under MAX_PAYLOAD_SIZE), its lists are
# of fixed-size items, and a column request is at most 136,192 B. column_contract holds it as
# well: its gossip messages are those sidecars (each message at most 65,535 B, its 2-byte
# length), its requests those requests, and a sidecar it builds holds at most four cells; its
# column env is a memory map, not an allocation. -rss_limit_mb=2048 bounds the whole process,
# column_contract's column env included: one env at a time (one per input, removed after it),
# its map at most cl-chain-columns' MIN_MAX_SIZE (256 MiB) even with every page resident.
# -timeout=10 s per input; column_contract's wait for its writer thread (WRITER_WAIT in
# fuzz/src/contract.rs, 8 s) stays 2 s under it, which fuzz/tests/writer_wait.rs checks.
#
# -max_len (m2a_max_len): without it libFuzzer caps inputs at the largest seed (49,379 B), and
# a BlocksByRange stream could never grow past that. blocks_by_range_resp gets 2 MiB: room for
# multi-block responses and blocks well into their bound, and at most ~21 x that (snappy's best
# ratio, ~42 MiB) decompressed per input, under the malloc limit per allocation. The gossip
# targets get the same 2 MiB for one message: blocks well into their cap, bombs past every topic
# cap. rpc_chunk gets 1 MiB for one chunk of any protocol: blocks well into their bound and 16
# full 64 KiB frames. The single-chunk targets get 4096 B: their largest valid chunk is an error
# chunk of 1 + 2 + max_compressed_len(256) = 333 B (a Status is 132 B), so 4096 B is over 12 x
# any valid chunk, past every max_compressed_len cut-off they have, and holds the 3,098 B
# snappy-bomb seed. enr_fields gets 4096 B too: over 13 x a record's 300 bytes.
# data_column_sidecar gets 1 MiB, as rpc_chunk: one gossip message (the Sepolia column cap
# compresses to at most max_compressed_len(44,072) = 51,449 B) or one response chunk (Fulu
# sidecars of hundreds of cells, Gloas ones past the cap, bombs past every bound).
# columns_by_root_req gets 256 KiB: its bound is 136,192 B (128 identifiers of 128 columns), at
# most 158,922 B compressed plus frame headers, so a whole request fits even sent uncompressed.
# columns_by_range_req gets 4096 B: its bound is 1,044 B (1,250 B compressed), so 4096 B is over
# 3 x that and holds its 3,096 B snappy-bomb seed. column_contract gets 256 KiB, as
# columns_by_root_req: room for a whole by-root request at its bound as one raw operation, or a
# few column messages at the cap, besides the anchor and queries every seed carries; an input
# holds at most 24 sidecars and 24 requests whatever its length.
M2A_RSS_LIMIT_MB=2048
M2A_MALLOC_LIMIT_MB=128
M2A_TIMEOUT_S=10
m2a_max_len() {
  case $1 in
    blocks_by_range_resp | gossip_transform | message_id) echo 2097152 ;;
    rpc_chunk | data_column_sidecar) echo 1048576 ;;
    columns_by_root_req | column_contract) echo 262144 ;;
    *) echo 4096 ;;
  esac
}

# The coverage-feature floor (libFuzzer's `ft:` once the seed corpus is loaded, the INITED line)
# a target must reach, so a run whose target body never executes cannot pass. Measured on the
# committed seeds (rustc 5d8fec066): status_v2 2,065, metadata_v3 1,803, ping_goodbye 1,861 (the
# timed codec in both directions), blocks_by_range_resp 5,257, rpc_chunk 2,352,
# gossip_transform 3,226, message_id 1,471, enr_fields 4,151, data_column_sidecar 3,841,
# columns_by_range_req 1,429, columns_by_root_req 1,895, column_contract 21,950 (cl-chain's
# column store and RPCs past the decoders); a target that returns at once
# (RUST_LIBFUZZER_DEBUG_PATH set) has 66-103. The floors sit at well under half of the real
# values and well over the no-op ones.
m2a_min_seed_ft() {
  case $1 in
    column_contract) echo 5000 ;;
    blocks_by_range_resp) echo 2000 ;;
    gossip_transform | enr_fields | data_column_sidecar) echo 1500 ;;
    columns_by_root_req) echo 800 ;;
    columns_by_range_req) echo 600 ;;
    rpc_chunk) echo 1000 ;;
    status_v2 | metadata_v3 | ping_goodbye) echo 800 ;;
    message_id) echo 600 ;;
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
#     CRATE_CC_NO_DEFAULTS, CROSS_COMPILE, SDKROOT and MACOSX_DEPLOYMENT_TARGET (cc turns it
#     into libFuzzer's -mmacosx-version-min). The <target> forms hold '-' and '.', so they are
#     no shell identifiers and bash does not list them: the names come from python;
#   - the lockfile pre-flight (m2a_lock_preflight): FUZZ_LOCK_CARGO, which replaces cargo in
#     scripts/check-fuzz-lock.sh's resolution check (its tests' stub);
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
        CRATE_CC_NO_DEFAULTS | CROSS_COMPILE | SDKROOT | MACOSX_DEPLOYMENT_TARGET | \
        FUZZ_LOCK_CARGO)
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

# m2a_lock_preflight: exit 2 unless scripts/check-fuzz-lock.sh passes: fuzz/Cargo.lock (what
# the targets link) resolves every shared crate as the root Cargo.lock (what the session binary
# links) does, and satisfies its manifests. Both locks are in the decoder key, but only this
# ties one to the other: without it a tree committed with another root snap 1.x would get a
# fresh gate for a version that was never fuzzed. Offline (CARGO_NET_OFFLINE=true): by then the
# sources are fetched (build-m2a.sh's `cargo metadata --locked`, CI's online lock check).
m2a_lock_preflight() {
  if ! CARGO_NET_OFFLINE=true bash "$repo/scripts/check-fuzz-lock.sh" "$repo"; then
    echo "ERROR: fuzz/Cargo.lock does not agree with Cargo.lock (scripts/check-fuzz-lock.sh," \
      "offline): run fuzz/regen-lock.sh, or fetch the sources (cargo fetch --locked in fuzz/)"
    exit 2
  fi
}

# The channel fuzz/rust-toolchain.toml pins.
m2a_toolchain_pin() {
  sed -n 's/^channel = "\(.*\)"$/\1/p' "$fuzz_dir/rust-toolchain.toml"
}

# The limits a run of the selected gate must use, as one JSON object.
m2a_limits_json() {
  local t out sep=''
  out="{\"rss_limit_mb\": $M2A_RSS_LIMIT_MB, \"malloc_limit_mb\": $M2A_MALLOC_LIMIT_MB"
  out="$out, \"timeout_s\": $M2A_TIMEOUT_S, \"build_flags\": ["
  for t in "${M2A_BUILD_FLAGS[@]}"; do out="$out$sep\"$t\""; sep=', '; done
  out="$out], \"max_len\": {"
  sep=''
  for t in "${GATE_TARGETS[@]}"; do out="$out$sep\"$t\": $(m2a_max_len "$t")"; sep=', '; done
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

# m2a_git <args>: git in the repository, run the way crates/cl-p2p/build_support.rs runs it
# (child_env): an environment cleared but for PATH, so no inherited GIT_DIR, GIT_WORK_TREE,
# GIT_INDEX_FILE, GIT_CONFIG_* (or HOME and XDG_CONFIG_HOME, which locate the global config,
# ignore and attributes files) can point git at another tree or filter what it sees; no system
# or global config or attributes (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL=/dev/null,
# GIT_ATTR_NOSYSTEM); no optional index writes (GIT_OPTIONAL_LOCKS=0); and no fsmonitor, whose
# hook would tell git which files changed (-c core.fsmonitor=false). Every git call in the fuzz
# scripts goes through it. As in build_support.rs, safe.directory is not read, so a checkout
# owned by another user fails git's ownership check (fail closed).
m2a_git() {
  env -i PATH="$PATH" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ATTR_NOSYSTEM=1 \
    GIT_OPTIONAL_LOCKS=0 git -C "$repo" -c core.fsmonitor=false "$@"
}

# m2a_worktree_diff: prints how the keyed paths on disk differ from HEAD, byte for byte and
# without git's view of the working tree: every file HEAD has under a keyed path is read from
# $repo and its blob id computed over the raw bytes (what `git hash-object --no-filters` gives;
# a symlink's id is over its target) and compared with HEAD's ("content differs from HEAD",
# "missing", "type differs from HEAD"), and every file on disk under a keyed path that HEAD
# lacks is listed ("not in HEAD"), whatever .gitignore or .git/info/exclude say. So none of
# what git still reads from the repository itself (.git/config filters, core.worktree,
# .git/info/attributes, the index's stat data, assume-unchanged or skip-worktree) can make a
# changed file look clean. Fails closed: a checkout whose bytes legitimately differ from the
# blobs (eol conversion, a smudge filter such as LFS) counts as dirty. Needs python3.
m2a_worktree_diff() {
  local format
  format=$(m2a_git rev-parse --show-object-format) || {
    echo "ERROR: git rev-parse --show-object-format failed" >&2
    return 1
  }
  (
    set -o pipefail
    m2a_git ls-tree -r -z --full-tree HEAD -- "${GATE_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}" |
      python3 -I -c '
import hashlib, os, stat, sys

repo, fmt, keyed = os.fsencode(sys.argv[1]), sys.argv[2], sys.argv[3:]
head = {}
for rec in sys.stdin.buffer.read().split(b"\0"):
    if rec:
        meta, path = rec.split(b"\t", 1)
        mode, kind, oid = meta.split(b" ")
        head[path] = (mode, kind, oid.decode())

def blob_id(data):
    h = hashlib.new(fmt)
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()

out = []
for path, (mode, kind, oid) in sorted(head.items()):
    shown, full = os.fsdecode(path), os.path.join(repo, path)
    if kind != b"blob":
        out.append(f"not a file in HEAD: {shown}")
        continue
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        out.append(f"missing: {shown}")
        continue
    link = mode == b"120000"
    if link != stat.S_ISLNK(st.st_mode) or not (link or stat.S_ISREG(st.st_mode)):
        out.append(f"type differs from HEAD: {shown}")
        continue
    if link:
        data = os.readlink(full)
    else:
        with open(full, "rb") as f:
            data = f.read()
    if blob_id(data) != oid:
        out.append(f"content differs from HEAD: {shown}")
for k in keyed:
    top = os.path.join(repo, os.fsencode(k))
    if os.path.isdir(top) and not os.path.islink(top):
        for dirpath, dirs, files in os.walk(top):
            for name in files + [d for d in dirs if os.path.islink(os.path.join(dirpath, d))]:
                rel = os.path.relpath(os.path.join(dirpath, name), repo)
                if rel not in head:
                    out.append(f"not in HEAD: {os.fsdecode(rel)}")
    elif os.path.lexists(top) and os.fsencode(k) not in head:
        out.append(f"not in HEAD: {k}")
for line in out:
    print(line)
' "$repo" "$format" "${GATE_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}"
  ) || {
    echo "ERROR: comparing the keyed paths with HEAD failed" >&2
    return 1
  }
}

# Prints the keyed paths that differ from HEAD, if any: what `git status` shows (modified,
# staged or untracked), the keyed files git is told not to look at (assume-unchanged, which
# `git ls-files -v` prints in lowercase, or skip-worktree, tag S: `git status` skips an edit to
# either, so the flag itself counts as dirty, edited or not), and m2a_worktree_diff's byte
# comparison. The comparison is what the check rests on: git status trusts the index's stat
# cache, which a status run through a hiding filter can leave stale, and runs the repository's
# own filters; its lines only add to the list (a staged change, say), they never clear it.
# Fails (status 1, message on stderr) if git or the comparison does.
m2a_dirty_paths() {
  local status listed diff tag path
  status=$(m2a_git status --porcelain --untracked-files=all -- \
    "${GATE_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}") || {
    echo "ERROR: git status failed" >&2
    return 1
  }
  listed=$(m2a_git ls-files -v -- "${GATE_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}") || {
    echo "ERROR: git ls-files failed" >&2
    return 1
  }
  diff=$(m2a_worktree_diff) || return 1
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
  [[ -z $diff ]] || printf '%s\n' "$diff"
}

# m2a_key_json [COMMIT]: prints the selected gate's decoder key of HEAD (or of COMMIT) as one JSON
# object; fails if a keyed path is not in it. With no argument the lockfiles are hashed as they
# are on disk (the dirty check holds them to HEAD's); at COMMIT they are read from git, so the
# working tree is never touched.
m2a_key_json() {
  local rev=${1:-HEAD} path sha out='{"git": {'
  local sep=''
  for path in "${GATE_KEY_PATHS[@]}"; do
    sha=$(m2a_git rev-parse --verify --quiet "$rev:$path") || {
      echo "ERROR: $path is not in $rev" >&2
      return 1
    }
    out="$out$sep\"$path\": \"$sha\""
    sep=', '
  done
  out="$out}, \"sha256\": {"
  sep=''
  for path in "${M2A_KEY_FILES[@]}"; do
    if (($# == 0)); then
      [[ -f $repo/$path ]] || {
        echo "ERROR: $path missing" >&2
        return 1
      }
      sha=$(m2a_sha256 "$repo/$path")
    else
      m2a_git cat-file -e "$rev:$path" 2>/dev/null || {
        echo "ERROR: $path is not in $rev" >&2
        return 1
      }
      sha=$( (set -o pipefail; m2a_git show "$rev:$path" | m2a_sha256 -)) || return 1
    fi
    out="$out$sep\"$path\": \"$sha\""
    sep=', '
  done
  printf '%s}}\n' "$out"
}

# m2a_key_heads: prints, as one JSON array, HEAD and every ancestor of it (git rev-list HEAD,
# newest first) whose decoder key is HEAD's: each keyed path names the same object there as in
# HEAD (git cat-file --batch-check of <commit>:<path>; for the lockfiles the same blob, so the
# same sha256). These are the commits a gate file of this tree may name as its `head`, the set
# the checker's head rule accepts; the m2a-session binary, which has no git at run time, embeds
# it. Fails if git or python3 does.
m2a_key_heads() {
  (
    set -o pipefail
    m2a_git rev-list HEAD |
      python3 -I -c '
import sys
paths = sys.argv[1:]
for rev in ["HEAD"] + sys.stdin.read().split():
    for p in paths:
        print(f"{rev}:{p} {rev}")
' "${GATE_KEY_PATHS[@]}" "${M2A_KEY_FILES[@]}" |
      m2a_git cat-file --batch-check='%(objectname) %(rest)' |
      python3 -I -c '
import json, sys
keys = {}
for line in sys.stdin.read().splitlines():
    if line.endswith(" missing"):
        rev, oid = line.split(":", 1)[0], None
    else:
        oid, rev = line.split(" ", 1)
    keys.setdefault(rev, []).append(oid)
head = keys.pop("HEAD")
print(json.dumps([rev for rev, key in keys.items() if key == head]))
'
  ) || {
    echo "ERROR: listing the commits with HEAD's decoder key failed" >&2
    return 1
  }
}
