#!/usr/bin/env bash
# Builds the m2a fuzz targets exactly as fuzz/run-m2a-gate.sh runs them: release, with debug
# assertions and overflow checks, AddressSanitizer, from the committed fuzz/Cargo.lock, with the
# rustc commit and cargo-fuzz release pinned in fuzz/m2a-common.sh.
#
# cargo-fuzz has no --locked, so the lockfile is enforced around it: `cargo metadata --locked`
# fails before the build if fuzz/Cargo.lock would change, and the build fails if the lockfile's
# sha256 is not the same afterwards. Before building, scripts/check-fuzz-lock.sh must pass,
# offline (m2a_lock_preflight): fuzz/Cargo.lock resolves every shared crate as the root
# Cargo.lock does, so the targets link what the session binary links. Exit 2 if not.
#
# Usage: fuzz/build-m2a.sh [TARGET...]   (default: all four)
# Refuses (exit 2) an environment or cargo config that changes the build (m2a_require_clean_env).
# Env: FUZZ_TOOLCHAIN (default: the nightly of fuzz/rust-toolchain.toml), CARGO (default cargo).
# Works on bash 3.2.
set -euo pipefail
# shellcheck source=m2a-common.sh
. "$(dirname "$0")/m2a-common.sh"

m2a_require_clean_env

# The pinned compiler and cargo-fuzz (fuzz/m2a-common.sh), or nothing is built.
rustc_commit=$(m2a_rustc -vV | sed -n 's/^commit-hash: //p')
if [[ $rustc_commit != "$M2A_RUSTC_COMMIT" ]]; then
  echo "ERROR: rustc commit $rustc_commit, want $M2A_RUSTC_COMMIT ($(m2a_toolchain_pin), fuzz/rust-toolchain.toml)"
  exit 1
fi
cargo_fuzz=$(m2a_cargo fuzz --version 2>/dev/null || true)
if [[ $cargo_fuzz != "cargo-fuzz $M2A_CARGO_FUZZ_VERSION" ]]; then
  echo "ERROR: ${cargo_fuzz:-no cargo-fuzz}, want cargo-fuzz $M2A_CARGO_FUZZ_VERSION" \
    "(cargo install cargo-fuzz --version $M2A_CARGO_FUZZ_VERSION --locked)"
  exit 1
fi

lock="$fuzz_dir/Cargo.lock"
[[ -f $lock ]] || { echo "ERROR: fuzz/Cargo.lock missing: it must be committed"; exit 1; }
before=$(m2a_sha256 "$lock")
if ! m2a_cargo metadata --locked --format-version 1 >/dev/null; then
  echo "ERROR: fuzz/Cargo.lock does not match fuzz/Cargo.toml (cargo metadata --locked failed)"
  exit 1
fi
m2a_lock_preflight
if (($# == 0)); then
  m2a_cargo fuzz build "${M2A_BUILD_FLAGS[@]}"
else
  for target in "$@"; do
    m2a_cargo fuzz build "${M2A_BUILD_FLAGS[@]}" "$target"
  done
fi
after=$(m2a_sha256 "$lock")
if [[ $before != "$after" ]]; then
  echo "ERROR: the fuzz build changed fuzz/Cargo.lock ($before -> $after)"
  exit 1
fi
echo "fuzz targets built (${*:-all}) from fuzz/Cargo.lock $after"
