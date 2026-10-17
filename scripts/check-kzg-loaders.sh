#!/usr/bin/env bash
# Fail if any crate can reach a trusted-setup load path other than crypto-kzg's pinned JSON loader,
# or if blst is built with `portable` anywhere in the workspace.
#   1. Nothing under crates/ names c-kzg's embedded settings (`ethereum_kzg_settings`, which escape
#      the digest pin), its text-format file loader (`load_trusted_setup_file`), or its raw loader
#      (`KzgSettings::load_trusted_setup`). The one allowed raw-loader call is in
#      crates/crypto-kzg/src/setup.rs, behind the digest check; the other two names are forbidden
#      there too.
#   2. `cargo tree -e features -i blst` (all targets, all features) shows no `portable`.
# Usage: scripts/check-kzg-loaders.sh [repo-root]
# Env: CARGO (default `cargo`); KZG_CHECK_NO_RG=1 forces the grep fallback. Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
cargo=${CARGO:-cargo}
pattern='ethereum_kzg_settings|load_trusted_setup_file|KzgSettings::load_trusted_setup'
always_forbidden='ethereum_kzg_settings|load_trusted_setup_file'
allowed_file=crates/crypto-kzg/src/setup.rs
dir=crates/crypto-kzg/
fail=0

if [[ ! -d $dir ]]; then
  echo "ERROR: $dir not found under $root"
  exit 1
fi

# 1. Forbidden loaders anywhere under crates/. Hidden and ignored files are searched too, so rg
#    and grep agree. A raw-loader line in the allowed file is dropped unless it also names one of
#    the always-forbidden loaders.
rc=0
if [[ -z ${KZG_CHECK_NO_RG:-} ]] && command -v rg >/dev/null 2>&1; then
  hits=$(rg -n --hidden --no-ignore -e "$pattern" crates/) || rc=$?
else
  hits=$(grep -rnE -e "$pattern" crates/) || rc=$?
fi
if ((rc == 0)); then
  hits=$(printf '%s\n' "$hits" | awk -v f="$allowed_file:" -v bad="$always_forbidden" \
    'index($0, f) != 1 || $0 ~ bad') || true
  [[ -n $hits ]] || rc=1
fi
case $rc in
  0) echo "ERROR: forbidden c-kzg setup loader under crates/:"; printf '%s\n' "$hits"; fail=1 ;;
  1) ;;
  *) echo "ERROR: searching crates/ failed (exit $rc)"; fail=1 ;;
esac

# 2. No `portable` blst. A failed or empty tree is not a pass: the check would prove nothing.
rc=0
tree=$("$cargo" tree -e features -i blst --target all --all-features --locked 2>&1) || rc=$?
if ((rc != 0)) || [[ $tree != *blst* ]]; then
  echo "ERROR: cargo tree -e features -i blst failed (exit $rc):"; printf '%s\n' "$tree"; fail=1
elif grep -qw portable <<<"$tree"; then
  echo "ERROR: blst is built with portable:"; printf '%s\n' "$tree"; fail=1
fi

if ((fail == 0)); then echo "kzg loaders OK"; fi
exit $fail
