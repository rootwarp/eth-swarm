#!/usr/bin/env bash
# Fail if crypto-kzg can reach a trusted-setup load path other than its pinned JSON loader, or if
# blst is built with `portable` anywhere in the workspace.
#   1. crates/crypto-kzg/ never names c-kzg's embedded settings (`ethereum_kzg_settings`, which
#      escape the digest pin) or its text-format file loader (`load_trusted_setup_file`).
#   2. `cargo tree -e features -i blst` (all targets, all features) shows no `portable`.
# Usage: scripts/check-kzg-loaders.sh [repo-root]
# Env: CARGO (default `cargo`); KZG_CHECK_NO_RG=1 forces the grep fallback. Works on bash 3.2.
set -euo pipefail
root=${1:-"$(cd "$(dirname "$0")/.." && pwd)"}
cd "$root"
cargo=${CARGO:-cargo}
pattern='ethereum_kzg_settings|load_trusted_setup_file'
dir=crates/crypto-kzg/
fail=0

if [[ ! -d $dir ]]; then
  echo "ERROR: $dir not found under $root"
  exit 1
fi

# 1. Forbidden loaders. Hidden and ignored files are searched too, so rg and grep agree.
rc=0
if [[ -z ${KZG_CHECK_NO_RG:-} ]] && command -v rg >/dev/null 2>&1; then
  hits=$(rg -n --hidden --no-ignore -e "$pattern" "$dir") || rc=$?
else
  hits=$(grep -rnE -e "$pattern" "$dir") || rc=$?
fi
case $rc in
  0) echo "ERROR: forbidden c-kzg setup loader in $dir:"; printf '%s\n' "$hits"; fail=1 ;;
  1) ;;
  *) echo "ERROR: searching $dir failed (exit $rc)"; fail=1 ;;
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
