#!/usr/bin/env bash
# Fail if the sigp SSZ git deps are not pinned to exactly the Lighthouse-unstable revs.
# Keep in sync with deny.toml [sources] comment and arch/ssz-crate-check.md.
set -euo pipefail
cd "$(dirname "$0")/.."
declare -A REV=(
  [ethereum_ssz]=974f78f421fbf70cba4e8f84e0fa28c23ad54f34
  [ssz_types]=8955d22edc7633f26fe3b5ac933facb5121d717a
  [tree_hash]=e5ea1875edddf12438506c3751cbb313f9c52d08
  [milhouse]=d67aabd2a7c405b3c16f4aaff159b137dc5b5e38
)
fail=0
[[ -f Cargo.lock ]] || { echo "ERROR: Cargo.lock must be committed"; exit 1; }
for repo in "${!REV[@]}"; do
  want=${REV[$repo]}; short=${want:0:7}
  # Cargo.toml (all manifests): rev = "..." on lines mentioning the repo
  while IFS= read -r line; do
    [[ $line == *"$short"* ]] || { echo "ERROR Cargo.toml: $repo not pinned to $short: $line"; fail=1; }
    [[ $line == *rev* ]] || { echo "ERROR Cargo.toml: $repo git dep without rev: $line"; fail=1; }
  done < <(git ls-files '*Cargo.toml' 2>/dev/null | xargs -r grep -h "github.com/sigp/$repo" || find . -name Cargo.toml -not -path './target/*' -exec grep -h "github.com/sigp/$repo" {} + || true)
  # Cargo.lock: source = "git+https://github.com/sigp/<repo>...#<full sha>"
  while IFS= read -r src; do
    [[ $src == *"#$want\"" ]] || { echo "ERROR Cargo.lock: $repo resolved to $src (want $want)"; fail=1; }
    if [[ $src == *"rev="* && $src != *"rev=$want#"* && $src != *"rev=$short#"* ]]; then echo "ERROR Cargo.lock: $repo requested rev differs: $src"; fail=1; fi
  done < <(grep -E "^source = \"git\+https://github.com/sigp/$repo(\.git)?[?#]" Cargo.lock || true)
done
[[ $fail == 0 ]] && echo "ssz revs OK"
exit $fail
