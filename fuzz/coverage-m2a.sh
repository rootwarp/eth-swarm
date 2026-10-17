#!/usr/bin/env bash
# Coverage of the m2a gate's bound checks: runs `cargo fuzz coverage` per target over its corpus
# and prints the execution counts of the lines that refuse oversize input:
#   - the 10 MiB prefix check (check_declared in p2p-wire: the MAX_PAYLOAD_SIZE cap and the
#     PayloadTooLarge refusal), every target;
#   - the max_compressed_len cut-off (the payload scanner's CompressedTooLarge, at a frame body;
#     at a frame header and in the decompressor it is reported, not required), every target;
#   - the frame caps: FrameTooLarge (a frame body over MAX_FRAME_BODY_LEN, a frame claiming more
#     than 64 KiB) and TooManyEmptyFrames, every target;
#   - in cl-p2p's read_response_chunks: the chunk-count check (the limit test and the
#     TooManyChunks refusal), the ResponseTooLarge byte budget and DataAfterError,
#     blocks_by_range_resp.
# A required line with a count of 0 fails the report. Lines are found by their source text (the
# refusal itself, or the line after a unique condition), so an edit that moves one fails loudly
# instead of reporting another line.
#
# The corpus is the committed seeds (fuzz/corpus and the slow seeds of fuzz/corpus-slow, which
# the gate does not fuzz from: the ResponseTooLarge budget needs seconds per input), plus what
# the last fuzz/run-m2a-gate.sh found (fuzz/target/m2a-gate/<target>/corpus) if that is there.
#
# Usage: fuzz/coverage-m2a.sh [--out FILE]   (default fuzz/artifacts/m2a-coverage.txt)
# Exit: 0 every required line ran, 1 one did not, 2 setup error (including an environment or
# cargo config m2a_require_clean_env refuses).
# Env: FUZZ_TOOLCHAIN, CARGO, RUSTC (see fuzz/m2a-common.sh). Works on bash 3.2.
set -euo pipefail
# shellcheck source=m2a-common.sh
. "$(dirname "$0")/m2a-common.sh"

out="$fuzz_dir/artifacts/m2a-coverage.txt"
while (($#)); do
  case $1 in
    --out) (($# >= 2)) || { echo "Usage: fuzz/coverage-m2a.sh [--out FILE]"; exit 2; }; out=$2; shift 2 ;;
    *) echo "Usage: fuzz/coverage-m2a.sh [--out FILE]"; exit 2 ;;
  esac
done
[[ $out == /* ]] || out="$PWD/$out"
# A coverage build under foreign flags would report other code than the gate runs.
m2a_require_clean_env

wire=crates/p2p-wire/src/rpc/codec.rs
rpc=crates/cl-p2p/src/rpc/codec.rs
# label | file | exact source text | line offset from it | targets that must execute it
# ("all", one target, or "-" for reported only)
CHECKS=(
  "10 MiB prefix: MAX_PAYLOAD_SIZE cap|$wire|let max = max.min(MAX_PAYLOAD_SIZE);|0|all"
  "10 MiB prefix: PayloadTooLarge|$wire|_ => Err(CodecError::PayloadTooLarge { len, max }),|0|all"
  "max_compressed_len cut-off: frame body|$wire|if end > p.limit {|1|all"
  "max_compressed_len cut-off: frame header|$wire|if p.pos + FRAME_HEADER_LEN > p.limit {|1|-"
  "max_compressed_len cut-off: decompress|$wire|CodecError::CompressedTooLarge { len: n, max: limit }|0|-"
  "FrameTooLarge: frame body|$wire|return Err(CodecError::FrameTooLarge { len: body_len });|0|all"
  "FrameTooLarge: decompressed frame|$wire|return Err(CodecError::FrameTooLarge { len });|0|all"
  "TooManyEmptyFrames|$wire|return Err(CodecError::TooManyEmptyFrames {|0|all"
  "chunk count: limit reached|$rpc|if chunks.len() as u64 == max_chunks {|0|blocks_by_range_resp"
  "chunk count: TooManyChunks|$rpc|return Err(ReadError::TooManyChunks { max: max_chunks });|0|blocks_by_range_resp"
  "ResponseTooLarge: byte budget|$rpc|_ => Err(ReadError::ResponseTooLarge { budget: self.total }),|0|blocks_by_range_resp"
  "DataAfterError|$rpc|return Err(ReadError::DataAfterError);|0|blocks_by_range_resp"
)

# Resolve every check to one line number first.
lines=()
for check in "${CHECKS[@]}"; do
  IFS='|' read -r label file text offset _ <<<"$check"
  n=$(grep -cF -- "$text" "$repo/$file" || true)
  if [[ $n != 1 ]]; then
    echo "ERROR: $file: want exactly one line with '$text', found $n (update CHECKS)"
    exit 2
  fi
  lines+=($(($(grep -nF -- "$text" "$repo/$file" | cut -d: -f1) + offset)))
done

m2a_cargo metadata --locked --format-version 1 >/dev/null \
  || { echo "ERROR: fuzz/Cargo.lock does not match fuzz/Cargo.toml"; exit 2; }
host=$(m2a_rustc -vV | sed -n 's/^host: //p')
llvm_cov="$(m2a_rustc --print sysroot)/lib/rustlib/$host/bin/llvm-cov"
[[ -x $llvm_cov ]] || { echo "ERROR: $llvm_cov missing (rustup component add llvm-tools)"; exit 2; }

report=$(mktemp)
trap 'rm -f "$report"' EXIT
{
  echo "m2a fuzz coverage, HEAD $(m2a_git rev-parse HEAD)$([[ -z $(m2a_dirty_paths) ]] || echo ' (dirty)')"
  echo "decoder key: $(m2a_key_json 2>&1 || true)"
  echo "toolchain: $(m2a_rustc -V)"
} > "$report"
mkdir -p "$fuzz_dir/coverage"
fail=0
for target in "${M2A_TARGETS[@]}"; do
  dirs=("$fuzz_dir/corpus/$target")
  slow="$fuzz_dir/corpus-slow/$target"
  if [[ -d $slow ]]; then dirs+=("$slow"); fi
  found="$fuzz_dir/target/m2a-gate/$target/corpus"
  if [[ -d $found ]] && [[ -n $(ls -A "$found") ]]; then dirs+=("$found"); fi
  if ! m2a_cargo fuzz coverage "${M2A_BUILD_FLAGS[@]}" "$target" "${dirs[@]}" \
    > "$fuzz_dir/coverage/$target.log" 2>&1; then
    echo "ERROR: cargo fuzz coverage $target failed; see fuzz/coverage/$target.log"
    exit 2
  fi
  bin="$fuzz_dir/target/$host/coverage/$host/release/$target"
  profdata="$fuzz_dir/coverage/$target/coverage.profdata"
  files=0
  for d in "${dirs[@]}"; do files=$((files + $(find "$d" -type f | wc -l))); done
  echo "" >> "$report"
  echo "== $target ($files inputs: ${dirs[*]#"$repo/"})" >> "$report"
  i=0
  for check in "${CHECKS[@]}"; do
    IFS='|' read -r label file _ _ need <<<"$check"
    line=${lines[$i]}
    i=$((i + 1))
    count=$("$llvm_cov" show "$bin" -instr-profile="$profdata" "$repo/$file" 2>/dev/null \
      | awk -F'|' -v n="$line" '$1 + 0 == n && $1 ~ /^ *[0-9]+ *$/ && !done { gsub(/ /, "", $2); print $2; done = 1 }')
    required=0
    [[ $need == all || $need == "$target" ]] && required=1
    status=""
    if ((required)); then
      if [[ -z $count || $count == 0 ]]; then status="NOT EXECUTED"; fail=1; else status="ok"; fi
    else
      status="not required"
    fi
    printf '  %-44s %s:%-5s %10s  %s\n' "$label" "$file" "$line" "${count:--}" "$status" >> "$report"
  done
done
mkdir -p "$(dirname "$out")"
cp "$report" "$out"
cat "$out"
echo ""
echo "wrote $out"
exit $fail
