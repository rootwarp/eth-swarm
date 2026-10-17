# Shared by the script tests: builds throwaway workspaces of path-only crates (no registry
# access) under $tmp. Source it after setting `tmp`.

# crate <ws> <name> [Cargo.toml tail...]: adds a library crate; each tail argument is one line.
crate() {
  local ws=$1 name=$2
  shift 2
  mkdir -p "$ws/$name/src"
  : > "$ws/$name/src/lib.rs"
  {
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n' "$name"
    for line in "$@"; do printf '%s\n' "$line"; done
  } > "$ws/$name/Cargo.toml"
}

# workspace <name> <member...>: writes the root manifest and an offline lockfile.
workspace() {
  local ws="$tmp/$1"
  shift
  local members=""
  for m in "$@"; do members="$members\"$m\", "; done
  printf '[workspace]\nresolver = "2"\nmembers = [%s]\n' "$members" > "$ws/Cargo.toml"
  cargo generate-lockfile --offline --quiet --manifest-path "$ws/Cargo.toml"
  echo "$ws/Cargo.toml"
}

passed=0 failed=0

# check <expect: pass|fail> <description> <script> <manifest> [grep pattern the output must contain]
check() {
  local expect=$1 desc=$2 script=$3 manifest=$4 want=${5:-} rc=0 out
  out=$(bash "$script" "$manifest" 2>&1) || rc=$?
  local ok=0
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | sed 's/^/       /'
  fi
}
