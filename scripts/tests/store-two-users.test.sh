#!/usr/bin/env bash
# Tests for scripts/store-two-users.sh.
# Run: bash scripts/tests/store-two-users.test.sh
# Offline and without root: stub `id`, `chown` and `chgrp` on PATH, a stub sudo (SUDO) that
# logs the user and runs the command as the current one, and a stub cargo (CARGO) whose
# "builds" are a fake fill_env (creates mdbx.dat and mdbx.lck) and a fake cl-store test binary
# (prints the two-user lines, or not). Every call goes to one log the cases read.
# Works on bash 3.2.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/../store-two-users.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

passed=0 failed=0
bin="$tmp/bin"
mkdir -p "$bin"
log="$tmp/log"
users="$tmp/users"
printf '%s\n' "writer 100 100" "reader 200 200" "rooty 0 0" "twin 100 300" > "$users"

cat > "$bin/id" <<'SH'
#!/usr/bin/env bash
# `id -u`: STUB_EUID (default 0). `id -u NAME`, `id -g NAME`: from STUB_USERS.
set -euo pipefail
if (($# == 1)) && [[ $1 == -u ]]; then echo "${STUB_EUID:-0}"; exit 0; fi
(($# == 2)) || exit 2
line=$(grep "^$2 " "$STUB_USERS") || { echo "id: '$2': no such user" >&2; exit 1; }
read -r _ uid gid <<<"$line"
case $1 in -u) echo "$uid" ;; -g) echo "$gid" ;; *) exit 2 ;; esac
SH
for tool in chown chgrp; do
  printf '#!/usr/bin/env bash\necho "%s $*" >> "$STUB_LOG"\n' "$tool" > "$bin/$tool"
done
cat > "$bin/sudo" <<'SH'
#!/usr/bin/env bash
# sudo -u USER CMD...: logs USER, runs CMD as the current user with STUB_AS=USER.
set -euo pipefail
[[ ${1:-} == -u && $# -ge 3 ]] || { echo "sudo stub: want -u USER CMD" >&2; exit 2; }
user=$2
shift 2
STUB_AS=$user exec "$@"
SH
cat > "$bin/cargo" <<'SH'
#!/usr/bin/env bash
# `test ... --no-run`: prints STUB_CARGO_TEST (default: the Executable line of the fake tests).
# `build ... --example fill_env`: installs the fake fill_env. STUB_CARGO_FAIL=test|build fails it.
set -euo pipefail
echo "cargo $*" >> "$STUB_LOG"
case " $* " in
  *" test "*)
    [[ ${STUB_CARGO_FAIL:-} != test ]] || { echo "error: could not compile" >&2; exit 101; }
    printf '%s\n' "${STUB_CARGO_TEST-  Executable unittests src/lib.rs ($STUB_TESTS)}" >&2 ;;
  *" build "*)
    [[ ${STUB_CARGO_FAIL:-} != build ]] || { echo "error: could not compile" >&2; exit 101; }
    mkdir -p "$CARGO_TARGET_DIR/debug/examples"
    cp "$STUB_FILL" "$CARGO_TARGET_DIR/debug/examples/fill_env" ;;
  *) exit 2 ;;
esac
SH
cat > "$tmp/fill_env" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
echo "fill_env as ${STUB_AS:-nobody} $*" >> "$STUB_LOG"
[[ ${STUB_FILL_FAIL:-} != 1 ]] || exit 1
touch "$1/mdbx.dat" "$1/mdbx.lck"
SH
cat > "$tmp/cl_store-0123" <<'SH'
#!/usr/bin/env bash
# The fake cl-store test binary: STUB_TESTS_MODE ok (both lines, laid out as libtest prints
# them), skip (cannot_write's only), silent (none), fail (exit 101).
env=${CL_STORE_TWO_USER_ENV:-}
modes=""
[[ -z $env ]] || modes=$(stat -c %a "$env" "$env/mdbx.dat" "$env/mdbx.lck" | tr '\n' ' ')
echo "tests as ${STUB_AS:-nobody} env=$env modes=$modes args=$*" >> "$STUB_LOG"
[[ -n $env ]] || exit 0
case ${STUB_TESTS_MODE:-ok} in
  ok)
    # As libtest prints them with --nocapture: each after its `test <name> ... `.
    echo "test reader::tests::cannot_write ... two-user: cannot_write ok on $env as uid 200"
    echo "ok"
    echo "test reader::tests::env_permissions ... two-user: env_permissions ok on $env as uid 200"
    echo "ok" ;;
  skip) echo "two-user: cannot_write ok on $env as uid 200" ;;
  silent) echo "running 0 tests" ;;
  fail) echo "test reader::tests::cannot_write ... FAILED"; exit 101 ;;
esac
SH
chmod +x "$bin"/* "$tmp/fill_env" "$tmp/cl_store-0123"

# check <expect: pass|fail> <description> <text the output must contain> [VAR=value...] -- [args]
check() {
  local expect=$1 desc=$2 want=$3 rc=0 out ok=0
  shift 3
  local vars=()
  while (($#)) && [[ $1 != -- ]]; do vars+=("$1"); shift; done
  shift
  : > "$log"
  rm -rf "$tmp/target"
  out=$(env PATH="$bin:$PATH" STUB_LOG="$log" STUB_USERS="$users" STUB_FILL="$tmp/fill_env" \
    STUB_TESTS="$tmp/cl_store-0123" CARGO="$bin/cargo" SUDO="$bin/sudo" \
    CARGO_TARGET_DIR="$tmp/target" ${vars[@]+"${vars[@]}"} bash "$script" "$@" 2>&1) || rc=$?
  if { [[ $expect == pass ]] && ((rc == 0)); } || { [[ $expect == fail ]] && ((rc != 0)); }; then ok=1; fi
  if ((ok)) && [[ -n $want ]] && ! grep -qF -- "$want" <<<"$out"; then ok=0; fi
  if ((ok)); then
    passed=$((passed + 1)); echo "ok   - $desc"
  else
    failed=$((failed + 1)); echo "FAIL - $desc (exit $rc)"; printf '%s\n' "$out" | tail -n 30 | sed 's/^/       /'
  fi
}

# logged <description> <text the log must contain>
logged() {
  if grep -qF -- "$2" "$log"; then
    passed=$((passed + 1)); echo "ok   - $1"
  else
    failed=$((failed + 1)); echo "FAIL - $1: no \"$2\" in the log"; sed 's/^/       /' "$log"
  fi
}

check pass "the writer fills the env, the reader runs both tests" "store two-user OK" -- writer reader
logged "fill_env runs as the writer" "fill_env as writer "
logged "the env directory is the writer's, in the reader's group" "chown writer:200 "
logged "the env files are in the reader's group" "chgrp 200 "
logged "the tests run as the reader, on the env it filled" "tests as reader env=/"
logged "  ... laid out as [5.43] has it: 0750, 0640, 0660" "/env modes=750 640 660 "
logged "  ... both of them, exactly, with their output" \
  "args=--exact reader::tests::cannot_write reader::tests::env_permissions --nocapture --test-threads=1"
logged "cargo builds the tests --locked" "cargo test --locked"
logged "cargo builds fill_env --locked" "cargo build --locked"

check fail "not root" "run as root" STUB_EUID=1000 -- writer reader
check fail "a user that does not exist" "no user nobody-here" -- writer nobody-here
check fail "root as the reader" "rooty is root" -- writer rooty
check fail "root as the writer" "rooty is root" -- rooty reader
check fail "one UID for both users" "are one user" -- writer twin
check fail "one argument" "usage" -- writer
check fail "the tests do not build" "building cl-store's tests failed" STUB_CARGO_FAIL=test -- writer reader
check fail "cargo names no test binary" "named no cl-store unittests executable" \
  STUB_CARGO_TEST="   Compiling cl-store" -- writer reader
check fail "fill_env does not build" "building fill_env failed" STUB_CARGO_FAIL=build -- writer reader
check fail "fill_env fails as the writer" "fill_env as writer failed" STUB_FILL_FAIL=1 -- writer reader
check fail "a test fails as the reader" "the tests failed as reader" STUB_TESTS_MODE=fail -- writer reader
check fail "env_permissions skipped (no line of its own)" "env_permissions did not check" \
  STUB_TESTS_MODE=skip -- writer reader
check fail "neither test ran (a filter that matched nothing)" "cannot_write did not check" \
  STUB_TESTS_MODE=silent -- writer reader

echo "passed: $passed, failed: $failed"
((failed == 0))
