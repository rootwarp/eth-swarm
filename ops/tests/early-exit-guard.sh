# shellcheck shell=bash
# Sourced by the ops test suites: early_exit_pipes FILE... prints FILE:LINE: TEXT for each pipe
# into a reader that can exit before its input ends (grep -q, grep -m, head, awk with an exit,
# sed with q) and returns 1 if there is any. Under pipefail such a pipe can fail although the
# reader matched: the writer dies of SIGPIPE. Read a here-string instead
# (`grep -q -- "$want" <<<"$text"`). The rules and their limits are in early-exit-guard.awk;
# early-exit-guard.test.sh checks them. Works on bash 3.2.
early_exit_guard_awk="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/early-exit-guard.awk"
early_exit_pipes() {
  LC_ALL=C awk -f "$early_exit_guard_awk" "$@"
}
