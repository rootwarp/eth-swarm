//! Oracle for `ci_checks::locked`: generated run values go through the check, and then real
//! bash runs each of them with a stub cargo that records each call. A false pass is a run value
//! that the check passes but that ran cargo without `--locked`. There must be none.
//!
//! The generator is deterministic (a fixed seed) and makes [`CASES`] run values from the shapes
//! that a word scan gets wrong: quotes, backslashes, continuations, comments, substitutions,
//! globs, brace expansions, redirects, pipes, wrapper commands, cargo names split by quotes or
//! empty expansions, aliases, and arguments that `cargo run` gives to the binary.
//!
//! One bash process (at a lower priority, in its own process group, with a deadline) runs all
//! of them, each in a subshell. A bash function catches a direct call, and an executable on
//! `PATH` catches a call through `env`, `command`, `exec`, a path or a new shell. Both record to
//! fd 3, which is a pipe that this test reads to its end. Thus a call from a background job or
//! a process substitution is recorded too.
//!
//! The stub reads the arguments as cargo 1.99 and clap do, independently of the check: an
//! optional first `+toolchain`, the global options (with short-option clusters, `--frozen` and
//! errors for unknown options), `CARGO_ALIAS_<NAME>` and `--config alias.<name>=..` for the
//! names that are not built in, and the trailing arguments of `cargo run`. It reads the
//! arguments of `cargo llvm-cov` as cargo-llvm-cov 0.9 and lexopt do: an option that takes a
//! value takes the next word, also one that starts with `-`.
//!
//! A second, small leg runs real cargo (offline, no dependencies, its own `CARGO_HOME`) on a
//! scratch package with no lockfile, for a fixed sample of passed lines. A new `Cargo.lock`
//! means that the line ran cargo unlocked. The leg is skipped if no cargo is found.

#![cfg(unix)]

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const SEED: u64 = 0x0236_10c4_ed5e_ed01;
const CASES: usize = 10_500;

/// The shapes that the issue lists, as they are written there, before the generated cases.
const ISSUE_SHAPES: &[&str] = &[
    "cargo test \"x --locked\"",
    "echo \"x #\"; cargo build",
    "\\>& cargo build",
    "car\\\ngo build",
    "echo \"$(cargo build)\"",
    "echo \"`cargo build`\"",
    "cat <(cargo build)",
    "echo x >\"$(cargo build)\"",
    "echo x >`cargo build`",
    "cargo build >&1---locked",
    "cargo build --locked 2>&1",
    "cargo build --locked >&-",
    "cargo test --locked 2>&1 | tee log",
    // Review findings: names built by expansions, nested trailing arguments, cargo words that
    // are not command words, and a moved cargo config.
    "${x:-car}go build",
    "$(echo car)go build",
    "x=car; y=go; $x$y build",
    "c=car\n${c}go build",
    "cargo llvm-cov run x --locked",
    "xargs -a f -I fmt cargo fmt",
    "ln -sf ./bin/cargo fmt; ./fmt build",
    "CARGO_HOME=h cargo fmt --check",
    // Deliberate bypasses after the fail-closed rewrite: a redirect before the command word,
    // wrappers that run their arguments, and cargo-llvm-cov options that take the next word.
    "x=car; y=go; >/dev/null $x$y build",
    "x=car; y=go; trap \"$x$y build\" EXIT",
    "x=car; y=go; find . -maxdepth 0 -exec $x$y build ';'",
    "cargo llvm-cov run --features --locked x",
    "cargo llvm-cov --lcov --output-path lcov.info --locked",
    // Review cycle 1: an escaped `<` or `>` before `|` or `&`, a quoted `;` in find, the
    // arguments of xargs after `{}`, and a command substitution in a `${..}`.
    "x=car; y=go; echo a\\>|$x$y build",
    "x=car; y=go; echo a\\>&$x$y build",
    "x=car; y=go; echo a\\<|$x$y build",
    "x=car; y=go; find . -maxdepth 0 -exec true ';' -exec $x$y build ';'",
    "x=car; y=go; echo b | xargs -I {} -P 1 $x$y {}",
    "a=car; b=go; : ${x:-$($a$b build)}",
];

/// Lines that the check must pass (a false refusal fails the test). They run with the other
/// cases, so a line here that ran cargo unlocked is a false pass too.
const POSITIVE_SHAPES: &[&str] = &[
    "echo \"${X}\" | xargs echo; echo $Y",
    "mkdir -p \"${OUT}\"; find . -name x -delete; ls $OUT",
    "git diff --name-only \"$(git merge-base HEAD origin/main)\" | xargs -r shellcheck; echo $?",
    "echo \"$(date)\" && find . -name x -delete && echo $HOME",
];

/// The stub: `oracle_cargo ARGS` writes `<kind> <case> <subcommand>` to fd 3. The kind is `L`
/// (locked), `N` (no lock needed), `U` (unlocked) or `E` (cargo or clap refuses the call).
const STUB: &str = r#"
oc_builtin() {
  case $1 in
    build|b|check|c|clean|doc|d|new|init|add|remove|run|r|test|t|bench|update|search|publish|\
    install|uninstall|help|version|metadata|tree|vendor|fetch|package|rustc|rustdoc|fix|\
    generate-lockfile|pkgid|locate-project|verify-project|info|config|owner|yank|login|logout)
      return 0 ;;
  esac
  return 1
}

# oc_upper NAME: the environment form of an alias name, or failure for an unusual name.
oc_upper() {
  case $1 in
    ''|*[!a-z0-9_-]*) return 1 ;;
    fmt) oc_up=FMT ;;
    clippy) oc_up=CLIPPY ;;
    nextest) oc_up=NEXTEST ;;
    deny) oc_up=DENY ;;
    llvm-cov) oc_up=LLVM_COV ;;
    frobnicate) oc_up=FROBNICATE ;;
    *) oc_up=$(printf '%s' "$1" | tr 'a-z-' 'A-Z_') ;;
  esac
}

# oc_alias NAME: sets oc_av to the alias of NAME, or fails if there is none.
oc_alias() {
  oc_upper "$1" || return 1
  eval "oc_set=\${CARGO_ALIAS_$oc_up+x} oc_av=\${CARGO_ALIAS_$oc_up-}"
  if [ -z "$oc_set" ]; then
    eval "oc_set=\${oc_cfg_$oc_up+x} oc_av=\${oc_cfg_$oc_up-}"
  fi
  [ -n "$oc_set" ]
}

# oc_config VALUE: one --config value.
oc_config() {
  case $1 in
    alias.*=*)
      oc_n=${1#alias.}
      oc_v=${oc_n#*=}
      oc_n=${oc_n%%=*}
      if oc_upper "$oc_n"; then
        eval "oc_cfg_$oc_up=\$oc_v"
        oc_cfg_names="$oc_cfg_names $oc_up"
      else
        oc_err=1
      fi ;;
    *=*) ;;
    *) oc_err=1 ;;
  esac
}

# oc_short LETTERS: one global short-option cluster.
oc_short() {
  oc_s=$1
  while [ -n "$oc_s" ]; do
    oc_l=${oc_s%"${oc_s#?}"}
    oc_s=${oc_s#?}
    case $oc_l in
      V|h) oc_info=1 ;;
      v|q) ;;
      C|Z) if [ -z "$oc_s" ]; then oc_skip=1; fi; return ;;
      *) oc_err=1; return ;;
    esac
  done
}

# oc_run_locked ARGS: the arguments after `cargo run`. Clap gives each word after the first
# positional argument to the binary. Status 0 locked, 1 unlocked, 2 refused.
oc_run_locked() {
  while [ $# -gt 0 ]; do
    oc_a=$1
    shift
    case $oc_a in
      --) return 1 ;;
      --locked|--frozen) return 0 ;;
      -p|--package|--bin|--example|--target)
        case ${1-} in -*|'') ;; *) shift ;; esac ;;
      -F|--features|-j|--jobs|--profile|--target-dir|--message-format|--color|--config|-Z|\
      -m|--manifest-path|--lockfile-path|--artifact-dir)
        case ${1-} in -*|'') return 2 ;; esac
        shift ;;
      --*) ;;
      -*)
        oc_s=${oc_a#-}
        while [ -n "$oc_s" ]; do
          oc_l=${oc_s%"${oc_s#?}"}
          oc_s=${oc_s#?}
          case $oc_l in
            q|v|r|h) ;;
            p) if [ -z "$oc_s" ]; then case ${1-} in -*|'') ;; *) shift ;; esac; fi; break ;;
            F|j|Z|m)
              if [ -z "$oc_s" ]; then
                case ${1-} in -*|'') return 2 ;; esac
                shift
              fi
              break ;;
            *) return 2 ;;
          esac
        done ;;
      *) return 1 ;;
    esac
  done
  return 1
}

# oc_llvm_locked ARGS: the arguments after `cargo llvm-cov`, as cargo-llvm-cov 0.9 reads them
# with lexopt: an option that takes a value takes the next word, also one that starts with `-`.
# The first positional argument is a subcommand, and `run` gives each word after its own first
# positional argument to the binary. Status 0 locked, 1 unlocked, 2 refused.
oc_llvm_locked() {
  oc_mode=
  while [ $# -gt 0 ]; do
    oc_a=$1
    shift
    case $oc_a in
      --) return 1 ;;
      --locked|--frozen) return 0 ;;
      --output-path|--output-dir|--failure-mode|--ignore-filename-regex|--fail-under-*|\
      --fail-uncovered-*|--dep-coverage|--nextest-archive-file|--archive-file|--cargo-profile|\
      --bin|--example|--test|--bench|--package|--exclude|--exclude-from-test|\
      --exclude-from-report|--jobs|--profile|--features|--target|--color|--manifest-path|\
      -p|-j|-F|-Z|-m)
        [ $# -gt 0 ] || return 2
        shift ;;
      --*) ;;
      -*)
        oc_s=${oc_a#-}
        while [ -n "$oc_s" ]; do
          oc_l=${oc_s%"${oc_s#?}"}
          oc_s=${oc_s#?}
          case $oc_l in
            p|j|F|Z|m)
              if [ -z "$oc_s" ]; then
                [ $# -gt 0 ] || return 2
                shift
              fi
              break ;;
          esac
        done ;;
      *)
        case $oc_mode in
          run) return 1 ;;
          sub) ;;
          *)
            case $oc_a in
              run) oc_mode=run ;;
              test|nextest|nextest-archive|report|clean|show-env) oc_mode=sub ;;
              *) return 2 ;;
            esac ;;
        esac ;;
    esac
  done
  return 1
}

oracle_kind() {
  for oc_n in $oc_cfg_names; do unset "oc_cfg_$oc_n"; done
  oc_cfg_names=
  oc_locked=0 oc_info=0 oc_sub= oc_skip= oc_err=0 oc_depth=0 oc_first=1
  while [ $# -gt 0 ]; do
    oc_a=$1
    shift
    if [ "$oc_first" = 1 ]; then
      oc_first=0
      case $oc_a in +*) continue ;; esac
    fi
    case $oc_skip in
      cfg) oc_skip=; oc_config "$oc_a"; continue ;;
      1) oc_skip=; continue ;;
    esac
    case $oc_a in
      --) break ;;
      --locked|--frozen) oc_locked=1 ;;
      --version|--help|--list) oc_info=1 ;;
      --config) oc_skip=cfg ;;
      --config=*) oc_config "${oc_a#--config=}" ;;
      --color|--explain) oc_skip=1 ;;
      --color=*|--explain=*|--verbose|--quiet|--offline) ;;
      --*) oc_err=1; break ;;
      -*) oc_short "${oc_a#-}" ;;
      *) oc_sub=$oc_a; break ;;
    esac
    [ "$oc_err" = 1 ] && break
  done
  if [ "$oc_err" = 1 ]; then oc_kind=E; return; fi
  if [ -z "$oc_sub" ]; then oc_kind=N; return; fi
  while ! oc_builtin "$oc_sub" && oc_alias "$oc_sub"; do
    oc_depth=$((oc_depth + 1))
    if [ "$oc_depth" -gt 5 ]; then oc_kind=E; return; fi
    set -- $oc_av "$@"
    oc_sub=${1-}
    [ $# -gt 0 ] && shift
  done
  case $oc_sub in
    fmt|help|version) oc_kind=N; return ;;
  esac
  if [ "$oc_locked" = 1 ]; then oc_kind=L; return; fi
  case $oc_sub in
    run|r)
      oc_run_locked "$@"
      case $? in 0) oc_kind=L ;; 1) oc_kind=U ;; *) oc_kind=E ;; esac
      return ;;
    llvm-cov)
      oc_llvm_locked "$@"
      case $? in 0) oc_kind=L ;; 1) oc_kind=U ;; *) oc_kind=E ;; esac
      return ;;
  esac
  for oc_a in "$@"; do
    case $oc_a in
      --) break ;;
      --locked|--frozen) oc_kind=L; return ;;
    esac
  done
  oc_kind=U
}

oracle_cargo() {
  oracle_kind "$@"
  case $oc_sub in
    ''|*[!A-Za-z0-9_.+-]*) oc_sub=other ;;
  esac
  printf '%s %s %s\n' "$oc_kind" "${ORACLE_CASE:-0}" "$oc_sub" >&3
}
"#;

const PATH_STUB: &str = "#!/bin/sh\n. \"$ORACLE_STUB\"\noracle_cargo \"$@\"\n";

/// Runs each NUL-terminated case of `$ORACLE_CASES` in a subshell, then writes `done <n>`.
const DRIVER: &str = r#"
. "$ORACLE_STUB"
cargo() { oracle_cargo "$@"; }
export ORACLE_CASE
exec 3>&1 >/dev/null 2>&1
n=0
while IFS= read -r -d '' c; do
  n=$((n + 1))
  ORACLE_CASE=$n
  ( eval "$c" ) </dev/null >/dev/null 2>&1
done < "$ORACLE_CASES"
echo "done $n" >&3
"#;

/// The real-cargo leg: runs each case with real cargo in a scratch package without a lockfile,
/// and writes `W <n>` if the case wrote `Cargo.lock`.
const REAL_DRIVER: &str = r#"
exec 3>&1 >/dev/null 2>&1
n=0
while IFS= read -r -d '' c; do
  n=$((n + 1))
  rm -f Cargo.lock
  ( eval "$c"; wait ) </dev/null >/dev/null 2>&1
  if [ -f Cargo.lock ]; then echo "W $n" >&3; fi
done < "$ORACLE_CASES"
rm -f Cargo.lock
echo "done $n" >&3
"#;

/// The time limit of one bash driver. The process group is killed after it.
const DEADLINE: Duration = Duration::from_secs(300);

/// splitmix64: small, fast and the same on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

/// Names of cargo: plain, split by quotes, backslashes, a continuation or an empty expansion,
/// built by a substitution, behind a wrapper, or by a path.
const CARGO_NAMES: &[&str] = &[
    "cargo",
    "cargo",
    "cargo",
    "cargo",
    "cargo",
    "cargo",
    "cargo",
    "cargo",
    "./bin/cargo",
    "CARGO",
    "\"cargo\"",
    "'cargo'",
    "c\"ar\"go",
    "ca''rgo",
    "\\cargo",
    "c\\argo",
    "car\\\ngo",
    "car${x}go",
    "car$(true)go",
    "car`true`go",
    "car$@go",
    "car{,}go",
    "$(echo cargo)",
    "`echo cargo`",
    "${y:-cargo}",
    "\"$(echo cargo)\"",
    "env cargo",
    "command cargo",
    "exec cargo",
    "eval cargo",
    "time cargo",
    "X=1 cargo",
    "CARGO_TERM_COLOR=always cargo",
    "x=cargo; $x",
    "x=cargo\n$x",
    "echo cargo |xargs",
    "bash -c cargo\\ build",
    "car{g..g}o",
    "~/.carg?/bin/carg?",
    "~/.cargo/bin/cargo",
    "CARGO_ALIAS_FMT=build cargo",
    "export CARGO_ALIAS_FMT=build; cargo",
    "env CARGO_ALIAS_CLIPPY=build cargo",
    "cargo -qC fmt",
    "cargo -C fmt",
    "cargo --config alias.fmt=build",
    "cargo --config=alias.fmt=build",
];

const SUBCOMMANDS: &[&str] = &[
    "build",
    "build",
    "test",
    "test",
    "check",
    "run",
    "clippy",
    "b",
    "fmt",
    "help",
    "version",
    "install",
    "frobnicate",
    "nextest",
    "r",
    "run",
    "llvm-cov",
    "llvm-cov run",
];

/// Arguments and the shapes that hide, move or fake `--locked`.
const ARGS: &[&str] = &[
    "--locked",
    "--locked",
    "--locked",
    "--locked",
    "--locked",
    "--locked",
    "--workspace",
    "-p x",
    "--release",
    "--",
    "+1.99.0",
    "--version",
    "-V",
    "--manifest-path m/Cargo.toml",
    "--config --locked",
    "--locked2",
    "--lock",
    "\"--locked\"",
    "'--locked'",
    "\"x --locked\"",
    "'x --locked'",
    "\"x #\"",
    "-\"-locked\"",
    "--loc\\ked",
    "\\--locked",
    "--loc\\\nked",
    "#",
    "# --locked",
    "#--locked",
    "x#--locked",
    "$(echo --locked)",
    "`echo --locked`",
    "\"$(echo --)\"",
    "<(echo --locked)",
    ">(cat)",
    "$(echo -- --locked)",
    "${y:---}",
    "$x",
    "${y:-'--'}",
    "{--locked,}",
    "{-,-}-locked",
    "2>&1",
    ">&-",
    ">&1---locked",
    ">&1",
    "2>log",
    ">log",
    "&>log",
    ">>log",
    "1>&2",
    "2>&1---locked",
    "\\>&",
    "<<<x",
    "--locked;",
    "--locked&&",
    "--locked|tee log",
    "\"a\nb\"",
    "'",
    "\"",
    "x\\",
    "*",
    "--locke?",
    "x",
    "-q x",
    "--bin p y",
    "--frozen",
    "-j --locked",
];

/// Commands that do not start with a cargo name, some of them naming cargo.
const OTHERS: &[&str] = &[
    "echo x",
    "true",
    ":",
    "echo \"x #\"",
    "echo 'x #'",
    "echo x #",
    "tee log",
    "echo \"a",
    "b\"",
    "echo '",
    "cat <<EOF",
    "EOF",
    "bash <<EOF",
    "echo cargo build",
    "# cargo build",
    "echo $CARGO_HOME ~/.cargo/bin",
    "x=car",
    "${x}go build",
    "f() { cargo build; }",
];

const GAPS: &[&str] = &[
    " ", " ", " ", " ", " ", " ", " ", " ", "  ", "\t", "", "\\\n", "\n",
];

const SEPARATORS: &[&str] = &[
    " && ",
    " && ",
    "; ",
    ";",
    " & ",
    " | ",
    "\n",
    "\n",
    "\n",
    "&&",
    " || ",
    " | tee log; ",
];

const SUFFIXES: &[&str] = &[
    " 2>&1",
    " | tee log",
    " 2>&1 | tee log",
    " >&-",
    " >&1---locked",
    " >log",
    " 2>/dev/null",
    " &",
    " # --locked",
    " #",
];

/// The plain parts of a cargo command that the check can pass.
const PLAIN_NAMES: &[&str] = &[
    "cargo",
    "cargo",
    "cargo",
    "./bin/cargo",
    "X=1 cargo",
    "time cargo",
];
const PLAIN_ARGS: &[&str] = &[
    "--locked",
    "--locked",
    "--locked",
    "--locked",
    "--workspace",
    "-p x",
    "--release",
    "--",
    "+1.99.0",
    "--version",
    "--manifest-path m/Cargo.toml",
    "--locked2",
    "# --locked",
    "x#--locked",
    "2>&1",
    "--locked;",
    "--locked&&",
    "|tee log",
    "x",
    "--bin p",
    "-q",
];
const PLAIN_GAPS: &[&str] = &[" ", " ", " ", "  ", "\t"];

/// A cargo command from plain parts, and then (in half of the cases) one part that a word scan
/// gets wrong in its place: near misses of a passing line.
fn near_miss(rng: &mut Rng) -> String {
    let mut parts = vec![rng.pick(PLAIN_NAMES)];
    if rng.chance(90) {
        parts.push(rng.pick(SUBCOMMANDS));
    }
    for _ in 0..rng.below(4) {
        parts.push(rng.pick(PLAIN_ARGS));
    }
    let mut gaps: Vec<&str> = (1..parts.len()).map(|_| rng.pick(PLAIN_GAPS)).collect();
    if rng.chance(50) {
        let i = rng.below(parts.len() + gaps.len());
        if i == 0 {
            parts[0] = rng.pick(CARGO_NAMES);
        } else if i < parts.len() {
            parts[i] = rng.pick(ARGS);
        } else {
            gaps[i - parts.len()] = rng.pick(GAPS);
        }
    }
    let mut s = String::from(parts[0]);
    for (gap, part) in gaps.iter().zip(&parts[1..]) {
        s.push_str(gap);
        s.push_str(part);
    }
    s
}

/// A cargo command from any parts.
fn any_parts(rng: &mut Rng) -> String {
    let mut s = String::from(rng.pick(CARGO_NAMES));
    if rng.chance(85) {
        s.push_str(if rng.chance(85) { " " } else { rng.pick(GAPS) });
        s.push_str(rng.pick(SUBCOMMANDS));
    }
    for _ in 0..rng.below(4) {
        s.push_str(rng.pick(GAPS));
        s.push_str(rng.pick(ARGS));
    }
    s
}

fn cargo_command(rng: &mut Rng) -> String {
    let mut s = if rng.chance(50) {
        near_miss(rng)
    } else {
        any_parts(rng)
    };
    if rng.chance(25) {
        s.push_str(rng.pick(SUFFIXES));
    }
    s
}

fn case(rng: &mut Rng) -> String {
    let mut s = String::new();
    let commands = if rng.chance(60) { 1 } else { 2 + rng.below(2) };
    for i in 0..commands {
        if i > 0 {
            s.push_str(rng.pick(SEPARATORS));
        }
        if rng.chance(80) {
            s.push_str(&cargo_command(rng));
        } else {
            s.push_str(rng.pick(OTHERS));
        }
    }
    s
}

fn cases() -> Vec<String> {
    let mut rng = Rng(SEED);
    let mut out: Vec<String> = ISSUE_SHAPES
        .iter()
        .chain(POSITIVE_SHAPES)
        .map(|s| s.to_string())
        .collect();
    while out.len() < CASES {
        out.push(case(&mut rng));
    }
    out
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

fn tool(name: &str) -> PathBuf {
    find_on_path(name).unwrap_or_else(|| panic!("{name} is not on PATH"))
}

fn write_executable(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, text).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn write_cases(path: &Path, cases: &[&str]) {
    let mut input = Vec::new();
    for c in cases {
        assert!(!c.contains('\0'));
        input.extend_from_slice(c.as_bytes());
        input.push(0);
    }
    fs::write(path, input).expect("write cases");
}

fn kill_group(pgid: u32) {
    let _ = Command::new(tool("kill"))
        .args(["-s", "KILL", "--", &format!("-{pgid}")])
        .stderr(Stdio::null())
        .status();
}

/// Runs `script` with bash at a lower priority in a new process group, and returns its fd 3
/// records once every process of the group closed the pipe. After [`DEADLINE`], or at the end,
/// the whole group is killed, so no process stays behind.
fn run_driver(script: &Path, env: &[(&str, &OsStr)], cwd: &Path) -> String {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(tool("nice"));
    cmd.args(["-n", "10"])
        .arg(tool("bash"))
        .arg(script)
        .env_clear()
        .envs(env.iter().copied())
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = cmd.spawn().expect("start the bash driver");
    let pgid = child.id();
    let mut stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let read = stdout.read_to_string(&mut text);
        let _ = tx.send(read.map(|_| text));
    });
    let text = match rx.recv_timeout(DEADLINE) {
        Ok(text) => text.expect("utf-8 records"),
        Err(_) => {
            kill_group(pgid);
            let _ = child.wait();
            panic!("the bash driver ran for more than {DEADLINE:?}");
        }
    };
    let status = child.wait().expect("wait for the bash driver");
    kill_group(pgid);
    assert!(status.success(), "driver failed: {status:?}");
    text
}

/// The `done <n>` count and the other records of a driver.
fn records(text: &str) -> (Option<usize>, Vec<(String, usize, String)>) {
    let mut done = None;
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split(' ');
        let kind = parts.next().unwrap_or_default().to_owned();
        let n: usize = parts
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("bad record {line:?}"));
        if kind == "done" {
            done = Some(n);
        } else {
            out.push((kind, n, parts.next().unwrap_or_default().to_owned()));
        }
    }
    (done, out)
}

/// `(kind, 1-based case, subcommand)` of each cargo call that the stub saw.
fn run_in_bash(cases: &[String]) -> Vec<(char, usize, String)> {
    let tmp = TempDir::new().expect("tempdir");
    let work = tmp.path().join("work");
    let home = tmp.path().join("home");
    let stub = tmp.path().join("stub.sh");
    fs::write(&stub, STUB).expect("write stub");
    write_executable(&work.join("bin/cargo"), PATH_STUB);
    write_executable(&home.join(".cargo/bin/cargo"), PATH_STUB);
    // An input file for `xargs -a f`.
    fs::write(work.join("f"), "build\n").expect("write xargs input");
    let driver = tmp.path().join("driver.sh");
    fs::write(&driver, DRIVER).expect("write driver");
    let cases_file = tmp.path().join("cases");
    write_cases(
        &cases_file,
        &cases.iter().map(String::as_str).collect::<Vec<_>>(),
    );

    // A clean environment: no CARGO from `cargo test`, and no real cargo on PATH.
    let path = format!("{}:/usr/bin:/bin", work.join("bin").display());
    let text = run_driver(
        &driver,
        &[
            ("PATH", path.as_ref()),
            ("HOME", home.as_os_str()),
            ("LC_ALL", "C".as_ref()),
            ("ORACLE_STUB", stub.as_os_str()),
            ("ORACLE_CASES", cases_file.as_os_str()),
        ],
        &work,
    );
    let (done, calls) = records(&text);
    assert_eq!(done, Some(cases.len()), "the driver did not run every case");
    calls
        .into_iter()
        .map(|(kind, n, sub)| {
            assert!(
                matches!(kind.as_str(), "L" | "N" | "U" | "E"),
                "record {kind:?}"
            );
            (kind.chars().next().unwrap_or('?'), n, sub)
        })
        .collect()
}

/// Subcommands that the real-cargo leg runs: quick on a package without dependencies.
const REAL_SUBCOMMANDS: &[&str] = &[
    "build", "b", "check", "c", "test", "t", "run", "r", "fmt", "help", "version",
];

/// Lines that the real-cargo leg must flag (they write a lockfile) or must not flag.
const REAL_CONTROLS: &[(&str, bool)] = &[
    ("cargo build", true),
    ("cargo run -q x --locked", true),
    ("cargo build --locked", false),
];

/// The number of passed lines that the real-cargo leg runs.
const REAL_SAMPLE: usize = 40;

/// The real cargo, if there is one: `$CARGO` (set by `cargo test`), else `cargo` on PATH.
fn real_cargo() -> Option<PathBuf> {
    std::env::var_os("CARGO")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| find_on_path("cargo"))
}

/// Runs `cases` with real cargo and returns the 1-based cases that wrote `Cargo.lock`.
fn run_with_real_cargo(cargo: &Path, cases: &[&str]) -> HashSet<usize> {
    // Under the target directory, not in a system temp directory.
    let tmp = TempDir::new_in(env!("CARGO_TARGET_TMPDIR")).expect("tempdir");
    let pkg = tmp.path().join("x");
    let home = tmp.path().join("home");
    fs::create_dir_all(pkg.join("src")).expect("mkdir");
    fs::write(
        pkg.join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .expect("write manifest");
    fs::write(pkg.join("src/main.rs"), "fn main() {}\n").expect("write main");
    let wrapper = format!("#!/bin/sh\nexec '{}' \"$@\"\n", cargo.display());
    write_executable(&pkg.join("bin/cargo"), &wrapper);
    write_executable(&home.join(".cargo/bin/cargo"), &wrapper);
    let driver = tmp.path().join("driver.sh");
    fs::write(&driver, REAL_DRIVER).expect("write driver");
    let cases_file = tmp.path().join("cases");
    write_cases(&cases_file, cases);

    let bin_dir = cargo.parent().expect("cargo directory");
    let path = format!("{}:/usr/bin:/bin", bin_dir.display());
    let cargo_home = home.join(".cargo");
    let target = tmp.path().join("target");
    let mut env: Vec<(&str, &OsStr)> = vec![
        ("PATH", path.as_ref()),
        ("HOME", home.as_os_str()),
        ("CARGO_HOME", cargo_home.as_os_str()),
        ("CARGO_TARGET_DIR", target.as_os_str()),
        ("CARGO_NET_OFFLINE", "true".as_ref()),
        ("CARGO_INCREMENTAL", "0".as_ref()),
        ("CARGO_BUILD_JOBS", "2".as_ref()),
        ("LC_ALL", "C".as_ref()),
        ("ORACLE_CASES", cases_file.as_os_str()),
    ];
    // A rustup proxy needs its own home and toolchain.
    let rustup: Vec<(&str, std::ffi::OsString)> = ["RUSTUP_HOME", "RUSTUP_TOOLCHAIN"]
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (*k, v)))
        .collect();
    env.extend(rustup.iter().map(|(k, v)| (*k, v.as_os_str())));
    let text = run_driver(&driver, &env, &pkg);
    let (done, written) = records(&text);
    assert_eq!(
        done,
        Some(cases.len()),
        "the real-cargo driver did not run every case"
    );
    written.into_iter().map(|(_, n, _)| n).collect()
}

#[test]
fn no_generated_run_value_passes_and_runs_cargo_unlocked() {
    let started = Instant::now();
    let cases = cases();
    let passed: Vec<bool> = cases
        .iter()
        .map(|c| ci_checks::locked::check_run(c, &[]).is_empty())
        .collect();
    let refused: Vec<&str> = POSITIVE_SHAPES
        .iter()
        .copied()
        .filter(|line| !ci_checks::locked::check_run(line, &[]).is_empty())
        .collect();
    assert!(refused.is_empty(), "false refusals: {refused:#?}");
    let calls = run_in_bash(&cases);
    let unlocked: HashSet<usize> = calls.iter().filter(|c| c.0 == 'U').map(|c| c.1).collect();
    let ran: HashSet<usize> = calls.iter().map(|c| c.1).collect();

    let false_passes: Vec<&String> = (1..=cases.len())
        .filter(|n| passed[n - 1] && unlocked.contains(n))
        .map(|n| &cases[n - 1])
        .collect();
    let caught = unlocked.iter().filter(|n| !passed[**n - 1]).count();
    let passed_and_ran = ran.iter().filter(|n| passed[**n - 1]).count();
    let pass_count = passed.iter().filter(|p| **p).count();
    eprintln!(
        "oracle: {} cases (seed {SEED:#x}), {pass_count} passed ({passed_and_ran} of them ran \
         cargo), {} ran cargo unlocked ({caught} rejected), {} false passes, {:.1?}",
        cases.len(),
        unlocked.len(),
        false_passes.len(),
        started.elapsed()
    );
    assert!(
        false_passes.is_empty(),
        "the check passed {} run values that ran cargo without --locked, for example:\n{:#?}",
        false_passes.len(),
        &false_passes[..false_passes.len().min(20)]
    );
    // The generator must make both kinds, or the oracle proves nothing.
    assert!(
        unlocked.len() >= 2_000,
        "only {} cases ran cargo unlocked",
        unlocked.len()
    );
    assert!(
        passed_and_ran >= 500,
        "only {passed_and_ran} passed cases ran cargo"
    );

    real_cargo_leg(&cases, &passed, &calls);
}

/// Runs a fixed sample of passed lines, and [`REAL_CONTROLS`], with real cargo.
fn real_cargo_leg(cases: &[String], passed: &[bool], calls: &[(char, usize, String)]) {
    let Some(cargo) = real_cargo() else {
        eprintln!("oracle: real-cargo leg skipped (no cargo on PATH)");
        return;
    };
    let started = Instant::now();
    let quick = |n: usize| {
        let mine: Vec<_> = calls.iter().filter(|c| c.1 == n).collect();
        !mine.is_empty()
            && mine
                .iter()
                .all(|c| REAL_SUBCOMMANDS.contains(&c.2.as_str()))
    };
    let sample: Vec<&str> = (1..=cases.len())
        .filter(|n| passed[n - 1] && quick(*n))
        .take(REAL_SAMPLE)
        .map(|n| cases[n - 1].as_str())
        .collect();
    let mut lines: Vec<&str> = REAL_CONTROLS.iter().map(|c| c.0).collect();
    lines.extend(&sample);
    let written = run_with_real_cargo(&cargo, &lines);
    for (i, (line, writes)) in REAL_CONTROLS.iter().enumerate() {
        assert_eq!(
            written.contains(&(i + 1)),
            *writes,
            "control {line:?}: real cargo did not behave as expected"
        );
    }
    let false_passes: Vec<&str> = (REAL_CONTROLS.len() + 1..=lines.len())
        .filter(|n| written.contains(n))
        .map(|n| lines[n - 1])
        .collect();
    eprintln!(
        "oracle: real cargo ({}) ran {} passed lines and {} controls, {} false passes, {:.1?}",
        cargo.display(),
        sample.len(),
        REAL_CONTROLS.len(),
        false_passes.len(),
        started.elapsed()
    );
    assert!(
        false_passes.is_empty(),
        "real cargo wrote Cargo.lock for lines that the check passed:\n{false_passes:#?}"
    );
    assert!(
        sample.len() >= REAL_SAMPLE / 2,
        "only {} sample lines",
        sample.len()
    );
}

#[test]
fn the_generator_is_deterministic_and_covers_the_issue_shapes() {
    let a = cases();
    assert_eq!(a.len(), CASES);
    assert_eq!(a, cases());
    for shape in ISSUE_SHAPES.iter().chain(POSITIVE_SHAPES) {
        assert!(a.iter().any(|c| c == shape), "{shape:?} is not generated");
    }
}
