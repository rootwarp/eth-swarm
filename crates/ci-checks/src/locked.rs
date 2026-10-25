//! `--locked` gate for the cargo calls in workflow `run:` steps and composite actions, so CI
//! never resolves dependencies past the committed `Cargo.lock` (bench/verify-ipc's own lockfile
//! included).
//!
//! The check does not model shell grammar. It fails closed:
//!
//! 1. The YAML parser reads every `run` and `shell` value: any key form (`run:`, `"run":`,
//!    `'run':`, a flow mapping, an alias, any letter case), at any depth, in every document.
//!    The check reads the decoded scalar, which is the text that the shell gets. A folded (`>`)
//!    block that can run cargo is refused: folding rules for more-indented lines differ between
//!    parsers. A file with U+0085, U+2028, U+2029 or a byte order mark after its start is
//!    refused, because parsers do not agree where its lines end. Two keys of one mapping that
//!    differ only in letter case (or are the same) are refused too.
//! 2. A run value is cut into lines. A line that ends in a backslash joins the next line, as a
//!    continuation does in bash.
//! 3. A line can run cargo if it holds a GitHub expression (`${{`), a NUL, `$'`, `HOME=`, or if
//!    some expansion of it can spell `cargo` (any letter case). For that, quotes and
//!    backslashes are removed, `?` and `[..]` are any one character, and `*` and a brace
//!    expansion (`{a,b}`, `{a..b}`) are any text. An expansion (`$name`, `${..}`, `$(..)`,
//!    backticks) is any text in a word that can be a command word:
//!    - the first word of a command, of a substitution or of a group;
//!    - a word after an assignment, a redirect (and its target) or a keyword, or after a
//!      command word with a quote;
//!    - each word after a wrapper such as `env`, `sudo` or `ssh`, up to the next separator.
//!      Thus `ssh "$HOST" uptime` fails: an expansion in the arguments of ssh can be an option
//!      such as `-oProxyCommand=..`;
//!    - each word after `xargs` or `parallel`, and after `-exec`, `-execdir`, `-ok`, `-okdir`
//!      or an expansion in the arguments of `find`, up to the unquoted end of the command (a
//!      quoted `;` and a `{}` do not end it). An expansion in the arguments of `find` that is
//!      not inside double quotes is a command word itself, so `find "$DIR"/x -name x` passes
//!      and `find $DIR -name x` fails. A double-quoted string includes its `${..}`, `$(..)`
//!      and backtick spans. If the check cannot find the end of such a span, the rest of the
//!      line is quoted.
//!
//!    Elsewhere an expansion is once kept and once removed, but a `${..}` that holds `$(` or a
//!    backtick is any text. The action of a `trap` is read as one more line, so
//!    `trap 'rm -rf "$tmp"' EXIT` passes. If the check cannot read the words of a `trap`, each
//!    later word is a command word. The check reads a double-quoted action only after quote
//!    removal. Thus it does not follow a variable value in that action, which the shell
//!    expands when it sets the trap and reads again as shell text when the trap runs
//!    (`trap "rm -f ${tmp}" EXIT` passes). Other lines are not checked.
//! 4. A line that can run cargo may hold only letters, digits, blanks, `_ . / , : = + ~ @ -`,
//!    the operators `; & && | ||`, `#` comments, and `2>&1` as the last word of a command.
//!    Thus a quote, a backslash, a continuation, `$`, a backtick, a glob, a brace, `<(`, `>(`,
//!    and every other redirect make the line fail. A pipe must go into `tee <file>`. The check
//!    reads the comment text too, because a comment can close a quote that an earlier line
//!    opened.
//! 5. In the text that is left, bash splits words only at blanks and operators, so each word
//!    is known. A word that is `cargo` or ends in `/cargo` (any letter case) is a cargo call
//!    only as the command word (after keywords and assignments), or after `env` (with
//!    assignments), `time`, `nice` or `sudo` without options. A cargo word in any other position
//!    fails (`xargs -I fmt cargo fmt`, `ln -s ../cargo fmt`). Any other word that names cargo
//!    fails, because the check cannot follow it (`x=cargo`, `~/.cargo/bin`), and so does a
//!    `CARGO_ALIAS_<x>`, `CARGO_HOME` or `HOME` word (an assignment or an `export`). An
//!    argument of a cargo call, and an assignment whose value does not name cargo
//!    (`CARGO_INCREMENTAL=0`), are not affected.
//! 6. Each call must name its subcommand after an optional first `+toolchain` and the global
//!    options. A short-option cluster with `C` or `Z` (`-qC dir`) fails, and so does any
//!    `--config` before the subcommand: cargo reads its value as a file if one has that name,
//!    and a key under `alias` or `include` can define an alias. Then:
//!    - subcommands that resolve the lockfile need `--locked` before any `--`:
//!      [`NEEDS_LOCK`]. `cargo run` and `cargo r` give each word after their first positional
//!      argument to the binary, so for them `--locked` must also come before that argument.
//!      For `llvm-cov`, `nextest` and `deny`, `--locked` must come before the nested
//!      subcommand, or after it and before its first positional argument (`llvm-cov run` gives
//!      the words after that argument to the binary). cargo-llvm-cov takes the next word as
//!      the value of an option, also a word that starts with `-`, so a short-option cluster
//!      that can end in such an option (`-vF`) fails;
//!    - [`NO_LOCK`] subcommands, and a call with only [`INFORMATIONAL`] flags, need no lock;
//!    - any other subcommand fails until it is put in one of the lists.
//! 7. A `shell` value is a command template, so it is checked as a line, with `{0}` read as a
//!    plain word, unless it is a bash or sh template.
//! 8. A step whose run value can run cargo must run in bash or sh: its own `shell`, else the
//!    job's `defaults.run.shell`, else the workflow's, else the runner default. The runner
//!    default counts only for a Linux or macOS `runs-on` label without an expression. A composite
//!    action step has no default. A step that uses an action that runs cargo
//!    (`actions-rs/cargo` and similar, or a `docker://` image with cargo in `args` or
//!    `entrypoint`) fails, and so does a Docker action whose `entrypoint`, `pre-entrypoint`,
//!    `post-entrypoint` or `args` can run cargo.
//! 9. A mapping key `CARGO_ALIAS_<x>` (at any depth), or `CARGO_HOME` or `HOME` in an `env`
//!    mapping (at any level) or in a mapping with an anchor (an alias can make it an `env`
//!    mapping), fails. Thus `with: &w {home: /x}` fails, although `with: {home: /x}` passes.
//! 10. In repository mode ([`check_repo`]), the check also reads each local action or
//!     reusable workflow that a `uses: ./<path>` names, nested ones too, and fails if it is
//!     missing or resolves outside the repository. Each `.cargo/config` and
//!     `.cargo/config.toml` of the repository is read as TOML: it must parse, must not
//!     `include` a file, and must not alias a name of [`NO_LOCK`] or [`NEEDS_LOCK`]. In a git
//!     work tree, the check reads:
//!     - each config file and `.cargo` link that git tracks, in submodules too;
//!     - each untracked config file and `.cargo` link that `git ls-files --others` lists,
//!       ignored ones too. That command does not go into an untracked nested repository or
//!       into a submodule, so the untracked files there are not read.
//!
//!     If git does not run, or tracks no file below the root, the check reads every directory
//!     but `.git`. A `.cargo` link must resolve inside the repository.
//!
//! A reviewed [`ALLOW`] entry passes one exact line or `uses:` value of one file. The check does
//! not follow a command name that comes from somewhere else: a variable value that is not in a
//! command word, an `env:` value, command output that is not in a command word, a config file
//! outside the repository, a script that the step runs, or a remote action or reusable
//! workflow (see `steps`).

use crate::Violation;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};
use yaml_rust2::YamlLoader;

mod cargo_config;
mod shell;
mod steps;

/// A reviewed line, or `uses:` value, that the check passes as it is.
#[derive(Debug, Clone, Copy)]
pub struct Allow {
    /// The file of the line, as the end of its path (`.github/workflows/ci.yml`).
    pub file: &'static str,
    /// What the line is.
    pub kind: AllowKind,
    /// The exact line (with its continuations) or `uses:` value, without leading and trailing
    /// blanks.
    pub line: &'static str,
    /// Why the line runs cargo with `--locked`, or runs no cargo.
    pub reason: &'static str,
}

/// What an [`Allow`] entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowKind {
    /// A line of a `run` value, a `shell` value, or a Docker action's `entrypoint` or `args`.
    Run,
    /// A `uses:` value.
    Uses,
}

/// The reviewed allow-list. An entry matches only its file, its kind and its exact line. Each
/// entry needs a reason, and a unit test fails if the line passes without the entry.
pub const ALLOW: &[Allow] = &[Allow {
    // Step "Disk usage".
    file: ".github/workflows/nightly.yml",
    kind: AllowKind::Run,
    line: "du -sh target/spec-vectors/*/* && df -h .",
    reason: "The globs give only arguments to du, and the line has no cargo call. The check \
             refuses it only because a glob can spell cargo.",
}];

/// Subcommands that resolve the lockfile, built-in aliases included.
pub const NEEDS_LOCK: &[&str] = &[
    "build", "b", "test", "t", "clippy", "run", "r", "doc", "d", "bench", "check", "c", "install",
    "nextest", "llvm-cov", "deny",
];

/// Subcommands that read no lockfile.
pub const NO_LOCK: &[&str] = &["fmt", "help", "version"];

/// Flags that make a call without a subcommand print information only.
pub const INFORMATIONAL: &[&str] = &["--version", "-V", "--help", "-h", "--list"];

/// One problem in a run value: the 0-based line of the run value where its command starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub message: String,
}

/// Checks one decoded run value. Each line that can run cargo gives at most one finding. The
/// [`AllowKind::Run`] entries of `allow` apply, whatever their file: the caller selects them.
pub fn check_run(value: &str, allow: &[Allow]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (line, unit) in shell::units(value) {
        let allowed = allow
            .iter()
            .any(|a| a.kind == AllowKind::Run && a.line == unit.trim());
        if !shell::can_run_cargo(&unit) || allowed {
            continue;
        }
        if let Err(problem) = shell::check_unit(&unit) {
            out.push(Finding {
                line,
                message: format!("{problem}: {}", unit.trim().replace('\n', "\\n")),
            });
        }
    }
    out
}

/// Characters after which YAML parsers do not agree where a line ends.
const LINE_BREAKS: &[char] = &['\u{0085}', '\u{2028}', '\u{2029}', '\u{feff}'];

/// Checks one workflow or action file's text. `name` is only used to label violations.
pub fn check_workflow(name: &str, text: &str, allow: &[Allow]) -> Vec<Violation> {
    let error = |line, message| Violation {
        file: name.to_owned(),
        line,
        message,
    };
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    if let Some(i) = body.find(LINE_BREAKS) {
        let line = body[..i].matches('\n').count() + 1;
        return vec![error(
            Some(line),
            "a Unicode line break or byte order mark (U+0085, U+2028, U+2029, U+FEFF): \
             YAML parsers do not agree where its line ends"
                .into(),
        )];
    }
    let allow: Vec<Allow> = allow
        .iter()
        .filter(|a| Path::new(name).ends_with(a.file))
        .copied()
        .collect();
    let allow = allow.as_slice();
    let mut values = Values::default();
    if let Err(e) = Parser::new_from_str(body).load(&mut values, true) {
        return vec![error(None, format!("not valid YAML: {e}"))];
    }
    let mut out = Vec::new();
    for (line, message) in values.key_problems {
        out.push(error(Some(line), message));
    }
    for v in values.found {
        if v.key == Key::Shell {
            if steps::is_bash_or_sh(&v.value) {
                continue;
            }
            for f in check_run(&v.value.replace("{0}", "script"), allow) {
                out.push(error(Some(v.line), format!("shell: {}", f.message)));
            }
            continue;
        }
        if v.style == TScalarStyle::Folded {
            if shell::can_run_cargo(&v.value) {
                out.push(error(
                    Some(v.line),
                    "folded run: scalar can run cargo (use a literal | block)".into(),
                ));
            }
            continue;
        }
        for f in check_run(&v.value, allow) {
            let line = if v.style == TScalarStyle::Literal {
                v.line + 1 + f.line
            } else {
                v.line
            };
            out.push(error(Some(line), f.message));
        }
    }
    match YamlLoader::load_from_str(body) {
        Ok(docs) => {
            for doc in &docs {
                out.extend(
                    steps::check_steps(doc, allow)
                        .into_iter()
                        .map(|m| error(None, m)),
                );
            }
        }
        Err(e) => out.push(error(None, format!("not valid YAML: {e}"))),
    }
    out
}

/// Checks the text of one cargo config file. `name` is only used to label violations.
pub fn check_cargo_config(name: &str, text: &str) -> Vec<Violation> {
    cargo_config::aliases(text)
        .into_iter()
        .map(|message| Violation {
            file: name.to_owned(),
            line: None,
            message,
        })
        .collect()
}

/// Why a scan could not give a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// A path does not exist, or the paths hold no workflow file.
    Nothing(String),
    /// A directory or a file could not be read.
    Unreadable(String),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Nothing(m) | PathError::Unreadable(m) => f.write_str(m),
        }
    }
}

/// What a scan read, and what is wrong.
#[derive(Debug)]
pub struct Scan {
    pub workflow_files: usize,
    pub config_files: usize,
    pub violations: Vec<Violation>,
}

/// Checks each file in `paths`. A directory gives its `*.yml` / `*.yaml` files, and each
/// `action.yml` / `action.yaml` below it (sorted). Violations are labelled with the path as
/// given.
pub fn check_paths(paths: &[PathBuf], allow: &[Allow]) -> Result<Scan, PathError> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_dir() {
            files.extend(yaml_files(path)?);
            files.extend(action_files(path)?);
        } else if path.is_file() {
            files.push(path.clone());
        } else {
            return Err(PathError::Nothing(format!(
                "{}: no such file or directory",
                path.display()
            )));
        }
    }
    if files.is_empty() {
        let names: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        return Err(PathError::Nothing(format!(
            "no workflow files in {}",
            names.join(" ")
        )));
    }
    let mut violations = Vec::new();
    for file in &files {
        let text = read(file)?;
        violations.extend(check_workflow(&file.display().to_string(), &text, allow));
    }
    Ok(Scan {
        workflow_files: files.len(),
        config_files: 0,
        violations,
    })
}

/// Checks a repository: `.github/workflows`, `.github/actions` (if it exists), each local
/// action or workflow that a `uses: ./<path>` names (also from those files), and each
/// `.cargo/config` and `.cargo/config.toml` of the repository. In a git work tree, the files
/// that git tracks and the untracked config files count (rule 10 of the module docs). A local
/// action, or a `.cargo` link, that resolves outside the repository fails.
pub fn check_repo(root: &Path, allow: &[Allow]) -> Result<Scan, PathError> {
    let mut paths = vec![root.join(".github/workflows")];
    let actions = root.join(".github/actions");
    if actions.is_dir() {
        paths.push(actions);
    }
    let mut scan = check_paths(&paths, allow)?;
    let top = root
        .canonicalize()
        .map_err(|e| PathError::Unreadable(format!("{}: {e}", root.display())))?;
    let mut files = Vec::new();
    for path in &paths {
        files.extend(if path.is_dir() {
            let mut all = yaml_files(path)?;
            all.extend(action_files(path)?);
            all
        } else {
            vec![path.clone()]
        });
    }
    let mut seen: HashSet<PathBuf> = files.iter().filter_map(|f| f.canonicalize().ok()).collect();
    while let Some(file) = files.pop() {
        let text = read(&file)?;
        for uses in local_uses(&text) {
            let problem = |message: String| Violation {
                file: file.display().to_string(),
                line: None,
                message,
            };
            match resolve_local(root, &top, &uses) {
                Err(message) => scan.violations.push(problem(message)),
                Ok((label, real)) => {
                    if seen.insert(real) {
                        let text = read(&label)?;
                        scan.violations.extend(check_workflow(
                            &label.display().to_string(),
                            &text,
                            allow,
                        ));
                        scan.workflow_files += 1;
                        files.push(label);
                    }
                }
            }
        }
    }
    let (configs, problems) = cargo_configs(root, &top)?;
    scan.violations.extend(problems);
    for file in &configs {
        let text = read(file)?;
        scan.violations
            .extend(check_cargo_config(&file.display().to_string(), &text));
    }
    scan.config_files = configs.len();
    Ok(scan)
}

/// The local `uses: ./<path>` values of a workflow or action (job and step level).
fn local_uses(text: &str) -> Vec<String> {
    let docs = YamlLoader::load_from_str(text).unwrap_or_default();
    docs.iter()
        .flat_map(steps::uses_values)
        .filter(|u| u.starts_with("./"))
        .collect()
}

/// The file of a local `uses:` value, as `(path to read, real path)`: the workflow file it
/// names, or the `action.yml` / `action.yaml` of its directory.
fn resolve_local(root: &Path, top: &Path, uses: &str) -> Result<(PathBuf, PathBuf), String> {
    let rel = uses.trim_start_matches("./");
    let target = root.join(rel);
    let candidates = if rel.ends_with(".yml") || rel.ends_with(".yaml") {
        vec![target]
    } else {
        vec![target.join("action.yml"), target.join("action.yaml")]
    };
    let Some(file) = candidates.into_iter().find(|c| c.is_file()) else {
        return Err(format!(
            "uses: {uses}: no action.yml or action.yaml (or workflow file) in the repository"
        ));
    };
    let real = file
        .canonicalize()
        .map_err(|e| format!("uses: {uses}: {e}"))?;
    if !real.starts_with(top) {
        return Err(format!("uses: {uses} resolves outside the repository"));
    }
    Ok((file, real))
}

fn read(file: &Path) -> Result<String, PathError> {
    std::fs::read_to_string(file)
        .map_err(|e| PathError::Unreadable(format!("{}: {e}", file.display())))
}

fn entries(dir: &Path) -> Result<Vec<PathBuf>, PathError> {
    let unreadable = |e: std::io::Error| PathError::Unreadable(format!("{}: {e}", dir.display()));
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(unreadable)? {
        out.push(entry.map_err(unreadable)?.path());
    }
    out.sort();
    Ok(out)
}

fn yaml_files(dir: &Path) -> Result<Vec<PathBuf>, PathError> {
    Ok(entries(dir)?
        .into_iter()
        .filter(|p| {
            p.is_file() && matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml"))
        })
        .collect())
}

/// Each `action.yml` / `action.yaml` in the directories below `dir` (not followed through
/// symbolic links).
fn action_files(dir: &Path) -> Result<Vec<PathBuf>, PathError> {
    let mut out = Vec::new();
    for path in entries(dir)? {
        if path.is_symlink() || !path.is_dir() {
            continue;
        }
        for name in ["action.yml", "action.yaml"] {
            let file = path.join(name);
            if file.is_file() {
                out.push(file);
            }
        }
        out.extend(action_files(&path)?);
    }
    Ok(out)
}

/// The cargo config files of the repository, and a problem for each `.cargo` link that
/// resolves outside it. In a git work tree, the paths of [`git_listed`]; else, or if git
/// tracks no file below `root`, every directory but `.git`.
fn cargo_configs(root: &Path, top: &Path) -> Result<(Vec<PathBuf>, Vec<Violation>), PathError> {
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    match git_listed(root) {
        Some(tracked) => {
            for rel in tracked {
                let path = root.join(&rel);
                let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                let parent = rel.parent().and_then(Path::file_name);
                if name == ".cargo" {
                    dirs.push(path);
                } else if parent.is_some_and(|p| p == ".cargo")
                    && matches!(name, "config" | "config.toml")
                {
                    files.push(path);
                }
            }
        }
        None => walk_cargo_dirs(root, &mut dirs)?,
    }
    let mut problems = Vec::new();
    let outside = |path: &Path| Violation {
        file: path.display().to_string(),
        line: None,
        message: "the cargo config resolves outside the repository".into(),
    };
    for dir in dirs {
        if dir.canonicalize().is_ok_and(|real| !real.starts_with(top)) {
            problems.push(outside(&dir));
            continue;
        }
        for name in ["config", "config.toml"] {
            let file = dir.join(name);
            if file.is_file() && !files.contains(&file) {
                files.push(file);
            }
        }
    }
    files.retain(|file| {
        let inside = file.canonicalize().is_ok_and(|real| real.starts_with(top));
        if !inside && file.exists() {
            problems.push(outside(file));
        }
        inside
    });
    files.sort();
    files.dedup();
    Ok((files, problems))
}

/// The paths that git tracks below `root` (submodules included), and the untracked `.cargo`
/// links and `.cargo/config` and `.cargo/config.toml` files (ignored ones too). `git ls-files
/// --others` does not go into an untracked nested repository or into a submodule, so their
/// untracked files are not in the list. `None` if `root` is not in a git work tree, git does
/// not run, or git tracks no file below `root` (the root is ignored or untracked).
fn git_listed(root: &Path) -> Option<Vec<PathBuf>> {
    let mut paths = git_ls_files(root, &["--cached", "--recurse-submodules"])?;
    if paths.is_empty() {
        return None;
    }
    paths.extend(git_ls_files(
        root,
        &[
            "--others",
            "--",
            ":(glob)**/.cargo",
            ":(glob)**/.cargo/config",
            ":(glob)**/.cargo/config.toml",
        ],
    )?);
    Some(paths)
}

/// The paths of `git ls-files -z <args>` in `root`, or `None` if git fails.
fn git_ls_files(root: &Path, args: &[&str]) -> Option<Vec<PathBuf>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    Some(
        text.split('\0')
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .collect(),
    )
}

/// Each `.cargo` directory or link below `dir`, without `.git` directories. A link is not
/// followed further. The walk does not skip a directory with a `CACHEDIR.TAG` or a `.git`
/// file: this walk runs when git cannot list the files (for example, git refuses a checkout
/// that another user owns), and then a committed `CACHEDIR.TAG` could hide a committed config.
fn walk_cargo_dirs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PathError> {
    for path in entries(dir)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == ".cargo" {
            out.push(path.clone());
        }
        if name == ".git" || path.is_symlink() || !path.is_dir() {
            continue;
        }
        walk_cargo_dirs(&path, out)?;
    }
    Ok(())
}

/// The keys whose scalar values the check reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Run,
    Shell,
}

/// One scalar value of a `run` or `shell` key.
struct Value {
    key: Key,
    /// 1-based line of the key. A block scalar starts on the next line.
    line: usize,
    style: TScalarStyle,
    value: String,
}

/// Where the next node sits in its parent collection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Key,
    Value,
    Item,
}

/// A collection that the parser is inside.
enum Open {
    Map {
        expect_key: bool,
        /// The keys so far, in lower case.
        keys: Vec<String>,
        /// The mapping is the value of an `env` key, or has an anchor (an alias can make it
        /// the value of an `env` key).
        env: bool,
    },
    Seq,
}

/// Records each scalar value of a `run` or `shell` key (any letter case), through aliases too,
/// and each key problem: two keys of one mapping that differ only in letter case (or are the
/// same), a `CARGO_ALIAS_` key anywhere, and a `CARGO_HOME` or `HOME` key of an `env` mapping
/// or of a mapping with an anchor.
#[derive(Default)]
struct Values {
    open: Vec<Open>,
    /// The key and its 1-based line, if the last key was `run` or `shell` and its value has
    /// not come yet.
    pending: Option<(Key, usize)>,
    /// The last key, in lower case.
    last_key: Option<String>,
    /// The scalar of each anchor id, or `None` for an anchored collection.
    anchors: HashMap<usize, Option<(String, TScalarStyle)>>,
    found: Vec<Value>,
    key_problems: Vec<(usize, String)>,
}

impl Values {
    fn next_role(&mut self) -> Role {
        match self.open.last_mut() {
            Some(Open::Map { expect_key, .. }) => {
                let role = if *expect_key { Role::Key } else { Role::Value };
                *expect_key = !*expect_key;
                role
            }
            Some(Open::Seq) | None => Role::Item,
        }
    }

    fn key(&mut self, key: &str, line: usize) {
        let lower = key.to_ascii_lowercase();
        if let Some(Open::Map { keys, env, .. }) = self.open.last_mut() {
            if keys.contains(&lower) {
                self.key_problems.push((
                    line,
                    format!(
                        "two keys that differ only in letter case, or are the same ({key:?}): \
                         the check cannot tell which one GitHub reads"
                    ),
                ));
            }
            keys.push(lower.clone());
            let refused = shell::refused_variable(key);
            let alias = lower.starts_with("cargo_alias_");
            if let Some(why) = refused.filter(|_| alias || *env) {
                self.key_problems.push((line, format!("{why} ({key:?})")));
            }
        }
        if lower == "run" {
            self.pending = Some((Key::Run, line));
        } else if lower == "shell" {
            self.pending = Some((Key::Shell, line));
        }
        self.last_key = Some(lower);
    }

    fn node(&mut self, scalar: Option<(String, TScalarStyle)>, mark: Marker) -> Role {
        let role = self.next_role();
        let pending = std::mem::take(&mut self.pending);
        match (role, scalar) {
            (Role::Key, Some((key, _))) => self.key(&key, mark.line()),
            (Role::Key, None) => self.last_key = None,
            (Role::Value, Some((value, style))) => {
                if let Some((key, line)) = pending {
                    self.found.push(Value {
                        key,
                        line,
                        style,
                        value,
                    });
                }
            }
            _ => {}
        }
        role
    }
}

impl MarkedEventReceiver for Values {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::Scalar(value, style, anchor, _) => {
                if anchor != 0 {
                    self.anchors.insert(anchor, Some((value.clone(), style)));
                }
                self.node(Some((value, style)), mark);
            }
            Event::Alias(id) => {
                let scalar = self.anchors.get(&id).cloned().flatten();
                self.node(scalar, mark);
            }
            Event::MappingStart(anchor, _) | Event::SequenceStart(anchor, _) => {
                if anchor != 0 {
                    self.anchors.insert(anchor, None);
                }
                let role = self.node(None, mark);
                // An alias can put an anchored mapping under an `env` key that is not above it.
                let env =
                    anchor != 0 || (role == Role::Value && self.last_key.as_deref() == Some("env"));
                self.open.push(if matches!(ev, Event::MappingStart(..)) {
                    Open::Map {
                        expect_key: true,
                        keys: Vec::new(),
                        env,
                    }
                } else {
                    Open::Seq
                });
            }
            Event::MappingEnd | Event::SequenceEnd => {
                self.open.pop();
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
