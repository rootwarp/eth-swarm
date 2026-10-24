//! The line rules of the `--locked` check (rules 2 to 7 of the module docs of `locked`).

use super::{INFORMATIONAL, NEEDS_LOCK, NO_LOCK};

/// Global options that take their value as the next word.
const VALUED: &[&str] = &[
    "--color",
    "--config",
    "--explain",
    "-Z",
    "-C",
    "--manifest-path",
    "--target-dir",
];

/// Options of `cargo run` that take a value (some of them an optional one) from the next word.
/// The list must hold only options that take a value: an option that is missing here makes the
/// check stricter, because its value then counts as the first positional argument.
const RUN_VALUED: &[&str] = &[
    "-p",
    "--package",
    "--bin",
    "--example",
    "-F",
    "--features",
    "-j",
    "--jobs",
    "--profile",
    "--target",
    "--target-dir",
    "--message-format",
    "--color",
    "--config",
    "-Z",
    "-m",
    "--manifest-path",
    "--lockfile-path",
    "--artifact-dir",
];

/// Subcommands that give each word after their first positional argument to the program that
/// they run (a clap trailing var-arg).
const TRAILING_ARGS: &[&str] = &["run", "r"];

/// External subcommands with nested subcommands, and those nested subcommands. Some nested
/// forms (`llvm-cov run`) give each word after their first positional argument to the binary,
/// so for all of them `--locked` must come before the first positional argument after the
/// nested subcommand.
const NESTED: &[(&str, &[&str])] = &[
    (
        "llvm-cov",
        &[
            "run",
            "test",
            "nextest",
            "nextest-archive",
            "report",
            "clean",
            "show-env",
        ],
    ),
    (
        "nextest",
        &["run", "list", "archive", "show-config", "self"],
    ),
    ("deny", &["check", "fetch", "init", "list"]),
];

/// The lines of a run value, as `(0-based first line, text)`. A line that ends in a backslash
/// (before an optional carriage return) is joined with the next line by a newline.
pub(super) fn units(value: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 0;
    let mut open = false;
    for (i, line) in value.split('\n').enumerate() {
        if open {
            buf.push('\n');
        } else {
            start = i;
        }
        buf.push_str(line);
        open = line.trim_end_matches('\r').ends_with('\\');
        if !open {
            out.push((start, std::mem::take(&mut buf)));
        }
    }
    if open {
        out.push((start, buf));
    }
    out
}

/// True if `text` can run cargo (rule 3 of the module docs).
pub(super) fn can_run_cargo(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("${{")
        || lower.contains('\0')
        || lower.contains("$'")
        || lower.contains("home=")
    {
        return true;
    }
    let raw: Vec<char> = lower.chars().collect();
    let in_command = command_words(&raw);
    let (kept, flags): (Vec<char>, Vec<bool>) = raw
        .iter()
        .zip(&in_command)
        .filter(|(c, _)| !matches!(c, '"' | '\'' | '\\' | '\n' | '\r'))
        .map(|(c, f)| (*c, *f))
        .unzip();
    can_spell_cargo(&pattern(&kept, &flags, true))
        || can_spell_cargo(&pattern(&kept, &flags, false))
}

/// Words after which the next word is a command word.
const KEYWORDS: &[&str] = &["if", "then", "else", "elif", "do", "while", "until", "!"];

/// Commands that can run their arguments as a command.
const WRAPPERS: &[&str] = &[
    "env", "exec", "command", "builtin", "eval", "xargs", "nice", "sudo", "doas", "nohup",
    "timeout", "time", "stdbuf", "setsid", "ionice", "flock", "bash", "sh", "dash", "zsh", "ksh",
    "su", "watch", "chroot",
];

/// A character that ends a word and starts a new command (or a substitution) after it.
fn is_separator(c: char) -> bool {
    matches!(c, ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`' | '\n')
}

/// For each character of `raw`, true if its word can be a command word. This over-estimates:
/// the first word of a command, of a substitution or of a group; a word after an assignment, a
/// keyword or a command word with a quote or a backslash (the real word ends are unknown); and
/// each word after a wrapper such as `env` or `xargs`.
fn command_words(raw: &[char]) -> Vec<bool> {
    let mut out = vec![false; raw.len()];
    let mut next_is_command = true;
    let mut after_wrapper = false;
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if is_separator(c) {
            next_is_command = true;
            after_wrapper = false;
            i += 1;
            continue;
        }
        if c == ' ' || c == '\t' {
            i += 1;
            continue;
        }
        let start = i;
        while i < raw.len() && !matches!(raw[i], ' ' | '\t') && !is_separator(raw[i]) {
            // `${..}` is part of the word, not a group.
            i = if raw[i] == '$' && raw.get(i + 1) == Some(&'{') {
                after_group(raw, i + 1, '{', '}')
            } else {
                i + 1
            };
        }
        let word: String = raw[start..i].iter().collect();
        let is_command = next_is_command || after_wrapper;
        let bare: String = word
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | '\\'))
            .collect();
        let assignment = is_command && is_assignment(&bare);
        // The value of an assignment is not a command word.
        if is_command && !assignment {
            out[start..i].fill(true);
        }
        let unclear = is_command && word.contains(['"', '\'', '\\']);
        next_is_command = unclear || assignment || KEYWORDS.contains(&bare.as_str());
        if is_command && WRAPPERS.contains(&bare.as_str()) {
            after_wrapper = true;
        }
    }
    out
}

/// `NAME=...` with a shell identifier as the name.
fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One part of the text as bash can expand it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Part {
    Char(char),
    /// One unknown character: `?`, a `[..]` class.
    One,
    /// Any text: `*`, a brace expansion with `,` or `..`.
    Any,
}

/// `c` as parts. An expansion (`$name`, `${..}`, `$(..)`, a backtick span) in a word that can
/// be a command word (`in_command`) is any text. Elsewhere, with `keep_expansions` it stays as
/// its characters, and without it, it is empty, so that `car${x}go` shows the name.
fn pattern(c: &[char], in_command: &[bool], keep_expansions: bool) -> Vec<Part> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let expansion = matches!(c[i], '$' | '`');
        if expansion && in_command[i] {
            out.push(Part::Any);
        }
        let keep = keep_expansions && !in_command[i];
        match c[i] {
            '$' if keep => {
                out.push(Part::Char('$'));
                i += 1;
                if c.get(i) == Some(&'{') {
                    // A parameter expansion, not a brace expansion: keep its characters.
                    let end = after_group(c, i, '{', '}');
                    out.extend(c[i..end].iter().map(|ch| Part::Char(*ch)));
                    i = end;
                }
            }
            '$' => {
                i += 1;
                match c.get(i) {
                    Some('{') => i = after_group(c, i, '{', '}'),
                    Some('(') => i = after_group(c, i, '(', ')'),
                    Some(&ch) if ch.is_ascii_alphabetic() || ch == '_' => {
                        while c
                            .get(i)
                            .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                        {
                            i += 1;
                        }
                    }
                    Some(&ch) if ch.is_ascii_digit() || "@*#?-$!".contains(ch) => i += 1,
                    _ => {}
                }
            }
            '`' if !keep => {
                i += 1;
                while c.get(i).is_some_and(|ch| *ch != '`') {
                    i += 1;
                }
                i += 1;
            }
            '?' => {
                out.push(Part::One);
                i += 1;
            }
            '*' => {
                out.push(Part::Any);
                i += 1;
            }
            '[' => match c[i + 1..].iter().position(|ch| *ch == ']') {
                Some(len) => {
                    out.push(Part::One);
                    i += len + 2;
                }
                None => {
                    out.push(Part::Char('['));
                    i += 1;
                }
            },
            '{' => {
                let end = after_group(c, i, '{', '}');
                let body: String = c[i..end].iter().collect();
                if body.contains(',') || body.contains("..") {
                    out.push(Part::Any);
                    i = end;
                } else {
                    out.push(Part::Char('{'));
                    i += 1;
                }
            }
            ch => {
                out.push(Part::Char(ch));
                i += 1;
            }
        }
    }
    out
}

/// True if some expansion of `parts` holds the text `cargo`.
fn can_spell_cargo(parts: &[Part]) -> bool {
    const TARGET: &[char] = &['c', 'a', 'r', 'g', 'o'];
    // `matched[k]`: the parts so far can end with the first `k` letters of the target.
    let mut matched = [false; 6];
    for part in parts {
        matched[0] = true;
        let mut next = [false; 6];
        for k in 0..TARGET.len() {
            if !matched[k] {
                continue;
            }
            match part {
                Part::Char(ch) if *ch == TARGET[k] => next[k + 1] = true,
                Part::Char(_) => {}
                Part::One => next[k + 1] = true,
                Part::Any => next[k..].iter_mut().for_each(|m| *m = true),
            }
        }
        if next[TARGET.len()] {
            return true;
        }
        matched = next;
    }
    false
}

/// The index after the `close` that matches the `open` at `c[at]` (or the end).
fn after_group(c: &[char], at: usize, open: char, close: char) -> usize {
    let mut depth = 0usize;
    for (i, ch) in c.iter().enumerate().skip(at) {
        if *ch == open {
            depth += 1;
        } else if *ch == close {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
    }
    c.len()
}

/// Checks one line that can run cargo (rules 4 to 7 of the module docs).
pub(super) fn check_unit(unit: &str) -> Result<(), String> {
    if let Some(shape) = unsafe_shape(unit) {
        return Err(format!("{shape} on a line that can run cargo"));
    }
    for cmd in commands(unit) {
        cmd.check()?;
    }
    Ok(())
}

fn is_plain(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            ' ' | '\t' | '_' | '.' | '/' | ',' | ':' | '=' | '+' | '~' | '@' | '-'
        )
}

/// A character after which bash starts a new word.
fn is_boundary(c: char) -> bool {
    matches!(c, ' ' | '\t' | ';' | '&' | '|')
}

/// The first construct of `unit` that rule 4 refuses, comments included.
fn unsafe_shape(unit: &str) -> Option<String> {
    let trimmed = unit.trim_end_matches('\r');
    if unit.contains("\\\n") || trimmed.ends_with('\\') {
        return Some("a line continuation".into());
    }
    let c: Vec<char> = unit.chars().collect();
    let at = |i: usize| c.get(i).copied();
    for (i, &ch) in c.iter().enumerate() {
        let shape = match ch {
            _ if is_plain(ch) => continue,
            '#' | ';' | '&' => continue,
            '|' if at(i + 1) == Some('&') => "a redirect (|&)",
            '|' => continue,
            '>' | '<' if at(i + 1) == Some('(') => "a process substitution (<( or >()",
            '>' if is_stderr_dup(&c, i) => continue,
            '>' | '<' => "a redirect other than a trailing 2>&1",
            '"' | '\'' => "a quote",
            '\\' => "a backslash",
            '`' => "a command substitution ($( or a backtick)",
            '$' if at(i + 1) == Some('(') => "a command substitution ($( or a backtick)",
            '$' if at(i + 1) == Some('{') && at(i + 2) == Some('{') => "a GitHub expression (${{)",
            '$' => "a parameter expansion ($)",
            other => return Some(format!("the character {other:?}")),
        };
        return Some(shape.into());
    }
    None
}

/// True if the `>` at `c[i]` is in a `2>&1` word that stands alone: a `2` at a word start
/// before it, and `&1` and a word end after it.
fn is_stderr_dup(c: &[char], i: usize) -> bool {
    let two_starts_word = i >= 1 && c[i - 1] == '2' && (i < 2 || is_boundary(c[i - 2]));
    let dup_one = c.get(i + 1) == Some(&'&') && c.get(i + 2) == Some(&'1');
    let word_ends = c.get(i + 3).is_none_or(|ch| is_boundary(*ch));
    two_starts_word && dup_one && word_ends
}

/// One simple command of a checked line.
#[derive(Default)]
struct SimpleCommand {
    /// The command is on the right side of a `|`.
    after_pipe: bool,
    words: Vec<String>,
    /// The command has a `2>&1`.
    stderr_dup: bool,
    /// A word comes after the `2>&1`.
    word_after_dup: bool,
}

/// Splits a line that [`unsafe_shape`] passed into simple commands, and drops its comment.
fn commands(unit: &str) -> Vec<SimpleCommand> {
    let c: Vec<char> = unit.chars().collect();
    let mut cmds = vec![SimpleCommand::default()];
    let mut word = String::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let cur = cmds.last_mut().expect("one command at least");
        match ch {
            '#' if word.is_empty() => break,
            ' ' | '\t' => cur.push_word(&mut word),
            '>' => {
                // `unsafe_shape` passed only a standalone `2>&1`.
                word.clear();
                if cur.stderr_dup {
                    cur.word_after_dup = true;
                }
                cur.stderr_dup = true;
                i += 2;
            }
            ';' | '&' | '|' => {
                cur.push_word(&mut word);
                let doubled = c.get(i + 1) == Some(&ch) && ch != ';';
                if doubled {
                    i += 1;
                }
                cmds.push(SimpleCommand {
                    after_pipe: ch == '|' && !doubled,
                    ..SimpleCommand::default()
                });
            }
            _ => word.push(ch),
        }
        i += 1;
    }
    cmds.last_mut()
        .expect("one command at least")
        .push_word(&mut word);
    cmds
}

fn names_cargo(word: &str) -> bool {
    word.to_ascii_lowercase().contains("cargo")
}

fn is_cargo_call(word: &str) -> bool {
    let w = word.to_ascii_lowercase();
    w == "cargo" || w.ends_with("/cargo")
}

/// Why an environment variable named by `word` (`NAME` or `NAME=VALUE`, any letter case) can
/// change what a cargo call does, if it can: `CARGO_ALIAS_<x>` defines an alias, and
/// `CARGO_HOME` or `HOME` moves the cargo config that cargo reads.
pub(super) fn refused_variable(word: &str) -> Option<&'static str> {
    let name = word
        .split('=')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if name.starts_with("CARGO_ALIAS_") {
        Some("a CARGO_ALIAS_ variable can turn a cargo call into another one")
    } else if name == "CARGO_HOME" || name == "HOME" {
        Some("CARGO_HOME or HOME moves the cargo config that cargo reads")
    } else {
        None
    }
}

/// Commands before a cargo word that the check reads: `env` (with assignments, no options),
/// `time`, `nice` and `sudo` (without options).
const CALL_PREFIXES: &[&str] = &["env", "time", "nice", "sudo"];

/// Shell keywords that can come before a command word.
const COMMAND_KEYWORDS: &[&str] = &["if", "then", "else", "elif", "do", "while", "until"];

/// `NAME=VALUE` with a shell identifier as the name and no cargo in the value.
fn is_plain_assignment(word: &str) -> bool {
    let Some((name, value)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    let ident = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    ident && !names_cargo(value)
}

impl SimpleCommand {
    fn push_word(&mut self, word: &mut String) {
        if word.is_empty() {
            return;
        }
        if self.stderr_dup {
            self.word_after_dup = true;
        }
        self.words.push(std::mem::take(word));
    }

    fn check(&self) -> Result<(), String> {
        if self.word_after_dup {
            return Err("2>&1 must end its command".into());
        }
        if self.after_pipe {
            let tee =
                matches!(self.words.as_slice(), [t, file] if t == "tee" && !file.starts_with('-'));
            if !tee {
                return Err("a pipe into a command other than `tee <file>`".into());
            }
        }
        let call = self.call_position();
        for (i, word) in self.words.iter().enumerate() {
            if Some(i) == call {
                return check_call(&self.words[i + 1..]).and_then(|()| {
                    match self.words[i + 1..].iter().find(|w| is_cargo_call(w)) {
                        Some(w) => Err(not_a_command_word(w)),
                        None => Ok(()),
                    }
                });
            }
            if is_cargo_call(word) {
                return Err(not_a_command_word(word));
            }
            if let Some(why) = refused_variable(word) {
                return Err(format!("{why} ({word:?})"));
            }
            if names_cargo(word) && !is_plain_assignment(word) {
                return Err(format!(
                    "a word that names cargo but is not a cargo call ({word:?})"
                ));
            }
        }
        Ok(())
    }

    /// The index of the cargo word that this command runs: after keywords and assignments,
    /// the command word itself, or the word after one of [`CALL_PREFIXES`].
    fn call_position(&self) -> Option<usize> {
        let w = &self.words;
        let mut i = 0;
        while w
            .get(i)
            .is_some_and(|x| COMMAND_KEYWORDS.contains(&x.as_str()))
        {
            i += 1;
        }
        while w.get(i).is_some_and(|x| is_assignment(x)) {
            i += 1;
        }
        let first = w.get(i)?;
        if is_cargo_call(first) {
            return Some(i);
        }
        if !CALL_PREFIXES.contains(&first.as_str()) {
            return None;
        }
        i += 1;
        if first == "env" {
            while w.get(i).is_some_and(|x| is_assignment(x)) {
                i += 1;
            }
        }
        w.get(i).filter(|x| is_cargo_call(x)).map(|_| i)
    }
}

fn not_a_command_word(word: &str) -> String {
    format!(
        "a cargo word not in a command position ({word:?}): the check reads only `cargo ..`, \
         or `env`, `time`, `nice` or `sudo` without options before it"
    )
}

/// Checks the arguments of one cargo call (rule 6 of the module docs).
fn check_call(args: &[String]) -> Result<(), String> {
    let mut locked = false;
    let mut informational = false;
    // rustup takes `+toolchain` only as the first argument. Later, cargo reads it as a
    // subcommand.
    let mut j = usize::from(args.first().is_some_and(|a| a.starts_with('+')));
    while j < args.len() {
        let arg = args[j].as_str();
        if arg == "--" {
            break;
        }
        if !arg.starts_with('-') {
            return check_subcommand(arg, locked, &args[j + 1..]);
        }
        let short_cluster = !arg.starts_with("--") && arg.len() > 2;
        if short_cluster && arg.contains(['C', 'Z']) {
            return Err(format!(
                "a short-option cluster with -C or -Z ({arg:?}): write -C or -Z as its own word"
            ));
        }
        if arg == "--config" {
            check_config_value(args.get(j + 1).map(String::as_str))?;
        } else if let Some(value) = arg.strip_prefix("--config=") {
            check_config_value(Some(value))?;
        }
        locked |= arg == "--locked";
        informational |= INFORMATIONAL.contains(&arg);
        if VALUED.contains(&arg) {
            j += 1;
        }
        j += 1;
    }
    if informational {
        Ok(())
    } else {
        Err("cargo without a visible subcommand".into())
    }
}

/// A `--config` before the subcommand can define an alias, through a key under `alias`, an
/// `include`, or a file: cargo reads the value as a file if one has that name (`a=1` too).
fn check_config_value(value: Option<&str>) -> Result<(), String> {
    Err(format!(
        "--config {:?} before the subcommand can load a file or define an alias \
         (put it after the subcommand)",
        value.unwrap_or_default()
    ))
}

fn check_subcommand(sub: &str, locked: bool, rest: &[String]) -> Result<(), String> {
    if NO_LOCK.contains(&sub) {
        return Ok(());
    }
    if !NEEDS_LOCK.contains(&sub) {
        return Err(format!(
            "unknown cargo subcommand {sub:?} (classify it in crates/ci-checks/src/locked.rs)"
        ));
    }
    let nested = NESTED
        .iter()
        .find(|(name, _)| *name == sub)
        .map(|(_, n)| *n);
    let locked = locked
        || if TRAILING_ARGS.contains(&sub) {
            locked_before_positional(rest)
        } else if let Some(nested) = nested {
            locked_in_nested(nested, rest)
        } else {
            rest.iter()
                .take_while(|a| a.as_str() != "--")
                .any(|a| a == "--locked")
        };
    if locked {
        Ok(())
    } else {
        Err(format!("cargo {sub} without --locked"))
    }
}

/// True if `--locked` comes before the nested subcommand, or after it and before `--` and the
/// first positional argument. A first positional argument that is not in `nested` fails.
fn locked_in_nested(nested: &[&str], rest: &[String]) -> bool {
    let mut j = 0;
    while j < rest.len() {
        let arg = rest[j].as_str();
        if arg == "--locked" {
            return true;
        }
        if arg == "--" {
            return false;
        }
        if !arg.starts_with('-') {
            return nested.contains(&arg) && locked_before_positional(&rest[j + 1..]);
        }
        let takes_next =
            RUN_VALUED.contains(&arg) && rest.get(j + 1).is_some_and(|next| !next.starts_with('-'));
        j += if takes_next { 2 } else { 1 };
    }
    false
}

/// True if `--locked` comes before `--` and before the first positional argument, after which
/// `cargo run` gives each word to the binary.
fn locked_before_positional(rest: &[String]) -> bool {
    let mut j = 0;
    while j < rest.len() {
        let arg = rest[j].as_str();
        if arg == "--" || !arg.starts_with('-') {
            return false;
        }
        if arg == "--locked" {
            return true;
        }
        let takes_next =
            RUN_VALUED.contains(&arg) && rest.get(j + 1).is_some_and(|next| !next.starts_with('-'));
        j += if takes_next { 2 } else { 1 };
    }
    false
}
