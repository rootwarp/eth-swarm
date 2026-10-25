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

/// Options of cargo-llvm-cov 0.9 that take a value (from `cargo llvm-cov --help`, `run --help`
/// and `report --help`). cargo-llvm-cov reads its arguments with lexopt, which takes the next
/// word as the value, also a word that starts with `-`. Only options that take a value can be
/// in the list.
const LLVM_COV_VALUED: &[&str] = &[
    "--output-path",
    "--output-dir",
    "--failure-mode",
    "--ignore-filename-regex",
    "--fail-under-functions",
    "--fail-under-lines",
    "--fail-under-file-lines",
    "--fail-under-regions",
    "--fail-uncovered-lines",
    "--fail-uncovered-regions",
    "--fail-uncovered-functions",
    "--dep-coverage",
    "--nextest-archive-file",
    "--archive-file",
    "--cargo-profile",
    "--bin",
    "--example",
    "--test",
    "--bench",
    "-p",
    "--package",
    "--exclude",
    "--exclude-from-test",
    "--exclude-from-report",
    "-j",
    "--jobs",
    "--profile",
    "-F",
    "--features",
    "--target",
    "--color",
    "-m",
    "--manifest-path",
    "-Z",
];

/// How a subcommand reads the options that take a value from the next word.
#[derive(Clone, Copy)]
struct Options {
    /// Options that take the next word as the value, also if it starts with `-` (lexopt).
    lexopt: &'static [&'static str],
    /// Options that take the next word as the value if it does not start with `-` (clap).
    clap: &'static [&'static str],
    /// The letters of the short options in `lexopt`. A short-option cluster whose first such
    /// letter is its last character takes the next word as the value, and it fails.
    valued_letters: &'static [char],
    /// The options after a nested `nextest` or `nextest-archive` subcommand.
    nextest: Option<&'static Options>,
}

/// `cargo run` and the other subcommands that clap reads.
const CLAP: Options = Options {
    lexopt: &[],
    clap: RUN_VALUED,
    valued_letters: &[],
    nextest: None,
};

/// `cargo llvm-cov`.
const LLVM_COV: Options = Options {
    lexopt: LLVM_COV_VALUED,
    clap: &[],
    valued_letters: &['p', 'j', 'F', 'Z', 'm'],
    nextest: Some(&LLVM_COV_NEXTEST),
};

/// `cargo llvm-cov nextest` and `nextest-archive`. cargo-llvm-cov gives the options that it
/// does not know to cargo-nextest, which reads them with clap.
const LLVM_COV_NEXTEST: Options = Options {
    lexopt: LLVM_COV_VALUED,
    clap: RUN_VALUED,
    valued_letters: &['p', 'j', 'F', 'Z', 'm'],
    nextest: None,
};

/// Where the check found `--locked` in the arguments after a subcommand.
#[derive(Debug, PartialEq, Eq)]
enum Lock {
    /// Where the subcommand reads it.
    Read,
    /// Not before `--`.
    Missing,
    /// Only after the first positional argument.
    AfterPositional,
    /// Only as the value of this option.
    Value(String),
    /// After this short-option cluster, which can take the next word as its value.
    Cluster(String),
}

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
    let scan = command_words(&raw);
    if scan.actions.iter().any(|action| can_run_cargo(action)) {
        return true;
    }
    let (kept, flags): (Vec<char>, Vec<bool>) = raw
        .iter()
        .zip(&scan.in_command)
        .filter(|(c, _)| !matches!(c, '"' | '\'' | '\\' | '\n' | '\r'))
        .map(|(c, f)| (*c, *f))
        .unzip();
    can_spell_cargo(&pattern(&kept, &flags, true))
        || can_spell_cargo(&pattern(&kept, &flags, false))
}

/// Words after which the next word is a command word.
const KEYWORDS: &[&str] = &["if", "then", "else", "elif", "do", "while", "until", "!"];

/// Commands that can run their arguments as a command: each later word of the command is a
/// command word, up to the next separator.
const WRAPPERS: &[&str] = &[
    "env",
    "exec",
    "command",
    "builtin",
    "eval",
    "nice",
    "sudo",
    "doas",
    "nohup",
    "timeout",
    "time",
    "stdbuf",
    "setsid",
    "ionice",
    "flock",
    "bash",
    "sh",
    "dash",
    "zsh",
    "ksh",
    "su",
    "watch",
    "chroot",
    "coproc",
    "script",
    // An expansion in the arguments of ssh can be an option such as `-oProxyCommand=..`.
    "ssh",
    "taskset",
    "unshare",
    "systemd-run",
    "chrt",
    "nsenter",
    "runuser",
    "strace",
    "fakeroot",
    "unbuffer",
    "busybox",
];

/// Commands whose arguments hold a command after a quoted `;` or a `{}`: each later word is a
/// command word, up to the unquoted end of the command.
const STICKY_WRAPPERS: &[&str] = &["xargs", "parallel"];

/// The primaries of find after which find runs the next words as a command.
const FIND_EXEC: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// A character that ends a word and starts a new command (or a substitution) after it.
fn is_separator(c: char) -> bool {
    matches!(c, ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`' | '\n')
}

/// What [`command_words`] found.
struct Scan {
    /// For each character, true if its word can be a command word.
    in_command: Vec<bool>,
    /// The action of each `trap`, as the command line that the shell runs later.
    actions: Vec<String>,
}

/// For each character of `raw`, true if its word can be a command word. This over-estimates:
/// the first word of a command, of a substitution or of a group; a word after an assignment, a
/// redirect (and its target), a keyword or a command word with a quote or a backslash (the real
/// word ends are unknown); each word after a wrapper such as `env`; and each word after
/// `xargs`, `parallel` or a `find -exec` up to the unquoted end of the command. The action of
/// a `trap` goes into [`Scan::actions`].
fn command_words(raw: &[char]) -> Scan {
    let quoted = quoted_chars(raw);
    let mut out = vec![false; raw.len()];
    let mut actions = Vec::new();
    let mut next_is_command = true;
    let mut after_wrapper = false;
    // The last word was a redirect operator without its target (`>`, `2>`, `<<<`).
    let mut target_next = false;
    // The nesting depth of substitutions and subshells, and the depth of the open find
    // command and of the open sticky wrapper.
    let mut depth = 0usize;
    let mut in_backtick = false;
    let mut find: Option<usize> = None;
    let mut sticky: Option<usize> = None;
    let mut i = 0;
    while i < raw.len() {
        let c = raw[i];
        if is_separator(c) {
            next_is_command = true;
            after_wrapper = false;
            target_next = false;
            if !quoted[i] {
                match c {
                    '(' => depth += 1,
                    ')' => depth = depth.saturating_sub(1),
                    '`' if in_backtick => {
                        in_backtick = false;
                        depth = depth.saturating_sub(1);
                    }
                    '`' => {
                        in_backtick = true;
                        depth += 1;
                    }
                    _ => {}
                }
                let ends = |open: usize| {
                    depth < open || (depth == open && matches!(c, ';' | '&' | '|' | '\n'))
                };
                if find.is_some_and(ends) {
                    find = None;
                }
                if sticky.is_some_and(ends) {
                    sticky = None;
                }
            }
            i += 1;
            continue;
        }
        if c == ' ' || c == '\t' {
            i += 1;
            continue;
        }
        let start = i;
        while i < raw.len()
            && !matches!(raw[i], ' ' | '\t')
            && (!is_separator(raw[i]) || in_redirect_operator(raw, start, i))
        {
            // `${..}` is part of the word, not a group.
            i = if raw[i] == '$' && raw.get(i + 1) == Some(&'{') {
                after_group(raw, i + 1, '{', '}')
            } else {
                i + 1
            };
        }
        let word: String = raw[start..i].iter().collect();
        let is_command = next_is_command || after_wrapper || sticky.is_some();
        let bare: String = word
            .chars()
            .filter(|c| !matches!(c, '"' | '\'' | '\\'))
            .collect();
        // Bash reads an assignment or a redirect only from unquoted text, so the raw word
        // decides. A quoted name or operator is part of the command word.
        let assignment = is_command && is_assignment(&word);
        let target = is_command && std::mem::take(&mut target_next);
        let operator = redirect_operator(&word);
        let redirect = is_command && operator.is_some();
        // In the arguments of find, an expansion can be `-exec`. An unquoted one can also hold
        // the command.
        let find_exec = find.is_some()
            && sticky.is_none()
            && (FIND_EXEC.contains(&bare.as_str()) || word.contains(['$', '`']));
        let find_command =
            find_exec && word.contains(['$', '`']) && !expansions_in_double_quotes(&word);
        // The value of an assignment, a redirect and its target are not command words.
        if (is_command && !assignment && !redirect && !target) || find_command {
            out[start..i].fill(true);
        }
        target_next = redirect && operator == Some(true);
        let unclear = is_command && word.contains(['"', '\'', '\\']);
        next_is_command =
            unclear || assignment || redirect || target || KEYWORDS.contains(&bare.as_str());
        if is_command && WRAPPERS.contains(&bare.as_str()) {
            after_wrapper = true;
        }
        if (is_command && STICKY_WRAPPERS.contains(&bare.as_str())) || find_exec {
            sticky.get_or_insert(depth);
        }
        if is_command && bare == "find" {
            find.get_or_insert(depth);
        }
        if is_command && bare == "trap" {
            match trap_action(raw, i) {
                Some(action) => actions.extend(action),
                None => after_wrapper = true,
            }
        }
    }
    Scan {
        in_command: out,
        actions,
    }
}

/// True if each `$` of `word` is inside double quotes and the word has no command
/// substitution (`"$dir"/x`), so that bash gives it as one argument.
fn expansions_in_double_quotes(word: &str) -> bool {
    let c: Vec<char> = word.chars().collect();
    let mut in_double = false;
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\\' => i += 2,
            '\'' if !in_double => match c[i + 1..].iter().position(|x| *x == '\'') {
                Some(len) => i += len + 2,
                None => return false,
            },
            '"' => {
                in_double = !in_double;
                i += 1;
            }
            '`' => return false,
            '$' if c.get(i + 1) == Some(&'(') || !in_double => return false,
            _ => i += 1,
        }
    }
    !in_double
}

/// For each character of `raw`, true if bash can read it as quoted: in quotes, after a
/// backslash, or a quote or a backslash itself. A double-quoted string includes each
/// `${..}`, `$(..)` and backtick span in it. If the check cannot find the end of a quoted
/// string, the rest of the text is quoted.
fn quoted_chars(raw: &[char]) -> Vec<bool> {
    let mut out = vec![false; raw.len()];
    let mut i = 0;
    while i < raw.len() {
        let end = match raw[i] {
            '\\' => (i + 2).min(raw.len()),
            '\'' => raw[i + 1..]
                .iter()
                .position(|c| *c == '\'')
                .map_or(raw.len(), |p| i + p + 2),
            '"' => after_double_quotes(raw, i).unwrap_or(raw.len()),
            _ => {
                i += 1;
                continue;
            }
        };
        out[i..end].fill(true);
        i = end;
    }
    out
}

/// True if a `$(..)`, a `${..}` or a backtick span starts at `raw[at]`.
fn starts_span(raw: &[char], at: usize) -> bool {
    raw[at] == '`' || (raw[at] == '$' && matches!(raw.get(at + 1), Some('(' | '{')))
}

/// The index after the double-quoted string whose `"` is at `raw[at]`, or `None` if the check
/// cannot find its end.
fn after_double_quotes(raw: &[char], at: usize) -> Option<usize> {
    let mut j = at + 1;
    loop {
        match *raw.get(j)? {
            '\\' => j += 2,
            '"' => return Some(j + 1),
            _ if starts_span(raw, j) => j = after_span(raw, j)?,
            _ => j += 1,
        }
    }
}

/// The index after the `$(..)`, `${..}` or backtick span at `raw[at]`, with the quotes and the
/// spans in it, or `None` if the check cannot find its end. The check does not read a
/// here-document or a `case` in a `$(..)`, nor a single quote in a `${..}`, because bash can
/// read a `)` or a `'` there in more than one way.
fn after_span(raw: &[char], at: usize) -> Option<usize> {
    if raw[at] == '`' {
        let mut j = at + 1;
        loop {
            match *raw.get(j)? {
                '\\' => j += 2,
                '`' => return Some(j + 1),
                _ => j += 1,
            }
        }
    }
    let (open, close) = if raw.get(at + 1) == Some(&'(') {
        ('(', ')')
    } else {
        ('{', '}')
    };
    let mut depth = 0usize;
    let mut j = at + 1;
    loop {
        let c = *raw.get(j)?;
        match c {
            '\\' => j += 2,
            '\'' if open == '{' => return None,
            '\'' => j += raw[j + 1..].iter().position(|c| *c == '\'')? + 2,
            '"' => j = after_double_quotes(raw, j)?,
            '<' if open == '(' && raw.get(j + 1) == Some(&'<') => return None,
            _ if starts_span(raw, j) => j = after_span(raw, j)?,
            _ if c == open => {
                depth += 1;
                j += 1;
            }
            _ if c == close => {
                depth -= 1;
                j += 1;
                if depth == 0 {
                    let body: String = raw[at..j].iter().collect();
                    return (!body.contains("case")).then_some(j);
                }
            }
            _ => j += 1,
        }
    }
}

/// The action of the `trap` command whose arguments start at `raw[at]`, as the text that the
/// shell runs later: `Some(None)` if it has none, and `None` if the check cannot read its words.
fn trap_action(raw: &[char], at: usize) -> Option<Option<String>> {
    let mut i = at;
    let mut options = true;
    loop {
        let Some((end, word)) = shell_word(raw, i)? else {
            return Some(None);
        };
        i = end;
        if options && word == "--" {
            options = false;
        } else if options && word.len() > 1 && word.starts_with('-') {
            // `-p`, `-l` or `-P`: no action.
        } else {
            return Some(Some(word));
        }
    }
}

/// The next word of the command at `raw[at]`, after blanks, as `(end, the text after quote
/// removal)`: `Some(None)` at the end of the command, and `None` if the check cannot read the
/// word (a substitution, a redirect, a continuation, an open quote, or a `${..}` with a quote
/// or a substitution in it).
fn shell_word(raw: &[char], at: usize) -> Option<Option<(usize, String)>> {
    let mut i = at;
    while matches!(raw.get(i), Some(' ' | '\t')) {
        i += 1;
    }
    let ends = |c: char| matches!(c, ' ' | '\t' | ';' | '&' | '|' | '(' | ')' | '\n');
    if raw.get(i).is_none_or(|c| ends(*c)) {
        return Some(None);
    }
    let mut word = String::new();
    // Appends the `${..}` at `raw[j]` and returns the index after it.
    let parameter = |j: usize, word: &mut String| -> Option<usize> {
        let end = after_group(raw, j + 1, '{', '}');
        let body = &raw[j..end];
        if body.iter().any(|c| matches!(c, '"' | '\'' | '`' | '(')) || end > raw.len() {
            return None;
        }
        word.extend(body);
        Some(end)
    };
    while let Some(&c) = raw.get(i) {
        match c {
            _ if ends(c) => break,
            '<' | '>' | '`' => return None,
            '$' if raw.get(i + 1) == Some(&'(') => return None,
            '$' if raw.get(i + 1) == Some(&'{') => i = parameter(i, &mut word)?,
            '\\' => {
                let next = *raw.get(i + 1)?;
                if next == '\n' {
                    return None;
                }
                word.push(next);
                i += 2;
            }
            '\'' => {
                let len = raw[i + 1..].iter().position(|c| *c == '\'')?;
                word.extend(&raw[i + 1..i + 1 + len]);
                i += len + 2;
            }
            '"' => {
                i += 1;
                loop {
                    match *raw.get(i)? {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '`' => return None,
                        '$' if raw.get(i + 1) == Some(&'(') => return None,
                        '$' if raw.get(i + 1) == Some(&'{') => i = parameter(i, &mut word)?,
                        '\\' => {
                            let next = *raw.get(i + 1)?;
                            if !matches!(next, '$' | '`' | '"' | '\\') {
                                word.push('\\');
                            }
                            if next == '\n' {
                                return None;
                            }
                            word.push(next);
                            i += 2;
                        }
                        ch => {
                            word.push(ch);
                            i += 1;
                        }
                    }
                }
            }
            ch => {
                word.push(ch);
                i += 1;
            }
        }
    }
    Some(Some((i, word)))
}

/// True if the `&` or `|` at `raw[i]` is part of a redirect operator (`>&`, `<&`, `>|`) of the
/// word that starts at `start`, and thus not a separator. A quote or a backslash in the word
/// before it can make the `<` or `>` a plain character, so then it is a separator.
fn in_redirect_operator(raw: &[char], start: usize, i: usize) -> bool {
    i > start
        && matches!(raw[i], '&' | '|')
        && matches!(raw[i - 1], '<' | '>')
        && !raw[start..i].iter().any(|c| matches!(c, '\\' | '"' | '\''))
}

/// The redirect operators of bash that a word can start with, the longest first.
const REDIRECTS: &[&str] = &["<<<", "<<-", "<<", "<>", "<&", "<", ">>", ">|", ">&", ">"];

/// `Some(alone)` if the raw `word` starts with an unquoted redirect operator, after optional
/// file descriptor digits. `alone` is true if the word is only the operator (`>`, `2>`, `<<<`),
/// so that the next word is its target.
fn redirect_operator(word: &str) -> Option<bool> {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let operator = REDIRECTS.iter().find(|op| rest.starts_with(**op))?;
    Some(rest.len() == operator.len())
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
            '$' if c.get(i + 1) == Some(&'{') && substitutes(c, i + 1) => {
                // A `${..}` that runs a command can give any text.
                out.push(Part::Any);
                i = after_group(c, i + 1, '{', '}');
            }
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

/// True if the `${..}` whose `{` is at `c[at]` holds a command substitution (`$(` or a
/// backtick).
fn substitutes(c: &[char], at: usize) -> bool {
    let body = &c[at..after_group(c, at, '{', '}')];
    body.contains(&'`') || body.windows(2).any(|w| w == ['$', '('])
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
    let options = if sub == "llvm-cov" { LLVM_COV } else { CLAP };
    let lock = if locked {
        Lock::Read
    } else if TRAILING_ARGS.contains(&sub) {
        options_lock(rest, options, &[])
    } else if let Some(nested) = nested {
        options_lock(rest, options, nested)
    } else if rest
        .iter()
        .take_while(|a| a.as_str() != "--")
        .any(|a| a == "--locked")
    {
        Lock::Read
    } else {
        Lock::Missing
    };
    match lock {
        Lock::Read => Ok(()),
        Lock::Missing => Err(format!("cargo {sub} without --locked")),
        Lock::AfterPositional => Err(format!(
            "cargo {sub} has --locked only after a positional argument, where the check does \
             not read it (put --locked before the first positional argument)"
        )),
        Lock::Value(option) => Err(format!(
            "cargo {sub} has --locked only as the value of {option:?}, which takes the next \
             word"
        )),
        Lock::Cluster(cluster) => Err(format!(
            "cargo {sub} has a short-option cluster that can take the next word as its value \
             ({cluster:?}): write each option as its own word"
        )),
    }
}

/// Where `--locked` is in `rest`, if the check reads it only before `--` and the first
/// positional argument. If that argument is one of `nested` (a nested subcommand), the check
/// reads the options after it in the same way, up to the next positional argument.
fn options_lock(rest: &[String], options: Options, nested: &[&str]) -> Lock {
    let mut value_of: Option<String> = None;
    let mut j = 0;
    while j < rest.len() {
        let arg = rest[j].as_str();
        if arg == "--" {
            break;
        }
        if !arg.starts_with('-') {
            if nested.contains(&arg) {
                let inner = match options.nextest {
                    Some(nextest) if arg.starts_with("nextest") => *nextest,
                    _ => options,
                };
                return match options_lock(&rest[j + 1..], inner, &[]) {
                    Lock::Missing => value_of.map_or(Lock::Missing, Lock::Value),
                    lock => lock,
                };
            }
            if rest[j..]
                .iter()
                .take_while(|a| a.as_str() != "--")
                .any(|a| a == "--locked")
            {
                return Lock::AfterPositional;
            }
            break;
        }
        if arg == "--locked" {
            return Lock::Read;
        }
        // In `-vF`, the value is the next word. In `-j8`, it is the rest of the cluster.
        let cluster = !arg.starts_with("--") && arg.len() > 2;
        let first_valued = arg[1..].find(options.valued_letters);
        if cluster && first_valued == Some(arg.len() - 2) {
            return Lock::Cluster(arg.to_owned());
        }
        // A `--` is never read as a value: then the check reads less.
        let takes_next = rest.get(j + 1).is_some_and(|next| {
            next != "--"
                && (options.lexopt.contains(&arg)
                    || (options.clap.contains(&arg) && !next.starts_with('-')))
        });
        if takes_next && rest[j + 1] == "--locked" {
            value_of.get_or_insert_with(|| arg.to_owned());
        }
        j += if takes_next { 2 } else { 1 };
    }
    value_of.map_or(Lock::Missing, Lock::Value)
}
