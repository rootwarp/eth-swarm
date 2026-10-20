//! `column_contract` gives each input one wall-clock deadline ([`INPUT_DEADLINE`], from the
//! input's start), checked by every wait for the writer thread, just under the gates' per-input
//! timeout (`M2A_TIMEOUT_S` in `fuzz/m2a-common.sh`, the `-timeout` every gate runs with): a
//! writer that stalls under load but finishes within the input's time is not reported as a
//! crash, and one that never drains or settles still fails with the harness's own message before
//! libFuzzer calls the input a timeout.
//!
//! The relation test reads the timeout from the scripts, so it has to see every write to
//! `M2A_TIMEOUT_S`. It guards against an accidental edit, not a deliberately hostile script, and
//! it is a line scanner, not a shell parser. It joins backslash-continued lines first, then
//! catches: the one definition in `fuzz/m2a-common.sh` changing; any later or second write
//! there (`export`, `readonly`, `declare`, indented, `+=`, `${…:=…}`, a function body, …); any
//! write in another `fuzz/*.sh` (assignment, `read`, `printf -v`, …); and any `eval`, `source`
//! or `.` it cannot follow, apart from the one line that sources `m2a-common.sh`. It does not
//! catch a name built in pieces (`+=` onto a partial name, `printf -v "$n"`, quoted fragments
//! such as `M2A_"TIMEOUT"_S`), nor anything else a shell evaluates before naming the variable.

use ethswarm_fuzz::INPUT_DEADLINE;
use std::time::Duration;

/// The configured margin between the input's deadline and the gates' per-input timeout. It covers
/// what the input runs outside its deadline: libFuzzer's call before the input's first line, and
/// the one wait step after the deadline passed before its check fails (microseconds). Teardown is
/// not in it: dropping the column ingest joins the writer thread with no limit, so a writer stuck
/// there surfaces as a libFuzzer timeout, which the gates reject.
const OUTSIDE_THE_DEADLINE: Duration = Duration::from_secs(2);

const NAME: &str = "M2A_TIMEOUT_S";

/// The one line by which a gate script reads `fuzz/m2a-common.sh`, exactly (a comment goes on
/// its own line); any other `source`, `.` or `eval` could set `M2A_TIMEOUT_S` out of the
/// scanner's sight, so it is refused.
const SOURCE_COMMON: &str = r#". "$(dirname "$0")/m2a-common.sh""#;

/// Whether `line` is a comment line: `#` after any indentation.
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

/// `script`'s lines with backslash continuations joined, each with the number of its first
/// line. A line ending in an odd number of backslashes goes on with the next, the backslash and
/// line break dropped as the shell drops them; a comment line's backslash is comment text, so
/// a comment line is never continued.
fn logical_lines(script: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut open: Option<(usize, String)> = None;
    for (n, line) in (1..).zip(script.lines()) {
        let (first, mut joined) = match open.take() {
            Some((first, text)) => (first, text + line),
            None if is_comment(line) => {
                out.push((n, line.to_owned()));
                continue;
            }
            None => (n, line.to_owned()),
        };
        let backslashes = joined.len() - joined.trim_end_matches('\\').len();
        if backslashes % 2 == 1 {
            joined.pop();
            open = Some((first, joined));
        } else {
            out.push((first, joined));
        }
    }
    out.extend(open);
    out
}

/// Whether `line[at..]`, where `NAME` starts, is the whole name and not part of a longer one.
fn is_the_name(line: &str, at: usize) -> bool {
    is_word_at(line, at, NAME.len())
}

/// Whether `line[at..at + len]` is a whole word: no name character on either side.
fn is_word_at(line: &str, at: usize, len: usize) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let before = line[..at].chars().next_back().is_some_and(word);
    let after = line[at + len..].chars().next().is_some_and(word);
    !before && !after
}

/// The characters that end a command word and may start a new command after them.
const SEPARATORS: &str = ";&|(){}`!";

/// `line`'s words split at whitespace and at [`SEPARATORS`] (each its own token), each with
/// the byte offset just past it.
fn tokens(line: &str) -> Vec<(&str, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (at, c) in line.char_indices() {
        let separator = SEPARATORS.contains(c);
        if c.is_whitespace() || separator {
            if let Some(from) = start.take() {
                out.push((&line[from..at], at));
            }
            if separator {
                out.push((&line[at..at + 1], at + 1));
            }
        } else if start.is_none() {
            start = Some(at);
        }
    }
    if let Some(from) = start {
        out.push((&line[from..], line.len()));
    }
    out
}

/// Refuses a line that runs code the scanner cannot follow: any `eval` or `source` word, and a
/// `.` (or a quoted `"."`, `'.'`) in a command's place (line start, after `;`, `&`, `|`, `(`,
/// `{`, `` ` ``, `!`, a keyword, a command prefix, or an option after `command`, `builtin` or
/// `exec`), unless the line is exactly [`SOURCE_COMMON`]. Comment lines are skipped by the
/// caller; anything else that merely looks like one is refused, never overlooked.
fn readable(n: usize, line: &str) -> Result<(), String> {
    if line == SOURCE_COMMON {
        return Ok(());
    }
    for word in ["eval", "source"] {
        if line
            .match_indices(word)
            .any(|(at, _)| is_word_at(line, at, word.len()))
        {
            return Err(format!(
                "line {n} uses `{word}`, which this test cannot follow: move text that only \
                 mentions it to its own comment line or reword it, and source m2a-common.sh only \
                 as `{SOURCE_COMMON}`: {line}"
            ));
        }
    }
    let mut command_place = true;
    let mut after_wrapper = false;
    for (token, end) in tokens(line) {
        let separator = token.len() == 1 && SEPARATORS.contains(token);
        let prefix = matches!(
            token,
            "if" | "then"
                | "elif"
                | "else"
                | "while"
                | "until"
                | "do"
                | "time"
                | "command"
                | "builtin"
                | "exec"
                | "env"
                | "nohup"
        ) || (token.contains('=') && !token.starts_with('='));
        // `command -p`, `exec -a`: the command still comes after the wrapper's options.
        let option = after_wrapper && token.starts_with('-');
        // `.` runs a file only as a whole word: `{key}.{…}` in a heredoc is no command.
        let whole = line[end..].chars().next().is_none_or(char::is_whitespace);
        let dot = matches!(token, "." | "\".\"" | "'.'");
        if dot && whole && command_place {
            return Err(format!(
                "line {n} sources a file with `.`: the one line allowed to is exactly \
                 `{SOURCE_COMMON}`, with any comment on its own line: {line}"
            ));
        }
        command_place = separator || (command_place && (prefix || option));
        after_wrapper =
            command_place && (option || matches!(token, "command" | "builtin" | "exec"));
    }
    Ok(())
}

/// The non-read mentions of `M2A_TIMEOUT_S` in `line`, by where they start. A read is
/// `$M2A_TIMEOUT_S` or `${M2A_TIMEOUT_S}`.
fn writes(line: &str) -> impl Iterator<Item = usize> + '_ {
    line.match_indices(NAME)
        .map(|(at, _)| at)
        .filter(move |&at| is_the_name(line, at))
        .filter(move |&at| {
            let read = line[..at].ends_with('$')
                || (line[..at].ends_with("${") && line[at + NAME.len()..].starts_with('}'));
            !read
        })
}

/// The one value `script` sets `M2A_TIMEOUT_S` to. Every other mention outside a comment line
/// must be a plain read (`$M2A_TIMEOUT_S` or `${M2A_TIMEOUT_S}`), so a later reassignment
/// (`export`, `readonly`, `declare`, indented, `${…:=…}`, …) is refused, not overlooked, and so
/// is any line the scanner cannot follow ([`readable`]). Lines are read joined
/// ([`logical_lines`]).
fn timeout_in(script: &str) -> Result<Duration, String> {
    let mut value = None;
    for (n, line) in logical_lines(script) {
        let line = line.as_str();
        if is_comment(line) {
            continue;
        }
        readable(n, line)?;
        for at in writes(line) {
            let defined = line
                .strip_prefix(NAME)
                .and_then(|rest| rest.strip_prefix('='))
                .filter(|secs| !secs.is_empty() && secs.bytes().all(|b| b.is_ascii_digit()));
            match (defined, value) {
                (Some(secs), None) if at == 0 => {
                    let secs = secs.parse().map_err(|e| format!("line {n}: {e}"))?;
                    value = Some(Duration::from_secs(secs));
                }
                (_, Some(_)) => return Err(format!("line {n} sets {NAME} again: {line}")),
                _ => return Err(format!("line {n} is not `{NAME}=<seconds>`: {line}")),
            }
        }
    }
    value.ok_or_else(|| format!("{NAME} is never set"))
}

/// Whether `script` only reads `M2A_TIMEOUT_S`: no mention outside a comment line is anything
/// but a plain read, and every line, read joined ([`logical_lines`]), is [`readable`]. Holds
/// for every gate script other than `fuzz/m2a-common.sh`, whose value they all run with once
/// they source it.
fn only_reads(script: &str) -> Result<(), String> {
    for (n, line) in logical_lines(script) {
        let line = line.as_str();
        if is_comment(line) {
            continue;
        }
        readable(n, line)?;
        if writes(line).next().is_some() {
            return Err(format!(
                "line {n} sets {NAME} outside m2a-common.sh: {line}"
            ));
        }
    }
    Ok(())
}

/// `M2A_TIMEOUT_S` as `fuzz/m2a-common.sh` sets it, with every other `fuzz/*.sh` (the gate
/// scripts that source it, `run-m2a-gate.sh` among them, and the ones that run those) only
/// reading it.
fn gate_timeout() -> Duration {
    let dir = env!("CARGO_MANIFEST_DIR");
    let mut scripts: Vec<_> = std::fs::read_dir(dir)
        .expect("list fuzz/")
        .map(|entry| entry.expect("a fuzz/ entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sh"))
        .collect();
    scripts.sort();
    let mut timeout = None;
    let mut sourcing = Vec::new();
    for path in &scripts {
        let script = std::fs::read_to_string(path).expect("read a fuzz/*.sh script");
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name == "m2a-common.sh" {
            timeout =
                Some(timeout_in(&script).unwrap_or_else(|e| panic!("{}: {e}", path.display())));
            continue;
        }
        only_reads(&script).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if logical_lines(&script)
            .iter()
            .any(|(_, line)| line == SOURCE_COMMON)
        {
            sourcing.push(name.to_owned());
        }
    }
    assert!(
        sourcing.iter().any(|name| name == "run-m2a-gate.sh"),
        "run-m2a-gate.sh no longer sources m2a-common.sh as `{SOURCE_COMMON}`: {sourcing:?}"
    );
    timeout.expect("fuzz/m2a-common.sh")
}

#[test]
fn the_input_deadline_is_just_under_the_per_input_timeout() {
    assert_eq!(
        INPUT_DEADLINE + OUTSIDE_THE_DEADLINE,
        gate_timeout(),
        "INPUT_DEADLINE must stay {OUTSIDE_THE_DEADLINE:?} under the gates' -timeout"
    );
}

#[test]
fn the_timeout_is_set_once_and_only_read_after() {
    let ten = Ok(Duration::from_secs(10));
    assert_eq!(timeout_in("M2A_TIMEOUT_S=10\n"), ten);
    assert_eq!(
        timeout_in("# M2A_TIMEOUT_S=99 is a comment\nM2A_TIMEOUT_S=10\nM2A_TIMEOUT_S_X=3\n"),
        ten
    );
    assert_eq!(
        timeout_in("M2A_TIMEOUT_S=10\nrun -timeout=$M2A_TIMEOUT_S \"${M2A_TIMEOUT_S}\"\n"),
        ten
    );
    for later in [
        "export M2A_TIMEOUT_S=20",
        "readonly M2A_TIMEOUT_S=20",
        "readonly M2A_TIMEOUT_S",
        "declare -r M2A_TIMEOUT_S=20",
        "  M2A_TIMEOUT_S=20",
        "\tM2A_TIMEOUT_S=20",
        "M2A_TIMEOUT_\\\nS=20",
        "f() { M2A_TIMEOUT_S=20; }",
        "M2A_TIMEOUT_S=20",
        "M2A_TIMEOUT_S+=0",
        ": \"${M2A_TIMEOUT_S:=20}\"",
    ] {
        let script = format!("M2A_TIMEOUT_S=10\n{later}\n");
        assert!(timeout_in(&script).is_err(), "{later:?} was overlooked");
    }
    for first in [
        "export M2A_TIMEOUT_S=10",
        "  M2A_TIMEOUT_S=10",
        "M2A_TIMEOUT_S=ten",
    ] {
        assert!(timeout_in(first).is_err(), "{first:?} was taken");
    }
    assert!(timeout_in("run -timeout=$M2A_TIMEOUT_S\n").is_err());
}

#[test]
fn a_gate_script_only_reads_the_timeout() {
    let reads = [
        "run -timeout=$M2A_TIMEOUT_S \"${M2A_TIMEOUT_S}\"",
        "# M2A_TIMEOUT_S=99 and eval and source in a comment",
        "M2A_TIMEOUT_S_X=3",
        "find . -name '*.sh'",
        "cd . && ls ./corpus",
        "if command -v sha256sum >/dev/null 2>&1; then :; fi",
        "    what = f\"{key}.{', '.join(sorted(value))}\"",
        SOURCE_COMMON,
    ];
    for line in reads {
        assert_eq!(
            only_reads(&format!("{line}\n")),
            Ok(()),
            "{line:?} was refused"
        );
    }
    for write in [
        "M2A_TIMEOUT_S=20",
        "export M2A_TIMEOUT_S=20",
        "  M2A_TIMEOUT_S=20",
        "X=1 M2A_TIMEOUT_S=3 run",
        "read -r M2A_TIMEOUT_S",
        "printf -v M2A_TIMEOUT_S %s 20",
        ": \"${M2A_TIMEOUT_S:=20}\"",
    ] {
        assert!(
            only_reads(&format!("{write}\n")).is_err(),
            "{write:?} was overlooked"
        );
    }
}

#[test]
fn a_line_the_parser_cannot_read_is_refused() {
    for unreadable in [
        "eval \"M2A_TIMEOUT_S=20\"",
        "eval \"$set\"",
        "source ./other.sh",
        "source \"$(dirname \"$0\")/m2a-common.sh\"",
        ". ./other.sh",
        "  . \"$(dirname \"$0\")/m2a-common.sh\"",
        ". \"$(dirname \"$0\")/m2a-common.sh\" extra",
        "true; . ./other.sh",
        "true && . ./other.sh",
        "if . ./other.sh; then :; fi",
        "! . ./other.sh",
        "command . ./other.sh",
        "builtin source ./other.sh",
        "X=1 . ./other.sh",
        "x=$(. ./other.sh)",
        "x=`. ./other.sh`",
        "f() { . ./other.sh; }",
        ". \"$(dirname \"$0\")/m2a-common.sh\" # a trailing comment",
        "M2A_TIMEOUT_\\\nS=20",
        ".\\\n ./other.sh",
        "\".\" ./other.sh",
        "'.' ./other.sh",
        "\"source\" ./other.sh",
        "command -p . ./other.sh",
        "exec -- . ./other.sh",
    ] {
        assert!(
            only_reads(&format!("{unreadable}\n")).is_err(),
            "{unreadable:?} was overlooked"
        );
        let script = format!("M2A_TIMEOUT_S=10\n{unreadable}\n");
        assert!(
            timeout_in(&script).is_err(),
            "{unreadable:?} was overlooked"
        );
    }
}

#[test]
fn a_refusal_says_how_to_fix_the_line() {
    let commented = format!("{SOURCE_COMMON} # read the shared settings\n");
    let refused = only_reads(&commented).expect_err("a trailing comment was taken");
    assert!(
        refused.contains(SOURCE_COMMON) && refused.contains("own line"),
        "{refused}"
    );
    let refused = only_reads("echo do not source this\n").expect_err("`source` was taken");
    assert!(refused.contains("own comment line"), "{refused}");
}

#[test]
fn a_continued_line_is_read_joined() {
    assert_eq!(
        logical_lines("a \\\n b\n# c \\\nd\ne \\\\\nf \\"),
        [
            (1, "a  b".to_owned()),
            (3, "# c \\".to_owned()),
            (4, "d".to_owned()),
            (5, "e \\\\".to_owned()),
            (6, "f ".to_owned()),
        ]
    );
    let reads = "run \\\n  -timeout=$M2A_TIMEOUT_S\n# M2A_TIMEOUT_S=1 \\\nM2A_TIMEOUT_S_X=3\n";
    assert_eq!(only_reads(reads), Ok(()));
}
