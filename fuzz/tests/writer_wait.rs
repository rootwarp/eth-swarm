//! `column_contract` gives each input one wall-clock deadline ([`INPUT_DEADLINE`], from the
//! input's start), checked by every wait for the writer thread, just under the gates' per-input
//! timeout (`M2A_TIMEOUT_S` in `fuzz/m2a-common.sh`, the `-timeout` every gate runs with): a
//! writer that stalls under load but finishes within the input's time is not reported as a
//! crash, and one that never drains or settles still fails with the harness's own message before
//! libFuzzer calls the input a timeout.

use ethswarm_fuzz::INPUT_DEADLINE;
use std::time::Duration;

/// What the input runs outside its deadline, at most: libFuzzer's call before the input's first
/// line, and the one wait step after the deadline passed before its check fails (microseconds).
const OUTSIDE_THE_DEADLINE: Duration = Duration::from_secs(2);

const NAME: &str = "M2A_TIMEOUT_S";

/// Whether `line[at..]`, where `NAME` starts, is the whole name and not part of a longer one.
fn is_the_name(line: &str, at: usize) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let before = line[..at].chars().next_back().is_some_and(word);
    let after = line[at + NAME.len()..].chars().next().is_some_and(word);
    !before && !after
}

/// The one value `script` sets `M2A_TIMEOUT_S` to. Every other mention outside a comment line
/// must be a plain read (`$M2A_TIMEOUT_S` or `${M2A_TIMEOUT_S}`), so a later reassignment
/// (`export`, `readonly`, `declare`, indented, `${…:=…}`, …) is refused, not overlooked.
fn timeout_in(script: &str) -> Result<Duration, String> {
    let mut value = None;
    for (n, line) in (1..).zip(script.lines()) {
        if line.trim_start().starts_with('#') {
            continue;
        }
        for (at, _) in line
            .match_indices(NAME)
            .filter(|&(at, _)| is_the_name(line, at))
        {
            let read = line[..at].ends_with('$')
                || (line[..at].ends_with("${") && line[at + NAME.len()..].starts_with('}'));
            if read {
                continue;
            }
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

/// `M2A_TIMEOUT_S` as `fuzz/m2a-common.sh` sets it.
fn gate_timeout() -> Duration {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/m2a-common.sh");
    let script = std::fs::read_to_string(path).expect("read fuzz/m2a-common.sh");
    timeout_in(&script).unwrap_or_else(|e| panic!("{path}: {e}"))
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
