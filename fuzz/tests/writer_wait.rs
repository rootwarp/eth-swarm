//! `column_contract` waits on the wall clock for the writer thread's settle step
//! ([`WRITER_WAIT`]) just under the gates' per-input timeout (`M2A_TIMEOUT_S` in
//! `fuzz/m2a-common.sh`, the `-timeout` every gate runs with): a writer that stalls under load
//! but settles within the input's time is not reported as a crash, and one that never settles
//! still fails with its own message before libFuzzer calls the input a timeout.

use ethswarm_fuzz::WRITER_WAIT;
use std::time::Duration;

/// What one input does besides the wait, at most: its other operations take milliseconds.
const REST_OF_THE_INPUT: Duration = Duration::from_secs(2);

/// `M2A_TIMEOUT_S` as `fuzz/m2a-common.sh` sets it.
fn gate_timeout() -> Duration {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/m2a-common.sh");
    let script = std::fs::read_to_string(path).expect("read fuzz/m2a-common.sh");
    let values: Vec<u64> = script
        .lines()
        .filter_map(|line| line.strip_prefix("M2A_TIMEOUT_S="))
        .map(|value| {
            value
                .trim()
                .parse()
                .expect("M2A_TIMEOUT_S is whole seconds")
        })
        .collect();
    match values.as_slice() {
        [secs] => Duration::from_secs(*secs),
        other => panic!("M2A_TIMEOUT_S set {} times in {path}", other.len()),
    }
}

#[test]
fn the_writer_wait_is_just_under_the_per_input_timeout() {
    assert_eq!(
        WRITER_WAIT + REST_OF_THE_INPUT,
        gate_timeout(),
        "WRITER_WAIT must stay {REST_OF_THE_INPUT:?} under the gates' -timeout"
    );
}
