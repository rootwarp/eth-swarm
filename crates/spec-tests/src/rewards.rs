//! consensus-spec-tests `tests/<preset>/gloas/rewards/<handler>/pyspec_tests/<case>/`, run
//! through `state_transition::per_epoch::{get_flag_index_deltas,
//! get_inactivity_penalty_deltas}`.
//!
//! Each case holds `pre.ssz_snappy`, `manifest.yaml` and one `Deltas` for each delta
//! function ([`DELTAS`]): `source_deltas`, `target_deltas` and `head_deltas` from
//! `get_flag_index_deltas` with the flag of the name, and `inactivity_penalty_deltas` from
//! `get_inactivity_penalty_deltas`. The check is each function on the pre-state, against
//! the rewards and the penalties of its file. The format is the same for each handler
//! directory (`basic`, `leak`, `random` and `inactivity_scores` at v1.7.0-beta.4), so the
//! runner takes any handler. A post-Altair case has no `inclusion_delay_deltas`.

use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::Gwei;
use consensus_types::{Mainnet, Minimal};
use ssz::Decode;
use state_transition::per_epoch::{get_flag_index_deltas, get_inactivity_penalty_deltas};
use state_transition::preset::{
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};
use state_transition::{Preset, StfError};

/// The delta function of one `Deltas` file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaFn {
    /// `get_flag_index_deltas(state, flag_index)`.
    Flag(usize),
    /// `get_inactivity_penalty_deltas(state)`.
    InactivityPenalty,
}

/// Each `Deltas` file of a case, with its delta function.
pub const DELTAS: [(&str, DeltaFn); 4] = [
    (
        "source_deltas.ssz_snappy",
        DeltaFn::Flag(TIMELY_SOURCE_FLAG_INDEX),
    ),
    (
        "target_deltas.ssz_snappy",
        DeltaFn::Flag(TIMELY_TARGET_FLAG_INDEX),
    ),
    (
        "head_deltas.ssz_snappy",
        DeltaFn::Flag(TIMELY_HEAD_FLAG_INDEX),
    ),
    (
        "inactivity_penalty_deltas.ssz_snappy",
        DeltaFn::InactivityPenalty,
    ),
];

/// `Deltas` of the rewards test format: the rewards and the penalties, one entry for each
/// validator. The pyspec writes two `ProgressiveList[uint64]`, which serialize as two
/// lists of `uint64`.
#[derive(Debug, PartialEq, Eq, ssz_derive::Decode, ssz_derive::Encode)]
pub struct Deltas {
    /// `rewards`.
    pub rewards: Vec<Gwei>,
    /// `penalties`.
    pub penalties: Vec<Gwei>,
}

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "gloas" && matches!(preset, "minimal" | "mainnet") && !handler.is_empty()
}

/// Runs one case. `Err` describes a failure.
pub fn run(reads: &Reads, case: &Case) -> Result<(), String> {
    match case.key.preset.as_str() {
        "minimal" => deltas::<Minimal>(reads, case),
        "mainnet" => deltas::<Mainnet>(reads, case),
        other => Err(format!("no rewards runner for preset {other}")),
    }
}

fn deltas<E: Preset>(reads: &Reads, case: &Case) -> Result<(), String> {
    let file = |name: &str| case.file(name).ok_or_else(|| format!("case has no {name}"));
    let bytes = fixture::ssz_snappy(reads, file("pre.ssz_snappy")?)?;
    let state =
        BeaconState::<E>::from_ssz_bytes(&bytes).map_err(|e| format!("pre.ssz_snappy: {e:?}"))?;
    // Read every file first, so that a failure of one function does not hide another file.
    let mut expected = Vec::with_capacity(DELTAS.len());
    for (name, function) in DELTAS {
        let bytes = fixture::ssz_snappy(reads, file(name)?)?;
        let deltas = Deltas::from_ssz_bytes(&bytes).map_err(|e| format!("{name}: {e:?}"))?;
        expected.push((name, function, deltas));
    }
    for (name, function, want) in expected {
        let got = compute(&state, function).map_err(|e| format!("{function:?}: {e}"))?;
        compare(name, &got, &want)?;
    }
    Ok(())
}

/// The deltas of `function` on `state`.
pub fn compute<E: Preset>(state: &BeaconState<E>, function: DeltaFn) -> Result<Deltas, StfError> {
    let (rewards, penalties) = match function {
        DeltaFn::Flag(flag_index) => get_flag_index_deltas(state, flag_index)?,
        DeltaFn::InactivityPenalty => get_inactivity_penalty_deltas(state)?,
    };
    Ok(Deltas { rewards, penalties })
}

/// `Err` names the list of `name` and the first validator whose delta differs.
fn compare(name: &str, got: &Deltas, want: &Deltas) -> Result<(), String> {
    for (list, got, want) in [
        ("rewards", &got.rewards, &want.rewards),
        ("penalties", &got.penalties, &want.penalties),
    ] {
        if got.len() != want.len() {
            return Err(format!("{name}: {} {list}, want {}", got.len(), want.len()));
        }
        if let Some((index, (g, w))) = got.iter().zip(want).enumerate().find(|(_, (g, w))| g != w) {
            return Err(format!("{name}: {list}[{index}] is {g}, want {w}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{CaseFile, CaseKey};
    use crate::sanity::tests::state;
    use consensus_types::gloas::Validator;
    use consensus_types::primitives::Root;
    use consensus_types::EthSpec;
    use ssz::Encode;

    const ETH: Gwei = 1_000_000_000;

    /// A minimal state at the last slot of epoch 3 with eight active validators. Validator
    /// `i` has the previous participation flags `i % 8`, so each flag set occurs, and the
    /// inactivity score `i`.
    fn rewards_state() -> BeaconState<Minimal> {
        let mut st = state(Minimal::start_slot_at_epoch(4) - 1);
        for i in 0..8u8 {
            st.validators
                .push(Validator {
                    pubkey: [i; 48],
                    withdrawal_credentials: Root::ZERO,
                    effective_balance: 32 * ETH,
                    slashed: false,
                    activation_eligibility_epoch: 0,
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                    withdrawable_epoch: u64::MAX,
                })
                .unwrap();
            st.balances.push(32 * ETH).unwrap();
            st.previous_epoch_participation.push(i % 8).unwrap();
            st.current_epoch_participation.push(0).unwrap();
            st.inactivity_scores.push(u64::from(i)).unwrap();
        }
        st.apply_updates().unwrap();
        st
    }

    fn snappy(bytes: Vec<u8>) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(&bytes).unwrap()
    }

    /// The files of a case of `pre` with the deltas that the transition computes; `change`
    /// can edit the deltas of one file before they are written.
    fn files(
        pre: &BeaconState<Minimal>,
        change: impl Fn(&str, &mut Deltas),
    ) -> Vec<(String, Vec<u8>)> {
        let mut files = vec![("pre.ssz_snappy".to_owned(), snappy(pre.as_ssz_bytes()))];
        for (name, function) in DELTAS {
            let mut deltas = compute(pre, function).unwrap();
            change(name, &mut deltas);
            files.push((name.to_owned(), snappy(deltas.as_ssz_bytes())));
        }
        files
    }

    /// A case of `preset` in a new directory under `dir` with `files`.
    fn case(dir: &std::path::Path, preset: &str, files: &[(String, Vec<u8>)]) -> Case {
        let dir = tempfile::tempdir_in(dir).unwrap().keep();
        let files = files
            .iter()
            .map(|(name, bytes)| {
                let path = dir.join(name);
                std::fs::write(&path, bytes).unwrap();
                CaseFile {
                    path,
                    name: name.clone(),
                }
            })
            .collect();
        Case {
            key: CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: preset.into(),
                runner: "rewards".into(),
                handler: "basic".into(),
                case: "pyspec_tests/case_0".into(),
            },
            files,
        }
    }

    #[test]
    fn handler_selection() {
        for handler in ["basic", "leak", "random", "inactivity_scores"] {
            assert!(supported("gloas", "minimal", handler));
            assert!(supported("gloas", "mainnet", handler));
            assert!(!supported("fulu", "minimal", handler));
            assert!(!supported("gloas", "general", handler));
        }
        assert!(!supported("gloas", "minimal", ""));
    }

    #[test]
    fn the_deltas_of_the_transition_pass_and_every_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let pre = rewards_state();
        // The state gives rewards and penalties that are not zero, so the check compares
        // real values.
        let target = compute(&pre, DeltaFn::Flag(TIMELY_TARGET_FLAG_INDEX)).unwrap();
        assert!(target.rewards.iter().any(|r| *r > 0), "{target:?}");
        assert!(target.penalties.iter().any(|p| *p > 0), "{target:?}");
        let inactivity = compute(&pre, DeltaFn::InactivityPenalty).unwrap();
        assert!(
            inactivity.penalties.iter().any(|p| *p > 0),
            "{inactivity:?}"
        );
        let c = case(dir.path(), "minimal", &files(&pre, |_, _| {}));
        let reads = Reads::default();
        assert_eq!(run(&reads, &c), Ok(()));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
    }

    #[test]
    fn deltas_that_differ_fail_with_the_file_and_the_validator() {
        let dir = tempfile::tempdir().unwrap();
        let pre = rewards_state();
        for (file, edit, needle) in [
            (
                "source_deltas.ssz_snappy",
                (|d: &mut Deltas| d.rewards[3] += 1) as fn(&mut Deltas),
                "source_deltas.ssz_snappy: rewards[3]",
            ),
            (
                "target_deltas.ssz_snappy",
                |d| d.penalties[0] += 1,
                "target_deltas.ssz_snappy: penalties[0]",
            ),
            (
                "head_deltas.ssz_snappy",
                |d| d.rewards.truncate(7),
                "head_deltas.ssz_snappy: 8 rewards, want 7",
            ),
            (
                "inactivity_penalty_deltas.ssz_snappy",
                |d| d.penalties.push(0),
                "inactivity_penalty_deltas.ssz_snappy: 8 penalties, want 9",
            ),
        ] {
            let files = files(&pre, |name, d| {
                if name == file {
                    edit(d);
                }
            });
            let err = run(&Reads::default(), &case(dir.path(), "minimal", &files)).unwrap_err();
            assert!(err.starts_with(needle), "{needle}: {err}");
        }
    }

    #[test]
    fn malformed_cases_fail() {
        let dir = tempfile::tempdir().unwrap();
        let pre = rewards_state();
        // A missing file.
        for missing in ["pre.ssz_snappy", "head_deltas.ssz_snappy"] {
            let mut files = files(&pre, |_, _| {});
            files.retain(|(name, _)| name != missing);
            let err = run(&Reads::default(), &case(dir.path(), "minimal", &files)).unwrap_err();
            assert_eq!(err, format!("case has no {missing}"));
        }
        // A file that does not decode.
        let mut bad = files(&pre, |_, _| {});
        bad[2].1 = snappy(vec![1, 2, 3]);
        let err = run(&Reads::default(), &case(dir.path(), "minimal", &bad)).unwrap_err();
        assert!(err.starts_with("target_deltas.ssz_snappy"), "{err}");
        // A minimal state does not decode as a mainnet one, and a preset without a runner.
        let good = files(&pre, |_, _| {});
        let err = run(&Reads::default(), &case(dir.path(), "mainnet", &good)).unwrap_err();
        assert!(err.starts_with("pre.ssz_snappy"), "{err}");
        let err = run(&Reads::default(), &case(dir.path(), "general", &good)).unwrap_err();
        assert!(err.contains("no rewards runner"), "{err}");
        // A state that the delta functions refuse: no inactivity score for each validator.
        let mut short = pre.clone();
        short.inactivity_scores = Default::default();
        let mut files = files(&pre, |_, _| {});
        files[0].1 = snappy(short.as_ssz_bytes());
        let err = run(&Reads::default(), &case(dir.path(), "minimal", &files)).unwrap_err();
        assert!(err.starts_with("InactivityPenalty"), "{err}");
    }
}
