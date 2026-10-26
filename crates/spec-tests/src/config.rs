//! The `config.yaml` of a state-transition case: the config of the preset, which the pyspec
//! writes for a test that reads config values. The transition takes its config values from
//! the preset, so each value that it reads must be the value of the case.
//!
//! [`check_config`] is the one check of the `operations`, `epoch_processing`, `sanity`,
//! `finality` and `random` runners. It compares these values, and another value fails the
//! case:
//!
//! - `PRESET_BASE` is the preset of the case.
//! - `GENESIS_FORK_VERSION`, the domain of the deposits and of the BLS-to-execution changes.
//! - `CAPELLA_FORK_VERSION`, the domain of the voluntary exits (EIP-7044).
//! - [`config_values`]: each config value that the transition compiles in, for example the
//!   churn values of the epoch steps and `SHARD_COMMITTEE_PERIOD`, which the voluntary exits
//!   and the consolidation requests read.
//!
//! It also gives how `GLOAS_FORK_EPOCH` compares with `fork.epoch` of the pre-state
//! ([`ForkEpoch`]): `get_ptc` reads `state.fork.epoch` as the Gloas fork epoch. A state that
//! the transition makes has `fork.epoch == GLOAS_FORK_EPOCH`, so [`check_same_config`]
//! requires the two epochs to agree. The operations runner has one case where they differ.
//! The fork versions are hex integers in YAML (`0x00000001`).

use crate::bls_backend::{bls_context, BlsOff};
use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::primitives::Epoch;
use state_transition::preset::config_values;
use state_transition::{BlsContext, Preset};

/// Every numeric value that [`check_config`] compares: `GENESIS_FORK_VERSION` and
/// `CAPELLA_FORK_VERSION` of `bls`, and the config values that the transition compiles in
/// ([`config_values`]), with the values of the config of preset `E`, which is also the config
/// of the vectors: `configs/{minimal,mainnet}.yaml`.
pub fn compared_values<E: Preset>(bls: &BlsContext) -> Vec<(&'static str, u64)> {
    let mut values = vec![
        (
            "GENESIS_FORK_VERSION",
            u64::from(u32::from_be_bytes(bls.genesis_fork_version)),
        ),
        (
            "CAPELLA_FORK_VERSION",
            u64::from(u32::from_be_bytes(bls.capella_fork_version)),
        ),
    ];
    values.extend(config_values::<E>());
    values
}

/// How `GLOAS_FORK_EPOCH` of a `config.yaml` compares with `fork.epoch` of the pre-state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForkEpoch {
    /// The case has no `config.yaml`, or its `GLOAS_FORK_EPOCH` is `fork.epoch`.
    Same,
    /// The `GLOAS_FORK_EPOCH` of the case, which is not `fork.epoch`.
    Differs(Epoch),
}

/// Checks the `config.yaml` of `case`, if it has one (see the module docs). `fork_epoch` is
/// `fork.epoch` of the pre-state. `Err` names the first value that is missing or differs.
pub fn check_config<E: Preset>(
    reads: &Reads,
    case: &Case,
    fork_epoch: Epoch,
) -> Result<ForkEpoch, String> {
    let Some(path) = case.file("config.yaml") else {
        return Ok(ForkEpoch::Same);
    };
    let config = fixture::load(reads, path)?;
    let field = |name: &str| fixture::field(&config, name).map_err(|e| format!("config.yaml: {e}"));
    let preset = &case.key.preset;
    let base = field("PRESET_BASE")?;
    if base.as_str() != Some(preset) {
        return Err(format!(
            "config.yaml sets PRESET_BASE to {base:?}, but the case is {preset}"
        ));
    }
    let unsigned = |value: &yaml_rust2::Yaml| value.as_i64().and_then(|v| u64::try_from(v).ok());
    let bls = bls_context(preset, &BlsOff)?;
    for (name, want) in compared_values::<E>(&bls) {
        let got = field(name)?;
        if unsigned(got) != Some(want) {
            return Err(format!(
                "config.yaml sets {name} to {got:?}, but the runner uses {want}"
            ));
        }
    }
    let value = field("GLOAS_FORK_EPOCH")?;
    let epoch = unsigned(value)
        .ok_or_else(|| format!("config.yaml: GLOAS_FORK_EPOCH {value:?} is not an epoch"))?;
    Ok(if epoch == fork_epoch {
        ForkEpoch::Same
    } else {
        ForkEpoch::Differs(epoch)
    })
}

/// [`check_config`], and `Err` if `GLOAS_FORK_EPOCH` is not `fork_epoch`.
pub fn check_same_config<E: Preset>(
    reads: &Reads,
    case: &Case,
    fork_epoch: Epoch,
) -> Result<(), String> {
    match check_config::<E>(reads, case, fork_epoch)? {
        ForkEpoch::Same => Ok(()),
        ForkEpoch::Differs(epoch) => Err(fork_epoch_differs(epoch, fork_epoch)),
    }
}

/// The error of a `GLOAS_FORK_EPOCH` that is not `fork.epoch` of the pre-state.
pub fn fork_epoch_differs(config: Epoch, fork_epoch: Epoch) -> String {
    format!(
        "config.yaml: GLOAS_FORK_EPOCH is {config}, but the pre-state has fork.epoch {fork_epoch}"
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::plan::{CaseFile, CaseKey};
    use consensus_types::{Mainnet, Minimal};

    /// A `config.yaml` of `preset` (`E`) with every value that [`check_config`] compares, as
    /// the config of the preset has them, and `GLOAS_FORK_EPOCH: 0`. Each `(name, value)` of
    /// `replace` changes one line, and a `name` with the value `None` removes its line.
    pub(crate) fn config_yaml<E: Preset>(preset: &str, replace: &[(&str, Option<&str>)]) -> String {
        let bls = bls_context(preset, &BlsOff).unwrap();
        let mut lines = vec![("PRESET_BASE".to_owned(), format!("'{preset}'"))];
        for (name, value) in compared_values::<E>(&bls) {
            let value = if name.ends_with("_FORK_VERSION") {
                format!("{value:#010x}")
            } else {
                value.to_string()
            };
            lines.push((name.to_owned(), value));
        }
        lines.push(("GLOAS_FORK_EPOCH".to_owned(), "0".to_owned()));
        for (name, value) in replace {
            let at = lines.iter().position(|(n, _)| n == name).unwrap();
            match value {
                Some(v) => lines[at].1 = (*v).to_owned(),
                None => drop(lines.remove(at)),
            }
        }
        lines.iter().map(|(n, v)| format!("{n}: {v}\n")).collect()
    }

    /// A case of `preset` in `dir` with `config.yaml` holding `config`, or no file if `None`.
    fn case(dir: &std::path::Path, preset: &str, config: Option<&str>) -> Case {
        let mut files = Vec::new();
        if let Some(text) = config {
            let path = dir.join("config.yaml");
            std::fs::write(&path, text).unwrap();
            files.push(CaseFile {
                path,
                name: "config.yaml".into(),
            });
        }
        Case {
            key: CaseKey {
                source: "consensus-specs".into(),
                fork: "gloas".into(),
                preset: preset.into(),
                runner: "operations".into(),
                handler: "payload_attestation".into(),
                case: "pyspec_tests/case_0".into(),
            },
            files,
        }
    }

    #[test]
    fn the_config_of_the_preset_passes() {
        let dir = tempfile::tempdir().unwrap();
        let reads = Reads::default();
        let c = case(dir.path(), "minimal", None);
        assert_eq!(check_config::<Minimal>(&reads, &c, 5), Ok(ForkEpoch::Same));
        let text = config_yaml::<Minimal>("minimal", &[]);
        // The minimal config writes the fork versions as hex.
        assert!(
            text.contains("GENESIS_FORK_VERSION: 0x00000001\n"),
            "{text}"
        );
        assert!(
            text.contains("CAPELLA_FORK_VERSION: 0x03000001\n"),
            "{text}"
        );
        let c = case(dir.path(), "minimal", Some(&text));
        assert_eq!(check_config::<Minimal>(&reads, &c, 0), Ok(ForkEpoch::Same));
        assert!(c.files.iter().all(|f| reads.contains(&f.path)));
        let c = case(
            dir.path(),
            "mainnet",
            Some(&config_yaml::<Mainnet>("mainnet", &[])),
        );
        assert_eq!(check_same_config::<Mainnet>(&reads, &c, 0), Ok(()));
        // The minimal config is not the mainnet config.
        let c = case(dir.path(), "mainnet", Some(&text));
        assert!(check_config::<Mainnet>(&reads, &c, 0).is_err());
    }

    #[test]
    fn the_gloas_fork_epoch_must_be_the_fork_epoch_of_the_pre_state() {
        let dir = tempfile::tempdir().unwrap();
        let reads = Reads::default();
        let c = case(
            dir.path(),
            "minimal",
            Some(&config_yaml::<Minimal>(
                "minimal",
                &[("GLOAS_FORK_EPOCH", Some("1"))],
            )),
        );
        assert_eq!(check_config::<Minimal>(&reads, &c, 1), Ok(ForkEpoch::Same));
        assert_eq!(check_same_config::<Minimal>(&reads, &c, 1), Ok(()));
        assert_eq!(
            check_config::<Minimal>(&reads, &c, 0),
            Ok(ForkEpoch::Differs(1))
        );
        let err = check_same_config::<Minimal>(&reads, &c, 0).unwrap_err();
        assert_eq!(err, fork_epoch_differs(1, 0));
        assert!(err.contains("GLOAS_FORK_EPOCH is 1"), "{err}");
    }

    #[test]
    fn another_or_a_missing_value_fails() {
        let dir = tempfile::tempdir().unwrap();
        let reads = Reads::default();
        let check = |replace: &[(&str, Option<&str>)]| {
            let text = config_yaml::<Minimal>("minimal", replace);
            check_config::<Minimal>(&reads, &case(dir.path(), "minimal", Some(&text)), 0)
        };
        for (name, value) in [
            ("PRESET_BASE", "'mainnet'"),
            ("GENESIS_FORK_VERSION", "0x00000000"),
            ("GENESIS_FORK_VERSION", "0x100000001"),
            ("CAPELLA_FORK_VERSION", "0x03000000"),
            ("SHARD_COMMITTEE_PERIOD", "256"),
            ("SHARD_COMMITTEE_PERIOD", "-1"),
            ("EJECTION_BALANCE", "1"),
            ("MIN_BUILDER_WITHDRAWABILITY_DELAY", "3"),
            ("GLOAS_FORK_EPOCH", "-1"),
            ("GLOAS_FORK_EPOCH", "x"),
        ] {
            let err = check(&[(name, Some(value))]).unwrap_err();
            assert!(err.contains(name), "{name}: {err}");
        }
        for name in [
            "PRESET_BASE",
            "GENESIS_FORK_VERSION",
            "CAPELLA_FORK_VERSION",
            "SHARD_COMMITTEE_PERIOD",
            "INACTIVITY_SCORE_BIAS",
            "GLOAS_FORK_EPOCH",
        ] {
            let err = check(&[(name, None)]).unwrap_err();
            assert_eq!(err, format!("config.yaml: missing `{name}`"));
        }
        // A file that is not YAML, and a preset without a config.
        let err =
            check_config::<Minimal>(&reads, &case(dir.path(), "minimal", Some(": :\n- [")), 0)
                .unwrap_err();
        assert!(err.contains("config.yaml"), "{err}");
        let text = config_yaml::<Minimal>("minimal", &[("PRESET_BASE", Some("'general'"))]);
        let err = check_config::<Minimal>(&reads, &case(dir.path(), "general", Some(&text)), 0)
            .unwrap_err();
        assert!(err.contains("general"), "{err}");
    }
}
