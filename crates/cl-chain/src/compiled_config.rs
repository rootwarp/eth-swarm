//! The startup check of the config values that the state transition compiles in.
//!
//! The state transition holds some config values (`configs/*.yaml`) as constants: the churn
//! and builder values, `SHARD_COMMITTEE_PERIOD`, `EJECTION_BALANCE` and others
//! ([`state_transition::preset::config_values`]). A network with other values gives other exit
//! and withdrawability epochs, and thus another state root. [`check_compiled_config`] compares
//! each of these values with the loaded network config, and a difference stops the start.
//!
//! The values that are different on each network (`GENESIS_FORK_VERSION`,
//! `CAPELLA_FORK_VERSION` and `BLOB_SCHEDULE`) are not constants. cl-chain gives them to the
//! transition through `state_transition::BlsContext`, from the same config.

use network_config::{ChainConfig, ConfigError};
use state_transition::preset::config_values;
use state_transition::Preset;

/// Compares each config value that the state transition of preset `P` compiles in with
/// `config`.
///
/// Call this at startup, after the network config loads and before cl-chain builds the
/// `BlsContext` or runs the state transition.
///
/// # Errors
///
/// The first compiled key that `config` does not have, that is not a uint64, or that has
/// another value ([`ConfigError::CompiledMismatch`] names the key, the config value and the
/// compiled value).
pub fn check_compiled_config<P: Preset>(config: &ChainConfig) -> Result<(), ConfigError> {
    config.check_compiled_values(&config_values::<P>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::{Mainnet, Minimal};
    use network_config::Network;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// A devnet config of the minimal preset, with the values of `configs/minimal.yaml` at
    /// consensus-specs v1.7.0-beta.4 for each compared key.
    const MINIMAL_DEVNET: &str = "\
PRESET_BASE: 'minimal'
CONFIG_NAME: 'fixture-devnet'
GENESIS_FORK_VERSION: 0x00000001
CAPELLA_FORK_VERSION: 0x03000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x60000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x70000001
GLOAS_FORK_EPOCH: 0
SLOT_DURATION_MS: 6000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
MIN_VALIDATOR_WITHDRAWABILITY_DELAY: 256
SHARD_COMMITTEE_PERIOD: 64
INACTIVITY_SCORE_BIAS: 4
INACTIVITY_SCORE_RECOVERY_RATE: 16
EJECTION_BALANCE: 16000000000
MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA: 64000000000
CHURN_LIMIT_QUOTIENT_GLOAS: 16
CONSOLIDATION_CHURN_LIMIT_QUOTIENT: 32
MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS: 128000000000
MIN_BUILDER_WITHDRAWABILITY_DELAY: 2
";

    /// The constants of the state transition that hold a config value, but are not
    /// transition constants: the fixture arguments of the `testing` module, which the tests give
    /// through `BlsContext`. The file is relative to `crates/state-transition/src`.
    const NOT_COMPILED: [(&str, &str); 3] = [
        ("testing.rs", "GENESIS_FORK_VERSION"),
        ("testing.rs", "CAPELLA_FORK_VERSION"),
        ("testing.rs", "MINIMAL_MAX_BLOBS_PER_BLOCK"),
    ];

    fn devnet(yaml: &str) -> ChainConfig {
        ChainConfig::from_devnet_yaml(yaml.as_bytes()).unwrap()
    }

    #[test]
    fn the_pinned_sepolia_hoodi_and_devnet_configs_pass() {
        for network in Network::ALL {
            let config = ChainConfig::load(network).unwrap();
            assert_eq!(
                check_compiled_config::<Mainnet>(&config),
                Ok(()),
                "{network}"
            );
        }
        assert_eq!(
            check_compiled_config::<Minimal>(&devnet(MINIMAL_DEVNET)),
            Ok(())
        );
    }

    #[test]
    fn a_config_that_differs_in_one_key_fails_startup() {
        for (key, compiled) in config_values::<Minimal>() {
            let line = format!("{key}: {compiled}\n");
            assert!(MINIMAL_DEVNET.contains(&line), "{key}");
            let other = compiled + 1;
            let config = devnet(&MINIMAL_DEVNET.replace(&line, &format!("{key}: {other}\n")));
            let err = check_compiled_config::<Minimal>(&config).unwrap_err();
            assert_eq!(
                err,
                ConfigError::CompiledMismatch {
                    key,
                    config: other,
                    compiled,
                }
            );
            let text = err.to_string();
            for part in [key.to_owned(), other.to_string(), compiled.to_string()] {
                assert!(text.contains(&part), "{part}: {text}");
            }
        }
    }

    #[test]
    fn a_config_without_a_compared_key_fails_startup() {
        let line = "SHARD_COMMITTEE_PERIOD: 64\n";
        let config = devnet(&MINIMAL_DEVNET.replace(line, ""));
        assert_eq!(
            check_compiled_config::<Minimal>(&config),
            Err(ConfigError::Missing("SHARD_COMMITTEE_PERIOD"))
        );
    }

    #[test]
    fn the_config_of_the_other_preset_fails_startup() {
        let sepolia = ChainConfig::load(Network::Sepolia).unwrap();
        let err = check_compiled_config::<Minimal>(&sepolia).unwrap_err();
        assert!(
            matches!(err, ConfigError::CompiledMismatch { .. }),
            "{err:?}"
        );
        let err = check_compiled_config::<Mainnet>(&devnet(MINIMAL_DEVNET)).unwrap_err();
        assert!(
            matches!(err, ConfigError::CompiledMismatch { .. }),
            "{err:?}"
        );
    }

    /// Every key of the pinned network configs.
    fn config_keys() -> BTreeSet<String> {
        Network::ALL
            .into_iter()
            .flat_map(|n| {
                std::str::from_utf8(n.embedded_config())
                    .unwrap()
                    .lines()
                    .filter_map(|line| {
                        let (key, _) = line.split_once(':')?;
                        let top_level = key
                            .bytes()
                            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
                        (top_level && !key.is_empty()).then(|| key.to_owned())
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Every `.rs` file under `dir`.
    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The constants of `source` that hold a config value: the name is a key of a network
    /// config, or the doc comment cites `configs/`.
    fn config_constants(source: &str, keys: &BTreeSet<String>) -> Vec<String> {
        let mut found = Vec::new();
        let mut doc_cites_configs = false;
        for line in source.lines().map(str::trim_start) {
            if let Some(doc) = line.strip_prefix("///") {
                doc_cites_configs |= doc.contains("configs/");
                continue;
            }
            if line.starts_with("#[") {
                continue;
            }
            let declaration = ["pub const ", "pub(crate) const ", "const "]
                .iter()
                .find_map(|prefix| line.strip_prefix(prefix));
            if let Some(name) = declaration
                .and_then(|rest| rest.split_once(':'))
                .map(|(n, _)| n)
            {
                if keys.contains(name) || doc_cites_configs {
                    found.push(name.to_owned());
                }
            }
            doc_cites_configs = false;
        }
        found
    }

    /// The guard of the compared list: a new constant of the state transition (on `Preset` or
    /// in the crate) with a config value fails this test until it is in
    /// [`state_transition::preset::config_values`].
    #[test]
    fn every_config_constant_of_the_state_transition_is_compared() {
        let keys = config_keys();
        assert!(
            keys.contains("SHARD_COMMITTEE_PERIOD") && keys.len() > 50,
            "{keys:?}"
        );
        let compared: BTreeSet<&str> = config_values::<Mainnet>().iter().map(|(k, _)| *k).collect();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../state-transition/src");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        let mut seen = BTreeSet::new();
        let mut missing = BTreeSet::new();
        for file in files {
            let relative = file
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let source = std::fs::read_to_string(&file).unwrap();
            for name in config_constants(&source, &keys) {
                let excused = NOT_COMPILED.contains(&(relative.as_str(), name.as_str()));
                if compared.contains(name.as_str()) {
                    seen.insert(name);
                } else if !excused {
                    missing.insert(format!("{relative}: {name}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "constants with a config value that config_values does not compare: {missing:?}"
        );
        // The scan finds each compared key, so the guard cannot pass on an empty scan.
        let seen: BTreeSet<&str> = seen.iter().map(String::as_str).collect();
        assert_eq!(seen, compared);
    }

    #[test]
    fn the_scan_finds_a_config_constant_by_its_name_or_by_its_doc() {
        let keys = BTreeSet::from(["SHARD_COMMITTEE_PERIOD".to_owned()]);
        let source = "\
/// `NEW_VALUE` (`configs/{minimal,mainnet}.yaml`).
#[allow(dead_code)]
pub const NEW_VALUE: u64 = 1;
/// `MAX_SEED_LOOKAHEAD` (`presets/*/phase0.yaml`).
pub const MAX_SEED_LOOKAHEAD: u64 = 4;
trait T {
    const SHARD_COMMITTEE_PERIOD: u64;
}
";
        assert_eq!(
            config_constants(source, &keys),
            ["NEW_VALUE", "SHARD_COMMITTEE_PERIOD"]
        );
    }
}
