//! `ChainConfig::check_compiled_values`: the config values that the node compiles in, compared
//! with the loaded network config.

use network_config::{ChainConfig, ConfigError, Network};
use sha2::{Digest, Sha256};

/// Parses `yaml` with its own digest.
fn parse(yaml: &str) -> ChainConfig {
    let sha256: [u8; 32] = Sha256::digest(yaml.as_bytes()).into();
    ChainConfig::from_yaml(yaml.as_bytes(), &sha256).unwrap()
}

const CONFIG: &str = "\
PRESET_BASE: 'mainnet'
CONFIG_NAME: 'devnet'
GENESIS_FORK_VERSION: 0x00000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x06000001
FULU_FORK_EPOCH: 10
GLOAS_FORK_VERSION: 0x07000001
GLOAS_FORK_EPOCH: 20
SLOT_DURATION_MS: 12000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
SHARD_COMMITTEE_PERIOD: 256
EJECTION_BALANCE: 16000000000
";

const COMPILED: [(&str, u64); 2] = [
    ("SHARD_COMMITTEE_PERIOD", 256),
    ("EJECTION_BALANCE", 16_000_000_000),
];

#[test]
fn equal_values_pass() {
    assert_eq!(parse(CONFIG).check_compiled_values(&COMPILED), Ok(()));
    assert_eq!(parse(CONFIG).check_compiled_values(&[]), Ok(()));
}

#[test]
fn a_value_that_differs_names_the_key_and_both_values() {
    let config = parse(&CONFIG.replace("EJECTION_BALANCE: 16000000000", "EJECTION_BALANCE: 1"));
    let err = config.check_compiled_values(&COMPILED).unwrap_err();
    assert_eq!(
        err,
        ConfigError::CompiledMismatch {
            key: "EJECTION_BALANCE",
            config: 1,
            compiled: 16_000_000_000,
        }
    );
    let text = err.to_string();
    for part in ["EJECTION_BALANCE", "= 1,", "16000000000"] {
        assert!(text.contains(part), "{part}: {text}");
    }
}

#[test]
fn a_missing_key_fails() {
    let config = parse(&CONFIG.replace("SHARD_COMMITTEE_PERIOD: 256\n", ""));
    assert_eq!(
        config.check_compiled_values(&COMPILED),
        Err(ConfigError::Missing("SHARD_COMMITTEE_PERIOD"))
    );
}

#[test]
fn a_value_that_is_not_a_uint64_fails() {
    for value in ["-1", "2**8", "18446744073709551616", "0x100"] {
        let yaml = CONFIG.replace(
            "SHARD_COMMITTEE_PERIOD: 256",
            &format!("SHARD_COMMITTEE_PERIOD: {value}"),
        );
        let err = parse(&yaml).check_compiled_values(&COMPILED).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "SHARD_COMMITTEE_PERIOD",
                    ..
                }
            ),
            "{value}: {err:?}"
        );
    }
}

#[test]
fn the_pinned_networks_have_the_mainnet_values_of_the_compared_keys() {
    for network in Network::ALL {
        let config = ChainConfig::load(network).unwrap();
        assert_eq!(config.check_compiled_values(&COMPILED), Ok(()), "{network}");
    }
}
