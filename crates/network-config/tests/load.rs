//! Loading the pinned eth-clients configs: digest check, parsing and blob parameters.

use network_config::{BlobParameters, ChainConfig, ConfigError, ForkName, Network};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Parses `yaml` with its own digest, so only the parser and validation are exercised.
fn parse(yaml: &str) -> Result<ChainConfig, ConfigError> {
    ChainConfig::from_yaml(yaml.as_bytes(), &sha256(yaml.as_bytes()))
}

const MINIMAL_CONFIG: &str = "\
PRESET_BASE: 'mainnet'
CONFIG_NAME: 'devnet'
GENESIS_FORK_VERSION: 0x00000001
ELECTRA_FORK_VERSION: 0x05000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x06000001
FULU_FORK_EPOCH: 10
GLOAS_FORK_VERSION: 0x07000001
GLOAS_FORK_EPOCH: 20
SLOT_DURATION_MS: 12000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
";

fn with_blob_schedule(schedule: &str) -> String {
    format!("{MINIMAL_CONFIG}BLOB_SCHEDULE:{schedule}")
}

proptest! {
    #[test]
    fn rejects_tampered_config(
        network in prop_oneof![Just(Network::Sepolia), Just(Network::Hoodi)],
        position in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let mut yaml = network.embedded_config().to_vec();
        let i = position.index(yaml.len());
        yaml[i] ^= flip;
        let err = ChainConfig::load_from(network, &yaml).unwrap_err();
        prop_assert!(matches!(err, ConfigError::DigestMismatch { .. }), "{err:?}");
    }
}

#[test]
fn untampered_configs_load() {
    for network in Network::ALL {
        let config = ChainConfig::load(network).unwrap();
        assert_eq!(config.config_name(), network.name());
        assert_eq!(config.preset_base(), "mainnet");
        assert_eq!(
            ChainConfig::load_from(network, network.embedded_config()).unwrap(),
            config
        );
    }
}

#[test]
fn sepolia_schedule_matches_pinned_config() {
    let config = ChainConfig::load(Network::Sepolia).unwrap();
    let schedule = config.fork_schedule();
    assert_eq!(schedule.fork_epoch(ForkName::Fulu), Some(272_640));
    assert_eq!(schedule.fork_epoch(ForkName::Gloas), Some(353_024));
    assert_eq!(schedule.fork_version(ForkName::Fulu), [0x90, 0, 0, 0x75]);
    assert_eq!(schedule.fork_version(ForkName::Gloas), [0x90, 0, 0, 0x76]);
    assert_eq!(schedule.fork_at(272_639), None);
    assert_eq!(schedule.fork_at(272_640), Some(ForkName::Fulu));
    assert_eq!(schedule.fork_at(353_023), Some(ForkName::Fulu));
    assert_eq!(schedule.fork_at(353_024), Some(ForkName::Gloas));
    assert_eq!(schedule.fork_at(u64::MAX), Some(ForkName::Gloas));
    assert_eq!(config.genesis_fork_version(), [0x90, 0, 0, 0x69]);
    assert_eq!(config.slot_duration_ms(), 12_000);
    assert_eq!(config.max_payload_size(), 10_485_760);
    assert_eq!(config.max_blobs_per_block_electra(), 9);
    assert_eq!(config.get("DEPOSIT_CHAIN_ID"), Some("11155111"));
    assert_eq!(config.get("NO_SUCH_KEY"), None);
}

#[test]
fn hoodi_schedule_matches_pinned_config() {
    let config = ChainConfig::load(Network::Hoodi).unwrap();
    assert_eq!(config.max_blobs_per_block_electra(), 9);
    let schedule = *config.fork_schedule();
    assert_eq!(schedule.fork_epoch(ForkName::Fulu), Some(50_688));
    assert_eq!(schedule.fork_epoch(ForkName::Gloas), Some(132_352));
    assert_eq!(schedule.fork_at(132_351), Some(ForkName::Fulu));
    assert_eq!(schedule.fork_at(132_352), Some(ForkName::Gloas));
}

#[test]
fn get_blob_parameters_follows_schedule() {
    let config = ChainConfig::load(Network::Sepolia).unwrap();
    let params = |epoch| config.get_blob_parameters(epoch);
    let electra = BlobParameters {
        epoch: 222_464,
        max_blobs_per_block: 9,
    };
    assert_eq!(params(0), electra);
    assert_eq!(params(274_175), electra);
    assert_eq!(
        params(274_176),
        BlobParameters {
            epoch: 274_176,
            max_blobs_per_block: 15
        }
    );
    assert_eq!(params(275_711).max_blobs_per_block, 15);
    assert_eq!(
        params(275_712),
        BlobParameters {
            epoch: 275_712,
            max_blobs_per_block: 21
        }
    );
    assert_eq!(params(u64::MAX).max_blobs_per_block, 21);
}

#[test]
fn unsorted_blob_schedule_is_accepted() {
    let yaml = with_blob_schedule(
        "\n  - EPOCH: 30\n    MAX_BLOBS_PER_BLOCK: 21\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 15\n",
    );
    let config = parse(&yaml).unwrap();
    assert_eq!(config.get_blob_parameters(29).max_blobs_per_block, 15);
    assert_eq!(config.get_blob_parameters(30).max_blobs_per_block, 21);
    assert_eq!(config.blob_schedule().len(), 2);
}

#[test]
fn empty_blob_schedule_falls_back_to_electra() {
    let config = parse(&with_blob_schedule(" []\n")).unwrap();
    assert!(config.blob_schedule().is_empty());
    assert_eq!(
        config.get_blob_parameters(100),
        BlobParameters {
            epoch: 0,
            max_blobs_per_block: 9
        }
    );
    // A config without the key at all behaves the same.
    assert!(parse(MINIMAL_CONFIG).unwrap().blob_schedule().is_empty());
}

#[test]
fn far_future_gloas_is_never_scheduled() {
    let yaml = MINIMAL_CONFIG.replace(
        "GLOAS_FORK_EPOCH: 20",
        "GLOAS_FORK_EPOCH: 18446744073709551615",
    );
    let schedule = *parse(&yaml).unwrap().fork_schedule();
    assert_eq!(schedule.fork_epoch(ForkName::Gloas), None);
    assert_eq!(schedule.fork_at(u64::MAX - 1), Some(ForkName::Fulu));
}

#[test]
fn rejects_invalid_blob_schedules() {
    let cases = [
        (
            "\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 15\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 21\n",
            "duplicate",
        ),
        ("\n  - EPOCH: 9\n    MAX_BLOBS_PER_BLOCK: 15\n", "FULU_FORK_EPOCH"),
        ("\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 4097\n", "4096"),
        ("\n  - EPOCH: 10\n", "MAX_BLOBS_PER_BLOCK"),
        ("\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: x\n", "MAX_BLOBS_PER_BLOCK"),
        (
            "\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 1\n    EXTRA: 1\n",
            "EXTRA",
        ),
    ];
    for (schedule, needle) in cases {
        let err = parse(&with_blob_schedule(schedule)).unwrap_err();
        assert!(err.to_string().contains(needle), "{schedule:?}: {err}");
    }
}

#[test]
fn rejects_malformed_yaml() {
    let cases = [
        (
            format!("{MINIMAL_CONFIG}FULU_FORK_EPOCH: 11\n"),
            "duplicate",
        ),
        (format!("{MINIMAL_CONFIG}not yaml\n"), "line 13"),
        (format!("{MINIMAL_CONFIG}  INDENTED: 1\n"), "line 13"),
        (format!("{MINIMAL_CONFIG}LIST:\n  EPOCH: 1\n"), "line 14"),
        (format!("{MINIMAL_CONFIG}LIST:\n  - \n"), "line 14"),
        (format!("{MINIMAL_CONFIG}KEY: 'unterminated\n"), "line 13"),
        (format!("{MINIMAL_CONFIG}: 1\n"), "line 13"),
        ("\u{feff}\u{fffd}".to_owned(), "line 1"),
        // Malformed blob schedules: `-` must be followed by a space, records must share one
        // item indentation, and record fields must line up under the first field.
        (
            with_blob_schedule("\n  -EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 15\n"),
            "line 14",
        ),
        (
            with_blob_schedule(
                "\n  - EPOCH: 10\n    MAX_BLOBS_PER_BLOCK: 15\n    - EPOCH: 11\n      MAX_BLOBS_PER_BLOCK: 21\n",
            ),
            "line 16",
        ),
        (
            with_blob_schedule("\n  - EPOCH: 10\n   MAX_BLOBS_PER_BLOCK: 15\n"),
            "line 15",
        ),
        (
            with_blob_schedule("\n  - EPOCH: 10\n      MAX_BLOBS_PER_BLOCK: 15\n"),
            "line 15",
        ),
        (
            with_blob_schedule("\n\t- EPOCH: 10\n\t  MAX_BLOBS_PER_BLOCK: 15\n"),
            "line 14",
        ),
    ];
    for (yaml, needle) in cases {
        let err = parse(&yaml).unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "{yaml:?}: {err:?}"
        );
        assert!(err.to_string().contains(needle), "{yaml:?}: {err}");
    }
    let not_utf8 = [0xff, 0xfe];
    assert!(matches!(
        ChainConfig::from_yaml(&not_utf8, &sha256(&not_utf8)),
        Err(ConfigError::Parse { line: 0, .. })
    ));
}

#[test]
fn rejects_missing_or_invalid_values() {
    let missing = MINIMAL_CONFIG.replace("FULU_FORK_EPOCH: 10\n", "");
    assert_eq!(
        parse(&missing).unwrap_err(),
        ConfigError::Missing("FULU_FORK_EPOCH")
    );
    let cases = [
        ("FULU_FORK_EPOCH: 10", "FULU_FORK_EPOCH: ten"),
        ("FULU_FORK_VERSION: 0x06000001", "FULU_FORK_VERSION: 0x0600"),
        (
            "FULU_FORK_VERSION: 0x06000001",
            "FULU_FORK_VERSION: 06000001",
        ),
        (
            "FULU_FORK_VERSION: 0x06000001",
            "FULU_FORK_VERSION: 0x0600000g",
        ),
        ("GLOAS_FORK_EPOCH: 20", "GLOAS_FORK_EPOCH: 9"),
    ];
    for (from, to) in cases {
        let err = parse(&MINIMAL_CONFIG.replace(from, to)).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{to}: {err:?}");
    }
    let scalar_list = format!("{MINIMAL_CONFIG}BLOB_SCHEDULE: 3\n");
    assert!(matches!(
        parse(&scalar_list).unwrap_err(),
        ConfigError::Invalid {
            key: "BLOB_SCHEDULE",
            ..
        }
    ));
    let list_scalar =
        MINIMAL_CONFIG.replace("SLOT_DURATION_MS: 12000\n", "SLOT_DURATION_MS:\n  - A: 1\n");
    assert!(matches!(
        parse(&list_scalar).unwrap_err(),
        ConfigError::Invalid {
            key: "SLOT_DURATION_MS",
            ..
        }
    ));
}

#[test]
fn network_names_round_trip() {
    for network in Network::ALL {
        assert_eq!(network.name().parse::<Network>(), Ok(network));
        assert_eq!(network.to_string(), network.name());
    }
    assert!("mainnet".parse::<Network>().is_err());
}

#[test]
fn large_blob_schedule_loads() {
    let schedule: String = (0..30_000u64)
        .map(|i| {
            format!(
                "\n  - EPOCH: {}\n    MAX_BLOBS_PER_BLOCK: {}",
                10 + i,
                i % 4096
            )
        })
        .collect();
    let config = parse(&with_blob_schedule(&format!("{schedule}\n"))).unwrap();
    assert_eq!(config.blob_schedule().len(), 30_000);
    assert_eq!(
        config.get_blob_parameters(30_009).max_blobs_per_block,
        29_999 % 4096
    );
}

#[test]
fn capella_fork_version_matches_the_pinned_configs() {
    let version = |network| {
        ChainConfig::load(network)
            .unwrap()
            .capella_fork_version()
            .unwrap()
    };
    assert_eq!(version(Network::Sepolia), [0x90, 0, 0, 0x72]);
    assert_eq!(version(Network::Hoodi), [0x40, 0, 0x09, 0x10]);
    let devnet = parse(&format!(
        "{MINIMAL_CONFIG}CAPELLA_FORK_VERSION: 0x03000001\n"
    ))
    .unwrap();
    assert_eq!(devnet.capella_fork_version(), Ok([0x03, 0, 0, 0x01]));
}

#[test]
fn a_missing_capella_fork_version_is_an_error_of_the_accessor() {
    // A config without the key loads: the fixture devnets of the other crates do not have it.
    // The caller that builds the BLS context gets the error that names the key.
    let config = parse(MINIMAL_CONFIG).unwrap();
    assert_eq!(
        config.capella_fork_version(),
        Err(ConfigError::Missing("CAPELLA_FORK_VERSION"))
    );
}

#[test]
fn a_malformed_capella_fork_version_fails_the_load() {
    for value in ["0x0300", "03000001", "0x0300000g"] {
        let yaml = format!("{MINIMAL_CONFIG}CAPELLA_FORK_VERSION: {value}\n");
        let err = parse(&yaml).unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "CAPELLA_FORK_VERSION",
                    ..
                }
            ),
            "{value}: {err:?}"
        );
    }
}
