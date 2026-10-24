//! Reading a devnet's genesis data from one directory: `config.yaml` through the strict reader
//! over its own sha256, and the genesis from the first two fields of `genesis.ssz`.

use std::path::{Path, PathBuf};

use network_config::network_dir::{
    genesis_from_state, read_config, read_genesis, NetworkDir, NetworkDirError, CONFIG_FILE,
    GENESIS_PREFIX_BYTES, GENESIS_STATE_FILE, MAX_CONFIG_BYTES,
};
use network_config::{ChainConfig, ConfigError, Genesis};

const CONFIG: &str = "\
PRESET_BASE: 'minimal'
CONFIG_NAME: 'fixture-devnet'
GENESIS_FORK_VERSION: 0x00000001
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x60000001
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x70000001
GLOAS_FORK_EPOCH: 2
SLOT_DURATION_MS: 6000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
BLOB_SCHEDULE:
  - EPOCH: 1
    MAX_BLOBS_PER_BLOCK: 12
";

const GENESIS: Genesis = Genesis {
    genesis_time: 1_760_800_000,
    genesis_validators_root: [0x42; 32],
};

/// A fresh directory for `name` under cargo's scratch directory for integration tests.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("network-dir")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The first 40 bytes of a genesis state with `genesis`, then `extra` filler bytes.
fn state(genesis: Genesis, extra: usize) -> Vec<u8> {
    let mut ssz = genesis.genesis_time.to_le_bytes().to_vec();
    ssz.extend_from_slice(&genesis.genesis_validators_root);
    ssz.extend(std::iter::repeat_n(0xee, extra));
    ssz
}

#[test]
fn the_genesis_is_the_states_first_two_fields() {
    assert_eq!(genesis_from_state(&state(GENESIS, 100)), Ok(GENESIS));
    assert_eq!(genesis_from_state(&state(GENESIS, 0)), Ok(GENESIS));
    let short = &state(GENESIS, 0)[..GENESIS_PREFIX_BYTES - 1];
    let err = genesis_from_state(short).unwrap_err();
    assert!(err.to_string().contains("39 bytes"), "{err}");
}

#[test]
fn the_genesis_file_is_read_by_its_prefix() {
    let dir = scratch("genesis");
    let path = dir.join(GENESIS_STATE_FILE);
    std::fs::write(&path, state(GENESIS, 4096)).unwrap();
    assert_eq!(read_genesis(&path).unwrap(), GENESIS);
    let missing = dir.join("missing.ssz");
    let err = read_genesis(&missing).unwrap_err();
    assert!(matches!(err, NetworkDirError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("missing.ssz"), "{err}");
    std::fs::write(&path, [1, 2, 3]).unwrap();
    let err = read_genesis(&path).unwrap_err().to_string();
    assert!(
        err.contains("3 bytes") && err.contains("genesis.ssz"),
        "{err}"
    );
}

#[test]
fn the_config_file_is_bounded() {
    let dir = scratch("config");
    let path = dir.join(CONFIG_FILE);
    std::fs::write(&path, CONFIG).unwrap();
    assert_eq!(read_config(&path).unwrap(), CONFIG.as_bytes());
    std::fs::write(&path, vec![b'#'; MAX_CONFIG_BYTES as usize + 1]).unwrap();
    let err = read_config(&path).unwrap_err();
    assert!(matches!(err, NetworkDirError::TooLarge { .. }), "{err:?}");
    assert!(err.to_string().contains("over"), "{err}");
    assert!(read_config(&dir.join("none.yaml")).is_err());
}

#[test]
fn a_devnet_config_is_read_strictly_over_its_own_digest() {
    let config = ChainConfig::from_devnet_yaml(CONFIG.as_bytes()).unwrap();
    assert_eq!(config.config_name(), "fixture-devnet");
    assert_eq!(config.blob_schedule().len(), 1);
    let broken = CONFIG.replace("FULU_FORK_EPOCH: 0", "FULU_FORK_EPOCH: x");
    assert!(matches!(
        ChainConfig::from_devnet_yaml(broken.as_bytes()),
        Err(ConfigError::Invalid { .. } | ConfigError::Parse { .. })
    ));
}

#[test]
fn a_network_dir_gives_the_config_and_the_genesis() {
    let dir = scratch("dir");
    std::fs::write(dir.join(CONFIG_FILE), CONFIG).unwrap();
    std::fs::write(dir.join(GENESIS_STATE_FILE), state(GENESIS, 64)).unwrap();
    let net = NetworkDir::read(&dir).unwrap();
    assert_eq!(net.genesis, GENESIS);
    assert_eq!(
        net.config,
        ChainConfig::from_devnet_yaml(CONFIG.as_bytes()).unwrap()
    );
}

#[test]
fn a_network_dir_without_a_file_or_with_a_bad_config_is_refused() {
    let dir = scratch("refused");
    let err = NetworkDir::read(&dir).unwrap_err().to_string();
    assert!(err.contains(CONFIG_FILE), "{err}");

    std::fs::write(dir.join(CONFIG_FILE), CONFIG).unwrap();
    let err = NetworkDir::read(&dir).unwrap_err().to_string();
    assert!(err.contains(GENESIS_STATE_FILE), "{err}");

    std::fs::write(dir.join(GENESIS_STATE_FILE), state(GENESIS, 0)).unwrap();
    std::fs::write(
        dir.join(CONFIG_FILE),
        CONFIG.replace("SLOT_DURATION_MS", "X"),
    )
    .unwrap();
    let err = NetworkDir::read(&dir).unwrap_err();
    assert!(matches!(err, NetworkDirError::Config { .. }), "{err:?}");
    assert!(err.to_string().contains(CONFIG_FILE), "{err}");
}
