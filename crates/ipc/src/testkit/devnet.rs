//! The fixture devnets that the network-hello tests share: their `config.yaml`, their genesis
//! and their [`NetworkHello`].
//!
//! - [`DEVNET_CONFIG`]: Fulu from genesis, a blob change to 12 at epoch 1, Gloas at epoch 2. Its
//!   digest changes at epochs 1 and 2, for the tests that cross a digest change.
//! - [`KURTOSIS_CONFIG`]: the shape of our Kurtosis devnet. Fulu and Gloas are both at epoch 0,
//!   and the blob schedule gives 21 blobs from epoch 0. Its fork schedule has one entry, and that
//!   entry is labelled Gloas.
//!
//! Both have the minimal preset (8-slot epochs) and 6 s slots, as the Kurtosis genesis generator
//! writes them. They share [`DEVNET_GENESIS`], which is in the past, so the wall clock is in
//! Gloas.

use network_config::{ChainConfig, Genesis};

use crate::hello::NetworkHello;

/// The devnet's `config.yaml`.
pub const DEVNET_CONFIG: &str = "\
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

/// The shape of our Kurtosis devnet: Fulu and Gloas at epoch 0, 21 blobs from epoch 0.
pub const KURTOSIS_CONFIG: &str = "\
PRESET_BASE: 'minimal'
CONFIG_NAME: 'testnet'
GENESIS_FORK_VERSION: 0x10000038
ELECTRA_FORK_VERSION: 0x60000038
ELECTRA_FORK_EPOCH: 0
FULU_FORK_VERSION: 0x70000038
FULU_FORK_EPOCH: 0
GLOAS_FORK_VERSION: 0x80000038
GLOAS_FORK_EPOCH: 0
SLOT_DURATION_MS: 6000
MAX_PAYLOAD_SIZE: 10485760
MAX_BLOBS_PER_BLOCK_ELECTRA: 9
BLOB_SCHEDULE:
  - EPOCH: 0
    MAX_BLOBS_PER_BLOCK: 21
";

/// The largest blob count of [`KURTOSIS_CONFIG`].
pub const KURTOSIS_MAX_BLOBS: u64 = 21;

/// The devnets' genesis.
pub const DEVNET_GENESIS: Genesis = Genesis {
    genesis_time: 1_760_800_000,
    genesis_validators_root: [0x42; 32],
};

/// The slot duration of [`DEVNET_CONFIG`] in milliseconds.
pub const DEVNET_SLOT_MS: u64 = 6_000;

/// [`DEVNET_CONFIG`] with `from` replaced by `to`, parsed by the strict reader. Panics if the
/// edited config does not parse.
#[must_use]
pub fn devnet_config_with(from: &str, to: &str) -> ChainConfig {
    ChainConfig::from_devnet_yaml(DEVNET_CONFIG.replace(from, to).as_bytes())
        .expect("the edited fixture devnet config parses")
}

/// [`DEVNET_CONFIG`], parsed by the strict reader.
#[must_use]
pub fn devnet_config() -> ChainConfig {
    ChainConfig::from_devnet_yaml(DEVNET_CONFIG.as_bytes())
        .expect("the fixture devnet config parses")
}

/// [`KURTOSIS_CONFIG`], parsed by the strict reader.
#[must_use]
pub fn kurtosis_config() -> ChainConfig {
    ChainConfig::from_devnet_yaml(KURTOSIS_CONFIG.as_bytes())
        .expect("the fixture Kurtosis config parses")
}

/// The network hello of [`KURTOSIS_CONFIG`], sent with `build`.
#[must_use]
pub fn kurtosis_hello(build: &str) -> NetworkHello {
    NetworkHello::new(build, &kurtosis_config(), DEVNET_GENESIS)
        .expect("the fixture Kurtosis devnet has a network hello")
}

/// The devnet's network hello, sent with `build`.
#[must_use]
pub fn devnet_hello(build: &str) -> NetworkHello {
    NetworkHello::new(build, &devnet_config(), DEVNET_GENESIS)
        .expect("the fixture devnet has a network hello")
}

/// Unix milliseconds at the start of `slot` of the devnet.
#[must_use]
pub fn devnet_ms(slot: u64) -> u64 {
    DEVNET_GENESIS.genesis_time * 1000 + slot * DEVNET_SLOT_MS
}

/// The bytes of a genesis state of the devnet: the genesis time and the genesis validators
/// root (its first two fields), then `extra` filler bytes.
#[must_use]
pub fn devnet_genesis_state(extra: usize) -> Vec<u8> {
    let mut state = DEVNET_GENESIS.genesis_time.to_le_bytes().to_vec();
    state.extend_from_slice(&DEVNET_GENESIS.genesis_validators_root);
    state.extend(std::iter::repeat_n(0xee, extra));
    state
}

/// Writes `bytes` to `path` with mode 0644, as the readers of a network directory accept a
/// file: a umask of 002 would leave the group able to write it. Panics if it cannot.
pub fn write_network_file(path: impl AsRef<std::path::Path>, bytes: impl AsRef<[u8]>) {
    use std::os::unix::fs::PermissionsExt;
    let path = path.as_ref();
    std::fs::write(path, bytes).expect("the network file is written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        .expect("the network file mode is set");
}
