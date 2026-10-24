//! A devnet's genesis data in one directory, as the genesis generator writes it: `config.yaml`
//! and `genesis.ssz` ([`NetworkDir::read`]).
//!
//! The config goes through the strict reader ([`ChainConfig::from_devnet_yaml`], over the bytes'
//! own sha256: a devnet has no pinned digest). The genesis is read from the genesis state: its
//! first two fields, `genesis_time` and `genesis_validators_root`, are both fixed-size, so they
//! are its first [`GENESIS_PREFIX_BYTES`] bytes in every fork ([`genesis_from_state`]).

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::chain_config::{ChainConfig, ConfigError, Genesis};

/// The config file of a network directory.
pub const CONFIG_FILE: &str = "config.yaml";

/// The genesis state of a network directory.
pub const GENESIS_STATE_FILE: &str = "genesis.ssz";

/// The largest `config.yaml` read: far above any network's.
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// The bytes of a genesis state that hold `genesis_time` (8) and `genesis_validators_root` (32).
pub const GENESIS_PREFIX_BYTES: usize = 40;

/// A genesis state shorter than [`GENESIS_PREFIX_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a genesis state is at least {GENESIS_PREFIX_BYTES} bytes, this one {got} bytes")]
pub struct ShortGenesisState {
    /// The bytes there were.
    pub got: usize,
}

/// Why a network directory or one of its files could not be read.
#[derive(Debug, thiserror::Error)]
pub enum NetworkDirError {
    /// The file cannot be opened or read.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The read error.
        #[source]
        source: io::Error,
    },
    /// The config is over [`MAX_CONFIG_BYTES`].
    #[error("{}: over {MAX_CONFIG_BYTES} bytes", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
    },
    /// The genesis state is too short.
    #[error("{}: {source}", path.display())]
    Genesis {
        /// The file.
        path: PathBuf,
        /// How short it is.
        #[source]
        source: ShortGenesisState,
    },
    /// The config does not parse.
    #[error("{}: {source}", path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// The parse error.
        #[source]
        source: ConfigError,
    },
}

/// A network directory, read: its config and its genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDir {
    /// `DIR/config.yaml`, parsed.
    pub config: ChainConfig,
    /// The genesis of `DIR/genesis.ssz`.
    pub genesis: Genesis,
}

impl NetworkDir {
    /// Reads `dir/config.yaml` ([`read_config`], [`ChainConfig::from_devnet_yaml`]) and
    /// `dir/genesis.ssz` ([`read_genesis`]).
    ///
    /// # Errors
    ///
    /// A file cannot be read, the config is too large or does not parse, or the genesis state
    /// is too short. The error names the file.
    pub fn read(dir: &Path) -> Result<Self, NetworkDirError> {
        let config_path = dir.join(CONFIG_FILE);
        let yaml = read_config(&config_path)?;
        let config =
            ChainConfig::from_devnet_yaml(&yaml).map_err(|source| NetworkDirError::Config {
                path: config_path,
                source,
            })?;
        let genesis = read_genesis(&dir.join(GENESIS_STATE_FILE))?;
        Ok(Self { config, genesis })
    }
}

impl ChainConfig {
    /// Parses a devnet's `yaml` with the strict reader. A devnet has no pinned digest, so the
    /// digest check is over the bytes' own sha256: only the parser and the validation apply.
    ///
    /// # Errors
    ///
    /// The config does not parse or is not valid.
    pub fn from_devnet_yaml(yaml: &[u8]) -> Result<Self, ConfigError> {
        let sha256: [u8; 32] = Sha256::digest(yaml).into();
        Self::from_yaml(yaml, &sha256)
    }
}

/// The genesis of a genesis state's SSZ: its first two fields.
///
/// # Errors
///
/// Fewer than [`GENESIS_PREFIX_BYTES`] bytes.
pub fn genesis_from_state(ssz: &[u8]) -> Result<Genesis, ShortGenesisState> {
    let Some(prefix) = ssz.get(..GENESIS_PREFIX_BYTES) else {
        return Err(ShortGenesisState { got: ssz.len() });
    };
    let (time, root) = prefix.split_at(8);
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(time);
    let mut genesis_validators_root = [0u8; 32];
    genesis_validators_root.copy_from_slice(root);
    Ok(Genesis {
        genesis_time: u64::from_le_bytes(time_bytes),
        genesis_validators_root,
    })
}

/// The genesis of the genesis state at `path`, from its first [`GENESIS_PREFIX_BYTES`] bytes.
///
/// # Errors
///
/// The file cannot be read or is too short.
pub fn read_genesis(path: &Path) -> Result<Genesis, NetworkDirError> {
    let mut prefix = Vec::with_capacity(GENESIS_PREFIX_BYTES);
    File::open(path)
        .and_then(|f| f.take(GENESIS_PREFIX_BYTES as u64).read_to_end(&mut prefix))
        .map_err(|source| NetworkDirError::Io {
            path: path.to_owned(),
            source,
        })?;
    genesis_from_state(&prefix).map_err(|source| NetworkDirError::Genesis {
        path: path.to_owned(),
        source,
    })
}

/// The bytes of the `config.yaml` at `path`, reading at most one byte past
/// [`MAX_CONFIG_BYTES`].
///
/// # Errors
///
/// The file cannot be read or is too large.
pub fn read_config(path: &Path) -> Result<Vec<u8>, NetworkDirError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|f| f.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|source| NetworkDirError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(NetworkDirError::TooLarge {
            path: path.to_owned(),
        });
    }
    Ok(bytes)
}
