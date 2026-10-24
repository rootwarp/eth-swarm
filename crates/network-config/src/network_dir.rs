//! A devnet's genesis data in one directory, as the genesis generator writes it: `config.yaml`
//! and `genesis.ssz` ([`NetworkDir::read`]).
//!
//! The config goes through the strict reader ([`ChainConfig::from_devnet_yaml`], over the bytes'
//! own sha256: a devnet has no pinned digest). The genesis is read from the genesis state: its
//! first two fields, `genesis_time` and `genesis_validators_root`, are both fixed-size, so they
//! are its first [`GENESIS_PREFIX_BYTES`] bytes in every fork ([`genesis_from_state`]).
//!
//! Both files are read only as regular files, owned by the effective UID or root, that the
//! group and others cannot write ([`open_network_file`]). A symlink, a FIFO, a device or a
//! directory at the path is refused before it is opened, so a FIFO cannot block the start.
//! The symlink refusal also refuses a Kubernetes ConfigMap or Secret mount: the kubelet puts
//! each key there as a symlink into a `..data` directory. Copy such files into a directory of
//! regular files first.
//!
//! The directory itself is not checked. It must be writable only by its owner: another user
//! who can write it can rename a file away and put another one in its place.

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
    /// The path is not a regular file: a symlink, a FIFO, a directory or another type, or a
    /// file that was replaced while it was opened.
    #[error("{}: {what}, not a regular file", path.display())]
    NotRegular {
        /// The file.
        path: PathBuf,
        /// What is at the path.
        what: &'static str,
    },
    /// The file is owned by a user that is neither the effective UID nor root.
    #[error("{}: owned by uid {owner}, not by uid {euid} or root", path.display())]
    Owner {
        /// The file.
        path: PathBuf,
        /// Its owner.
        owner: u32,
        /// The effective UID of the process.
        euid: u32,
    },
    /// The group or others can write the file.
    #[error("{}: mode {mode:o} lets the group or others write it", path.display())]
    Writable {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
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
/// The file is not a regular file that only its owner can write ([`open_network_file`]),
/// cannot be read, or is too short.
pub fn read_genesis(path: &Path) -> Result<Genesis, NetworkDirError> {
    let mut prefix = Vec::with_capacity(GENESIS_PREFIX_BYTES);
    open_network_file(path)?
        .take(GENESIS_PREFIX_BYTES as u64)
        .read_to_end(&mut prefix)
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
/// The file is not a regular file that only its owner can write ([`open_network_file`]),
/// cannot be read, or is too large.
pub fn read_config(path: &Path) -> Result<Vec<u8>, NetworkDirError> {
    let mut bytes = Vec::new();
    open_network_file(path)?
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
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

/// Opens the file at `path` for reading if it is a regular file, owned by the effective UID or
/// root, that the group and others cannot write.
///
/// The `lstat` comes first and refuses anything but a regular file before any open: a
/// symlink, a FIFO, a socket, a directory or a device, which an open alone can act on. The
/// open then follows no symlink (`O_NOFOLLOW`: one swapped in after the `lstat`) and does not
/// block (`O_NONBLOCK`: a FIFO swapped in opens at once). The open file must still be a regular
/// file, the one that the `lstat` saw (same device and inode). Its owner must be the effective
/// UID or root, and its mode must have no group or other write bit. Every check after the open
/// is on the open file.
///
/// # Errors
///
/// [`NetworkDirError::NotRegular`], [`NetworkDirError::Owner`], [`NetworkDirError::Writable`],
/// or [`NetworkDirError::Io`] if the file cannot be examined or opened.
pub fn open_network_file(path: &Path) -> Result<File, NetworkDirError> {
    open_network_file_as(path, rustix::process::geteuid().as_raw())
}

/// [`open_network_file`] for the effective UID `euid`.
fn open_network_file_as(path: &Path, euid: u32) -> Result<File, NetworkDirError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let io = |source| NetworkDirError::Io {
        path: path.to_owned(),
        source,
    };
    let not_regular = |what| NetworkDirError::NotRegular {
        path: path.to_owned(),
        what,
    };
    let before = std::fs::symlink_metadata(path).map_err(io)?;
    let kind = before.file_type();
    if !kind.is_file() {
        return Err(not_regular(if kind.is_symlink() {
            "a symlink"
        } else if kind.is_dir() {
            "a directory"
        } else if kind.is_fifo() {
            "a FIFO"
        } else if kind.is_socket() {
            "a socket"
        } else if kind.is_char_device() || kind.is_block_device() {
            "a device"
        } else {
            "an unknown file type"
        }));
    }
    let file = open_no_follow(path)?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() || (meta.dev(), meta.ino()) != (before.dev(), before.ino()) {
        return Err(not_regular("a file replaced while it was opened"));
    }
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(NetworkDirError::Owner {
            path: path.to_owned(),
            owner: meta.uid(),
            euid,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(NetworkDirError::Writable {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(file)
}

/// Opens `path` read only with `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`: a symlink is
/// refused (`ELOOP`), a FIFO opens at once, and a terminal swapped in never becomes the
/// controlling terminal of the process.
fn open_no_follow(path: &Path) -> Result<File, NetworkDirError> {
    use rustix::fs::{Mode, OFlags};
    let flags =
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
    match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => Ok(File::from(fd)),
        Err(rustix::io::Errno::LOOP) => Err(NetworkDirError::NotRegular {
            path: path.to_owned(),
            what: "a symlink",
        }),
        Err(e) => Err(NetworkDirError::Io {
            path: path.to_owned(),
            source: e.into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory for `name` under the crate's target directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/network-dir-unit")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// The open itself follows no symlink: a symlink swapped in after the `lstat` is refused
    /// by the open, never read through.
    #[test]
    fn the_open_follows_no_symlink() {
        let dir = scratch("open-symlink");
        let target = dir.join("real");
        write_file(&target, b"x");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = open_no_follow(&link).unwrap_err();
        assert!(matches!(err, NetworkDirError::NotRegular { .. }), "{err:?}");
        assert!(err.to_string().contains("symlink"), "{err}");
        assert!(open_no_follow(&target).is_ok());
    }

    /// The open itself does not block: a FIFO swapped in after the `lstat` opens at once, and
    /// the checks on the open file then refuse it.
    #[test]
    fn the_open_does_not_block_on_a_fifo() {
        let dir = scratch("open-fifo");
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let (done, opened) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done.send(open_no_follow(&fifo).map(drop));
        });
        let opened = opened
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the open returned without blocking");
        assert!(opened.is_ok(), "{opened:?}");
    }

    /// The file must be owned by the effective UID or by root.
    #[test]
    fn a_file_of_another_owner_is_refused() {
        let dir = scratch("owner");
        let path = dir.join(CONFIG_FILE);
        write_file(&path, b"x");
        let me = rustix::process::geteuid().as_raw();
        assert!(open_network_file_as(&path, me).is_ok());
        if me != 0 {
            // Owned by `me`, neither the effective UID given nor root.
            let err = open_network_file_as(&path, me + 1).unwrap_err();
            assert!(
                matches!(err, NetworkDirError::Owner { owner, euid, .. }
                    if owner == me && euid == me + 1),
                "{err:?}"
            );
            assert!(err.to_string().contains("owned by uid"), "{err}");
        }
    }
}
