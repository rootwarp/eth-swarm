//! On-disk snapshot of the finalized pubkey cache.
//!
//! Layout (little-endian): `MAGIC` (8) | `VERSION` u32 | `len` u64 | `root` (32) | `len` × 48-byte keys.
//! `root` = SHA-256 over the concatenated keys `0..len`; cl-chain computes the same over its
//! finalized registry prefix. Any mismatch on start means "rebuild from scratch", never "trust".

use std::path::Path;

use crate::PubkeyCache;

pub type Key = [u8; 48];

const MAGIC: &[u8; 8] = b"CLVPKC01";
const VERSION: u32 = 1;
const HEADER: usize = 8 + 4 + 8 + 32;

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("read: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad magic, version or short header")]
    BadHeader,
    #[error("file size does not match header length (partial write)")]
    Truncated,
    #[error("stored root does not match keys")]
    RootMismatch,
}

/// What cl-verify should do after reading the saved file at start-up.
#[derive(Debug)]
pub enum Startup {
    Use(PubkeyCache<Key>),
    Rebuild(RebuildReason),
}

#[derive(Debug, PartialEq, Eq)]
pub enum RebuildReason {
    /// Missing, partial or corrupted file (message for the log).
    Unreadable(String),
    LengthMismatch {
        file: u64,
        chain: u64,
    },
    RootMismatch,
}

/// SHA-256 over the concatenated compressed keys.
pub fn root_of(keys: &[Key]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for k in keys {
        h.update(k);
    }
    h.finalize().into()
}

/// Writes the file atomically: temp file, fsync, rename.
pub fn save(cache: &PubkeyCache<Key>, path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut buf = Vec::with_capacity(HEADER + cache.keys.len() * 48);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&cache.high_water().to_le_bytes());
    buf.extend_from_slice(&root_of(&cache.keys));
    for k in &cache.keys {
        buf.extend_from_slice(k);
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

pub fn load(path: &Path) -> Result<PubkeyCache<Key>, LoadError> {
    let (_, _, keys) = read_checked(&std::fs::read(path)?)?;
    Ok(PubkeyCache { keys })
}

fn read_checked(b: &[u8]) -> Result<(u64, [u8; 32], Vec<Key>), LoadError> {
    let header = b.get(..HEADER).ok_or(LoadError::BadHeader)?;
    let (magic, rest) = header.split_at(8);
    let (version, rest) = rest.split_at(4);
    let (len, root) = rest.split_at(8);
    if magic != MAGIC || version != VERSION.to_le_bytes() {
        return Err(LoadError::BadHeader);
    }
    let len = u64::from_le_bytes(len.try_into().map_err(|_| LoadError::BadHeader)?);
    let root: [u8; 32] = root.try_into().map_err(|_| LoadError::BadHeader)?;
    let body = &b[HEADER..];
    if usize::try_from(len).ok().and_then(|l| l.checked_mul(48)) != Some(body.len()) {
        return Err(LoadError::Truncated);
    }
    let keys: Vec<Key> = body.as_chunks::<48>().0.to_vec();
    if root_of(&keys) != root {
        return Err(LoadError::RootMismatch);
    }
    Ok((len, root, keys))
}

/// Start-up check against cl-chain's finalized registry (length and root of its pubkeys).
/// Anything but an exact match means rebuild from scratch via PubkeyFeed from index 0.
pub fn startup(path: &Path, chain_len: u64, chain_root: [u8; 32]) -> Startup {
    match std::fs::read(path)
        .map_err(LoadError::from)
        .and_then(|b| read_checked(&b))
    {
        Err(e) => Startup::Rebuild(RebuildReason::Unreadable(e.to_string())),
        Ok((len, _, _)) if len != chain_len => Startup::Rebuild(RebuildReason::LengthMismatch {
            file: len,
            chain: chain_len,
        }),
        Ok((_, root, _)) if root != chain_root => Startup::Rebuild(RebuildReason::RootMismatch),
        Ok((_, _, keys)) => Startup::Use(PubkeyCache { keys }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: u8) -> Vec<Key> {
        (0..n).map(|i| [i; 48]).collect()
    }

    fn cache(n: u8) -> PubkeyCache<Key> {
        let mut c = PubkeyCache::new();
        c.append_range(0, keys(n)).unwrap();
        c
    }

    fn saved(n: u8) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pubkeys.bin");
        save(&cache(n), &path).unwrap();
        (dir, path)
    }

    #[test]
    fn save_load_round_trip() {
        let (_dir, path) = saved(5);
        let c = load(&path).unwrap();
        assert_eq!(c.high_water(), 5);
        assert_eq!(c.get(4), crate::Lookup::Known(&[4; 48]));
    }

    #[test]
    fn corrupted_file_is_rejected() {
        let (_dir, path) = saved(5);
        let mut b = std::fs::read(&path).unwrap();
        let last = b.len() - 1;
        b[last] ^= 0xff;
        std::fs::write(&path, b).unwrap();
        assert!(matches!(load(&path), Err(LoadError::RootMismatch)));
        let mut b = std::fs::read(&path).unwrap();
        b[0] ^= 0xff;
        std::fs::write(&path, b).unwrap();
        assert!(matches!(load(&path), Err(LoadError::BadHeader)));
    }

    #[test]
    fn partial_file_is_rejected() {
        let (_dir, path) = saved(5);
        let b = std::fs::read(&path).unwrap();
        for cut in [0, 10, 52, b.len() - 1] {
            std::fs::write(&path, &b[..cut]).unwrap();
            assert!(load(&path).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn startup_uses_matching_file_and_rebuilds_on_mismatch() {
        let (_dir, path) = saved(5);
        let root5 = root_of(&keys(5));
        assert!(matches!(startup(&path, 5, root5), Startup::Use(c) if c.high_water() == 5));
        assert!(matches!(
            startup(&path, 6, root_of(&keys(6))),
            Startup::Rebuild(RebuildReason::LengthMismatch { file: 5, chain: 6 })
        ));
        assert!(matches!(
            startup(&path, 5, [9; 32]),
            Startup::Rebuild(RebuildReason::RootMismatch)
        ));
        std::fs::write(&path, b"junk").unwrap();
        assert!(matches!(
            startup(&path, 5, root5),
            Startup::Rebuild(RebuildReason::Unreadable(_))
        ));
        assert!(matches!(
            startup(&path.with_extension("missing"), 5, root5),
            Startup::Rebuild(RebuildReason::Unreadable(_))
        ));
    }
}
