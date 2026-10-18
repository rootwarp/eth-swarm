//! [`open_export`]: the only way replay opens an export; and [`diff_root_lists`], the
//! consistency check between two exports of one devnet.

use super::export::{block_fields, check_parent, digest_at, BLOCK_TOPIC, MAX_GENESIS_STATE_BYTES};
use super::manifest::{BlockEntry, ExportManifest, EXPORT_FILE, GENESIS_STATE_FILE};
use super::ExportError;
use crate::archive::{
    open_verified, read_regular, Archive, ArchiveError, ArchiveFile, ForkDigest, Sha256Digest,
    MAX_MANIFEST_LEN,
};
use consensus_types::forked::{BeaconState, SignedBeaconBlock};
use consensus_types::primitives::{Epoch, ForkName, Root, Slot};
use consensus_types::{EthSpec, ForkSchedule, Mainnet, Minimal};
use network_config::{ScheduledFork, FAR_FUTURE_EPOCH};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use tree_hash::TreeHash;

/// An export whose manifest, segments, block files and genesis state were verified when it
/// was opened.
#[derive(Debug, Clone)]
pub struct Export {
    dir: PathBuf,
    manifest: ExportManifest,
    export_sha256: Sha256Digest,
    segments: Vec<Archive>,
}

impl Export {
    /// The export directory, `<out>/<devnet>`.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The verified manifest.
    pub fn manifest(&self) -> &ExportManifest {
        &self.manifest
    }

    /// The export digest: the sha256 of the manifest body, which holds every block root, every
    /// segment's archive digest and the genesis state's sha256. Pin this to pin the export.
    pub fn export_sha256(&self) -> Sha256Digest {
        self.export_sha256
    }

    /// The archive segments, each opened through [`open_verified`], in manifest order.
    pub fn segments(&self) -> &[Archive] {
        &self.segments
    }

    /// One entry per slot from genesis to the export slot: the block root, or `None` for an
    /// empty slot.
    pub fn root_list(&self) -> Vec<Option<Root>> {
        self.manifest.root_list()
    }

    /// The genesis state's SSZ, re-checked against the bound and the manifest's length and
    /// sha256.
    pub fn genesis_state_ssz(&self) -> Result<Vec<u8>, ExportError> {
        read_state(&self.dir, &self.manifest)
    }

    /// The SSZ of an exported block, read from its segment through [`Archive::read_ssz`]
    /// (length and sha256 re-checked). `block` must be one of the manifest's blocks.
    pub fn block_ssz(&self, block: &BlockEntry) -> Result<Vec<u8>, ExportError> {
        if !self.manifest.blocks.contains(block) {
            return Err(ExportError::Mismatch(format!(
                "slot {} root {} is not a block of the export",
                block.slot, block.root
            )));
        }
        for segment in &self.segments {
            let file = segment
                .files()
                .iter()
                .find(|f| f.slot == block.slot && f.root == block.root);
            if let Some(file) = file {
                return Ok(segment.read_ssz(file)?);
            }
        }
        Err(ExportError::Mismatch(format!(
            "slot {}: no segment holds the block",
            block.slot
        )))
    }
}

/// Opens the export at `dir` (`<out>/<devnet>`) after verifying all of it: the manifest's
/// header digest and fields, the directory's name (the devnet's), every segment through
/// [`open_verified`] with the archive digest the manifest records, the segments' block files
/// against the manifest's blocks (same slots and roots, nothing more or less), and the genesis
/// state's size (at most [`MAX_GENESIS_STATE_BYTES`], checked before it is read), length and
/// sha256. Then it decodes, with the fork of each object's slot, the genesis state (at slot 0,
/// with the manifest's `genesis_time`, `genesis_validators_root` and state root) and every
/// block (at its listed slot, hashing to its listed root, under the fork digest in force at its
/// slot, with the block before it as its parent and, for genesis, the genesis state's root as
/// its `state_root`). It refuses any entry of `dir` the manifest does not list, an unsealed
/// `.open-*` segment included.
///
/// This proves the export holds together and is a hash chain from its genesis block and
/// state; it does not prove the chain is the devnet's. Open checks no signature and runs no
/// state transition, so whoever can write the directory can fabricate a consistent suffix
/// (drop or replace the tip, rewrite blocks after any slot) and rehash every manifest. Only
/// the `export_sha256` pinned when the export was made, from the run log, authenticates it:
/// replay opens through [`open_export_pinned`].
pub fn open_export(dir: &Path) -> Result<Export, ExportError> {
    open(dir, None)
}

/// [`open_export`], after checking that the manifest's `export_sha256` is `expected`, the
/// digest the export printed when it was made (keep it in the run log). The pin is checked
/// before anything but the manifest is read; with it, every block root, segment digest and
/// the genesis state's sha256 are the pinned ones, so a forged or truncated export is refused
/// with [`ExportError::NotPinned`].
pub fn open_export_pinned(dir: &Path, expected: Sha256Digest) -> Result<Export, ExportError> {
    open(dir, Some(expected))
}

fn open(dir: &Path, pin: Option<Sha256Digest>) -> Result<Export, ExportError> {
    let meta = fs::symlink_metadata(dir).map_err(ExportError::io(dir))?;
    if !meta.is_dir() {
        return Err(ArchiveError::NotRegular(dir.display().to_string()).into());
    }
    let manifest_path = dir.join(EXPORT_FILE);
    let bytes = read_regular(&manifest_path, EXPORT_FILE, MAX_MANIFEST_LEN)?;
    if bytes.len() as u64 > MAX_MANIFEST_LEN {
        return Err(ExportError::Mismatch(format!(
            "{EXPORT_FILE} is over {MAX_MANIFEST_LEN} bytes"
        )));
    }
    let (manifest, export_sha256) =
        ExportManifest::parse(&bytes).map_err(|source| ExportError::Manifest {
            path: manifest_path,
            source,
        })?;
    if let Some(expected) = pin.filter(|pin| *pin != export_sha256) {
        return Err(ExportError::NotPinned {
            expected: hex::encode(expected),
            actual: hex::encode(export_sha256),
        });
    }
    let real = fs::canonicalize(dir).map_err(ExportError::io(dir))?;
    if real.file_name().and_then(|n| n.to_str()) != Some(manifest.devnet.as_str()) {
        return Err(ExportError::Mismatch(format!(
            "{}: the export's devnet is {}",
            dir.display(),
            manifest.devnet
        )));
    }
    refuse_unlisted(dir, &manifest)?;
    let segments = open_segments(dir, &manifest)?;
    if manifest.preset == Minimal::NAME {
        verify_contents::<Minimal>(dir, &manifest, &segments)?;
    } else {
        verify_contents::<Mainnet>(dir, &manifest, &segments)?;
    }
    Ok(Export {
        dir: dir.to_owned(),
        manifest,
        export_sha256,
        segments,
    })
}

/// Fails on the first entry of `dir` that is not the manifest, the genesis state or a listed
/// segment directory.
fn refuse_unlisted(dir: &Path, manifest: &ExportManifest) -> Result<(), ExportError> {
    let segments: BTreeSet<&str> = manifest.segments.iter().map(|s| s.dir.as_str()).collect();
    for entry in fs::read_dir(dir).map_err(ExportError::io(dir))? {
        let entry = entry.map_err(ExportError::io(dir))?;
        let kind = entry.file_type().map_err(ExportError::io(entry.path()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let listed = if kind.is_file() {
            name == EXPORT_FILE || name == GENESIS_STATE_FILE
        } else {
            kind.is_dir() && segments.contains(name.as_str())
        };
        if !listed {
            return Err(ArchiveError::ExtraFile(name).into());
        }
    }
    Ok(())
}

/// Opens every segment and checks that, together, they hold exactly the manifest's blocks.
fn open_segments(dir: &Path, manifest: &ExportManifest) -> Result<Vec<Archive>, ExportError> {
    let mismatch = |m: String| Err(ExportError::Mismatch(m));
    let mut segments = Vec::new();
    let mut files: Vec<(Slot, Root)> = Vec::new();
    for entry in &manifest.segments {
        let archive = open_verified(&dir.join(&entry.dir))?;
        if archive.archive_sha256() != entry.archive_sha256 {
            return mismatch(format!(
                "segment {}: archive_sha256 {}, the export says {}",
                entry.dir,
                hex::encode(archive.archive_sha256()),
                hex::encode(entry.archive_sha256)
            ));
        }
        let m = archive.manifest();
        if m.network != manifest.devnet || m.preset != manifest.preset {
            return mismatch(format!(
                "segment {}: network {:?} preset {:?}, the export's are {:?} and {:?}",
                entry.dir, m.network, m.preset, manifest.devnet, manifest.preset
            ));
        }
        if let Some(f) = archive.files().iter().find(|f| f.topic != BLOCK_TOPIC) {
            return mismatch(format!("segment {}: {} is not a block", entry.dir, f.path));
        }
        files.extend(
            archive
                .files()
                .iter()
                .map(|f: &ArchiveFile| (f.slot, f.root)),
        );
        segments.push(archive);
    }
    files.sort_unstable();
    let blocks: Vec<(Slot, Root)> = manifest.blocks.iter().map(|b| (b.slot, b.root)).collect();
    if files != blocks {
        let first = files
            .iter()
            .zip(&blocks)
            .position(|(a, b)| a != b)
            .unwrap_or(files.len().min(blocks.len()));
        return mismatch(format!(
            "the segments hold {} block files, the export lists {} blocks; they differ from \
             entry {first}",
            files.len(),
            blocks.len()
        ));
    }
    Ok(segments)
}

/// The manifest's fork schedule; a fork it does not list is not scheduled.
fn fork_schedule(manifest: &ExportManifest) -> Result<ForkSchedule, ExportError> {
    let scheduled = |fork: ForkName| {
        manifest
            .fork_schedule
            .iter()
            .find(|f| f.fork == fork)
            .map_or(
                ScheduledFork {
                    version: [0; 4],
                    epoch: FAR_FUTURE_EPOCH,
                },
                |f| ScheduledFork {
                    version: f.version,
                    epoch: f.epoch,
                },
            )
    };
    ForkSchedule::new(scheduled(ForkName::Fulu), scheduled(ForkName::Gloas))
        .map_err(|e| ExportError::Mismatch(format!("fork_schedule: {e}")))
}

/// Decodes the genesis state and every block with the fork of its own slot and re-checks them
/// against the manifest: the state at slot 0 with the manifest's `genesis_time`,
/// `genesis_validators_root` and state root; each block at its listed slot, hashing to its
/// listed root, filed under the fork digest in force at its slot, and with the block before it
/// (across empty slots) as its parent, the genesis block with a zero parent and the genesis
/// state's root as its `state_root`.
fn verify_contents<E: EthSpec>(
    dir: &Path,
    manifest: &ExportManifest,
    segments: &[Archive],
) -> Result<(), ExportError> {
    let schedule = fork_schedule(manifest)?;
    verify_genesis_state::<E>(&read_state(dir, manifest)?, manifest, &schedule)?;
    let digests: Vec<(Epoch, ForkDigest)> = manifest
        .fork_digests
        .iter()
        .map(|d| (d.epoch, d.digest))
        .collect();
    let files: BTreeMap<(Slot, Root), (&Archive, &ArchiveFile)> = segments
        .iter()
        .flat_map(|a| a.files().iter().map(move |f| ((f.slot, f.root), (a, f))))
        .collect();
    let mut tip: Option<&BlockEntry> = None;
    for entry in &manifest.blocks {
        let slot = entry.slot;
        let mismatch = |m: String| Err(ExportError::Mismatch(format!("slot {slot}: {m}")));
        let Some(&(archive, file)) = files.get(&(slot, entry.root)) else {
            return mismatch("no segment holds the block".into());
        };
        let expected = digest_at::<E>(&digests, slot);
        if expected != Some(file.fork_digest) {
            return mismatch(format!(
                "the block's fork digest 0x{} is not export.toml's for its epoch",
                hex::encode(file.fork_digest)
            ));
        }
        let ssz = archive.read_ssz(file)?;
        let block =
            SignedBeaconBlock::<E>::from_ssz_bytes_by_slot(&ssz, &schedule).map_err(|source| {
                ExportError::Decode {
                    what: "block",
                    slot: Some(slot),
                    source,
                }
            })?;
        if block.slot() != slot {
            return mismatch(format!("the file holds a block of slot {}", block.slot()));
        }
        let (root, parent_root, state_root) = block_fields(&block);
        if root != entry.root {
            return mismatch(format!(
                "the block hashes to root {root}, export.toml lists {}",
                entry.root
            ));
        }
        check_parent(
            tip,
            slot,
            parent_root,
            state_root,
            manifest.genesis_state_root,
        )?;
        tip = Some(entry);
    }
    Ok(())
}

/// The genesis state decodes with the fork of slot 0, is at slot 0, and has the manifest's
/// `genesis_time`, `genesis_validators_root` and state root.
fn verify_genesis_state<E: EthSpec>(
    ssz: &[u8],
    manifest: &ExportManifest,
    schedule: &ForkSchedule,
) -> Result<(), ExportError> {
    let state = BeaconState::<E>::from_ssz_bytes_by_slot(ssz, schedule).map_err(|source| {
        ExportError::Decode {
            what: "genesis state",
            slot: None,
            source,
        }
    })?;
    let (time, validators_root) = match &state {
        BeaconState::Fulu(s) => (s.genesis_time, s.genesis_validators_root),
        BeaconState::Gloas(s) => (s.genesis_time, s.genesis_validators_root),
    };
    let mismatch = |field: &str, state: String, listed: String| {
        Err(ExportError::Mismatch(format!(
            "genesis state: {field} {state}, export.toml says {listed}"
        )))
    };
    if state.slot() != 0 {
        return mismatch("slot", state.slot().to_string(), "0".into());
    }
    if time != manifest.genesis_time {
        return mismatch(
            "genesis_time",
            time.to_string(),
            manifest.genesis_time.to_string(),
        );
    }
    if validators_root != manifest.genesis_validators_root {
        return mismatch(
            "genesis_validators_root",
            validators_root.to_string(),
            manifest.genesis_validators_root.to_string(),
        );
    }
    let root = state.tree_hash_root();
    if root != manifest.genesis_state_root {
        return mismatch(
            "state root",
            root.to_string(),
            manifest.genesis_state_root.to_string(),
        );
    }
    Ok(())
}

/// Reads the genesis state and checks its length and sha256. A file over
/// [`MAX_GENESIS_STATE_BYTES`] is refused by its size before any of it is read, and the read
/// stops one byte past the manifest's length, itself at most that bound.
fn read_state(dir: &Path, manifest: &ExportManifest) -> Result<Vec<u8>, ExportError> {
    let file = &manifest.genesis_state;
    let path = dir.join(&file.path);
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if meta.is_file() && meta.len() > MAX_GENESIS_STATE_BYTES {
            return Err(ExportError::Mismatch(format!(
                "{}: {} bytes, over the {MAX_GENESIS_STATE_BYTES}-byte bound",
                file.path,
                meta.len()
            )));
        }
    }
    let limit = file.len.min(MAX_GENESIS_STATE_BYTES);
    let bytes = read_regular(&path, &file.path, limit)?;
    if bytes.len() as u64 != file.len {
        return Err(ArchiveError::LengthMismatch {
            path: file.path.clone(),
            expected: file.len,
            actual: bytes.len() as u64,
        }
        .into());
    }
    let actual: Sha256Digest = Sha256::digest(&bytes).into();
    if actual != file.sha256 {
        return Err(ArchiveError::Sha256Mismatch {
            path: file.path.clone(),
            expected: hex::encode(file.sha256),
            actual: hex::encode(actual),
        }
        .into());
    }
    Ok(bytes)
}

/// One side of a root-list difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotEntry {
    /// A block with this root.
    Block(Root),
    /// An empty slot.
    Empty,
    /// The slot is past this export's export slot.
    NotExported,
}

/// What [`diff_root_lists`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootListDiff {
    /// The same block root, or the same empty slot, at every slot.
    Identical {
        /// The slots compared, from genesis.
        slots: u64,
    },
    /// The lists differ; `slot` is the first slot where they do.
    Differ {
        /// The first differing slot.
        slot: Slot,
        /// The first export's entry at `slot`.
        a: SlotEntry,
        /// The second export's entry at `slot`.
        b: SlotEntry,
    },
}

/// Compares two root lists slot by slot from genesis ([`Export::root_list`]): identical, or
/// the first slot where they differ, a list that ends earlier included.
pub fn diff_root_lists(a: &[Option<Root>], b: &[Option<Root>]) -> RootListDiff {
    let entry = |list: &[Option<Root>], at: usize| match list.get(at) {
        Some(Some(root)) => SlotEntry::Block(*root),
        Some(None) => SlotEntry::Empty,
        None => SlotEntry::NotExported,
    };
    let len = a.len().max(b.len());
    (0..len)
        .map(|at| (at, entry(a, at), entry(b, at)))
        .find(|(_, x, y)| x != y)
        .map_or(
            RootListDiff::Identical { slots: len as u64 },
            |(at, a, b)| RootListDiff::Differ {
                slot: at as Slot,
                a,
                b,
            },
        )
}
