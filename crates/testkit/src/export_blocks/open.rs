//! [`open_export`]: the only way replay opens an export; and [`diff_root_lists`], the
//! consistency check between two exports of one devnet.

use super::export::BLOCK_TOPIC;
use super::manifest::{BlockEntry, ExportManifest, EXPORT_FILE, GENESIS_STATE_FILE};
use super::ExportError;
use crate::archive::{
    open_verified, read_regular, Archive, ArchiveError, ArchiveFile, Sha256Digest, MAX_MANIFEST_LEN,
};
use consensus_types::primitives::{Root, Slot};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

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

    /// The genesis state's SSZ, re-checked against the manifest's length and sha256.
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
/// state's length and sha256. It refuses any entry of `dir` the manifest does not list, an
/// unsealed `.open-*` segment included.
pub fn open_export(dir: &Path) -> Result<Export, ExportError> {
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
    read_state(dir, &manifest)?;
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

/// Reads the genesis state and checks its length and sha256.
fn read_state(dir: &Path, manifest: &ExportManifest) -> Result<Vec<u8>, ExportError> {
    let file = &manifest.genesis_state;
    let bytes = read_regular(&dir.join(&file.path), &file.path, file.len)?;
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
