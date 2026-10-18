//! [`Writer`]: a capture into rolling segments.
//!
//! `<out>/<network>/` and any missing parent are created each fsynced in its own parent, and a
//! `<out>/<network>` that is a symlink is refused. A segment is built in
//! `<out>/<network>/.open-<window_start>-<n>/`. Every payload is written to a hidden temp name
//! in its topic directory, fsynced, moved to `<topic>/<slot>_0x<root>.ssz_snappy` without ever
//! replacing an existing file, and the directory fsynced, so a named file is always complete.
//! Sealing first removes whatever a failed put left that the manifest will not list (a file
//! whose directory fsync failed, an empty topic directory), then writes `manifest.toml` the same
//! way and renames the directory to `<out>/<network>/<slot_start>-<slot_end>/`. A crash before
//! the seal leaves only an `.open-*` directory without a manifest, which is no archive: nothing
//! a manifest references can be partial, and at most one segment of payloads is lost.
//!
//! Segments roll on aligned windows of `slots_per_segment` slots: the first payload at or past
//! the open window's end seals the open segment ([`ClosedBy::Roll`]) and opens the next. A late
//! payload, for a slot before the open window, joins the open segment and lowers its
//! `slot_start`, so segments can overlap but never drop a payload. A segment covers its whole
//! window when it rolls, from its window start when a roll opened it, from its first slot when
//! the capture opened it, and up to its last slot when it closes. A segment also rolls, ending
//! at its last slot, before its manifest could pass [`MAX_MANIFEST_LEN`], which the reader
//! refuses; the next one then starts at the payload that rolled it, in the same window.
//!
//! Every payload must be on the network's fork digest for its slot's epoch
//! ([`CaptureConfig::fork_digests`]). The payload bytes are kept under a disk budget
//! (`max_bytes`), checked before a payload can roll the open segment; passing it, or any write
//! error such as a full disk, stops the capture with an error. [`Writer::close`] then still
//! seals what was written, marked [`ClosedBy::Error`] with the reason (cut to
//! [`MAX_ERROR_LEN`](super::MAX_ERROR_LEN) bytes), so a stopped capture is never mistaken for a
//! complete one.

use super::error::ArchiveError;
use super::manifest::{
    base_len_bound as manifest_base_len_bound, file_len_bound as manifest_file_len_bound,
    truncate_error, ArchiveFile, ClosedBy, ForkDigest, Manifest, MANIFEST_FILE, MAX_MANIFEST_LEN,
};
use super::names::{
    file_name, file_path, segment_name, validate_network, validate_topic, TopicKind,
};
use super::payload::{decode_payload, max_compressed_payload_len, ChainParams, PayloadError};
use consensus_types::primitives::{Epoch, Root, Slot};
use consensus_types::EthSpec;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::marker::PhantomData;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Mode of every file a capture writes: readable by replay users, writable by none.
const FILE_MODE: u32 = 0o644;
/// Mode of every directory a capture creates.
const DIR_MODE: u32 = 0o755;
/// The prefix of a segment directory that is not sealed yet.
pub const OPEN_PREFIX: &str = ".open-";

/// What a capture records about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfig {
    /// The network name, the archive's top directory (`[a-z0-9_-]`).
    pub network: String,
    /// The subscribed gossip topics, without fork digest and encoding; a payload on any other
    /// topic is refused.
    pub topics: Vec<String>,
    /// The capture host, for the manifest.
    pub capture_host: String,
    /// The clock the host keeps time with (e.g. `chrony`), for the manifest.
    pub clock_source: String,
    /// The segment window in slots.
    pub slots_per_segment: u64,
    /// The payload bytes the capture may write before it stops.
    pub max_bytes: u64,
    /// The network's fork digest from each epoch on, ascending by epoch: every entry of
    /// `network_config::digest::digest_schedule`, so blob-parameter changes are in it. A
    /// payload whose topic digest is not the one of its slot's epoch is refused.
    pub fork_digests: Vec<(Epoch, ForkDigest)>,
}

/// One payload as gossip delivered it.
#[derive(Debug, Clone, Copy)]
pub struct Capture<'a> {
    /// The topic name, without fork digest and encoding.
    pub topic: &'a str,
    /// The fork digest of the topic it arrived on.
    pub fork_digest: ForkDigest,
    /// The snappy block-compressed SSZ bytes, stored as they are.
    pub payload: &'a [u8],
}

/// Where a payload was stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// `<topic>/<slot>_0x<root>.ssz_snappy`, relative to its segment.
    pub path: String,
    /// The object's slot.
    pub slot: Slot,
    /// The block root it is filed under.
    pub root: Root,
}

/// An injected write fault (feature `test-support`). `Crash` and `DiskFull` apply to the next
/// payload write; `DirSync` to the next fsync of its directory.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// The process dies after `after` bytes of the temp file: it stays where it is, nothing
    /// is renamed and the capture is stopped. Drop the writer to finish the simulated crash.
    Crash {
        /// Bytes written before the crash.
        after: usize,
    },
    /// The disk fills after `after` bytes: the write fails with `StorageFull`.
    DiskFull {
        /// Bytes written before the disk is full.
        after: usize,
    },
    /// The next fsync of `dir` fails, after whatever it was to make durable is done (a
    /// rename after a payload write, a directory create).
    DirSync {
        /// The directory, as the writer names it (`out` joined with the names below it).
        dir: PathBuf,
    },
}

/// A capture into `<out>/<network>/` segments.
#[derive(Debug)]
pub struct Writer<E: EthSpec> {
    network_dir: PathBuf,
    config: CaptureConfig,
    chain: ChainParams,
    open: Option<Segment>,
    sealed: Vec<PathBuf>,
    written: u64,
    peer_count: u32,
    stopped: Option<String>,
    /// [`manifest_base_len_bound`] of this capture's fields.
    manifest_base_len: u64,
    /// The manifest length a segment rolls before passing: [`MAX_MANIFEST_LEN`] but in tests.
    max_manifest_len: u64,
    #[cfg(any(test, feature = "test-support"))]
    fault: Option<Fault>,
    sync_fault: SyncFault,
    _spec: PhantomData<E>,
}

#[derive(Debug)]
struct Segment {
    dir: PathBuf,
    window_end: Slot,
    covers_from: Slot,
    last_slot: Slot,
    files: BTreeMap<String, ArchiveFile>,
    topic_dirs: BTreeSet<String>,
    /// An upper bound on the length of the segment's manifest so far.
    manifest_len: u64,
}

/// Where a sealed segment's slot range ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentEnd {
    /// At the end of its window: the capture moved past it.
    Window,
    /// At its last stored slot.
    LastSlot,
}

impl<E: EthSpec> Writer<E> {
    /// Starts a capture into `<out>/<network>/`, creating it and any missing parent, each made
    /// durable in its own parent. Refuses an invalid network or topic name, a topic the archive
    /// cannot file, an empty host or clock source, a zero segment window, and a
    /// `<out>/<network>` that is a symlink or not a directory.
    pub fn create(
        out: &Path,
        config: CaptureConfig,
        chain: ChainParams,
    ) -> Result<Self, ArchiveError> {
        Self::create_inner(out, config, chain, SyncFault::default())
    }

    /// [`Writer::create`] with `fault` injected from the start (feature `test-support`), so it
    /// can hit the directory creation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn create_with_fault(
        out: &Path,
        config: CaptureConfig,
        chain: ChainParams,
        fault: Fault,
    ) -> Result<Self, ArchiveError> {
        let (write, sync) = match fault {
            Fault::DirSync { dir } => (None, Some(dir)),
            write => (Some(write), None),
        };
        let mut w = Self::create_inner(out, config, chain, sync)?;
        w.fault = write;
        Ok(w)
    }

    fn create_inner(
        out: &Path,
        mut config: CaptureConfig,
        chain: ChainParams,
        mut sync_fault: SyncFault,
    ) -> Result<Self, ArchiveError> {
        validate_network(&config.network)?;
        config.topics.sort();
        config.topics.dedup();
        if config.topics.is_empty() {
            return Err(ArchiveError::Config("no topic to capture".into()));
        }
        for topic in &config.topics {
            validate_topic(topic)?;
            TopicKind::of(topic)?;
        }
        if config.slots_per_segment == 0 {
            return Err(ArchiveError::Config(
                "slots_per_segment must be at least 1".into(),
            ));
        }
        if config.capture_host.is_empty() || config.clock_source.is_empty() {
            return Err(ArchiveError::Config(
                "capture_host and clock_source must not be empty".into(),
            ));
        }
        if config.fork_digests.is_empty()
            || config.fork_digests.windows(2).any(|w| w[0].0 >= w[1].0)
        {
            return Err(ArchiveError::Config(
                "fork_digests must be non-empty and strictly ascending by epoch".into(),
            ));
        }
        let manifest_base_len = manifest_base_len_bound(
            &config.network,
            &config.topics,
            &config.capture_host,
            &config.clock_source,
        );
        let longest_topic = config
            .topics
            .iter()
            .max_by_key(|t| t.len())
            .expect("not empty");
        let largest_file = manifest_file_len_bound(&ArchiveFile {
            path: file_path(longest_topic, i64::MAX as u64, &Root::ZERO),
            topic: longest_topic.clone(),
            slot: i64::MAX as u64,
            root: Root::ZERO,
            fork_digest: [0; 4],
            len: max_compressed_payload_len() as u64,
            sha256: [0; 32],
        });
        if manifest_base_len.saturating_add(largest_file) > MAX_MANIFEST_LEN {
            return Err(ArchiveError::Config(format!(
                "the capture fields leave no room for a file in a manifest of {MAX_MANIFEST_LEN} bytes"
            )));
        }
        let network_dir = out.join(&config.network);
        create_dir_all_durable(&network_dir, &mut sync_fault)?;
        // Never follow a planted symlink out of the archive root.
        let meta = fs::symlink_metadata(&network_dir).map_err(ArchiveError::io(&network_dir))?;
        if !meta.is_dir() {
            return Err(ArchiveError::NotRegular(network_dir.display().to_string()));
        }
        Ok(Self {
            network_dir,
            config,
            chain,
            open: None,
            sealed: Vec::new(),
            written: 0,
            peer_count: 0,
            stopped: None,
            manifest_base_len,
            max_manifest_len: MAX_MANIFEST_LEN,
            #[cfg(any(test, feature = "test-support"))]
            fault: None,
            sync_fault,
            _spec: PhantomData,
        })
    }

    /// The peer count recorded in the next sealed manifest.
    pub fn set_peer_count(&mut self, peers: u32) {
        self.peer_count = peers;
    }

    /// Stops the capture for a reason outside the writer (its source failed): later calls to
    /// [`Writer::put`] fail, and [`Writer::close`] seals the open segment as
    /// [`ClosedBy::Error`] with `reason`. An earlier stop keeps its reason.
    pub fn stop(&mut self, reason: String) {
        self.stopped.get_or_insert(reason);
    }

    /// Every segment sealed so far, oldest first.
    pub fn sealed(&self) -> &[PathBuf] {
        &self.sealed
    }

    /// Lowers the manifest length a segment rolls before passing.
    #[cfg(test)]
    fn set_max_manifest_len(&mut self, len: u64) {
        self.max_manifest_len = len;
    }

    /// Injects a write fault into the next payload write (feature `test-support`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn inject_fault(&mut self, fault: Fault) {
        match fault {
            Fault::DirSync { dir } => self.sync_fault = Some(dir),
            write => self.fault = Some(write),
        }
    }

    /// Archives one payload, rolling the open segment first if the payload's slot is past its
    /// window. A [`ArchiveError::Payload`] refuses only this payload; any other error stops the
    /// capture, and every later call fails with [`ArchiveError::Stopped`].
    pub fn put(&mut self, capture: Capture<'_>) -> Result<Stored, ArchiveError> {
        if let Some(reason) = &self.stopped {
            return Err(ArchiveError::Stopped(reason.clone()));
        }
        let result = self.store(capture);
        if let Err(e) = &result {
            if e.stops_capture() {
                self.stopped = Some(e.to_string());
            }
        }
        result
    }

    fn store(&mut self, capture: Capture<'_>) -> Result<Stored, ArchiveError> {
        let Capture {
            topic,
            fork_digest,
            payload,
        } = capture;
        if self
            .config
            .topics
            .binary_search_by(|t| t.as_str().cmp(topic))
            .is_err()
        {
            return Err(PayloadError::Unsubscribed(topic.to_owned()).into());
        }
        let decoded = decode_payload::<E>(TopicKind::of(topic)?, payload, &self.chain)?;
        let expected = digest_at(&self.config.fork_digests, E::epoch_at_slot(decoded.slot));
        if expected != Some(fork_digest) {
            return Err(PayloadError::ForkDigest {
                slot: decoded.slot,
                expected,
                got: fork_digest,
            }
            .into());
        }
        let path = file_path(topic, decoded.slot, &decoded.root);
        let len = payload.len() as u64;
        let file = ArchiveFile {
            path: path.clone(),
            topic: topic.to_owned(),
            slot: decoded.slot,
            root: decoded.root,
            fork_digest,
            len,
            sha256: Sha256::digest(payload).into(),
        };
        let manifest_len = manifest_file_len_bound(&file);

        let rolls = self
            .open
            .as_ref()
            .is_some_and(|s| decoded.slot >= s.window_end);
        // A rolled-to segment starts empty, so only a payload that stays can be a duplicate.
        let existing = self.open.as_ref().and_then(|s| s.files.get(&path));
        if let Some(existing) = existing.filter(|_| !rolls) {
            return Err(PayloadError::Duplicate {
                path,
                identical: existing.sha256 == file.sha256,
            }
            .into());
        }
        // Before the roll: a payload the budget refuses leaves the open segment open, so the
        // seal at close says why the capture stopped.
        if self.written.saturating_add(len) > self.config.max_bytes {
            return Err(ArchiveError::BudgetExhausted {
                budget: self.config.max_bytes,
                written: self.written,
                needed: len,
            });
        }
        // A manifest past the limit could never be opened: roll before it would be.
        let full = !rolls
            && self.open.as_ref().is_some_and(|s| {
                !s.files.is_empty()
                    && s.manifest_len.saturating_add(manifest_len) > self.max_manifest_len
            });
        let covers_from = if rolls {
            self.seal(ClosedBy::Roll, SegmentEnd::Window)?;
            Some(window_start(decoded.slot, self.config.slots_per_segment))
        } else {
            if full {
                self.seal(ClosedBy::Roll, SegmentEnd::LastSlot)?;
            }
            None
        };
        if self.open.is_none() {
            let from = covers_from.unwrap_or(decoded.slot);
            self.open = Some(self.open_segment(decoded.slot, from)?);
        }
        #[cfg(any(test, feature = "test-support"))]
        let fault = self.fault.take();
        #[cfg(not(any(test, feature = "test-support")))]
        let fault = None;
        let segment = self.open.as_mut().expect("opened above");
        let topic_dir = segment.dir.join(topic);
        if !segment.topic_dirs.contains(topic) {
            create_dir(&topic_dir)?;
            sync_dir(&segment.dir, &mut self.sync_fault)?;
            segment.topic_dirs.insert(topic.to_owned());
        }
        write_durable(
            &topic_dir,
            &file_name(decoded.slot, &decoded.root),
            payload,
            fault,
            &mut self.sync_fault,
        )?;
        segment.covers_from = segment.covers_from.min(decoded.slot);
        segment.last_slot = segment.last_slot.max(decoded.slot);
        segment.manifest_len = segment.manifest_len.saturating_add(manifest_len);
        segment.files.insert(path.clone(), file);
        self.written += len;
        Ok(Stored {
            path,
            slot: decoded.slot,
            root: decoded.root,
        })
    }

    /// Creates `.open-<window_start>-<n>` for a segment whose window holds `slot`.
    fn open_segment(&mut self, slot: Slot, covers_from: Slot) -> Result<Segment, ArchiveError> {
        let start = window_start(slot, self.config.slots_per_segment);
        let mut n = 0u32;
        let dir = loop {
            let dir = self.network_dir.join(format!("{OPEN_PREFIX}{start}-{n}"));
            match fs::DirBuilder::new().mode(DIR_MODE).create(&dir) {
                Ok(()) => break dir,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n += 1,
                Err(e) => return Err(ArchiveError::io(dir)(e)),
            }
        };
        sync_dir(&self.network_dir, &mut self.sync_fault)?;
        Ok(Segment {
            dir,
            window_end: start.saturating_add(self.config.slots_per_segment),
            covers_from,
            last_slot: slot,
            files: BTreeMap::new(),
            topic_dirs: BTreeSet::new(),
            manifest_len: self.manifest_base_len,
        })
    }

    /// Seals the open segment, if any: manifest, then the rename to its slot range.
    fn seal(&mut self, closed_by: ClosedBy, end: SegmentEnd) -> Result<(), ArchiveError> {
        let Some(segment) = self.open.take() else {
            return Ok(());
        };
        prune(&segment, &self.config.topics, &mut self.sync_fault)?;
        if segment.files.is_empty() {
            return fs::remove_dir(&segment.dir).map_err(ArchiveError::io(&segment.dir));
        }
        let slot_end = match end {
            // A window at the top of the slot range ends where TOML integers do.
            SegmentEnd::Window => (segment.window_end - 1).min(i64::MAX as u64),
            SegmentEnd::LastSlot => segment.last_slot,
        };
        let files: Vec<ArchiveFile> = segment.files.into_values().collect();
        let manifest = Manifest {
            network: self.config.network.clone(),
            preset: E::NAME.to_owned(),
            slot_start: segment.covers_from,
            slot_end,
            fork_digests: files
                .iter()
                .map(|f| f.fork_digest)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            topics: self.config.topics.clone(),
            peer_count: self.peer_count,
            capture_host: self.config.capture_host.clone(),
            clock_source: self.config.clock_source.clone(),
            closed_by,
            error: self
                .stopped
                .as_deref()
                .filter(|_| closed_by == ClosedBy::Error)
                .map(truncate_error),
            total_bytes: files.iter().map(|f| f.len).sum(),
            files,
        };
        let manifest_path = segment.dir.join(MANIFEST_FILE);
        let (bytes, _) = manifest.render().map_err(|source| ArchiveError::Manifest {
            path: manifest_path,
            source,
        })?;
        write_durable(
            &segment.dir,
            MANIFEST_FILE,
            &bytes,
            None,
            &mut self.sync_fault,
        )?;

        // Claim the name with an empty directory, which the rename then replaces: an existing
        // segment is never overwritten.
        let target = self
            .network_dir
            .join(segment_name(manifest.slot_start, manifest.slot_end));
        match fs::DirBuilder::new().mode(DIR_MODE).create(&target) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(ArchiveError::SegmentExists {
                    target,
                    open: segment.dir,
                })
            }
            Err(e) => return Err(ArchiveError::io(target)(e)),
        }
        fs::rename(&segment.dir, &target).map_err(ArchiveError::io(&target))?;
        sync_dir(&self.network_dir, &mut self.sync_fault)?;
        self.sealed.push(target);
        Ok(())
    }

    /// Seals the open segment ([`ClosedBy::Close`], or [`ClosedBy::Error`] after a stop) and
    /// returns every segment the capture sealed, oldest first. A capture that stored nothing
    /// leaves nothing behind.
    pub fn close(mut self) -> Result<Vec<PathBuf>, ArchiveError> {
        let closed_by = if self.stopped.is_some() {
            ClosedBy::Error
        } else {
            ClosedBy::Close
        };
        self.seal(closed_by, SegmentEnd::LastSlot)?;
        Ok(self.sealed)
    }
}

/// Removes from the segment what its manifest will not list, so a failed put cannot make the
/// sealed segment unreadable: in every topic directory, each regular file that is not a stored
/// payload (one whose rename went through but whose directory fsync failed, or a temp file),
/// and every topic directory left without a stored payload (a failed first write to a new
/// topic). Entries the writer cannot have made (a non-topic name, a symlink) are left for
/// [`open_verified`](super::open_verified) to refuse.
fn prune(segment: &Segment, topics: &[String], sync: &mut SyncFault) -> Result<(), ArchiveError> {
    let stored: BTreeSet<&str> = segment.files.values().map(|f| f.topic.as_str()).collect();
    let mut removed_topic = false;
    for (topic, topic_dir) in own_entries(&segment.dir, |name, kind| {
        kind.is_dir() && topics.binary_search_by(|t| t.as_str().cmp(name)).is_ok()
    })? {
        let unlisted = own_entries(&topic_dir, |name, kind| {
            kind.is_file() && !segment.files.contains_key(&format!("{topic}/{name}"))
        })?;
        for (_, file) in &unlisted {
            fs::remove_file(file).map_err(ArchiveError::io(file))?;
        }
        if !stored.contains(topic.as_str()) {
            fs::remove_dir(&topic_dir).map_err(ArchiveError::io(&topic_dir))?;
            removed_topic = true;
        } else if !unlisted.is_empty() {
            sync_dir(&topic_dir, sync)?;
        }
    }
    if removed_topic {
        sync_dir(&segment.dir, sync)?;
    }
    Ok(())
}

/// The UTF-8 named entries of `dir` that `keep` accepts, by name and type (never following a
/// symlink), with their paths.
fn own_entries(
    dir: &Path,
    keep: impl Fn(&str, fs::FileType) -> bool,
) -> Result<Vec<(String, PathBuf)>, ArchiveError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(ArchiveError::io(dir))? {
        let entry = entry.map_err(ArchiveError::io(dir))?;
        let kind = entry.file_type().map_err(ArchiveError::io(entry.path()))?;
        if let Some(name) = entry.file_name().to_str() {
            if keep(name, kind) {
                out.push((name.to_owned(), entry.path()));
            }
        }
    }
    Ok(out)
}

/// The digest of `schedule` (ascending by epoch) in force at `epoch`, `None` before its first.
fn digest_at(schedule: &[(Epoch, ForkDigest)], epoch: Epoch) -> Option<ForkDigest> {
    schedule
        .iter()
        .rev()
        .find(|(from, _)| *from <= epoch)
        .map(|(_, digest)| *digest)
}

/// The first slot of the aligned window of `slots_per_segment` slots that holds `slot`.
fn window_start(slot: Slot, slots_per_segment: u64) -> Slot {
    slot - slot % slots_per_segment
}

fn create_dir(dir: &Path) -> Result<(), ArchiveError> {
    fs::DirBuilder::new()
        .mode(DIR_MODE)
        .create(dir)
        .map_err(ArchiveError::io(dir))
}

/// Creates `dir` and every missing parent, top down, fsyncing the parent of each directory it
/// creates, so a power loss cannot drop a new archive root with everything in it. A `dir` that
/// exists (even as a symlink or a file) is left for the caller to check.
fn create_dir_all_durable(dir: &Path, sync: &mut SyncFault) -> Result<(), ArchiveError> {
    let mut missing = Vec::new();
    let mut at = dir;
    loop {
        match fs::symlink_metadata(at) {
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::NotFound => missing.push(at),
            Err(e) => return Err(ArchiveError::io(at)(e)),
        }
        match at.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => at = parent,
            _ => break,
        }
    }
    for created in missing.into_iter().rev() {
        match fs::DirBuilder::new().mode(DIR_MODE).create(created) {
            Ok(()) => {}
            // Created meanwhile by someone else, who made it durable.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(ArchiveError::io(created)(e)),
        }
        let parent = created
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        sync_dir(parent, sync)?;
    }
    Ok(())
}

/// Creates `dir` exclusively, after any missing parent ([`create_dir_all_durable`]), and makes
/// it durable in its parent: of two callers racing for one `dir`, exactly one succeeds and the
/// other gets `AlreadyExists`, so `dir` is claimed before anything is written into it.
pub(crate) fn create_dir_new_durable(dir: &Path) -> Result<(), ArchiveError> {
    let mut sync = SyncFault::default();
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    create_dir_all_durable(parent, &mut sync)?;
    create_dir(dir)?;
    sync_dir(parent, &mut sync)
}

/// fsyncs a directory, so a create or rename in it is durable.
fn sync_dir(dir: &Path, fault: &mut SyncFault) -> Result<(), ArchiveError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .and_then(|()| injected_sync_failure(dir, fault))
        .map_err(ArchiveError::io(dir))
}

/// A pending [`Fault::DirSync`]: the directory whose next fsync fails.
#[cfg(any(test, feature = "test-support"))]
type SyncFault = Option<PathBuf>;
#[cfg(not(any(test, feature = "test-support")))]
type SyncFault = Option<std::convert::Infallible>;

#[cfg(any(test, feature = "test-support"))]
fn injected_sync_failure(dir: &Path, fault: &mut SyncFault) -> io::Result<()> {
    if fault.as_deref() != Some(dir) {
        return Ok(());
    }
    *fault = None;
    Err(io::Error::other("injected: directory fsync failed"))
}

#[cfg(not(any(test, feature = "test-support")))]
fn injected_sync_failure(_: &Path, _: &mut SyncFault) -> io::Result<()> {
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
type WriteFault = Option<Fault>;
#[cfg(not(any(test, feature = "test-support")))]
type WriteFault = Option<std::convert::Infallible>;

/// Writes `dir/name` durably: a hidden temp file, fsync, a move that never replaces an existing
/// `name` ([`rename_no_replace`]), directory fsync. The temp file is always removed, so no
/// partial file is left behind but by a crash.
pub(crate) fn write_durable(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    fault: WriteFault,
    sync: &mut SyncFault,
) -> Result<(), ArchiveError> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut crashed = false;
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&tmp)
        .and_then(|mut file| {
            write_all(&mut file, bytes, fault, &mut crashed)?;
            file.sync_all()
        })
        .map_err(ArchiveError::io(&tmp));
    if let Err(e) = written {
        if !crashed {
            let _ = fs::remove_file(&tmp);
        }
        return Err(e);
    }
    let target = dir.join(name);
    let linked = rename_no_replace(&tmp, &target);
    let _ = fs::remove_file(&tmp);
    linked.map_err(ArchiveError::io(target))?;
    sync_dir(dir, sync)
}

/// Moves `from` to `to` without ever replacing an existing `to` (`AlreadyExists` then): a hard
/// link, which refuses an existing target atomically, then the unlink of `from` by the caller.
/// A crash between the two leaves both names of one complete file, in a directory that is not
/// sealed yet. (A `RENAME_NOREPLACE` rename would need a syscall crate this crate does not
/// link.)
fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::hard_link(from, to)
}

#[cfg(any(test, feature = "test-support"))]
fn write_all(
    file: &mut File,
    bytes: &[u8],
    fault: WriteFault,
    crashed: &mut bool,
) -> io::Result<()> {
    match fault {
        None | Some(Fault::DirSync { .. }) => file.write_all(bytes),
        Some(Fault::Crash { after }) => {
            file.write_all(&bytes[..after.min(bytes.len())])?;
            *crashed = true;
            Err(io::Error::other("injected crash"))
        }
        Some(Fault::DiskFull { after }) => {
            file.write_all(&bytes[..after.min(bytes.len())])?;
            Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "injected: disk full",
            ))
        }
    }
}

#[cfg(not(any(test, feature = "test-support")))]
fn write_all(file: &mut File, bytes: &[u8], _: WriteFault, _: &mut bool) -> io::Result<()> {
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::fixtures::{self, Spec};
    use crate::archive::manifest::Sha256Digest;

    const COLUMN: &str = "data_column_sidecar_3";

    fn config(slots_per_segment: u64) -> CaptureConfig {
        CaptureConfig {
            network: "devnet".into(),
            topics: vec![COLUMN.into(), "beacon_block".into()],
            capture_host: "probe-1".into(),
            clock_source: "chrony".into(),
            slots_per_segment,
            max_bytes: 1 << 30,
            fork_digests: fixtures::fork_digests(),
        }
    }

    fn writer(out: &Path, config: CaptureConfig) -> Writer<Spec> {
        Writer::create(out, config, fixtures::chain()).unwrap()
    }

    fn put_block(w: &mut Writer<Spec>, slot: Slot) -> Result<Stored, ArchiveError> {
        let (payload, _) = fixtures::block(slot, 0);
        w.put(Capture {
            topic: "beacon_block",
            fork_digest: fixtures::fork_digest(slot),
            payload: &payload,
        })
    }

    fn manifest(segment: &Path) -> Manifest {
        Manifest::parse(&fs::read(segment.join(MANIFEST_FILE)).unwrap())
            .unwrap()
            .0
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn sha256(bytes: &[u8]) -> Sha256Digest {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn stores_payloads_as_delivered_with_their_roots() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(32));
        w.set_peer_count(31);
        let (block, block_root) = fixtures::block(10, 0);
        let (column, column_root) = fixtures::column(10, 0, 3);
        assert_eq!(column_root, block_root);
        let stored = w
            .put(Capture {
                topic: "beacon_block",
                fork_digest: fixtures::BPO_DIGEST,
                payload: &block,
            })
            .unwrap();
        assert_eq!(
            stored,
            Stored {
                path: format!("beacon_block/{}", file_name(10, &block_root)),
                slot: 10,
                root: block_root,
            }
        );
        w.put(Capture {
            topic: COLUMN,
            fork_digest: fixtures::BPO_DIGEST,
            payload: &column,
        })
        .unwrap();

        let sealed = w.close().unwrap();
        let segment = out.path().join("devnet").join("10-10");
        assert_eq!(sealed, vec![segment.clone()]);
        assert_eq!(names(&out.path().join("devnet")), ["10-10"]);
        assert_eq!(names(&segment), ["beacon_block", COLUMN, MANIFEST_FILE]);
        assert_eq!(fs::read(segment.join(&stored.path)).unwrap(), block);

        let m = manifest(&segment);
        assert_eq!(
            (m.network.as_str(), m.preset.as_str()),
            ("devnet", "minimal")
        );
        assert_eq!((m.slot_start, m.slot_end), (10, 10));
        assert_eq!(m.topics, ["beacon_block", COLUMN]);
        assert_eq!(m.fork_digests, [fixtures::BPO_DIGEST]);
        assert_eq!((m.peer_count, m.capture_host.as_str()), (31, "probe-1"));
        assert_eq!((m.closed_by, m.error), (ClosedBy::Close, None));
        assert_eq!(m.total_bytes, (block.len() + column.len()) as u64);
        let roots: Vec<_> = m.files.iter().map(|f| (f.topic.as_str(), f.root)).collect();
        assert_eq!(roots, [("beacon_block", block_root), (COLUMN, column_root)]);
        assert_eq!(m.files[0].sha256, sha256(&block));
        assert_eq!(m.files[1].sha256, sha256(&column));
    }

    #[test]
    fn rolls_on_aligned_windows() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        for slot in [3, 5, 9, 17, 18] {
            put_block(&mut w, slot).unwrap();
        }
        assert_eq!(w.sealed().len(), 2);
        let net = out.path().join("devnet");
        assert_eq!(
            w.close().unwrap(),
            ["3-7", "8-15", "16-18"].map(|s| net.join(s))
        );
        let ranges: Vec<_> = ["3-7", "8-15", "16-18"]
            .iter()
            .map(|s| {
                let m = manifest(&net.join(s));
                (
                    m.closed_by,
                    m.files.iter().map(|f| f.slot).collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            ranges,
            [
                (ClosedBy::Roll, vec![3, 5]),
                (ClosedBy::Roll, vec![9]),
                (ClosedBy::Close, vec![17, 18])
            ]
        );
    }

    #[test]
    fn a_segment_rolls_before_its_manifest_would_pass_the_limit() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(64));
        // Room for exactly the first three files.
        let entry = |slot: Slot| {
            let (payload, root) = fixtures::block(slot, 0);
            manifest_file_len_bound(&ArchiveFile {
                path: file_path("beacon_block", slot, &root),
                topic: "beacon_block".into(),
                slot,
                root,
                fork_digest: fixtures::fork_digest(slot),
                len: payload.len() as u64,
                sha256: sha256(&payload),
            })
        };
        let limit = w.manifest_base_len + entry(1) + entry(2) + entry(3);
        w.set_max_manifest_len(limit);
        for slot in 1..=7 {
            put_block(&mut w, slot).unwrap();
        }
        let sealed = w.close().unwrap();
        let net = out.path().join("devnet");
        assert_eq!(sealed, ["1-3", "4-6", "7-7"].map(|s| net.join(s)));
        let mut slots = Vec::new();
        for (segment, closed_by) in
            sealed
                .iter()
                .zip([ClosedBy::Roll, ClosedBy::Roll, ClosedBy::Close])
        {
            let len = fs::metadata(segment.join(MANIFEST_FILE)).unwrap().len();
            assert!(len <= limit, "{len} > {limit}");
            let archive = crate::archive::open_verified(segment).unwrap();
            assert_eq!(archive.manifest().closed_by, closed_by);
            slots.extend(archive.files().iter().map(|f| f.slot));
        }
        assert_eq!(slots, (1..=7).collect::<Vec<_>>());
    }

    #[test]
    fn a_config_too_large_for_any_manifest_is_refused() {
        let out = tempfile::tempdir().unwrap();
        let e = Writer::<Spec>::create(
            out.path(),
            CaptureConfig {
                clock_source: "x".repeat(MAX_MANIFEST_LEN as usize),
                ..config(8)
            },
            fixtures::chain(),
        )
        .unwrap_err();
        assert!(
            matches!(&e, ArchiveError::Config(m) if m.contains("manifest")),
            "{e}"
        );
    }

    #[test]
    fn a_late_payload_joins_the_open_segment() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 9).unwrap();
        put_block(&mut w, 2).unwrap();
        let sealed = w.close().unwrap();
        assert_eq!(sealed, [out.path().join("devnet/2-9")]);
        let m = manifest(&sealed[0]);
        assert_eq!(m.files.iter().map(|f| f.slot).collect::<Vec<_>>(), [2, 9]);
    }

    #[test]
    fn refused_payloads_do_not_stop_the_capture() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        let (block, _) = fixtures::block(4, 0);
        // The same block message (so the same root) under another signature.
        let mut other = p2p_wire::testkit::fulu_block::<Spec>(4);
        other.message.proposer_index = 0;
        other.signature = [0x11; 96];
        let other = fixtures::snappy(&ssz::Encode::as_ssz_bytes(&other));
        let put = |w: &mut Writer<Spec>, topic, payload| {
            w.put(Capture {
                topic,
                fork_digest: fixtures::FULU_DIGEST,
                payload,
            })
        };
        put(&mut w, "beacon_block", &block).unwrap();
        let refusals = [
            put(&mut w, "voluntary_exit", &block),
            put(&mut w, "../beacon_block", &block),
            put(&mut w, "beacon_block", b"garbage"),
            put(&mut w, COLUMN, &block),
            put(&mut w, "beacon_block", &block),
            put(&mut w, "beacon_block", &other),
        ];
        for r in &refusals {
            let e = r.as_ref().unwrap_err();
            assert!(!e.stops_capture(), "{e}");
        }
        assert!(matches!(
            refusals[0],
            Err(ArchiveError::Payload(PayloadError::Unsubscribed(_)))
        ));
        assert!(matches!(
            refusals[4],
            Err(ArchiveError::Payload(PayloadError::Duplicate {
                identical: true,
                ..
            }))
        ));
        assert!(matches!(
            refusals[5],
            Err(ArchiveError::Payload(PayloadError::Duplicate {
                identical: false,
                ..
            }))
        ));
        put_block(&mut w, 5).unwrap();
        let sealed = w.close().unwrap();
        assert_eq!(manifest(&sealed[0]).files.len(), 2);
    }

    #[test]
    fn a_payload_on_another_fork_digest_than_its_slots_is_refused() {
        use fixtures::{BPO_DIGEST, FULU_DIGEST, GLOAS_DIGEST, GLOAS_SLOT};
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(64));
        let mut put = |slot: Slot, fork_digest| {
            let (payload, _) = fixtures::block(slot, 0);
            w.put(Capture {
                topic: "beacon_block",
                fork_digest,
                payload: &payload,
            })
        };
        // The blob-parameter change at epoch 1 changes the digest inside Fulu.
        for (slot, wrong, right) in [
            (7, BPO_DIGEST, FULU_DIGEST),
            (8, FULU_DIGEST, BPO_DIGEST),
            (GLOAS_SLOT - 1, GLOAS_DIGEST, BPO_DIGEST),
            (GLOAS_SLOT, BPO_DIGEST, GLOAS_DIGEST),
        ] {
            let e = put(slot, wrong).unwrap_err();
            assert!(
                matches!(
                    &e,
                    ArchiveError::Payload(PayloadError::ForkDigest { slot: s, expected, got })
                        if *s == slot && *expected == Some(right) && *got == wrong
                ),
                "{slot}: {e}"
            );
            assert!(!e.stops_capture());
            put(slot, right).unwrap();
        }
        let sealed = w.close().unwrap();
        let mut every = vec![FULU_DIGEST, BPO_DIGEST, GLOAS_DIGEST];
        every.sort();
        assert_eq!(manifest(&sealed[0]).fork_digests, every);

        // A slot before the first digest has none.
        let mut w = writer(
            out.path(),
            CaptureConfig {
                fork_digests: vec![(1, BPO_DIGEST)],
                ..config(8)
            },
        );
        let e = put_block(&mut w, 3).unwrap_err();
        assert!(
            matches!(
                &e,
                ArchiveError::Payload(PayloadError::ForkDigest { expected: None, .. })
            ),
            "{e}"
        );
    }

    #[test]
    fn the_disk_budget_stops_the_capture_and_the_seal_says_so() {
        let out = tempfile::tempdir().unwrap();
        let (block, _) = fixtures::block(4, 0);
        let mut w = writer(
            out.path(),
            CaptureConfig {
                max_bytes: block.len() as u64 + 10,
                ..config(8)
            },
        );
        put_block(&mut w, 4).unwrap();
        let err = put_block(&mut w, 5).unwrap_err();
        assert!(matches!(err, ArchiveError::BudgetExhausted { .. }), "{err}");
        assert!(err.stops_capture());
        assert!(matches!(
            put_block(&mut w, 6),
            Err(ArchiveError::Stopped(_))
        ));
        let sealed = w.close().unwrap();
        let m = manifest(&sealed[0]);
        assert_eq!(m.closed_by, ClosedBy::Error);
        assert!(m.error.unwrap().contains("disk budget"));
        assert_eq!(m.files.iter().map(|f| f.slot).collect::<Vec<_>>(), [4]);
    }

    #[test]
    fn a_budget_exhausted_by_the_payload_that_rolls_seals_an_error() {
        let out = tempfile::tempdir().unwrap();
        let (block, _) = fixtures::block(4, 0);
        let mut w = writer(
            out.path(),
            CaptureConfig {
                max_bytes: block.len() as u64 + 10,
                ..config(8)
            },
        );
        put_block(&mut w, 4).unwrap();
        // Slot 9 is past the window and over the budget.
        let err = put_block(&mut w, 9).unwrap_err();
        assert!(matches!(err, ArchiveError::BudgetExhausted { .. }), "{err}");
        assert!(w.sealed().is_empty(), "not sealed as a roll");
        let sealed = w.close().unwrap();
        assert_eq!(sealed, [out.path().join("devnet/4-4")]);
        assert_error_seal(&sealed, &[4], "disk budget");
    }

    #[test]
    fn a_full_disk_mid_write_stops_the_capture_without_a_partial_file() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 4).unwrap();
        w.inject_fault(Fault::DiskFull { after: 7 });
        let err = put_block(&mut w, 5).unwrap_err();
        assert!(
            matches!(&err, ArchiveError::Io { source, .. } if source.kind() == io::ErrorKind::StorageFull),
            "{err}"
        );
        assert!(matches!(
            put_block(&mut w, 6),
            Err(ArchiveError::Stopped(_))
        ));
        let sealed = w.close().unwrap();
        assert_eq!(sealed, [out.path().join("devnet/4-4")]);
        assert_eq!(
            names(&sealed[0].join("beacon_block")).len(),
            1,
            "no temp file left"
        );
        let m = manifest(&sealed[0]);
        assert_eq!(m.closed_by, ClosedBy::Error);
        assert!(m.error.unwrap().contains("disk full"));
    }

    /// The seal of a stopped capture verifies, holds every payload stored before the stop and
    /// says why it stopped.
    fn assert_error_seal(sealed: &[PathBuf], slots: &[Slot], reason: &str) {
        let archive = crate::archive::open_verified(sealed.last().unwrap()).unwrap();
        let m = archive.manifest();
        assert_eq!(m.closed_by, ClosedBy::Error);
        assert!(
            m.error.as_deref().unwrap().contains(reason),
            "{:?}",
            m.error
        );
        assert_eq!(m.files.iter().map(|f| f.slot).collect::<Vec<_>>(), slots);
        for file in archive.files() {
            archive.read(file).unwrap();
        }
    }

    #[test]
    fn a_failed_first_write_to_a_new_topic_leaves_a_readable_archive() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 4).unwrap();
        w.inject_fault(Fault::DiskFull { after: 3 });
        let (column, _) = fixtures::column(4, 0, 3);
        let e = w
            .put(Capture {
                topic: COLUMN,
                fork_digest: fixtures::FULU_DIGEST,
                payload: &column,
            })
            .unwrap_err();
        assert!(e.stops_capture(), "{e}");
        let sealed = w.close().unwrap();
        assert_eq!(names(&sealed[0]), ["beacon_block", MANIFEST_FILE]);
        assert_error_seal(&sealed, &[4], "disk full");
    }

    #[test]
    fn a_failed_fsync_after_the_rename_leaves_a_readable_archive() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 4).unwrap();
        let topic_dir = out
            .path()
            .join("devnet")
            .join(format!("{OPEN_PREFIX}0-0/beacon_block"));
        w.inject_fault(Fault::DirSync {
            dir: topic_dir.clone(),
        });
        let e = put_block(&mut w, 5).unwrap_err();
        assert!(
            matches!(&e, ArchiveError::Io { path, .. } if *path == topic_dir),
            "{e}"
        );
        assert_eq!(names(&topic_dir).len(), 2, "the renamed file is there");
        let sealed = w.close().unwrap();
        assert_eq!(names(&sealed[0].join("beacon_block")).len(), 1);
        assert_error_seal(&sealed, &[4], "injected");
    }

    #[test]
    fn a_crash_leaves_no_archive_for_the_open_segment() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 4).unwrap();
        w.inject_fault(Fault::Crash { after: 7 });
        assert!(put_block(&mut w, 5).unwrap_err().stops_capture());
        drop(w);
        let net = out.path().join("devnet");
        let open = names(&net);
        assert_eq!(open.len(), 1);
        assert!(open[0].starts_with(OPEN_PREFIX), "{open:?}");
        assert!(!net.join(&open[0]).join(MANIFEST_FILE).exists());
        let topic = names(&net.join(&open[0]).join("beacon_block"));
        assert_eq!(
            topic.len(),
            2,
            "the complete file and the crashed temp file"
        );
        assert!(topic
            .iter()
            .any(|n| n.starts_with('.') && n.ends_with(".tmp")));
    }

    #[test]
    fn an_outside_stop_is_sealed_as_an_error() {
        let out = tempfile::tempdir().unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 4).unwrap();
        w.stop("the tap disconnected".into());
        w.stop("a later reason".into());
        let e = put_block(&mut w, 5).unwrap_err();
        assert!(
            matches!(&e, ArchiveError::Stopped(r) if r == "the tap disconnected"),
            "{e}"
        );
        let sealed = w.close().unwrap();
        let m = manifest(&sealed[0]);
        assert_eq!(m.closed_by, ClosedBy::Error);
        assert_eq!(m.error.as_deref(), Some("the tap disconnected"));
    }

    #[test]
    fn a_taken_segment_name_keeps_the_sealed_segment() {
        let out = tempfile::tempdir().unwrap();
        fs::create_dir_all(out.path().join("devnet/4-4")).unwrap();
        let mut w = writer(out.path(), config(8));
        put_block(&mut w, 4).unwrap();
        let err = w.close().unwrap_err();
        let ArchiveError::SegmentExists { open, .. } = err else {
            panic!("{err}");
        };
        assert_eq!(manifest(&open).files.len(), 1);
        assert!(names(&out.path().join("devnet/4-4")).is_empty());
    }

    #[test]
    fn an_empty_capture_leaves_nothing() {
        let out = tempfile::tempdir().unwrap();
        let w = writer(out.path(), config(8));
        assert_eq!(w.close().unwrap(), Vec::<PathBuf>::new());
        assert!(names(&out.path().join("devnet")).is_empty());

        let (block, _) = fixtures::block(4, 0);
        let mut w = writer(
            out.path(),
            CaptureConfig {
                max_bytes: 1,
                ..config(8)
            },
        );
        assert!(w
            .put(Capture {
                topic: "beacon_block",
                fork_digest: fixtures::FULU_DIGEST,
                payload: &block,
            })
            .unwrap_err()
            .stops_capture());
        assert_eq!(w.close().unwrap(), Vec::<PathBuf>::new());
        assert!(names(&out.path().join("devnet")).is_empty());
    }

    #[test]
    fn the_config_is_checked() {
        let out = tempfile::tempdir().unwrap();
        let refuse = |config: CaptureConfig| {
            Writer::<Spec>::create(out.path(), config, fixtures::chain()).unwrap_err()
        };
        let e = refuse(CaptureConfig {
            network: "..".into(),
            ..config(8)
        });
        assert!(matches!(e, ArchiveError::Name(_)), "{e}");
        let e = refuse(CaptureConfig {
            topics: vec!["../x".into()],
            ..config(8)
        });
        assert!(matches!(e, ArchiveError::Name(_)), "{e}");
        let e = refuse(CaptureConfig {
            topics: vec!["voluntary_exit".into()],
            ..config(8)
        });
        assert!(matches!(e, ArchiveError::Name(_)), "{e}");
        for bad in [
            CaptureConfig {
                topics: vec![],
                ..config(8)
            },
            config(0),
            CaptureConfig {
                capture_host: String::new(),
                ..config(8)
            },
            CaptureConfig {
                clock_source: String::new(),
                ..config(8)
            },
            CaptureConfig {
                fork_digests: vec![],
                ..config(8)
            },
            CaptureConfig {
                fork_digests: vec![(1, [1; 4]), (1, [2; 4])],
                ..config(8)
            },
            CaptureConfig {
                fork_digests: vec![(2, [1; 4]), (1, [2; 4])],
                ..config(8)
            },
        ] {
            assert!(matches!(refuse(bad), ArchiveError::Config(_)));
        }
        // Duplicate topics collapse; nothing is created for a refused config.
        let w = writer(
            out.path(),
            CaptureConfig {
                topics: vec!["beacon_block".into(), "beacon_block".into()],
                ..config(8)
            },
        );
        assert_eq!(w.config.topics, ["beacon_block"]);
    }

    #[test]
    fn a_durable_write_never_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("taken"), b"old").unwrap();
        let e = write_durable(dir.path(), "taken", b"new", None, &mut None).unwrap_err();
        assert!(
            matches!(&e, ArchiveError::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists),
            "{e}"
        );
        assert_eq!(fs::read(dir.path().join("taken")).unwrap(), b"old");
        assert_eq!(names(dir.path()), ["taken"], "no temp file left");
        write_durable(dir.path(), "free", b"new", None, &mut None).unwrap();
        assert_eq!(fs::read(dir.path().join("free")).unwrap(), b"new");
        assert_eq!(names(dir.path()), ["free", "taken"]);
    }

    #[test]
    fn every_created_directory_is_made_durable_in_its_parent() {
        // `out` and its parent are missing: `a`, `a/b` and `a/b/devnet` are created, so `.`,
        // `a` and `a/b` must each be fsynced.
        for parent in ["", "a", "a/b"] {
            let tmp = tempfile::tempdir().unwrap();
            let out = tmp.path().join("a/b");
            let dir = tmp.path().join(parent);
            let fault = Fault::DirSync { dir: dir.clone() };
            let e = Writer::<Spec>::create_with_fault(&out, config(8), fixtures::chain(), fault)
                .unwrap_err();
            assert!(
                matches!(&e, ArchiveError::Io { path, .. } if *path == dir),
                "{parent:?}: {e}"
            );
        }
        // Nothing is created under an existing network directory, so nothing is synced.
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("devnet")).unwrap();
        let fault = Fault::DirSync {
            dir: tmp.path().to_owned(),
        };
        Writer::<Spec>::create_with_fault(tmp.path(), config(8), fixtures::chain(), fault).unwrap();
    }

    #[test]
    fn a_symlinked_network_dir_is_refused() {
        let out = tempfile::tempdir().unwrap();
        let elsewhere = out.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let link = out.path().join("devnet");
        std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
        let refuse = || Writer::<Spec>::create(out.path(), config(8), fixtures::chain());
        let e = refuse().unwrap_err();
        assert!(matches!(&e, ArchiveError::NotRegular(_)), "{e}");
        assert!(names(&elsewhere).is_empty());
        // A dangling one, and a file, the same.
        fs::remove_dir(&elsewhere).unwrap();
        assert!(matches!(refuse(), Err(ArchiveError::NotRegular(_))));
        fs::remove_file(&link).unwrap();
        fs::write(&link, b"").unwrap();
        assert!(matches!(refuse(), Err(ArchiveError::NotRegular(_))));
    }

    #[test]
    fn an_unwritable_out_dir_is_an_io_error() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("file");
        fs::write(&file, b"").unwrap();
        let e = Writer::<Spec>::create(&file, config(8), fixtures::chain()).unwrap_err();
        assert!(matches!(e, ArchiveError::Io { .. }), "{e}");
    }
}
