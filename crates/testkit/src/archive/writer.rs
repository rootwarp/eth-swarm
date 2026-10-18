//! [`Writer`]: a capture into rolling segments.
//!
//! A segment is built in `<out>/<network>/.open-<window_start>-<n>/`. Every payload is written
//! to a hidden temp name in its topic directory, fsynced, renamed to
//! `<topic>/<slot>_0x<root>.ssz_snappy`, and the directory fsynced, so a named file is always
//! complete. Sealing writes `manifest.toml` the same way and then renames the directory to
//! `<out>/<network>/<slot_start>-<slot_end>/`. A crash before the seal leaves only an `.open-*`
//! directory without a manifest, which is no archive: nothing a manifest references can be
//! partial, and at most one segment of payloads is lost.
//!
//! Segments roll on aligned windows of `slots_per_segment` slots: the first payload at or past
//! the open window's end seals the open segment ([`ClosedBy::Roll`]) and opens the next. A late
//! payload, for a slot before the open window, joins the open segment and lowers its
//! `slot_start`, so segments can overlap but never drop a payload. A segment covers its whole
//! window when it rolls, from its window start when a roll opened it, from its first slot when
//! the capture opened it, and up to its last slot when it closes.
//!
//! The payload bytes are kept under a disk budget (`max_bytes`); passing it, or any write
//! error such as a full disk, stops the capture with an error. [`Writer::close`] then still
//! seals what was written, marked [`ClosedBy::Error`] with the reason, so a stopped capture is
//! never mistaken for a complete one.

use super::error::ArchiveError;
use super::manifest::{ArchiveFile, ClosedBy, ForkDigest, Manifest, MANIFEST_FILE};
use super::names::{
    file_name, file_path, segment_name, validate_network, validate_topic, TopicKind,
};
use super::payload::{decode_payload, ChainParams, PayloadError};
use consensus_types::primitives::{Root, Slot};
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

/// An injected write fault (feature `test-support`), applied to the next payload write.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    #[cfg(any(test, feature = "test-support"))]
    fault: Option<Fault>,
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
}

impl<E: EthSpec> Writer<E> {
    /// Starts a capture into `<out>/<network>/`, creating it if missing. Refuses an invalid
    /// network or topic name, a topic the archive cannot file, an empty host or clock source,
    /// and a zero segment window.
    pub fn create(
        out: &Path,
        mut config: CaptureConfig,
        chain: ChainParams,
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
        let network_dir = out.join(&config.network);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&network_dir)
            .map_err(ArchiveError::io(&network_dir))?;
        sync_dir(out)?;
        Ok(Self {
            network_dir,
            config,
            chain,
            open: None,
            sealed: Vec::new(),
            written: 0,
            peer_count: 0,
            stopped: None,
            #[cfg(any(test, feature = "test-support"))]
            fault: None,
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

    /// Injects a write fault into the next payload write (feature `test-support`).
    #[cfg(any(test, feature = "test-support"))]
    pub fn inject_fault(&mut self, fault: Fault) {
        self.fault = Some(fault);
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
        let path = file_path(topic, decoded.slot, &decoded.root);
        let sha256: [u8; 32] = Sha256::digest(payload).into();

        let rolls = self
            .open
            .as_ref()
            .is_some_and(|s| decoded.slot >= s.window_end);
        let covers_from = if rolls {
            self.seal(ClosedBy::Roll)?;
            Some(window_start(decoded.slot, self.config.slots_per_segment))
        } else {
            None
        };
        if let Some(existing) = self.open.as_ref().and_then(|s| s.files.get(&path)) {
            return Err(PayloadError::Duplicate {
                path,
                identical: existing.sha256 == sha256,
            }
            .into());
        }
        let len = payload.len() as u64;
        if self.written.saturating_add(len) > self.config.max_bytes {
            return Err(ArchiveError::BudgetExhausted {
                budget: self.config.max_bytes,
                written: self.written,
                needed: len,
            });
        }
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
            sync_dir(&segment.dir)?;
            segment.topic_dirs.insert(topic.to_owned());
        }
        write_durable(
            &topic_dir,
            &file_name(decoded.slot, &decoded.root),
            payload,
            fault,
        )?;
        segment.covers_from = segment.covers_from.min(decoded.slot);
        segment.last_slot = segment.last_slot.max(decoded.slot);
        segment.files.insert(
            path.clone(),
            ArchiveFile {
                path: path.clone(),
                topic: topic.to_owned(),
                slot: decoded.slot,
                root: decoded.root,
                fork_digest,
                len,
                sha256,
            },
        );
        self.written += len;
        Ok(Stored {
            path,
            slot: decoded.slot,
            root: decoded.root,
        })
    }

    /// Creates `.open-<window_start>-<n>` for a segment whose window holds `slot`.
    fn open_segment(&self, slot: Slot, covers_from: Slot) -> Result<Segment, ArchiveError> {
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
        sync_dir(&self.network_dir)?;
        Ok(Segment {
            dir,
            window_end: start.saturating_add(self.config.slots_per_segment),
            covers_from,
            last_slot: slot,
            files: BTreeMap::new(),
            topic_dirs: BTreeSet::new(),
        })
    }

    /// Seals the open segment, if any: manifest, then the rename to its slot range.
    fn seal(&mut self, closed_by: ClosedBy) -> Result<(), ArchiveError> {
        let Some(segment) = self.open.take() else {
            return Ok(());
        };
        if segment.files.is_empty() {
            for topic in &segment.topic_dirs {
                let _ = fs::remove_dir(segment.dir.join(topic));
            }
            return fs::remove_dir(&segment.dir).map_err(ArchiveError::io(&segment.dir));
        }
        let slot_end = match closed_by {
            // A window at the top of the slot range ends where TOML integers do.
            ClosedBy::Roll => (segment.window_end - 1).min(i64::MAX as u64),
            ClosedBy::Close | ClosedBy::Error => segment.last_slot,
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
                .clone()
                .filter(|_| closed_by == ClosedBy::Error),
            total_bytes: files.iter().map(|f| f.len).sum(),
            files,
        };
        let manifest_path = segment.dir.join(MANIFEST_FILE);
        let (bytes, _) = manifest.render().map_err(|source| ArchiveError::Manifest {
            path: manifest_path,
            source,
        })?;
        write_durable(&segment.dir, MANIFEST_FILE, &bytes, None)?;

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
        sync_dir(&self.network_dir)?;
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
        self.seal(closed_by)?;
        Ok(self.sealed)
    }
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

/// fsyncs a directory, so a create or rename in it is durable.
fn sync_dir(dir: &Path) -> Result<(), ArchiveError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(ArchiveError::io(dir))
}

#[cfg(any(test, feature = "test-support"))]
type WriteFault = Option<Fault>;
#[cfg(not(any(test, feature = "test-support")))]
type WriteFault = Option<std::convert::Infallible>;

/// Writes `dir/name` durably: a hidden temp file, fsync, rename, directory fsync. On an error
/// the temp file is removed, so no partial file is left behind.
fn write_durable(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    fault: WriteFault,
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
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        return Err(ArchiveError::io(target)(e));
    }
    sync_dir(dir)
}

#[cfg(any(test, feature = "test-support"))]
fn write_all(
    file: &mut File,
    bytes: &[u8],
    fault: WriteFault,
    crashed: &mut bool,
) -> io::Result<()> {
    match fault {
        None => file.write_all(bytes),
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

    const DIGEST: ForkDigest = [0xf0, 1, 0, 1];
    const COLUMN: &str = "data_column_sidecar_3";

    fn config(slots_per_segment: u64) -> CaptureConfig {
        CaptureConfig {
            network: "devnet".into(),
            topics: vec![COLUMN.into(), "beacon_block".into()],
            capture_host: "probe-1".into(),
            clock_source: "chrony".into(),
            slots_per_segment,
            max_bytes: 1 << 30,
        }
    }

    fn writer(out: &Path, config: CaptureConfig) -> Writer<Spec> {
        Writer::create(out, config, fixtures::chain()).unwrap()
    }

    fn put_block(w: &mut Writer<Spec>, slot: Slot) -> Result<Stored, ArchiveError> {
        let (payload, _) = fixtures::block(slot, 0);
        w.put(Capture {
            topic: "beacon_block",
            fork_digest: DIGEST,
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
                fork_digest: DIGEST,
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
            fork_digest: [0xf0, 1, 0, 2],
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
        assert_eq!(m.fork_digests, [DIGEST, [0xf0, 1, 0, 2]]);
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
                fork_digest: DIGEST,
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
                fork_digest: DIGEST,
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
    fn an_unwritable_out_dir_is_an_io_error() {
        let out = tempfile::tempdir().unwrap();
        let file = out.path().join("file");
        fs::write(&file, b"").unwrap();
        let e = Writer::<Spec>::create(&file, config(8), fixtures::chain()).unwrap_err();
        assert!(matches!(e, ArchiveError::Io { .. }), "{e}");
    }
}
