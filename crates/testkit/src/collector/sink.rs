//! [`Collector`]: turns stamped arrivals into a capture directory, off the hot path.
//!
//! ```text
//! <dir>/capture.toml    what the capture is (network, genesis, slot duration, sources, host)
//! <dir>/records.jsonl   one ArrivalRecord per line, in arrival order
//! <dir>/gaps.jsonl      one MissingInterval per line, as each one closes
//! <dir>/ntp.jsonl       one NtpSample per line
//! <dir>/summary.toml    written at the end: counts and every missing interval, for the manifest
//! ```
//!
//! Gossip payloads are decoded here (slot, block root) and handed to the archive
//! ([`crate::archive::Writer`]) as received; SSE events are decoded from their JSON. A message
//! that does not decode is still recorded, with no slot or root, and counted. Every file is
//! created new: a capture never overwrites another.

use super::arrival::{Arrival, Drops, MissingInterval};
use super::decode::{decode_gossip, decode_sse, parse_gossip_topic, topic_subnet};
use super::ntp::NtpSample;
use super::record::{ArrivalRecord, Source};
use crate::archive::{ArchiveError, Capture, ChainParams, PayloadError, TopicKind, Writer};
use consensus_types::EthSpec;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// `capture.toml`.
pub const CAPTURE_FILE: &str = "capture.toml";
/// `records.jsonl`.
pub const RECORDS_FILE: &str = "records.jsonl";
/// `gaps.jsonl`.
pub const GAPS_FILE: &str = "gaps.jsonl";
/// `ntp.jsonl`.
pub const NTP_FILE: &str = "ntp.jsonl";
/// `summary.toml`.
pub const SUMMARY_FILE: &str = "summary.toml";

/// What a capture is: `capture.toml`, everything the offsets need besides the records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureInfo {
    /// The network (`hoodi`, `sepolia`).
    pub network: String,
    /// `genesis_time`, Unix seconds.
    pub genesis_time: u64,
    /// `SLOT_DURATION_MS` of the network's config.
    pub slot_duration_ms: u64,
    /// `DATA_COLUMN_SIDECAR_SUBNET_COUNT`, for the subnet of an SSE column.
    pub column_subnet_count: u64,
    /// The sources collected.
    pub sources: Vec<Source>,
    /// The SSE event names subscribed.
    pub sse_topics: Vec<String>,
    /// The capture host.
    pub host: String,
    /// The time daemon the NTP offset is sampled from (`chrony`, `timesyncd`, `none`).
    pub time_daemon: String,
    /// The capture's start, monotonic nanoseconds.
    pub started_mono_ns: u64,
    /// The capture's start, Unix nanoseconds: relates the monotonic clock to the wall.
    pub started_wall_ns: u64,
}

/// `summary.toml`: what the capture saw, and what it missed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    /// Records written.
    pub records: u64,
    /// Of which gossip.
    pub gossip_records: u64,
    /// Of which SSE.
    pub sse_records: u64,
    /// Records whose payload or JSON did not decode (no slot or root).
    pub undecoded: u64,
    /// Arrivals dropped because the collector was behind.
    pub dropped: u64,
    /// Payloads archived.
    pub archived: u64,
    /// Payloads the archive refused (it went on).
    pub archive_refused: u64,
    /// Why the archive stopped, if it did.
    pub archive_error: Option<String>,
    /// The archive segments sealed.
    pub archive_segments: Vec<String>,
    /// NTP samples taken.
    pub ntp_samples: u64,
    /// Of which failed.
    pub ntp_failures: u64,
    /// Every interval a source was down.
    pub missing: Vec<MissingInterval>,
}

/// Writing the capture failed: it stops.
#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    /// A file system operation failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// A file did not encode or parse.
    #[error("{}: {reason}", path.display())]
    Format {
        /// The file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
}

/// A capture directory being written.
#[derive(Debug)]
pub struct Collector<E: EthSpec> {
    dir: PathBuf,
    records: Lines,
    gaps: Lines,
    ntp: Lines,
    chain: ChainParams,
    column_subnet_count: u64,
    archive: Option<Writer<E>>,
    summary: Summary,
}

/// One JSON-lines file.
#[derive(Debug)]
struct Lines {
    path: PathBuf,
    out: BufWriter<File>,
}

impl Lines {
    fn create(dir: &Path, name: &str) -> Result<Self, CollectorError> {
        let path = dir.join(name);
        let file = create_new(&path)?;
        Ok(Self {
            out: BufWriter::new(file),
            path,
        })
    }

    fn push<T: Serialize>(&mut self, value: &T) -> Result<(), CollectorError> {
        let line = serde_json::to_string(value).map_err(|e| CollectorError::Format {
            path: self.path.clone(),
            reason: e.to_string(),
        })?;
        writeln!(self.out, "{line}").map_err(io_error(&self.path))
    }

    fn flush(&mut self) -> Result<(), CollectorError> {
        self.out.flush().map_err(io_error(&self.path))
    }

    fn finish(mut self) -> Result<(), CollectorError> {
        self.flush()?;
        self.out.get_ref().sync_all().map_err(io_error(&self.path))
    }
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> CollectorError + '_ {
    move |source| CollectorError::Io {
        path: path.to_owned(),
        source,
    }
}

fn create_new(path: &Path) -> Result<File, CollectorError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error(path))
}

fn write_toml<T: Serialize>(path: &Path, value: &T) -> Result<(), CollectorError> {
    let text = toml::to_string(value).map_err(|e| CollectorError::Format {
        path: path.to_owned(),
        reason: e.to_string(),
    })?;
    let mut file = create_new(path)?;
    file.write_all(text.as_bytes()).map_err(io_error(path))?;
    file.sync_all().map_err(io_error(path))
}

impl<E: EthSpec> Collector<E> {
    /// Starts a capture in `dir` (created if missing; refused if it already holds one),
    /// writing `info` to `capture.toml`. Gossip payloads are decoded with `chain` and archived
    /// into `archive` when there is one.
    pub fn create(
        dir: &Path,
        info: CaptureInfo,
        chain: ChainParams,
        archive: Option<Writer<E>>,
    ) -> Result<Self, CollectorError> {
        std::fs::create_dir_all(dir).map_err(io_error(dir))?;
        write_toml(&dir.join(CAPTURE_FILE), &info)?;
        Ok(Self {
            dir: dir.to_owned(),
            records: Lines::create(dir, RECORDS_FILE)?,
            gaps: Lines::create(dir, GAPS_FILE)?,
            ntp: Lines::create(dir, NTP_FILE)?,
            chain,
            column_subnet_count: info.column_subnet_count,
            archive,
            summary: Summary::default(),
        })
    }

    /// Records one arrival. Returns a line worth logging (a gap, an NTP sample, the archive
    /// stopping), if any.
    pub fn handle(&mut self, arrival: Arrival) -> Result<Option<String>, CollectorError> {
        match arrival {
            Arrival::Tap(tap) => {
                let (record, notice) = self.gossip(tap);
                self.record(&record)?;
                Ok(notice)
            }
            Arrival::Sse(stamped) => {
                let (slot, block_root, subnet) =
                    decode_sse(&stamped.event, self.column_subnet_count);
                if slot.is_none() && block_root.is_none() {
                    self.summary.undecoded += 1;
                }
                self.record(&ArrivalRecord {
                    source: Source::Sse,
                    topic: stamped.event.event,
                    subnet,
                    msg_id: None,
                    block_root,
                    slot,
                    recv_mono_ns: stamped.stamp.mono_ns,
                    recv_wall_ns: stamped.stamp.wall_ns,
                    peer: None,
                })?;
                Ok(None)
            }
            Arrival::Gap(gap) => {
                self.gaps.push(&gap)?;
                self.gaps.flush()?;
                let notice = gap_notice(&gap);
                self.summary.missing.push(gap);
                Ok(Some(notice))
            }
            Arrival::Ntp(sample) => {
                self.ntp.push(&sample)?;
                self.summary.ntp_samples += 1;
                self.summary.ntp_failures += u64::from(sample.clock_error_ns.is_none());
                Ok(Some(ntp_notice(&sample)))
            }
        }
    }

    fn record(&mut self, record: &ArrivalRecord) -> Result<(), CollectorError> {
        self.records.push(record)?;
        self.summary.records += 1;
        match record.source {
            Source::Gossip => self.summary.gossip_records += 1,
            Source::Sse => self.summary.sse_records += 1,
        }
        Ok(())
    }

    /// Decodes a tap record and archives its payload.
    fn gossip(&mut self, tap: super::tap::TapRecord) -> (ArrivalRecord, Option<String>) {
        let parsed = parse_gossip_topic(&tap.topic);
        let name = parsed.map_or(tap.topic.as_str(), |t| t.name);
        let decoded = match parsed {
            Some(_) => decode_gossip::<E>(name, &tap.payload, &self.chain),
            None => Ok(None),
        };
        if parsed.is_none() || decoded.is_err() {
            self.summary.undecoded += 1;
        }
        let decoded = decoded.ok().flatten();
        let mut notice = None;
        if let (Some(topic), Some(archive)) = (parsed, self.archive.as_mut()) {
            if TopicKind::of(topic.name).is_ok() {
                let stored = archive.put(Capture {
                    topic: topic.name,
                    fork_digest: topic.fork_digest,
                    payload: &tap.payload,
                });
                match stored {
                    Ok(_) => self.summary.archived += 1,
                    Err(ArchiveError::Payload(PayloadError::Unsubscribed(_))) => {}
                    Err(e) if e.stops_capture() => {
                        if self.summary.archive_error.is_none() {
                            notice = Some(format!("archive stopped: {e}"));
                            self.summary.archive_error = Some(e.to_string());
                        }
                    }
                    Err(_) => self.summary.archive_refused += 1,
                }
            }
        }
        let record = ArrivalRecord {
            source: Source::Gossip,
            topic: name.to_owned(),
            subnet: topic_subnet(name),
            msg_id: Some(format!("0x{}", hex::encode(&tap.msg_id))),
            block_root: decoded.map(|d| d.root),
            slot: decoded.map(|d| d.slot),
            recv_mono_ns: tap.stamp.mono_ns,
            recv_wall_ns: tap.stamp.wall_ns,
            peer: Some(tap.peer),
        };
        (record, notice)
    }

    /// Flushes the line files.
    pub fn flush(&mut self) -> Result<(), CollectorError> {
        self.records.flush()?;
        self.gaps.flush()?;
        self.ntp.flush()
    }

    /// Ends the capture: flushes and syncs the files, closes the archive, writes
    /// `summary.toml` with `dropped` arrivals counted.
    pub fn finish(mut self, dropped: u64) -> Result<Summary, CollectorError> {
        self.records.finish()?;
        self.gaps.finish()?;
        self.ntp.finish()?;
        if let Some(archive) = self.archive.take() {
            let sealed = archive.sealed().to_vec();
            let segments = match archive.close() {
                Ok(segments) => segments,
                Err(e) => {
                    let error = self.summary.archive_error.get_or_insert_with(String::new);
                    if !error.is_empty() {
                        error.push_str("; ");
                    }
                    error.push_str(&format!("closing: {e}"));
                    sealed
                }
            };
            self.summary.archive_segments =
                segments.iter().map(|p| p.display().to_string()).collect();
        }
        self.summary.dropped = dropped;
        write_toml(&self.dir.join(SUMMARY_FILE), &self.summary)?;
        Ok(self.summary)
    }
}

fn gap_notice(gap: &MissingInterval) -> String {
    format!(
        "missing interval: {:?} down for {} ms ({}; {} failed reconnects{})",
        gap.source,
        gap.duration_ns() / 1_000_000,
        gap.reason,
        gap.failed_attempts,
        if gap.open_at_shutdown {
            "; still down at shutdown"
        } else {
            ""
        }
    )
}

fn ntp_notice(sample: &NtpSample) -> String {
    match (&sample.clock_error_ns, &sample.error) {
        (Some(ns), _) => format!(
            "ntp: {} clock error {:+.3} ms (local minus NTP)",
            sample.daemon,
            *ns as f64 / 1e6
        ),
        (None, error) => format!(
            "ntp: {} sample failed: {}",
            sample.daemon,
            error.as_deref().unwrap_or("no value")
        ),
    }
}

/// Runs `collector` over `rx` until every sender is gone (blocking: run it on a blocking
/// thread), flushing whenever the channel is drained, then finishes it. `log` gets every line
/// worth logging.
pub fn collect<E: EthSpec>(
    mut collector: Collector<E>,
    mut rx: mpsc::Receiver<Arrival>,
    drops: &Drops,
    log: &mut dyn FnMut(&str),
) -> Result<Summary, CollectorError> {
    while let Some(arrival) = rx.blocking_recv() {
        let mut next = Some(arrival);
        while let Some(arrival) = next {
            if let Some(line) = collector.handle(arrival)? {
                log(&line);
            }
            next = rx.try_recv().ok();
        }
        collector.flush()?;
    }
    collector.finish(drops.get())
}

/// Reads a capture directory's `capture.toml` and `records.jsonl`.
pub fn read_capture(dir: &Path) -> Result<(CaptureInfo, Vec<ArrivalRecord>), CollectorError> {
    let info_path = dir.join(CAPTURE_FILE);
    let text = std::fs::read_to_string(&info_path).map_err(io_error(&info_path))?;
    let info = toml::from_str(&text).map_err(|e| CollectorError::Format {
        path: info_path.clone(),
        reason: e.to_string(),
    })?;
    let path = dir.join(RECORDS_FILE);
    let file = File::open(&path).map_err(io_error(&path))?;
    let mut records = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(io_error(&path))?;
        let record = serde_json::from_str(&line).map_err(|e| CollectorError::Format {
            path: path.clone(),
            reason: format!("line {}: {e}", i + 1),
        })?;
        records.push(record);
    }
    Ok((info, records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::fixtures::{self, Spec, GLOAS_SLOT};
    use crate::archive::{open_verified, CaptureConfig};
    use crate::collector::arrival::{Arrivals, StampedEvent};
    use crate::collector::clock::Stamp;
    use crate::collector::sse::SseEvent;
    use crate::collector::tap::TapRecord;
    use crate::collector::testing;
    use consensus_types::primitives::Root;

    const DIGEST: &str = "0a1b2c3d";

    fn info() -> CaptureInfo {
        CaptureInfo {
            network: "sepolia".into(),
            genesis_time: 1_655_733_600,
            slot_duration_ms: 12_000,
            column_subnet_count: 128,
            sources: vec![Source::Gossip],
            sse_topics: vec![],
            host: "probe".into(),
            time_daemon: "chrony".into(),
            started_mono_ns: 0,
            started_wall_ns: 1,
        }
    }

    fn tap(name: &str, payload: Vec<u8>, mono_ns: u64) -> Arrival {
        Arrival::Tap(TapRecord {
            stamp: Stamp {
                mono_ns,
                wall_ns: mono_ns + 1_000,
            },
            topic: format!("/eth2/{DIGEST}/{name}/ssz_snappy"),
            msg_id: vec![0xde, 0xad],
            peer: "16Uiu2HAm".into(),
            payload,
        })
    }

    fn archive(out: &Path) -> Writer<Spec> {
        let config = CaptureConfig {
            network: "sepolia".into(),
            topics: vec!["beacon_block".into(), "data_column_sidecar_4".into()],
            capture_host: "probe".into(),
            clock_source: "chrony".into(),
            slots_per_segment: 32,
            max_bytes: 1 << 30,
        };
        Writer::create(out, config, fixtures::chain()).unwrap()
    }

    #[test]
    fn tap_records_are_decoded_and_archived() {
        let dir = tempfile::tempdir().unwrap();
        let capture = dir.path().join("capture");
        let mut c = Collector::create(
            &capture,
            info(),
            fixtures::chain(),
            Some(archive(&dir.path().join("archive"))),
        )
        .unwrap();
        let (block, root) = fixtures::block(GLOAS_SLOT, 1);
        let (column, _) = fixtures::column(GLOAS_SLOT, 1, 4);
        let (other_column, _) = fixtures::column(GLOAS_SLOT, 1, 5);
        let envelope = testing::envelope(GLOAS_SLOT, root);
        for (i, arrival) in [
            tap("beacon_block", block.clone(), 10),
            tap("execution_payload", envelope, 20),
            tap("data_column_sidecar_4", column, 30),
            // Not subscribed by the archive: recorded, not archived.
            tap("data_column_sidecar_5", other_column, 40),
            // The same block again: the archive refuses the duplicate, the record stays.
            tap("beacon_block", block, 50),
            // Garbage on an archived topic: recorded without slot or root, refused.
            tap("beacon_block", vec![0xff; 4], 60),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(c.handle(arrival).unwrap(), None, "arrival {i}");
        }
        // A topic that is not /eth2/…: recorded as given.
        let mut odd = tap("beacon_block", vec![], 70);
        if let Arrival::Tap(t) = &mut odd {
            t.topic = "weird".into();
        }
        c.handle(odd).unwrap();
        let summary = c.finish(3).unwrap();
        assert_eq!(
            (summary.records, summary.gossip_records, summary.sse_records),
            (7, 7, 0)
        );
        assert_eq!((summary.archived, summary.archive_refused), (2, 2));
        assert_eq!(summary.undecoded, 2);
        assert_eq!(summary.dropped, 3);
        assert_eq!(summary.archive_error, None);
        assert_eq!(summary.archive_segments.len(), 1);
        open_verified(Path::new(&summary.archive_segments[0])).unwrap();

        let (_, records) = read_capture(&capture).unwrap();
        let first = &records[0];
        assert_eq!(first.topic, "beacon_block");
        assert_eq!(
            (first.slot, first.block_root),
            (Some(GLOAS_SLOT), Some(root))
        );
        assert_eq!((first.recv_mono_ns, first.recv_wall_ns), (10, 1_010));
        assert_eq!(first.msg_id.as_deref(), Some("0xdead"));
        assert_eq!(first.peer.as_deref(), Some("16Uiu2HAm"));
        assert_eq!(first.subnet, None);
        // The envelope and its column match: 10 ns apart.
        assert_eq!(records[1].block_root, Some(root));
        assert_eq!(records[2].subnet, Some(4));
        let matched = crate::collector::envelope_relative(&records);
        assert_eq!(matched.columns.len(), 2);
        assert_eq!(matched.columns[0].offset_ns, 10);
        assert_eq!((records[5].slot, records[5].block_root), (None, None));
        assert_eq!(records[6].topic, "weird");
    }

    #[test]
    fn an_archive_that_stops_is_logged_once_and_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = archive(&dir.path().join("archive"));
        writer.stop("disk gone".into());
        let mut c = Collector::create(
            &dir.path().join("c"),
            info(),
            fixtures::chain(),
            Some(writer),
        )
        .unwrap();
        let (block, _) = fixtures::block(GLOAS_SLOT, 1);
        let first = c.handle(tap("beacon_block", block.clone(), 1)).unwrap();
        assert!(first.unwrap().contains("archive stopped"));
        assert_eq!(c.handle(tap("beacon_block", block, 2)).unwrap(), None);
        let summary = c.finish(0).unwrap();
        assert!(summary.archive_error.unwrap().contains("disk gone"));
        assert_eq!(summary.records, 2);
    }

    #[test]
    fn sse_gaps_and_ntp_samples() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("c");
        let mut c = Collector::<Spec>::create(&out, info(), fixtures::chain(), None).unwrap();
        let sse = |data: &str| {
            Arrival::Sse(StampedEvent {
                stamp: Stamp {
                    mono_ns: 5,
                    wall_ns: 6,
                },
                event: SseEvent {
                    event: "block_gossip".into(),
                    data: data.into(),
                },
            })
        };
        let root = format!("0x{}", "11".repeat(32));
        c.handle(sse(&format!(r#"{{"slot":"4","block":"{root}"}}"#)))
            .unwrap();
        c.handle(sse("garbage")).unwrap();
        let ok = NtpSample {
            mono_ns: 1,
            wall_ns: 2,
            daemon: "chrony".into(),
            clock_error_ns: Some(-1_500_000),
            error: None,
        };
        let failed = NtpSample {
            clock_error_ns: None,
            error: Some("chronyc: exit status: 1".into()),
            ..ok.clone()
        };
        let logged = c.handle(Arrival::Ntp(ok.clone())).unwrap().unwrap();
        assert_eq!(
            logged,
            "ntp: chrony clock error -1.500 ms (local minus NTP)"
        );
        let logged = c.handle(Arrival::Ntp(failed.clone())).unwrap().unwrap();
        assert!(logged.contains("sample failed: chronyc"), "{logged}");
        let gap = MissingInterval {
            source: Source::Sse,
            start_mono_ns: 0,
            start_wall_ns: 0,
            end_mono_ns: 2_000_000_000,
            end_wall_ns: 2_000_000_000,
            reason: "/eth/v1/events: connect: refused".into(),
            failed_attempts: 2,
            open_at_shutdown: true,
        };
        let logged = c.handle(Arrival::Gap(gap.clone())).unwrap().unwrap();
        assert_eq!(
            logged,
            "missing interval: Sse down for 2000 ms (/eth/v1/events: connect: refused; \
             2 failed reconnects; still down at shutdown)"
        );
        let summary = c.finish(0).unwrap();
        assert_eq!((summary.sse_records, summary.undecoded), (2, 1));
        assert_eq!((summary.ntp_samples, summary.ntp_failures), (2, 1));
        assert_eq!(summary.missing, vec![gap]);
        let ntp: Vec<NtpSample> = std::fs::read_to_string(out.join(NTP_FILE))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(ntp, vec![ok, failed]);
        let (_, records) = read_capture(&out).unwrap();
        assert_eq!(records[0].block_root, Some(Root::repeat_byte(0x11)));
        assert_eq!(records[0].slot, Some(4));
    }

    #[test]
    fn a_capture_never_overwrites_another() {
        let dir = tempfile::tempdir().unwrap();
        let c = Collector::<Spec>::create(dir.path(), info(), fixtures::chain(), None).unwrap();
        c.finish(0).unwrap();
        let err =
            Collector::<Spec>::create(dir.path(), info(), fixtures::chain(), None).unwrap_err();
        assert!(
            matches!(&err, CollectorError::Io { path, .. } if path.ends_with(CAPTURE_FILE)),
            "{err}"
        );
    }

    #[test]
    fn read_capture_refuses_malformed_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_capture(dir.path()),
            Err(CollectorError::Io { .. })
        ));
        std::fs::write(dir.path().join(CAPTURE_FILE), "network = 1\n").unwrap();
        let err = read_capture(dir.path()).unwrap_err();
        assert!(matches!(err, CollectorError::Format { .. }), "{err}");
        write_toml(&dir.path().join("x.toml"), &info()).unwrap();
        std::fs::rename(dir.path().join("x.toml"), dir.path().join(CAPTURE_FILE)).unwrap();
        assert!(matches!(
            read_capture(dir.path()),
            Err(CollectorError::Io { .. })
        ));
        std::fs::write(dir.path().join(RECORDS_FILE), "{}\n").unwrap();
        let err = read_capture(dir.path()).unwrap_err();
        assert!(err.to_string().contains("line 1"), "{err}");
    }

    #[tokio::test]
    async fn collect_runs_until_every_sender_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("c");
        let c = Collector::<Spec>::create(&out, info(), fixtures::chain(), None).unwrap();
        let (arrivals, rx) = Arrivals::channel(16);
        let (block, _) = fixtures::block(3, 0);
        for i in 0..3 {
            assert!(arrivals.offer(tap("beacon_block", block.clone(), i)));
        }
        arrivals
            .deliver(Arrival::Gap(MissingInterval {
                source: Source::Sse,
                start_mono_ns: 0,
                start_wall_ns: 0,
                end_mono_ns: 1,
                end_wall_ns: 1,
                reason: "x".into(),
                failed_attempts: 0,
                open_at_shutdown: false,
            }))
            .await
            .unwrap();
        let counter = arrivals.drops();
        drop(arrivals);
        let summary = tokio::task::spawn_blocking(move || {
            let mut lines = Vec::new();
            let summary = collect(c, rx, &counter, &mut |l| lines.push(l.to_owned())).unwrap();
            assert_eq!(lines.len(), 1);
            summary
        })
        .await
        .unwrap();
        assert_eq!((summary.records, summary.missing.len()), (3, 1));
        assert!(out.join(SUMMARY_FILE).exists());
    }
}
