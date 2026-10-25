//! [`Collector`]: turns stamped arrivals into a capture directory, off the hot path.
//!
//! ```text
//! <dir>/capture.toml    what the capture is (network, genesis, slot duration, sources, host)
//! <dir>/records.jsonl   one ArrivalRecord per line, in arrival order
//! <dir>/gaps.jsonl      one MissingInterval per line, as each one closes
//! <dir>/ntp.jsonl       one NtpSample per line
//! <dir>/summary.toml    written at the end: counts, for the manifest (gaps.jsonl lists the gaps)
//! ```
//!
//! The manifest covers the configured topic set: `capture.toml` lists the subscribed topics of
//! each source, the ones the reference node refused, and the attestation subnets sampled;
//! `summary.toml` gives every one of them its count `n` and bytes, zeros included (a refused
//! topic too), and lists as gaps (`missing_topics`) the topics and subnets with nothing
//! recorded, the refused ones among them; `unsupported_topics` names the refused ones again. An
//! unaggregated attestation outside the sampled subnets (or of no known subnet) is counted,
//! never recorded.
//!
//! Gossip payloads are decoded here (slot, block root) and handed to the archive
//! ([`crate::archive::Writer`]) as received; SSE events are decoded from their JSON. A message
//! that does not decode is still recorded, with no slot or root, and counted as undecoded
//! (unless the subnet sample drops it). Every file is
//! created new: a capture never overwrites another.

use super::arrival::{Arrival, ArrivalReceiver, Drops, MissingInterval};
use super::decode::{decode_gossip, decode_sse, parse_gossip_topic, topic_subnet, SseSubnets};
use super::ntp::NtpSample;
use super::record::{ArrivalRecord, Source};
use crate::archive::{ArchiveError, Capture, ChainParams, PayloadError, TopicKind, Writer};
use consensus_types::EthSpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

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

/// What a capture is: `capture.toml`, everything the offsets need besides the records, and the
/// configured topic set. The fields after `started_wall_ns` are absent from earlier captures,
/// and read as empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The configured SSE events the reference node refused at start (it does not emit them
    /// at its version): never subscribed, listed as gaps.
    #[serde(default)]
    pub sse_topics_unsupported: Vec<String>,
    /// The gossip topic names our probe subscribes (`beacon_block`, `beacon_attestation_3`).
    #[serde(default)]
    pub gossip_topics: Vec<String>,
    /// The attestation subnets sampled, ascending: an unaggregated attestation on another
    /// subnet, or of no known subnet, is counted and not recorded.
    #[serde(default)]
    pub attestation_subnets: Vec<u64>,
    /// The attestation subnets the reference node subscribed at start (its metadata
    /// `attnets`), when it was read.
    #[serde(default)]
    pub node_attnets: Option<Vec<u64>>,
    /// The committees per slot at the start, for the subnet of an SSE `single_attestation`.
    #[serde(default)]
    pub committees_per_slot: Option<u64>,
    /// `SLOTS_PER_EPOCH`, for the same.
    #[serde(default)]
    pub slots_per_epoch: Option<u64>,
}

/// One topic of the manifest: what a source recorded on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopicCount {
    /// The source.
    pub source: Source,
    /// The topic: a gossip topic name, or an SSE event name.
    pub topic: String,
    /// Records written.
    pub n: u64,
    /// Their [`ArrivalRecord::bytes`].
    pub bytes: u64,
}

/// One sampled attestation subnet of the manifest: the unaggregated attestations a source
/// recorded on it (gossip `beacon_attestation_<subnet>`, SSE `single_attestation`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetCount {
    /// The source.
    pub source: Source,
    /// The subnet.
    pub subnet: u64,
    /// Records written.
    pub n: u64,
    /// Their [`ArrivalRecord::bytes`].
    pub bytes: u64,
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
    /// Records written whose payload or JSON did not decode (no slot or root); an arrival the
    /// subnet sample drops is not counted here.
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
    /// Intervals a source was down. Each is a line of [`Summary::gaps_file`]; the summary only
    /// counts them, so it stays the same size however long the capture runs.
    pub missing_intervals: u64,
    /// Their total length, monotonic nanoseconds.
    pub missing_ns: u64,
    /// Of which still open when the capture stopped.
    pub missing_open_at_shutdown: u64,
    /// The file that lists every missing interval, relative to the capture directory:
    /// [`GAPS_FILE`].
    pub gaps_file: String,
    /// Unaggregated attestations outside the sampled subnets (or of no known subnet): counted,
    /// not recorded.
    #[serde(default)]
    pub outside_sampled_subnets: u64,
    /// The configured topics and sampled subnets with nothing recorded (`sse:<event>`,
    /// `gossip:<topic>`, `<source>:attestation_subnet_<n>`): gaps. The refused topics are
    /// among them, so this lists every configured topic with no data.
    #[serde(default)]
    pub missing_topics: Vec<String>,
    /// The configured topics the reference node refused at start (`sse:<event>`): gaps, also
    /// in [`Summary::missing_topics`] with their `n = 0` row.
    #[serde(default)]
    pub unsupported_topics: Vec<String>,
    /// Every configured topic of every source with its count, zeros included, and any other
    /// topic recorded; by source and topic.
    #[serde(default)]
    pub topics: Vec<TopicCount>,
    /// Every sampled subnet of every source with its count, zeros included.
    #[serde(default)]
    pub attestation_subnets: Vec<SubnetCount>,
}

impl Summary {
    /// The gaps, for the log: every topic and subnet of [`Summary::missing_topics`] and
    /// [`Summary::unsupported_topics`], each once, a refused topic marked `(refused)`. A summary
    /// written before refused topics had rows of their own lists them in `unsupported_topics`
    /// only; they come first.
    pub fn topic_gaps(&self) -> Vec<String> {
        let refused = |t: &String| self.unsupported_topics.contains(t);
        let mark = |t: &String| {
            if refused(t) {
                format!("{t} (refused)")
            } else {
                t.clone()
            }
        };
        (self.unsupported_topics.iter())
            .filter(|t| !self.missing_topics.contains(t))
            .chain(&self.missing_topics)
            .map(mark)
            .collect()
    }
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
    subnets: SseSubnets,
    archive: Option<Writer<E>>,
    summary: Summary,
    manifest: Manifest,
}

/// The manifest's counts while the capture runs: `(n, bytes)` per topic and per sampled
/// subnet, the configured ones from the start. An SSE event the node refused is configured
/// too: it gets its `n = 0` row, so it is in `missing_topics` as well as `unsupported_topics`.
#[derive(Debug, Default)]
struct Manifest {
    sampled: Vec<u64>,
    topics: BTreeMap<(Source, String), (u64, u64)>,
    subnets: BTreeMap<(Source, u64), (u64, u64)>,
}

impl Manifest {
    fn new(info: &CaptureInfo) -> Self {
        let mut m = Manifest {
            sampled: info.attestation_subnets.clone(),
            ..Manifest::default()
        };
        m.sampled.sort_unstable();
        m.sampled.dedup();
        for source in &info.sources {
            let configured = match source {
                Source::Sse => [&info.sse_topics[..], &info.sse_topics_unsupported[..]].concat(),
                Source::Gossip => info.gossip_topics.clone(),
            };
            for topic in configured {
                m.topics.insert((*source, topic), (0, 0));
            }
            for subnet in &m.sampled {
                m.subnets.insert((*source, *subnet), (0, 0));
            }
        }
        m
    }

    /// Whether `record` is kept: anything but an unaggregated attestation outside the sampled
    /// subnets. A kept attestation is counted on its subnet.
    fn sampled(&mut self, record: &ArrivalRecord) -> bool {
        let attestation = match record.source {
            Source::Sse => record.topic == super::topics::SINGLE_ATTESTATION,
            Source::Gossip => record.topic.starts_with("beacon_attestation_"),
        };
        if !attestation {
            return true;
        }
        let Some(subnet) = record
            .subnet
            .filter(|s| self.sampled.binary_search(s).is_ok())
        else {
            return false;
        };
        add(
            self.subnets.entry((record.source, subnet)).or_default(),
            record,
        );
        true
    }

    fn count(&mut self, record: &ArrivalRecord) {
        let key = (record.source, record.topic.clone());
        add(self.topics.entry(key).or_default(), record);
    }

    /// The summary's rows and gaps.
    fn fill(&self, summary: &mut Summary) {
        let prefix = |source: Source| match source {
            Source::Sse => "sse",
            Source::Gossip => "gossip",
        };
        summary.topics = (self.topics.iter())
            .map(|((source, topic), (n, bytes))| TopicCount {
                source: *source,
                topic: topic.clone(),
                n: *n,
                bytes: *bytes,
            })
            .collect();
        summary.attestation_subnets = (self.subnets.iter())
            .map(|((source, subnet), (n, bytes))| SubnetCount {
                source: *source,
                subnet: *subnet,
                n: *n,
                bytes: *bytes,
            })
            .collect();
        let empty_topics = (summary.topics.iter())
            .filter(|t| t.n == 0)
            .map(|t| format!("{}:{}", prefix(t.source), t.topic));
        let empty_subnets = (summary.attestation_subnets.iter())
            .filter(|s| s.n == 0)
            .map(|s| format!("{}:attestation_subnet_{}", prefix(s.source), s.subnet));
        summary.missing_topics = empty_topics.chain(empty_subnets).collect();
    }
}

fn add(count: &mut (u64, u64), record: &ArrivalRecord) {
    count.0 += 1;
    count.1 = count.1.saturating_add(record.bytes);
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
        let info = &info;
        Ok(Self {
            dir: dir.to_owned(),
            records: Lines::create(dir, RECORDS_FILE)?,
            gaps: Lines::create(dir, GAPS_FILE)?,
            ntp: Lines::create(dir, NTP_FILE)?,
            chain,
            subnets: SseSubnets {
                column_subnet_count: info.column_subnet_count,
                committees_per_slot: info.committees_per_slot,
                slots_per_epoch: info.slots_per_epoch,
            },
            archive,
            summary: Summary {
                gaps_file: GAPS_FILE.to_owned(),
                unsupported_topics: (info.sse_topics_unsupported.iter())
                    .map(|t| format!("sse:{t}"))
                    .collect(),
                ..Summary::default()
            },
            manifest: Manifest::new(info),
        })
    }

    /// Records one arrival. Returns a line worth logging (a gap, an NTP sample, the archive
    /// stopping), if any.
    pub fn handle(&mut self, arrival: Arrival) -> Result<Option<String>, CollectorError> {
        match arrival {
            Arrival::Tap(tap) => {
                let (record, undecoded, notice) = self.gossip(tap);
                self.record(&record, undecoded)?;
                Ok(notice)
            }
            Arrival::Sse(stamped) => {
                let (slot, block_root, subnet) = decode_sse(&stamped.event, &self.subnets);
                let undecoded = slot.is_none() && block_root.is_none();
                let record = ArrivalRecord {
                    source: Source::Sse,
                    topic: stamped.event.event,
                    subnet,
                    msg_id: None,
                    block_root,
                    slot,
                    recv_mono_ns: stamped.stamp.mono_ns,
                    recv_wall_ns: stamped.stamp.wall_ns,
                    peer: None,
                    bytes: stamped.event.data.len() as u64,
                };
                self.record(&record, undecoded)?;
                Ok(None)
            }
            Arrival::Gap(gap) => {
                self.gaps.push(&gap)?;
                self.gaps.flush()?;
                let summary = &mut self.summary;
                summary.missing_intervals += 1;
                summary.missing_ns = summary.missing_ns.saturating_add(gap.duration_ns());
                summary.missing_open_at_shutdown += u64::from(gap.open_at_shutdown);
                Ok(Some(gap_notice(&gap)))
            }
            Arrival::Ntp(sample) => {
                self.ntp.push(&sample)?;
                self.summary.ntp_samples += 1;
                self.summary.ntp_failures += u64::from(sample.clock_error_ns.is_none());
                Ok(Some(ntp_notice(&sample)))
            }
        }
    }

    /// Writes `record` unless the subnet sample drops it; `undecoded` (its payload or JSON did
    /// not decode) is counted only for a record written.
    fn record(&mut self, record: &ArrivalRecord, undecoded: bool) -> Result<(), CollectorError> {
        if !self.manifest.sampled(record) {
            self.summary.outside_sampled_subnets += 1;
            return Ok(());
        }
        self.records.push(record)?;
        self.manifest.count(record);
        self.summary.records += 1;
        self.summary.undecoded += u64::from(undecoded);
        match record.source {
            Source::Gossip => self.summary.gossip_records += 1,
            Source::Sse => self.summary.sse_records += 1,
        }
        Ok(())
    }

    /// Decodes a tap record and archives its payload: the record, whether it did not decode,
    /// and a notice.
    fn gossip(&mut self, tap: super::tap::TapRecord) -> (ArrivalRecord, bool, Option<String>) {
        let parsed = parse_gossip_topic(&tap.topic);
        let name = parsed.map_or(tap.topic.as_str(), |t| t.name);
        let decoded = match parsed {
            Some(_) => decode_gossip::<E>(name, &tap.payload, &self.chain),
            None => Ok(None),
        };
        let undecoded = parsed.is_none() || decoded.is_err();
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
            bytes: tap.payload.len() as u64,
        };
        (record, undecoded, notice)
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
        self.manifest.fill(&mut self.summary);
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
    mut rx: ArrivalReceiver,
    drops: &Drops,
    log: &mut dyn FnMut(&str),
) -> Result<Summary, CollectorError> {
    while let Some(arrival) = rx.blocking_recv() {
        let mut next = Some(arrival);
        while let Some(arrival) = next {
            if let Some(line) = collector.handle(arrival)? {
                log(&line);
            }
            next = rx.try_recv();
        }
        collector.flush()?;
    }
    collector.finish(drops.get())
}

/// The longest line `records.jsonl` may hold: 64 KiB. A record is a few hundred bytes (its
/// longest field is the topic: an event name is at most `MAX_EVENT_NAME_BYTES`); a longer line
/// is not one, and is refused without being read whole.
pub const MAX_RECORD_LINE_BYTES: usize = 64 << 10;

/// Reads a capture directory's `capture.toml`.
pub fn read_info(dir: &Path) -> Result<CaptureInfo, CollectorError> {
    let path = dir.join(CAPTURE_FILE);
    let text = std::fs::read_to_string(&path).map_err(io_error(&path))?;
    toml::from_str(&text).map_err(|e| CollectorError::Format {
        path,
        reason: e.to_string(),
    })
}

/// Reads a capture directory's `summary.toml`: `None` while there is none yet (the capture is
/// still being written, or stopped before it finished).
pub fn read_summary(dir: &Path) -> Result<Option<Summary>, CollectorError> {
    let path = dir.join(SUMMARY_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error(&path)(e)),
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| CollectorError::Format {
            path,
            reason: e.to_string(),
        })
}

/// The records of a capture directory's `records.jsonl`, read one line at a time: memory does
/// not grow with the capture. Ends after the first error.
pub fn records(dir: &Path) -> Result<Records, CollectorError> {
    let path = dir.join(RECORDS_FILE);
    let file = File::open(&path).map_err(io_error(&path))?;
    Ok(Records {
        lines: BufReader::new(file),
        path,
        line: 0,
        buf: Vec::new(),
        failed: false,
    })
}

/// The iterator [`records`] returns.
#[derive(Debug)]
pub struct Records {
    lines: BufReader<File>,
    path: PathBuf,
    line: u64,
    buf: Vec<u8>,
    failed: bool,
}

impl Records {
    fn format(&self, reason: String) -> CollectorError {
        CollectorError::Format {
            path: self.path.clone(),
            reason: format!("line {}: {reason}", self.line),
        }
    }

    fn read_next(&mut self) -> Result<Option<ArrivalRecord>, CollectorError> {
        self.buf.clear();
        // One byte past the cap, to tell a line at the cap from one over it.
        let cap = MAX_RECORD_LINE_BYTES as u64 + 1;
        let read = (&mut self.lines)
            .take(cap)
            .read_until(b'\n', &mut self.buf)
            .map_err(io_error(&self.path))?;
        if read == 0 {
            return Ok(None);
        }
        self.line += 1;
        if self.buf.last() == Some(&b'\n') {
            self.buf.pop();
        } else if read as u64 == cap {
            return Err(self.format(format!("over {MAX_RECORD_LINE_BYTES} bytes")));
        }
        serde_json::from_slice(&self.buf)
            .map(Some)
            .map_err(|e| self.format(e.to_string()))
    }
}

impl Iterator for Records {
    type Item = Result<ArrivalRecord, CollectorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let next = self.read_next().transpose();
        self.failed = matches!(next, Some(Err(_)));
        next
    }
}

/// Reads a capture directory's `capture.toml` and every record of `records.jsonl` into memory.
/// For a long capture, read [`records`] one at a time instead.
pub fn read_capture(dir: &Path) -> Result<(CaptureInfo, Vec<ArrivalRecord>), CollectorError> {
    let info = read_info(dir)?;
    let records = records(dir)?.collect::<Result<_, _>>()?;
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
    use crate::collector::topics::SINGLE_ATTESTATION;
    use consensus_types::primitives::Root;

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
            ..CaptureInfo::default()
        }
    }

    fn tap(name: &str, payload: Vec<u8>, mono_ns: u64) -> Arrival {
        Arrival::Tap(TapRecord {
            stamp: Stamp {
                mono_ns,
                wall_ns: mono_ns + 1_000,
            },
            // Every payload here is at a Gloas slot, so on the Gloas digest.
            topic: format!(
                "/eth2/{}/{name}/ssz_snappy",
                hex::encode(fixtures::GLOAS_DIGEST)
            ),
            msg_id: vec![0xde, 0xad],
            peer: "16Uiu2HAm".into(),
            payload,
        })
    }

    fn archive(out: &Path) -> Writer<Spec> {
        // Not "sepolia": the fixtures are of the minimal preset.
        let config = CaptureConfig {
            network: "devnet".into(),
            topics: vec!["beacon_block".into(), "data_column_sidecar_4".into()],
            capture_host: "probe".into(),
            clock_source: "chrony".into(),
            slots_per_segment: 32,
            max_bytes: 1 << 30,
            fork_digests: fixtures::fork_digests(),
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
        let closed = MissingInterval {
            start_mono_ns: 3_000_000_000,
            end_mono_ns: 3_500_000_000,
            open_at_shutdown: false,
            ..gap.clone()
        };
        c.handle(Arrival::Gap(closed.clone())).unwrap();
        let summary = c.finish(0).unwrap();
        assert_eq!((summary.sse_records, summary.undecoded), (2, 1));
        assert_eq!((summary.ntp_samples, summary.ntp_failures), (2, 1));
        // The summary counts the intervals; gaps.jsonl lists them.
        assert_eq!(
            (
                summary.missing_intervals,
                summary.missing_ns,
                summary.missing_open_at_shutdown
            ),
            (2, 2_500_000_000, 1)
        );
        assert_eq!(summary.gaps_file, GAPS_FILE);
        let listed: Vec<MissingInterval> = std::fs::read_to_string(out.join(GAPS_FILE))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(listed, vec![gap, closed]);
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
    fn only_kept_records_count_as_undecoded() {
        let dir = tempfile::tempdir().unwrap();
        let info = CaptureInfo {
            sources: vec![Source::Sse],
            sse_topics: vec![SINGLE_ATTESTATION.into(), "block_gossip".into()],
            attestation_subnets: vec![3],
            committees_per_slot: Some(64),
            slots_per_epoch: Some(32),
            ..info()
        };
        let mut c = Collector::<Spec>::create(dir.path(), info, fixtures::chain(), None).unwrap();
        let sse = |event: &str, data: &str| {
            Arrival::Sse(StampedEvent {
                stamp: Stamp {
                    mono_ns: 1,
                    wall_ns: 2,
                },
                event: SseEvent {
                    event: event.into(),
                    data: data.into(),
                },
            })
        };
        // A malformed attestation has no subnet, so it is not sampled: dropped, not undecoded.
        c.handle(sse(SINGLE_ATTESTATION, "garbage")).unwrap();
        // A malformed block is kept: undecoded.
        c.handle(sse("block_gossip", "garbage")).unwrap();
        let summary = c.finish(0).unwrap();
        assert_eq!(
            (
                summary.records,
                summary.undecoded,
                summary.outside_sampled_subnets
            ),
            (1, 1, 1)
        );
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

    #[test]
    fn a_summary_is_read_when_written() {
        let dir = tempfile::tempdir().unwrap();
        // A capture still being written has none yet.
        assert_eq!(read_summary(dir.path()).unwrap(), None);
        let c = Collector::<Spec>::create(dir.path(), info(), fixtures::chain(), None).unwrap();
        let summary = c.finish(4).unwrap();
        assert_eq!(read_summary(dir.path()).unwrap(), Some(summary));
        std::fs::write(dir.path().join(SUMMARY_FILE), "records = \"x\"\n").unwrap();
        let err = read_summary(dir.path()).unwrap_err();
        assert!(matches!(err, CollectorError::Format { .. }), "{err}");
        // Anything else that keeps it from being read is an error too.
        let not_a_dir = dir.path().join(SUMMARY_FILE);
        let err = read_summary(&not_a_dir).unwrap_err();
        assert!(matches!(err, CollectorError::Io { .. }), "{err}");
    }

    #[test]
    fn records_are_read_one_line_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        write_toml(&dir.path().join(CAPTURE_FILE), &info()).unwrap();
        assert_eq!(read_info(dir.path()).unwrap(), info());
        let line = r#"{"source":"sse","topic":"block_gossip","subnet":null,"msg_id":null,"block_root":null,"slot":1,"recv_mono_ns":0,"recv_wall_ns":0,"peer":null}"#;
        let long = format!("{{\"topic\":\"{}\"}}", "x".repeat(MAX_RECORD_LINE_BYTES));
        std::fs::write(
            dir.path().join(RECORDS_FILE),
            format!("{line}\n{line}\n{long}\n{line}\n"),
        )
        .unwrap();
        // The records before a bad line come first: nothing reads the file whole.
        let mut it = records(dir.path()).unwrap();
        assert_eq!(it.next().unwrap().unwrap().slot, Some(1));
        assert_eq!(it.next().unwrap().unwrap().slot, Some(1));
        let err = it.next().unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "{}: line 3: over {MAX_RECORD_LINE_BYTES} bytes",
                dir.path().join(RECORDS_FILE).display()
            )
        );
        assert!(it.next().is_none(), "nothing after an error");
        // A last line without its newline (a capture still being written) is a record too.
        std::fs::write(dir.path().join(RECORDS_FILE), format!("{line}\n{line}")).unwrap();
        assert_eq!(records(dir.path()).unwrap().count(), 2);
    }

    #[tokio::test]
    async fn collect_runs_until_every_sender_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("c");
        let c = Collector::<Spec>::create(&out, info(), fixtures::chain(), None).unwrap();
        let (arrivals, rx) = Arrivals::channel(16, usize::MAX);
        let (block, _) = fixtures::block(3, 0);
        for i in 0..3 {
            assert_eq!(
                arrivals.offer(tap("beacon_block", block.clone(), i)),
                Ok(true)
            );
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
        assert_eq!((summary.records, summary.missing_intervals), (3, 1));
        assert!(out.join(SUMMARY_FILE).exists());
    }
}
