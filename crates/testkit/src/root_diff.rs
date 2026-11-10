//! Epoch-aligned finalized/justified checkpoint comparisons. Gaps are never matches.

use crate::archive::canonical_hex;
use consensus_types::primitives::Root;
use serde::{Deserialize, Serialize};

/// A checkpoint compares both its epoch and its root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint epoch.
    pub epoch: u64,
    /// Beacon block root.
    pub root: Root,
}

/// The two checkpoints in this slice; head/payload status is a separate comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoints {
    /// Finalized checkpoint.
    pub finalized: Checkpoint,
    /// Current justified checkpoint (not previous justified).
    pub justified: Checkpoint,
}

/// Why a sample cannot establish agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gap {
    /// Our QueryService read failed.
    Ours,
    /// Reference read failed.
    Reference,
    /// Both reads failed.
    Both,
    /// The polling slot was missed; no late comparison was made.
    MissedSample,
}

/// One JSONL record. `match` is null for gaps, never true.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Epoch being sampled at boundary plus one slot.
    pub epoch: u64,
    /// Our checkpoints, if read successfully.
    pub ours: Option<Checkpoints>,
    /// Reference checkpoints, if read successfully.
    pub reference: Option<Checkpoints>,
    /// True/false only for a completed comparison.
    pub r#match: Option<bool>,
    /// Missing evidence, if any.
    pub gap: Option<Gap>,
}

impl Record {
    /// An observed divergence, as distinct from missing evidence.
    pub fn is_mismatch(&self) -> bool {
        self.r#match == Some(false)
    }
}

/// Compare one epoch's observations.
pub fn compare(epoch: u64, ours: Option<Checkpoints>, reference: Option<Checkpoints>) -> Record {
    let (matches, gap) = match (&ours, &reference) {
        (Some(a), Some(b)) => (Some(a == b), None),
        (Some(_), None) => (None, Some(Gap::Reference)),
        (None, Some(_)) => (None, Some(Gap::Ours)),
        (None, None) => (None, Some(Gap::Both)),
    };
    Record {
        epoch,
        ours,
        reference,
        r#match: matches,
        gap,
    }
}

/// A sanitized tooling error: response bodies and reference URLs are never included.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed/missing checkpoint data.
    #[error("invalid finality checkpoint response")]
    InvalidFinality,
    /// Reference transport, HTTP status or JSON failure.
    #[error("reference finality read failed")]
    Reference,
    /// QueryService transport, deadline or response-contract failure.
    #[error("QueryService checkpoint read failed")]
    Query,
    /// Invalid schedule or arithmetic overflow.
    #[error("invalid or overflowing epoch schedule")]
    Schedule,
    /// Record encoding failed.
    #[error("cannot encode root-diff record")]
    Record,
    /// Output failed; a partial run must not be reported as success.
    #[error("root-diff output: {0}")]
    Io(#[source] std::io::Error),
}

/// Decode Beacon API finality JSON with strict decimal epochs and 32-byte roots.
pub fn parse_finality(body: &[u8]) -> Result<Checkpoints, Error> {
    #[derive(Deserialize)]
    struct Response {
        data: Data,
    }
    #[derive(Deserialize)]
    struct Data {
        finalized: ApiCheckpoint,
        current_justified: ApiCheckpoint,
    }
    #[derive(Deserialize)]
    struct ApiCheckpoint {
        epoch: String,
        root: String,
    }
    fn checkpoint(api: ApiCheckpoint) -> Result<Checkpoint, Error> {
        if api.epoch.is_empty() || !api.epoch.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::InvalidFinality);
        }
        let epoch = api.epoch.parse().map_err(|_| Error::InvalidFinality)?;
        let root = api
            .root
            .strip_prefix("0x")
            .and_then(canonical_hex::<32>)
            .ok_or(Error::InvalidFinality)?;
        Ok(Checkpoint {
            epoch,
            root: Root::from(root),
        })
    }
    let response: Response = serde_json::from_slice(body).map_err(|_| Error::InvalidFinality)?;
    Ok(Checkpoints {
        finalized: checkpoint(response.data.finalized)?,
        justified: checkpoint(response.data.current_justified)?,
    })
}

/// Checkpoint source; both production transports and deterministic fixtures implement it.
pub trait CheckpointSource: Sync {
    /// Read the canonical state at a fixed sample slot, never an arbitrary moving head.
    fn read(
        &self,
        slot: u64,
    ) -> impl std::future::Future<Output = Result<Checkpoints, Error>> + Send;
}

/// Bounded Beacon API finality reads; the URL type restricts endpoints to loopback/tunnels.
#[derive(Clone, Debug)]
pub struct Reference {
    url: crate::collector::ReferenceApiUrl,
    timeout: std::time::Duration,
}

impl Reference {
    /// A reference with a deadline covering connect, headers and the bounded body.
    pub fn new(url: crate::collector::ReferenceApiUrl, timeout: std::time::Duration) -> Self {
        Self { url, timeout }
    }

    pub(crate) async fn read_state(&self, state: &str) -> Result<Checkpoints, Error> {
        let path = format!("/eth/v1/beacon/states/{state}/finality_checkpoints");
        let body: serde_json::Value = crate::collector::get_json_at(
            &self.url,
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            &path,
            crate::collector::MAX_JSON_BYTES,
            self.timeout,
        )
        .await
        .map_err(|_| Error::Reference)?;
        parse_finality(&serde_json::to_vec(&body).map_err(|_| Error::InvalidFinality)?)
    }
}

impl CheckpointSource for Reference {
    async fn read(&self, slot: u64) -> Result<Checkpoints, Error> {
        self.read_state(&slot.to_string()).await
    }
}

/// Read both sources concurrently; any failure is missing evidence, never agreement.
pub async fn sample(
    epoch: u64,
    slot: u64,
    ours: &impl CheckpointSource,
    reference: &impl CheckpointSource,
) -> Record {
    let (ours, reference) = tokio::join!(ours.read(slot), reference.read(slot));
    compare(epoch, ours.ok(), reference.ok())
}

/// chain.v1 QueryService over UDS, with the expected server UID checked before sending bytes.
#[derive(Clone, Debug)]
pub struct QuerySource {
    socket: std::path::PathBuf,
    uid: u32,
    timeout: std::time::Duration,
}

impl QuerySource {
    /// Reconnect on every sample; a stale server/channel cannot supply a cached success.
    pub fn new(socket: std::path::PathBuf, uid: u32, timeout: std::time::Duration) -> Self {
        Self {
            socket,
            uid,
            timeout,
        }
    }
}

impl CheckpointSource for QuerySource {
    async fn read(&self, slot: u64) -> Result<Checkpoints, Error> {
        use ethswarm_proto::chain::{self as pb, query_service_client::QueryServiceClient};
        fn checkpoint(
            value: Option<ethswarm_proto::common::Checkpoint>,
        ) -> Result<Checkpoint, Error> {
            let value = value.ok_or(Error::Query)?;
            let root: [u8; 32] = value.root.try_into().map_err(|_| Error::Query)?;
            Ok(Checkpoint {
                epoch: value.epoch,
                root: Root::from(root),
            })
        }
        let read = async {
            let channel = ipc::uds::connect_path(&self.socket, self.uid)
                .await
                .map_err(|_| Error::Query)?;
            let mut client = QueryServiceClient::new(channel).max_decoding_message_size(64 << 10);
            let mut request = tonic::Request::new(pb::GetStateSummaryRequest {
                state: Some(pb::HotStateId {
                    id: Some(pb::hot_state_id::Id::Slot(slot)),
                }),
            });
            request.set_timeout(self.timeout);
            let response = client
                .get_state_summary(request)
                .await
                .map_err(|_| Error::Query)?
                .into_inner();
            if response.slot != slot
                || response.state_root.len() != 32
                || response.block_root.len() != 32
            {
                return Err(Error::Query);
            }
            Ok(Checkpoints {
                finalized: checkpoint(response.finalized)?,
                justified: checkpoint(response.justified)?,
            })
        };
        tokio::time::timeout(self.timeout, read)
            .await
            .map_err(|_| Error::Query)?
    }
}

/// Validated epoch sampling schedule, at the start of slot `epoch * slots_per_epoch + 1`.
#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    genesis: u64,
    seconds_per_slot: u64,
    slots_per_epoch: u64,
}

impl Schedule {
    /// Reject zero slot duration, epochs without a +1 slot, and overflowing epoch periods.
    pub fn new(genesis: u64, seconds_per_slot: u64, slots_per_epoch: u64) -> Result<Self, Error> {
        if seconds_per_slot == 0
            || slots_per_epoch < 2
            || seconds_per_slot.checked_mul(slots_per_epoch).is_none()
        {
            return Err(Error::Schedule);
        }
        let result = Self {
            genesis,
            seconds_per_slot,
            slots_per_epoch,
        };
        result.due(0)?;
        Ok(result)
    }

    /// The completed epoch-boundary state both sources read at the +1-slot poll.
    pub fn sample_slot(&self, epoch: u64) -> Result<u64, Error> {
        epoch
            .checked_mul(self.slots_per_epoch)
            .ok_or(Error::Schedule)
    }

    /// Sampling time since Unix epoch.
    pub fn due(&self, epoch: u64) -> Result<std::time::Duration, Error> {
        self.sample_slot(epoch)?
            .checked_add(1)
            .and_then(|slot| slot.checked_mul(self.seconds_per_slot))
            .and_then(|seconds| self.genesis.checked_add(seconds))
            .filter(|seconds| *seconds <= u64::MAX / 1_000_000_000)
            .map(std::time::Duration::from_secs)
            .ok_or(Error::Schedule)
    }

    /// First scheduled epoch at or after `now`; subsecond precision prevents early polling.
    pub fn next_epoch(&self, now: std::time::Duration) -> Result<u64, Error> {
        let Some(delta) = now.checked_sub(self.due(0)?) else {
            return Ok(0);
        };
        let epoch = delta.as_secs() / (self.seconds_per_slot * self.slots_per_epoch);
        if self.due(epoch)? < now {
            epoch.checked_add(1).ok_or(Error::Schedule)
        } else {
            Ok(epoch)
        }
    }
}

/// A finite run. The CLI chooses the next future epoch unless explicitly overridden.
#[derive(Clone, Copy, Debug)]
pub struct RunConfig {
    /// Network timing, provided explicitly rather than assuming mainnet defaults.
    pub schedule: Schedule,
    /// First epoch to record.
    pub first_epoch: u64,
    /// Number of consecutive epochs (must be nonzero).
    pub epochs: u64,
}

/// Sticky run totals: later matches or gaps never clear a divergence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RunReport {
    /// Number of JSONL records written.
    pub samples: u64,
    /// Completed comparisons that differed.
    pub mismatches: u64,
    /// Samples lacking evidence.
    pub gaps: u64,
}

impl RunReport {
    /// 0 complete agreement; 1 any mismatch; 2 incomplete evidence without a mismatch.
    pub fn exit_code(&self) -> u8 {
        if self.mismatches > 0 {
            1
        } else if self.gaps > 0 {
            2
        } else {
            0
        }
    }
}

/// Poll fixed epoch boundaries + one slot and flush one JSONL record per epoch.
///
/// Clock and pause are injected so tests never sleep. Late polling slots become explicit gaps;
/// slow requests cannot cause interval drift or turn a missed epoch into a moving-head match.
/// Cancelling this future stops further reads/writes. Completed records are flushed individually.
pub async fn run(
    config: RunConfig,
    ours: &impl CheckpointSource,
    reference: &impl CheckpointSource,
    clock: &impl crate::collector::Clock,
    pause: &impl crate::collector::Pause,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<RunReport, Error> {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let end = config
        .first_epoch
        .checked_add(config.epochs)
        .ok_or(Error::Schedule)?;
    if config.epochs == 0 {
        return Err(Error::Schedule);
    }
    config.schedule.due(end - 1)?;
    let mut report = RunReport::default();
    for epoch in config.first_epoch..end {
        let due = config.schedule.due(epoch)?;
        loop {
            let now = Duration::from_nanos(clock.now().wall_ns);
            let Some(wait) = due.checked_sub(now).filter(|wait| !wait.is_zero()) else {
                break;
            };
            pause.pause(wait).await;
        }
        let now = Duration::from_nanos(clock.now().wall_ns);
        let record =
            if now.saturating_sub(due) >= Duration::from_secs(config.schedule.seconds_per_slot) {
                Record {
                    epoch,
                    ours: None,
                    reference: None,
                    r#match: None,
                    gap: Some(Gap::MissedSample),
                }
            } else {
                sample(epoch, config.schedule.sample_slot(epoch)?, ours, reference).await
            };
        let mut line = serde_json::to_vec(&record).map_err(|_| Error::Record)?;
        line.push(b'\n');
        output.write_all(&line).await.map_err(Error::Io)?;
        output.flush().await.map_err(Error::Io)?;
        report.samples += 1;
        report.mismatches += u64::from(record.is_mismatch());
        report.gaps += u64::from(record.gap.is_some());
    }
    Ok(report)
}
