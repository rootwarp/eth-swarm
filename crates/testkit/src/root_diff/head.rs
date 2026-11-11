//! Slot-correlated head and payload-status comparison; missing evidence never matches.
use consensus_types::primitives::Root;
use serde::{Deserialize, Serialize};

/// Gloas fork-choice head status, not an Engine API validation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadStatus {
    /// The head has no selected execution payload.
    Empty,
    /// The head's execution payload is selected.
    Full,
}

/// A current atomic head/status read guaranteed by its adapter (not a cached SSE event).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadSnapshot {
    /// Head block slot (may precede the polling slot after an empty slot).
    pub slot: u64,
    /// Head beacon block root.
    pub root: Root,
    /// This head's FULL/EMPTY selection.
    pub status: PayloadStatus,
}

/// An observed SSE transition. FULL-to-EMPTY events are optional, so this is not
/// evidence of the current selection and cannot be supplied to `compare_head`.
///
/// ```compile_fail
/// use testkit::root_diff::{compare_head, HeadEvents};
/// fn stale(sample: &testkit::head_lag::Sample, events: &HeadEvents) {
///     compare_head(sample, None, events.snapshot());
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadEvent {
    /// Slot carried by the event.
    pub slot: u64,
    /// Beacon block root carried by the event.
    pub root: Root,
    /// Selection at the observed transition, not necessarily the current selection.
    pub status: PayloadStatus,
}

/// An uncomparable head sample, rather than a mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeadGap {
    /// Lag exceeds the comparison gate.
    Lag,
    /// The shared sample is invalid or incomplete.
    Sample,
    /// Our atomic status snapshot is absent or does not match the sampled head.
    Ours,
    /// No current atomic reference status read matches the sampled head.
    Reference,
}

/// Shared head-diff JSONL record. `match` is null unless `compared` is true.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadRecord {
    /// Polling slot, not either head's slot.
    pub slot: u64,
    /// Signed reference-minus-ours lag from the shared head-lag sample.
    pub lag: Option<i64>,
    /// Our sampled beacon head root.
    pub head_ours: Option<Root>,
    /// Reference sampled beacon head root.
    pub head_ref: Option<Root>,
    /// Our matching snapshot's status, if available.
    pub status_ours: Option<PayloadStatus>,
    /// The reference current read's status, if available.
    pub status_ref: Option<PayloadStatus>,
    /// Whether the lag gate and all evidence checks succeeded.
    pub compared: bool,
    /// True/false only for a completed comparison.
    pub r#match: Option<bool>,
    /// Why no comparison was made.
    pub gap: Option<HeadGap>,
}

impl HeadRecord {
    /// An actual head or status divergence, not a gap.
    pub fn is_mismatch(&self) -> bool {
        self.r#match == Some(false)
    }
}

/// Compare the shared sample's head roots and atomic status observations.
pub fn compare_head(
    sample: &crate::head_lag::Sample,
    ours: Option<HeadSnapshot>,
    reference: Option<HeadSnapshot>,
) -> HeadRecord {
    let sample_ok = sample.gap.is_none()
        && sample
            .ours
            .as_ref()
            .zip(sample.reference.as_ref())
            .is_some_and(|(a, b)| {
                sample
                    .lag
                    .is_some_and(|lag| i128::from(lag) == i128::from(b.slot) - i128::from(a.slot))
            });
    let coherent = |snapshot: &Option<HeadSnapshot>, head: &Option<crate::head_lag::Head>| {
        snapshot
            .as_ref()
            .zip(head.as_ref())
            .is_some_and(|(a, b)| a.slot == b.slot && a.root == b.root)
    };
    let gap = if !sample_ok {
        Some(HeadGap::Sample)
    } else if sample.lag.is_some_and(|lag| lag > 2) {
        Some(HeadGap::Lag)
    } else if !coherent(&ours, &sample.ours) {
        Some(HeadGap::Ours)
    } else if !coherent(&reference, &sample.reference) {
        Some(HeadGap::Reference)
    } else {
        None
    };
    let compared = gap.is_none();
    let matches = if compared {
        Some(
            ours.as_ref().map(|h| (h.root, h.status))
                == reference.as_ref().map(|h| (h.root, h.status)),
        )
    } else {
        None
    };
    HeadRecord {
        slot: sample.slot,
        lag: sample.lag,
        head_ours: sample.ours.as_ref().map(|h| h.root),
        head_ref: sample.reference.as_ref().map(|h| h.root),
        status_ours: ours.as_ref().map(|h| h.status),
        status_ref: reference.as_ref().map(|h| h.status),
        compared,
        r#match: matches,
        gap,
    }
}

/// Invalid event, stream configuration, or shared head evidence (content is redacted).
#[derive(Debug, thiserror::Error)]
#[error("invalid head comparison evidence or stream configuration")]
pub struct HeadError;

/// One connection's bounded SSE parser and latest head. Disconnect discards all evidence.
#[derive(Default)]
pub struct HeadEvents {
    parser: crate::collector::SseParser,
    current: Option<HeadEvent>,
    connected: bool,
}
impl HeadEvents {
    /// Begin a new connection; neither a partial frame nor an old head can cross it.
    pub fn reconnected(&mut self) {
        self.disconnected();
        self.connected = true;
    }
    /// Invalidate immediately on EOF, timeout, transport failure or dropped input.
    pub fn disconnected(&mut self) {
        self.current = None;
        self.parser = Default::default();
        self.connected = false;
    }
    /// The most recent valid event on this connection only.
    pub fn snapshot(&self) -> Option<HeadEvent> {
        self.current.clone()
    }
    /// Decode recorded or live chunks. Invalid subscribed events invalidate the old head.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), HeadError> {
        if !self.connected {
            return Err(HeadError);
        }
        let result = self.consume(chunk);
        if result.is_err() {
            self.disconnected();
        }
        result
    }
    fn consume(&mut self, chunk: &[u8]) -> Result<(), HeadError> {
        for event in self.parser.feed(chunk).map_err(|_| HeadError)? {
            if event.event != "head_v2" {
                // This connection requested only head_v2. A legacy/misrouted event is not
                // evidence that the last FULL/EMPTY selection remains current.
                return Err(HeadError);
            }
            #[derive(Deserialize)]
            struct Event {
                version: String,
                data: Data,
            }
            #[derive(Deserialize)]
            struct Data {
                slot: String,
                block: String,
                payload_status: PayloadStatus,
            }
            let event: Event = serde_json::from_str(&event.data).map_err(|_| HeadError)?;
            if !matches!(
                event.version.as_str(),
                "phase0"
                    | "altair"
                    | "bellatrix"
                    | "capella"
                    | "deneb"
                    | "electra"
                    | "fulu"
                    | "gloas"
            ) || event.data.slot.is_empty()
                || !event.data.slot.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(HeadError);
            }
            let root = super::api_root(&event.data.block).ok_or(HeadError)?;
            self.current = Some(HeadEvent {
                slot: event.data.slot.parse().map_err(|_| HeadError)?,
                root: Root::from(root),
                status: event.data.payload_status,
            });
        }
        Ok(())
    }
}

/// Owned head_v2 subscription. Drop cancels the bounded reader and invalidates cached evidence.
pub struct HeadStream {
    current: tokio::sync::watch::Receiver<Option<HeadEvent>>,
    task: tokio::task::JoinHandle<()>,
    publish: tokio::sync::watch::Sender<Option<HeadEvent>>,
}
impl HeadStream {
    /// Subscribe on the existing owner-checked loopback/tunnel URL, with bounded deadlines.
    pub fn start(
        url: crate::collector::ReferenceApiUrl,
        request_timeout: std::time::Duration,
        idle_timeout: std::time::Duration,
    ) -> Result<Self, HeadError> {
        if request_timeout.is_zero() || idle_timeout.is_zero() {
            return Err(HeadError);
        }
        let (publish, current) = tokio::sync::watch::channel(None);
        let sender = publish.clone();
        let task = tokio::spawn(async move {
            use http_body_util::BodyExt;
            let mut delay = std::time::Duration::from_secs(1);
            loop {
                let mut events = HeadEvents::default();
                if let Ok(mut body) = crate::collector::open_stream(
                    &url,
                    "/eth/v1/events?topics=head_v2",
                    request_timeout,
                )
                .await
                {
                    events.reconnected();
                    let mut received = false;
                    while let Ok(Some(Ok(frame))) =
                        tokio::time::timeout(idle_timeout, body.frame()).await
                    {
                        let Ok(chunk) = frame.into_data() else {
                            continue;
                        };
                        if events.feed(&chunk).is_err() {
                            break;
                        }
                        let snapshot = events.snapshot();
                        received |= snapshot.is_some();
                        sender.send_replace(snapshot);
                    }
                    if received {
                        delay = std::time::Duration::from_secs(1);
                    }
                }
                // Publish loss before backoff, not only after the next connection succeeds.
                sender.send_replace(None);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(30));
            }
        });
        Ok(Self {
            current,
            task,
            publish,
        })
    }
    /// Latest observed transition on this connection; never proof of current status.
    pub fn snapshot(&self) -> Option<HeadEvent> {
        self.current.borrow().clone()
    }
    /// Observe readiness and connection-loss changes without polling or timing sleeps.
    pub fn updates(&self) -> tokio::sync::watch::Receiver<Option<HeadEvent>> {
        self.current.clone()
    }
}
impl Drop for HeadStream {
    fn drop(&mut self) {
        self.publish.send_replace(None);
        self.task.abort();
    }
}

impl PayloadStatus {
    pub(crate) fn from_wire(value: i32) -> Result<Self, HeadError> {
        match ethswarm_proto::chain::HeadPayloadStatus::try_from(value) {
            Ok(ethswarm_proto::chain::HeadPayloadStatus::Empty) => Ok(Self::Empty),
            Ok(ethswarm_proto::chain::HeadPayloadStatus::Full) => Ok(Self::Full),
            _ => Err(HeadError),
        }
    }
}

/// A finite comparison run, including its shared head-lag statistics.
#[derive(Debug, Serialize)]
pub struct HeadSummary {
    /// Planned samples successfully written.
    pub samples: u64,
    /// Samples with complete gated head/status evidence.
    pub compared: u64,
    /// Compared samples with root or status divergence.
    pub mismatches: u64,
    /// Samples with missing or incoherent evidence.
    pub gaps: u64,
    /// Samples deliberately skipped because lag exceeds two slots.
    pub skipped: u64,
    /// Run-wide statistics from the very same observations.
    pub lag: crate::head_lag::Summary,
}
impl HeadSummary {
    /// Mismatch=1; missing/skipped/no comparison=2; complete match=0.
    pub fn exit_code(&self) -> u8 {
        if self.mismatches > 0 {
            1
        } else if self.gaps > 0 || self.skipped > 0 || self.compared == 0 {
            2
        } else {
            0
        }
    }
}

struct HeadSink<'a, L, H> {
    lag: &'a mut L,
    head: &'a mut H,
    samples: u64,
    compared: u64,
    mismatches: u64,
    gaps: u64,
    skipped: u64,
}
impl<L: tokio::io::AsyncWrite + Unpin, H: tokio::io::AsyncWrite + Unpin> crate::head_lag::SampleSink
    for HeadSink<'_, L, H>
{
    async fn record(
        &mut self,
        sample: &crate::head_lag::Sample,
    ) -> Result<(), crate::head_lag::Error> {
        let current = |head: &Option<crate::head_lag::Head>| {
            head.as_ref().and_then(|head| {
                head.payload_status.map(|status| HeadSnapshot {
                    slot: head.slot,
                    root: head.root,
                    status,
                })
            })
        };
        // Only the sampled reads' adapter-guaranteed atomic statuses certify a comparison.
        // Generic head_v2 permits omitted transitions, even with a live heartbeat.
        let record = compare_head(sample, current(&sample.ours), current(&sample.reference));
        crate::head_lag::write_jsonl(self.lag, sample).await?;
        crate::head_lag::write_jsonl(self.head, &record).await?;
        self.samples += 1;
        self.compared += u64::from(record.compared);
        self.mismatches += u64::from(record.is_mismatch());
        self.skipped += u64::from(record.gap == Some(HeadGap::Lag));
        self.gaps += u64::from(record.gap.is_some_and(|gap| gap != HeadGap::Lag));
        Ok(())
    }
}

/// Use the shared sampler for lag and authoritative current head/status comparisons.
/// SSE is observational only. Header-only adapters supply no status and produce gaps;
/// an adapter must guarantee the status in the same current read to certify a comparison.
/// The stream parameter preserves caller-owned observation/lifecycle compatibility only.
/// The output tuple is `(lag_samples, head_comparisons)`. Drops cancel in-flight reads;
/// the caller owns the SSE stream and its shutdown lifetime.
pub async fn run_head(
    config: crate::head_lag::RunConfig,
    ours: &impl crate::head_lag::HeadSource,
    reference: &impl crate::head_lag::HeadSource,
    _events: &HeadStream,
    clock: &impl crate::collector::Clock,
    pause: &impl crate::collector::Pause,
    outputs: (
        &mut (impl tokio::io::AsyncWrite + Unpin),
        &mut (impl tokio::io::AsyncWrite + Unpin),
    ),
) -> Result<HeadSummary, crate::head_lag::Error> {
    let mut sink = HeadSink {
        lag: outputs.0,
        head: outputs.1,
        samples: 0,
        compared: 0,
        mismatches: 0,
        gaps: 0,
        skipped: 0,
    };
    let lag =
        crate::head_lag::run_with_sink(config, ours, reference, clock, pause, &mut sink).await?;
    Ok(HeadSummary {
        samples: sink.samples,
        compared: sink.compared,
        mismatches: sink.mismatches,
        gaps: sink.gaps,
        skipped: sink.skipped,
        lag,
    })
}
