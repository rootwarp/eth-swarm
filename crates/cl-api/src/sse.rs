//! `GET /eth/v1/events`: the beacon-APIs event stream (`apis/eventstream/index.yaml` at
//! `01e99a6`), fed by cl-chain's chain.v1 `EventsService`.
//!
//! - **Topics** ([`Topics::parse`]). `topics` is repeated (`topics=head&topics=block`) or
//!   comma-separated (`topics=head,block`); a topic named twice counts once. The topics served
//!   are [`Topic::ALL`]. Any other name, a beacon-APIs topic not served yet
//!   (`execution_payload`, `payload_attestation_message`, ...), an empty name or no topic at all
//!   answers 400 with the beacon-APIs error body, before anything else is looked at.
//! - **Events** ([`render`]). cl-chain writes each event's beacon-API JSON into the frame's
//!   `data_json` (`cl_chain::events`). It is parsed and written again, so what goes out has
//!   exactly the fields of the topic's schema, integers as quoted decimals and roots and hashes
//!   as `0x` and 64 lowercase hex digits, on one `data` line. A frame whose data does not parse
//!   is dropped and logged. One HEAD frame is two events, `head` then `head_v2`:
//!   - `head` is the 01e99a6 schema, without `payload_status`.
//!   - `head_v2` is `{"version": <fork of the head's slot>, "data": {...}}` with
//!     `payload_status`. The dependent roots take their v2 names: `current_epoch_dependent_root`
//!     is the frame's `previous_duty_dependent_root` and `next_epoch_dependent_root` its
//!     `current_duty_dependent_root`. A head before Fulu has no fork to name, so it has no
//!     `head_v2`.
//!
//!   `block` carries the Gloas `builder_index` and `block_hash` when cl-chain names them.
//! - **Fan-out** ([`EventHub`]). One chain.v1 `Subscribe`, on every v1 kind, serves every
//!   connection. [`EventHub::follow`] renders each frame once and broadcasts it. A connection may
//!   fall [`CLIENT_QUEUE_EVENTS`] events behind. Past that, its stream ends, and the other
//!   connections and the subscription go on. The policy is to close the slow connection: the hub
//!   never waits for one, and a stream never skips events silently. A client that has stopped
//!   reading altogether is closed by the server's write timeout.
//! - **No gaps.** cl-chain replays nothing, so a stream lives within one subscription. Until the
//!   subscription is open (cl-chain's hello read), a request answers 503. When it ends, every
//!   open stream ends with it, and the hub subscribes again after [`UPSTREAM_RETRY`]. It ends
//!   when cl-chain stops or ends it (a stream that lags its bus), or breaks the contract: a `seq`
//!   that does not rise, or `EVENT_KIND_UNSPECIFIED`. A client that reconnects reconciles over
//!   the REST routes.
//! - **Shutdown.** [`EventHub::follow`] stops with the server, and every open stream ends with
//!   it, so the server's drain does not wait on them.
//!
//! The route is mounted without the request timeout (`server::router`).

use std::convert::Infallible;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use ethswarm_proto::chain as pb;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderValue, StatusCode, Uri};
use ipc::frame::Inbound;
use ipc::{ContractError, Link};
use network_config::{ForkName, ForkSchedule};
use pb::events_service_client::EventsServiceClient;
use pb::EventKind;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize, Serializer};
use tokio::sync::broadcast::{self, error::RecvError};
use tonic::transport::Channel;

use crate::server::{ApiError, ApiState};

/// The route.
pub const EVENTS_PATH: &str = "/eth/v1/events";

/// Events one connection may fall behind the subscription before its stream ends: the
/// per-connection queue. Its policy is to close that connection, never to wait for it or to skip
/// events. [6.26] tunes the cap.
pub const CLIENT_QUEUE_EVENTS: usize = 256;

/// The pause before the hub subscribes again after its subscription ended or failed.
pub const UPSTREAM_RETRY: Duration = Duration::from_secs(1);

/// The chain.v1 kinds the hub subscribes to: every v1 kind.
const KINDS: [EventKind; 4] = [
    EventKind::Head,
    EventKind::Block,
    EventKind::FinalizedCheckpoint,
    EventKind::ChainReorg,
];

/// The other topics of the beacon APIs at `01e99a6`, which are not served yet.
const NOT_SERVED: [&str; 19] = [
    "block_gossip",
    "attestation",
    "single_attestation",
    "voluntary_exit",
    "bls_to_execution_change",
    "proposer_slashing",
    "attester_slashing",
    "contribution_and_proof",
    "light_client_finality_update",
    "light_client_optimistic_update",
    "payload_attributes",
    "data_column_sidecar",
    "execution_payload",
    "execution_payload_gossip",
    "execution_payload_available",
    "execution_payload_bid",
    "payload_attestation_message",
    "fast_confirmation",
    "proposer_preferences",
];

/// A topic this server streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Head,
    HeadV2,
    Block,
    FinalizedCheckpoint,
    ChainReorg,
}

impl Topic {
    /// Every topic served, in the order of one frame's events.
    pub const ALL: [Self; 5] = [
        Self::Head,
        Self::HeadV2,
        Self::Block,
        Self::FinalizedCheckpoint,
        Self::ChainReorg,
    ];

    /// The beacon-APIs name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Head => "head",
            Self::HeadV2 => "head_v2",
            Self::Block => "block",
            Self::FinalizedCheckpoint => "finalized_checkpoint",
            Self::ChainReorg => "chain_reorg",
        }
    }

    fn named(name: &str) -> Result<Self, ApiError> {
        if let Some(topic) = Self::ALL.into_iter().find(|t| t.name() == name) {
            return Ok(topic);
        }
        let message = if name.is_empty() {
            "Invalid topic: an empty name".to_owned()
        } else if NOT_SERVED.contains(&name) {
            format!("Topic not served yet: {name}")
        } else {
            format!("Invalid topic: {name}")
        };
        Err(ApiError::bad_request(message))
    }
}

/// The topics one connection asked for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Topics(u8);

impl Topics {
    /// The `topics` of a query string; other parameters are ignored.
    ///
    /// # Errors
    ///
    /// 400 for a name that is not a served topic (an empty one included), or no topic.
    pub fn parse(query: Option<&str>) -> Result<Self, ApiError> {
        let mut topics = Self::default();
        let pairs = form_urlencoded::parse(query.unwrap_or_default().as_bytes());
        for (_, value) in pairs.filter(|(key, _)| key == "topics") {
            for name in value.split(',') {
                topics.0 |= 1 << Topic::named(name)? as u8;
            }
        }
        if topics.0 == 0 {
            return Err(ApiError::bad_request("No topic given in topics"));
        }
        Ok(topics)
    }

    #[must_use]
    pub fn contains(self, topic: Topic) -> bool {
        self.0 & (1 << topic as u8) != 0
    }
}

/// What `head_v2` needs to name the fork of a head: the fork schedule and the epoch length.
#[derive(Clone, Copy, Debug)]
pub struct Forks {
    pub schedule: ForkSchedule,
    pub slots_per_epoch: u64,
}

impl Forks {
    /// The network's, from its link.
    #[must_use]
    pub fn of(link: &Link) -> Self {
        Self {
            schedule: *link.schedule(),
            slots_per_epoch: link.slots_per_epoch(),
        }
    }

    fn at_slot(&self, slot: u64) -> Option<ForkName> {
        self.schedule.fork_at(slot / self.slots_per_epoch.max(1))
    }
}

/// One frame, rendered once for every connection: its events in order, each as
/// `text/event-stream` text.
#[derive(Debug)]
pub struct Rendered {
    events: Vec<(Topic, Bytes)>,
}

impl Rendered {
    /// What a connection on `topics` sends of it; `None` if nothing.
    #[must_use]
    pub fn chunk(&self, topics: Topics) -> Option<Bytes> {
        let mut texts = self
            .events
            .iter()
            .filter(|(topic, _)| topics.contains(*topic))
            .map(|(_, text)| text);
        let first = texts.next()?;
        let Some(second) = texts.next() else {
            return Some(first.clone());
        };
        let mut joined = first.to_vec();
        for text in std::iter::once(second).chain(texts) {
            joined.extend_from_slice(text);
        }
        Some(joined.into())
    }
}

/// The events of one chain.v1 frame body; `Ok(None)` for a kind this server does not stream.
///
/// # Errors
///
/// The frame's `data_json` does not parse as its kind's event.
pub fn render(body: &pb::SubscribeResponseBody, forks: &Forks) -> Result<Option<Rendered>, String> {
    let data = &body.data_json;
    let events = match EventKind::try_from(body.kind) {
        Ok(EventKind::Head) => heads(data, forks)?,
        Ok(EventKind::Block) => vec![again::<BlockData>(Topic::Block, data)?],
        Ok(EventKind::FinalizedCheckpoint) => {
            vec![again::<FinalizedData>(Topic::FinalizedCheckpoint, data)?]
        }
        Ok(EventKind::ChainReorg) => vec![again::<ReorgData>(Topic::ChainReorg, data)?],
        _ => return Ok(None),
    };
    Ok(Some(Rendered { events }))
}

fn parse<T: DeserializeOwned>(topic: Topic, data: &[u8]) -> Result<T, String> {
    serde_json::from_slice(data).map_err(|e| format!("{} data: {e}", topic.name()))
}

/// `data` parsed as `T` and written again as `topic`'s event.
fn again<T: DeserializeOwned + Serialize>(
    topic: Topic,
    data: &[u8],
) -> Result<(Topic, Bytes), String> {
    Ok((topic, sse(topic, &parse::<T>(topic, data)?)))
}

/// One event: its `event` line and one `data` line (compact JSON has no line break).
fn sse(topic: Topic, data: &impl Serialize) -> Bytes {
    // Strings, numbers and booleans only: serializing cannot fail.
    let json = serde_json::to_string(data).unwrap_or_default();
    Bytes::from(format!("event: {}\ndata: {json}\n\n", topic.name()))
}

/// `head`, then `head_v2` if the head's slot has a fork.
fn heads(data: &[u8], forks: &Forks) -> Result<Vec<(Topic, Bytes)>, String> {
    let h: HeadData = parse(Topic::Head, data)?;
    let v1 = HeadV1 {
        slot: h.slot,
        block: &h.block,
        state: &h.state,
        epoch_transition: h.epoch_transition,
        previous_duty_dependent_root: &h.previous_duty_dependent_root,
        current_duty_dependent_root: &h.current_duty_dependent_root,
        execution_optimistic: h.execution_optimistic,
    };
    let mut events = vec![(Topic::Head, sse(Topic::Head, &v1))];
    let Some(fork) = forks.at_slot(h.slot.0) else {
        tracing::debug!(slot = h.slot.0, "a head before Fulu: no head_v2");
        return Ok(events);
    };
    let v2 = HeadV2 {
        version: fork.as_str(),
        data: HeadV2Data {
            slot: h.slot,
            block: &h.block,
            state: &h.state,
            payload_status: h.payload_status,
            epoch_transition: h.epoch_transition,
            current_epoch_dependent_root: &h.previous_duty_dependent_root,
            next_epoch_dependent_root: &h.current_duty_dependent_root,
            execution_optimistic: h.execution_optimistic,
        },
    };
    events.push((Topic::HeadV2, sse(Topic::HeadV2, &v2)));
    Ok(events)
}

/// A `uint64` as the beacon APIs write it: a quoted decimal.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "String")]
struct Quoted(u64);

impl TryFrom<String> for Quoted {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        // Digits only: `u64::from_str` would also take a leading `+`.
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("{s:?} is not a quoted decimal"));
        }
        s.parse().map(Self).map_err(|e| format!("{s:?}: {e}"))
    }
}

impl Serialize for Quoted {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

/// A root or a hash: `0x` and 64 hex digits, kept in lowercase.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "String")]
struct Hex32(String);

impl TryFrom<String> for Hex32 {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        match s.strip_prefix("0x") {
            Some(hex) if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                Ok(Self(s.to_ascii_lowercase()))
            }
            _ => Err(format!("{s:?} is not 0x and 32 bytes of hex")),
        }
    }
}

impl Serialize for Hex32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// The fork-choice head node's payload status (`head_v2`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PayloadStatus {
    Empty,
    Full,
    Pending,
}

/// HEAD's `data_json`: the `head` fields and the head node's `payload_status`.
#[derive(Deserialize)]
struct HeadData {
    slot: Quoted,
    block: Hex32,
    state: Hex32,
    epoch_transition: bool,
    previous_duty_dependent_root: Hex32,
    current_duty_dependent_root: Hex32,
    execution_optimistic: bool,
    payload_status: PayloadStatus,
}

/// `head`.
#[derive(Serialize)]
struct HeadV1<'a> {
    slot: Quoted,
    block: &'a Hex32,
    state: &'a Hex32,
    epoch_transition: bool,
    previous_duty_dependent_root: &'a Hex32,
    current_duty_dependent_root: &'a Hex32,
    execution_optimistic: bool,
}

/// `head_v2`.
#[derive(Serialize)]
struct HeadV2<'a> {
    version: &'static str,
    data: HeadV2Data<'a>,
}

#[derive(Serialize)]
struct HeadV2Data<'a> {
    slot: Quoted,
    block: &'a Hex32,
    state: &'a Hex32,
    payload_status: PayloadStatus,
    epoch_transition: bool,
    current_epoch_dependent_root: &'a Hex32,
    next_epoch_dependent_root: &'a Hex32,
    execution_optimistic: bool,
}

/// `block`; the bid's fields from Gloas.
#[derive(Serialize, Deserialize)]
struct BlockData {
    slot: Quoted,
    block: Hex32,
    execution_optimistic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    builder_index: Option<Quoted>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_hash: Option<Hex32>,
}

/// `finalized_checkpoint`.
#[derive(Serialize, Deserialize)]
struct FinalizedData {
    block: Hex32,
    state: Hex32,
    epoch: Quoted,
    execution_optimistic: bool,
}

/// `chain_reorg`.
#[derive(Serialize, Deserialize)]
struct ReorgData {
    slot: Quoted,
    depth: Quoted,
    old_head_block: Hex32,
    new_head_block: Hex32,
    old_head_state: Hex32,
    new_head_state: Hex32,
    epoch: Quoted,
    execution_optimistic: bool,
}

/// The fan-out: one chain.v1 `Subscribe` shared by every connection (see the module docs).
/// Clones share it.
#[derive(Clone, Debug)]
pub struct EventHub {
    inner: Arc<Hub>,
}

#[derive(Debug)]
struct Hub {
    /// The open subscription's events, `None` while there is none.
    live: Mutex<Option<broadcast::Sender<Arc<Rendered>>>>,
    /// [`CLIENT_QUEUE_EVENTS`], or a test's.
    queue: usize,
}

impl Default for EventHub {
    fn default() -> Self {
        Self::new()
    }
}

impl EventHub {
    /// A hub whose connections may fall [`CLIENT_QUEUE_EVENTS`] events behind.
    #[must_use]
    pub fn new() -> Self {
        Self::with_queue(CLIENT_QUEUE_EVENTS)
    }

    /// A hub whose connections may fall `events` (at least one) behind. The broadcast
    /// channel rounds this up to a power of two, as [`CLIENT_QUEUE_EVENTS`] already is.
    #[must_use]
    pub fn with_queue(events: usize) -> Self {
        Self {
            inner: Arc::new(Hub {
                live: Mutex::new(None),
                queue: events.max(1),
            }),
        }
    }

    fn live(&self) -> MutexGuard<'_, Option<broadcast::Sender<Arc<Rendered>>>> {
        self.inner
            .live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether a subscription is open, so a new connection is served.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.live().is_some()
    }

    /// The open subscription's next events, if one is open.
    fn attach(&self) -> Option<broadcast::Receiver<Arc<Rendered>>> {
        self.live().as_ref().map(broadcast::Sender::subscribe)
    }

    /// Subscribes to cl-chain's events through `client` with `link`'s hello, and again after
    /// [`UPSTREAM_RETRY`] each time the subscription fails or ends, until `stop`. Then every
    /// open stream ends.
    pub async fn follow(
        self,
        mut client: EventsServiceClient<Channel>,
        link: Link,
        stop: impl Future<Output = ()>,
    ) {
        let subscriptions = async {
            loop {
                match self.subscription(&mut client, &link).await {
                    Ok(end) => tracing::warn!(
                        %end,
                        "cl-chain's event stream ended, and every /eth/v1/events stream with it"
                    ),
                    Err(e) => tracing::debug!(error = %e, "cannot subscribe to cl-chain's events"),
                }
                tokio::time::sleep(UPSTREAM_RETRY).await;
            }
        };
        tokio::select! {
            () = stop => {}
            () = subscriptions => {}
        }
        self.live().take();
    }

    /// One subscription, served to new connections while it is open: why it ended, or `Err`
    /// if it did not open.
    async fn subscription(
        &self,
        client: &mut EventsServiceClient<Channel>,
        link: &Link,
    ) -> Result<String, String> {
        let request = pb::SubscribeRequest {
            kinds: KINDS.map(|kind| kind as i32).to_vec(),
            resume_from_seq: 0,
            hello: Some(link.local()),
        };
        let stream = client
            .subscribe(request)
            .await
            .map_err(|e| format!("Subscribe: {e}"))?
            .into_inner();
        let mut frames = link
            .open(Inbound::from_server(stream))
            .await
            .map_err(|e| format!("Subscribe: {e}"))?;
        let (sender, _) = broadcast::channel(self.inner.queue);
        *self.live() = Some(sender.clone());
        tracing::info!("subscribed to cl-chain's events: /eth/v1/events is served");
        let forks = Forks::of(link);
        let mut last = 0;
        let end = loop {
            let body = match frames.body().await {
                Ok(Some(accepted)) => accepted.body,
                Ok(None) => break "cl-chain closed it".to_owned(),
                Err(e) => break e.to_string(),
            };
            if body.seq <= last || body.kind == EventKind::Unspecified as i32 {
                let detail = format!(
                    "event seq {} of kind {} after seq {last}",
                    body.seq, body.kind
                );
                let e = ContractError::violation(detail);
                link.record(&e);
                break e.to_string();
            }
            last = body.seq;
            match render(&body, &forks) {
                Ok(Some(event)) => {
                    // No connection is attached: nothing to send it to.
                    let _ = sender.send(Arc::new(event));
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(seq = body.seq, error = %e, "cl-chain event dropped"),
            }
        };
        self.live().take();
        Ok(end)
    }
}

/// The route.
pub fn routes() -> Router<ApiState> {
    Router::new().route(EVENTS_PATH, get(events))
}

/// 400 for bad topics, 503 without a subscription, else the stream.
async fn events(State(state): State<ApiState>, uri: Uri) -> Response {
    let topics = match Topics::parse(uri.query()) {
        Ok(topics) => topics,
        Err(e) => return e.into_response(),
    };
    let Some(receiver) = state.events.attach() else {
        let message = "Not subscribed to cl-chain's events yet; try again";
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, message).into_response();
    };
    let stream = futures_util::stream::unfold(receiver, move |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if let Some(chunk) = event.chunk(topics) {
                        return Some((Ok::<_, Infallible>(chunk), receiver));
                    }
                }
                Err(RecvError::Lagged(missed)) => {
                    tracing::info!(missed, "an /eth/v1/events client fell behind: closed");
                    return None;
                }
                Err(RecvError::Closed) => return None,
            }
        }
    });
    let headers = [
        (CONTENT_TYPE, HeaderValue::from_static("text/event-stream")),
        (CACHE_CONTROL, HeaderValue::from_static("no-cache")),
    ];
    (headers, Body::from_stream(stream)).into_response()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Instant;

    use http::header::{CACHE_CONTROL, CONTENT_TYPE};
    use http::{HeaderMap, StatusCode};
    use pb::EventKind;
    use serde_json::{json, Value};
    use tokio::net::{TcpListener, TcpSocket};
    use tokio::sync::watch;

    use super::*;
    use crate::node_state::NodeState;
    use crate::server::{self, HttpLimits};
    use crate::testing::{
        self, event, FakeEvents, RunningChain, SseClient, SseEvent, SseParser, WITHIN,
    };

    const FIXTURE: &str = include_str!("../tests/fixtures/beacon-apis-01e99a6-eventstream.json");

    /// Sepolia: 32 slots per epoch, Fulu at epoch 272640, Gloas at 353024.
    const SLOTS: u64 = 32;
    const FULU_EPOCH: u64 = 272_640;
    const GLOAS_EPOCH: u64 = 353_024;
    const FULU_SLOT: u64 = FULU_EPOCH * SLOTS + 3;
    const GLOAS_SLOT: u64 = GLOAS_EPOCH * SLOTS + 3;

    const ALL: &str = "topics=head,head_v2,block,finalized_checkpoint,chain_reorg";
    const ALL_NAMES: [&str; 5] = [
        "head",
        "head_v2",
        "block",
        "finalized_checkpoint",
        "chain_reorg",
    ];

    /// 32 bytes of `n`, as the beacon APIs write them.
    fn hex(n: u8) -> String {
        format!("0x{}", format!("{n:02x}").repeat(32))
    }

    fn forks() -> Forks {
        Forks {
            schedule: *testing::sepolia().fork_schedule(),
            slots_per_epoch: SLOTS,
        }
    }

    /// A HEAD frame as cl-chain's `events.rs` writes it.
    fn head(seq: u64, slot: u64, payload_status: &str) -> pb::SubscribeResponseBody {
        let data = json!({
            "slot": slot.to_string(),
            "block": hex(1),
            "state": hex(2),
            "epoch_transition": true,
            "previous_duty_dependent_root": hex(3),
            "current_duty_dependent_root": hex(4),
            "execution_optimistic": true,
            "payload_status": payload_status,
        });
        event(seq, EventKind::Head, slot, &data)
    }

    /// A BLOCK frame; `bid` is the Gloas `(builder_index, block_hash byte)`.
    fn block(seq: u64, slot: u64, bid: Option<(u64, u8)>) -> pb::SubscribeResponseBody {
        let mut data = json!({
            "slot": slot.to_string(),
            "block": hex(5),
            "execution_optimistic": false,
        });
        if let Some((builder_index, hash)) = bid {
            data["builder_index"] = json!(builder_index.to_string());
            data["block_hash"] = json!(hex(hash));
        }
        event(seq, EventKind::Block, slot, &data)
    }

    fn finalized_data(epoch: u64) -> Value {
        json!({
            "block": hex(7),
            "state": hex(8),
            "epoch": epoch.to_string(),
            "execution_optimistic": false,
        })
    }

    fn finalized(seq: u64, epoch: u64) -> pb::SubscribeResponseBody {
        let data = finalized_data(epoch);
        event(seq, EventKind::FinalizedCheckpoint, epoch * SLOTS, &data)
    }

    fn reorg_data(slot: u64, depth: u64) -> Value {
        json!({
            "slot": slot.to_string(),
            "depth": depth.to_string(),
            "old_head_block": hex(9),
            "new_head_block": hex(10),
            "old_head_state": hex(11),
            "new_head_state": hex(12),
            "epoch": (slot / SLOTS).to_string(),
            "execution_optimistic": false,
        })
    }

    fn reorg(seq: u64, slot: u64, depth: u64) -> pb::SubscribeResponseBody {
        event(seq, EventKind::ChainReorg, slot, &reorg_data(slot, depth))
    }

    fn topics(query: &str) -> Topics {
        Topics::parse(Some(query)).unwrap()
    }

    /// The events a connection on `query`'s topics sends of `body`.
    fn sse(body: &pb::SubscribeResponseBody, query: &str) -> Vec<SseEvent> {
        let rendered = render(body, &forks())
            .unwrap()
            .expect("an event this server streams");
        rendered
            .chunk(topics(query))
            .map_or_else(Vec::new, |chunk| {
                assert!(chunk.ends_with(b"\n\n"), "{chunk:?}");
                assert!(!chunk.contains(&b'\r'), "{chunk:?}");
                let events = SseParser::default().push(&chunk);
                // One `event` and one `data` line each.
                assert_eq!(chunk.split(|&b| b == b'\n').count(), 3 * events.len() + 1);
                events
            })
    }

    fn names(events: &[SseEvent]) -> Vec<&str> {
        events.iter().map(|e| e.event.as_str()).collect()
    }

    /// The beacon-APIs error body with `code`, its message holding `needle`.
    fn assert_error(status: StatusCode, headers: &HeaderMap, body: &[u8], code: u16, needle: &str) {
        assert_eq!(status.as_u16(), code, "{}", String::from_utf8_lossy(body));
        assert_eq!(headers[CONTENT_TYPE], "application/json");
        let body = testing::json(body);
        assert_eq!(body.as_object().unwrap().len(), 2, "{body}");
        assert_eq!(body["code"], code);
        let message = body["message"].as_str().unwrap();
        assert!(!message.is_empty() && message.contains(needle), "{message}");
    }

    fn spec() -> Value {
        let spec: Value = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(
            spec["source"]["commit"],
            "01e99a6530b22941f619bde525cbf8bb61991d42"
        );
        spec
    }

    /// Unknown topics, the topics of the beacon APIs this server does not stream yet, and no
    /// topic at all: 400 with the beacon-APIs error body, before the hub is asked (it has no
    /// subscription here, so a request that passes answers 503).
    #[tokio::test]
    async fn unknown_topic_400() {
        let app = testing::router(testing::api_state(NodeState::new(testing::clock())));
        let spec = spec();
        let enumerated: Vec<&str> = spec["topics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap())
            .collect();
        let served: Vec<&str> = Topic::ALL.iter().map(|t| t.name()).collect();
        assert_eq!(served, ALL_NAMES);
        assert!(served.iter().all(|t| enumerated.contains(t)));
        let mut refused: Vec<String> = [
            "weather_forecast",
            "HEAD",
            "head_v3",
            "payload_attestation",
            "execution_payload_envelope",
        ]
        .map(String::from)
        .to_vec();
        refused.extend(
            enumerated
                .iter()
                .filter(|t| !served.contains(t))
                .map(|t| (*t).to_owned()),
        );
        for later in [
            "execution_payload",
            "payload_attestation_message",
            "block_gossip",
        ] {
            assert!(refused.iter().any(|t| t == later), "{later}");
        }
        for topic in &refused {
            for query in [
                format!("topics={topic}"),
                format!("topics=head,{topic}"),
                format!("topics=block&topics={topic}"),
            ] {
                let (status, headers, body) =
                    testing::get(&app, &format!("{EVENTS_PATH}?{query}")).await;
                assert_error(status, &headers, &body, 400, topic);
            }
        }
        for query in [
            "",
            "?",
            "?topics=",
            "?topics=,",
            "?topics=head,",
            "?topics=,head",
            "?topics=head&topics=",
            "?topic=head",
            "?topics=%20",
            "?topics=head%20",
        ] {
            let (status, headers, body) =
                testing::get(&app, &format!("{EVENTS_PATH}{query}")).await;
            assert_error(status, &headers, &body, 400, "");
        }
        // Served topics pass, named once or twice, repeated or comma-separated.
        for query in [
            "topics=head",
            "topics=head_v2",
            ALL,
            "topics=head&topics=head",
            "topics=finalized_checkpoint&topics=chain_reorg&other=1",
        ] {
            let (status, headers, body) =
                testing::get(&app, &format!("{EVENTS_PATH}?{query}")).await;
            assert_error(status, &headers, &body, 503, "");
        }
        let set = topics("topics=head,block&topics=chain_reorg");
        for (topic, has) in Topic::ALL.into_iter().zip([true, false, true, false, true]) {
            assert_eq!(set.contains(topic), has, "{topic:?}");
        }
    }

    /// Each HEAD frame is `head` (the 01e99a6 schema, without `payload_status`) and then
    /// `head_v2` (`version`, and `payload_status` with the v2 names of the dependent roots).
    #[test]
    fn head_v2_payload_status() {
        let v1 = |slot: u64| {
            json!({
                "slot": slot.to_string(),
                "block": hex(1),
                "state": hex(2),
                "epoch_transition": true,
                "previous_duty_dependent_root": hex(3),
                "current_duty_dependent_root": hex(4),
                "execution_optimistic": true,
            })
        };
        let v2 = |version: &str, payload_status: &str, slot: u64| {
            json!({
                "version": version,
                "data": {
                    "slot": slot.to_string(),
                    "block": hex(1),
                    "state": hex(2),
                    "payload_status": payload_status,
                    "epoch_transition": true,
                    "current_epoch_dependent_root": hex(3),
                    "next_epoch_dependent_root": hex(4),
                    "execution_optimistic": true,
                },
            })
        };
        let both = sse(&head(1, GLOAS_SLOT, "empty"), "topics=head,head_v2");
        assert_eq!(names(&both), ["head", "head_v2"]);
        assert_eq!(both[0].json(), v1(GLOAS_SLOT));
        assert_eq!(both[1].json(), v2("gloas", "empty", GLOAS_SLOT));
        // Head first, however the topics were named.
        let reversed = sse(&head(1, GLOAS_SLOT, "empty"), "topics=head_v2&topics=head");
        assert_eq!(names(&reversed), ["head", "head_v2"]);
        // The payload turning full: a second head, on each topic alone.
        let only_v1 = sse(&head(2, GLOAS_SLOT, "full"), "topics=head");
        assert_eq!(names(&only_v1), ["head"]);
        assert_eq!(only_v1[0].json(), v1(GLOAS_SLOT));
        let only_v2 = sse(&head(2, GLOAS_SLOT, "full"), "topics=head_v2");
        assert_eq!(names(&only_v2), ["head_v2"]);
        assert_eq!(only_v2[0].json(), v2("gloas", "full", GLOAS_SLOT));
        // Not asked for.
        let others = "topics=block,finalized_checkpoint,chain_reorg";
        assert!(sse(&head(3, GLOAS_SLOT, "full"), others).is_empty());
        // A Fulu head names fulu (its payload is full).
        let fulu = sse(&head(4, FULU_SLOT, "full"), "topics=head,head_v2");
        assert_eq!(fulu[1].json(), v2("fulu", "full", FULU_SLOT));
        // Before Fulu there is no fork to name: head only.
        let early = sse(
            &head(5, FULU_EPOCH * SLOTS - 1, "full"),
            "topics=head,head_v2",
        );
        assert_eq!(names(&early), ["head"]);
        assert_eq!(early[0].json(), v1(FULU_EPOCH * SLOTS - 1));
    }

    /// `block` carries the Gloas bid's `builder_index` and `block_hash`; a Fulu block has none.
    #[test]
    fn block_gloas_fields() {
        let gloas = sse(&block(1, GLOAS_SLOT, Some((42, 0xab))), "topics=block");
        assert_eq!(names(&gloas), ["block"]);
        assert_eq!(
            gloas[0].json(),
            json!({
                "slot": GLOAS_SLOT.to_string(),
                "block": hex(5),
                "execution_optimistic": false,
                "builder_index": "42",
                "block_hash": hex(0xab),
            })
        );
        // BUILDER_INDEX_SELF_BUILD, quoted.
        let own = sse(
            &block(2, GLOAS_SLOT, Some((u64::MAX, 0xcd))),
            "topics=block",
        );
        assert_eq!(own[0].json()["builder_index"], "18446744073709551615");
        let fulu = sse(&block(3, FULU_SLOT, None), "topics=block");
        assert_eq!(
            fulu[0].json(),
            json!({"slot": FULU_SLOT.to_string(), "block": hex(5), "execution_optimistic": false})
        );
        let others = "topics=head,head_v2,finalized_checkpoint,chain_reorg";
        assert!(sse(&block(4, GLOAS_SLOT, Some((1, 1))), others).is_empty());
    }

    /// A JSON value's shape as the beacon APIs fix it: `uint64` for a quoted decimal, `hexN`
    /// for `0x` and N lowercase hex digits, keys sorted.
    fn shape(value: &Value) -> String {
        let lower_hex = |s: &str| {
            s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        match value {
            Value::Bool(_) => "bool".into(),
            Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                "uint64".into()
            }
            Value::String(s) if s.strip_prefix("0x").is_some_and(lower_hex) => {
                format!("hex{}", s.len() - 2)
            }
            Value::String(_) => "string".into(),
            Value::Object(map) => {
                let mut fields: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{k}: {}", shape(v)))
                    .collect();
                fields.sort();
                format!("{{{}}}", fields.join(", "))
            }
            other => panic!("not in an eventstream example: {other}"),
        }
    }

    /// Every event this server streams has the shape of its `01e99a6` example: the same fields,
    /// integers as quoted decimals, roots and hashes as `0x` hex. Data that breaks those rules
    /// is not streamed.
    #[test]
    fn finalized_and_reorg_schemas() {
        let spec = spec();
        let examples = &spec["examples"];
        assert_eq!(
            shape(&examples["finalized_checkpoint"]),
            "{block: hex64, epoch: uint64, execution_optimistic: bool, state: hex64}"
        );
        assert_eq!(
            shape(&examples["chain_reorg"]),
            "{depth: uint64, epoch: uint64, execution_optimistic: bool, new_head_block: hex64, \
             new_head_state: hex64, old_head_block: hex64, old_head_state: hex64, slot: uint64}"
        );
        let finalized_events = sse(&finalized(1, 9), "topics=finalized_checkpoint");
        assert_eq!(names(&finalized_events), ["finalized_checkpoint"]);
        assert_eq!(finalized_events[0].json(), finalized_data(9));
        let reorg_events = sse(&reorg(2, GLOAS_SLOT, 3), "topics=chain_reorg");
        assert_eq!(names(&reorg_events), ["chain_reorg"]);
        assert_eq!(reorg_events[0].json(), reorg_data(GLOAS_SLOT, 3));
        let cases = [
            (head(1, GLOAS_SLOT, "empty"), "head"),
            (head(1, GLOAS_SLOT, "empty"), "head_v2"),
            (block(2, GLOAS_SLOT, Some((42, 0xab))), "block"),
            (finalized(3, 9), "finalized_checkpoint"),
            (reorg(4, GLOAS_SLOT, 3), "chain_reorg"),
        ];
        for (body, topic) in cases {
            let events = sse(&body, &format!("topics={topic}"));
            assert_eq!(names(&events), [topic]);
            assert_eq!(shape(&events[0].json()), shape(&examples[topic]), "{topic}");
        }
        let v2 = &sse(&head(1, GLOAS_SLOT, "empty"), "topics=head_v2")[0].json();
        assert_eq!(v2["version"], examples["head_v2"]["version"]);
        assert_eq!(v2["data"]["payload_status"], "empty");
        // Hex in capitals is written in lowercase.
        let mut upper = finalized_data(9);
        upper["block"] = json!(hex(0xab).to_uppercase().replacen("0X", "0x", 1));
        let body = event(1, EventKind::FinalizedCheckpoint, 0, &upper);
        assert_eq!(
            sse(&body, "topics=finalized_checkpoint")[0].json()["block"],
            hex(0xab)
        );
        // Not streamed: an integer that is not a quoted decimal in u64, a root that is not 0x
        // and 64 hex digits, a missing field, an unknown payload status, data that is not JSON.
        let mut bad = Vec::new();
        for epoch in [
            json!(9),
            json!("-1"),
            json!("+9"),
            json!(""),
            json!("18446744073709551616"),
        ] {
            let mut data = finalized_data(9);
            data["epoch"] = epoch;
            bad.push((EventKind::FinalizedCheckpoint, data));
        }
        for root in [
            "0x1234".to_owned(),
            format!("0x{}", "zz".repeat(32)),
            "11".repeat(32),
            format!("0X{}", "11".repeat(32)),
            format!("0x{}", "11".repeat(33)),
        ] {
            let mut data = finalized_data(9);
            data["state"] = json!(root);
            bad.push((EventKind::FinalizedCheckpoint, data));
        }
        let mut no_epoch = finalized_data(9);
        no_epoch.as_object_mut().unwrap().remove("epoch");
        bad.push((EventKind::FinalizedCheckpoint, no_epoch));
        let mut depth = reorg_data(GLOAS_SLOT, 3);
        depth["depth"] = json!(3);
        bad.push((EventKind::ChainReorg, depth));
        let mut status = testing::json(&head(1, GLOAS_SLOT, "empty").data_json);
        status["payload_status"] = json!("withheld");
        bad.push((EventKind::Head, status));
        let mut builder = testing::json(&block(1, GLOAS_SLOT, Some((1, 1))).data_json);
        builder["builder_index"] = json!(1);
        bad.push((EventKind::Block, builder));
        for (kind, data) in bad {
            let body = event(1, kind, 0, &data);
            assert!(render(&body, &forks()).is_err(), "{kind:?} {data}");
        }
        let mut not_json = finalized(1, 9);
        not_json.data_json = b"{\"block\":".to_vec();
        assert!(render(&not_json, &forks()).is_err());
        // A kind this server does not stream renders to nothing.
        for kind in [5, 6, 7, 8, 99] {
            let mut body = finalized(1, 9);
            body.kind = kind;
            assert!(render(&body, &forks()).unwrap().is_none(), "{kind}");
        }
    }

    /// The SSE parser of the test client: comments, CRLF, several data lines, a default event
    /// type, an event split anywhere, and the text this server writes.
    #[test]
    fn sse_parser_reads_event_streams() {
        let text = ": a comment\r\nevent: head\r\ndata: {\"a\":1}\r\n\r\n\
                    data:one\ndata: two\nid: 7\nretry: 10\n\n\
                    event: empty\n\n\
                    event: block\ndata\n\n";
        let expected = vec![
            SseEvent {
                event: "head".into(),
                data: "{\"a\":1}".into(),
            },
            SseEvent {
                event: "message".into(),
                data: "one\ntwo".into(),
            },
            SseEvent {
                event: "block".into(),
                data: String::new(),
            },
        ];
        assert_eq!(SseParser::default().push(text.as_bytes()), expected);
        for split in 1..text.len() {
            let mut parser = SseParser::default();
            let mut events = parser.push(&text.as_bytes()[..split]);
            events.extend(parser.push(&text.as_bytes()[split..]));
            assert_eq!(events, expected, "split at {split}");
        }
    }

    /// The test client reads a `text/event-stream` over hyper, whatever the chunking.
    #[tokio::test]
    async fn sse_client_over_hyper() {
        let parts = [
            "event: he",
            "ad\ndata: {\"slot\":\"1\"}\n",
            "\nevent: block\n",
            "data: 2\n\n",
        ];
        let stream = move || async move {
            let chunks = parts.map(|p| Ok::<_, std::convert::Infallible>(Bytes::from(p)));
            axum::body::Body::from_stream(futures_util::stream::iter(chunks))
        };
        let app = Router::new().route("/stream", get(stream));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (_stop, stopped) = watch::channel(false);
        tokio::spawn(server::serve(
            listener,
            app,
            HttpLimits::default(),
            wait(stopped),
        ));
        let mut client = SseClient::connect(addr, "/stream").await;
        assert_eq!(client.status, StatusCode::OK);
        let events = client.take(2).await;
        assert_eq!(names(&events), ["head", "block"]);
        assert_eq!(events[0].json(), json!({"slot": "1"}));
        assert_eq!(events[1].data, "2");
        assert_eq!(client.next().await, None);
    }

    async fn wait(mut stop: watch::Receiver<bool>) {
        let _ = stop.wait_for(|stop| *stop).await;
    }

    /// The Beacon API on a loopback port, its hub following a fake cl-chain on a Unix socket.
    struct Api {
        addr: SocketAddr,
        fake: FakeEvents,
        hub: EventHub,
        stop: watch::Sender<bool>,
        server: tokio::task::JoinHandle<()>,
        follower: tokio::task::JoinHandle<()>,
        _chain: RunningChain,
        _dir: tempfile::TempDir,
    }

    async fn local() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    /// A loopback listener whose connections have a small send buffer, so the server's writes
    /// to a client that does not read block soon.
    fn tight_listener() -> TcpListener {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(16 << 10).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.listen(64).unwrap()
    }

    impl Api {
        /// `queue` events per connection, on `listener`, with a 10 s write timeout; returns
        /// once the hub has subscribed.
        async fn start(queue: usize, listener: TcpListener) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("chain.sock");
            let fake = FakeEvents::new();
            let chain = fake.serve_uds(&socket);
            let channel = ipc::uds::connect_path(&socket, ipc::peercred::effective_uid())
                .await
                .unwrap();
            let hub = EventHub::with_queue(queue);
            let (stop, stopped) = watch::channel(false);
            let client = EventsServiceClient::new(channel);
            let follower = tokio::spawn(hub.clone().follow(
                client,
                testing::link(),
                wait(stopped.clone()),
            ));
            let state = ApiState {
                events: hub.clone(),
                ..testing::api_state(NodeState::new(testing::clock()))
            };
            let limits = HttpLimits {
                write_timeout: Duration::from_secs(10),
                ..HttpLimits::default()
            };
            let app = server::router(state, limits.request_timeout);
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(server::serve(listener, app, limits, wait(stopped)));
            let api = Self {
                addr,
                fake,
                hub,
                stop,
                server,
                follower,
                _chain: chain,
                _dir: dir,
            };
            api.until_live().await;
            api
        }

        async fn until_live(&self) {
            let start = Instant::now();
            while !self.hub.is_live() {
                assert!(start.elapsed() < WITHIN, "the hub never subscribed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }

        /// A stream on `query`'s topics: 200, `text/event-stream`, not cached.
        async fn client(&self, query: &str) -> SseClient {
            let client = SseClient::connect(self.addr, &format!("{EVENTS_PATH}?{query}")).await;
            assert_eq!(client.status, StatusCode::OK, "{query}");
            assert_eq!(client.headers[CONTENT_TYPE], "text/event-stream");
            assert_eq!(client.headers[CACHE_CONTROL], "no-cache");
            client
        }
    }

    /// Clients on different topics share the hub's one `Subscribe` (every v1 kind), and each
    /// gets exactly its topics.
    #[tokio::test]
    async fn fanout_single_upstream() {
        let api = Api::start(CLIENT_QUEUE_EVENTS, local().await).await;
        let sets = [
            ("topics=head", vec!["head"]),
            ("topics=head_v2", vec!["head_v2"]),
            ("topics=block", vec!["block"]),
            (
                "topics=finalized_checkpoint,chain_reorg",
                vec!["finalized_checkpoint", "chain_reorg"],
            ),
            (ALL, ALL_NAMES.to_vec()),
            (ALL, ALL_NAMES.to_vec()),
            (ALL, ALL_NAMES.to_vec()),
            (
                "topics=chain_reorg&topics=head",
                vec!["head", "chain_reorg"],
            ),
        ];
        let mut clients = Vec::new();
        for (query, _) in &sets {
            clients.push(api.client(query).await);
        }
        api.fake.push(head(1, GLOAS_SLOT, "empty"));
        api.fake.push(block(2, GLOAS_SLOT, Some((42, 0xab))));
        api.fake.push(finalized(3, GLOAS_EPOCH));
        api.fake.push(reorg(4, GLOAS_SLOT, 1));
        for (client, (query, expected)) in clients.iter_mut().zip(&sets) {
            let events = client.take(expected.len()).await;
            assert_eq!(&names(&events), expected, "{query}");
            let extra = client.next_within(Duration::from_millis(100)).await;
            assert!(extra.is_err(), "{query}: {extra:?}");
        }
        assert_eq!(api.fake.subscribes(), 1);
        let kinds = [
            EventKind::Head,
            EventKind::Block,
            EventKind::FinalizedCheckpoint,
            EventKind::ChainReorg,
        ];
        assert_eq!(api.fake.kinds(), kinds.map(|k| k as i32));
    }

    /// The key of an event's data: its slot, or a checkpoint's epoch.
    fn key(event: &SseEvent) -> (String, u64) {
        let data = event.json();
        let data = if event.event == "head_v2" {
            &data["data"]
        } else {
            &data
        };
        let key = data
            .get("slot")
            .or_else(|| data.get("epoch"))
            .and_then(Value::as_str)
            .unwrap();
        (event.event.clone(), key.parse().unwrap())
    }

    /// Each connection gets its events in the order cl-chain sent them, `head` before
    /// `head_v2`.
    #[tokio::test]
    async fn per_connection_order() {
        let api = Api::start(CLIENT_QUEUE_EVENTS, local().await).await;
        let mut all = api.client(ALL).await;
        let mut blocks = api.client("topics=block").await;
        let mut heads = api.client("topics=head_v2,head").await;
        for round in 0..100 {
            let (seq, slot, epoch) = (4 * round, GLOAS_SLOT + round, GLOAS_EPOCH + round);
            api.fake.push(head(seq + 1, slot, "empty"));
            api.fake.push(block(seq + 2, slot, Some((round, 1))));
            api.fake.push(finalized(seq + 3, epoch));
            api.fake.push(reorg(seq + 4, slot, round));
            let expected = [
                ("head", slot),
                ("head_v2", slot),
                ("block", slot),
                ("finalized_checkpoint", epoch),
                ("chain_reorg", slot),
            ];
            let got: Vec<_> = all.take(5).await.iter().map(key).collect();
            let expected: Vec<_> = expected
                .iter()
                .map(|(n, k)| ((*n).to_owned(), *k))
                .collect();
            assert_eq!(got, expected, "round {round}");
            assert_eq!(key(&blocks.take(1).await[0]), ("block".into(), slot));
            let got: Vec<_> = heads.take(2).await.iter().map(key).collect();
            assert_eq!(got, expected[..2], "round {round}");
        }
    }

    /// A client that does not read falls behind: once it is more than the queue behind, its
    /// stream ends (it gets, in order, what it was sent before, then the end). The client that
    /// reads, and the subscription, are not affected.
    #[tokio::test]
    async fn slow_client_evicted() {
        const QUEUE: usize = 8;
        const EVENTS: u64 = 2000;
        let api = Api::start(QUEUE, tight_listener()).await;
        let mut fast = api.client("topics=block").await;
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4 << 10).unwrap();
        let stream = socket.connect(api.addr).await.unwrap();
        let target = format!("{EVENTS_PATH}?topics=block");
        let mut slow = SseClient::over(stream, &target).await;
        assert_eq!(slow.status, StatusCode::OK);
        for i in 0..EVENTS {
            api.fake.push(block(i + 1, GLOAS_SLOT + i, None));
            let event = fast.next().await.expect("the reading client stays open");
            assert_eq!(key(&event), ("block".into(), GLOAS_SLOT + i));
        }
        let mut got = Vec::new();
        while let Some(event) = slow.next().await {
            got.push(key(&event).1 - GLOAS_SLOT);
        }
        assert!(!got.is_empty(), "nothing reached the slow client");
        assert!(
            (got.len() as u64) < EVENTS - QUEUE as u64,
            "the slow client got {} of {EVENTS}",
            got.len()
        );
        assert_eq!(got, (0..got.len() as u64).collect::<Vec<_>>());
        // The others go on, on the same subscription.
        api.fake.push(block(EVENTS + 1, GLOAS_SLOT + EVENTS, None));
        assert_eq!(key(&fast.next().await.unwrap()).1, GLOAS_SLOT + EVENTS);
        let mut late = api.client("topics=block").await;
        api.fake
            .push(block(EVENTS + 2, GLOAS_SLOT + EVENTS + 1, None));
        assert_eq!(key(&late.next().await.unwrap()).1, GLOAS_SLOT + EVENTS + 1);
        assert_eq!(api.fake.subscribes(), 1);
    }

    /// Shutdown ends every open stream, so the server's drain does not wait on them.
    #[tokio::test]
    async fn shutdown_ends_open_streams() {
        let api = Api::start(CLIENT_QUEUE_EVENTS, local().await).await;
        let mut clients = Vec::new();
        for query in [ALL, "topics=head", "topics=chain_reorg"] {
            clients.push(api.client(query).await);
        }
        api.fake.push(head(1, GLOAS_SLOT, "empty"));
        assert_eq!(names(&clients[0].take(2).await), ["head", "head_v2"]);
        assert_eq!(names(&clients[1].take(1).await), ["head"]);
        let start = Instant::now();
        api.stop.send_replace(true);
        for client in &mut clients {
            assert_eq!(client.next().await, None);
        }
        tokio::time::timeout(WITHIN, api.server)
            .await
            .expect("serve returns")
            .unwrap();
        tokio::time::timeout(WITHIN, api.follower)
            .await
            .expect("the hub stops")
            .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{:?}",
            start.elapsed()
        );
        assert!(!api.hub.is_live());
    }

    /// cl-chain's stream ends: every open stream ends with it (nothing is replayed), new ones
    /// answer 503 until the hub has subscribed again, then are served.
    #[tokio::test]
    async fn upstream_loss_ends_streams() {
        let api = Api::start(CLIENT_QUEUE_EVENTS, local().await).await;
        let mut client = api.client(ALL).await;
        api.fake.push(block(1, GLOAS_SLOT, None));
        assert_eq!(names(&client.take(1).await), ["block"]);
        api.fake.end_streams();
        assert_eq!(client.next().await, None);
        let start = Instant::now();
        let mut refused = 0;
        let mut again = loop {
            let target = format!("{EVENTS_PATH}?{ALL}");
            let client = SseClient::connect(api.addr, &target).await;
            if client.status == StatusCode::OK {
                break client;
            }
            let (status, headers) = (client.status, client.headers.clone());
            assert_error(status, &headers, &client.bytes().await, 503, "");
            refused += 1;
            assert!(start.elapsed() < WITHIN, "the hub never subscribed again");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(refused > 0);
        assert!(
            start.elapsed() >= UPSTREAM_RETRY / 2,
            "{:?}",
            start.elapsed()
        );
        assert_eq!(api.fake.subscribes(), 2);
        api.fake.push(block(2, GLOAS_SLOT + 1, None));
        assert_eq!(
            key(&again.take(1).await[0]),
            ("block".into(), GLOAS_SLOT + 1)
        );
    }

    /// Frames are checked: data that does not parse drops that event, a kind this server does
    /// not stream is skipped, and a `seq` that does not rise or `EVENT_KIND_UNSPECIFIED` breaks
    /// the contract, which ends the subscription and every stream.
    #[tokio::test]
    async fn upstream_frames_checked() {
        let api = Api::start(CLIENT_QUEUE_EVENTS, local().await).await;
        let mut client = api.client(ALL).await;
        let mut bad = block(1, GLOAS_SLOT, None);
        bad.data_json = b"{\"slot\": 1}".to_vec();
        api.fake.push(bad);
        let mut later = block(2, GLOAS_SLOT, None);
        later.kind = EventKind::ExecutionPayload as i32;
        api.fake.push(later);
        api.fake.push(block(3, GLOAS_SLOT + 3, None));
        assert_eq!(
            key(&client.take(1).await[0]),
            ("block".into(), GLOAS_SLOT + 3)
        );
        api.fake.push(block(3, GLOAS_SLOT + 4, None));
        assert_eq!(client.next().await, None);
        api.until_live().await;
        let mut client = api.client(ALL).await;
        let mut unspecified = block(10, GLOAS_SLOT, None);
        unspecified.kind = EventKind::Unspecified as i32;
        api.fake.push(unspecified);
        assert_eq!(client.next().await, None);
        assert_eq!(api.fake.subscribes(), 2);
    }
}
