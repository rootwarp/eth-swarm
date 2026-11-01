//! `ethswarm.discv5.v1.DiscoveryService`, served to cl-p2p from the running discv5
//! ([`DiscoveryServer`]).
//!
//! - **`WatchPeers`**: our hello, then one `PeerCandidate` per record of the routing table that
//!   passes the filter now ([`PeerSource::table_records`]), then one per record that discv5
//!   reports from then on ([`PeerFeed`]). A watcher that falls behind the feed loses the oldest
//!   candidates (and the next lookup finds them again), so no watcher can hold discv5 back. The
//!   stream ends with `UNAVAILABLE` when cl-discv5 stops, so it does not hold the drain.
//! - **`FindPeers`**: our hello, then one `PeerCandidate` per peer that serves a wanted
//!   attestation subnet, sync-committee subnet or custody column ([`crate::subnet_query`]), at
//!   most the request's `target`, then the end of the stream. A malformed request is refused
//!   before any frame (`INVALID_ARGUMENT`; another fork digest `FAILED_PRECONDITION`); a failed
//!   lookup ends the stream with `UNAVAILABLE`.
//! - **`GetLocalEnr`**: the local record as it is now, in its `enr:` text form.
//! - `UpdateEnr` is still a stub (contract checks, then `UNIMPLEMENTED`).
//!
//! A candidate ([`candidate`]) carries the record, its libp2p peer ID ([`peer_id_text`]: the
//! identity multihash of the protobuf-encoded secp256k1 key, base58btc, as libp2p prints it),
//! its `/ip4|ip6/<addr>/tcp/<port>` addresses, its `cgc` and its `nfd`. A record without a TCP
//! address cannot be dialled and is not sent.

use crate::enr::{CombinedPublicKey, Enr, EnrFields, NodeId};
use crate::service::{Discovery, ServiceError};
use crate::subnet_query::{Finder, SlotClock, SubnetQuery, MAX_TARGET};
use ethswarm_proto::discv5 as pb;
use ipc::frame::OutFrame;
use ipc::hello::stream_hello;
use ipc::stub::StubStream;
use ipc::Link;
use p2p_wire::rpc::messages::ForkDigest;
use pb::discovery_service_server::{DiscoveryService, DiscoveryServiceServer};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

/// The candidates the feed holds for a slow watcher at most \[est\]: a few lookups' worth.
pub const FEED_CAPACITY: usize = 256;

/// What the server reads from discv5.
pub trait PeerSource: Send + Sync + 'static {
    /// The local record now.
    fn local_enr(&self) -> Enr;
    /// The routing table's records that pass the filter now.
    fn table_records(&self) -> Vec<Enr>;
    /// Our fork digest now.
    fn fork_digest(&self) -> ForkDigest;
    /// A lookup for at most `max` records that pass the IP rules, have our exact `eth2` fork
    /// digest and that `query` matches.
    fn find_matching(
        &self,
        query: SubnetQuery,
        max: usize,
    ) -> impl Future<Output = Result<Vec<Enr>, ServiceError>> + Send;
}

impl PeerSource for Discovery {
    fn local_enr(&self) -> Enr {
        Discovery::local_enr(self)
    }

    fn table_records(&self) -> Vec<Enr> {
        Discovery::table_records(self)
    }

    fn fork_digest(&self) -> ForkDigest {
        Discovery::fork_digest(self)
    }

    /// Towards a random node ID, as the periodic lookups.
    async fn find_matching(
        &self,
        query: SubnetQuery,
        max: usize,
    ) -> Result<Vec<Enr>, ServiceError> {
        let wanted = move |enr: &Enr| query.matches(enr);
        self.find_peers_matching(NodeId::random(), wanted, max)
            .await
    }
}

/// The records discv5 reports, to every watcher.
#[derive(Debug, Clone)]
pub struct PeerFeed(broadcast::Sender<Enr>);

impl Default for PeerFeed {
    fn default() -> Self {
        Self(broadcast::channel(FEED_CAPACITY).0)
    }
}

impl PeerFeed {
    /// Hands `enr` to every watcher now; nothing waits for them.
    pub fn send(&self, enr: Enr) {
        let _ = self.0.send(enr);
    }

    fn subscribe(&self) -> broadcast::Receiver<Enr> {
        self.0.subscribe()
    }
}

/// The libp2p peer ID of a secp256k1 record, as libp2p prints it; `None` for another key type.
#[must_use]
pub fn peer_id_text(enr: &Enr) -> Option<String> {
    use enr::EnrPublicKey as _;
    let CombinedPublicKey::Secp256k1(_) = enr.public_key() else {
        return None;
    };
    let raw = enr.public_key().encode();
    let compressed: &[u8] = raw.as_ref();
    // libp2p's protobuf PublicKey { Type = Secp256k1 (2), Data = the 33-byte point }.
    let mut key = vec![0x08, 0x02, 0x12, u8::try_from(compressed.len()).ok()?];
    key.extend_from_slice(compressed);
    // The identity multihash (code 0x00), as for every key of at most 42 bytes.
    let mut multihash = vec![0x00, u8::try_from(key.len()).ok()?];
    multihash.extend_from_slice(&key);
    Some(base58btc(&multihash))
}

/// The Bitcoin base58 alphabet.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// `bytes` in base58btc.
fn base58btc(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    // Little-endian base58 digits.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .map(|&d| char::from(BASE58[usize::from(d)])),
    );
    out
}

/// The candidate of `enr` (see the module docs); `None` without a secp256k1 key or a TCP
/// address.
#[must_use]
pub fn candidate(enr: &Enr) -> Option<pb::PeerCandidate> {
    let peer_id = peer_id_text(enr)?;
    let mut multiaddrs = Vec::new();
    if let (Some(ip), Some(port)) = (enr.ip4(), enr.tcp4()) {
        multiaddrs.push(format!("/ip4/{ip}/tcp/{port}"));
    }
    if let (Some(ip), Some(port)) = (enr.ip6(), enr.tcp6()) {
        multiaddrs.push(format!("/ip6/{ip}/tcp/{port}"));
    }
    if multiaddrs.is_empty() {
        return None;
    }
    let fields = EnrFields::read(enr).ok();
    Some(pb::PeerCandidate {
        enr: Some(pb::Enr {
            text: enr.to_base64(),
        }),
        peer_id,
        multiaddrs,
        custody_group_count: fields.as_ref().and_then(|f| f.cgc).unwrap_or(0),
        next_fork_digest: fields
            .and_then(|f| f.nfd)
            .map(|d| d.to_vec())
            .unwrap_or_default(),
    })
}

/// `DiscoveryService` over a [`PeerSource`] and its [`PeerFeed`] (see the module docs).
pub struct DiscoveryServer<S> {
    link: Link,
    source: Arc<S>,
    feed: PeerFeed,
    stop: watch::Receiver<bool>,
    finder: Arc<Finder>,
}

impl<S> Clone for DiscoveryServer<S> {
    fn clone(&self) -> Self {
        Self {
            link: self.link.clone(),
            source: Arc::clone(&self.source),
            feed: self.feed.clone(),
            stop: self.stop.clone(),
            finder: Arc::clone(&self.finder),
        }
    }
}

impl<S: PeerSource> DiscoveryServer<S> {
    /// A server of `source` and `feed`, holding every stream to `link`; its streams end when
    /// `stop` turns true or its sender goes. `FindPeers` caches by the slot `slots` reads.
    #[must_use]
    pub fn new(
        link: Link,
        source: Arc<S>,
        feed: PeerFeed,
        stop: watch::Receiver<bool>,
        slots: SlotClock,
    ) -> Self {
        Self {
            link,
            source,
            feed,
            stop,
            finder: Arc::new(Finder::new(slots)),
        }
    }

    /// The tonic service.
    #[must_use]
    pub fn into_service(self) -> DiscoveryServiceServer<Self> {
        DiscoveryServiceServer::new(self)
    }
}

/// The status a `WatchPeers` or `FindPeers` stream ends with when cl-discv5 stops.
fn stopping() -> Status {
    Status::unavailable("cl-discv5 is stopping")
}

/// The deadline of a call: its `grpc-timeout` (gRPC over HTTP/2: 1 to 8 digits, then `H`, `M`,
/// `S`, `m`, `u` or `n`) from now; none without one or for one that does not parse, as tonic's
/// server reads it.
fn deadline(metadata: &MetadataMap) -> Option<Instant> {
    let text = metadata.get("grpc-timeout")?.to_str().ok()?;
    let (digits, unit) = text.split_at(text.len().checked_sub(1)?);
    if !(1..=8).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    let timeout = match unit {
        "H" => Duration::from_secs(n * 3600),
        "M" => Duration::from_secs(n * 60),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return None,
    };
    Instant::now().checked_add(timeout)
}

/// Until `stop` turns true or its sender goes.
async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

#[tonic::async_trait]
impl<S: PeerSource> DiscoveryService for DiscoveryServer<S> {
    type WatchPeersStream = StubStream<pb::WatchPeersResponse>;

    async fn watch_peers(
        &self,
        request: Request<pb::WatchPeersRequest>,
    ) -> Result<Response<Self::WatchPeersStream>, Status> {
        self.link
            .accept_hello_field(request.get_ref().hello.as_ref())
            .map_err(|e| e.to_status())?;
        let (_, ours) = stream_hello(&self.link.local()).map_err(|e| e.to_status())?;
        // Subscribed before the snapshot, so no record falls between the two.
        let mut feed = self.feed.subscribe();
        let table = self.source.table_records();
        let mut stop = self.stop.clone();
        let (tx, rx) = mpsc::channel(16);
        ipc::spawn_in_span(async move {
            let body =
                |c| pb::WatchPeersResponse::body(pb::WatchPeersResponseBody { candidate: Some(c) });
            if tx
                .send(Ok(pb::WatchPeersResponse::hello(ours)))
                .await
                .is_err()
            {
                return;
            }
            for c in table.iter().filter_map(candidate) {
                if tx.send(Ok(body(c))).await.is_err() {
                    return;
                }
            }
            loop {
                if *stop.borrow_and_update() {
                    let _ = tx.send(Err(stopping())).await;
                    return;
                }
                tokio::select! {
                    next = feed.recv() => match next {
                        Ok(enr) => {
                            if let Some(c) = candidate(&enr) {
                                if tx.send(Ok(body(c))).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(lost)) => {
                            tracing::debug!(lost, "a slow peer watcher lost candidates");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let _ = tx.send(Err(stopping())).await;
                            return;
                        }
                    },
                    changed = stop.changed() => if changed.is_err() {
                        let _ = tx.send(Err(stopping())).await;
                        return;
                    },
                    () = tx.closed() => return,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type FindPeersStream = StubStream<pb::FindPeersResponse>;

    async fn find_peers(
        &self,
        request: Request<pb::FindPeersRequest>,
    ) -> Result<Response<Self::FindPeersStream>, Status> {
        let deadline = deadline(request.metadata());
        let request = request.into_inner();
        self.link
            .accept_hello_field(request.hello.as_ref())
            .map_err(|e| e.to_status())?;
        let digest = self.source.fork_digest();
        let (query, target) = SubnetQuery::parse(&request, digest)?;
        let (_, ours) = stream_hello(&self.link.local()).map_err(|e| e.to_status())?;
        let (source, finder) = (Arc::clone(&self.source), Arc::clone(&self.finder));
        let stop = self.stop.clone();
        let (tx, rx) = mpsc::channel(16);
        // The wait for a lookup runs after our hello, in the stream: tonic's own `grpc-timeout`
        // covers the handler only, and would end the call `CANCELLED`.
        ipc::spawn_in_span(async move {
            if tx
                .send(Ok(pb::FindPeersResponse::hello(ours)))
                .await
                .is_err()
            {
                return;
            }
            let lookup = || async move { source.find_matching(query, MAX_TARGET).await };
            let found = tokio::select! {
                biased;
                () = stopped(stop) => Err(stopping()),
                found = finder.find(query, digest, deadline, lookup) => found.map_err(Status::from),
                () = tx.closed() => return,
            };
            match found {
                Ok(found) => {
                    for c in found.iter().filter_map(candidate).take(target) {
                        let body = pb::FindPeersResponseBody { candidate: Some(c) };
                        if tx
                            .send(Ok(pb::FindPeersResponse::body(body)))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
                Err(status) => {
                    let _ = tx.send(Err(status)).await;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn update_enr(
        &self,
        _: Request<pb::UpdateEnrRequest>,
    ) -> Result<Response<pb::UpdateEnrResponse>, Status> {
        ipc::stub::unary(&self.link, "update_enr", &[])
    }

    async fn get_local_enr(
        &self,
        _: Request<pb::GetLocalEnrRequest>,
    ) -> Result<Response<pb::GetLocalEnrResponse>, Status> {
        self.link.check_unary(&[]).map_err(|e| e.to_status())?;
        Ok(Response::new(pb::GetLocalEnrResponse {
            enr: Some(pb::Enr {
                text: self.source.local_enr().to_base64(),
            }),
        }))
    }
}

#[cfg(test)]
mod tests;
