//! Test fixtures (feature `testkit`): a loopback libp2p peer that answers Status v2.
//!
//! [`StatusPeer`] listens on an ephemeral 127.0.0.1 TCP port with TCP + Noise + yamux, serves
//! only `/eth2/beacon_chain/req/status/2/ssz_snappy` (inbound), and answers each Status request
//! with whatever its responder returns. Nothing here leaves the host.

use crate::m2a_session::PinnedPeer;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::identity::Keypair;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
use p2p_wire::rpc::codec::{decode_request, encode_error_chunk, encode_success_chunk};
use p2p_wire::rpc::messages::StatusV2;
use p2p_wire::rpc::protocols::{Protocol, Request, ResultCode};
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// What the peer answers one Status request with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReply {
    /// A success chunk with this Status.
    Status(StatusV2),
    /// An error chunk.
    Error(ResultCode, Vec<u8>),
}

/// Answers the `n`th (0-based) Status request, given the request.
pub type Responder = Box<dyn Fn(&StatusV2, usize) -> StatusReply + Send + Sync>;

/// The responder side of the Status protocol, for the fixture only.
#[derive(Clone, Default)]
struct ResponderCodec;

/// How long after its last answer a disconnecting peer closes the connection.
const DISCONNECT_DELAY: Duration = Duration::from_millis(100);

/// The largest request chunk read: a Status v2 is 84 bytes, framed well under this.
const MAX_REQUEST_BYTES: u64 = 1024;

impl request_response::Codec for ResponderCodec {
    type Protocol = Protocol;
    type Request = StatusV2;
    type Response = StatusReply;

    async fn read_request<T>(&mut self, protocol: &Protocol, io: &mut T) -> io::Result<StatusV2>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buf = Vec::new();
        io.take(MAX_REQUEST_BYTES).read_to_end(&mut buf).await?;
        match decode_request(*protocol, &buf) {
            Ok(Request::Status(s)) => Ok(s),
            Ok(other) => Err(io::Error::other(format!("not a Status: {other:?}"))),
            Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }

    async fn read_response<T>(&mut self, _: &Protocol, _: &mut T) -> io::Result<StatusReply>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn write_request<T>(&mut self, _: &Protocol, _: &mut T, _: StatusV2) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::ErrorKind::Unsupported.into())
    }

    async fn write_response<T>(
        &mut self,
        _: &Protocol,
        io: &mut T,
        reply: StatusReply,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = match reply {
            StatusReply::Status(s) => {
                let ssz = Request::Status(s).ssz_body().unwrap_or_default();
                encode_success_chunk(None, &ssz)
            }
            StatusReply::Error(code, message) => encode_error_chunk(code, &message),
        }
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        io.write_all(&bytes).await?;
        io.flush().await
    }
}

/// A loopback peer that answers Status v2.
pub struct StatusPeer {
    /// Its peer ID.
    pub id: PeerId,
    /// `/ip4/127.0.0.1/tcp/<port>`, without `/p2p/`.
    pub addr: Multiaddr,
    requests: Arc<Mutex<Vec<StatusV2>>>,
    connections: Arc<AtomicU32>,
}

impl StatusPeer {
    /// Starts the peer. After answering `disconnect_after` requests (if given), it closes every
    /// connection to the requester shortly after (100 ms).
    pub async fn spawn(respond: Responder, disconnect_after: Option<usize>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicU32::new(0));
        let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("tcp transport")
            .with_behaviour(|_| {
                request_response::Behaviour::with_codec(
                    ResponderCodec,
                    [(Protocol::StatusV2, ProtocolSupport::Inbound)],
                    request_response::Config::default(),
                )
            })
            .expect("behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let id = *swarm.local_peer_id();
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .expect("listen");
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        let seen = Arc::clone(&requests);
        let established = Arc::clone(&connections);
        tokio::spawn(async move {
            let mut answered = 0usize;
            // The requester to drop, and when: a moment after the answer, so the answer is
            // read before the connection goes.
            let mut drop_at: Option<(tokio::time::Instant, PeerId)> = None;
            loop {
                let event = match drop_at {
                    Some((at, peer)) => tokio::select! {
                        event = swarm.select_next_some() => event,
                        () = tokio::time::sleep_until(at) => {
                            let _ = swarm.disconnect_peer_id(peer);
                            drop_at = None;
                            continue;
                        }
                    },
                    None => swarm.select_next_some().await,
                };
                match event {
                    SwarmEvent::ConnectionEstablished { .. } => {
                        established.fetch_add(1, Ordering::SeqCst);
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    }) => {
                        let n = {
                            let mut seen = seen.lock().expect("not poisoned");
                            seen.push(request.clone());
                            seen.len() - 1
                        };
                        let reply = respond(&request, n);
                        let _ = swarm.behaviour_mut().send_response(channel, reply);
                    }
                    SwarmEvent::Behaviour(request_response::Event::ResponseSent {
                        peer, ..
                    }) => {
                        answered += 1;
                        if disconnect_after == Some(answered) {
                            drop_at = Some((tokio::time::Instant::now() + DISCONNECT_DELAY, peer));
                        }
                    }
                    _ => {}
                }
            }
        });
        Self {
            id,
            addr,
            requests,
            connections,
        }
    }

    /// A peer that echoes the requester's fork digest in a fixed Status otherwise.
    pub async fn echoing(status: StatusV2) -> Self {
        Self::spawn(
            Box::new(move |req, _| {
                StatusReply::Status(StatusV2 {
                    fork_digest: req.fork_digest,
                    ..status.clone()
                })
            }),
            None,
        )
        .await
    }

    /// The peer pinned at its address.
    pub fn pinned(&self) -> PinnedPeer {
        PinnedPeer {
            peer_id: self.id,
            addr: self.addr.clone(),
        }
    }

    /// Every Status request received, in order.
    pub fn requests(&self) -> Vec<StatusV2> {
        self.requests.lock().expect("not poisoned").clone()
    }

    /// Connections ever established to the peer.
    pub fn connections(&self) -> u32 {
        self.connections.load(Ordering::SeqCst)
    }
}
