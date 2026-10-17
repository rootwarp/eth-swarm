//! Outbound requests on a running swarm: the dialer's side of each exchange.
//!
//! [`status`] sends our Status v2 on `/eth2/beacon_chain/req/status/2/ssz_snappy` and returns
//! the peer's, once it passed the handshake check of `phase0/p2p-interface.md` "Status"
//! (L1414–1455): a peer whose `fork_digest` differs from ours is on another network or fork,
//! and the exchange fails ([`OutboundError::ForkDigestMismatch`], which carries the peer's
//! Status for the log). `fulu/p2p-interface.md` L538–571 defines Status v2 (the added
//! `earliest_available_slot`); judging the other fields is the caller's business.

use crate::rpc::codec::RpcCodec;
use consensus_types::EthSpec;
use futures::StreamExt;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{PeerId, Swarm};
use p2p_wire::rpc::messages::{ForkDigest, StatusV2};
use p2p_wire::rpc::protocols::{Request, Response, ResponseChunk, ResultCode};

/// One event of an outbound `request_response` behaviour.
pub type RpcEvent<E> = request_response::Event<Request, Vec<ResponseChunk<E>>>;

/// A behaviour with a Status v2 `request_response` behaviour inside.
pub trait StatusRpc<E: EthSpec>: NetworkBehaviour {
    /// The Status v2 behaviour.
    fn status_rpc(&mut self) -> &mut request_response::Behaviour<RpcCodec<E>>;

    /// The Status behaviour's event inside `event`, or `None` for another behaviour's.
    fn status_event(event: Self::ToSwarm) -> Option<RpcEvent<E>>;
}

/// Why an outbound exchange failed.
#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    /// The peer's Status names another fork digest: the handshake fails.
    #[error(
        "fork digest mismatch: ours 0x{}, the peer's 0x{}",
        hex(.ours),
        hex(&.peer.fork_digest)
    )]
    ForkDigestMismatch {
        /// Our digest.
        ours: ForkDigest,
        /// The peer's whole Status.
        peer: Box<StatusV2>,
    },
    /// The peer answered with an error chunk.
    #[error("error response {code:?}: {message}")]
    ErrorResponse {
        /// The result code.
        code: ResultCode,
        /// The peer's message, lossily UTF-8.
        message: String,
    },
    /// The response was not one Status chunk.
    #[error("unexpected response: {0}")]
    UnexpectedResponse(String),
    /// `request_response` reported the request failed (dial, timeout, stream, codec).
    #[error("request failed: {0}")]
    Failure(String),
    /// The last connection to the peer closed before a response.
    #[error("the peer disconnected before responding")]
    Disconnected,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `error` and every `source()` under it, `: `-separated.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut next = error.source();
    while let Some(e) = next {
        out.push_str(": ");
        out.push_str(&e.to_string());
        next = e.source();
    }
    out
}

/// Sends `ours` to `peer` and drives `swarm` until the peer's Status arrives or the exchange
/// fails. The peer's Status is returned only if its `fork_digest` equals ours.
///
/// Events of other behaviours that arrive meanwhile are dropped (logged at debug).
pub async fn status<E, B>(
    swarm: &mut Swarm<B>,
    peer: PeerId,
    ours: &StatusV2,
) -> Result<StatusV2, OutboundError>
where
    E: EthSpec,
    B: StatusRpc<E>,
{
    let id = swarm
        .behaviour_mut()
        .status_rpc()
        .send_request(&peer, Request::Status(ours.clone()));
    let chunks = wait_for_response::<E, B>(swarm, id).await?;
    let theirs = single_status(chunks)?;
    if theirs.fork_digest != ours.fork_digest {
        return Err(OutboundError::ForkDigestMismatch {
            ours: ours.fork_digest,
            peer: Box::new(theirs),
        });
    }
    Ok(theirs)
}

/// Drives `swarm` until request `id` has a response or fails. A closed connection is not
/// judged here: `request_response` fails every request still pending on it
/// (`OutboundFailure::ConnectionClosed`), and a response that arrived first is delivered first.
async fn wait_for_response<E, B>(
    swarm: &mut Swarm<B>,
    id: OutboundRequestId,
) -> Result<Vec<ResponseChunk<E>>, OutboundError>
where
    E: EthSpec,
    B: StatusRpc<E>,
{
    loop {
        match swarm.select_next_some().await {
            SwarmEvent::Behaviour(event) => match B::status_event(event) {
                Some(request_response::Event::Message {
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                }) if request_id == id => return Ok(response),
                Some(request_response::Event::OutboundFailure {
                    request_id, error, ..
                }) if request_id == id => {
                    return Err(match error {
                        request_response::OutboundFailure::ConnectionClosed => {
                            OutboundError::Disconnected
                        }
                        error => OutboundError::Failure(error_chain(&error)),
                    });
                }
                Some(other) => tracing::debug!(event = ?other, "status behaviour event"),
                None => tracing::debug!("another behaviour's event"),
            },
            _ => tracing::trace!("swarm event while waiting for a response"),
        }
    }
}

/// The one Status chunk of a Status response.
fn single_status<E: EthSpec>(mut chunks: Vec<ResponseChunk<E>>) -> Result<StatusV2, OutboundError> {
    if chunks.len() != 1 {
        return Err(OutboundError::UnexpectedResponse(format!(
            "{} chunks",
            chunks.len()
        )));
    }
    match chunks.remove(0) {
        ResponseChunk::Success(Response::Status(s)) => Ok(s),
        ResponseChunk::Success(other) => {
            Err(OutboundError::UnexpectedResponse(format!("{other:?}")))
        }
        ResponseChunk::Error { code, message } => Err(OutboundError::ErrorResponse {
            code,
            message: String::from_utf8_lossy(&message).into_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m2a_session::{NodeKey, Session, Transport};
    use crate::rpc::codec::Deadlines;
    use crate::testkit::{StatusPeer, StatusReply};
    use consensus_types::primitives::B256;
    use consensus_types::Minimal;
    use p2p_wire::rpc::codec::ContextTable;
    use p2p_wire::rpc::messages::Ping;
    use std::sync::Arc;

    type E = Minimal;

    const OURS: ForkDigest = [0x66, 0x9e, 0x6c, 0x11];

    fn ours() -> StatusV2 {
        StatusV2 {
            fork_digest: OURS,
            finalized_root: B256::repeat_byte(1),
            finalized_epoch: 10,
            head_root: B256::repeat_byte(2),
            head_slot: 320,
            earliest_available_slot: 320,
        }
    }

    async fn connected(peer: &StatusPeer) -> Session<E> {
        let mut session = Session::<E>::start(
            NodeKey::ephemeral(),
            peer.pinned(),
            Arc::new(ContextTable::new()),
            Deadlines::default(),
            Transport::Tcp,
        )
        .unwrap();
        session.connect().await.unwrap();
        session
    }

    #[tokio::test]
    async fn status_digest_match_returns_the_peers_status() {
        let theirs = StatusV2 {
            head_slot: 999,
            earliest_available_slot: 7,
            ..ours()
        };
        let peer = StatusPeer::echoing(theirs.clone()).await;
        let mut session = connected(&peer).await;
        let got = status(session.swarm(), peer.id, &ours()).await.unwrap();
        assert_eq!(got, theirs);
        assert_eq!(
            peer.requests(),
            vec![ours()],
            "the peer received our Status"
        );
    }

    #[tokio::test]
    async fn status_digest_mismatch_fails() {
        let foreign = StatusV2 {
            fork_digest: [0xde, 0xad, 0xbe, 0xef],
            ..ours()
        };
        let reply = foreign.clone();
        let peer = StatusPeer::spawn(
            Box::new(move |_, _| StatusReply::Status(reply.clone())),
            None,
        )
        .await;
        let mut session = connected(&peer).await;
        let err = status(session.swarm(), peer.id, &ours()).await.unwrap_err();
        match &err {
            OutboundError::ForkDigestMismatch { ours: o, peer: p } => {
                assert_eq!(*o, OURS);
                assert_eq!(**p, foreign);
            }
            other => panic!("{other}"),
        }
        assert!(err.to_string().contains("deadbeef"), "{err}");
        assert!(err.to_string().contains("669e6c11"), "{err}");
    }

    #[tokio::test]
    async fn error_chunk_fails() {
        let peer = StatusPeer::spawn(
            Box::new(|_, _| StatusReply::Error(ResultCode::ServerError, b"busy".to_vec())),
            None,
        )
        .await;
        let mut session = connected(&peer).await;
        let err = status(session.swarm(), peer.id, &ours()).await.unwrap_err();
        assert!(
            matches!(&err, OutboundError::ErrorResponse { code: ResultCode::ServerError, message } if message == "busy"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_peer_without_status_fails_the_request() {
        // Not connected at all: request_response dials, and the allow list has no address.
        let peer = StatusPeer::echoing(ours()).await;
        let mut session = connected(&peer).await;
        let stranger = PeerId::random();
        let err = status(session.swarm(), stranger, &ours())
            .await
            .unwrap_err();
        assert!(matches!(err, OutboundError::Failure(_)), "{err}");
    }

    #[tokio::test]
    async fn a_connection_closed_under_the_request_is_disconnected() {
        let peer = StatusPeer::echoing(ours()).await;
        let mut session = connected(&peer).await;
        let id = session
            .swarm()
            .behaviour_mut()
            .status
            .send_request(&peer.id, Request::Status(ours()));
        session.swarm().disconnect_peer_id(peer.id).unwrap();
        let err = wait_for_response::<E, _>(session.swarm(), id)
            .await
            .unwrap_err();
        assert!(matches!(err, OutboundError::Disconnected), "{err}");
    }

    #[test]
    fn single_status_refuses_other_shapes() {
        let none: Vec<ResponseChunk<E>> = vec![];
        assert!(matches!(
            single_status(none),
            Err(OutboundError::UnexpectedResponse(_))
        ));
        let ping = vec![ResponseChunk::<E>::Success(Response::Ping(Ping(1)))];
        assert!(matches!(
            single_status(ping),
            Err(OutboundError::UnexpectedResponse(_))
        ));
        let two = vec![
            ResponseChunk::<E>::Success(Response::Status(ours())),
            ResponseChunk::<E>::Success(Response::Status(ours())),
        ];
        assert!(matches!(
            single_status(two),
            Err(OutboundError::UnexpectedResponse(_))
        ));
    }

    #[test]
    fn error_chain_joins_sources() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer")]
        struct Outer(#[source] std::io::Error);
        assert_eq!(
            error_chain(&Outer(std::io::Error::other("cause"))),
            "outer: cause"
        );
    }
}
