//! `connect`: dial each reference CL's TCP address with the probe swarm and confirm Noise and
//! the muxer negotiated, naming the muxer.
//!
//! One swarm per peer, no listener, dropped once its dial ended: a dial that timed out cannot
//! complete during the next peer's, so the muxer a swarm reports is its own peer's. The dial
//! names the peer ID (`DialOpts::peer_id`), so an established connection means TCP connected,
//! Noise XX proved that identity, and multistream-select confirmed a muxer (two are offered,
//! yamux first, so the lazy negotiation of a single protocol does not apply).
//!
//! The criterion is yamux, and a connection on yamux passes. A connection on mplex passes only
//! as a recorded deviation, labelled `peer offers no yamux: recorded deviation` in its PASS
//! line, and only when our dial proposed yamux before mplex ([`our_offer`], cl-p2p's
//! [`muxers`]): as dialer we propose the muxers one at a time, in order, and the peer either
//! accepts a proposal or refuses it (`na`). A yamux-capable peer accepts our first proposal and
//! negotiates yamux, so mplex on our dial means the peer refused yamux: it offers none (a TCP
//! client MUST support mplex and MAY support yamux, so it is within the spec, short of the
//! criterion). mplex without yamux proposed before it, or any other muxer, fails.
//!
//! The swarm carries no gossipsub: the verdict is given when the connection is established,
//! before anything runs over it.

use super::devnet::Devnet;
use super::report::Check;
use super::swarm::{error_chain, probe_swarm, SwarmPlan};
use cl_p2p::behaviour::SpecBehaviour;
use cl_p2p::m2a_session::PinnedPeer;
use cl_p2p::rpc::inbound::SharedStatus;
use cl_p2p::transport::{
    muxers, DialFailure, Direction, MuxerBudget, MuxerObserver, TransportMetrics,
};
use consensus_types::EthSpec;
use futures::StreamExt;
use libp2p::core::upgrade::UpgradeInfo;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::SwarmEvent;
use libp2p::Swarm;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The check's name.
pub const NAME: &str = "connect";
/// The muxer the criterion asks for.
pub const YAMUX: &str = "/yamux/1.0.0";
/// The muxer a peer without yamux negotiates.
pub const MPLEX: &str = "/mplex/6.7.0";
/// The label of a connection on mplex to a peer that refused our yamux proposal.
pub const MPLEX_DEVIATION: &str = "peer offers no yamux: recorded deviation";
/// How long each dial may take by default \[est\].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// What `connect` dials.
#[derive(Debug, Clone)]
pub struct ConnectPlan {
    /// The reference CLs, each at its TCP address.
    pub peers: Vec<PinnedPeer>,
    /// How long each dial may take.
    pub timeout: Duration,
}

/// The muxers the swarm negotiated as dialer, in order.
type Heard = Arc<Mutex<Vec<String>>>;

/// Dials every peer of `plan` in turn: one line per peer.
pub async fn connect<E: EthSpec>(devnet: &Devnet, plan: &ConnectPlan) -> Check {
    let mut check = Check::new(NAME);
    let offer = our_offer();
    for peer in &plan.peers {
        let (outcome, muxer) = match dial_alone::<E>(devnet, peer, plan.timeout).await {
            Ok(dialled) => dialled,
            Err(e) => {
                check.fail(format!("peer {}: probe swarm: {e}", peer.peer_id));
                continue;
            }
        };
        let at = format!("peer {} at {}", peer.peer_id, peer.addr);
        match (outcome, muxer) {
            (Ok(()), Some(muxer)) => match judge_muxer(&offer, &muxer) {
                Ok(None) => {
                    tracing::info!(peer = %peer.peer_id, addr = %peer.addr, %muxer, "connected: Noise XX and yamux");
                    check.pass(format!(
                        "{at}: TCP connected, Noise XX proved the peer ID, muxer={muxer}"
                    ));
                }
                Ok(Some(deviation)) => {
                    tracing::warn!(peer = %peer.peer_id, addr = %peer.addr, %muxer, "connected on mplex: the peer refused our yamux proposal");
                    check.pass(format!(
                        "{at}: TCP connected, Noise XX proved the peer ID, muxer={muxer} \
                         ({deviation})"
                    ));
                }
                Err(why) => {
                    tracing::warn!(peer = %peer.peer_id, addr = %peer.addr, %muxer, "connected on another muxer than yamux");
                    check.fail(format!("{at}: Noise XX proved the peer ID, but {why}"));
                }
            },
            (Ok(()), None) => check.fail(format!("{at}: connected, but no muxer was reported")),
            (Err(why), _) => {
                tracing::warn!(peer = %peer.peer_id, addr = %peer.addr, %why, "dial failed");
                check.fail(format!("{at}: {why}"));
            }
        }
    }
    check
}

/// The muxer protocols our dial proposes, in order: those of cl-p2p's [`muxers`], the pair the
/// probe swarm is built with, yamux first. The budget and its metrics are thrown away.
#[must_use]
pub fn our_offer() -> Vec<String> {
    let mut registry = prometheus_client::registry::Registry::default();
    let (yamux, mplex) = muxers(MuxerBudget::with_defaults(&TransportMetrics::register(
        &mut registry,
    )));
    let yamux = yamux().protocol_info().map(str::to_owned);
    yamux
        .chain(mplex().protocol_info().map(str::to_owned))
        .collect()
}

/// The verdict on `muxer`, negotiated on our dial with the proposals `offer`: yamux passes
/// (`Ok(None)`); mplex passes as the recorded deviation (`Ok(Some(label))`) when yamux was
/// proposed before it, so the peer refused yamux; anything else is the failure's reason.
fn judge_muxer(offer: &[String], muxer: &str) -> Result<Option<&'static str>, String> {
    if muxer == YAMUX {
        return Ok(None);
    }
    let not_yamux = format!("the muxer is {muxer}, not {YAMUX}");
    if muxer != MPLEX {
        return Err(not_yamux);
    }
    // Every proposal before the one negotiated was refused.
    if offer.iter().take_while(|p| *p != muxer).any(|p| p == YAMUX) {
        Ok(Some(MPLEX_DEVIATION))
    } else {
        Err(format!(
            "{not_yamux}, and our dial never proposed {YAMUX} before it: the peer may offer yamux"
        ))
    }
}

/// Dials `peer` from a swarm of its own, which is dropped when this returns: a dial that timed
/// out cannot complete later, and the only muxer that swarm reports is that peer's. The dial's
/// outcome, and the muxer the swarm negotiated as dialer (the last, if it reported more).
async fn dial_alone<E: EthSpec>(
    devnet: &Devnet,
    peer: &PinnedPeer,
    timeout: Duration,
) -> Result<(Result<(), String>, Option<String>), String> {
    let heard = Heard::default();
    let record = Arc::clone(&heard);
    let observer = MuxerObserver::new(move |muxer, side| {
        if side == Direction::Outbound {
            record
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(muxer.to_owned());
        }
    });
    let swarm_plan = SwarmPlan {
        listen: Vec::new(),
        idle: timeout.max(Duration::from_secs(10)),
        bypass: vec![peer.peer_id],
        muxer_observer: Some(observer),
        ping_interval: cl_p2p::rpc::inbound::PING_INTERVAL,
        gossip: None,
    };
    let mut swarm = probe_swarm::<E>(devnet, Arc::new(SharedStatus::new(None)), swarm_plan)?;
    let outcome = dial(&mut swarm, peer, timeout).await;
    drop(swarm);
    let muxer = heard
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .last()
        .cloned();
    Ok((outcome, muxer))
}

/// Dials `peer` and drives the swarm until its connection is up, the dial failed, or `timeout`
/// passed.
async fn dial<E: EthSpec>(
    swarm: &mut Swarm<SpecBehaviour<E>>,
    peer: &PinnedPeer,
    timeout: Duration,
) -> Result<(), String> {
    let opts = DialOpts::peer_id(peer.peer_id)
        .addresses(vec![peer.addr.clone()])
        .build();
    swarm.dial(opts).map_err(|e| failure(&e))?;
    let wait = async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } if peer_id == peer.peer_id && endpoint.is_dialer() => return Ok(()),
                SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(p),
                    error,
                    ..
                } if p == peer.peer_id => return Err(failure(&error)),
                other => tracing::debug!(event = ?other, "swarm event"),
            }
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .unwrap_or_else(|_| Err(format!("no connection within {timeout:?}")))
}

/// A failed dial: its `p2p_dial_failures_total` reason, then the whole error.
fn failure(error: &libp2p::swarm::DialError) -> String {
    format!(
        "dial failed (reason={}): {}",
        DialFailure::of(error).as_str(),
        error_chain(error)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{closed_port_peer, devnet, mplex_only_peer, StandIn};
    use consensus_types::Minimal;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn yamux_and_a_refused_yamux_pass_and_every_other_outcome_fails() {
        let devnet = devnet();
        let cl = StandIn::spawn::<Minimal>(&devnet, None).await;
        let other = StandIn::spawn::<Minimal>(&devnet, None).await;
        let wrong_id = PinnedPeer {
            peer_id: libp2p::PeerId::random(),
            addr: other.addr.clone(),
        };
        let mplex = mplex_only_peer().await;
        let plan = ConnectPlan {
            peers: vec![cl.pinned(), wrong_id, closed_port_peer(), mplex.clone()],
            timeout: Duration::from_secs(10),
        };
        let check = connect::<Minimal>(&devnet, &plan).await;
        let lines = check.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].pass, "{lines:?}");
        assert!(lines[0].detail.contains("/yamux/1.0.0"), "{lines:?}");
        assert!(lines[0].detail.contains(&cl.id.to_string()), "{lines:?}");
        assert!(
            !lines[1].pass && lines[1].detail.contains("wrong_peer_id"),
            "{lines:?}"
        );
        assert!(
            !lines[2].pass && lines[2].detail.contains("refused"),
            "{lines:?}"
        );
        // The mplex-only peer refused our yamux proposal: a pass, labelled as a deviation.
        assert!(lines[3].pass, "{lines:?}");
        assert!(
            lines[3]
                .detail
                .contains("muxer=/mplex/6.7.0 (peer offers no yamux: recorded deviation)"),
            "{lines:?}"
        );
        assert!(!lines[0].detail.contains("deviation"), "{lines:?}");
        assert!(!check.passed());

        let passing = ConnectPlan {
            peers: vec![cl.pinned(), mplex],
            timeout: Duration::from_secs(10),
        };
        assert!(connect::<Minimal>(&devnet, &passing).await.passed());
    }

    fn offer(protocols: &[&str]) -> Vec<String> {
        protocols.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn our_dial_proposes_yamux_before_mplex() {
        assert_eq!(our_offer(), offer(&[YAMUX, MPLEX]));
    }

    #[test]
    fn mplex_passes_only_after_a_refused_yamux_proposal() {
        let ours = offer(&[YAMUX, MPLEX]);
        assert_eq!(judge_muxer(&ours, YAMUX), Ok(None));
        assert_eq!(
            judge_muxer(&ours, MPLEX),
            Ok(Some("peer offers no yamux: recorded deviation"))
        );
        // A peer never asked for yamux before it took mplex may well speak yamux: a failure.
        for offered in [offer(&[MPLEX, YAMUX]), offer(&[MPLEX])] {
            let why = judge_muxer(&offered, MPLEX).unwrap_err();
            assert!(
                why.contains("the muxer is /mplex/6.7.0, not /yamux/1.0.0"),
                "{why}"
            );
            assert!(
                why.contains("never proposed /yamux/1.0.0 before it"),
                "{why}"
            );
        }
        let why = judge_muxer(&ours, "/other/1.0.0").unwrap_err();
        assert_eq!(why, "the muxer is /other/1.0.0, not /yamux/1.0.0");
    }

    /// A TCP proxy on 127.0.0.1 that holds each connection `delay` before it relays it to
    /// `upstream`.
    async fn slow_proxy(upstream: &libp2p::Multiaddr, delay: Duration) -> libp2p::Multiaddr {
        use libp2p::multiaddr::Protocol;
        let port = upstream
            .iter()
            .find_map(|p| match p {
                Protocol::Tcp(port) => Some(port),
                _ => None,
            })
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if let Ok(mut server) =
                        tokio::net::TcpStream::connect(("127.0.0.1", port)).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        format!("/ip4/127.0.0.1/tcp/{local}").parse().unwrap()
    }

    /// A dial that timed out is gone: its connection cannot complete while the next peer is
    /// dialled, so it never lends that peer its muxer, and the timed-out peer never sees us.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_dial_never_completes_later() {
        let devnet = devnet();
        let late = cl_p2p::testkit::StatusPeer::echoing(p2p_wire::testkit::status()).await;
        let next = StandIn::spawn::<Minimal>(&devnet, None).await;
        let plan = ConnectPlan {
            peers: vec![
                PinnedPeer {
                    peer_id: late.id,
                    addr: slow_proxy(&late.addr, Duration::from_millis(800)).await,
                },
                PinnedPeer {
                    peer_id: next.id,
                    addr: slow_proxy(&next.addr, Duration::from_millis(600)).await,
                },
            ],
            timeout: Duration::from_millis(500),
        };
        let check = connect::<Minimal>(&devnet, &plan).await;
        let lines = check.lines();
        assert!(
            !lines[0].pass && lines[0].detail.contains("no connection within"),
            "{lines:?}"
        );
        assert!(!lines[1].pass, "the second dial times out too: {lines:?}");
        // Past the first proxy's release: a connection left in a live swarm would be up now.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(late.connections(), 0, "the timed-out dial completed later");
    }

    #[tokio::test]
    async fn a_silent_address_times_out() {
        // A TCP listener that accepts and never speaks: the dial never completes.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let peer = PinnedPeer {
            peer_id: libp2p::PeerId::random(),
            addr: format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap(),
        };
        let plan = ConnectPlan {
            peers: vec![peer],
            timeout: Duration::from_millis(500),
        };
        let check = connect::<Minimal>(&devnet(), &plan).await;
        assert!(!check.passed());
        assert!(
            check.lines()[0].detail.contains("no connection within"),
            "{check:?}"
        );
    }
}
