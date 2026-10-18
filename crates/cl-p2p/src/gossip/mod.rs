//! The probe's gossipsub: subscribed to the configured topics (`beacon_block` by default), it
//! reports IGNORE for every message, so it forwards no data message at all.
//!
//! - [`config`]: [`GossipConfig`] (topics, caps, timings), the gossipsub settings it builds
//!   (StrictNoSign, manual validation, the Altair message-id) and [`WireTransform`], the
//!   bounded snappy transform from `p2p-wire`.
//! - [`ignore_all`]: [`IgnoreAll`], the behaviour that wraps gossipsub, reports IGNORE for each
//!   message and exposes no way to publish, with an optional bounded [`CaptureTap`].
//!
//! The swarm takes it through [`crate::transport::build_swarm_with_gossip`]. gossipsub's own
//! metrics (`topic_msg_sent_counts`, `topic_msg_published`, `mesh_peer_counts`, ...) go on the
//! registry given to [`IgnoreAll::new`].

pub mod config;
pub mod ignore_all;

#[cfg(test)]
mod tests;

pub use config::{GossipConfig, WireTransform};
pub use ignore_all::{
    capture_tap, CaptureReader, CaptureTap, Captured, IgnoreAll, IgnoreAllEvent, ProbeGossipsub,
    ValidationSink,
};

use libp2p::gossipsub::{ConfigBuilderError, SubscriptionError};

/// Why the probe's gossipsub could not be built.
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    /// A zero heartbeat interval.
    #[error("gossipsub heartbeat interval is zero")]
    ZeroHeartbeat,
    /// gossipsub refused the configuration.
    #[error("gossipsub config: {0}")]
    Config(#[from] ConfigBuilderError),
    /// gossipsub refused the privacy and validation pair.
    #[error("gossipsub: {0}")]
    Behaviour(&'static str),
    /// A topic could not be subscribed.
    #[error("gossipsub subscribe: {0}")]
    Subscribe(#[from] SubscriptionError),
}

/// N messages injected by a forwarding neighbour: N IGNORE reports and N `Ignored` events, and
/// gossipsub's own counters read N ignored, 0 accepted, 0 rejected, 0 invalid, 0 sent and 0
/// published, while the neighbour's identical counters read its N publishes.
#[tokio::test]
async fn ignore_all_reports_every_message() {
    use std::collections::HashSet;
    const N: usize = 25;
    let probe = tests::Probe::spawn(N).await;
    let neighbour = tests::Neighbour::spawn().await;
    neighbour.dial(probe.center.addr.clone());
    neighbour.wait_for_mesh_with(probe.center.peer).await;

    let mut sent = HashSet::new();
    for i in 0..N {
        sent.insert(neighbour.publish(tests::payload("ignore", i, 200)).await);
    }
    let delivered = probe.center.wait_for_deliveries(N).await;
    let ids: HashSet<_> = delivered.iter().map(|d| d.id.clone()).collect();
    assert_eq!(ids, sent, "every message reached the probe once");
    assert!(delivered
        .iter()
        .all(|d| d.in_cache == Some(true) && d.source == neighbour.peer));

    let metrics = probe.metrics();
    assert_eq!(metrics.sum("ignored_messages_per_topic"), N as u64);
    assert_eq!(metrics.sum("topic_msg_recv_counts"), N as u64);
    for zero in [
        "accepted_messages_per_topic",
        "rejected_messages_per_topic",
        "invalid_messages_per_topic",
        "topic_msg_published",
        "topic_msg_sent_counts",
    ] {
        assert_eq!(metrics.sum(zero), 0, "{zero}");
    }
    // The same registration on the neighbour counts its publishes: the zeros are the probe's.
    let theirs = neighbour.metrics();
    assert_eq!(theirs.sum("topic_msg_published"), N as u64);
    assert!(theirs.sum("topic_msg_sent_counts") >= N as u64);

    // The tap got every message, with its decompressed bytes.
    let mut captured = 0;
    while let Some(c) = probe.capture.try_next() {
        assert!(sent.contains(&libp2p::gossipsub::MessageId::new(&c.message_id)));
        assert_eq!(c.data.len(), 200);
        captured += 1;
    }
    assert_eq!((captured, probe.capture.dropped()), (N, 0));
}

/// Three forwarding gossipsub neighbours and a scripted meshsub peer around the probe. Each
/// neighbour's transport taps the bytes it reads from every stream, and the scripted peer reads
/// the probe's stream itself; the data messages (`RPC.publish`) in what the probe sent are
/// counted from those bytes. Through a flood with duplicates, IWANT for every seen id (before
/// and after the message cache has shifted them out) and an overload burst past the capture
/// queue, the probe sends none, while the same taps see the neighbours' forwards to each other.
#[tokio::test]
async fn zero_egress_wire_bytes() {
    const CAPTURE: usize = 64;
    let probe = tests::Probe::spawn(CAPTURE).await;
    let observed = tests::run_scenarios(&probe.center, || {
        probe.metrics().sum("heartbeat_duration_count")
    })
    .await;

    for (i, n) in observed.neighbours.iter().enumerate() {
        assert_eq!(
            (n.from_center.publish_msgs, n.from_center.publish_bytes),
            (0, 0),
            "neighbour {i} received data from the probe: {n:?}"
        );
        assert!(
            n.from_center.frames > 0,
            "neighbour {i}: the tap saw no probe traffic at all"
        );
        assert!(
            n.from_neighbours.publish_bytes > 0,
            "neighbour {i}: the tap saw no forwards between neighbours"
        );
    }
    let s = &observed.scripted;
    assert_eq!(
        (s.publish_msgs, s.publish_bytes, s.ihave_ids),
        (0, 0, 0),
        "{s:?}"
    );
    assert!(s.frames > 0, "the scripted peer read no probe traffic");
    assert!(
        observed.delivered >= observed.expected_at_least,
        "{} delivered, {} expected",
        observed.delivered,
        observed.expected_at_least
    );

    let metrics = probe.metrics();
    for zero in ["topic_msg_sent_counts", "topic_msg_published"] {
        assert_eq!(metrics.sum(zero), 0, "{zero}");
    }
    for (i, n) in observed.neighbour_metrics.iter().enumerate() {
        assert!(
            n.sum("topic_msg_published") > 0,
            "neighbour {i} published nothing"
        );
    }
    assert_eq!(
        metrics.sum("ignored_messages_per_topic"),
        observed.delivered as u64
    );
    assert_eq!(metrics.sum("accepted_messages_per_topic"), 0);
    assert_eq!(metrics.sum("rejected_messages_per_topic"), 0);
    // The mesh degree per topic is exported: the three neighbours and the scripted peer.
    assert!(metrics.sum_matching("mesh_peer_counts", &tests::topic().to_string()) >= 3);
    // The message cache shifted past every message: more than mcache_len heartbeats ran.
    assert!(metrics.sum("heartbeat_duration_count") > config::MCACHE_LEN as u64);

    // The capture queue held CAPTURE messages and counted the rest as dropped.
    let mut captured = 0;
    while probe.capture.try_next().is_some() {
        captured += 1;
    }
    assert_eq!(captured, CAPTURE);
    assert_eq!(
        captured as u64 + probe.capture.dropped(),
        observed.delivered as u64
    );
}
