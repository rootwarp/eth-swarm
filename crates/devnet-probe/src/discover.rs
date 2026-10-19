//! `discover`: our discv5 in local mode, seeded with the bootnode ENRs, must find every
//! reference CL's node record within the deadline.
//!
//! The node runs cl-discv5's [`Discovery`] in [`NetworkMode::Local`] with a fresh secp256k1 key
//! and a local record carrying the devnet's `eth2`, `nfd` and `cgc` at the wall-clock epoch.
//! Local mode's routing-table IP rules ([`cl_discv5::service::is_local_ip`]: loopback, private,
//! link-local, CGNAT, IPv6 unique-local) gate everything discv5 sends: a record a peer hands
//! us with any other address is never queried, pinged or put in the table, so the probe sends
//! no packet to a public host. Each bootnode goes into the routing table; then, until every
//! expected node is found or the deadline passed, one lookup per missing node, targeted at its
//! node ID. Lookups return only records on our fork digest within the IP rules
//! ([`Discovery::find_peers`] filters them), and a node counts as found once a lookup returned
//! its record or the event stream reported it (a lookup came across it, or a session with it
//! was established): its record reached us over discv5.

use super::api::hex0x;
use super::report::Check;
use cl_discv5::enr::{build_local_enr, fork_id, CombinedKey, Enr, LocalAddr, NodeId};
use cl_discv5::service::{Discovery, DiscoveryConfig, NetworkMode, PeerEvent};
use consensus_types::das::CUSTODY_REQUIREMENT;
use p2p_wire::enr::ForkFields;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// The check's name.
pub const NAME: &str = "discover";
/// How long the lookups may take by default \[est\].
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(60);
/// The UDP address our node listens on by default.
pub const DEFAULT_LISTEN: SocketAddr = SocketAddr::new(
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    cl_discv5::enr::DEFAULT_PORT,
);
/// The most records one lookup returns.
const MAX_PEERS: usize = 16;
/// The pause between two rounds of lookups.
const ROUND_PAUSE: Duration = Duration::from_millis(500);

/// What `discover` runs.
#[derive(Debug, Clone)]
pub struct DiscoverPlan {
    /// Our record's fork fields: the devnet's at the wall-clock epoch.
    pub fork: ForkFields,
    /// Where our node listens (UDP). An unspecified IP leaves `ip` out of our record.
    pub listen: SocketAddr,
    /// The records the routing table starts from.
    pub bootnodes: Vec<Enr>,
    /// The reference CLs' records: each node must be found.
    pub expected: Vec<Enr>,
    /// How long the lookups may take.
    pub deadline: Duration,
}

/// Records found, by node ID, with when.
type Found = Arc<Mutex<HashMap<NodeId, (Enr, Instant)>>>;

fn note(found: &Found, enr: Enr) {
    found
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(enr.node_id())
        .or_insert((enr, Instant::now()));
}

/// Runs the check: one line per bootnode, then one per expected node.
pub async fn discover(plan: &DiscoverPlan) -> Check {
    if Instant::now().checked_add(plan.deadline).is_none() {
        return Check::failed(
            NAME,
            format!(
                "the deadline {:?} is past what the clock can hold",
                plan.deadline
            ),
        );
    }
    let key = CombinedKey::generate_secp256k1();
    let ip = match plan.listen.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let addr = LocalAddr {
        ip,
        tcp_port: plan.listen.port(),
        udp_port: plan.listen.port(),
    };
    let enr = match build_local_enr(&key, &plan.fork, CUSTODY_REQUIREMENT, &addr) {
        Ok(enr) => enr,
        Err(e) => return Check::failed(NAME, format!("our record: {e}")),
    };
    let mut config = DiscoveryConfig::new(plan.listen.ip(), NetworkMode::Local);
    config.udp_port = plan.listen.port();
    let mut discovery = match Discovery::new(enr, key, &config) {
        Ok(d) => d,
        Err(e) => return Check::failed(NAME, format!("discv5: {e}")),
    };
    let mut events = match discovery.start().await {
        Ok(events) => events,
        Err(e) => return Check::failed(NAME, format!("discv5 on {}: {e}", plan.listen)),
    };
    let ours = discovery.fork_digest();
    tracing::info!(
        node = %discovery.local_enr().node_id(),
        listen = %plan.listen,
        fork_digest = %hex0x(&ours),
        "discv5 started in local mode"
    );
    let found = Found::default();
    let seen = Arc::clone(&found);
    let drain = tokio::spawn(async move {
        while let Some(event) = events.next().await {
            match event {
                PeerEvent::Discovered(enr) | PeerEvent::SessionEstablished(enr, _) => {
                    note(&seen, enr);
                }
                PeerEvent::SocketUpdated(addr) => tracing::debug!(%addr, "our socket updated"),
            }
        }
    });
    let mut check = Check::new(NAME);
    for boot in &plan.bootnodes {
        let at = format!("bootnode {}", hex0x(&boot.node_id().raw()));
        match discovery.add_enr(boot.clone()) {
            Ok(()) => check.pass(format!(
                "{at} at {}: in the routing table",
                boot.udp4_socket()
                    .map_or_else(|| "no UDP socket".to_owned(), |s| s.to_string())
            )),
            Err(e) => check.fail(format!("{at}: {e}")),
        }
    }
    let start = Instant::now();
    let end = start.checked_add(plan.deadline).unwrap_or(start);
    let missing = |found: &Found| -> Vec<NodeId> {
        let found = found.lock().unwrap_or_else(PoisonError::into_inner);
        plan.expected
            .iter()
            .map(Enr::node_id)
            .filter(|id| !found.contains_key(id))
            .collect()
    };
    loop {
        let open = missing(&found);
        if open.is_empty() || Instant::now() >= end {
            break;
        }
        for target in open {
            let left = end.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, discovery.find_peers(target, MAX_PEERS)).await {
                Ok(Ok(enrs)) => enrs.into_iter().for_each(|enr| note(&found, enr)),
                Ok(Err(e)) => tracing::debug!(%target, error = %e, "lookup failed"),
                Err(_) => break,
            }
        }
        tokio::time::sleep(ROUND_PAUSE.min(end.saturating_duration_since(Instant::now()))).await;
    }
    drain.abort();
    let found = found.lock().unwrap_or_else(PoisonError::into_inner);
    for want in &plan.expected {
        let id = hex0x(&want.node_id().raw());
        match found.get(&want.node_id()) {
            Some((enr, at)) => check.pass(format!(
                "node {id}: found through discv5 {:.1} s in (record seq {}, eth2 fork digest {}, \
                 ours)",
                at.saturating_duration_since(start).as_secs_f64(),
                enr.seq(),
                hex0x(&ours)
            )),
            None => {
                let digest = fork_id(want).map(|f| f.fork_digest);
                let why = match digest {
                    Ok(d) if d != ours => format!(
                        "its record's eth2 fork digest {} is not ours {}, and our lookups return \
                         only our fork",
                        hex0x(&d),
                        hex0x(&ours)
                    ),
                    Ok(_) => format!("not found within {:?}", plan.deadline),
                    Err(e) => format!("its record has no usable eth2 field ({e})"),
                };
                check.fail(format!("node {id}: {why}"));
            }
        }
    }
    check
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{devnet, discv5_node as node, now_ms, on_free_udp_port, port_taken};
    use cl_discv5::enr::{build_local_enr, LocalAddr};
    use std::net::Ipv4Addr;

    /// A plan on loopback; [`discover_on_free_port`] picks its port.
    fn plan(fork: ForkFields, bootnodes: Vec<Enr>, expected: Vec<Enr>) -> DiscoverPlan {
        DiscoverPlan {
            fork,
            listen: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            bootnodes,
            expected,
            deadline: Duration::from_secs(5),
        }
    }

    /// [`discover`] with our node on a fresh loopback port, run again on another one while
    /// our node finds its port taken.
    async fn discover_on_free_port(plan: &DiscoverPlan) -> Check {
        on_free_udp_port(|port| {
            let mut plan = plan.clone();
            plan.listen.set_port(port);
            async move {
                let check = discover(&plan).await;
                match check
                    .lines()
                    .iter()
                    .find(|l| !l.pass && port_taken(&l.detail))
                {
                    Some(taken) => Err(taken.detail.clone()),
                    None => Ok(check),
                }
            }
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_reference_cl_is_found_through_the_bootnode() {
        let fork = devnet().fork_fields(now_ms()).unwrap();
        let (boot, _boot_events) = node(&fork).await;
        let (c, _c_events) = node(&fork).await;
        let (d, _d_events) = node(&fork).await;
        boot.add_enr(c.local_enr()).unwrap();
        boot.add_enr(d.local_enr()).unwrap();
        let expected = vec![boot.local_enr(), c.local_enr(), d.local_enr()];
        let check = discover_on_free_port(&plan(fork, vec![boot.local_enr()], expected)).await;
        assert!(check.passed(), "{check:#?}");
        let lines = check.lines();
        assert!(lines[0].detail.starts_with("bootnode"), "{lines:#?}");
        for n in [&boot, &c, &d] {
            let id = hex0x(&n.local_enr().node_id().raw());
            assert!(
                lines
                    .iter()
                    .any(|l| l.detail.contains(&id) && l.detail.contains("found")),
                "{id}: {lines:#?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_off_fork_or_unknown_record_is_never_found() {
        let devnet = devnet();
        let fork = devnet.fork_fields(now_ms()).unwrap();
        // The schedule's Fulu digest, not the wall clock's Gloas one.
        let other = devnet
            .fork_fields(u128::from(devnet.genesis().genesis_time) * 1000)
            .unwrap();
        assert_ne!(other.eth2.fork_digest, fork.eth2.fork_digest);
        let (boot, _boot_events) = node(&fork).await;
        let (off_fork, _off_events) = node(&other).await;
        let (unknown, _unknown_events) = node(&fork).await;
        boot.add_enr(off_fork.local_enr()).unwrap();
        let mut plan = plan(
            fork,
            vec![boot.local_enr()],
            vec![off_fork.local_enr(), unknown.local_enr()],
        );
        plan.deadline = Duration::from_secs(2);
        let check = discover_on_free_port(&plan).await;
        assert!(!check.passed());
        let failed: Vec<&str> = check
            .lines()
            .iter()
            .filter(|l| !l.pass)
            .map(|l| l.detail.as_str())
            .collect();
        assert_eq!(failed.len(), 2, "{failed:#?}");
        assert!(failed[0].contains("not ours"), "{failed:#?}");
        assert!(failed[1].contains("not found within"), "{failed:#?}");
    }

    /// A deadline past what the clock can hold fails the check; it does not panic.
    #[tokio::test]
    async fn a_deadline_past_the_clock_fails_without_a_panic() {
        let fork = devnet().fork_fields(now_ms()).unwrap();
        let mut plan = plan(fork, Vec::new(), Vec::new());
        plan.deadline = Duration::MAX;
        let check = discover_on_free_port(&plan).await;
        assert!(!check.passed());
        assert!(check.lines()[0].detail.contains("deadline"), "{check:#?}");
    }

    /// Our node runs in local mode: a record at an address that is not local (TEST-NET-1
    /// here) is refused by the routing table, so nothing is ever sent to it.
    #[tokio::test]
    async fn a_record_that_is_not_local_is_refused() {
        let fork = devnet().fork_fields(now_ms()).unwrap();
        let key = CombinedKey::generate_secp256k1();
        let addr = LocalAddr::new(Ipv4Addr::new(192, 0, 2, 1));
        let far = build_local_enr(&key, &fork, 4, &addr).unwrap();
        let mut plan = plan(fork, vec![far.clone()], vec![far]);
        plan.deadline = Duration::from_millis(300);
        let check = discover_on_free_port(&plan).await;
        assert!(!check.passed());
        assert!(
            check.lines()[0].detail.contains("routing table refused"),
            "{check:#?}"
        );
    }

    #[tokio::test]
    async fn a_bootnode_the_table_refuses_fails() {
        let fork = devnet().fork_fields(now_ms()).unwrap();
        // A record without a UDP socket: the routing table refuses it.
        let key = CombinedKey::generate_secp256k1();
        let no_udp = Enr::builder().ip4(Ipv4Addr::LOCALHOST).build(&key).unwrap();
        let mut plan = plan(fork, vec![no_udp.clone()], vec![no_udp]);
        plan.deadline = Duration::from_millis(300);
        let check = discover_on_free_port(&plan).await;
        assert!(!check.passed());
        assert!(
            check.lines()[0].detail.contains("routing table refused"),
            "{check:#?}"
        );
    }
}
