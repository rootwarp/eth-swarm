//! The ipc contract suite against `cl-p2p`: every rule in process and over a Unix socket.

use ipc::testkit::{probe, Server, Target};
use ipc::Link;

fn target(link: Link) -> Target {
    let routes = cl_p2p::P2pStub::new(link.clone()).routes();
    Target::new("ethswarm.p2p.v1", Server::new(routes), link)
        .with_probe(probe::p2p_request_blocks_by_range())
}

ipc::contract_suite!(target);
