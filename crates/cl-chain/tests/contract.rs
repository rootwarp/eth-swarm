//! The ipc contract suite against `cl-chain`: every rule in process and over a Unix socket.

use ipc::testkit::{probe, Server, Target};
use ipc::Link;

fn target(link: Link) -> Target {
    let routes = cl_chain::ChainStub::new(link.clone()).routes();
    Target::new("ethswarm.chain.v1", Server::new(routes), link)
        .with_probe(probe::chain_import_batch())
        .with_unary_probe(probe::chain_submit())
}

ipc::contract_suite!(target);
