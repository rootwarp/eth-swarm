//! The ipc contract suite against `cl-discv5`: every rule in process and over a Unix socket.

use ipc::testkit::{probe, Server, Target};
use ipc::Link;

fn target(link: Link) -> Target {
    let routes = cl_discv5::Discv5Stub::new(link.clone()).routes();
    Target::new("ethswarm.discv5.v1", Server::new(routes), link)
        .with_probe(probe::discv5_watch_peers())
}

ipc::contract_suite!(target);
