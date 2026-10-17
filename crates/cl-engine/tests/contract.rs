//! The ipc contract suite against `cl-engine`: every rule in process and over a Unix socket.

use ipc::testkit::{Server, Target};
use ipc::Link;

fn target(link: Link) -> Target {
    let routes = cl_engine::EngineStub::new(link.clone()).routes();
    Target::new("ethswarm.engine.v1", Server::new(routes), link)
}

ipc::contract_suite!(target);
