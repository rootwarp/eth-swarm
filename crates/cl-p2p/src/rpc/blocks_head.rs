//! `BeaconBlocksByHead` v1 answers (#230; `fulu/p2p-interface.md` L796–863). Not served yet.

use super::responder::{ChunkSink, Responder, Serving};
use consensus_types::EthSpec;
use libp2p::PeerId;
use p2p_wire::rpc::protocols::Request;

/// Serves BeaconBlocksByHead v1 (not yet).
#[derive(Clone)]
pub struct ByHeadResponder;

impl<E: EthSpec> Responder<E> for ByHeadResponder {
    fn serve(&self, _: PeerId, _: Request, _: ChunkSink<E>) -> Serving {
        todo!("#230")
    }
}
