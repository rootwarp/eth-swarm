//! The req/resp protocols this client speaks, with their payload bounds and response counts.
//!
//! Protocol IDs follow `phase0/p2p-interface.md` "Protocol identification":
//! `/eth2/beacon_chain/req/<message_name>/<version>/<encoding>`, always `ssz_snappy`. Only
//! `BeaconBlocksByRange` v2 carries context bytes (`altair/p2p-interface.md`, the fork digest of
//! the block's fork); the other responses have one shape in every fork. `Goodbye` has a request
//! and no response: the disconnecting peer writes its reason and closes the stream.

use crate::rpc::messages::{
    BlocksByRangeV2Request, ErrorMessage, Goodbye, MetaDataV3, Ping, StatusV2,
    MAX_ERROR_MESSAGE_LEN,
};
use consensus_types::caps::{self, ObjectKind};
use consensus_types::{forked, EthSpec, ForkName};
use ssz::Encode;
use std::fmt;

/// `MAX_REQUEST_BLOCKS_DENEB` (`deneb/p2p-interface.md` configuration): the most blocks a
/// `BeaconBlocksByRange` response may hold. 128 in every known network config.
pub const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;

/// A req/resp protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// `/eth2/beacon_chain/req/status/2/ssz_snappy`.
    StatusV2,
    /// `/eth2/beacon_chain/req/metadata/3/ssz_snappy`.
    MetaDataV3,
    /// `/eth2/beacon_chain/req/ping/1/ssz_snappy`.
    PingV1,
    /// `/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy`.
    BlocksByRangeV2,
    /// `/eth2/beacon_chain/req/goodbye/1/ssz_snappy`.
    GoodbyeV1,
}

impl Protocol {
    /// Every protocol.
    pub const ALL: [Protocol; 5] = [
        Protocol::StatusV2,
        Protocol::MetaDataV3,
        Protocol::PingV1,
        Protocol::BlocksByRangeV2,
        Protocol::GoodbyeV1,
    ];

    /// The multistream protocol ID.
    pub const fn id(self) -> &'static str {
        match self {
            Protocol::StatusV2 => "/eth2/beacon_chain/req/status/2/ssz_snappy",
            Protocol::MetaDataV3 => "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
            Protocol::PingV1 => "/eth2/beacon_chain/req/ping/1/ssz_snappy",
            Protocol::BlocksByRangeV2 => {
                "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
            }
            Protocol::GoodbyeV1 => "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
        }
    }

    /// Whether a success chunk carries the 4-byte fork digest before its payload.
    pub const fn has_context_bytes(self) -> bool {
        matches!(self, Protocol::BlocksByRangeV2)
    }

    /// Whether the response is exactly one chunk (every protocol but `BeaconBlocksByRange`,
    /// whose response may hold anything from no blocks to `count`, and `Goodbye`, which has
    /// none).
    pub const fn single_response(self) -> bool {
        !matches!(self, Protocol::BlocksByRangeV2 | Protocol::GoodbyeV1)
    }

    /// Whether a responder may answer `3: ResourceUnavailable` (`phase0/p2p-interface.md` L1291:
    /// "only valid as a response where specified"). Of these protocols only
    /// `BeaconBlocksByRange` specifies it (L1540, for blocks the responder does not have).
    pub const fn permits_resource_unavailable(self) -> bool {
        matches!(self, Protocol::BlocksByRangeV2)
    }

    /// The SSZ length of the request body, or `None` for a protocol whose request is empty
    /// (`MetaData`: nothing at all is written, not even a length prefix).
    pub fn request_len(self) -> Option<usize> {
        match self {
            Protocol::StatusV2 => Some(<StatusV2 as ssz::Decode>::ssz_fixed_len()),
            Protocol::MetaDataV3 => None,
            Protocol::PingV1 => Some(<Ping as ssz::Decode>::ssz_fixed_len()),
            Protocol::BlocksByRangeV2 => {
                Some(<BlocksByRangeV2Request as ssz::Decode>::ssz_fixed_len())
            }
            Protocol::GoodbyeV1 => Some(<Goodbye as ssz::Decode>::ssz_fixed_len()),
        }
    }

    /// The largest success payload: the type bound, capped at `MAX_PAYLOAD_SIZE`. A block's
    /// bound depends on its fork, so a protocol with context bytes needs `fork`; `None` there
    /// means the context was not read. `Goodbye` has no response, so `None`.
    pub fn response_max_len<E: EthSpec>(self, fork: Option<ForkName>) -> Option<usize> {
        match self {
            Protocol::StatusV2 => Some(<StatusV2 as ssz::Decode>::ssz_fixed_len()),
            Protocol::MetaDataV3 => Some(<MetaDataV3 as ssz::Decode>::ssz_fixed_len()),
            Protocol::PingV1 => Some(<Ping as ssz::Decode>::ssz_fixed_len()),
            Protocol::BlocksByRangeV2 => {
                fork.and_then(|f| caps::max_size::<E>(ObjectKind::SignedBeaconBlock, f))
            }
            Protocol::GoodbyeV1 => None,
        }
    }

    /// The largest error payload: `ErrorMessage` is `List[byte, 256]`.
    pub const fn error_max_len(self) -> usize {
        MAX_ERROR_MESSAGE_LEN
    }
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        self.id()
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// An outbound request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `Status` v2.
    Status(StatusV2),
    /// `GetMetaData` v3 (empty request body).
    MetaData,
    /// `Ping`.
    Ping(Ping),
    /// `BeaconBlocksByRange` v2.
    BlocksByRange(BlocksByRangeV2Request),
    /// `Goodbye`: the reason the sender is disconnecting.
    Goodbye(Goodbye),
}

impl Request {
    /// The protocol the request is sent on.
    pub fn protocol(&self) -> Protocol {
        match self {
            Request::Status(_) => Protocol::StatusV2,
            Request::MetaData => Protocol::MetaDataV3,
            Request::Ping(_) => Protocol::PingV1,
            Request::BlocksByRange(_) => Protocol::BlocksByRangeV2,
            Request::Goodbye(_) => Protocol::GoodbyeV1,
        }
    }

    /// The most response chunks the peer may send: 1 for the single-response protocols, the
    /// request's `count` (at most [`MAX_REQUEST_BLOCKS_DENEB`]) for `BeaconBlocksByRange`, 0
    /// for `Goodbye`.
    pub fn max_response_chunks(&self) -> u64 {
        match self {
            Request::BlocksByRange(r) => r.count.min(MAX_REQUEST_BLOCKS_DENEB),
            Request::Goodbye(_) => 0,
            _ => 1,
        }
    }

    /// The SSZ request body, `None` for an empty request.
    pub fn ssz_body(&self) -> Option<Vec<u8>> {
        match self {
            Request::Status(s) => Some(s.as_ssz_bytes()),
            Request::MetaData => None,
            Request::Ping(p) => Some(p.as_ssz_bytes()),
            Request::BlocksByRange(r) => Some(r.as_ssz_bytes()),
            Request::Goodbye(g) => Some(g.as_ssz_bytes()),
        }
    }
}

/// A decoded success payload.
#[derive(Debug, Clone, PartialEq)]
// `MetaData`'s inline bitvectors make it the largest variant (a few hundred bytes); short-lived
// decode results, so not worth a box. The block, which is far larger, is boxed.
#[allow(clippy::large_enum_variant)]
pub enum Response<E: EthSpec> {
    /// `Status` v2.
    Status(StatusV2),
    /// `MetaData` v3.
    MetaData(MetaDataV3),
    /// `Ping`.
    Ping(Ping),
    /// One block of a `BeaconBlocksByRange` response, in the fork its context bytes named.
    /// Boxed: a block is far larger than the other responses.
    Block(Box<forked::SignedBeaconBlock<E>>),
}

impl<E: EthSpec> Response<E> {
    /// The protocol this is the response of.
    pub fn protocol(&self) -> Protocol {
        match self {
            Response::Status(_) => Protocol::StatusV2,
            Response::MetaData(_) => Protocol::MetaDataV3,
            Response::Ping(_) => Protocol::PingV1,
            Response::Block(_) => Protocol::BlocksByRangeV2,
        }
    }

    /// The SSZ payload of the success chunk.
    pub fn ssz_bytes(&self) -> Vec<u8> {
        match self {
            Response::Status(s) => s.as_ssz_bytes(),
            Response::MetaData(m) => m.as_ssz_bytes(),
            Response::Ping(p) => p.as_ssz_bytes(),
            Response::Block(b) => b.as_ssz_bytes(),
        }
    }
}

/// The result code of a response chunk (`phase0/p2p-interface.md` "Responding side").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ResultCode {
    /// 0: the payload is the response.
    Success = 0,
    /// 1: the request was malformed.
    InvalidRequest = 1,
    /// 2: the responder failed.
    ServerError = 2,
    /// 3: the responder does not have the data.
    ResourceUnavailable = 3,
}

/// A decoded response chunk.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // see `Response`
pub enum ResponseChunk<E: EthSpec> {
    /// Result code 0.
    Success(Response<E>),
    /// Result code 1, 2 or 3 with its `ErrorMessage`. An error chunk ends the response.
    Error {
        /// The result code (never [`ResultCode::Success`]).
        code: ResultCode,
        /// The responder's message.
        message: ErrorMessage,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::messages::Goodbye;
    use consensus_types::Minimal;

    #[test]
    fn protocol_ids_match_the_spec() {
        let ids: Vec<&str> = Protocol::ALL.iter().map(|p| p.id()).collect();
        assert_eq!(
            ids,
            [
                "/eth2/beacon_chain/req/status/2/ssz_snappy",
                "/eth2/beacon_chain/req/metadata/3/ssz_snappy",
                "/eth2/beacon_chain/req/ping/1/ssz_snappy",
                "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
                "/eth2/beacon_chain/req/goodbye/1/ssz_snappy",
            ]
        );
        assert_eq!(Protocol::PingV1.as_ref(), Protocol::PingV1.to_string());
    }

    #[test]
    fn only_blocks_by_range_has_context_bytes() {
        for p in Protocol::ALL {
            assert_eq!(p.has_context_bytes(), p == Protocol::BlocksByRangeV2, "{p}");
            let single = !matches!(p, Protocol::BlocksByRangeV2 | Protocol::GoodbyeV1);
            assert_eq!(p.single_response(), single, "{p}");
        }
    }

    #[test]
    fn goodbye_has_no_response() {
        let p = Protocol::GoodbyeV1;
        assert_eq!(p.request_len(), Some(8));
        assert_eq!(p.response_max_len::<Minimal>(None), None);
        let request = Request::Goodbye(Goodbye(2));
        assert_eq!(request.protocol(), p);
        assert_eq!(request.max_response_chunks(), 0);
        assert_eq!(request.ssz_body(), Some(2u64.to_le_bytes().to_vec()));
    }

    #[test]
    fn only_blocks_by_range_permits_resource_unavailable() {
        for p in Protocol::ALL {
            let permits = p == Protocol::BlocksByRangeV2;
            assert_eq!(p.permits_resource_unavailable(), permits, "{p}");
        }
    }

    #[test]
    fn fixed_sizes_match_the_spec() {
        assert_eq!(
            Protocol::StatusV2.request_len(),
            Some(4 + 32 + 8 + 32 + 8 + 8)
        );
        assert_eq!(Protocol::MetaDataV3.request_len(), None);
        assert_eq!(Protocol::PingV1.request_len(), Some(8));
        assert_eq!(Protocol::BlocksByRangeV2.request_len(), Some(24));
        let meta = Protocol::MetaDataV3.response_max_len::<Minimal>(None);
        assert_eq!(meta, Some(8 + 8 + 1 + 8));
        assert_eq!(Protocol::StatusV2.error_max_len(), 256);
    }

    #[test]
    fn block_bound_needs_the_fork() {
        let p = Protocol::BlocksByRangeV2;
        assert_eq!(p.response_max_len::<Minimal>(None), None);
        for fork in ForkName::ALL {
            let max = p.response_max_len::<Minimal>(Some(fork)).unwrap();
            assert!(max <= caps::MAX_PAYLOAD_SIZE, "{fork}: {max}");
        }
    }

    #[test]
    fn max_response_chunks() {
        let range = |count| {
            Request::BlocksByRange(BlocksByRangeV2Request {
                start_slot: 0,
                count,
                step: 1,
            })
        };
        assert_eq!(range(2).max_response_chunks(), 2);
        assert_eq!(range(0).max_response_chunks(), 0);
        assert_eq!(
            range(u64::MAX).max_response_chunks(),
            MAX_REQUEST_BLOCKS_DENEB
        );
        assert_eq!(Request::MetaData.max_response_chunks(), 1);
        assert_eq!(Request::Ping(Ping(1)).max_response_chunks(), 1);
        assert_eq!(Request::MetaData.ssz_body(), None);
        assert_eq!(Request::MetaData.protocol(), Protocol::MetaDataV3);
    }

    #[test]
    fn responses_name_their_protocol_and_payload() {
        use crate::testkit;
        let status: Response<Minimal> = Response::Status(testkit::status());
        assert_eq!(status.protocol(), Protocol::StatusV2);
        assert_eq!(status.ssz_bytes(), testkit::status().as_ssz_bytes());
        let metadata: Response<Minimal> = Response::MetaData(testkit::metadata());
        assert_eq!(metadata.protocol(), Protocol::MetaDataV3);
        assert_eq!(metadata.ssz_bytes().len(), 25);
        let ping: Response<Minimal> = Response::Ping(Ping(3));
        assert_eq!(ping.protocol(), Protocol::PingV1);
        assert_eq!(ping.ssz_bytes(), 3u64.to_le_bytes());
        let block = forked::SignedBeaconBlock::Fulu(testkit::fulu_block::<Minimal>(1));
        let ssz = block.as_ssz_bytes();
        let block = Response::Block(Box::new(block));
        assert_eq!(block.protocol(), Protocol::BlocksByRangeV2);
        assert_eq!(block.ssz_bytes(), ssz);
    }
}
