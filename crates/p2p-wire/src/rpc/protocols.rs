//! The req/resp protocols this client speaks, with their payload bounds and response counts.
//!
//! Protocol IDs follow `phase0/p2p-interface.md` "Protocol identification":
//! `/eth2/beacon_chain/req/<message_name>/<version>/<encoding>`, always `ssz_snappy`. Only
//! `BeaconBlocksByRange` v2 carries context bytes (`altair/p2p-interface.md`, the fork digest of
//! the block's fork); the other responses have one shape in every fork. `Goodbye` carries a
//! `uint64` reason both ways ("Request, Response Content", `phase0/p2p-interface.md` L1461): the
//! disconnecting peer writes its reason, and the response is one chunk with a reason too (L1483),
//! though some clients send none.
//!
//! [`ProtocolLimits`] is the one row per protocol the codec and the transport check against: the
//! request ceiling, the response chunk count and the SSZ length bounds of request and response
//! (`phase0/p2p-interface.md` "What are SSZ type size bounds?", L2627). The bounds are the type's
//! own, from `consensus_types::caps`; `MAX_PAYLOAD_SIZE` caps only a type whose bound is larger
//! (`phase0` L1365).

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

/// `MAX_REQUEST_PAYLOADS` (`gloas/p2p-interface.md` L84): the most execution payload envelopes
/// one `ExecutionPayloadEnvelopesByRange`/`ByRoot` request may ask for.
pub const MAX_REQUEST_PAYLOADS: u64 = 128;

/// `MAX_REQUEST_DATA_COLUMN_SIDECARS` (`fulu/p2p-interface.md` L174:
/// `MAX_REQUEST_BLOCKS_DENEB * NUMBER_OF_COLUMNS`): the most column sidecars one
/// `DataColumnSidecarsByRange`/`ByRoot` request may ask for.
pub const MAX_REQUEST_DATA_COLUMN_SIDECARS: u64 = 16_384;

/// The shortest `SignedBeaconBlock` of either fork, as a lower bound: the fixed parts of
/// `SignedBeaconBlock` (the `message` offset and the 96-byte signature) and of `BeaconBlock`
/// (`slot`, `proposer_index`, `parent_root`, `state_root` and the `body` offset). Both forks
/// share them; the body only adds to it.
pub const MIN_SIGNED_BEACON_BLOCK_LEN: usize = (4 + 96) + (8 + 8 + 32 + 32 + 4);

/// An SSZ length range: a declared length outside it is refused at the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SszBounds {
    /// The shortest valid encoding.
    pub min: usize,
    /// The longest valid encoding, at most `MAX_PAYLOAD_SIZE`.
    pub max: usize,
}

impl SszBounds {
    /// Exactly `len` bytes: a fixed-size type.
    pub const fn exactly(len: usize) -> Self {
        Self { min: len, max: len }
    }

    /// At most `max` bytes, `max` capped at `MAX_PAYLOAD_SIZE`.
    pub fn up_to(max: usize) -> Self {
        Self {
            min: 0,
            max: max.min(caps::MAX_PAYLOAD_SIZE),
        }
    }
}

/// One protocol's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolLimits {
    /// The multistream protocol ID.
    pub id: &'static str,
    /// The most items one request may ask for ([`MAX_REQUEST_BLOCKS_DENEB`] for
    /// `BeaconBlocksByRange`); 0 for a request that names no items.
    pub max_request_items: u64,
    /// The most response chunks one request can be answered with.
    pub max_response_chunks: u64,
    /// The request payload's SSZ length range; `None` for an empty request (`MetaData`).
    pub request: Option<SszBounds>,
    /// The shortest success payload, over every fork the protocol serves; 0 if it has none.
    pub ssz_min: usize,
    /// The longest success payload, over every fork, capped at `MAX_PAYLOAD_SIZE`; 0 if it has
    /// none. A block's own bound is its fork's ([`Protocol::response_bounds`]).
    pub ssz_max: usize,
}

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
    /// whose response may hold anything from no blocks to `count`, and `Goodbye`, whose one
    /// chunk some clients leave out).
    pub const fn single_response(self) -> bool {
        !matches!(self, Protocol::BlocksByRangeV2 | Protocol::GoodbyeV1)
    }

    /// Whether a responder may answer `3: ResourceUnavailable` (`phase0/p2p-interface.md` L1291:
    /// "only valid as a response where specified"). Of these protocols only
    /// `BeaconBlocksByRange` specifies it (L1540, for blocks the responder does not have).
    pub const fn permits_resource_unavailable(self) -> bool {
        matches!(self, Protocol::BlocksByRangeV2)
    }

    /// This protocol's row of limits.
    pub fn limits<E: EthSpec>(self) -> ProtocolLimits {
        let (max_request_items, max_response_chunks) = match self {
            Protocol::BlocksByRangeV2 => (MAX_REQUEST_BLOCKS_DENEB, MAX_REQUEST_BLOCKS_DENEB),
            _ => (0, 1),
        };
        let (ssz_min, ssz_max) = match self {
            Protocol::BlocksByRangeV2 => (
                MIN_SIGNED_BEACON_BLOCK_LEN,
                ForkName::ALL
                    .into_iter()
                    .filter_map(|fork| self.response_max_len::<E>(Some(fork)))
                    .max()
                    .unwrap_or(0),
            ),
            _ => self
                .response_max_len::<E>(None)
                .map_or((0, 0), |len| (len, len)),
        };
        ProtocolLimits {
            id: self.id(),
            max_request_items,
            max_response_chunks,
            request: self.request_bounds(),
            ssz_min,
            ssz_max,
        }
    }

    /// The request payload's SSZ length range: every request is fixed-size, so one length.
    /// `None` for an empty request.
    pub fn request_bounds(self) -> Option<SszBounds> {
        self.request_len().map(SszBounds::exactly)
    }

    /// The success payload's SSZ length range at `fork` (which a protocol with context bytes
    /// needs, see [`Protocol::response_max_len`]); `None` where there is no bound to read with.
    pub fn response_bounds<E: EthSpec>(self, fork: Option<ForkName>) -> Option<SszBounds> {
        let max = self.response_max_len::<E>(fork)?;
        let min = match self {
            Protocol::BlocksByRangeV2 => MIN_SIGNED_BEACON_BLOCK_LEN,
            _ => max,
        };
        Some(SszBounds { min, max })
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
    /// means the context was not read.
    pub fn response_max_len<E: EthSpec>(self, fork: Option<ForkName>) -> Option<usize> {
        match self {
            Protocol::StatusV2 => Some(<StatusV2 as ssz::Decode>::ssz_fixed_len()),
            Protocol::MetaDataV3 => Some(<MetaDataV3 as ssz::Decode>::ssz_fixed_len()),
            Protocol::PingV1 => Some(<Ping as ssz::Decode>::ssz_fixed_len()),
            Protocol::BlocksByRangeV2 => {
                fork.and_then(|f| caps::max_size::<E>(ObjectKind::SignedBeaconBlock, f))
            }
            Protocol::GoodbyeV1 => Some(<Goodbye as ssz::Decode>::ssz_fixed_len()),
        }
    }

    /// The largest error payload: `ErrorMessage` is `List[byte, 256]`.
    pub const fn error_max_len(self) -> usize {
        MAX_ERROR_MESSAGE_LEN
    }

    /// The error payload's SSZ length range: 0 to 256 bytes.
    pub const fn error_bounds(self) -> SszBounds {
        SszBounds {
            min: 0,
            max: self.error_max_len(),
        }
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

    /// The most response chunks the peer may send: the request's `count` (at most
    /// [`MAX_REQUEST_BLOCKS_DENEB`]) for `BeaconBlocksByRange`, 1 for every other protocol.
    pub fn max_response_chunks(&self) -> u64 {
        match self {
            Request::BlocksByRange(r) => r.count.min(MAX_REQUEST_BLOCKS_DENEB),
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
    /// `Goodbye`: the responder's reason.
    Goodbye(Goodbye),
}

impl<E: EthSpec> Response<E> {
    /// The protocol this is the response of.
    pub fn protocol(&self) -> Protocol {
        match self {
            Response::Status(_) => Protocol::StatusV2,
            Response::MetaData(_) => Protocol::MetaDataV3,
            Response::Ping(_) => Protocol::PingV1,
            Response::Block(_) => Protocol::BlocksByRangeV2,
            Response::Goodbye(_) => Protocol::GoodbyeV1,
        }
    }

    /// The SSZ payload of the success chunk.
    pub fn ssz_bytes(&self) -> Vec<u8> {
        match self {
            Response::Status(s) => s.as_ssz_bytes(),
            Response::MetaData(m) => m.as_ssz_bytes(),
            Response::Ping(p) => p.as_ssz_bytes(),
            Response::Block(b) => b.as_ssz_bytes(),
            Response::Goodbye(g) => g.as_ssz_bytes(),
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
    fn goodbye_has_at_most_one_response_chunk() {
        // "Request, Response Content: (Uint64)" and "The response MUST consist of a single
        // `response_chunk`" (`phase0/p2p-interface.md` L1461, L1483); some clients send none.
        let p = Protocol::GoodbyeV1;
        assert_eq!(p.request_len(), Some(8));
        assert_eq!(p.response_max_len::<Minimal>(None), Some(8));
        assert!(!p.single_response(), "an empty response is accepted too");
        let request = Request::Goodbye(Goodbye(2));
        assert_eq!(request.protocol(), p);
        assert_eq!(request.max_response_chunks(), 1);
        assert_eq!(request.ssz_body(), Some(2u64.to_le_bytes().to_vec()));
        let response = Response::<Minimal>::Goodbye(Goodbye(2));
        assert_eq!(response.protocol(), p);
        assert_eq!(response.ssz_bytes(), 2u64.to_le_bytes());
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
    fn limits_table_has_one_row_per_protocol() {
        use consensus_types::Mainnet;
        let rows: Vec<ProtocolLimits> = Protocol::ALL
            .iter()
            .map(|p| p.limits::<Minimal>())
            .collect();
        for (row, p) in rows.iter().zip(Protocol::ALL) {
            assert_eq!(row.id, p.id());
            assert!(row.ssz_min <= row.ssz_max, "{p}");
            assert!(row.ssz_max <= caps::MAX_PAYLOAD_SIZE, "{p}");
        }
        let status = Protocol::StatusV2.limits::<Minimal>();
        assert_eq!(status.request, Some(SszBounds::exactly(92)));
        assert_eq!((status.ssz_min, status.ssz_max), (92, 92));
        assert_eq!(
            (status.max_request_items, status.max_response_chunks),
            (0, 1)
        );
        let metadata = Protocol::MetaDataV3.limits::<Minimal>();
        assert_eq!(metadata.request, None);
        assert_eq!((metadata.ssz_min, metadata.ssz_max), (25, 25));
        let ping = Protocol::PingV1.limits::<Minimal>();
        assert_eq!(ping.request, Some(SszBounds::exactly(8)));
        let goodbye = Protocol::GoodbyeV1.limits::<Minimal>();
        assert_eq!(goodbye.request, Some(SszBounds::exactly(8)));
        assert_eq!(
            (
                goodbye.max_response_chunks,
                goodbye.ssz_min,
                goodbye.ssz_max
            ),
            (1, 8, 8)
        );
        // Blocks: 128 a request, the bound the largest fork's, capped at MAX_PAYLOAD_SIZE.
        for blocks in [
            Protocol::BlocksByRangeV2.limits::<Minimal>(),
            Protocol::BlocksByRangeV2.limits::<Mainnet>(),
        ] {
            assert_eq!(blocks.request, Some(SszBounds::exactly(24)));
            assert_eq!(blocks.max_request_items, MAX_REQUEST_BLOCKS_DENEB);
            assert_eq!(blocks.max_response_chunks, 128);
            assert_eq!(blocks.ssz_min, MIN_SIGNED_BEACON_BLOCK_LEN);
            assert_eq!(blocks.ssz_max, caps::MAX_PAYLOAD_SIZE);
        }
        assert_eq!(MAX_REQUEST_PAYLOADS, 128);
        assert_eq!(MAX_REQUEST_DATA_COLUMN_SIDECARS, 128 * 128);
    }

    #[test]
    fn block_minimum_is_a_lower_bound() {
        use crate::testkit;
        let fulu = testkit::fulu_block::<Minimal>(1).as_ssz_bytes().len();
        let gloas = testkit::gloas_block::<Minimal>(1).as_ssz_bytes().len();
        assert!(
            MIN_SIGNED_BEACON_BLOCK_LEN < fulu.min(gloas),
            "{fulu} {gloas}"
        );
        let p = Protocol::BlocksByRangeV2;
        assert_eq!(p.response_bounds::<Minimal>(None), None);
        let gloas_bounds = p.response_bounds::<Minimal>(Some(ForkName::Gloas)).unwrap();
        assert_eq!(gloas_bounds.min, MIN_SIGNED_BEACON_BLOCK_LEN);
        assert_eq!(
            Some(gloas_bounds.max),
            p.response_max_len::<Minimal>(Some(ForkName::Gloas))
        );
        assert_eq!(p.error_bounds(), SszBounds { min: 0, max: 256 });
        assert_eq!(SszBounds::up_to(usize::MAX).max, caps::MAX_PAYLOAD_SIZE);
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
