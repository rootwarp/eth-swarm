//! The req/resp protocols this client speaks, with their payload bounds and response counts.
//!
//! Protocol IDs follow `phase0/p2p-interface.md` "Protocol identification":
//! `/eth2/beacon_chain/req/<message_name>/<version>/<encoding>`, always `ssz_snappy`.
//! `BeaconBlocksByRange` v2, `BeaconBlocksByHead` v1, `BeaconBlocksByRoot` v2 and the two column
//! protocols carry context
//! bytes (`altair/p2p-interface.md`; for a block or a column sidecar the digest of the epoch of
//! its slot, `fulu/p2p-interface.md` L700–702, L766–768, L847–848); the other responses have
//! one shape in every fork.
//! `Goodbye` carries a
//! `uint64` reason both ways ("Request, Response Content", `phase0/p2p-interface.md` L1461): the
//! disconnecting peer writes its reason, and the response is one chunk with a reason too (L1483),
//! though some clients send none.
//!
//! [`ProtocolLimits`] is the one row per protocol the codec and the transport check against: the
//! request ceiling, the response chunk count and the SSZ length bounds of request and response
//! (`phase0/p2p-interface.md` "What are SSZ type size bounds?", L2627). The bounds are the type's
//! own, from `consensus_types::caps`; `MAX_PAYLOAD_SIZE` caps only a type whose bound is larger
//! (`phase0` L1365). A column sidecar's bound depends on the network's blob schedule
//! ([`NetworkCaps`]), so a column chunk is read only with the network's caps
//! ([`Protocol::response_bounds_with`]); the table row holds the preset bound.

use crate::rpc::messages::{
    BlocksByHeadV1Request, BlocksByRangeV2Request, BlocksByRootV2Request,
    DataColumnsByRangeV1Request, DataColumnsByRootIdentifier, DataColumnsByRootV1Request,
    ErrorMessage, Goodbye, MetaDataV3, Ping, StatusV2, MAX_ERROR_MESSAGE_LEN,
};
use consensus_types::caps::{self, NetworkCaps, ObjectKind};
use consensus_types::{forked, EthSpec, ForkName};
use ssz::Encode;
use std::fmt;

/// `MAX_REQUEST_BLOCKS_DENEB` (`deneb/p2p-interface.md` configuration): the most blocks a
/// block response may hold, and the most roots a `BeaconBlocksByRoot` request names. 128 in
/// every known network config.
pub const MAX_REQUEST_BLOCKS_DENEB: u64 = 128;

/// `MAX_REQUEST_PAYLOADS` (`gloas/p2p-interface.md` L84): the most execution payload envelopes
/// one `ExecutionPayloadEnvelopesByRange`/`ByRoot` request may ask for.
pub const MAX_REQUEST_PAYLOADS: u64 = 128;

/// `MAX_REQUEST_DATA_COLUMN_SIDECARS` (`fulu/p2p-interface.md` L174:
/// `MAX_REQUEST_BLOCKS_DENEB * NUMBER_OF_COLUMNS`): the most column sidecars one
/// `DataColumnSidecarsByRange`/`ByRoot` request may ask for.
pub const MAX_REQUEST_DATA_COLUMN_SIDECARS: u64 = 16_384;

/// `NUMBER_OF_COLUMNS` (`fulu/das-core.md`): the most column indices one request names per block,
/// and the bound on every index (`0..NUMBER_OF_COLUMNS`).
pub const NUMBER_OF_COLUMNS: u64 = 128;

/// The shortest Fulu `DataColumnSidecar`: its fixed part, `index` (8), three offsets (12),
/// `signed_block_header` (208) and `kzg_commitments_inclusion_proof` (4 × 32).
pub const MIN_FULU_DATA_COLUMN_SIDECAR_LEN: usize = 8 + 3 * 4 + 208 + 4 * 32;

/// The shortest Gloas `DataColumnSidecar`: its fixed part, `index` (8), two offsets (8), `slot`
/// (8) and `beacon_block_root` (32).
pub const MIN_GLOAS_DATA_COLUMN_SIDECAR_LEN: usize = 8 + 2 * 4 + 8 + 32;

/// The SSZ length of a `DataColumnSidecarsByRange` v1 request: `start_slot` and `count` (16), the
/// `columns` offset (4), then 8 bytes per index, at most `NUMBER_OF_COLUMNS`.
const COLUMNS_BY_RANGE_REQUEST: SszBounds = SszBounds {
    min: 8 + 8 + 4,
    max: 8 + 8 + 4 + 8 * NUMBER_OF_COLUMNS as usize,
};

/// The SSZ length of a `DataColumnSidecarsByRoot` v1 request: per identifier its offset in the
/// list (4), `block_root` (32), the `columns` offset (4) and 8 bytes per index, at most
/// `MAX_REQUEST_BLOCKS_DENEB` identifiers of `NUMBER_OF_COLUMNS` indices each. The empty list is
/// 0 bytes.
const COLUMNS_BY_ROOT_REQUEST: SszBounds = SszBounds {
    min: 0,
    max: MAX_REQUEST_BLOCKS_DENEB as usize * (4 + 32 + 4 + 8 * NUMBER_OF_COLUMNS as usize),
};

/// The SSZ length of a `BeaconBlocksByRoot` v2 request: 32 bytes per root, at most
/// `MAX_REQUEST_BLOCKS_DENEB` roots (`deneb/p2p-interface.md` L78–83). One more root is past the
/// bound, refused at the length prefix (`1: InvalidRequest`).
const BLOCKS_BY_ROOT_REQUEST: SszBounds = SszBounds {
    min: 0,
    max: MAX_REQUEST_BLOCKS_DENEB as usize * 32,
};

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
    /// `/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy`.
    DataColumnsByRangeV1,
    /// `/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy`.
    DataColumnsByRootV1,
    /// `/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy` (Fulu).
    BlocksByHeadV1,
    /// `/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy`.
    BlocksByRootV2,
}

impl Protocol {
    /// Every protocol. New ones go at the end: fuzz seeds select a protocol by its index here.
    pub const ALL: [Protocol; 9] = [
        Protocol::StatusV2,
        Protocol::MetaDataV3,
        Protocol::PingV1,
        Protocol::BlocksByRangeV2,
        Protocol::GoodbyeV1,
        Protocol::DataColumnsByRangeV1,
        Protocol::DataColumnsByRootV1,
        Protocol::BlocksByHeadV1,
        Protocol::BlocksByRootV2,
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
            Protocol::DataColumnsByRangeV1 => {
                "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
            }
            Protocol::DataColumnsByRootV1 => {
                "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
            }
            Protocol::BlocksByHeadV1 => "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy",
            Protocol::BlocksByRootV2 => "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
        }
    }

    /// Whether this is one of the three block protocols, whose responses are blocks.
    pub const fn is_blocks(self) -> bool {
        matches!(
            self,
            Protocol::BlocksByRangeV2 | Protocol::BlocksByHeadV1 | Protocol::BlocksByRootV2
        )
    }

    /// Whether this is one of the two data column protocols.
    pub const fn is_columns(self) -> bool {
        matches!(
            self,
            Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1
        )
    }

    /// Whether a success chunk carries the 4-byte fork digest before its payload.
    pub const fn has_context_bytes(self) -> bool {
        self.is_blocks() || self.is_columns()
    }

    /// Whether the response is exactly one chunk (every protocol but the block and column
    /// protocols, whose responses may hold anything from no chunk to their request's count, and
    /// `Goodbye`, whose one chunk some clients leave out).
    pub const fn single_response(self) -> bool {
        !matches!(self, Protocol::GoodbyeV1) && !self.is_blocks() && !self.is_columns()
    }

    /// Whether a responder may answer `3: ResourceUnavailable` (`phase0/p2p-interface.md` L1291:
    /// "only valid as a response where specified"): `BeaconBlocksByRange` (L1540, for blocks
    /// the responder does not have), `BeaconBlocksByHead` (`fulu/p2p-interface.md` L837–838, a
    /// `beacon_root` older than the serve window), `BeaconBlocksByRoot` (`phase0` L1613–1615, a
    /// root before the serve window), `DataColumnSidecarsByRange` (L654–656,
    /// outside `data_column_serve_range`) and `DataColumnSidecarsByRoot` (L754–756, before
    /// `minimum_request_epoch`).
    pub const fn permits_resource_unavailable(self) -> bool {
        self.is_blocks() || self.is_columns()
    }

    /// This protocol's row of limits.
    pub fn limits<E: EthSpec>(self) -> ProtocolLimits {
        let (max_request_items, max_response_chunks) = match self {
            Protocol::BlocksByRangeV2 | Protocol::BlocksByHeadV1 | Protocol::BlocksByRootV2 => {
                (MAX_REQUEST_BLOCKS_DENEB, MAX_REQUEST_BLOCKS_DENEB)
            }
            Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1 => (
                MAX_REQUEST_DATA_COLUMN_SIDECARS,
                MAX_REQUEST_DATA_COLUMN_SIDECARS,
            ),
            _ => (0, 1),
        };
        let (ssz_min, ssz_max) = match self {
            Protocol::BlocksByRangeV2 | Protocol::BlocksByHeadV1 | Protocol::BlocksByRootV2 => (
                MIN_SIGNED_BEACON_BLOCK_LEN,
                ForkName::ALL
                    .into_iter()
                    .filter_map(|fork| self.response_max_len::<E>(Some(fork)))
                    .max()
                    .unwrap_or(0),
            ),
            // The preset bound: the network's own is at or below it.
            Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1 => {
                let network = Some(&NetworkCaps::PRESET_BOUND);
                let bounds = ForkName::ALL
                    .into_iter()
                    .filter_map(|fork| self.response_bounds_with::<E>(Some(fork), network));
                bounds.fold((usize::MAX, 0), |(min, max), b| {
                    (min.min(b.min), max.max(b.max))
                })
            }
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

    /// The request payload's SSZ length range: one length for a fixed-size request, the list
    /// bounds of a column request. `None` for an empty request.
    pub fn request_bounds(self) -> Option<SszBounds> {
        match self {
            Protocol::DataColumnsByRangeV1 => Some(COLUMNS_BY_RANGE_REQUEST),
            Protocol::DataColumnsByRootV1 => Some(COLUMNS_BY_ROOT_REQUEST),
            Protocol::BlocksByRootV2 => Some(BLOCKS_BY_ROOT_REQUEST),
            _ => self.request_len().map(SszBounds::exactly),
        }
    }

    /// The success payload's SSZ length range at `fork` (which a protocol with context bytes
    /// needs, see [`Protocol::response_max_len`]); `None` where there is no bound to read with,
    /// a column sidecar's included ([`Protocol::response_bounds_with`]).
    pub fn response_bounds<E: EthSpec>(self, fork: Option<ForkName>) -> Option<SszBounds> {
        self.response_bounds_with::<E>(fork, None)
    }

    /// [`Protocol::response_bounds`] with the network's caps, which a column sidecar's bound
    /// needs (`gloas/p2p-interface.md` L321–341): `None` for a column protocol without them.
    pub fn response_bounds_with<E: EthSpec>(
        self,
        fork: Option<ForkName>,
        network: Option<&NetworkCaps>,
    ) -> Option<SszBounds> {
        let max = self.response_max_len_with::<E>(fork, network)?;
        let min = match (self, fork) {
            (
                Protocol::BlocksByRangeV2 | Protocol::BlocksByHeadV1 | Protocol::BlocksByRootV2,
                _,
            ) => MIN_SIGNED_BEACON_BLOCK_LEN,
            (Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1, Some(fork)) => {
                match fork {
                    ForkName::Fulu => MIN_FULU_DATA_COLUMN_SIDECAR_LEN,
                    ForkName::Gloas => MIN_GLOAS_DATA_COLUMN_SIDECAR_LEN,
                }
            }
            _ => max,
        };
        Some(SszBounds { min, max })
    }

    /// The SSZ length of a fixed-size request body, or `None` for a protocol whose request is
    /// empty (`MetaData`: nothing at all is written, not even a length prefix) or variable-size
    /// (the by-root and column requests: [`Protocol::request_bounds`]).
    pub fn request_len(self) -> Option<usize> {
        match self {
            Protocol::StatusV2 => Some(<StatusV2 as ssz::Decode>::ssz_fixed_len()),
            Protocol::MetaDataV3 => None,
            Protocol::PingV1 => Some(<Ping as ssz::Decode>::ssz_fixed_len()),
            Protocol::BlocksByRangeV2 => {
                Some(<BlocksByRangeV2Request as ssz::Decode>::ssz_fixed_len())
            }
            Protocol::GoodbyeV1 => Some(<Goodbye as ssz::Decode>::ssz_fixed_len()),
            Protocol::DataColumnsByRangeV1
            | Protocol::DataColumnsByRootV1
            | Protocol::BlocksByRootV2 => None,
            Protocol::BlocksByHeadV1 => {
                Some(<BlocksByHeadV1Request as ssz::Decode>::ssz_fixed_len())
            }
        }
    }

    /// The largest success payload: the type bound, capped at `MAX_PAYLOAD_SIZE`. A block's
    /// bound depends on its fork, so a protocol with context bytes needs `fork`; `None` there
    /// means the context was not read. A column sidecar's needs the network's caps too:
    /// `None` here, see [`Protocol::response_max_len_with`].
    pub fn response_max_len<E: EthSpec>(self, fork: Option<ForkName>) -> Option<usize> {
        self.response_max_len_with::<E>(fork, None)
    }

    /// [`Protocol::response_max_len`] with the network's caps, for a column sidecar.
    pub fn response_max_len_with<E: EthSpec>(
        self,
        fork: Option<ForkName>,
        network: Option<&NetworkCaps>,
    ) -> Option<usize> {
        match self {
            Protocol::StatusV2 => Some(<StatusV2 as ssz::Decode>::ssz_fixed_len()),
            Protocol::MetaDataV3 => Some(<MetaDataV3 as ssz::Decode>::ssz_fixed_len()),
            Protocol::PingV1 => Some(<Ping as ssz::Decode>::ssz_fixed_len()),
            Protocol::BlocksByRangeV2 | Protocol::BlocksByHeadV1 | Protocol::BlocksByRootV2 => {
                fork.and_then(|f| caps::max_size::<E>(ObjectKind::SignedBeaconBlock, f))
            }
            Protocol::GoodbyeV1 => Some(<Goodbye as ssz::Decode>::ssz_fixed_len()),
            Protocol::DataColumnsByRangeV1 | Protocol::DataColumnsByRootV1 => {
                let (fork, network) = (fork?, network?);
                caps::max_size_for::<E>(ObjectKind::DataColumnSidecar, fork, network)
            }
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
    /// `DataColumnSidecarsByRange` v1.
    DataColumnsByRange(DataColumnsByRangeV1Request),
    /// `DataColumnSidecarsByRoot` v1.
    DataColumnsByRoot(DataColumnsByRootV1Request),
    /// `BeaconBlocksByHead` v1.
    BlocksByHead(BlocksByHeadV1Request),
    /// `BeaconBlocksByRoot` v2.
    BlocksByRoot(BlocksByRootV2Request),
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
            Request::DataColumnsByRange(_) => Protocol::DataColumnsByRangeV1,
            Request::DataColumnsByRoot(_) => Protocol::DataColumnsByRootV1,
            Request::BlocksByHead(_) => Protocol::BlocksByHeadV1,
            Request::BlocksByRoot(_) => Protocol::BlocksByRootV2,
        }
    }

    /// The most response chunks the peer may send: the request's `count` (at most
    /// [`MAX_REQUEST_BLOCKS_DENEB`]) for `BeaconBlocksByRange` and `BeaconBlocksByHead` (whose
    /// larger `count` is served as that many, `fulu/p2p-interface.md` L820–821); the sidecars a
    /// column request names (`count × len(columns)`, L684–685; the sum of the identifiers'
    /// columns, L728–730), at most [`MAX_REQUEST_DATA_COLUMN_SIDECARS`]; the roots a
    /// `BeaconBlocksByRoot` request names; 1 for every other protocol.
    pub fn max_response_chunks(&self) -> u64 {
        match self {
            Request::BlocksByRange(r) => r.count.min(MAX_REQUEST_BLOCKS_DENEB),
            Request::BlocksByHead(r) => r.count.min(MAX_REQUEST_BLOCKS_DENEB),
            Request::BlocksByRoot(r) => r.0.len() as u64,
            Request::DataColumnsByRange(r) => {
                r.requested_sidecars().min(MAX_REQUEST_DATA_COLUMN_SIDECARS)
            }
            Request::DataColumnsByRoot(r) => {
                r.requested_sidecars().min(MAX_REQUEST_DATA_COLUMN_SIDECARS)
            }
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
            Request::DataColumnsByRange(r) => Some(r.as_ssz_bytes()),
            Request::DataColumnsByRoot(r) => Some(r.as_ssz_bytes()),
            Request::BlocksByHead(r) => Some(r.as_ssz_bytes()),
            Request::BlocksByRoot(r) => Some(r.as_ssz_bytes()),
        }
    }
}

/// Why a column request is semantically invalid, if it is (`1: InvalidRequest`): an index at or
/// past `NUMBER_OF_COLUMNS`, or more sidecars than `MAX_REQUEST_DATA_COLUMN_SIDECARS`
/// (`fulu/p2p-interface.md` L746–747; for a range, `count × len(columns)`). The SSZ list bounds
/// (`NUMBER_OF_COLUMNS` indices, `MAX_REQUEST_BLOCKS_DENEB` identifiers) are the decoder's.
pub fn column_request_error(request: &Request) -> Option<String> {
    let (indices, sidecars): (Vec<&u64>, u64) = match request {
        Request::DataColumnsByRange(r) => (r.columns.iter().collect(), r.requested_sidecars()),
        Request::DataColumnsByRoot(r) => (
            r.0.iter()
                .flat_map(|id: &DataColumnsByRootIdentifier| id.columns.iter())
                .collect(),
            r.requested_sidecars(),
        ),
        _ => return None,
    };
    if let Some(index) = indices.into_iter().find(|&&i| i >= NUMBER_OF_COLUMNS) {
        return Some(format!(
            "column index {index} is not below NUMBER_OF_COLUMNS {NUMBER_OF_COLUMNS}"
        ));
    }
    (sidecars > MAX_REQUEST_DATA_COLUMN_SIDECARS).then(|| {
        format!(
            "{sidecars} sidecars requested, above MAX_REQUEST_DATA_COLUMN_SIDECARS \
             {MAX_REQUEST_DATA_COLUMN_SIDECARS}"
        )
    })
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
    /// One block of a block protocol's response, in the fork its context bytes named.
    /// Boxed: a block is far larger than the other responses.
    Block(Box<forked::SignedBeaconBlock<E>>),
    /// `Goodbye`: the responder's reason.
    Goodbye(Goodbye),
    /// One sidecar of a `DataColumnSidecarsByRange` or `DataColumnSidecarsByRoot` response, in
    /// the fork its context bytes named. Boxed: far larger than the other responses.
    DataColumn(Box<forked::DataColumnSidecar<E>>),
}

impl<E: EthSpec> Response<E> {
    /// Whether this is a response of `protocol`: a block answers both block protocols, a
    /// column sidecar both column protocols, every other response its own one.
    pub fn answers(&self, protocol: Protocol) -> bool {
        match self {
            Response::Status(_) => protocol == Protocol::StatusV2,
            Response::MetaData(_) => protocol == Protocol::MetaDataV3,
            Response::Ping(_) => protocol == Protocol::PingV1,
            Response::Block(_) => protocol.is_blocks(),
            Response::Goodbye(_) => protocol == Protocol::GoodbyeV1,
            Response::DataColumn(_) => protocol.is_columns(),
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
            Response::DataColumn(c) => c.as_ssz_bytes(),
        }
    }

    /// The length of [`Self::ssz_bytes`], without encoding it.
    pub fn ssz_bytes_len(&self) -> usize {
        match self {
            Response::Status(s) => s.ssz_bytes_len(),
            Response::MetaData(m) => m.ssz_bytes_len(),
            Response::Ping(p) => p.ssz_bytes_len(),
            Response::Block(b) => b.ssz_bytes_len(),
            Response::Goodbye(g) => g.ssz_bytes_len(),
            Response::DataColumn(c) => c.ssz_bytes_len(),
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
    use crate::testkit;
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
                "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy",
                "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy",
                "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy",
                "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy",
            ]
        );
        assert_eq!(Protocol::PingV1.as_ref(), Protocol::PingV1.to_string());
    }

    #[test]
    fn blocks_and_columns_have_context_bytes() {
        for p in Protocol::ALL {
            let multi = matches!(
                p,
                Protocol::BlocksByRangeV2
                    | Protocol::BlocksByHeadV1
                    | Protocol::BlocksByRootV2
                    | Protocol::DataColumnsByRangeV1
                    | Protocol::DataColumnsByRootV1
            );
            assert_eq!(p.has_context_bytes(), multi, "{p}");
            let single = !multi && p != Protocol::GoodbyeV1;
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
        assert!(response.answers(p));
        assert!(!response.answers(Protocol::PingV1));
        assert_eq!(response.ssz_bytes(), 2u64.to_le_bytes());
    }

    #[test]
    fn only_blocks_and_columns_permit_resource_unavailable() {
        for p in Protocol::ALL {
            let permits = p.is_blocks() || p.is_columns();
            let blocks = matches!(
                p,
                Protocol::BlocksByRangeV2 | Protocol::BlocksByHeadV1 | Protocol::BlocksByRootV2
            );
            assert_eq!(p.is_blocks(), blocks, "{p}");
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
        // `(beacon_root: Root, count: uint64)` (`fulu/p2p-interface.md` L804–808).
        assert_eq!(Protocol::BlocksByHeadV1.request_len(), Some(32 + 8));
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
        // BeaconBlocksByHead: `min(count, MAX_REQUEST_BLOCKS_DENEB)` (`fulu` L820–821).
        for (count, max) in [(0, 0), (1, 1), (128, 128), (129, 128), (u64::MAX, 128)] {
            assert_eq!(head(count).max_response_chunks(), max, "{count}");
        }
        assert_eq!(Request::MetaData.ssz_body(), None);
        assert_eq!(Request::MetaData.protocol(), Protocol::MetaDataV3);
    }

    #[test]
    fn responses_name_their_protocol_and_payload() {
        use crate::testkit;
        let status: Response<Minimal> = Response::Status(testkit::status());
        assert!(status.answers(Protocol::StatusV2));
        assert_eq!(status.ssz_bytes(), testkit::status().as_ssz_bytes());
        let metadata: Response<Minimal> = Response::MetaData(testkit::metadata());
        assert!(metadata.answers(Protocol::MetaDataV3));
        assert_eq!(metadata.ssz_bytes().len(), 25);
        let ping: Response<Minimal> = Response::Ping(Ping(3));
        assert!(ping.answers(Protocol::PingV1));
        assert_eq!(ping.ssz_bytes(), 3u64.to_le_bytes());
        let block = forked::SignedBeaconBlock::Fulu(testkit::fulu_block::<Minimal>(1));
        let ssz = block.as_ssz_bytes();
        let block = Response::Block(Box::new(block));
        for p in Protocol::ALL {
            assert_eq!(block.answers(p), p.is_blocks(), "{p}");
        }
        assert_eq!(block.ssz_bytes(), ssz);
        let sidecar = forked::DataColumnSidecar::Gloas(testkit::gloas_sidecar::<Minimal>(3, 9));
        let ssz = sidecar.as_ssz_bytes();
        let column = Response::DataColumn(Box::new(sidecar));
        for p in Protocol::ALL {
            assert_eq!(column.answers(p), p.is_columns(), "{p}");
        }
        assert_eq!(column.ssz_bytes(), ssz);
        for response in [status, metadata, ping, block, column] {
            assert_eq!(response.ssz_bytes_len(), response.ssz_bytes().len());
        }
        let goodbye: Response<Minimal> = Response::Goodbye(Goodbye(3));
        assert_eq!(goodbye.ssz_bytes_len(), 8);
    }

    fn head(count: u64) -> Request {
        Request::BlocksByHead(BlocksByHeadV1Request {
            beacon_root: [7; 32].into(),
            count,
        })
    }

    /// #230: BeaconBlocksByHead v1 (`fulu/p2p-interface.md` L796–863), new in Fulu: last in
    /// `ALL` (fuzz seeds pick a protocol by its index there), context bytes per block, any
    /// number of chunks up to `count`, `3: ResourceUnavailable` permitted (L837–838), a fixed
    /// 40-byte request and the block bounds of BeaconBlocksByRange v2 at every fork. The
    /// request body is its SSZ container.
    #[test]
    fn blocks_by_head_row() {
        use consensus_types::Mainnet;
        let p = Protocol::BlocksByHeadV1;
        assert_eq!(
            p.id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy"
        );
        assert_eq!(Protocol::ALL[7], p, "new protocols go at the end");
        assert!(p.has_context_bytes());
        assert!(!p.single_response());
        assert!(p.permits_resource_unavailable());
        assert_eq!(p.request_bounds(), Some(SszBounds::exactly(40)));
        let range = Protocol::BlocksByRangeV2;
        assert_eq!(p.response_bounds::<Minimal>(None), None);
        for fork in ForkName::ALL {
            assert_eq!(
                p.response_bounds::<Mainnet>(Some(fork)),
                range.response_bounds::<Mainnet>(Some(fork)),
                "{fork}"
            );
        }
        for (row, by_range) in [
            (p.limits::<Minimal>(), range.limits::<Minimal>()),
            (p.limits::<Mainnet>(), range.limits::<Mainnet>()),
        ] {
            assert_eq!(row.id, p.id());
            assert_eq!(row.request, Some(SszBounds::exactly(40)));
            assert_eq!(
                (row.max_request_items, row.max_response_chunks),
                (MAX_REQUEST_BLOCKS_DENEB, MAX_REQUEST_BLOCKS_DENEB)
            );
            assert_eq!(
                (row.ssz_min, row.ssz_max),
                (by_range.ssz_min, by_range.ssz_max)
            );
        }
        let request = head(129);
        assert_eq!(request.protocol(), p);
        let body = request.ssz_body().unwrap();
        assert_eq!(body, [&[7; 32][..], &129u64.to_le_bytes()].concat());
    }

    /// BeaconBlocksByRoot v2 (`phase0/p2p-interface.md` L1577–1626, `deneb` L78–83, `gloas`
    /// L1376–1394): last in `ALL`, context bytes per block, any number of chunks up to the
    /// roots named, `3: ResourceUnavailable` permitted (L1613–1615), the block bounds of
    /// BeaconBlocksByRange v2, and a request of at most `MAX_REQUEST_BLOCKS_DENEB` roots: one
    /// more is past the SSZ bound.
    #[test]
    fn blocks_by_root_row() {
        use crate::rpc::codec::{decode_request, encode_chunk};
        use crate::rpc::messages::BlocksByRootV2Request;
        use consensus_types::Mainnet;
        let p = Protocol::BlocksByRootV2;
        assert_eq!(
            p.id(),
            "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
        );
        assert_eq!(
            Protocol::ALL.last(),
            Some(&p),
            "new protocols go at the end"
        );
        assert_eq!(Protocol::ALL.len(), 9);
        assert!(p.is_blocks() && p.has_context_bytes() && !p.single_response());
        assert!(p.permits_resource_unavailable());
        assert_eq!(p.request_len(), None);
        assert_eq!(p.request_bounds(), Some(SszBounds { min: 0, max: 4096 }));
        let range = Protocol::BlocksByRangeV2;
        for fork in ForkName::ALL {
            assert_eq!(
                p.response_bounds::<Mainnet>(Some(fork)),
                range.response_bounds::<Mainnet>(Some(fork)),
                "{fork}"
            );
        }
        let (row, by_range) = (p.limits::<Mainnet>(), range.limits::<Mainnet>());
        assert_eq!(
            (row.max_request_items, row.max_response_chunks),
            (MAX_REQUEST_BLOCKS_DENEB, MAX_REQUEST_BLOCKS_DENEB)
        );
        assert_eq!(
            (row.ssz_min, row.ssz_max),
            (by_range.ssz_min, by_range.ssz_max)
        );
        let roots = |n: u8| {
            let roots: Vec<_> = (0..n).map(|i| [i; 32].into()).collect();
            Request::BlocksByRoot(BlocksByRootV2Request(roots.try_into().unwrap()))
        };
        for n in [0, 1, 128] {
            let request = roots(n);
            assert_eq!(request.protocol(), p);
            assert_eq!(request.max_response_chunks(), u64::from(n));
            let body = request.ssz_body().unwrap();
            assert_eq!(body.len(), 32 * usize::from(n));
            let wire = encode_chunk(&body).unwrap();
            assert_eq!(decode_request(p, &wire).unwrap(), request, "{n}");
        }
        // 129 roots: past `BeaconBlockRoots`' limit, refused at the length prefix.
        let over: Vec<u8> = (0..129u8).flat_map(|i| [i; 32]).collect();
        assert!(decode_request(p, &encode_chunk(&over).unwrap()).is_err());
        // Not a whole number of roots.
        assert!(decode_request(p, &encode_chunk(&[7; 33]).unwrap()).is_err());
    }

    fn by_range(start_slot: u64, count: u64, columns: Vec<u64>) -> Request {
        Request::DataColumnsByRange(DataColumnsByRangeV1Request {
            start_slot,
            count,
            columns: columns.try_into().unwrap(),
        })
    }

    fn by_root(ids: Vec<(u8, Vec<u64>)>) -> Request {
        let ids: Vec<_> = ids
            .into_iter()
            .map(|(byte, columns)| DataColumnsByRootIdentifier {
                block_root: consensus_types::primitives::B256::repeat_byte(byte),
                columns: columns.try_into().unwrap(),
            })
            .collect();
        Request::DataColumnsByRoot(DataColumnsByRootV1Request(ids.try_into().unwrap()))
    }

    #[test]
    fn column_requests_count_their_sidecars() {
        let range = by_range(64, 32, vec![1, 47, 87, 102]);
        assert_eq!(range.protocol(), Protocol::DataColumnsByRangeV1);
        assert_eq!(range.max_response_chunks(), 128);
        assert_eq!(column_request_error(&range), None);
        // At most MAX_REQUEST_DATA_COLUMN_SIDECARS, however many are named.
        let huge = by_range(0, u64::MAX, vec![0, 1]);
        assert_eq!(huge.max_response_chunks(), MAX_REQUEST_DATA_COLUMN_SIDECARS);
        assert!(column_request_error(&huge).unwrap().contains("above"));
        assert_eq!(
            column_request_error(&by_range(0, 128, (0..128).collect())),
            None
        );
        assert!(column_request_error(&by_range(0, 129, (0..128).collect())).is_some());
        let past = by_range(0, 1, vec![128]);
        assert!(column_request_error(&past).unwrap().contains("128"));
        let root = by_root(vec![(1, vec![1, 47]), (2, vec![87])]);
        assert_eq!(root.protocol(), Protocol::DataColumnsByRootV1);
        assert_eq!(root.max_response_chunks(), 3);
        assert_eq!(column_request_error(&root), None);
        assert!(column_request_error(&by_root(vec![(1, vec![5, 200])])).is_some());
        assert_eq!(column_request_error(&Request::MetaData), None);
    }

    #[test]
    fn column_request_bounds_are_their_ssz_lists() {
        let range = Protocol::DataColumnsByRangeV1.request_bounds().unwrap();
        assert_eq!(by_range(0, 1, vec![]).ssz_body().unwrap().len(), range.min);
        let full = by_range(0, 1, (0..128).collect()).ssz_body().unwrap();
        assert_eq!(full.len(), range.max);
        let root = Protocol::DataColumnsByRootV1.request_bounds().unwrap();
        assert_eq!(by_root(vec![]).ssz_body().unwrap().len(), root.min);
        let ids = (0..128).map(|i| (i as u8, (0..128).collect())).collect();
        assert_eq!(by_root(ids).ssz_body().unwrap().len(), root.max);
        assert_eq!(Protocol::DataColumnsByRangeV1.request_len(), None);
    }

    #[test]
    fn column_sidecar_bounds_need_the_network() {
        use consensus_types::Mainnet;
        let network = NetworkCaps::from_blob_schedule(21, &[]);
        for p in [
            Protocol::DataColumnsByRangeV1,
            Protocol::DataColumnsByRootV1,
        ] {
            assert_eq!(p.response_bounds::<Mainnet>(Some(ForkName::Gloas)), None);
            assert_eq!(p.response_max_len::<Mainnet>(Some(ForkName::Fulu)), None);
            assert_eq!(
                p.response_bounds_with::<Mainnet>(None, Some(&network)),
                None
            );
            let gloas = p
                .response_bounds_with::<Mainnet>(Some(ForkName::Gloas), Some(&network))
                .unwrap();
            assert_eq!(gloas.min, MIN_GLOAS_DATA_COLUMN_SIDECAR_LEN);
            assert_eq!(
                gloas.max as u64,
                caps::compute_max_data_column_sidecar_size::<Mainnet>(&network)
            );
            let fulu = p
                .response_bounds_with::<Mainnet>(Some(ForkName::Fulu), Some(&network))
                .unwrap();
            assert_eq!(fulu.min, MIN_FULU_DATA_COLUMN_SIDECAR_LEN);
            assert!(fulu.max > fulu.min);
            let row = p.limits::<Mainnet>();
            assert_eq!(row.ssz_min, MIN_GLOAS_DATA_COLUMN_SIDECAR_LEN);
            assert!(row.ssz_max >= fulu.max.max(gloas.max));
            assert_eq!(row.max_response_chunks, MAX_REQUEST_DATA_COLUMN_SIDECARS);
        }
        // The fixed parts are the shortest sidecars of each fork.
        let empty_gloas = testkit::gloas_sidecar::<Mainnet>(0, 0);
        let empty_gloas = consensus_types::gloas::DataColumnSidecar::<Mainnet> {
            column: Default::default(),
            kzg_proofs: Default::default(),
            ..empty_gloas
        };
        assert_eq!(
            empty_gloas.as_ssz_bytes().len(),
            MIN_GLOAS_DATA_COLUMN_SIDECAR_LEN
        );
        let empty_fulu = testkit::fulu_sidecar::<Mainnet>(0, 0);
        let empty_fulu = consensus_types::fulu::DataColumnSidecar::<Mainnet> {
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            ..empty_fulu
        };
        assert_eq!(
            empty_fulu.as_ssz_bytes().len(),
            MIN_FULU_DATA_COLUMN_SIDECAR_LEN
        );
    }
}
