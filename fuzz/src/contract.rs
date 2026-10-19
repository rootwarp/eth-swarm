//! The gate-2b target, `column_contract`: cl-chain's storage contract and column store, then its
//! column RPCs, driven with arbitrary sidecars and requests (`gloas/p2p-interface.md`
//! L1286–1325, `fulu/p2p-interface.md` L605–790).
//!
//! # The probe, in process
//!
//! Each input gets a probe of its own, built from cl-chain's production parts:
//!
//! - **The column store**: `ColumnIngest` (pending queue, root wait, storage contract, writer
//!   thread) with the default `IngestLimits`, on a temp `cl-chain-columns` env (one directory per
//!   input, removed when the input ends). Its map is at most `MIN_MAX_SIZE` (256 MiB), so the
//!   gate's `-rss_limit_mb=2048` covers the whole map with room for everything else.
//! - **The reference**: a stub Beacon API that vouches for the eight fixed blocks of
//!   [`CHAIN`] (their headers and SSZ, through the real `RefView`), and for no other root.
//! - **cl-verify**: a stub whose verdict comes from the input: the first byte of the first proof
//!   ([`kzg_verdict`]).
//! - **Custody**: node `U256::MAX` (columns [`CUSTODY`]), set at [`cgc_set_slot`].
//! - **The column RPCs**: `ReqRespServer` over `ColumnServer`, called in process with the
//!   chain.v1 requests cl-p2p sends (our hello in line) and read as cl-p2p reads them.
//!
//! The runtime's clock is paused, so the root wait and its retries take no wall time.
//!
//! # The input: a sequence of operations
//!
//! Each operation starts with a byte whose value modulo [`OPS`] picks it:
//!
//! - [`OP_GOSSIP`]: five bytes describe a sidecar of a fixed block ([`GossipSpec`]), which goes
//!   to `ColumnIngest::on_column` as cl-p2p hands it over.
//! - [`OP_RAW_GOSSIP`]: a subnet byte, a 2-byte little-endian length, then the `data` of a gossip
//!   message on `data_column_sidecar_{subnet}`: the snappy transform, the decode by the fork of
//!   the sidecar's slot, then `on_column` (a message that does not decode to a Gloas sidecar
//!   goes no further, as in cl-p2p).
//! - [`OP_RANGE`] and [`OP_ROOT`]: a request described by bytes ([`RangeSpec`], [`RootSpec`]).
//! - [`OP_RAW_RANGE`] and [`OP_RAW_ROOT`]: a 3-byte little-endian length, then one inbound
//!   request on the wire, read by the timed codec and the request decoder (held to each other as
//!   in the request targets).
//!
//! A request goes to cl-chain whatever cl-p2p would make of it, so cl-chain's own bounds are
//! fuzzed too. An input holds at most [`MAX_GOSSIP`] sidecars and [`MAX_REQUESTS`] requests;
//! parsing stops at the first operation past them or cut short.
//!
//! # The invariants
//!
//! After each sidecar the store has settled (nothing queued), and:
//!
//! - the sidecar ended exactly once: stored, or dropped for one reason, never queue-full (one
//!   sidecar at a time never fills the queue); its verdict was IGNORE;
//! - the outcome is the contract's, checked in its order ([`expected`]): structure, subnet,
//!   custody, forward only, root, slot, commitments, KZG. A root the reference does not know is
//!   dropped as `unknown_root`, `root_timeout` or `root_wait_full`;
//! - cl-verify was asked about exactly the sidecar's cells against its block's bid commitments,
//!   at its index, if and only if the sidecar passed every check before KZG;
//! - the store holds exactly the copies the contract accepted, the last one per
//!   `(root, index)`.
//!
//! Every response is a hello, then sidecar chunks with `seq` from 1, each envelope passing the
//! link's type and digest checks and naming its sidecar's slot and root, then at most one error
//! chunk, last; no read fails. Then:
//!
//! - **a sidecar the contract rejected never appears in a response**: every sidecar served was
//!   accepted earlier, and is the copy stored last for its `(root, index)`;
//! - a request is refused `1: InvalidRequest` exactly when cl-chain's bounds refuse it
//!   (`range_request_bounds`, `root_request_bounds`), which agree with the spec rule and with
//!   cl-p2p's admission check; any other refusal is `3: ResourceUnavailable`;
//! - by range: nothing below `earliest_available_slot` or outside the range, only requested
//!   custody columns, every block whole, in `(slot, index)` order, one chain (each block an
//!   ancestor of the next); naming nothing is an empty success, and anything else with nothing
//!   stored is `3`;
//! - by root: exactly the requested pairs stored at or above `earliest_available_slot`, per
//!   identifier in request order, each pair once.

use crate::columns::request_verdicts;
use crate::{column_network, column_schedule, column_topic, column_transform, E};
use cl_chain::da::custody::{Advertise, Custody, EnrCgc, EnrError};
use cl_chain::probe::ingest::PENDING_LINK_SLOTS;
use cl_chain::probe::{
    ApiError, BlockApi, Checkpoint, ColumnContract, ColumnIngest, ColumnMetrics, Drop,
    GossipColumn, Header, IngestLimits, QueueMetrics, RefLimits, RefView, ReferenceApi, Root,
};
use cl_chain::reqresp::{ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock};
use cl_chain::verify::client::{KzgOutcome, KzgVerifier};
use cl_chain_columns::{ColumnWriter, WriterOptions, MIN_MAX_SIZE};
use consensus_types::das::compute_subnet_for_data_column_sidecar;
use consensus_types::primitives::U256;
use consensus_types::{forked, gloas, EthSpec, ForkName};
use ethswarm_proto::chain as pb;
use ethswarm_proto::common::{Envelope, ErrorCode, Hello, PayloadType, Verdict};
use ethswarm_proto::verify::KzgCellProof;
use futures::StreamExt;
use ipc::envelope::DigestTable;
use ipc::stub::StubStream;
use ipc::Link;
use p2p_wire::rpc::messages::{
    DataColumnsByRangeV1Request, DataColumnsByRootIdentifier, DataColumnsByRootV1Request,
};
use p2p_wire::rpc::protocols::{Protocol, Request};
use p2p_wire::testkit;
use pb::req_resp_service_server::ReqRespService;
use ssz::{Decode, Encode};
use ssz_types::typenum::Unsigned;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use tree_hash::TreeHash;

/// A structured sidecar of a fixed block ([`GossipSpec`]).
pub const OP_GOSSIP: u8 = 0;
/// A gossip message's `data` on a column subnet.
pub const OP_RAW_GOSSIP: u8 = 1;
/// A structured `DataColumnSidecarsByRange` request ([`RangeSpec`]).
pub const OP_RANGE: u8 = 2;
/// A structured `DataColumnSidecarsByRoot` request ([`RootSpec`]).
pub const OP_ROOT: u8 = 3;
/// A `DataColumnSidecarsByRange` v1 request on the wire.
pub const OP_RAW_RANGE: u8 = 4;
/// A `DataColumnSidecarsByRoot` v1 request on the wire.
pub const OP_RAW_ROOT: u8 = 5;
/// An operation byte picks `byte % OPS`.
pub const OPS: u8 = 6;

/// Sidecars one input sends at most: each one is a write to the column env.
pub const MAX_GOSSIP: usize = 24;
/// Requests one input sends at most.
pub const MAX_REQUESTS: usize = 24;

/// [`GossipSpec::block`]: with this bit set the sidecar names a root the reference does not know
/// (the fixed block's root with its last byte changed).
pub const UNKNOWN_ROOT: u8 = 0x80;
/// [`GossipSpec::flags`]: the sidecar arrives on the subnet after its own.
pub const WRONG_SUBNET: u8 = 0x01;
/// [`GossipSpec::flags`]: the sidecar names the slot after its block's.
pub const SLOT_AFTER: u8 = 0x02;
/// [`GossipSpec::flags`]: one cell more than the bid has commitments.
pub const EXTRA_CELL: u8 = 0x04;
/// [`GossipSpec::flags`]: one cell fewer than the bid has commitments.
pub const MISSING_CELL: u8 = 0x08;
/// [`GossipSpec::flags`]: one proof fewer than cells.
pub const MISSING_PROOF: u8 = 0x10;

/// [`kzg_verdict`] of a first proof starting with this byte: valid.
pub const KZG_VALID: u8 = 0;
/// [`kzg_verdict`]: invalid.
pub const KZG_INVALID: u8 = 1;
/// [`kzg_verdict`]: no verdict (cl-verify silent or overloaded).
pub const KZG_NO_VERDICT: u8 = 2;

/// The custody columns of node `U256::MAX` (`get_custody_groups(U256::MAX, 4)`).
pub const CUSTODY: [u64; 4] = [1, 47, 87, 102];

/// The blocks the stub reference vouches for, `(slot after the first, parent, blobs)`: the first
/// (`P`) is before [`cgc_set_slot`]; `A` at it starts the stored chain; `C` carries no blobs, so
/// `D` links through it to `B`; `F` is another branch at `D`'s slot, and `H` follows it a slot
/// later than the gap.
pub const CHAIN: [(u64, Option<usize>, usize); 8] = [
    (0, None, 2),
    (1, Some(0), 2),
    (2, Some(1), 1),
    (3, Some(2), 0),
    (4, Some(3), 2),
    (4, Some(2), 1),
    (5, Some(4), 3),
    (7, Some(5), 1),
];

/// How far the first block of [`CHAIN`] is past the first Gloas slot.
const CHAIN_OFFSET: u64 = 63;
/// The serve range ends this far past the first Gloas slot.
const SERVE_SPAN: u64 = 4096;

/// One block the stub reference vouches for.
#[derive(Debug, Clone)]
pub struct KnownBlock {
    pub slot: u64,
    pub root: Root,
    /// Its parent in [`CHAIN`], if it has one there.
    pub parent: Option<usize>,
    /// The bid's `blob_kzg_commitments`.
    pub commitments: Vec<[u8; 48]>,
    ssz: Vec<u8>,
}

/// The first slot of the Gloas fork on the pinned Sepolia schedule (the mainnet preset).
pub fn gloas_slot() -> u64 {
    column_schedule()
        .fork_epoch(ForkName::Gloas)
        .expect("Sepolia schedules Gloas")
        * E::slots_per_epoch()
}

/// The slot custody is set at: the second block of [`CHAIN`].
pub fn cgc_set_slot() -> u64 {
    gloas_slot() + CHAIN_OFFSET + 1
}

/// The blocks of [`CHAIN`], built once.
pub fn known_blocks() -> &'static [KnownBlock] {
    static BLOCKS: OnceLock<Vec<KnownBlock>> = OnceLock::new();
    BLOCKS.get_or_init(|| {
        let first = gloas_slot() + CHAIN_OFFSET;
        let mut blocks: Vec<KnownBlock> = Vec::new();
        for (i, &(offset, parent, blobs)) in CHAIN.iter().enumerate() {
            let slot = first + offset;
            let mut block = testkit::gloas_block::<E>(slot);
            if let Some(p) = parent {
                block.message.parent_root = blocks[p].root.into();
            }
            let commitments: Vec<[u8; 48]> = (0..blobs)
                .map(|row| {
                    let mut c = [0xc0 | i as u8; 48];
                    c[47] = row as u8;
                    c
                })
                .collect();
            block
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments = commitments.clone().try_into().expect("a few commitments");
            blocks.push(KnownBlock {
                slot,
                root: block.message.tree_hash_root().0,
                parent,
                commitments,
                ssz: block.as_ssz_bytes(),
            });
        }
        blocks
    })
}

fn known(root: &Root) -> Option<&'static KnownBlock> {
    known_blocks().iter().find(|b| b.root == *root)
}

/// The stub cl-verify's verdict on a batch whose first proof is `first_proof`: by its first
/// byte, [`KZG_VALID`] (and 3) valid, [`KZG_INVALID`] invalid, [`KZG_NO_VERDICT`] none.
pub fn kzg_verdict(first_proof: Option<&[u8]>) -> KzgOutcome {
    match first_proof.and_then(|p| p.first()).map(|b| b & 3) {
        Some(KZG_INVALID) => KzgOutcome::Invalid,
        Some(KZG_NO_VERDICT) => KzgOutcome::NoVerdict("the stub has no verdict".into()),
        _ => KzgOutcome::Valid,
    }
}

/// [`OP_GOSSIP`]'s five bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipSpec {
    /// Bits 0-2: the block of [`CHAIN`]; [`UNKNOWN_ROOT`]: a root the reference does not know.
    pub block: u8,
    /// The column index (128 and up are past `NUMBER_OF_COLUMNS`).
    pub index: u8,
    /// [`WRONG_SUBNET`], [`SLOT_AFTER`], [`EXTRA_CELL`], [`MISSING_CELL`], [`MISSING_PROOF`].
    pub flags: u8,
    /// The first byte of the first proof: the KZG verdict ([`kzg_verdict`]).
    pub verdict: u8,
    /// Every other cell and proof byte, so two copies can differ.
    pub fill: u8,
}

impl GossipSpec {
    pub fn bytes(self) -> [u8; 6] {
        [
            OP_GOSSIP,
            self.block,
            self.index,
            self.flags,
            self.verdict,
            self.fill,
        ]
    }

    /// The sidecar and the subnet it arrives on.
    pub fn column(self) -> GossipColumn<E> {
        let block = &known_blocks()[usize::from(self.block & 7)];
        let mut root = block.root;
        if self.block & UNKNOWN_ROOT != 0 {
            root[31] ^= 0x5a;
        }
        let index = u64::from(self.index);
        let blobs = block.commitments.len();
        let cells = if self.flags & EXTRA_CELL != 0 {
            blobs + 1
        } else if self.flags & MISSING_CELL != 0 {
            blobs.saturating_sub(1)
        } else {
            blobs
        };
        let proofs = if self.flags & MISSING_PROOF != 0 {
            cells.saturating_sub(1)
        } else {
            cells
        };
        let cell_len = <E as EthSpec>::BytesPerCell::to_usize();
        let column: Vec<_> = (0..cells)
            .map(|row| {
                let mut cell = vec![self.fill; cell_len];
                cell[0] = row as u8;
                cell.try_into().expect("BYTES_PER_CELL bytes")
            })
            .collect();
        let kzg_proofs: Vec<[u8; 48]> = (0..proofs)
            .map(|row| {
                let mut proof = [self.fill; 48];
                if row == 0 {
                    proof[0] = self.verdict;
                }
                proof
            })
            .collect();
        let subnet = compute_subnet_for_data_column_sidecar(index);
        GossipColumn {
            sidecar: gloas::DataColumnSidecar {
                index,
                column: column.try_into().expect("an unbounded list"),
                kzg_proofs: kzg_proofs.try_into().expect("an unbounded list"),
                slot: block.slot + u64::from(self.flags & SLOT_AFTER != 0),
                beacon_block_root: root.into(),
            },
            subnet_id: if self.flags & WRONG_SUBNET != 0 {
                (subnet + 1) % 128
            } else {
                subnet
            },
        }
    }
}

/// [`OP_RANGE`]: a start byte (the slot before the first block of [`CHAIN`], plus the byte), a
/// count byte (0 to 251 as is; 252: 129, 253: 8,192, 254: 16,385, 255: `u64::MAX`), then a byte
/// with the number of columns (at most 128) and one byte per column index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeSpec {
    pub start: u8,
    pub count: u8,
    pub columns: Vec<u8>,
}

impl RangeSpec {
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![OP_RANGE, self.start, self.count, self.columns.len() as u8];
        out.extend(&self.columns);
        out
    }

    pub fn request(&self) -> DataColumnsByRangeV1Request {
        DataColumnsByRangeV1Request {
            start_slot: gloas_slot() + CHAIN_OFFSET - 1 + u64::from(self.start),
            count: match self.count {
                252 => 129,
                253 => 8_192,
                254 => 16_385,
                255 => u64::MAX,
                n => u64::from(n),
            },
            columns: self
                .columns
                .iter()
                .map(|&i| u64::from(i))
                .collect::<Vec<_>>()
                .try_into()
                .expect("at most NUMBER_OF_COLUMNS columns"),
        }
    }
}

/// [`OP_ROOT`]: a byte with the number of identifiers (at most 128), then per identifier a block
/// byte (as [`GossipSpec::block`]), a byte with its number of columns (at most 128) and one byte
/// per column index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSpec {
    pub ids: Vec<(u8, Vec<u8>)>,
}

impl RootSpec {
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = vec![OP_ROOT, self.ids.len() as u8];
        for (block, columns) in &self.ids {
            out.extend([*block, columns.len() as u8]);
            out.extend(columns);
        }
        out
    }

    pub fn request(&self) -> DataColumnsByRootV1Request {
        let ids: Vec<_> = self
            .ids
            .iter()
            .map(|(block, columns)| {
                let mut root = known_blocks()[usize::from(block & 7)].root;
                if block & UNKNOWN_ROOT != 0 {
                    root[31] ^= 0x5a;
                }
                DataColumnsByRootIdentifier {
                    block_root: root.into(),
                    columns: columns
                        .iter()
                        .map(|&i| u64::from(i))
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("at most NUMBER_OF_COLUMNS columns"),
                }
            })
            .collect();
        DataColumnsByRootV1Request(ids.try_into().expect("at most 128 identifiers"))
    }
}

/// `data` as an [`OP_RAW_GOSSIP`] on `subnet` (`data` at most 65,535 bytes).
pub fn raw_gossip(subnet: u8, data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).expect("a 2-byte length");
    let mut out = vec![OP_RAW_GOSSIP, subnet];
    out.extend(len.to_le_bytes());
    out.extend(data);
    out
}

/// `wire` as an [`OP_RAW_RANGE`] or [`OP_RAW_ROOT`] (`wire` under 16 MiB).
pub fn raw_request(op: u8, wire: &[u8]) -> Vec<u8> {
    let len = u32::try_from(wire.len()).expect("a small request");
    assert!(len < 1 << 24, "a 3-byte length");
    let mut out = vec![op];
    out.extend(&len.to_le_bytes()[..3]);
    out.extend(wire);
    out
}

/// One parsed operation.
enum Op {
    /// A sidecar for `on_column`; `None` if the message did not decode to a Gloas sidecar.
    Gossip(Option<GossipColumn<E>>),
    /// A request; `None` if the wire bytes did not decode to one.
    Request(Option<Request>),
}

/// The input, read from the front.
struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    /// A count byte, at most `max`.
    fn count(&mut self, max: u8) -> Option<usize> {
        self.byte().map(|n| usize::from(n.min(max)))
    }

    fn len_le(&mut self, bytes: usize) -> Option<usize> {
        let raw = self.take(bytes)?;
        Some(raw.iter().rev().fold(0, |n, &b| n << 8 | usize::from(b)))
    }
}

/// Parses `data` into operations (see the module docs); the raw ones go through the gossip
/// transform or the request codec here, before the probe starts.
fn parse(data: &[u8]) -> Vec<Op> {
    let mut input = Input(data);
    let mut ops = Vec::new();
    let (mut sidecars, mut requests) = (0, 0);
    while let Some(op) = input.byte() {
        let gossip = matches!(op % OPS, OP_GOSSIP | OP_RAW_GOSSIP);
        if (gossip && sidecars == MAX_GOSSIP) || (!gossip && requests == MAX_REQUESTS) {
            break;
        }
        let parsed = match op % OPS {
            OP_GOSSIP => input.take(5).map(|b| {
                let spec = GossipSpec {
                    block: b[0],
                    index: b[1],
                    flags: b[2],
                    verdict: b[3],
                    fill: b[4],
                };
                Op::Gossip(Some(spec.column()))
            }),
            OP_RAW_GOSSIP => (|| {
                let subnet = input.byte()?;
                let len = input.len_le(2)?;
                let data = input.take(len)?;
                Some(Op::Gossip(decode_gossip(subnet, data)))
            })(),
            OP_RANGE => (|| {
                let start = input.byte()?;
                let count = input.byte()?;
                let n = input.count(128)?;
                let columns = input.take(n)?.to_vec();
                let spec = RangeSpec {
                    start,
                    count,
                    columns,
                };
                Some(Op::Request(Some(Request::DataColumnsByRange(
                    spec.request(),
                ))))
            })(),
            OP_ROOT => (|| {
                let n = input.count(128)?;
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    let block = input.byte()?;
                    let len = input.count(128)?;
                    ids.push((block, input.take(len)?.to_vec()));
                }
                let spec = RootSpec { ids };
                Some(Op::Request(Some(Request::DataColumnsByRoot(
                    spec.request(),
                ))))
            })(),
            raw => (|| {
                let len = input.len_le(3)?;
                let wire = input.take(len)?;
                let protocol = if raw == OP_RAW_RANGE {
                    Protocol::DataColumnsByRangeV1
                } else {
                    Protocol::DataColumnsByRootV1
                };
                Some(Op::Request(crate::request(protocol, wire)))
            })(),
        };
        let Some(parsed) = parsed else {
            break;
        };
        match parsed {
            Op::Gossip(_) => sidecars += 1,
            Op::Request(_) => requests += 1,
        }
        ops.push(parsed);
    }
    ops
}

/// A gossip message's `data` on the column subnet `subnet % 128`, as cl-p2p takes it: the snappy
/// transform, then the decode by the fork of the sidecar's slot. Only a Gloas sidecar goes on.
fn decode_gossip(subnet: u8, data: &[u8]) -> Option<GossipColumn<E>> {
    let subnet = subnet % 128;
    let ssz = column_transform()
        .inbound(&column_topic(subnet), data)
        .ok()?;
    let decoded = forked::DataColumnSidecar::<E>::from_ssz_bytes_by_slot(
        &ssz,
        column_schedule(),
        column_network(),
    );
    match decoded {
        Ok(forked::DataColumnSidecar::Gloas(sidecar)) => Some(GossipColumn {
            sidecar,
            subnet_id: u64::from(subnet),
        }),
        _ => None,
    }
}

/// What happened to one operation, for the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A sidecar: stored, or dropped with its reason. `None`: it never reached cl-chain.
    Gossip(Option<Result<(), Drop>>),
    /// A request: what cl-chain answered. `None`: it never reached cl-chain.
    Answer(Option<Answer>),
}

/// What cl-chain answered a column request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// A success: these sidecars `(slot, root, index)`, in order.
    Sidecars(Vec<(u64, Root, u64)>),
    /// One error chunk with this code.
    Refused(ErrorCode),
}

/// The ENR is not under test.
struct NoEnr;

impl EnrCgc for NoEnr {
    fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
        Ok(())
    }
}

/// The stub reference: [`known_blocks`] and nothing else.
struct Reference;

impl ReferenceApi for Reference {
    async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
        Err(ApiError("the Status is not under test".into()))
    }

    async fn header(&self, root: Root) -> Result<Header, ApiError> {
        known(&root)
            .map(|b| Header { root, slot: b.slot })
            .ok_or_else(|| ApiError("404".into()))
    }
}

impl BlockApi for Reference {
    async fn block(&self, root: Root) -> Result<Vec<u8>, ApiError> {
        known(&root)
            .map(|b| b.ssz.clone())
            .ok_or_else(|| ApiError("404".into()))
    }
}

/// The stub cl-verify: [`kzg_verdict`], every batch it was asked about kept.
#[derive(Clone, Default)]
struct Kzg {
    asked: Arc<Mutex<Vec<Vec<KzgCellProof>>>>,
}

impl Kzg {
    fn take(&self) -> Vec<Vec<KzgCellProof>> {
        std::mem::take(&mut *self.asked.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl KzgVerifier for Kzg {
    async fn verify_cells(&self, cells: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
        let outcome = kzg_verdict(cells.first().map(|c| c.proof.as_slice()));
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(cells);
        outcome
    }
}

/// The serve range: from the first Gloas slot, [`SERVE_SPAN`] slots; the digest of each slot's
/// fork.
struct Clock;

impl ServeClock for Clock {
    fn serve_range(&self) -> Option<(u64, u64)> {
        Some((gloas_slot(), gloas_slot() + SERVE_SPAN))
    }

    fn fork_digest(&self, slot: u64) -> Option<[u8; 4]> {
        Some(if slot >= gloas_slot() {
            testkit::GLOAS_DIGEST
        } else {
            testkit::FULU_DIGEST
        })
    }
}

/// The chain.v1 link both ends hold: our hello, the Sepolia schedule and the fixture digests.
fn link() -> Link {
    let schedule = column_schedule();
    let epoch = |fork| schedule.fork_epoch(fork).expect("Sepolia schedules it");
    let digests = DigestTable::new(vec![
        (epoch(ForkName::Fulu), ForkName::Fulu, testkit::FULU_DIGEST),
        (
            epoch(ForkName::Gloas),
            ForkName::Gloas,
            testkit::GLOAS_DIGEST,
        ),
    ])
    .expect("two digests");
    let hello = Hello {
        api_version: 1,
        min_api_version: 1,
        max_api_version: 1,
        ..Default::default()
    };
    Link::new::<E>(hello, 1, *schedule, digests)
}

type Ingest = ColumnIngest<Reference, E, Kzg, Arc<ColumnWriter>, NoEnr>;

/// What the contract must do with a sidecar: store it, or drop it for one of these reasons; and
/// whether cl-verify is asked about it (against this block).
struct Expected {
    outcome: Result<(), &'static [Drop]>,
    kzg: Option<&'static KnownBlock>,
}

const UNKNOWN: &[Drop] = &[Drop::UnknownRoot, Drop::RootTimeout, Drop::RootWaitFull];

/// The contract's checks, in its order (`cl_chain::probe::column`), written out on their own.
fn expected(column: &GossipColumn<E>) -> Expected {
    let s = &column.sidecar;
    let drop = |reasons| Expected {
        outcome: Err(reasons),
        kzg: None,
    };
    if s.index >= 128 {
        return drop(&[Drop::NotCustody]);
    }
    if s.column.is_empty() {
        return drop(&[Drop::CommitmentsMismatch]);
    }
    if s.kzg_proofs.len() != s.column.len() {
        return drop(&[Drop::KzgInvalid]);
    }
    if s.index % 128 != column.subnet_id {
        return drop(&[Drop::WrongSubnet]);
    }
    if !CUSTODY.contains(&s.index) {
        return drop(&[Drop::NotCustody]);
    }
    if s.slot < cgc_set_slot() {
        return drop(&[Drop::BeforeCustodySlot]);
    }
    let Some(block) = known(&s.beacon_block_root.0) else {
        return drop(UNKNOWN);
    };
    if block.slot != s.slot {
        return drop(&[Drop::UnknownRoot]);
    }
    if block.commitments.len() != s.column.len() {
        return drop(&[Drop::CommitmentsMismatch]);
    }
    let outcome = match kzg_verdict(s.kzg_proofs.first().map(|p| p.as_slice())) {
        KzgOutcome::Valid => Ok(()),
        KzgOutcome::Invalid => Err(&[Drop::KzgInvalid][..]),
        KzgOutcome::NoVerdict(_) => Err(&[Drop::VerifyTimeout][..]),
    };
    Expected {
        outcome,
        kzg: Some(block),
    }
}

/// What the harness knows the store must hold.
#[derive(Default)]
struct Model {
    /// The copy stored last per `(root, index)`.
    stored: BTreeMap<(Root, u64), Vec<u8>>,
    /// Every sidecar the contract accepted, as SSZ.
    accepted: HashSet<Vec<u8>>,
    /// Every sidecar the contract rejected, as SSZ.
    rejected: HashSet<Vec<u8>>,
}

/// The counters a sidecar's end moves.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Counts {
    stored: u64,
    queue_full: u64,
    dropped: Vec<u64>,
}

/// The probe of one input (see the module docs).
struct Probe {
    ingest: Ingest,
    server: ReqRespServer,
    columns: Arc<ColumnServer>,
    writer: Arc<ColumnWriter>,
    queue: QueueMetrics,
    kzg: Kzg,
    link: Link,
    model: Model,
    events: Vec<Event>,
}

impl Probe {
    /// Must run within the runtime.
    fn start(writer: &Arc<ColumnWriter>) -> Self {
        let custody = Custody::open(
            Arc::clone(writer),
            NoEnr,
            U256::MAX,
            Advertise::Custody,
            cgc_set_slot(),
        )
        .expect("the custody record");
        assert_eq!(custody.custody_columns(), CUSTODY);
        let kzg = Kzg::default();
        let queue = QueueMetrics::default();
        let ingest = ColumnIngest::start(
            RefView::new(Reference, *column_schedule(), RefLimits::default()),
            custody,
            ColumnContract {
                kzg: kzg.clone(),
                verify_timeout: Duration::from_secs(10),
                metrics: ColumnMetrics::default(),
            },
            Arc::clone(writer),
            IngestLimits::default(),
            queue.clone(),
        )
        .expect("the column store");
        let columns = Arc::new(ColumnServer::new(
            Arc::clone(writer) as Arc<dyn ColumnStore>,
            U256::MAX,
            Arc::new(Clock),
            ServeBudget::default(),
        ));
        let link = link();
        Self {
            ingest,
            server: ReqRespServer::new(link.clone(), Arc::clone(&columns)),
            columns,
            writer: Arc::clone(writer),
            queue,
            kzg,
            link,
            model: Model::default(),
            events: Vec::new(),
        }
    }

    fn counts(&self) -> Counts {
        let metrics = &self.ingest.contract().metrics;
        Counts {
            stored: self.queue.stored(),
            queue_full: self.queue.queue_dropped(),
            dropped: Drop::ALL.iter().map(|&d| metrics.dropped(d)).collect(),
        }
    }

    async fn run(&mut self, ops: Vec<Op>) {
        for op in ops {
            match op {
                Op::Gossip(None) => self.events.push(Event::Gossip(None)),
                Op::Request(None) => self.events.push(Event::Answer(None)),
                Op::Gossip(Some(column)) => self.gossip(column).await,
                Op::Request(Some(Request::DataColumnsByRange(r))) => self.by_range(r).await,
                Op::Request(Some(Request::DataColumnsByRoot(r))) => self.by_root(r).await,
                Op::Request(Some(other)) => panic!("a column request decoded to {other:?}"),
            }
        }
    }

    /// Waits until nothing is queued: on the paused clock, the root wait's timers fire at once;
    /// the writer thread runs on the wall clock.
    async fn settle(&self) {
        while self.ingest.pending() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if self.ingest.pending() > 0 {
                std::thread::sleep(Duration::from_micros(20));
            }
        }
    }

    async fn gossip(&mut self, column: GossipColumn<E>) {
        let want = expected(&column);
        let before = self.counts();
        let verdict = self.ingest.on_column(column.clone());
        assert_eq!(verdict, Verdict::Ignore, "a column's verdict is IGNORE");
        self.settle().await;
        let after = self.counts();
        let s = &column.sidecar;
        let (root, index) = (s.beacon_block_root.0, s.index);
        let deltas: Vec<u64> = after
            .dropped
            .iter()
            .zip(&before.dropped)
            .map(|(a, b)| a - b)
            .collect();
        let stored = after.stored - before.stored;
        let total = stored + (after.queue_full - before.queue_full) + deltas.iter().sum::<u64>();
        assert_eq!(
            total, 1,
            "a sidecar ended {total} times: {before:?} -> {after:?}"
        );
        assert_eq!(
            after.queue_full, before.queue_full,
            "one sidecar at a time filled the queue"
        );
        let actual = if stored == 1 {
            // The writer settles pending links once the column's place is back; settle the
            // same slots here, so the writer's own call finds them done and every later read
            // sees one state.
            self.writer
                .settle_pending(s.slot.saturating_sub(PENDING_LINK_SLOTS))
                .expect("settle pending links");
            Ok(())
        } else {
            let at = deltas.iter().position(|&d| d == 1).expect("one drop");
            Err(Drop::ALL[at])
        };
        match (want.outcome, actual) {
            (Ok(()), Ok(())) => {}
            (Err(reasons), Err(reason)) => assert!(
                reasons.contains(&reason),
                "dropped as {}, want one of {reasons:?}",
                reason.reason()
            ),
            (want, actual) => panic!("the contract ended a sidecar {actual:?}, want {want:?}"),
        }

        // cl-verify saw exactly this sidecar's cells, against its block's commitments.
        let asked = self.kzg.take();
        match want.kzg {
            None => assert!(
                asked.is_empty(),
                "cl-verify asked about a sidecar it never had to see"
            ),
            Some(block) => {
                let [cells] = asked.as_slice() else {
                    panic!("cl-verify asked {} times about one sidecar", asked.len());
                };
                assert_eq!(cells.len(), s.column.len(), "one cell per row");
                for (row, cell) in cells.iter().enumerate() {
                    assert_eq!(
                        cell.commitment, block.commitments[row],
                        "row {row}'s commitment"
                    );
                    assert_eq!(cell.cell_index, index, "the cell index is the column's");
                    assert!(cell.cell == s.column[row].to_vec(), "row {row}'s cell");
                    assert_eq!(cell.proof, s.kzg_proofs[row], "row {row}'s proof");
                }
            }
        }

        let ssz = s.as_ssz_bytes();
        match actual {
            Ok(()) => {
                self.model.stored.insert((root, index), ssz.clone());
                self.model.accepted.insert(ssz);
            }
            Err(_) => {
                self.model.rejected.insert(ssz);
            }
        }
        // The store holds exactly what the contract accepted.
        let reader = self.writer.reader();
        assert_eq!(
            reader.get(&root, index).expect("read the column env"),
            self.model.stored.get(&(root, index)).cloned(),
            "the store's copy of ({}, {index})",
            hex(&root)
        );
        assert_eq!(
            reader.column_count().expect("count the column env"),
            self.model.stored.len() as u64,
            "the store holds a column the contract did not accept"
        );
        self.events.push(Event::Gossip(Some(actual)));
    }

    async fn by_range(&mut self, r: DataColumnsByRangeV1Request) {
        let columns = r.columns.to_vec();
        let bounds = request_verdicts(&Request::DataColumnsByRange(r.clone()));
        let earliest = self.columns.earliest_available_slot();
        let request = pb::DataColumnsByRangeRequest {
            start_slot: r.start_slot,
            count: r.count,
            columns: columns.clone(),
            hello: Some(self.link.local().clone()),
        };
        let stream = self
            .server
            .data_columns_by_range(tonic::Request::new(request))
            .await
            .expect("a range request with our hello opens its stream")
            .into_inner();
        let answer = self
            .read(stream, |r| match r.frame {
                Some(pb::data_columns_by_range_response::Frame::Hello(_)) => Frame::Hello,
                Some(pb::data_columns_by_range_response::Frame::Body(b)) => Frame::Item(b.item),
                None => Frame::Empty,
            })
            .await;
        let wanted: BTreeSet<u64> = columns.iter().copied().collect();
        let summary = match (&bounds, answer) {
            (Err(_), answer) => {
                assert_eq!(answer, Read::Refused(ErrorCode::Invalid), "out of bounds");
                Answer::Refused(ErrorCode::Invalid)
            }
            (Ok(_), Read::Refused(code)) => {
                assert_eq!(code, ErrorCode::ResourceUnavailable, "within bounds");
                assert!(
                    r.count > 0 && !wanted.is_empty(),
                    "a request naming nothing refused"
                );
                Answer::Refused(code)
            }
            (Ok(_), Read::Sidecars(served)) => {
                let names_nothing = r.count == 0 || wanted.is_empty();
                assert!(
                    !names_nothing || served.is_empty(),
                    "a request naming nothing answered with sidecars"
                );
                assert!(
                    names_nothing || !self.model.stored.is_empty(),
                    "an empty store answered a request with success, not 3: ResourceUnavailable"
                );
                self.check_range(&r, &wanted, earliest, &served)
            }
        };
        self.events.push(Event::Answer(Some(summary)));
    }

    /// The by-range rules of the module docs, on a success.
    fn check_range(
        &self,
        r: &DataColumnsByRangeV1Request,
        wanted: &BTreeSet<u64>,
        earliest: Option<u64>,
        served: &[Envelope],
    ) -> Answer {
        let end = r.start_slot.saturating_add(r.count);
        let mut out = Vec::new();
        let mut blocks: Vec<(u64, Root, BTreeSet<u64>)> = Vec::new();
        for e in served {
            let (slot, root, index) = self.check_served(e);
            assert!(
                (r.start_slot..end).contains(&slot),
                "slot {slot} outside [{}, {end})",
                r.start_slot
            );
            assert!(
                earliest.is_some_and(|earliest| slot >= earliest),
                "slot {slot} below earliest_available_slot {earliest:?}"
            );
            assert!(wanted.contains(&index), "column {index} was not requested");
            assert!(
                CUSTODY.contains(&index),
                "column {index} is not a custody column"
            );
            if let Some(&(last_slot, _, _)) = blocks.last() {
                assert!(slot >= last_slot, "out of slot order");
            }
            match blocks.last_mut() {
                Some((s, b, indices)) if (*s, *b) == (slot, root) => {
                    assert!(
                        indices.last().is_some_and(|&last| index > last),
                        "out of index order, or twice"
                    );
                    indices.insert(index);
                }
                _ => {
                    assert!(
                        blocks.last().is_none_or(|&(s, _, _)| slot > s),
                        "two blocks at slot {slot}"
                    );
                    blocks.push((slot, root, BTreeSet::from([index])));
                }
            }
            out.push((slot, root, index));
        }
        for (slot, _, indices) in &blocks {
            assert_eq!(indices, wanted, "the block at slot {slot} is not whole");
        }
        for pair in blocks.windows(2) {
            assert!(
                ancestor(&pair[0].1, &pair[1].1),
                "the block at slot {} does not descend from the one at slot {}",
                pair[1].0,
                pair[0].0
            );
        }
        Answer::Sidecars(out)
    }

    async fn by_root(&mut self, r: DataColumnsByRootV1Request) {
        let ids: Vec<(Root, Vec<u64>)> =
            r.0.iter()
                .map(|id| (id.block_root.0, id.columns.to_vec()))
                .collect();
        let bounds = request_verdicts(&Request::DataColumnsByRoot(r.clone()));
        let earliest = self.columns.earliest_available_slot();
        let request = pb::DataColumnsByRootRequest {
            ids: ids
                .iter()
                .map(|(root, columns)| pb::DataColumnsByRootIdentifier {
                    block_root: root.to_vec(),
                    columns: columns.clone(),
                })
                .collect(),
            hello: Some(self.link.local().clone()),
        };
        let stream = self
            .server
            .data_columns_by_root(tonic::Request::new(request))
            .await
            .expect("a root request with our hello opens its stream")
            .into_inner();
        let answer = self
            .read(stream, |r| match r.frame {
                Some(pb::data_columns_by_root_response::Frame::Hello(_)) => Frame::Hello,
                Some(pb::data_columns_by_root_response::Frame::Body(b)) => Frame::Item(b.item),
                None => Frame::Empty,
            })
            .await;
        let summary = match (&bounds, answer) {
            (Err(_), answer) => {
                assert_eq!(answer, Read::Refused(ErrorCode::Invalid), "out of bounds");
                Answer::Refused(ErrorCode::Invalid)
            }
            (Ok(_), Read::Refused(code)) => {
                panic!("a by-root request within bounds refused {code:?}")
            }
            (Ok(_), Read::Sidecars(served)) => {
                let got: Vec<(u64, Root, u64)> =
                    served.iter().map(|e| self.check_served(e)).collect();
                let want = self.expected_by_root(&ids, earliest);
                assert_eq!(got, want, "the by-root answer");
                Answer::Sidecars(got)
            }
        };
        self.events.push(Event::Answer(Some(summary)));
    }

    /// Per identifier in request order, its columns in index order, each pair once: the ones
    /// stored for a block at or above `earliest`.
    fn expected_by_root(
        &self,
        ids: &[(Root, Vec<u64>)],
        earliest: Option<u64>,
    ) -> Vec<(u64, Root, u64)> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (root, columns) in ids {
            let columns: BTreeSet<u64> = columns.iter().copied().collect();
            for index in columns {
                if !seen.insert((*root, index)) || !self.model.stored.contains_key(&(*root, index))
                {
                    continue;
                }
                let slot = known(root).expect("only known roots are stored").slot;
                if earliest.is_some_and(|e| slot >= e) {
                    out.push((slot, *root, index));
                }
            }
        }
        out
    }

    /// One served envelope: a Gloas sidecar the contract accepted, the copy stored last for its
    /// `(root, index)`, never one it only rejected; its envelope names its slot and root.
    fn check_served(&self, e: &Envelope) -> (u64, Root, u64) {
        let sidecar = gloas::DataColumnSidecar::<E>::from_ssz_bytes(&e.ssz)
            .expect("a served sidecar decodes as Gloas");
        let root = sidecar.beacon_block_root.0;
        assert_eq!(e.slot, sidecar.slot, "the envelope's slot");
        assert_eq!(e.root, root.to_vec(), "the envelope's root");
        let accepted = self.model.accepted.contains(&e.ssz);
        assert!(
            accepted || !self.model.rejected.contains(&e.ssz),
            "a sidecar the contract rejected was served"
        );
        assert!(accepted, "a sidecar the contract never saw was served");
        assert_eq!(
            self.model.stored.get(&(root, sidecar.index)),
            Some(&e.ssz),
            "served another copy than the one stored last"
        );
        (sidecar.slot, root, sidecar.index)
    }

    /// Reads one column response as cl-p2p does: our hello first, then sidecar chunks with
    /// `seq` from 1, each envelope passing the link's checks, then at most one error chunk.
    async fn read<R>(&self, mut stream: StubStream<R>, frame: fn(R) -> Frame) -> Read {
        let first = stream
            .next()
            .await
            .expect("a response")
            .expect("no failed read");
        assert!(
            matches!(frame(first), Frame::Hello),
            "the response starts with a hello"
        );
        let mut served = Vec::new();
        while let Some(next) = stream.next().await {
            let item = match frame(next.expect("no failed read")) {
                Frame::Item(Some(item)) => item.result,
                Frame::Hello => panic!("a second hello"),
                Frame::Item(None) | Frame::Empty => panic!("an empty frame"),
            };
            match item {
                Some(pb::response_chunk::Result::Chunk(envelope)) => {
                    assert_eq!(envelope.seq, served.len() as u64 + 1, "seq");
                    assert_eq!(
                        envelope.payload_type,
                        PayloadType::DataColumnSidecar as i32,
                        "payload type"
                    );
                    if let Err(e) = self.link.check_envelope(&envelope) {
                        panic!("an envelope the link refuses: {e}");
                    }
                    served.push(envelope);
                }
                Some(pb::response_chunk::Result::Error(error)) => {
                    assert!(
                        stream.next().await.is_none(),
                        "a frame after the error chunk"
                    );
                    assert!(served.is_empty(), "an error chunk after sidecars");
                    let code = ErrorCode::try_from(error.code).expect("a known error code");
                    return Read::Refused(code);
                }
                None => panic!("a chunk with no result"),
            }
        }
        Read::Sidecars(served)
    }
}

/// One response frame, of either column RPC.
enum Frame {
    Hello,
    Item(Option<pb::ResponseChunk>),
    Empty,
}

/// One response, read.
#[derive(Debug, PartialEq)]
enum Read {
    Sidecars(Vec<Envelope>),
    Refused(ErrorCode),
}

/// Whether `older` is an ancestor of `newer` in [`CHAIN`].
fn ancestor(older: &Root, newer: &Root) -> bool {
    let blocks = known_blocks();
    let mut at = blocks.iter().position(|b| b.root == *newer);
    while let Some(i) = at {
        at = blocks[i].parent;
        if at.is_some_and(|p| blocks[p].root == *older) {
            return true;
        }
    }
    false
}

fn hex(root: &Root) -> String {
    root[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// `column_contract`: see the module docs.
pub fn column_contract(data: &[u8]) {
    column_contract_events(data);
}

/// [`column_contract`], returning what happened to each operation.
pub fn column_contract_events(data: &[u8]) -> Vec<Event> {
    let ops = parse(data);
    let dir = tempfile::Builder::new()
        .prefix("ethswarm-fuzz-columns-")
        .tempdir()
        .expect("a temp dir for the column env");
    let writer = Arc::new(
        ColumnWriter::open_with(
            dir.path(),
            WriterOptions {
                max_size: MIN_MAX_SIZE,
            },
        )
        .expect("the column env"),
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("a current-thread runtime with a paused clock");
    let events = runtime.block_on(async {
        let mut probe = Probe::start(&writer);
        probe.run(ops).await;
        std::mem::take(&mut probe.events)
    });
    drop(runtime);
    let writer = Arc::into_inner(writer).expect("every handle of the column env is gone");
    drop(writer);
    dir.close().expect("remove the column env");
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chain_is_as_documented() {
        let blocks = known_blocks();
        assert_eq!(blocks[0].slot + 1, cgc_set_slot());
        assert_eq!(blocks[1].slot, cgc_set_slot());
        assert!(blocks[3].commitments.is_empty());
        assert_eq!(blocks[4].slot, blocks[5].slot);
        assert!(ancestor(&blocks[2].root, &blocks[4].root));
        assert!(!ancestor(&blocks[4].root, &blocks[5].root));
        let roots: HashSet<Root> = blocks.iter().map(|b| b.root).collect();
        assert_eq!(roots.len(), CHAIN.len());
        // UNKNOWN_ROOT names no block of the chain.
        for block in 0..8u8 {
            let spec = GossipSpec {
                block: block | UNKNOWN_ROOT,
                index: 1,
                flags: 0,
                verdict: KZG_VALID,
                fill: 0,
            };
            assert!(!roots.contains(&spec.column().sidecar.beacon_block_root.0));
        }
    }

    fn spec(block: u8, index: u8, verdict: u8) -> GossipSpec {
        GossipSpec {
            block,
            index,
            flags: 0,
            verdict,
            fill: 0x11,
        }
    }

    #[test]
    fn a_valid_sidecar_is_stored_and_served_an_invalid_one_never() {
        let a = &known_blocks()[1];
        let mut input = Vec::new();
        input.extend(spec(1, 47, KZG_VALID).bytes());
        input.extend(spec(1, 87, KZG_INVALID).bytes());
        let range = RangeSpec {
            start: 2,
            count: 1,
            columns: vec![47],
        };
        assert_eq!(range.request().start_slot, a.slot);
        input.extend(range.bytes());
        input.extend(
            RangeSpec {
                start: 2,
                count: 1,
                columns: vec![87],
            }
            .bytes(),
        );
        input.extend(
            RootSpec {
                ids: vec![(1, vec![87, 47, 47])],
            }
            .bytes(),
        );
        let events = column_contract_events(&input);
        assert_eq!(
            events,
            [
                Event::Gossip(Some(Ok(()))),
                Event::Gossip(Some(Err(Drop::KzgInvalid))),
                Event::Answer(Some(Answer::Sidecars(vec![(a.slot, a.root, 47)]))),
                Event::Answer(Some(Answer::Refused(ErrorCode::ResourceUnavailable))),
                Event::Answer(Some(Answer::Sidecars(vec![(a.slot, a.root, 47)]))),
            ]
        );
    }

    #[test]
    fn the_verdict_comes_from_the_first_proof() {
        assert_eq!(kzg_verdict(Some(&[KZG_VALID])), KzgOutcome::Valid);
        assert_eq!(kzg_verdict(Some(&[3])), KzgOutcome::Valid);
        assert_eq!(kzg_verdict(Some(&[KZG_INVALID])), KzgOutcome::Invalid);
        assert!(matches!(
            kzg_verdict(Some(&[KZG_NO_VERDICT])),
            KzgOutcome::NoVerdict(_)
        ));
        assert_eq!(kzg_verdict(None), KzgOutcome::Valid);
    }
}
