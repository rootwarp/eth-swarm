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
//!   chain.v1 requests cl-p2p sends (our hello in line) and read as cl-p2p reads them. The
//!   server follows a fixed reference chain that holds every block of [`CHAIN`], both branches
//!   (`CanonicalChain::fixed`), so the answers are the store's own chain rules, which the model
//!   below writes out. Which branch the reference's head is on is not fuzzed here: cl-chain's
//!   `reqresp` and `probe::canon` tests cover it.
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
//!   `(root, index)`;
//! - the store's chain links, first stored slot, contiguous-from slot and finalized watermark
//!   are the harness's own model of them ([`Links`]): the link walk and the writer's link rules
//!   written out on their own, from the accepted writes alone. A stored sidecar's write is in
//!   once nothing is queued, but the writer thread's settle step after it runs later: the
//!   harness waits for it (the store's links go from the write's to the settle step's, and to
//!   nothing else) and never settles for the writer, so a writer that skips or botches its own
//!   settle step fails here. Every wait on the writer thread, for the queue to drain and for a
//!   settle step, checks the input's one wall-clock deadline ([`INPUT_DEADLINE`] from its
//!   start), so a writer that never drains or settles fails with the harness's message before
//!   the gates' per-input timeout. The teardown's join of the writer thread is not bounded by
//!   it: a writer stuck there surfaces as a libFuzzer timeout, which the gates reject too.
//!
//! Every response is a hello, then sidecar chunks with `seq` from 1, each envelope passing the
//! link's type and digest checks and naming its sidecar's slot and root, then at most one error
//! chunk, last; no read fails. Then:
//!
//! - **a sidecar the contract rejected never appears in a response**: every sidecar served was
//!   accepted earlier, and is the copy stored last for its `(root, index)`;
//! - `earliest_available_slot` is the harness's ([`Links::earliest`]: the first stored slot,
//!   the slot after the finalized watermark, `cgc_set_slot` and the contiguous-from slot, all
//!   from the model), the server reports exactly that, and every expectation below uses the
//!   harness's value, never the server's;
//! - a request is refused `1: InvalidRequest` exactly when cl-chain's bounds refuse it
//!   (`range_request_bounds`, `root_request_bounds`), which agree with the spec rule and with
//!   cl-p2p's admission check;
//! - by range, within bounds, the answer is exactly the one the serving rules give, computed by
//!   the harness from its model ([`Model::expected_range`]): an empty success only for a
//!   request naming nothing, one starting past the serve range, or a range with no stored block
//!   and none waited for; `3: ResourceUnavailable` exactly where the rules refuse; else the
//!   chain prefix of whole blocks, each the next blob-carrying block after the one before it
//!   (never a block further down its chain). cl-chain cuts an answer short only at its budget,
//!   and everything this harness can store fits one answer (checked), so no shorter answer is
//!   allowed (cl-p2p's window and token cuts are not in this harness);
//! - by root: exactly the requested pairs stored at or above the harness's
//!   `earliest_available_slot`, per identifier in request order, each pair once.

use crate::columns::request_verdicts;
use crate::{column_network, column_schedule, column_topic, column_transform, E};
use cl_chain::da::custody::{Advertise, Custody, EnrCgc, EnrError};
use cl_chain::probe::ingest::{MAX_LINK_WALK, PENDING_LINK_SLOTS};
use cl_chain::probe::{
    ApiError, BlockApi, CanonicalChain, ChainView, Checkpoint, ColumnContract, ColumnIngest,
    ColumnMetrics, Drop, GossipColumn, Header, IngestLimits, QueueMetrics, RefLimits, RefView,
    ReferenceApi, Root,
};
use cl_chain::reqresp::{ColumnServer, ColumnStore, ReqRespServer, ServeBudget, ServeClock};
use cl_chain::verify::client::{KzgOutcome, KzgVerifier};
use cl_chain_columns::{BlockLink, ColumnWriter, WriterOptions, MIN_MAX_SIZE};
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
use std::time::{Duration, Instant};
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
/// How long one input may wait on the wall clock for the writer thread, from the input's start
/// and over all its waits ([`Deadline`]): the drains of the column queue ([`Probe::settle`]) and
/// the waits for the writer's settle steps ([`Probe::await_writer`]) all check this one
/// deadline. 8 s, far past the few milliseconds an input takes, so a writer thread that stalls
/// on a loaded machine but finishes within the input's time is not reported as a crash, and 2 s
/// under the gates' per-input timeout (`-timeout=10`, `M2A_TIMEOUT_S` in `fuzz/m2a-common.sh`,
/// which `tests/writer_wait.rs` holds it to), so a writer that never drains the queue or never
/// settles, in any drain or settle wait, fails with the harness's own message rather than as a
/// libFuzzer timeout. The teardown is not bounded by this deadline: dropping the column ingest
/// joins the writer thread with no limit, so a writer thread stuck in a settle step that
/// changed nothing (one no settle wait watches) blocks that join and surfaces as a libFuzzer
/// timeout. That is never a pass by mistake: the gates reject any timeout.
pub const INPUT_DEADLINE: Duration = Duration::from_secs(8);

/// One input's wall-clock deadline: set once, when the input starts ([`Deadline::input`]), and
/// checked by every wait, so the waits share [`INPUT_DEADLINE`] rather than each starting anew.
#[derive(Debug, Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    /// [`INPUT_DEADLINE`] from now, the input's start.
    fn input() -> Self {
        Self::after(INPUT_DEADLINE)
    }

    /// `wait` from now.
    fn after(wait: Duration) -> Self {
        Self(Instant::now() + wait)
    }

    /// Fails with `stuck`'s message once the deadline has passed.
    fn check(self, stuck: impl FnOnce() -> String) {
        assert!(
            Instant::now() < self.0,
            "{} (past the input's {INPUT_DEADLINE:?} deadline)",
            stuck()
        );
    }

    /// Polls `poll` on the wall clock until it is `Ok`, checking the deadline between tries:
    /// past it, fails with `stuck` of the last `Err`.
    fn wait_for<T>(self, mut poll: impl FnMut() -> Result<(), T>, stuck: impl Fn(T) -> String) {
        loop {
            match poll() {
                Ok(()) => return,
                Err(last) => self.check(|| stuck(last)),
            }
            std::thread::sleep(Duration::from_micros(50));
        }
    }
}

/// Waits until `pending` is 0: on the paused clock, the root wait's timers fire at once; the
/// writer thread runs on the wall clock, within `deadline`.
async fn drain(deadline: Deadline, pending: impl Fn() -> usize) {
    while pending() > 0 {
        deadline.check(|| {
            format!(
                "the column queue never drained: {} sidecars still queued",
                pending()
            )
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        if pending() > 0 {
            std::thread::sleep(Duration::from_micros(20));
        }
    }
}

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

/// The place of `root` in [`CHAIN`].
fn known_index(root: &Root) -> Option<usize> {
    known_blocks().iter().position(|b| b.root == *root)
}

/// The nearest blob-carrying ancestor of `root` in [`CHAIN`], passing through blocks without
/// blobs: the block a range answer may hold right before it.
fn blob_parent(root: &Root) -> Option<Root> {
    let blocks = known_blocks();
    let mut at = blocks[known_index(root)?].parent;
    while let Some(i) = at {
        if !blocks[i].commitments.is_empty() {
            return Some(blocks[i].root);
        }
        at = blocks[i].parent;
    }
    None
}

/// `data_column_serve_range` of the stub clock, as inclusive slots.
fn serve_range() -> (u64, u64) {
    (gloas_slot(), gloas_slot() + SERVE_SPAN)
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
        Some(serve_range())
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

/// What the harness knows the store must hold, from the sidecars the contract accepted alone.
#[derive(Default)]
struct Model {
    /// The copy stored last per `(root, index)`.
    stored: BTreeMap<(Root, u64), Vec<u8>>,
    /// Every sidecar the contract accepted, as SSZ.
    accepted: HashSet<Vec<u8>>,
    /// Every sidecar the contract rejected, as SSZ.
    rejected: HashSet<Vec<u8>>,
    /// The store's links and slots after every write and its settle step.
    links: Links,
}

/// The store's chain links and the slots `earliest_available_slot` comes from, as the harness
/// models them ([`Model::links`]) or reads them from the store ([`observe`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Links {
    /// Each stored block's link, by its place in [`CHAIN`].
    by_block: BTreeMap<usize, BlockLink>,
    /// The lowest slot a column was ever stored at.
    first_stored: Option<u64>,
    /// The highest slot a gap raised it to; `None` before the first gap.
    contiguous_from: Option<u64>,
    /// The finalized-slot watermark: nothing finalizes in this harness.
    finalized: Option<u64>,
}

impl Links {
    /// The link the column's task walks for block `b` (`cl_chain::probe::ingest`, step 6): its
    /// nearest stored ancestor, through ancestors without blobs; a start at an ancestor before
    /// `cgc_set_slot`; pending on a blob-carrying ancestor not stored; a gap if the reference
    /// knows no parent, or past [`MAX_LINK_WALK`] blocks.
    fn walk(&self, b: usize) -> BlockLink {
        let blocks = known_blocks();
        let mut parent = blocks[b].parent;
        for _ in 0..=MAX_LINK_WALK {
            let Some(p) = parent else {
                return BlockLink::Gap;
            };
            let ancestor = &blocks[p];
            if self.by_block.contains_key(&p) {
                return BlockLink::Parent(ancestor.root);
            }
            if ancestor.slot < cgc_set_slot() {
                return BlockLink::Start;
            }
            if !ancestor.commitments.is_empty() {
                return BlockLink::Pending(ancestor.root, ancestor.slot);
            }
            parent = ancestor.parent;
        }
        BlockLink::Gap
    }

    /// A write of block `b`: the walked link replaces the stored one unless the stored one is
    /// linked and the walk is not, or one is a gap and the other pending; a gap it stores raises
    /// the contiguous-from slot; every block pending on `b` links to it.
    fn write(&mut self, b: usize) {
        let block = &known_blocks()[b];
        let walked = self.walk(b);
        let kept = matches!(
            (self.by_block.get(&b), walked),
            (
                Some(BlockLink::Start | BlockLink::Parent(_)),
                BlockLink::Gap | BlockLink::Pending(..)
            ) | (Some(BlockLink::Gap), BlockLink::Pending(..))
                | (Some(BlockLink::Pending(..)), BlockLink::Gap)
        );
        if !kept {
            self.by_block.insert(b, walked);
            if walked == BlockLink::Gap {
                self.raise(block.slot);
            }
        }
        for link in self.by_block.values_mut() {
            if matches!(link, BlockLink::Pending(target, _) if *target == block.root) {
                *link = BlockLink::Parent(block.root);
            }
        }
        self.first_stored = Some(self.first_stored.map_or(block.slot, |s| s.min(block.slot)));
    }

    /// The writer's settle step after a write at `slot`: a block still pending at a slot more
    /// than [`PENDING_LINK_SLOTS`] below it is a gap from then on (no finality covers its
    /// ancestor here), raising the contiguous-from slot to its own.
    fn settle(&mut self, slot: u64) {
        let before = slot.saturating_sub(PENDING_LINK_SLOTS);
        let blocks = known_blocks();
        let mut gaps = Vec::new();
        for (&b, link) in &mut self.by_block {
            if matches!(link, BlockLink::Pending(..)) && blocks[b].slot < before {
                *link = BlockLink::Gap;
                gaps.push(blocks[b].slot);
            }
        }
        for slot in gaps {
            self.raise(slot);
        }
    }

    fn raise(&mut self, slot: u64) {
        self.contiguous_from = Some(self.contiguous_from.map_or(slot, |c| c.max(slot)));
    }

    /// `earliest_available_slot` (`cl_chain::reqresp`, `# What is served`): the highest of the
    /// first stored slot, the slot after the finalized watermark, `cgc_set_slot` and the
    /// contiguous-from slot; `None` while nothing is stored.
    fn earliest(&self) -> Option<u64> {
        let after_finalized = self.finalized.map_or(0, |f| f.saturating_add(1));
        Some(
            self.first_stored?
                .max(after_finalized)
                .max(cgc_set_slot())
                .max(self.contiguous_from.unwrap_or(0)),
        )
    }

    /// The chain a range answer follows among the stored blocks `read` (in `(slot, root)`
    /// order): the longest chain of parent links within them, ties to the higher tip, and of
    /// tips still tied, only the blocks every tied chain holds.
    fn one_chain(&self, read: &[usize]) -> Vec<usize> {
        let blocks = known_blocks();
        let chain_to = |tip: usize| {
            let mut chain = vec![tip];
            while let Some(BlockLink::Parent(parent)) =
                chain.last().and_then(|b| self.by_block.get(b))
            {
                match read.iter().find(|&&b| blocks[b].root == *parent) {
                    Some(&p) => chain.push(p),
                    None => break,
                }
            }
            chain.reverse();
            chain
        };
        let chains: Vec<Vec<usize>> = read.iter().map(|&b| chain_to(b)).collect();
        let key = |chain: &[usize]| (chain.len(), chain.last().map(|&b| blocks[b].slot));
        let Some(best) = chains.iter().map(|c| key(c)).max() else {
            return Vec::new();
        };
        let tied: Vec<&Vec<usize>> = chains.iter().filter(|c| key(c) == best).collect();
        tied[0]
            .iter()
            .copied()
            .filter(|b| tied.iter().all(|c| c.contains(b)))
            .collect()
    }
}

/// The store's [`Links`], read in one transaction.
fn observe(writer: &ColumnWriter) -> Links {
    let snapshot = writer.reader().snapshot().expect("read the column env");
    let by_block = known_blocks()
        .iter()
        .enumerate()
        .filter_map(|(i, b)| {
            let link = snapshot.link_of(&b.root).expect("read a block's link");
            link.map(|link| (i, link))
        })
        .collect();
    Links {
        by_block,
        first_stored: snapshot.first_stored_slot().expect("the first stored slot"),
        contiguous_from: snapshot
            .contiguous_from()
            .expect("the contiguous-from slot"),
        finalized: snapshot.finalized_slot().expect("the finalized watermark"),
    }
}

impl Model {
    /// The accepted copy `ssz` of block `b`'s column `index`, stored as one write of the writer
    /// thread. Returns the links as of the write, before the writer's settle step; the model's
    /// links are as of after it.
    fn store(&mut self, b: usize, index: u64, ssz: Vec<u8>) -> Links {
        let block = &known_blocks()[b];
        self.accepted.insert(ssz.clone());
        self.stored.insert((block.root, index), ssz);
        self.links.write(b);
        let written = self.links.clone();
        self.links.settle(block.slot);
        written
    }

    /// Whether block `b` holds every column of `wanted`.
    fn whole(&self, b: usize, wanted: &BTreeSet<u64>) -> bool {
        let root = known_blocks()[b].root;
        wanted.iter().all(|&i| self.stored.contains_key(&(root, i)))
    }

    /// cl-chain cuts an answer short only at its budget ([`ServeBudget::default`]); everything
    /// this harness stores fits in one answer, so it never cuts one.
    fn assert_under_budget(&self) {
        let budget = ServeBudget::default();
        let bytes: usize = self.stored.values().map(Vec::len).sum();
        assert!(
            bytes <= budget.max_bytes && self.stored.len() <= budget.max_sidecars,
            "the store holds more than one answer's budget: the harness has no model of the cut"
        );
    }

    /// The by-range answer the serving rules give (`cl_chain::reqresp`, `# What is served`,
    /// `# One chain` and `# Order and completeness`) to a request within bounds, from the model
    /// alone.
    fn expected_range(&self, start: u64, count: u64, columns: &[u64]) -> Answer {
        self.assert_under_budget();
        let unavailable = Answer::Refused(ErrorCode::ResourceUnavailable);
        let nothing = Answer::Sidecars(Vec::new());
        let wanted: BTreeSet<u64> = columns.iter().copied().collect();
        if wanted.is_empty() || count == 0 {
            return nothing;
        }
        let Some(earliest) = self.links.earliest() else {
            return unavailable;
        };
        let (first, last) = serve_range();
        if start > last {
            // The future: no column exists there yet.
            return nothing;
        }
        if start < earliest.max(first) || !wanted.iter().all(|i| CUSTODY.contains(i)) {
            return unavailable;
        }
        let end = start.saturating_add(count).min(last.saturating_add(1));
        let blocks = known_blocks();
        // A blob-carrying block a stored block waits for: the read ends before it.
        let missing = self
            .links
            .by_block
            .values()
            .filter_map(|link| match *link {
                BlockLink::Pending(_, slot) => Some(slot),
                _ => None,
            })
            .filter(|slot| (start..end).contains(slot))
            .min();
        let mut read: Vec<usize> = self
            .links
            .by_block
            .keys()
            .copied()
            .filter(|&b| (start..missing.unwrap_or(end)).contains(&blocks[b].slot))
            .collect();
        read.sort_by_key(|&b| (blocks[b].slot, blocks[b].root));
        let chain = self.links.one_chain(&read);
        let (Some(&head), Some(&tip)) = (chain.first(), chain.last()) else {
            return if read.is_empty() && missing.is_none() {
                nothing
            } else {
                unavailable
            };
        };
        // The chain's first block must be the first blob-carrying block of the range on it.
        let starts_the_range = match self.links.by_block[&head] {
            BlockLink::Start => true,
            BlockLink::Parent(parent) => known(&parent).expect("a stored parent").slot < start,
            BlockLink::Pending(_, slot) => slot < start,
            BlockLink::Gap => blocks[head].slot <= start,
        };
        if !starts_the_range {
            return unavailable;
        }
        // A block after the tip whose link was never followed may be on the chain: the answer
        // ends before its slot.
        let after_tip = read
            .iter()
            .position(|&b| b == tip)
            .expect("the tip was read")
            + 1;
        let unlinked = read[after_tip..]
            .iter()
            .find(|b| {
                matches!(
                    self.links.by_block[b],
                    BlockLink::Gap | BlockLink::Pending(..)
                )
            })
            .map(|&b| blocks[b].slot);
        let mut out = Vec::new();
        for &b in &chain {
            let block = &blocks[b];
            if unlinked.is_some_and(|slot| block.slot >= slot) || !self.whole(b, &wanted) {
                break;
            }
            out.extend(wanted.iter().map(|&i| (block.slot, block.root, i)));
        }
        if out.is_empty() {
            unavailable
        } else {
            Answer::Sidecars(out)
        }
    }

    /// The by-root answer: per identifier in request order, its columns in index order, each
    /// pair once, the ones stored for a block at or above the model's
    /// `earliest_available_slot` and within the serve range.
    fn expected_by_root(&self, ids: &[(Root, Vec<u64>)]) -> Vec<(u64, Root, u64)> {
        self.assert_under_budget();
        let (first, last) = serve_range();
        let earliest = self.links.earliest();
        let servable = |slot: u64| earliest.is_some_and(|e| slot >= e.max(first)) && slot <= last;
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for (root, columns) in ids {
            let columns: BTreeSet<u64> = columns.iter().copied().collect();
            for index in columns {
                if !seen.insert((*root, index)) || !self.stored.contains_key(&(*root, index)) {
                    continue;
                }
                let slot = known(root).expect("only known roots are stored").slot;
                if servable(slot) {
                    out.push((slot, *root, index));
                }
            }
        }
        out
    }
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
    /// The input's deadline: every wait for the writer thread checks it.
    deadline: Deadline,
}

impl Probe {
    /// Must run within the runtime; every wait checks `deadline`.
    fn start(writer: &Arc<ColumnWriter>, deadline: Deadline) -> Self {
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
        let every_block = ChainView::new(known_blocks().iter().map(|b| (b.slot, b.root)))
            .expect("the blocks of CHAIN");
        let columns = Arc::new(
            ColumnServer::new(
                Arc::clone(writer) as Arc<dyn ColumnStore>,
                U256::MAX,
                Arc::new(Clock),
                ServeBudget::default(),
            )
            .following(Arc::new(CanonicalChain::fixed(every_block))),
        );
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
            deadline,
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

    /// Waits until nothing is queued, within the input's deadline ([`drain`]).
    async fn settle(&self) {
        drain(self.deadline, || self.ingest.pending()).await;
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
                let block = known_index(&root).expect("only known roots are stored");
                let written = self.model.store(block, index, ssz);
                self.await_writer(&written);
            }
            Err(_) => {
                self.model.rejected.insert(ssz);
                assert_eq!(
                    observe(&self.writer),
                    self.model.links,
                    "a dropped sidecar moved the store's links"
                );
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

    /// Waits for the writer thread's settle step after a write: the store's links are the
    /// write's (`written`) until they are the model's, and never anything else. With nothing
    /// to settle the two are the same, and there is nothing to wait for.
    /// It waits within the input's deadline.
    fn await_writer(&self, written: &Links) {
        let want = &self.model.links;
        self.deadline.wait_for(
            || {
                let seen = observe(&self.writer);
                if seen == *want {
                    return Ok(());
                }
                assert_eq!(
                    seen, *written,
                    "the store's links are neither the write's nor its settle step's {want:?}"
                );
                Err(seen)
            },
            |seen| {
                format!(
                    "the writer thread never settled its pending links: {seen:?}, want {want:?}"
                )
            },
        );
    }

    /// `earliest_available_slot` as the harness derives it; the server must report the same.
    fn check_earliest(&self) -> Option<u64> {
        let earliest = self.model.links.earliest();
        assert_eq!(
            self.columns.earliest_available_slot(),
            earliest,
            "the server's earliest_available_slot"
        );
        earliest
    }

    async fn by_range(&mut self, r: DataColumnsByRangeV1Request) {
        let columns = r.columns.to_vec();
        let bounds = request_verdicts(&Request::DataColumnsByRange(r.clone()));
        let earliest = self.check_earliest();
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
            (Ok(_), answer) => {
                let got = match answer {
                    Read::Refused(code) => Answer::Refused(code),
                    Read::Sidecars(served) => {
                        Answer::Sidecars(self.check_range(&r, &wanted, earliest, &served))
                    }
                };
                let want = self.model.expected_range(r.start_slot, r.count, &columns);
                assert_eq!(got, want, "the by-range answer to {r:?}");
                got
            }
        };
        self.events.push(Event::Answer(Some(summary)));
    }

    /// The shape of a by-range success, on its own: every sidecar served was accepted, within
    /// the range and at or above `earliest`, a requested custody column; whole blocks in
    /// `(slot, index)` order, each the next blob-carrying block after the one before it.
    fn check_range(
        &self,
        r: &DataColumnsByRangeV1Request,
        wanted: &BTreeSet<u64>,
        earliest: Option<u64>,
        served: &[Envelope],
    ) -> Vec<(u64, Root, u64)> {
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
            assert_eq!(
                blob_parent(&pair[1].1),
                Some(pair[0].1),
                "the block at slot {} is not the next blob-carrying block after the one at slot {}",
                pair[1].0,
                pair[0].0
            );
        }
        out
    }

    async fn by_root(&mut self, r: DataColumnsByRootV1Request) {
        let ids: Vec<(Root, Vec<u64>)> =
            r.0.iter()
                .map(|id| (id.block_root.0, id.columns.to_vec()))
                .collect();
        let bounds = request_verdicts(&Request::DataColumnsByRoot(r.clone()));
        self.check_earliest();
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
                let want = self.model.expected_by_root(&ids);
                assert_eq!(got, want, "the by-root answer");
                Answer::Sidecars(got)
            }
        };
        self.events.push(Event::Answer(Some(summary)));
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

fn hex(root: &Root) -> String {
    root[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// `column_contract`: see the module docs.
pub fn column_contract(data: &[u8]) {
    column_contract_events(data);
}

/// [`column_contract`], returning what happened to each operation.
pub fn column_contract_events(data: &[u8]) -> Vec<Event> {
    let deadline = Deadline::input();
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
        let mut probe = Probe::start(&writer, deadline);
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
        // D's next blob-carrying block back is B, through C; F's is B too; P has none.
        assert_eq!(blob_parent(&blocks[4].root), Some(blocks[2].root));
        assert_eq!(blob_parent(&blocks[5].root), Some(blocks[2].root));
        assert_eq!(blob_parent(&blocks[2].root), Some(blocks[1].root));
        assert_eq!(blob_parent(&blocks[0].root), None);
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

    /// The message `run` panicked with.
    fn panic_message(run: impl FnOnce()) -> String {
        let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
            .expect_err("the wait never failed");
        err.downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_default()
    }

    /// A wait whose writer never finishes fails at the input's deadline with the harness's own
    /// message, the drain of the queue and the wait for a settle step alike.
    #[test]
    fn a_wait_past_the_input_deadline_fails_with_its_own_message() {
        let passed = Deadline::after(Duration::ZERO);
        let message = panic_message(|| passed.wait_for(|| Err(7), |n| format!("stuck at {n}")));
        assert!(message.starts_with("stuck at 7"), "{message}");
        assert!(message.contains("deadline"), "{message}");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let message = panic_message(|| runtime.block_on(drain(passed, || 3)));
        assert!(message.contains("3 sidecars still queued"), "{message}");
        // Nothing to wait for: no check at all, even past the deadline.
        passed.wait_for(|| Ok::<(), ()>(()), |()| unreachable!());
        runtime.block_on(drain(passed, || 0));
    }

    /// One deadline per input, not one per wait: once earlier work took the input's whole
    /// time, a later wait fails at its first check instead of starting a fresh deadline. Only
    /// the later waits are timed, against the whole budget: a fresh deadline per wait makes each
    /// take at least the budget, while the shared one fails within microseconds, so only a
    /// pause as long as the budget itself could fail a correct wait here.
    #[test]
    fn every_wait_of_an_input_shares_its_deadline() {
        let budget = Duration::from_secs(1);
        let deadline = Deadline::after(budget);
        // An earlier wait, done at once, then the rest of the input's time spent elsewhere.
        deadline.wait_for(|| Ok::<(), ()>(()), |()| unreachable!());
        std::thread::sleep(budget);
        assert!(
            Instant::now() >= deadline.0,
            "the input's time is not up yet"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        let drained = Instant::now();
        let message = panic_message(|| runtime.block_on(drain(deadline, || 1)));
        let took = drained.elapsed();
        assert!(message.contains("1 sidecars still queued"), "{message}");
        assert!(
            took < budget,
            "the drain started a fresh deadline: {took:?}"
        );
        let waited = Instant::now();
        let message = panic_message(|| deadline.wait_for(|| Err(2), |n| format!("stuck at {n}")));
        let took = waited.elapsed();
        assert!(message.starts_with("stuck at 2"), "{message}");
        assert!(took < budget, "the wait started a fresh deadline: {took:?}");
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

    /// A model with these columns stored, in order: `(block, columns)`.
    fn model_of(writes: &[(usize, &[u64])]) -> Model {
        let mut model = Model::default();
        for &(block, columns) in writes {
            for &index in columns {
                model.store(block, index, vec![block as u8, index as u8]);
            }
        }
        model
    }

    /// Block `b`'s `columns`, as an answer lists them.
    fn whole(b: usize, columns: &[u64]) -> Vec<(u64, Root, u64)> {
        let block = &known_blocks()[b];
        columns
            .iter()
            .map(|&i| (block.slot, block.root, i))
            .collect()
    }

    const UNAVAILABLE: Answer = Answer::Refused(ErrorCode::ResourceUnavailable);

    #[test]
    fn a_range_ends_before_a_partial_block_and_never_jumps_past_it() {
        let blocks = known_blocks();
        // A whole, B with two columns of four, D whole.
        let model = model_of(&[(1, &CUSTODY), (2, &[1, 47]), (4, &CUSTODY)]);
        assert_eq!(model.links.by_block[&4], BlockLink::Parent(blocks[2].root));
        assert_eq!(
            model.expected_range(blocks[1].slot, 8, &CUSTODY),
            Answer::Sidecars(whole(1, &CUSTODY)),
            "A, then nothing past B: not A then D"
        );
        assert_eq!(
            model.expected_range(blocks[1].slot, 8, &[47, 1, 47]),
            Answer::Sidecars([whole(1, &[1, 47]), whole(2, &[1, 47]), whole(4, &[1, 47])].concat())
        );
        // From B's slot the first block lacks columns: nothing can be served.
        assert_eq!(
            model.expected_range(blocks[2].slot, 8, &CUSTODY),
            UNAVAILABLE
        );
    }

    #[test]
    fn a_range_refuses_or_answers_nothing_only_where_the_rules_say() {
        let blocks = known_blocks();
        let empty = Model::default();
        assert_eq!(empty.links.earliest(), None);
        assert_eq!(empty.expected_range(blocks[1].slot, 1, &[1]), UNAVAILABLE);
        assert_eq!(empty.expected_range(u64::MAX, 1, &[1]), UNAVAILABLE);
        assert_eq!(
            empty.expected_range(blocks[1].slot, 0, &[1]),
            Answer::Sidecars(Vec::new())
        );
        assert_eq!(
            empty.expected_range(blocks[1].slot, 4, &[]),
            Answer::Sidecars(Vec::new())
        );
        let model = model_of(&[(1, &CUSTODY)]);
        // Below earliest_available_slot, another column, or a range before A: refused.
        assert_eq!(model.expected_range(blocks[0].slot, 4, &[1]), UNAVAILABLE);
        assert_eq!(model.expected_range(blocks[1].slot, 4, &[2]), UNAVAILABLE);
        // Past the serve range: the future, an empty success.
        assert_eq!(
            model.expected_range(serve_range().1 + 1, 4, &[1]),
            Answer::Sidecars(Vec::new())
        );
        // In range, after the stored blocks: nothing stored there and nothing waited for.
        assert_eq!(
            model.expected_range(blocks[2].slot, 4, &[1]),
            Answer::Sidecars(Vec::new())
        );
        // D waits for B: a range over B's slot is refused until B is stored.
        let waiting = model_of(&[(1, &CUSTODY), (4, &CUSTODY)]);
        assert_eq!(
            waiting.links.by_block[&4],
            BlockLink::Pending(blocks[2].root, blocks[2].slot)
        );
        assert_eq!(waiting.expected_range(blocks[2].slot, 8, &[1]), UNAVAILABLE);
        assert_eq!(
            waiting.expected_range(blocks[1].slot, 8, &[1]),
            Answer::Sidecars(whole(1, &[1]))
        );
    }

    #[test]
    fn the_writer_settles_a_block_left_waiting_and_earliest_rises_to_it() {
        let blocks = known_blocks();
        let (a, b) = (&blocks[1], &blocks[2]);
        let mut model = model_of(&[(2, &[1])]);
        assert_eq!(model.links.by_block[&2], BlockLink::Pending(a.root, a.slot));
        assert_eq!(model.links.contiguous_from, None);
        // H, five slots past B: the write leaves B waiting, the settle step after it a gap.
        let written = model.store(7, 1, vec![7]);
        assert_eq!(written.by_block[&2], BlockLink::Pending(a.root, a.slot));
        assert_eq!(model.links.by_block[&2], BlockLink::Gap);
        assert_eq!(model.links.contiguous_from, Some(b.slot));
        // A comes late: stored, but below earliest_available_slot, so never served.
        model.store(1, 1, vec![1]);
        assert_eq!(model.links.by_block[&1], BlockLink::Start);
        assert_eq!(model.links.by_block[&2], BlockLink::Gap);
        assert_eq!(model.links.first_stored, Some(a.slot));
        assert_eq!(model.links.earliest(), Some(b.slot));
        assert!(model.expected_by_root(&[(a.root, vec![1])]).is_empty());
        assert_eq!(model.expected_by_root(&[(b.root, vec![1])]), whole(2, &[1]));
        assert_eq!(model.expected_range(a.slot, 8, &[1]), UNAVAILABLE);
    }

    #[test]
    fn of_two_tied_branches_a_range_serves_only_what_they_share() {
        let blocks = known_blocks();
        // D and F, both on B at one slot: tied, so the answer ends with B.
        let model = model_of(&[(1, &[1]), (2, &[1]), (4, &[1]), (5, &[1])]);
        assert_eq!(
            model.expected_range(blocks[1].slot, 8, &[1]),
            Answer::Sidecars([whole(1, &[1]), whole(2, &[1])].concat())
        );
        // From D's slot they share nothing.
        assert_eq!(model.expected_range(blocks[4].slot, 8, &[1]), UNAVAILABLE);
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
