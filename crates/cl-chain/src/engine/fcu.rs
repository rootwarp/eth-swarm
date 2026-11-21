//! The arguments of `engine_forkchoiceUpdatedV4` (execution-apis `amsterdam.md`), from a fork
//! choice view. The rules are consensus-specs v1.7.0-beta.4:
//!
//! - **Head** (`gloas/validator.md` L347-358): the head block's bid `block_hash` when the head
//!   node's payload is FULL; otherwise (EMPTY or PENDING) the bid's `parent_block_hash`.
//! - **Finalized** (`gloas/fork-choice.md` L120, L125-126): the finalized block's bid
//!   `parent_block_hash`, whatever the status of its own payload.
//! - **Safe** (`gloas/fork-choice.md` L121, `gloas/fast-confirmation.md` L38-41): the safe
//!   block's bid `parent_block_hash`. The fast confirmation rule is not wired yet, so the safe
//!   block is the justified checkpoint's block.
//! - **Unknown blocks.** A finalized or safe block the view has no bid for gives the zero hash,
//!   as before any payload is finalized (`bellatrix/fork-choice.md` L84-87). A head without a
//!   bid gives no arguments: there is nothing to tell the EL.
//! - **Fulu blocks** have no bid. The view gives a Fulu block's payload `block_hash` as both
//!   fields ([`Bid::fulu`]), so the same rules give the payload hash a Fulu node sends: for the
//!   head (a Fulu head is FULL), and for the finalized and safe blocks
//!   (`bellatrix/fast-confirmation.md` L26-28).
//! - **Custody** (`gloas/fork-choice.md` L131-134, L254-262): the custody columns as the SSZ
//!   `CustodyColumnBits` ([`custody_column_bits`]). They are always sent, never `null`.
//! - **Payload attributes**: none. v1 builds no blocks, so the request has no
//!   `payload_attributes`, and cl-engine sends `null` with `engine_forkchoiceUpdatedV4`.

use super::client::FcuOutcome;
pub use crate::persist::durable::PayloadStatus;
use consensus_types::das::NUMBER_OF_COLUMNS;
use consensus_types::primitives::{ColumnIndex, Hash32, Root};
use ethswarm_proto::engine as pb;

/// Bytes of `CustodyColumnBits` (`Bitvector[NUMBER_OF_COLUMNS]`): the 16 bytes of
/// `custodyColumns`.
pub const CUSTODY_COLUMN_BYTES: usize = NUMBER_OF_COLUMNS as usize / 8;

/// What fork choice knows of a block's execution payload: two fields of its
/// `body.signed_execution_payload_bid.message`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bid {
    /// `bid.block_hash`: the payload the block commits to.
    pub block_hash: Hash32,
    /// `bid.parent_block_hash`: the payload it builds on.
    pub parent_block_hash: Hash32,
}

impl Bid {
    /// A Fulu block: its payload's `block_hash`, as both fields.
    #[must_use]
    pub const fn fulu(block_hash: Hash32) -> Self {
        Self {
            block_hash,
            parent_block_hash: block_hash,
        }
    }
}

/// The fork choice state the arguments come from: the chain core's store
/// ([`crate::core::ChainCore`]), or a view built by hand in tests.
pub trait ForkchoiceView {
    /// The head node: its block root and its payload status. A Fulu head is FULL.
    fn head(&self) -> (Root, PayloadStatus);
    /// The bid of the block at `root`, or `None` for a block the view does not know.
    fn bid_of(&self, root: &Root) -> Option<Bid>;
    /// `store.finalized_checkpoint.root`.
    fn finalized_root(&self) -> Root;
    /// `store.justified_checkpoint.root`: the safe block until fast confirmation is wired.
    fn justified_root(&self) -> Root;
}

/// One `forkchoiceUpdatedV4` call's arguments, without its `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForkchoiceArgs {
    /// `forkchoiceState.headBlockHash`.
    pub head_block_hash: Hash32,
    /// `forkchoiceState.safeBlockHash`.
    pub safe_block_hash: Hash32,
    /// `forkchoiceState.finalizedBlockHash`.
    pub finalized_block_hash: Hash32,
    /// `custodyColumns`: the SSZ `CustodyColumnBits`.
    pub custody_columns: [u8; CUSTODY_COLUMN_BYTES],
}

/// Where the chain core sends forkchoiceUpdated arguments: [`FcuSender`] over engine.v1.
///
/// [`FcuSender`]: super::client::FcuSender
pub trait ForkchoiceSink: Send {
    /// Sends `args`, without a wait for the EL.
    fn send(&self, args: ForkchoiceArgs);
    /// An answered call, each once: an `INVALID` or `INVALID_BLOCK_HASH` answer not taken yet
    /// first (a later answer does not replace it), else the latest if it was not taken yet.
    fn take_outcome(&self) -> Option<FcuOutcome>;
    /// Stops for good: arguments not sent yet are dropped, a lost call is not tried again, and
    /// no later call is sent. A call already on its way can still be answered.
    fn halt(&self);
}

impl ForkchoiceArgs {
    /// The engine.v1 request for these arguments with `seq`. It has no `payload_attributes`
    /// (cl-engine sends `null` and picks `engine_forkchoiceUpdatedV4`) and no raised wait.
    #[must_use]
    pub fn request(&self, seq: u64) -> pb::ForkchoiceUpdatedRequest {
        pb::ForkchoiceUpdatedRequest {
            seq,
            head_block_hash: self.head_block_hash.to_vec(),
            safe_block_hash: self.safe_block_hash.to_vec(),
            finalized_block_hash: self.finalized_block_hash.to_vec(),
            payload_attributes: None,
            timeout_ms: 0,
            custody_columns: self.custody_columns.to_vec(),
        }
    }
}

/// The arguments for `view`'s head, with `custody_columns` as the custody set (see the module
/// docs). `None` when the view has no bid for the head block.
#[must_use]
pub fn forkchoice_args(
    view: &impl ForkchoiceView,
    custody_columns: [u8; CUSTODY_COLUMN_BYTES],
) -> Option<ForkchoiceArgs> {
    let (head, status) = view.head();
    let bid = view.bid_of(&head)?;
    let head_block_hash = match status {
        PayloadStatus::Full => bid.block_hash,
        PayloadStatus::Empty | PayloadStatus::Pending => bid.parent_block_hash,
    };
    let parent_hash = |root: Root| {
        view.bid_of(&root)
            .map_or(Hash32::ZERO, |bid| bid.parent_block_hash)
    };
    Some(ForkchoiceArgs {
        head_block_hash,
        safe_block_hash: parent_hash(view.justified_root()),
        finalized_block_hash: parent_hash(view.finalized_root()),
        custody_columns,
    })
}

/// `get_custody_column_bits` (`gloas/fork-choice.md` L254-262) of the node's custody
/// `columns` (`Custody::custody_columns`), as the SSZ `Bitvector[128]`: column `i` is bit
/// `i % 8` of byte `i / 8`, least significant bit first. An index at or past
/// `NUMBER_OF_COLUMNS` is not a column and sets nothing.
#[must_use]
pub fn custody_column_bits(columns: &[ColumnIndex]) -> [u8; CUSTODY_COLUMN_BYTES] {
    let mut bits = [0; CUSTODY_COLUMN_BYTES];
    for &column in columns {
        if column < NUMBER_OF_COLUMNS {
            // Below 128, so both fit.
            bits[(column / 8) as usize] |= 1 << (column % 8);
        }
    }
    bits
}
