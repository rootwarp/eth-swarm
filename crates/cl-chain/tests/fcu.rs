//! The `forkchoiceUpdatedV4` arguments from fork choice views built by hand, and the custody
//! bitmap (consensus-specs v1.7.0-beta.4).

use cl_chain::engine::fcu::{
    custody_column_bits, forkchoice_args, Bid, ForkchoiceArgs, ForkchoiceView, PayloadStatus,
    CUSTODY_COLUMN_BYTES,
};
use consensus_types::das;
use consensus_types::primitives::{Hash32, Root, U256};
use ssz::Encode;
use ssz_types::typenum::U128;
use ssz_types::BitVector;
use std::collections::HashMap;

/// Any custody set: the arguments carry it as given.
const CUSTODY: [u8; CUSTODY_COLUMN_BYTES] = [0xa5; CUSTODY_COLUMN_BYTES];

const HEAD: u8 = 0x33;
const JUSTIFIED: u8 = 0x22;
const FINALIZED: u8 = 0x11;

fn root(n: u8) -> Root {
    Root::repeat_byte(n)
}

fn hash(n: u8) -> Hash32 {
    Hash32::repeat_byte(n)
}

struct View {
    head: (Root, PayloadStatus),
    bids: HashMap<Root, Bid>,
    finalized: Root,
    justified: Root,
}

impl ForkchoiceView for View {
    fn head(&self) -> (Root, PayloadStatus) {
        self.head
    }

    fn bid_of(&self, root: &Root) -> Option<Bid> {
        self.bids.get(root).copied()
    }

    fn finalized_root(&self) -> Root {
        self.finalized
    }

    fn justified_root(&self) -> Root {
        self.justified
    }
}

/// A Gloas chain: the finalized block, the justified block and the head, each with a bid whose
/// `block_hash` is `0x?1…` and whose `parent_block_hash` is `0x?0…`.
fn gloas(status: PayloadStatus) -> View {
    let bid = |block, parent| Bid {
        block_hash: hash(block),
        parent_block_hash: hash(parent),
    };
    View {
        head: (root(HEAD), status),
        bids: HashMap::from([
            (root(FINALIZED), bid(0xf1, 0xf0)),
            (root(JUSTIFIED), bid(0xa1, 0xa0)),
            (root(HEAD), bid(0x31, 0x30)),
        ]),
        finalized: root(FINALIZED),
        justified: root(JUSTIFIED),
    }
}

fn args(view: &View) -> ForkchoiceArgs {
    forkchoice_args(view, CUSTODY).expect("the view knows its head")
}

/// A FULL head is its payload: the bid's `block_hash` (`gloas/validator.md` L355).
#[test]
fn full_head_block_hash() {
    let args = args(&gloas(PayloadStatus::Full));
    assert_eq!(args.head_block_hash, hash(0x31));
    assert_eq!(args.custody_columns, CUSTODY);
}

/// An EMPTY head's payload did not come: the head is the payload it built on, the bid's
/// `parent_block_hash` (`gloas/validator.md` L358).
#[test]
fn empty_head_parent_hash() {
    assert_eq!(
        args(&gloas(PayloadStatus::Empty)).head_block_hash,
        hash(0x30)
    );
}

/// A PENDING head's payload is not known yet: the bid's `parent_block_hash`, as EMPTY.
#[test]
fn pending_head_parent_hash() {
    assert_eq!(
        args(&gloas(PayloadStatus::Pending)).head_block_hash,
        hash(0x30)
    );
}

/// The finalized hash is the finalized block's bid `parent_block_hash`, one payload behind,
/// whatever the head's status (`gloas/fork-choice.md` L120). A finalized block the view does not
/// know, and a genesis block (its bid all zeros), give the zero hash.
#[test]
fn finalized_bid_parent_hash() {
    for status in [
        PayloadStatus::Full,
        PayloadStatus::Empty,
        PayloadStatus::Pending,
    ] {
        assert_eq!(args(&gloas(status)).finalized_block_hash, hash(0xf0));
    }
    let mut unknown = gloas(PayloadStatus::Full);
    unknown.bids.remove(&root(FINALIZED));
    assert_eq!(args(&unknown).finalized_block_hash, Hash32::ZERO);
    let mut genesis = gloas(PayloadStatus::Full);
    genesis.bids.insert(
        root(FINALIZED),
        Bid {
            block_hash: Hash32::ZERO,
            parent_block_hash: Hash32::ZERO,
        },
    );
    assert_eq!(args(&genesis).finalized_block_hash, Hash32::ZERO);
}

/// Without fast confirmation the safe block is the justified one, and its hash is that block's
/// bid `parent_block_hash` (`gloas/fast-confirmation.md` L38-41). Unknown: the zero hash. At a
/// justified block that is also the finalized one, safe and finalized agree.
#[test]
fn safe_is_justified_bid_parent_hash() {
    let args_full = args(&gloas(PayloadStatus::Full));
    assert_eq!(args_full.safe_block_hash, hash(0xa0));
    assert_eq!(
        args(&gloas(PayloadStatus::Empty)).safe_block_hash,
        hash(0xa0)
    );
    let mut unknown = gloas(PayloadStatus::Full);
    unknown.bids.remove(&root(JUSTIFIED));
    assert_eq!(args(&unknown).safe_block_hash, Hash32::ZERO);
    let mut same = gloas(PayloadStatus::Full);
    same.justified = root(FINALIZED);
    let same = args(&same);
    assert_eq!(same.safe_block_hash, same.finalized_block_hash);
    assert_eq!(same.safe_block_hash, hash(0xf0));
}

/// A Fulu head is FULL and its view gives its payload `block_hash` as both bid fields: the head,
/// safe and finalized hashes are the payload hashes, as a Fulu node sends them.
#[test]
fn fulu_head_uses_payload_hash() {
    assert_eq!(
        Bid::fulu(hash(0x41)),
        Bid {
            block_hash: hash(0x41),
            parent_block_hash: hash(0x41),
        }
    );
    let view = View {
        head: (root(HEAD), PayloadStatus::Full),
        bids: HashMap::from([
            (root(HEAD), Bid::fulu(hash(0x41))),
            (root(JUSTIFIED), Bid::fulu(hash(0x42))),
            (root(FINALIZED), Bid::fulu(hash(0x43))),
        ]),
        finalized: root(FINALIZED),
        justified: root(JUSTIFIED),
    };
    let args = args(&view);
    assert_eq!(args.head_block_hash, hash(0x41));
    assert_eq!(args.safe_block_hash, hash(0x42));
    assert_eq!(args.finalized_block_hash, hash(0x43));
}

/// A head block the view has no bid for gives no arguments, never a zero head.
#[test]
fn unknown_head_has_no_args() {
    let mut view = gloas(PayloadStatus::Full);
    view.bids.remove(&root(HEAD));
    assert_eq!(forkchoice_args(&view, CUSTODY), None);
}

/// Four custody groups set exactly the bits of their columns (`compute_columns_for_custody_group`)
/// in the 16 bytes, which are the SSZ `Bitvector[128]` of those columns.
#[test]
fn custody_bitmap() {
    let node_id = U256::from(0x00c0_ffee_u64);
    let groups = das::get_custody_groups(node_id, das::CUSTODY_REQUIREMENT).unwrap();
    assert_eq!(groups.len(), 4);
    let mut columns = Vec::new();
    for group in &groups {
        columns.extend(das::compute_columns_for_custody_group(*group).unwrap());
    }
    let bits = custody_column_bits(&das::custody_columns(node_id, groups.len() as u64).unwrap());
    assert_eq!(bits.len(), 16);
    for column in 0..das::NUMBER_OF_COLUMNS {
        let set = (bits[(column / 8) as usize] >> (column % 8)) & 1 == 1;
        assert_eq!(set, columns.contains(&column), "column {column}");
    }
    let ones: u32 = bits.iter().map(|byte| byte.count_ones()).sum();
    assert_eq!(ones as usize, columns.len());
    let mut ssz_bits = BitVector::<U128>::new();
    for column in &columns {
        ssz_bits.set(*column as usize, true).unwrap();
    }
    assert_eq!(ssz_bits.as_ssz_bytes(), bits.to_vec());
    // Bit `i % 8` of byte `i / 8`, least significant first.
    let mut want = [0u8; CUSTODY_COLUMN_BYTES];
    want[0] = 0x01;
    want[1] = 0x02;
    want[15] = 0x80;
    assert_eq!(custody_column_bits(&[0, 9, 127]), want);
    assert_eq!(custody_column_bits(&[]), [0; CUSTODY_COLUMN_BYTES]);
    assert_eq!(custody_column_bits(&[128, 1000]), [0; CUSTODY_COLUMN_BYTES]);
}
