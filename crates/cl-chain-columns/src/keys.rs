//! On-disk layout of the column store. Readers in other processes (cl-store) decode the same
//! bytes, so changing anything here is a schema change.
//!
//! | table              | key                                                   | value                       |
//! |--------------------|-------------------------------------------------------|-----------------------------|
//! | [`COLUMNS_TABLE`]  | `slot (u64 BE) ‖ block_root (32) ‖ column_index (u64 BE)`, 48 bytes | SSZ `DataColumnSidecar` |
//! | [`ROOTS_TABLE`]    | `block_root (32)`                                     | `slot (u64 BE)`             |
//! | [`LINKS_TABLE`]    | `block_root (32)`                                     | [`BlockLink`]: `kind (1) ‖ root (32)`, and for kind 3 `‖ slot (u64 BE)` |
//! | [`META_TABLE`]     | ASCII name: [`CGC_KEY`], [`CGC_SET_SLOT_KEY`], [`METADATA_SEQ_KEY`], [`ADVERTISED_CGC_KEY`], [`FINALIZED_SLOT_KEY`], [`FIRST_STORED_SLOT_KEY`], [`CONTIGUOUS_FROM_KEY`] | `u64 BE` |
//!
//! Big-endian slot first makes MDBX's lexicographic key order equal slot order, so finality
//! pruning is one cursor walk from the first key up to the finalized slot. All columns of a block
//! share the 40-byte [`block_prefix`] and sit next to each other in index order, so a block-root
//! lookup is "slot from [`ROOTS_TABLE`], then a prefix scan".

/// Beacon block root (`Root`, 32 bytes).
pub type BlockRoot = [u8; 32];

/// Column sidecars: [`column_key`] → opaque SSZ bytes.
pub const COLUMNS_TABLE: &str = "columns";
/// Index from block root to the slot that prefixes its column keys.
pub const ROOTS_TABLE: &str = "column_roots";
/// Index from block root to the block's [`BlockLink`]: how it ties to the stored block before
/// it on its chain.
pub const LINKS_TABLE: &str = "column_links";
/// Small scalar values for this env: the custody record ([`CGC_KEY`], [`CGC_SET_SLOT_KEY`],
/// [`METADATA_SEQ_KEY`], [`ADVERTISED_CGC_KEY`]), [`FINALIZED_SLOT_KEY`] and
/// [`FIRST_STORED_SLOT_KEY`].
pub const META_TABLE: &str = "meta";
/// Every table this env holds, in creation order.
pub const TABLES: [&str; 4] = [COLUMNS_TABLE, ROOTS_TABLE, META_TABLE, LINKS_TABLE];

/// [`META_TABLE`] key of the node's custody group count. It never decreases
/// ([`Error::CgcDecrease`](crate::Error::CgcDecrease)).
pub const CGC_KEY: &[u8] = b"cgc";
/// [`META_TABLE`] key of the slot at which [`CGC_KEY`] was last set: the slot Status
/// `earliest_available_slot` reflects (`fulu/validator.md`).
pub const CGC_SET_SLOT_KEY: &[u8] = b"cgc_set_slot";
/// [`META_TABLE`] key of the node's MetaData `seq_number`, kept so it never goes back across a
/// restart.
pub const METADATA_SEQ_KEY: &[u8] = b"metadata_seq";
/// [`META_TABLE`] key of the custody group count the node advertises (ENR `cgc`, MetaData
/// `custody_group_count`); 0 while it withholds its custody from peers.
pub const ADVERTISED_CGC_KEY: &[u8] = b"advertised_cgc";
/// [`META_TABLE`] key of the finalized-slot watermark: the highest slot finality pruning has
/// covered. Writes at or below it are refused, so a late write cannot undo a prune.
pub const FINALIZED_SLOT_KEY: &[u8] = b"finalized_slot";
/// [`META_TABLE`] key of the lowest slot any column was ever stored at, written in the
/// transaction that stores that column. Pruning never moves it: it records where storing began.
///
/// A historical minimum, not proof that the data is held: one column lowers it even if the
/// block's other custody columns never arrive, pruning leaves it below the data that remains,
/// and raising the custody group count does not move it. Status `earliest_available_slot` is
/// derived from it but never equal to it alone: it is the highest of this slot, the slot after
/// [`FINALIZED_SLOT_KEY`] and [`CGC_SET_SLOT_KEY`].
pub const FIRST_STORED_SLOT_KEY: &[u8] = b"first_stored_slot";

/// [`META_TABLE`] key of the slot from which the stored blocks are contiguous: the highest slot
/// of a block written with [`BlockLink::Gap`] (a blob-carrying block before it on its chain is
/// not held), or the slot after the highest block of an env written before [`LINKS_TABLE`]
/// existed (its blocks have no links). It only rises. Status `earliest_available_slot` is never
/// below it.
pub const CONTIGUOUS_FROM_KEY: &[u8] = b"contiguous_from";

/// How a stored block ties to the stored block before it on its chain, as cl-chain learned when
/// it stored the block (the parent roots come from the blocks the reference vouched for, through
/// any blocks without blobs, which hold no columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockLink {
    /// Nothing before it on its chain is to be held: it is the first block from the slot custody
    /// was set at, or its chain reaches the finalized watermark first.
    Start,
    /// The nearest blob-carrying block before it on its chain is this stored root.
    Parent(BlockRoot),
    /// A blob-carrying block before it on its chain is not held, or its chain could not be
    /// followed: the store is contiguous only from this block on.
    Gap,
    /// The nearest blob-carrying block before it on its chain is this root, at this slot, not
    /// stored yet: its columns may still be on their way. It links once that block is written,
    /// or is settled ([`ColumnWriter::settle_pending`](crate::ColumnWriter::settle_pending)): a
    /// [`BlockLink::Start`] once finality covers the slot, else a [`BlockLink::Gap`]. Until then
    /// it ties to nothing and raises nothing, and the slot is known to hold a block the store
    /// lacks ([`Snapshot::first_pending_target`](crate::Snapshot::first_pending_target)).
    Pending(BlockRoot, u64),
}

/// Length of a [`BlockLink`] value of kinds 0 to 2: `kind ‖ root`.
pub const LINK_LEN: usize = 1 + 32;
/// Length of a [`BlockLink::Pending`] value: `3 ‖ root ‖ slot BE`.
pub const PENDING_LINK_LEN: usize = LINK_LEN + 8;

impl BlockLink {
    /// The value stored in [`LINKS_TABLE`]: [`LINK_LEN`] bytes, [`PENDING_LINK_LEN`] for a
    /// pending link.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, root) = match self {
            BlockLink::Start => (0, [0; 32]),
            BlockLink::Parent(root) => (1, *root),
            BlockLink::Gap => (2, [0; 32]),
            BlockLink::Pending(root, _) => (3, *root),
        };
        let mut out = Vec::with_capacity(PENDING_LINK_LEN);
        out.push(kind);
        out.extend_from_slice(&root);
        if let BlockLink::Pending(_, slot) = self {
            out.extend_from_slice(&slot.to_be_bytes());
        }
        out
    }

    /// The link a [`LINKS_TABLE`] value holds; `None` for any other bytes, a pending link
    /// without its slot ([`Self::legacy_pending_target`]) included.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&kind, rest) = bytes.split_first()?;
        let root: BlockRoot = rest.get(..32)?.try_into().ok()?;
        match (kind, &rest[32..]) {
            (0, []) if root == [0; 32] => Some(BlockLink::Start),
            (1, []) => Some(BlockLink::Parent(root)),
            (2, []) if root == [0; 32] => Some(BlockLink::Gap),
            (3, slot) => Some(BlockLink::Pending(root, decode_u64(slot)?)),
            _ => None,
        }
    }

    /// The target of a pending link as stores before pending links carried their target's slot
    /// wrote it (`3 ‖ root`, [`LINK_LEN`] bytes); `None` for any other bytes. The writer migrates
    /// such a link when it opens the env, and a reader reads it as a [`BlockLink::Gap`].
    #[must_use]
    pub fn legacy_pending_target(bytes: &[u8]) -> Option<BlockRoot> {
        match bytes.split_first()? {
            (3, root) => root.try_into().ok(),
            _ => None,
        }
    }
}

/// Length of a [`column_key`].
pub const COLUMN_KEY_LEN: usize = BLOCK_PREFIX_LEN + 8;
/// Length of a [`block_prefix`].
pub const BLOCK_PREFIX_LEN: usize = 8 + 32;

/// Key of one column: `slot BE ‖ block_root ‖ column_index BE`.
#[must_use]
pub fn column_key(slot: u64, block_root: &BlockRoot, column_index: u64) -> [u8; COLUMN_KEY_LEN] {
    let mut key = [0u8; COLUMN_KEY_LEN];
    key[..BLOCK_PREFIX_LEN].copy_from_slice(&block_prefix(slot, block_root));
    key[BLOCK_PREFIX_LEN..].copy_from_slice(&column_index.to_be_bytes());
    key
}

/// Prefix shared by every column key of one block: `slot BE ‖ block_root`.
#[must_use]
pub fn block_prefix(slot: u64, block_root: &BlockRoot) -> [u8; BLOCK_PREFIX_LEN] {
    let mut prefix = [0u8; BLOCK_PREFIX_LEN];
    prefix[..8].copy_from_slice(&slot.to_be_bytes());
    prefix[8..].copy_from_slice(block_root);
    prefix
}

/// Splits a [`column_key`] into `(slot, block_root, column_index)`; `None` if the length is wrong.
#[must_use]
pub fn decode_column_key(key: &[u8]) -> Option<(u64, BlockRoot, u64)> {
    if key.len() != COLUMN_KEY_LEN {
        return None;
    }
    let slot = decode_u64(&key[..8])?;
    let block_root = key[8..BLOCK_PREFIX_LEN].try_into().ok()?;
    let column_index = decode_u64(&key[BLOCK_PREFIX_LEN..])?;
    Some((slot, block_root, column_index))
}

/// Decodes an 8-byte big-endian `u64`; `None` if the length is wrong.
#[must_use]
pub fn decode_u64(bytes: &[u8]) -> Option<u64> {
    bytes.try_into().ok().map(u64::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_A: BlockRoot = [0xaa; 32];
    const ROOT_B: BlockRoot = [0xbb; 32];

    #[test]
    fn column_key_is_slot_root_index_big_endian() {
        let key = column_key(0x0102, &ROOT_A, 7);
        assert_eq!(key.len(), COLUMN_KEY_LEN);
        assert_eq!(&key[..8], &0x0102u64.to_be_bytes());
        assert_eq!(&key[8..40], &ROOT_A);
        assert_eq!(&key[40..], &7u64.to_be_bytes());
    }

    #[test]
    fn keys_sort_by_slot_then_root_then_index() {
        let mut keys = vec![
            column_key(256, &ROOT_A, 0),
            column_key(1, &ROOT_B, 0),
            column_key(1, &ROOT_A, 127),
            column_key(1, &ROOT_A, 2),
        ];
        keys.sort();
        assert_eq!(
            keys,
            vec![
                column_key(1, &ROOT_A, 2),
                column_key(1, &ROOT_A, 127),
                column_key(1, &ROOT_B, 0),
                column_key(256, &ROOT_A, 0),
            ]
        );
    }

    #[test]
    fn block_prefix_is_the_first_forty_key_bytes() {
        let key = column_key(9, &ROOT_B, 3);
        assert_eq!(block_prefix(9, &ROOT_B), key[..BLOCK_PREFIX_LEN]);
    }

    #[test]
    fn links_round_trip_and_refuse_other_bytes() {
        for link in [
            BlockLink::Start,
            BlockLink::Parent(ROOT_A),
            BlockLink::Gap,
            BlockLink::Pending(ROOT_B, 77),
        ] {
            assert_eq!(BlockLink::decode(&link.encode()), Some(link));
            assert_eq!(BlockLink::legacy_pending_target(&link.encode()), None);
        }
        assert_eq!(BlockLink::Gap.encode().len(), LINK_LEN);
        let pending = BlockLink::Pending(ROOT_B, 0x0102).encode();
        assert_eq!(pending.len(), PENDING_LINK_LEN);
        assert_eq!(pending[0], 3);
        assert_eq!(&pending[1..33], &ROOT_B);
        assert_eq!(&pending[33..], &0x0102u64.to_be_bytes());
        assert_eq!(BlockLink::decode(&[1; 32]), None);
        assert_eq!(BlockLink::decode(&[4; LINK_LEN]), None);
        assert_eq!(BlockLink::decode(&[]), None);
        let mut gap = BlockLink::Gap.encode();
        gap[5] = 1;
        assert_eq!(BlockLink::decode(&gap), None);
        // Only a pending link carries a slot.
        let mut parent = BlockLink::Parent(ROOT_A).encode();
        parent.extend_from_slice(&9u64.to_be_bytes());
        assert_eq!(BlockLink::decode(&parent), None);
        assert_eq!(BlockLink::decode(&pending[..PENDING_LINK_LEN - 1]), None);
        // A pending link without its slot, as stores wrote it before: not a link of today.
        let mut legacy = vec![3];
        legacy.extend_from_slice(&ROOT_B);
        assert_eq!(BlockLink::decode(&legacy), None);
        assert_eq!(BlockLink::legacy_pending_target(&legacy), Some(ROOT_B));
        assert_eq!(BlockLink::legacy_pending_target(&[3; 20]), None);
    }

    #[test]
    fn decode_round_trips_and_rejects_bad_lengths() {
        let key = column_key(u64::MAX, &ROOT_A, 127);
        assert_eq!(decode_column_key(&key), Some((u64::MAX, ROOT_A, 127)));
        assert_eq!(decode_column_key(&key[..47]), None);
        assert_eq!(decode_u64(&9u64.to_be_bytes()), Some(9));
        assert_eq!(decode_u64(&[0; 7]), None);
    }
}
