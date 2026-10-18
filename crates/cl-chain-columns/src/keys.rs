//! On-disk layout of the column store. Readers in other processes (cl-store) decode the same
//! bytes, so changing anything here is a schema change.
//!
//! | table              | key                                                   | value                       |
//! |--------------------|-------------------------------------------------------|-----------------------------|
//! | [`COLUMNS_TABLE`]  | `slot (u64 BE) ‖ block_root (32) ‖ column_index (u64 BE)`, 48 bytes | SSZ `DataColumnSidecar` |
//! | [`ROOTS_TABLE`]    | `block_root (32)`                                     | `slot (u64 BE)`             |
//! | [`META_TABLE`]     | ASCII name: [`CGC_KEY`], [`CGC_SET_SLOT_KEY`], [`METADATA_SEQ_KEY`], [`ADVERTISED_CGC_KEY`], [`FINALIZED_SLOT_KEY`] | `u64 BE` |
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
/// Small scalar values for this env: the custody record ([`CGC_KEY`], [`CGC_SET_SLOT_KEY`],
/// [`METADATA_SEQ_KEY`], [`ADVERTISED_CGC_KEY`]) and [`FINALIZED_SLOT_KEY`].
pub const META_TABLE: &str = "meta";
/// Every table this env holds, in creation order.
pub const TABLES: [&str; 3] = [COLUMNS_TABLE, ROOTS_TABLE, META_TABLE];

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
    fn decode_round_trips_and_rejects_bad_lengths() {
        let key = column_key(u64::MAX, &ROOT_A, 127);
        assert_eq!(decode_column_key(&key), Some((u64::MAX, ROOT_A, 127)));
        assert_eq!(decode_column_key(&key[..47]), None);
        assert_eq!(decode_u64(&9u64.to_be_bytes()), Some(9));
        assert_eq!(decode_u64(&[0; 7]), None);
    }
}
