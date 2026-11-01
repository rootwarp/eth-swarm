//! Keys of the env. Big-endian slot first, so MDBX's byte order is slot order and a range of
//! slots is one cursor walk.

/// A block root (`Root`, 32 bytes).
pub type Root = [u8; 32];

/// Length of a [`slot_root_key`].
pub const SLOT_ROOT_KEY_LEN: usize = 8 + 32;

/// `slot (u64 BE) ‖ root`: the key of `blocks` and `states` (by block root), and the prefix
/// of every `columns` key of the block.
#[must_use]
pub fn slot_root_key(slot: u64, root: &Root) -> [u8; SLOT_ROOT_KEY_LEN] {
    let mut key = [0u8; SLOT_ROOT_KEY_LEN];
    key[..8].copy_from_slice(&slot.to_be_bytes());
    key[8..].copy_from_slice(root);
    key
}

/// `(slot, root)` of a [`slot_root_key`]; `None` for any other length.
#[must_use]
pub fn decode_slot_root_key(key: &[u8]) -> Option<(u64, Root)> {
    let key: &[u8; SLOT_ROOT_KEY_LEN] = key.try_into().ok()?;
    let (slot, root) = key.split_at(8);
    Some((
        u64::from_be_bytes(slot.try_into().ok()?),
        root.try_into().ok()?,
    ))
}

/// `meta` row of the schema version, `u64 BE` ([`crate::version`]).
pub const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

/// `meta` row reserved for #130's head/finalized stamp, written in every commit. Any length;
/// nothing in this version reads it.
pub const STAMP_KEY: &[u8] = b"stamp";

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn a_slot_root_key_is_slot_big_endian_then_root() {
        let root: Root = std::array::from_fn(|i| i as u8);
        let key = slot_root_key(0x0102_0304_0506_0708, &root);
        assert_eq!(key.len(), SLOT_ROOT_KEY_LEN);
        assert_eq!(SLOT_ROOT_KEY_LEN, 40);
        assert_eq!(&key[..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&key[8..], &root);
        assert_eq!(
            decode_slot_root_key(&key),
            Some((0x0102_0304_0506_0708, root))
        );
        assert_eq!(decode_slot_root_key(&key[..39]), None);
        assert_eq!(decode_slot_root_key(&[0; 41]), None);
    }

    proptest! {
        /// MDBX compares keys as bytes: that order is `(slot, root)` order.
        #[test]
        fn key_byte_order_is_slot_then_root_order(
            a in (any::<u64>(), any::<[u8; 32]>()),
            b in (any::<u64>(), any::<[u8; 32]>()),
            same_slot in any::<bool>(),
        ) {
            let b = if same_slot { (a.0, b.1) } else { b };
            prop_assert_eq!(
                slot_root_key(a.0, &a.1).cmp(&slot_root_key(b.0, &b.1)),
                a.cmp(&b)
            );
        }
    }
}
