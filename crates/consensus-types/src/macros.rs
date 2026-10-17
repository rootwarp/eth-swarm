//! Container definition macros.
//!
//! Every container gets the SSZ and tree-hash derives plus a [`crate::caps::SszMaxLen`] impl, the
//! largest encoding its field bounds allow. That impl is what [`crate::caps::max_size`] is built
//! from, so a new container cannot exist without a size bound.

/// Defines `pub struct $name` (optionally generic over an [`crate::preset::EthSpec`] `E`).
///
/// Extra attributes, such as the progressive-container `#[tree_hash(...)]`, go after the doc
/// comment so that they follow the derive that introduces them.
macro_rules! container {
    (
        $(#[$meta:meta])*
        $name:ident $(<$E:ident>)? {
            $( $(#[$fmeta:meta])* $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone, PartialEq, ssz_derive::Encode, ssz_derive::Decode, tree_hash_derive::TreeHash)]
        $(#[$meta])*
        pub struct $name $(<$E: $crate::preset::EthSpec>)? {
            $( $(#[$fmeta])* pub $field: $ty, )*
        }

        impl $(<$E: $crate::preset::EthSpec>)? $crate::caps::SszMaxLen for $name $(<$E>)? {
            fn ssz_max_len() -> u64 {
                0u64 $( .saturating_add($crate::caps::field_max_len::<$ty>()) )*
            }
        }
    };
}

pub(crate) use container;
