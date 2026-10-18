//! Custody helpers from `fulu/das-core.md` ("Helpers") and `fulu/p2p-interface.md`, ported 1:1
//! (unchanged in Gloas).
//!
//! - [`get_custody_groups`]: the custody groups of a node id for a custody group count.
//! - [`compute_columns_for_custody_group`]: the columns of one custody group.
//! - [`compute_subnet_for_data_column_sidecar`]: the `data_column_sidecar_{subnet_id}` subnet of
//!   a column.
//! - [`custody_columns`]: the columns of every custody group of a node, the set the node keeps
//!   and subscribes to.
//!
//! The spec functions `assert` their inputs; here an out-of-range input is a [`DasError`]. A
//! discv5 node id (32 bytes) is the big-endian encoding of the spec's `NodeID` (`uint256`):
//! pass `U256::from_be_bytes(node_id.raw())`.

use crate::primitives::{ColumnIndex, U256};
use sha2::{Digest, Sha256};

/// `CustodyIndex` (`fulu/das-core.md`).
pub type CustodyIndex = u64;

/// `NUMBER_OF_COLUMNS` (`fulu/das-core.md`), equal to `EthSpec::NumberOfColumns` in both
/// presets.
pub const NUMBER_OF_COLUMNS: u64 = 128;
/// `NUMBER_OF_CUSTODY_GROUPS` (`fulu/das-core.md` "Custody setting", the same in the mainnet
/// and minimal configs).
pub const NUMBER_OF_CUSTODY_GROUPS: u64 = 128;
/// `CUSTODY_REQUIREMENT` (`fulu/das-core.md` "Custody setting"): the fewest custody groups an
/// honest node custodies and serves.
pub const CUSTODY_REQUIREMENT: u64 = 4;
/// `DATA_COLUMN_SIDECAR_SUBNET_COUNT` (`fulu` config).
pub const DATA_COLUMN_SIDECAR_SUBNET_COUNT: u64 = 128;

/// An input the spec function would `assert` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DasError {
    /// `custody_group_count` is above [`NUMBER_OF_CUSTODY_GROUPS`].
    #[error(
        "custody group count {0} exceeds NUMBER_OF_CUSTODY_GROUPS ({NUMBER_OF_CUSTODY_GROUPS})"
    )]
    CustodyGroupCount(u64),
    /// `custody_group` is not below [`NUMBER_OF_CUSTODY_GROUPS`].
    #[error(
        "custody group {0} is not below NUMBER_OF_CUSTODY_GROUPS ({NUMBER_OF_CUSTODY_GROUPS})"
    )]
    CustodyGroup(u64),
}

/// `get_custody_groups(node_id, custody_group_count)`: sorted, without duplicates.
///
/// # Errors
///
/// [`DasError::CustodyGroupCount`] if `custody_group_count` exceeds
/// [`NUMBER_OF_CUSTODY_GROUPS`].
pub fn get_custody_groups(
    node_id: U256,
    custody_group_count: u64,
) -> Result<Vec<CustodyIndex>, DasError> {
    if custody_group_count > NUMBER_OF_CUSTODY_GROUPS {
        return Err(DasError::CustodyGroupCount(custody_group_count));
    }
    if custody_group_count == NUMBER_OF_CUSTODY_GROUPS {
        return Ok((0..NUMBER_OF_CUSTODY_GROUPS).collect());
    }
    let mut taken = [false; NUMBER_OF_CUSTODY_GROUPS as usize];
    let mut groups = Vec::with_capacity(custody_group_count as usize);
    let mut current_id = node_id;
    while (groups.len() as u64) < custody_group_count {
        let digest = Sha256::digest(current_id.to_le_bytes::<32>());
        let mut head = [0u8; 8];
        head.copy_from_slice(&digest[..8]);
        let group = u64::from_le_bytes(head) % NUMBER_OF_CUSTODY_GROUPS;
        if !std::mem::replace(&mut taken[group as usize], true) {
            groups.push(group);
        }
        // `current_id += 1`, wrapping from UINT256_MAX to 0 ("overflow prevention").
        current_id = current_id.wrapping_add(U256::from(1u8));
    }
    groups.sort_unstable();
    Ok(groups)
}

/// `compute_columns_for_custody_group(custody_group)`, in increasing order.
///
/// # Errors
///
/// [`DasError::CustodyGroup`] unless `custody_group` is below [`NUMBER_OF_CUSTODY_GROUPS`].
pub fn compute_columns_for_custody_group(
    custody_group: CustodyIndex,
) -> Result<Vec<ColumnIndex>, DasError> {
    if custody_group >= NUMBER_OF_CUSTODY_GROUPS {
        return Err(DasError::CustodyGroup(custody_group));
    }
    let columns_per_group = NUMBER_OF_COLUMNS / NUMBER_OF_CUSTODY_GROUPS;
    Ok((0..columns_per_group)
        .map(|index| NUMBER_OF_CUSTODY_GROUPS * index + custody_group)
        .collect())
}

/// `compute_subnet_for_data_column_sidecar(column_index)` (`fulu/p2p-interface.md`).
#[must_use]
pub fn compute_subnet_for_data_column_sidecar(column_index: ColumnIndex) -> u64 {
    column_index % DATA_COLUMN_SIDECAR_SUBNET_COUNT
}

/// Every column of every custody group of `node_id` at `custody_group_count`, sorted and
/// without duplicates.
///
/// # Errors
///
/// As [`get_custody_groups`].
pub fn custody_columns(
    node_id: U256,
    custody_group_count: u64,
) -> Result<Vec<ColumnIndex>, DasError> {
    let mut columns = Vec::new();
    for group in get_custody_groups(node_id, custody_group_count)? {
        columns.extend(compute_columns_for_custody_group(group)?);
    }
    columns.sort_unstable();
    columns.dedup();
    Ok(columns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EthSpec, Mainnet, Minimal};
    use typenum::Unsigned;

    fn id(decimal: &str) -> U256 {
        decimal.parse().unwrap()
    }

    /// `get_custody_groups_2` of the beta.4 vectors.
    #[test]
    fn custody_groups_match_a_vector() {
        let node =
            id("84065159290331321853352677657753050104170032838956724170714636178275273565505");
        assert_eq!(
            get_custody_groups(node, 6),
            Ok(vec![27, 29, 58, 67, 96, 117])
        );
    }

    /// `get_custody_groups_max_node_id_*`: the id wraps from UINT256_MAX to 0.
    #[test]
    fn the_node_id_wraps_at_the_top() {
        assert_eq!(get_custody_groups(U256::MAX, 4), Ok(vec![1, 47, 87, 102]));
        assert_eq!(
            get_custody_groups(U256::MAX - U256::from(1u8), 4),
            Ok(vec![1, 47, 87, 102])
        );
        assert_eq!(get_custody_groups(U256::MAX, 0), Ok(vec![]));
    }

    #[test]
    fn every_group_at_the_full_count_and_none_past_it() {
        let all: Vec<u64> = (0..NUMBER_OF_CUSTODY_GROUPS).collect();
        assert_eq!(
            get_custody_groups(U256::ZERO, NUMBER_OF_CUSTODY_GROUPS),
            Ok(all.clone())
        );
        // One below the full count takes the hashing path and still yields distinct groups.
        let most = get_custody_groups(U256::ZERO, NUMBER_OF_CUSTODY_GROUPS - 1).unwrap();
        assert_eq!(most.len(), 127);
        assert!(most.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(
            get_custody_groups(U256::ZERO, NUMBER_OF_CUSTODY_GROUPS + 1),
            Err(DasError::CustodyGroupCount(129))
        );
    }

    #[test]
    fn one_column_per_group() {
        assert_eq!(compute_columns_for_custody_group(0), Ok(vec![0]));
        assert_eq!(compute_columns_for_custody_group(127), Ok(vec![127]));
        assert_eq!(
            compute_columns_for_custody_group(128),
            Err(DasError::CustodyGroup(128))
        );
    }

    #[test]
    fn the_subnet_is_the_column_modulo_the_subnet_count() {
        assert_eq!(compute_subnet_for_data_column_sidecar(0), 0);
        assert_eq!(compute_subnet_for_data_column_sidecar(127), 127);
        assert_eq!(compute_subnet_for_data_column_sidecar(128), 0);
        assert_eq!(compute_subnet_for_data_column_sidecar(300), 44);
    }

    #[test]
    fn custody_columns_are_the_columns_of_the_groups() {
        assert_eq!(custody_columns(U256::MAX, 4), Ok(vec![1, 47, 87, 102]));
        assert_eq!(
            custody_columns(U256::MAX, 129),
            Err(DasError::CustodyGroupCount(129))
        );
    }

    #[test]
    fn the_column_count_is_the_presets() {
        assert_eq!(
            <Minimal as EthSpec>::NumberOfColumns::to_u64(),
            NUMBER_OF_COLUMNS
        );
        assert_eq!(
            <Mainnet as EthSpec>::NumberOfColumns::to_u64(),
            NUMBER_OF_COLUMNS
        );
    }
}
