//! The storage contract for gossip column sidecars ([`storage_contract`]).
//!
//! With no fork choice in probe mode, a column sidecar is trusted only if all of these hold,
//! checked in this order; the first that fails drops it with its [`Drop`] reason:
//!
//! 1. **Structure** (`verify_data_column_sidecar`, `gloas/p2p-interface.md`): `index <
//!    NUMBER_OF_COLUMNS` (else `not_custody`: no custody column has that index), at least one
//!    cell (else `commitments_mismatch`: a sidecar for zero blobs matches no bid), and as many
//!    proofs as cells (else `kzg_invalid`).
//! 2. **Subnet**: `compute_subnet_for_data_column_sidecar(index)` is the subnet it arrived on
//!    (else `wrong_subnet`).
//! 3. **Custody**: `index` is a column of one of our custody groups
//!    (`compute_columns_for_custody_group` of `get_custody_groups`, else `not_custody`), and
//!    the sidecar's slot is at or after `cgc_set_slot`, the slot our custody count was set at
//!    (else `before_cgc_set_slot`): columns are stored forward only, never backfilled.
//! 4. **Root**: the reference node vouches for `beacon_block_root`, at the sidecar's slot
//!    ([`RefView`], else `unknown_root`, which includes a reference that is down, slow or busy).
//! 5. **Commitments**: the bid of that block commits to exactly as many blobs as the sidecar
//!    has cells (else `commitments_mismatch`).
//! 6. **KZG** (`verify_data_column_sidecar_kzg_proofs`): cl-verify verifies every cell against
//!    the bid's commitment of its row, at cell index `index`, by
//!    `verify_cell_kzg_proof_batch` (else `kzg_invalid`). No verdict within the deadline, from a
//!    silent, overloaded or absent cl-verify, is `verify_timeout`: dropped, never stored.
//!
//! The cheap local checks (1 to 3) come first, so a column that cannot be ours never costs a
//! reference request or a KZG check. Every drop increments `probe_column_dropped_total{reason}`
//! ([`ColumnMetrics`]); the column store ([`super::ColumnIngest`]) adds `root_timeout` (the
//! root stayed unknown past its wait) and `store_failed` (the column env refused the write).
//! Only a [`Verified`] column can be stored ([`store_verified`]), and only [`storage_contract`]
//! makes one.

use super::{BlockApi, RefView, ReferenceApi};
use crate::da::custody::Custody;
use crate::verify::client::{KzgOutcome, KzgVerifier};
use consensus_types::das::{compute_subnet_for_data_column_sidecar, NUMBER_OF_COLUMNS};
use consensus_types::{gloas, EthSpec};
use ethswarm_proto::verify::KzgCellProof;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use ssz::Encode;
use std::time::Duration;

/// A column sidecar as it arrived on gossip.
#[derive(Debug, Clone, PartialEq)]
pub struct GossipColumn<E: EthSpec> {
    pub sidecar: gloas::DataColumnSidecar<E>,
    /// The `data_column_sidecar_{subnet_id}` topic it arrived on.
    pub subnet_id: u64,
}

/// Why a column is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Drop {
    #[error("unknown_root")]
    UnknownRoot,
    #[error("kzg_invalid")]
    KzgInvalid,
    #[error("commitments_mismatch")]
    CommitmentsMismatch,
    #[error("not_custody")]
    NotCustody,
    #[error("wrong_subnet")]
    WrongSubnet,
    #[error("verify_timeout")]
    VerifyTimeout,
    /// The sidecar's slot is before `cgc_set_slot`: no backfill.
    #[error("before_cgc_set_slot")]
    BeforeCustodySlot,
    /// The block root stayed unknown to the reference for the whole root wait.
    #[error("root_timeout")]
    RootTimeout,
    /// The column passed the contract, but the column env did not store it.
    #[error("store_failed")]
    StoreFailed,
}

impl Drop {
    /// Every reason.
    pub const ALL: [Drop; 9] = [
        Drop::UnknownRoot,
        Drop::KzgInvalid,
        Drop::CommitmentsMismatch,
        Drop::NotCustody,
        Drop::WrongSubnet,
        Drop::VerifyTimeout,
        Drop::BeforeCustodySlot,
        Drop::RootTimeout,
        Drop::StoreFailed,
    ];

    /// The `reason` label.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Drop::UnknownRoot => "unknown_root",
            Drop::KzgInvalid => "kzg_invalid",
            Drop::CommitmentsMismatch => "commitments_mismatch",
            Drop::NotCustody => "not_custody",
            Drop::WrongSubnet => "wrong_subnet",
            Drop::VerifyTimeout => "verify_timeout",
            Drop::BeforeCustodySlot => "before_cgc_set_slot",
            Drop::RootTimeout => "root_timeout",
            Drop::StoreFailed => "store_failed",
        }
    }
}

/// A column that passed the contract.
#[derive(Debug)]
pub struct Verified<'a, E: EthSpec> {
    column: &'a GossipColumn<E>,
}

impl<E: EthSpec> Verified<'_, E> {
    #[must_use]
    pub fn sidecar(&self) -> &gloas::DataColumnSidecar<E> {
        &self.column.sidecar
    }
}

type ReasonLabel = [(&'static str, &'static str); 1];

/// `probe_column_dropped_total{reason}`.
#[derive(Debug, Clone, Default)]
pub struct ColumnMetrics {
    dropped: Family<ReasonLabel, Counter>,
}

impl ColumnMetrics {
    /// Registers the counter in `registry`.
    pub fn register(registry: &mut Registry) -> Self {
        let metrics = Self::default();
        registry.register(
            "probe_column_dropped",
            "Gossip column sidecars dropped by the storage contract, by reason",
            metrics.dropped.clone(),
        );
        metrics
    }

    /// Columns dropped for `reason` so far.
    #[must_use]
    pub fn dropped(&self, reason: Drop) -> u64 {
        self.dropped
            .get_or_create(&[("reason", reason.reason())])
            .get()
    }

    pub(crate) fn count(&self, reason: Drop) {
        self.dropped
            .get_or_create(&[("reason", reason.reason())])
            .inc();
    }

    /// Counts `column` as dropped for `reason`, and logs it.
    pub(crate) fn drop_column<E: EthSpec>(&self, column: &GossipColumn<E>, reason: Drop) {
        self.count(reason);
        tracing::debug!(
            reason = reason.reason(),
            index = column.sidecar.index,
            slot = column.sidecar.slot,
            subnet = column.subnet_id,
            "column sidecar dropped"
        );
    }
}

/// What the contract checks KZG with.
pub struct ColumnContract<V> {
    pub kzg: V,
    pub verify_timeout: Duration,
    pub metrics: ColumnMetrics,
}

/// Checks `column` against the storage contract (see the module docs): the reference's root
/// (`refs`), our custody (`custody`) and KZG through cl-verify (`contract`). A drop is counted in
/// `contract.metrics` before it is returned.
///
/// # Errors
///
/// [`Drop`]: the first condition that does not hold.
pub async fn storage_contract<'a, E, A, V, S, C>(
    column: &'a GossipColumn<E>,
    refs: &RefView<A, E>,
    custody: &Custody<S, C>,
    contract: &ColumnContract<V>,
) -> Result<Verified<'a, E>, Drop>
where
    E: EthSpec,
    A: ReferenceApi + BlockApi,
    V: KzgVerifier,
{
    let checked = check(column, refs, custody, contract).await;
    if let Err(reason) = checked {
        contract.metrics.drop_column(column, reason);
    }
    checked.map(|()| Verified { column })
}

/// The contract's local checks, 1 to 3 of the module docs: structure, subnet and custody,
/// forward-only included. They need no reference request and no KZG check.
pub(crate) fn local_check<E: EthSpec, S, C>(
    column: &GossipColumn<E>,
    custody: &Custody<S, C>,
) -> Result<(), Drop> {
    let sidecar = &column.sidecar;
    if sidecar.index >= NUMBER_OF_COLUMNS {
        return Err(Drop::NotCustody);
    }
    if sidecar.column.is_empty() {
        return Err(Drop::CommitmentsMismatch);
    }
    if sidecar.kzg_proofs.len() != sidecar.column.len() {
        return Err(Drop::KzgInvalid);
    }
    if compute_subnet_for_data_column_sidecar(sidecar.index) != column.subnet_id {
        return Err(Drop::WrongSubnet);
    }
    if custody
        .custody_columns()
        .binary_search(&sidecar.index)
        .is_err()
    {
        return Err(Drop::NotCustody);
    }
    if sidecar.slot < custody.cgc_set_slot() {
        return Err(Drop::BeforeCustodySlot);
    }
    Ok(())
}

async fn check<E, A, V, S, C>(
    column: &GossipColumn<E>,
    refs: &RefView<A, E>,
    custody: &Custody<S, C>,
    contract: &ColumnContract<V>,
) -> Result<(), Drop>
where
    E: EthSpec,
    A: ReferenceApi + BlockApi,
    V: KzgVerifier,
{
    local_check(column, custody)?;
    let sidecar = &column.sidecar;
    let block = refs
        .lookup(sidecar.beacon_block_root.0)
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, "column root not vouched for by the reference");
            Drop::UnknownRoot
        })?;
    if block.slot != sidecar.slot {
        return Err(Drop::UnknownRoot);
    }
    if block.commitments.len() != sidecar.column.len() {
        return Err(Drop::CommitmentsMismatch);
    }
    let cells = block
        .commitments
        .iter()
        .zip(sidecar.column.iter().zip(sidecar.kzg_proofs.iter()))
        .map(|(commitment, (cell, proof))| KzgCellProof {
            commitment: commitment.to_vec(),
            cell_index: sidecar.index,
            cell: cell.to_vec(),
            proof: proof.to_vec(),
        })
        .collect();
    match contract
        .kzg
        .verify_cells(cells, contract.verify_timeout)
        .await
    {
        KzgOutcome::Valid => Ok(()),
        KzgOutcome::Invalid => Err(Drop::KzgInvalid),
        KzgOutcome::NoVerdict(why) => {
            tracing::debug!(%why, "no KZG verdict from cl-verify");
            Err(Drop::VerifyTimeout)
        }
    }
}

/// Stores a column that passed [`storage_contract`] in the column env, as its SSZ under
/// `(slot, beacon_block_root, index)`.
///
/// # Errors
///
/// The column store's ([`cl_chain_columns::ColumnWriter::write_columns`]).
pub fn store_verified<E: EthSpec>(
    verified: &Verified<'_, E>,
    writer: &cl_chain_columns::ColumnWriter,
) -> Result<(), cl_chain_columns::Error> {
    let sidecar = verified.sidecar();
    let ssz = sidecar.as_ssz_bytes();
    let column = cl_chain_columns::Column {
        index: sidecar.index,
        ssz: &ssz,
    };
    writer
        .write_columns(sidecar.slot, &sidecar.beacon_block_root.0, &[column])
        .map(drop)
}

#[cfg(test)]
mod tests {
    use super::super::{ApiError, Checkpoint, Header, RefLimits, Root};
    use super::*;
    use crate::da::custody::{Advertise, EnrCgc, EnrError};
    use crate::testing::{gloas_block, schedule, Spec};
    use cl_chain_columns::ColumnWriter;
    use consensus_types::primitives::U256;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A custody column of `U256::MAX`.
    const CUSTODY_COLUMN: u64 = 47;

    /// A reference that knows nothing: the roots below are seeded instead.
    struct NoReference;

    impl ReferenceApi for NoReference {
        async fn finalized_checkpoint(&self) -> Result<Checkpoint, ApiError> {
            Err(ApiError("not used".into()))
        }

        async fn header(&self, _: Root) -> Result<Header, ApiError> {
            Err(ApiError("not used".into()))
        }
    }

    impl BlockApi for NoReference {
        async fn block(&self, _: Root) -> Result<Vec<u8>, ApiError> {
            Err(ApiError("not used".into()))
        }
    }

    struct NoEnr;

    impl EnrCgc for NoEnr {
        fn set_cgc(&mut self, _: u64) -> Result<(), EnrError> {
            Ok(())
        }
    }

    /// A cl-verify that accepts any batch, counting the batches it was asked about.
    #[derive(Default)]
    struct AcceptsAll {
        asked: AtomicUsize,
    }

    impl KzgVerifier for AcceptsAll {
        async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
            self.asked.fetch_add(1, Ordering::SeqCst);
            KzgOutcome::Valid
        }
    }

    #[tokio::test]
    async fn a_column_of_no_cells_is_dropped_even_for_a_bid_of_no_blobs() {
        let refs = RefView::<_, Spec>::new(NoReference, schedule(), RefLimits::default());
        let (block, _, root) = gloas_block(9, &[]);
        refs.seed(&block);
        let dir = tempfile::tempdir().unwrap();
        let writer = ColumnWriter::open(dir.path()).unwrap();
        let custody = Custody::open(writer, NoEnr, U256::MAX, Advertise::Withheld, 0).unwrap();
        assert!(custody.custody_columns().contains(&CUSTODY_COLUMN));
        let contract = ColumnContract {
            kzg: AcceptsAll::default(),
            verify_timeout: Duration::from_secs(1),
            metrics: ColumnMetrics::default(),
        };
        // Every later check holds: a vouched root at its slot, zero commitments for zero cells,
        // and a verifier that accepts anything.
        let empty = GossipColumn {
            sidecar: gloas::DataColumnSidecar {
                index: CUSTODY_COLUMN,
                column: Vec::new().try_into().unwrap(),
                kzg_proofs: Vec::new().try_into().unwrap(),
                slot: 9,
                beacon_block_root: root.into(),
            },
            subnet_id: CUSTODY_COLUMN,
        };
        let dropped = storage_contract(&empty, &refs, &custody, &contract).await;
        assert_eq!(dropped.unwrap_err(), Drop::CommitmentsMismatch);
        assert_eq!(contract.metrics.dropped(Drop::CommitmentsMismatch), 1);
        assert_eq!(contract.kzg.asked.load(Ordering::SeqCst), 0, "never sent");
    }
}
