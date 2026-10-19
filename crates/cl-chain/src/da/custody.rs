//! The node's custody group count (`cgc`), which cl-chain owns.
//!
//! - **Never decreasing, persisted.** The count starts at `CUSTODY_REQUIREMENT` (4,
//!   `fulu/das-core.md`). [`Custody::set_cgc`] refuses a decrease ([`CustodyError::Decrease`])
//!   and leaves the stored value as it is: a node SHOULD NOT lower its `custody_group_count`,
//!   and the highest one SHOULD persist across restarts (`fulu/validator.md`). The record
//!   ([`CustodyRecord`]) is stored through a [`CustodyStore`]: for now the `cl-chain-columns`
//!   env, written in one durable MDBX transaction, which the column store also checks against a
//!   decrease.
//! - **`cgc_set_slot`.** The slot the count was last raised at, the value Status
//!   `earliest_available_slot` reflects (`fulu/validator.md`).
//! - **MetaData and ENR.** A change of the advertised count bumps the MetaData `seq_number`
//!   once ([`Custody::metadata`]) and sets the ENR `cgc` once through [`EnrCgc`] (cl-discv5
//!   re-signs the record, one `seq` bump).
//! - **Subscriptions.** [`Custody::subscriptions`] is the `WatchSubscriptions` body that tells
//!   cl-p2p which column subnets to join: the columns of exactly the node's custody groups
//!   (`get_custody_groups`, `compute_columns_for_custody_group`).
//!
//! # Advertising: [`Advertise`]
//!
//! What peers are told (ENR `cgc`, MetaData `custody_group_count`) is a separate switch from
//! what the node custodies. cl-chain serves its custody columns by range and by root
//! ([`crate::reqresp`]), so the default is [`Advertise::Custody`]: peers are told the stored
//! count, 4 groups on a first start, and may ask for those columns. [`Advertise::Withheld`]
//! tells them 0 while the node still custodies and subscribes to its groups, for a node that
//! must not be asked for columns. Peers MAY reject a count below `CUSTODY_REQUIREMENT`
//! (`fulu/p2p-interface.md`), so the choice is made before the first public advertisement.

use cl_chain_columns::{ColumnWriter, CustodyRecord};
use consensus_types::das::{self, CUSTODY_REQUIREMENT, NUMBER_OF_CUSTODY_GROUPS};
use consensus_types::primitives::{ColumnIndex, Slot, U256};
use ethswarm_proto::chain as pb;
use std::sync::Arc;

/// `ATTESTATION_SUBNET_COUNT` / 8: the bytes of MetaData `attnets`.
const ATTNETS_BYTES: usize = 8;
/// `SYNC_COMMITTEE_SUBNET_COUNT` (4) in whole bytes: MetaData `syncnets`.
const SYNCNETS_BYTES: usize = 1;

/// Where the [`CustodyRecord`] lives across restarts.
pub trait CustodyStore {
    /// The stored record, `None` on a node's first start.
    fn load(&self) -> Result<Option<CustodyRecord>, cl_chain_columns::Error>;
    /// Stores `record` whole and durably. A `cgc` below the stored one is refused.
    fn save(&self, record: &CustodyRecord) -> Result<(), cl_chain_columns::Error>;
}

impl CustodyStore for ColumnWriter {
    fn load(&self) -> Result<Option<CustodyRecord>, cl_chain_columns::Error> {
        self.reader().custody()
    }

    fn save(&self, record: &CustodyRecord) -> Result<(), cl_chain_columns::Error> {
        self.set_custody(record)
    }
}

impl<T: CustodyStore + ?Sized> CustodyStore for Arc<T> {
    fn load(&self) -> Result<Option<CustodyRecord>, cl_chain_columns::Error> {
        (**self).load()
    }

    fn save(&self, record: &CustodyRecord) -> Result<(), cl_chain_columns::Error> {
        (**self).save(record)
    }
}

/// The local ENR's `cgc`, which cl-discv5 holds and re-signs (`ethswarm.discv5.v1`
/// `UpdateEnr`).
pub trait EnrCgc {
    /// Sets the record's `cgc`; the record's `seq` moves by one when the value changes and not
    /// at all when it is already there.
    fn set_cgc(&mut self, cgc: u64) -> Result<(), EnrError>;
}

/// cl-discv5 did not take the new `cgc`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("ENR cgc update failed: {0}")]
pub struct EnrError(pub String);

/// What peers are told the custody group count is; see the module docs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Advertise {
    /// The stored count: the default, since the custody columns are served.
    #[default]
    Custody,
    /// 0, whatever the node custodies.
    Withheld,
}

impl Advertise {
    /// The advertised count for a custody group count of `cgc`.
    #[must_use]
    pub fn of(self, cgc: u64) -> u64 {
        match self {
            Advertise::Custody => cgc,
            Advertise::Withheld => 0,
        }
    }
}

/// Why a custody change was refused or did not complete.
#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    /// The custody group count never decreases; nothing changed.
    #[error("cgc {requested} is below the custody group count {stored}")]
    Decrease { stored: u64, requested: u64 },
    /// Above `NUMBER_OF_CUSTODY_GROUPS`; nothing changed.
    #[error("cgc {0} exceeds NUMBER_OF_CUSTODY_GROUPS ({NUMBER_OF_CUSTODY_GROUPS})")]
    OutOfRange(u64),
    /// The store failed; nothing changed.
    #[error("custody store: {0}")]
    Store(#[from] cl_chain_columns::Error),
    /// The record is stored and in effect, but the ENR still holds the old `cgc`: retry with
    /// [`Custody::publish_enr`].
    #[error(transparent)]
    Enr(#[from] EnrError),
}

/// The node's custody: see the module docs.
#[derive(Debug)]
pub struct Custody<S, E> {
    store: S,
    enr: E,
    node_id: U256,
    advertise: Advertise,
    record: CustodyRecord,
}

impl<S: CustodyStore, E: EnrCgc> Custody<S, E> {
    /// Loads the stored record, or on a first start creates one at `CUSTODY_REQUIREMENT` set
    /// at `slot`, and sets the ENR `cgc` to the advertised count.
    ///
    /// A stored count below `CUSTODY_REQUIREMENT` is raised to it (at `slot`). An advertised
    /// count that differs from the stored one (the [`Advertise`] switch moved across a
    /// restart) bumps the MetaData `seq_number` once. `node_id` is the discv5 node id as the
    /// spec's `uint256` (`U256::from_be_bytes(node_id.raw())`).
    ///
    /// # Errors
    ///
    /// [`CustodyError::OutOfRange`] for a stored count above `NUMBER_OF_CUSTODY_GROUPS`,
    /// [`CustodyError::Store`] and [`CustodyError::Enr`].
    pub fn open(
        store: S,
        enr: E,
        node_id: U256,
        advertise: Advertise,
        slot: Slot,
    ) -> Result<Self, CustodyError> {
        let stored = store.load()?;
        let current = stored.unwrap_or_default();
        if current.cgc > NUMBER_OF_CUSTODY_GROUPS {
            return Err(CustodyError::OutOfRange(current.cgc));
        }
        let mut record = current;
        if record.cgc < CUSTODY_REQUIREMENT {
            record.cgc = CUSTODY_REQUIREMENT;
            record.cgc_set_slot = slot;
        }
        record.advertised_cgc = advertise.of(record.cgc);
        if stored.is_some() && record.advertised_cgc != current.advertised_cgc {
            record.metadata_seq += 1;
        }
        if stored != Some(record) {
            store.save(&record)?;
        }
        let mut custody = Self {
            store,
            enr,
            node_id,
            advertise,
            record,
        };
        custody.publish_enr()?;
        Ok(custody)
    }

    /// Raises the custody group count to `cgc`, set at `slot`. Returns whether it changed: the
    /// same count again is no change and bumps nothing.
    ///
    /// The new record is stored first; only then does it take effect. When the advertised
    /// count changes, the MetaData `seq_number` and the ENR `cgc` move once each.
    ///
    /// # Errors
    ///
    /// [`CustodyError::Decrease`] for a count below the current one and
    /// [`CustodyError::OutOfRange`] above `NUMBER_OF_CUSTODY_GROUPS`, both with nothing
    /// changed; [`CustodyError::Store`] with nothing changed; [`CustodyError::Enr`] with the new
    /// count stored and in effect.
    pub fn set_cgc(&mut self, cgc: u64, slot: Slot) -> Result<bool, CustodyError> {
        if cgc > NUMBER_OF_CUSTODY_GROUPS {
            return Err(CustodyError::OutOfRange(cgc));
        }
        let stored = self.record.cgc;
        if cgc < stored {
            return Err(CustodyError::Decrease {
                stored,
                requested: cgc,
            });
        }
        if cgc == stored {
            return Ok(false);
        }
        let advertised_cgc = self.advertise.of(cgc);
        let advertised_changed = advertised_cgc != self.record.advertised_cgc;
        let next = CustodyRecord {
            cgc,
            cgc_set_slot: slot,
            metadata_seq: self.record.metadata_seq + u64::from(advertised_changed),
            advertised_cgc,
        };
        self.store.save(&next)?;
        self.record = next;
        if advertised_changed {
            self.publish_enr()?;
        }
        Ok(true)
    }

    /// Sets the ENR `cgc` to the advertised count again, after a [`CustodyError::Enr`].
    ///
    /// # Errors
    ///
    /// [`CustodyError::Enr`].
    pub fn publish_enr(&mut self) -> Result<(), CustodyError> {
        Ok(self.enr.set_cgc(self.record.advertised_cgc)?)
    }
}

impl<S, E> Custody<S, E> {
    /// The custody group count: what the node custodies and subscribes to.
    #[must_use]
    pub fn cgc(&self) -> u64 {
        self.record.cgc
    }

    /// The count peers are told (ENR `cgc`, MetaData `custody_group_count`).
    #[must_use]
    pub fn advertised_cgc(&self) -> u64 {
        self.record.advertised_cgc
    }

    /// The slot the count was last raised at.
    #[must_use]
    pub fn cgc_set_slot(&self) -> Slot {
        self.record.cgc_set_slot
    }

    /// The stored record.
    #[must_use]
    pub fn record(&self) -> CustodyRecord {
        self.record
    }

    /// The local ENR handle.
    pub fn enr(&self) -> &E {
        &self.enr
    }

    /// `get_custody_groups(node_id, cgc)`.
    #[must_use]
    pub fn custody_groups(&self) -> Vec<u64> {
        das::get_custody_groups(self.node_id, self.record.cgc)
            .expect("the custody group count is checked against NUMBER_OF_CUSTODY_GROUPS")
    }

    /// The columns of every custody group, sorted.
    #[must_use]
    pub fn custody_columns(&self) -> Vec<ColumnIndex> {
        das::custody_columns(self.node_id, self.record.cgc)
            .expect("the custody group count is checked against NUMBER_OF_CUSTODY_GROUPS")
    }

    /// Our MetaData v3 (`ReqRespService/GetMetadata`): no attestation or sync subnets, and the
    /// advertised custody group count.
    #[must_use]
    pub fn metadata(&self) -> pb::GetMetadataResponse {
        pb::GetMetadataResponse {
            seq_number: self.record.metadata_seq,
            attnets: vec![0; ATTNETS_BYTES],
            syncnets: vec![0; SYNCNETS_BYTES],
            custody_group_count: self.record.advertised_cgc,
        }
    }

    /// The `WatchSubscriptions` body for cl-p2p: the custody columns under each of
    /// `fork_digests` (the current digest, and the next one ahead of a fork or BPO boundary).
    #[must_use]
    pub fn subscriptions(&self, fork_digests: &[[u8; 4]]) -> pb::WatchSubscriptionsResponseBody {
        pb::WatchSubscriptionsResponseBody {
            attnets: Vec::new(),
            syncnets: Vec::new(),
            custody_columns: self.custody_columns(),
            fork_digests: fork_digests.iter().map(|d| d.to_vec()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cl_discv5::enr::{build_local_enr, CombinedKey, Enr, EnrFields, LocalAddr};
    use p2p_wire::enr::{EnrForkId, ForkFields};
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    /// The ENR as cl-discv5 holds it: the record and the key that signs it.
    struct LocalEnr {
        enr: Enr,
        key: CombinedKey,
    }

    impl LocalEnr {
        fn new() -> Self {
            let key = CombinedKey::generate_secp256k1();
            let fork = ForkFields {
                eth2: EnrForkId {
                    fork_digest: [1, 2, 3, 4],
                    next_fork_version: [0; 4],
                    next_fork_epoch: u64::MAX,
                },
                nfd: [0; 4],
            };
            let addr = LocalAddr::new(Ipv4Addr::LOCALHOST);
            let enr = build_local_enr(&key, &fork, 0, &addr).unwrap();
            Self { enr, key }
        }

        fn cgc(&self) -> Option<u64> {
            EnrFields::read(&self.enr).unwrap().cgc
        }
    }

    impl EnrCgc for LocalEnr {
        fn set_cgc(&mut self, cgc: u64) -> Result<(), EnrError> {
            cl_discv5::enr::set_cgc(&mut self.enr, &self.key, cgc)
                .map(drop)
                .map_err(|e| EnrError(e.to_string()))
        }
    }

    /// A node id with a known custody set.
    const NODE: U256 = U256::MAX;

    fn open(dir: &tempfile::TempDir, advertise: Advertise) -> Custody<ColumnWriter, LocalEnr> {
        let writer = ColumnWriter::open(dir.path()).unwrap();
        Custody::open(writer, LocalEnr::new(), NODE, advertise, 100).unwrap()
    }

    /// Exit 9c: by default the ENR advertises `cgc` = 4, the custody the node serves.
    #[test]
    fn by_default_the_enr_advertises_cgc_4() {
        let dir = tempfile::tempdir().unwrap();
        let custody = open(&dir, Advertise::default());
        assert_eq!(custody.enr().cgc(), Some(CUSTODY_REQUIREMENT));
        assert_eq!(custody.enr().cgc(), Some(4));
        assert_eq!(custody.advertised_cgc(), 4);
        assert_eq!(custody.metadata().custody_group_count, 4);
        // Across a restart too.
        drop(custody);
        assert_eq!(open(&dir, Advertise::default()).enr().cgc(), Some(4));
    }

    #[test]
    fn a_first_start_custodies_four_groups_and_the_enr_says_four() {
        let dir = tempfile::tempdir().unwrap();
        let custody = open(&dir, Advertise::Custody);
        assert_eq!(custody.cgc(), CUSTODY_REQUIREMENT);
        assert_eq!(custody.cgc_set_slot(), 100);
        assert_eq!(custody.enr().cgc(), Some(4));
        assert_eq!(custody.metadata().custody_group_count, 4);
        assert_eq!(custody.custody_groups(), vec![1, 47, 87, 102]);
        assert_eq!(custody.custody_columns(), vec![1, 47, 87, 102]);
    }

    #[test]
    fn refuse_decrease() {
        let dir = tempfile::tempdir().unwrap();
        let mut custody = open(&dir, Advertise::Custody);
        assert_eq!(custody.cgc(), 4);
        let err = custody.set_cgc(2, 200).unwrap_err();
        assert!(
            matches!(
                err,
                CustodyError::Decrease {
                    stored: 4,
                    requested: 2
                }
            ),
            "{err:?}"
        );
        assert_eq!(custody.cgc(), 4);
        assert_eq!(custody.cgc_set_slot(), 100);
        let stored = custody.store.load().unwrap().unwrap();
        assert_eq!((stored.cgc, stored.cgc_set_slot), (4, 100));
    }

    #[test]
    fn metadata_seq_bumps() {
        let dir = tempfile::tempdir().unwrap();
        let mut custody = open(&dir, Advertise::Custody);
        let (meta_seq, enr_seq) = (custody.metadata().seq_number, custody.enr().enr.seq());

        assert!(custody.set_cgc(8, 200).unwrap());
        assert_eq!(custody.metadata().seq_number, meta_seq + 1);
        assert_eq!(custody.enr().enr.seq(), enr_seq + 1);
        assert_eq!(custody.metadata().custody_group_count, 8);
        assert_eq!(custody.enr().cgc(), Some(8));
        assert_eq!(custody.cgc_set_slot(), 200);

        // The same count again, and a refused decrease, bump nothing.
        assert!(!custody.set_cgc(8, 300).unwrap());
        assert!(custody.set_cgc(4, 300).is_err());
        assert_eq!(custody.metadata().seq_number, meta_seq + 1);
        assert_eq!(custody.enr().enr.seq(), enr_seq + 1);
        assert_eq!(custody.cgc_set_slot(), 200);
        assert_eq!(
            custody.store.load().unwrap().unwrap().metadata_seq,
            meta_seq + 1
        );
    }

    /// Withheld: peers are told 0, the node still custodies its groups, and a raise moves
    /// neither the MetaData nor the ENR.
    #[test]
    fn a_withheld_count_advertises_zero() {
        let dir = tempfile::tempdir().unwrap();
        let mut custody = open(&dir, Advertise::Withheld);
        assert_eq!(custody.advertised_cgc(), 0);
        assert_eq!(custody.enr().cgc(), Some(0));
        assert_eq!(custody.custody_columns().len(), 4);
        let (meta_seq, enr_seq) = (custody.metadata().seq_number, custody.enr().enr.seq());
        assert!(custody.set_cgc(8, 200).unwrap());
        assert_eq!(custody.custody_columns().len(), 8);
        assert_eq!(custody.metadata().seq_number, meta_seq);
        assert_eq!(custody.metadata().custody_group_count, 0);
        assert_eq!(custody.enr().enr.seq(), enr_seq);
    }

    /// Turning the switch on across a restart changes the MetaData: one seq bump.
    #[test]
    fn turning_advertising_on_bumps_the_seq_once() {
        let dir = tempfile::tempdir().unwrap();
        let seq = open(&dir, Advertise::Withheld).metadata().seq_number;
        let custody = open(&dir, Advertise::Custody);
        assert_eq!(custody.metadata().seq_number, seq + 1);
        assert_eq!(custody.enr().cgc(), Some(4));
        drop(custody);
        assert_eq!(
            open(&dir, Advertise::Custody).metadata().seq_number,
            seq + 1
        );
    }

    #[test]
    fn counts_past_the_group_count_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut custody = open(&dir, Advertise::Custody);
        let err = custody.set_cgc(129, 200).unwrap_err();
        assert!(matches!(err, CustodyError::OutOfRange(129)), "{err:?}");
        assert!(custody.set_cgc(128, 200).unwrap());
        assert_eq!(custody.custody_columns(), (0..128).collect::<Vec<_>>());
    }

    #[test]
    fn a_stored_count_below_the_requirement_is_raised() {
        let dir = tempfile::tempdir().unwrap();
        ColumnWriter::open(dir.path()).unwrap().set_cgc(0).unwrap();
        let custody = open(&dir, Advertise::Custody);
        assert_eq!((custody.cgc(), custody.cgc_set_slot()), (4, 100));
        assert_eq!(custody.store.load().unwrap().unwrap().cgc, 4);
    }

    #[test]
    fn the_subscriptions_are_the_custody_columns_per_digest() {
        let dir = tempfile::tempdir().unwrap();
        let custody = open(&dir, Advertise::Withheld);
        let body = custody.subscriptions(&[[1, 2, 3, 4], [5, 6, 7, 8]]);
        assert_eq!(body.custody_columns, vec![1, 47, 87, 102]);
        assert_eq!(body.fork_digests, vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]);
        assert!(body.attnets.is_empty() && body.syncnets.is_empty());
        let meta = custody.metadata();
        assert_eq!((meta.attnets.len(), meta.syncnets.len()), (8, 1));
    }

    /// A store that fails on demand.
    #[derive(Debug, Default)]
    struct FlakyStore {
        record: RefCell<Option<CustodyRecord>>,
        fail_load: bool,
        fail_save: RefCell<bool>,
    }

    impl CustodyStore for FlakyStore {
        fn load(&self) -> Result<Option<CustodyRecord>, cl_chain_columns::Error> {
            if self.fail_load {
                return Err(cl_chain_columns::Error::MapFull);
            }
            Ok(*self.record.borrow())
        }

        fn save(&self, record: &CustodyRecord) -> Result<(), cl_chain_columns::Error> {
            if *self.fail_save.borrow() {
                return Err(cl_chain_columns::Error::MapFull);
            }
            *self.record.borrow_mut() = Some(*record);
            Ok(())
        }
    }

    /// An ENR that refuses on demand and counts the updates it took.
    #[derive(Debug, Default)]
    struct FlakyEnr {
        fail: bool,
        set: Vec<u64>,
    }

    impl EnrCgc for FlakyEnr {
        fn set_cgc(&mut self, cgc: u64) -> Result<(), EnrError> {
            if self.fail {
                return Err(EnrError("discv5 down".into()));
            }
            self.set.push(cgc);
            Ok(())
        }
    }

    #[test]
    fn a_failed_save_changes_nothing() {
        let mut custody = Custody::open(
            FlakyStore::default(),
            FlakyEnr::default(),
            NODE,
            Advertise::Custody,
            1,
        )
        .unwrap();
        *custody.store.fail_save.borrow_mut() = true;
        let err = custody.set_cgc(8, 2).unwrap_err();
        assert!(matches!(err, CustodyError::Store(_)), "{err:?}");
        assert_eq!((custody.cgc(), custody.metadata().seq_number), (4, 0));
        assert_eq!(custody.enr().set, vec![4]);

        let failing = FlakyStore {
            fail_load: true,
            ..FlakyStore::default()
        };
        let err =
            Custody::open(failing, FlakyEnr::default(), NODE, Advertise::Custody, 1).unwrap_err();
        assert!(matches!(err, CustodyError::Store(_)), "{err:?}");
    }

    #[test]
    fn a_failed_enr_update_keeps_the_new_count_and_can_be_retried() {
        let mut custody = Custody::open(
            FlakyStore::default(),
            FlakyEnr::default(),
            NODE,
            Advertise::Custody,
            1,
        )
        .unwrap();
        custody.enr.fail = true;
        let err = custody.set_cgc(8, 2).unwrap_err();
        assert!(matches!(err, CustodyError::Enr(_)), "{err}");
        assert_eq!(custody.cgc(), 8);
        assert_eq!(custody.store.load().unwrap().unwrap().cgc, 8);
        custody.enr.fail = false;
        custody.publish_enr().unwrap();
        assert_eq!(custody.enr().set, vec![4, 8]);
    }

    #[test]
    fn a_corrupt_stored_count_is_refused() {
        let store = FlakyStore {
            record: RefCell::new(Some(CustodyRecord {
                cgc: 200,
                ..CustodyRecord::default()
            })),
            ..FlakyStore::default()
        };
        let err =
            Custody::open(store, FlakyEnr::default(), NODE, Advertise::Custody, 1).unwrap_err();
        assert!(matches!(err, CustodyError::OutOfRange(200)), "{err:?}");
    }

    #[test]
    fn the_writer_is_shared_through_an_arc() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(ColumnWriter::open(dir.path()).unwrap());
        let custody = Custody::open(
            writer.clone(),
            FlakyEnr::default(),
            NODE,
            Advertise::Custody,
            1,
        )
        .unwrap();
        assert_eq!(writer.reader().custody().unwrap(), Some(custody.record()));
    }
}
