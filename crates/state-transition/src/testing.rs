//! Test inputs: a Gloas genesis-like state with a given registry, empty blocks, builders
//! and their requests, a scripted signature backend and a pubkey aggregator without BLS.

use crate::caches::get_beacon_proposer_index;
use crate::caches::{initialize_proposer_lookahead, initialize_ptc_window};
use crate::per_block::builder::{process_builder_deposit_request, process_builder_exit_request};
use crate::preset::{BUILDER_INDEX_SELF_BUILD, BUILDER_WITHDRAWAL_PREFIX};
use crate::signatures::G2_POINT_AT_INFINITY;
use crate::{
    AggregationError, BackendError, BlsContext, Preset, PubkeyAggregator, SignatureBackend,
    SignatureSet, SignerRef,
};
use consensus_types::gloas::*;
use consensus_types::primitives::{
    Address, BLSPubkey, Bytes32, Epoch, Gwei, Root, Version, FAR_FUTURE_EPOCH,
};
use milhouse::{List, ProgressiveList, Vector};
use ssz::BitVector;
use ssz_types::FixedVector;
use std::cell::RefCell;
use std::collections::VecDeque;
use tree_hash::TreeHash;

/// A Gloas state at slot 0 whose validators have `effective_balances` (each also its
/// balance), all active from epoch 0. Every RANDAO mix is `mix`. The proposer lookahead and
/// the PTC window are initialized as at genesis.
pub(crate) fn genesis_state_with_mix<E: Preset>(
    effective_balances: &[Gwei],
    mix: Bytes32,
) -> BeaconState<E> {
    let mut state = registry_state(effective_balances, mix);
    refresh_lookahead(&mut state);
    state
}

/// [`genesis_state_with_mix`] with a zero proposer lookahead and PTC window, for registries
/// too small to give every slot a non-empty committee (the PTC of such a slot does not exist).
pub(crate) fn registry_state<E: Preset>(
    effective_balances: &[Gwei],
    mix: Bytes32,
) -> BeaconState<E> {
    let validators = effective_balances.iter().enumerate().map(|(i, &b)| {
        let mut pubkey = [0u8; 48];
        pubkey[..8].copy_from_slice(&(i as u64).to_le_bytes());
        Validator {
            pubkey,
            withdrawal_credentials: Bytes32::ZERO,
            effective_balance: b,
            slashed: false,
            activation_eligibility_epoch: 0,
            activation_epoch: 0,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    });
    let checkpoint = Checkpoint {
        epoch: 0,
        root: Root::ZERO,
    };
    let eth1_data = Eth1Data {
        deposit_root: Root::ZERO,
        deposit_count: 0,
        block_hash: mix,
    };
    let sync_committee = SyncCommittee {
        pubkeys: FixedVector::from_elem([0; 48]),
        aggregate_pubkey: [0; 48],
    };
    let payment = BuilderPendingPayment {
        weight: 0,
        withdrawal: BuilderPendingWithdrawal {
            fee_recipient: Address::ZERO,
            amount: 0,
            builder_index: 0,
        },
        proposer_index: 0,
    };
    BeaconState {
        genesis_time: 0,
        genesis_validators_root: Root::repeat_byte(0x42),
        slot: 0,
        fork: Fork {
            previous_version: [0x07, 0, 0, 0x01],
            current_version: [0x07, 0, 0, 0x01],
            epoch: 0,
        },
        latest_block_header: BeaconBlockHeader {
            slot: 0,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body_root: Root::ZERO,
        },
        block_roots: Vector::default(),
        state_roots: Vector::default(),
        historical_roots: List::default(),
        eth1_data,
        eth1_data_votes: List::default(),
        eth1_deposit_index: 0,
        validators: ProgressiveList::try_from_iter(validators).unwrap(),
        balances: ProgressiveList::try_from_iter(effective_balances.iter().copied()).unwrap(),
        randao_mixes: Vector::from_elem(mix).unwrap(),
        slashings: Vector::default(),
        previous_epoch_participation: ProgressiveList::try_from_iter(
            effective_balances.iter().map(|_| 0),
        )
        .unwrap(),
        current_epoch_participation: ProgressiveList::try_from_iter(
            effective_balances.iter().map(|_| 0),
        )
        .unwrap(),
        justification_bits: BitVector::new(),
        previous_justified_checkpoint: checkpoint.clone(),
        current_justified_checkpoint: checkpoint.clone(),
        finalized_checkpoint: checkpoint,
        inactivity_scores: ProgressiveList::try_from_iter(effective_balances.iter().map(|_| 0))
            .unwrap(),
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        latest_block_hash: Root::ZERO,
        next_withdrawal_index: 0,
        next_withdrawal_validator_index: 0,
        historical_summaries: List::default(),
        deposit_requests_start_index: u64::MAX,
        deposit_balance_to_consume: 0,
        exit_balance_to_consume: 0,
        earliest_exit_epoch: 0,
        consolidation_balance_to_consume: 0,
        earliest_consolidation_epoch: 0,
        pending_deposits: ProgressiveList::default(),
        pending_partial_withdrawals: ProgressiveList::default(),
        pending_consolidations: ProgressiveList::default(),
        proposer_lookahead: Vector::default(),
        builders: ProgressiveList::default(),
        next_withdrawal_builder_index: 0,
        execution_payload_availability: BitVector::new(),
        builder_pending_payments: Vector::from_elem(payment).unwrap(),
        builder_pending_withdrawals: ProgressiveList::default(),
        latest_execution_payload_bid: empty_bid(0),
        payload_expected_withdrawals: ProgressiveList::default(),
        ptc_window: Vector::default(),
    }
}

/// [`genesis_state_with_mix`] with a fixed mix.
pub(crate) fn genesis_state<E: Preset>(effective_balances: &[Gwei]) -> BeaconState<E> {
    genesis_state_with_mix(effective_balances, Bytes32::repeat_byte(0x5a))
}

/// Sets `proposer_lookahead` and `ptc_window` as the fork upgrade does at the state's epoch.
pub(crate) fn refresh_lookahead<E: Preset>(state: &mut BeaconState<E>) {
    state.proposer_lookahead = Vector::new(initialize_proposer_lookahead(state).unwrap()).unwrap();
    state.ptc_window = Vector::new(initialize_ptc_window(state).unwrap()).unwrap();
}

/// An empty Gloas bid for `slot`.
fn empty_bid<E: Preset>(slot: u64) -> ExecutionPayloadBid<E> {
    ExecutionPayloadBid {
        parent_block_hash: Root::ZERO,
        parent_block_root: Root::ZERO,
        block_hash: Root::ZERO,
        prev_randao: Root::ZERO,
        fee_recipient: Address::ZERO,
        gas_limit: 0,
        builder_index: 0,
        slot,
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: Default::default(),
        execution_requests_root: Root::ZERO,
    }
}

/// A block at `slot` by `proposer_index` with an empty body (no sync committee bits, the
/// infinity sync signature and a self-build bid), a zero `state_root` and the signature
/// `[0x11; 96]`.
pub(crate) fn signed_block<E: Preset>(slot: u64, proposer_index: u64) -> SignedBeaconBlock<E> {
    let body = BeaconBlockBody {
        randao_reveal: [0; 96],
        eth1_data: Eth1Data {
            deposit_root: Root::ZERO,
            deposit_count: 0,
            block_hash: Root::ZERO,
        },
        graffiti: Bytes32::ZERO,
        proposer_slashings: Default::default(),
        attester_slashings: Default::default(),
        attestations: Default::default(),
        deposits: Default::default(),
        voluntary_exits: Default::default(),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: BitVector::new(),
            sync_committee_signature: G2_POINT_AT_INFINITY,
        },
        bls_to_execution_changes: Default::default(),
        // A self-build bid (`BUILDER_INDEX_SELF_BUILD`) with the infinity signature.
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: ExecutionPayloadBid {
                builder_index: BUILDER_INDEX_SELF_BUILD,
                ..empty_bid(slot)
            },
            signature: G2_POINT_AT_INFINITY,
        },
        payload_attestations: Default::default(),
        parent_execution_requests: ExecutionRequests {
            deposits: Default::default(),
            withdrawals: Default::default(),
            consolidations: Default::default(),
            builder_deposits: Default::default(),
            builder_exits: Default::default(),
        },
    };
    SignedBeaconBlock {
        message: BeaconBlock {
            slot,
            proposer_index,
            parent_root: Root::ZERO,
            state_root: Root::ZERO,
            body,
        },
        signature: [0x11; 96],
    }
}

/// The `GENESIS_FORK_VERSION` of `configs/minimal.yaml` (L27), for the builder deposits of
/// the tests.
pub(crate) const GENESIS_FORK_VERSION: Version = [0x00, 0x00, 0x00, 0x01];

/// The `CAPELLA_FORK_VERSION` of `configs/minimal.yaml` (L43), for the voluntary exits of
/// the tests.
pub(crate) const CAPELLA_FORK_VERSION: Version = [0x03, 0x00, 0x00, 0x01];

/// A [`SignatureBackend`] that gives the scripted verdicts in sequence and records each set
/// that it gets. A call after the last verdict panics, so a test also proves that no other
/// call occurs.
///
/// A script follows the contract of [`SignatureBackend`]: `Err` stands for a backend
/// without a verdict, and `Ok(false)` for any invalid set, which includes a key that fails
/// `KeyValidate`.
pub(crate) struct ScriptedBackend {
    verdicts: RefCell<VecDeque<Result<bool, BackendError>>>,
    seen: RefCell<Vec<SignatureSet>>,
}

impl ScriptedBackend {
    /// A backend that gives `verdicts`, one for each call.
    pub(crate) fn new(verdicts: impl IntoIterator<Item = Result<bool, BackendError>>) -> Self {
        Self {
            verdicts: RefCell::new(verdicts.into_iter().collect()),
            seen: RefCell::new(Vec::new()),
        }
    }

    /// The sets of every call, in sequence.
    pub(crate) fn seen(&self) -> Vec<SignatureSet> {
        self.seen.borrow().clone()
    }
}

impl SignatureBackend for ScriptedBackend {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        self.seen.borrow_mut().extend_from_slice(sets);
        self.verdicts
            .borrow_mut()
            .pop_front()
            .expect("a backend call that the test did not script")
    }
}

/// A [`SignatureBackend`] that follows its contract for inline keys without BLS: a set
/// with a signer in `invalid_keys` gives `Ok(false)`, as a key that fails `KeyValidate`
/// must, and every other set is valid. It never gives `Err`. It records each set that it
/// gets.
pub(crate) struct ContractBackend {
    invalid_keys: Vec<BLSPubkey>,
    seen: RefCell<Vec<SignatureSet>>,
}

impl ContractBackend {
    /// A backend for which the keys `invalid_keys` fail `KeyValidate`.
    pub(crate) fn new(invalid_keys: impl IntoIterator<Item = BLSPubkey>) -> Self {
        Self {
            invalid_keys: invalid_keys.into_iter().collect(),
            seen: RefCell::new(Vec::new()),
        }
    }

    /// The sets of every call, in sequence.
    pub(crate) fn seen(&self) -> Vec<SignatureSet> {
        self.seen.borrow().clone()
    }
}

impl SignatureBackend for ContractBackend {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        self.seen.borrow_mut().extend_from_slice(sets);
        let decodes = |signer: &SignerRef| match signer {
            SignerRef::Inline(key) => !self.invalid_keys.contains(key),
            SignerRef::Validator(_) | SignerRef::Builder { .. } => true,
        };
        Ok(sets.iter().all(|set| set.signers().iter().all(decodes)))
    }
}

/// A builder with the key `[key; 48]` and the execution address `[key; 20]`, with
/// `balance`, deposited in `deposit_epoch` and not exiting.
pub(crate) fn builder(key: u8, balance: Gwei, deposit_epoch: Epoch) -> Builder {
    Builder {
        pubkey: [key; 48],
        version: 0,
        execution_address: Address::repeat_byte(key),
        balance,
        deposit_epoch,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    }
}

/// A builder deposit request of `amount` for the key `[key; 48]`, with the builder
/// withdrawal credentials of the address `[key; 20]` and the signature `[0x22; 96]`.
pub(crate) fn builder_deposit_request(key: u8, amount: Gwei) -> BuilderDepositRequest {
    let mut withdrawal_credentials = Bytes32::ZERO;
    withdrawal_credentials[0] = BUILDER_WITHDRAWAL_PREFIX;
    withdrawal_credentials[12..].fill(key);
    BuilderDepositRequest {
        pubkey: [key; 48],
        withdrawal_credentials,
        amount,
        signature: [0x22; 96],
    }
}

/// A builder exit request for the key `[key; 48]` from the address `[key; 20]`.
pub(crate) fn builder_exit_request(key: u8) -> BuilderExitRequest {
    BuilderExitRequest {
        source_address: Address::repeat_byte(key),
        pubkey: [key; 48],
    }
}

/// The key of the builder that exits in [`index_reuse_states`].
pub(crate) const EXITED_BUILDER_KEY: u8 = 0xa1;
/// The key of the new builder that takes its index in [`index_reuse_states`].
pub(crate) const REUSING_BUILDER_KEY: u8 = 0xb1;

/// The index reuse of G L2322-2331, through the real requests. The registry starts with the
/// builders `[0xa1; 48]` (index 0) and `[0xa2; 48]` (index 1), both deposited in epoch 0
/// and finalized at epoch 3. Builder 0 exits in epoch 3, and the state goes to its
/// withdrawable epoch with its balance swept to 0.
///
/// Returns that state, and the state after a deposit of 7 Gwei for the key `[0xb1; 48]`
/// with a valid signature, which takes index 0.
pub(crate) fn index_reuse_states<E: Preset>() -> (BeaconState<E>, BeaconState<E>) {
    let mut state = registry_state::<E>(&[32_000_000_000; 8], Bytes32::ZERO);
    state.slot = E::start_slot_at_epoch(3) + 1;
    state.finalized_checkpoint.epoch = 3;
    for key in [EXITED_BUILDER_KEY, 0xa2] {
        state.builders.push(builder(key, 5_000_000_000, 0)).unwrap();
    }
    process_builder_exit_request(&mut state, &builder_exit_request(EXITED_BUILDER_KEY)).unwrap();
    let withdrawable_epoch = state.builders.get(0).unwrap().withdrawable_epoch;
    assert_eq!(withdrawable_epoch, 3 + E::MIN_BUILDER_WITHDRAWABILITY_DELAY);
    // The builders sweep of `process_withdrawals` pays the balance out.
    state.builders.get_mut(0).unwrap().balance = 0;
    state.slot = E::start_slot_at_epoch(withdrawable_epoch);
    let exited = state.clone();
    let backend = ScriptedBackend::new([Ok(true)]);
    let request = builder_deposit_request(REUSING_BUILDER_KEY, 7);
    process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend).unwrap();
    (exited, state)
}

/// [`signed_block`] at `state.slot` by the proposer of the slot, whose parent is the latest
/// block header: a block that `process_block_header` accepts on `state`.
pub(crate) fn block_at_state_slot<E: Preset>(state: &BeaconState<E>) -> SignedBeaconBlock<E> {
    let proposer = get_beacon_proposer_index(state).unwrap();
    let mut block = signed_block::<E>(state.slot, proposer);
    block.message.parent_root = state.latest_block_header.tree_hash_root();
    block
}

/// A [`PubkeyAggregator`] without BLS: the byte-wise XOR of the keys. It is not the BLS sum,
/// but it depends on each key and on the number of times a key occurs. An empty input fails,
/// as in `eth_aggregate_pubkeys`.
pub(crate) struct XorAggregator;

impl PubkeyAggregator for XorAggregator {
    fn aggregate_pubkeys(&self, pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        if pubkeys.is_empty() {
            return Err(AggregationError("no keys".into()));
        }
        let mut sum = [0u8; 48];
        for key in pubkeys {
            for (s, k) in sum.iter_mut().zip(key) {
                *s ^= k;
            }
        }
        Ok(sum)
    }
}

/// A [`BlsContext`] of the minimal config with `backend` and the [`XorAggregator`].
pub(crate) fn bls_context(backend: &dyn SignatureBackend) -> BlsContext<'_> {
    BlsContext {
        backend,
        aggregator: &XorAggregator,
        genesis_fork_version: GENESIS_FORK_VERSION,
        capella_fork_version: CAPELLA_FORK_VERSION,
    }
}

/// A [`SignatureBackend`] for the tests that need no verdict: each call gives `Err`.
pub(crate) struct NoVerdicts;

impl SignatureBackend for NoVerdicts {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Err(BackendError("no verdicts in this test".into()))
    }
}

/// [`bls_context`] with [`NoVerdicts`], for the tests that check no signature.
pub(crate) fn no_bls() -> BlsContext<'static> {
    bls_context(&NoVerdicts)
}
