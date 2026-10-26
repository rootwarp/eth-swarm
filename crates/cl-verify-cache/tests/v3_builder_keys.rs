//! V-3 builder keys (M3 exit 2b): the builder key cache against reusable builder indices,
//! re-registered keys, a reorg across a builder deposit, and self-build signing.
//!
//! The registries come from the real Gloas state transition on minimal-preset states: builder
//! deposits with a real proof of possession (`process_builder_deposit_request`), exits
//! (`process_builder_exit_request`) and the builders sweep (`process_withdrawals`). A finalized
//! state reaches the cache through `BuilderKeyCache::append_range`, in the entry shape of
//! cl-chain's builder feed: `(builder_key_version, state.builders[i].pubkey)`, decoded with
//! `KeyValidate` as cl-verify does. The signatures are real BLS signatures (crypto-bls `verify`).
//!
//! [`Verifier`] plays cl-chain and cl-verify together. A builder signer always carries the key
//! of `state.builders[index]` of the state that the signature is verified against. On gossip it
//! resolves from the cache only. On import cl-chain sends the key inline when the cache does not
//! hold that exact entry.
//!
//! Spec: `gloas/beacon-chain.md` L2322-2331 (index reuse), L2170-2172 (self-build bid) and
//! L2104-2115 (envelope signer).

use std::cell::Cell;

use cl_verify_cache::{
    BuilderEntry, BuilderKeyCache, BuilderSigner, CompressedPubkey, IgnoreReason, Lookup, Origin,
    PubkeyCache, Resolution, Signer,
};
use consensus_types::gloas::{
    BeaconState, BuilderDepositRequest, BuilderExitRequest, ExecutionPayload,
    ExecutionPayloadEnvelope, SignedExecutionPayloadBid,
};
use consensus_types::primitives::{
    Address, BLSSignature, BuilderIndex, Bytes32, Epoch, Gwei, Root, FAR_FUTURE_EPOCH,
};
use consensus_types::signing::{
    compute_signing_root, envelope_signer, SignatureSet, SignerRef, BUILDER_INDEX_SELF_BUILD,
    DOMAIN_BEACON_BUILDER,
};
use consensus_types::{EthSpec, Minimal};
use crypto_bls::{PublicKey, Signature};
use state_transition::accessors::{builder_key_version, get_domain};
use state_transition::per_block::builder::{
    builder_deposit_signature_set, process_builder_deposit_request, process_builder_exit_request,
};
use state_transition::per_block::{
    process_block_header, process_execution_payload_bid, process_withdrawals,
};
use state_transition::per_slot::process_slots;
use state_transition::preset::BUILDER_WITHDRAWAL_PREFIX;
use state_transition::signatures::{block_bid_signature_set, execution_payload_bid_signature_set};
use state_transition::testing::{
    bid_for_state, block_at_state_slot, empty_requests, genesis_state, index_reuse_states, no_bls,
    registry_state, EXITED_BUILDER_KEY, GENESIS_FORK_VERSION, MINIMAL_MAX_BLOBS_PER_BLOCK,
    REUSING_BUILDER_KEY,
};
use state_transition::{BackendError, Preset, SignatureBackend};

type E = Minimal;

const ETH: Gwei = 1_000_000_000;

/// The number of validators of the test states.
const VALIDATORS: usize = 8;

// --- Keys -------------------------------------------------------------------------------------

/// A BLS key pair from blst, for a builder or a validator.
struct Key {
    secret: blst::min_pk::SecretKey,
    public: PublicKey,
}

impl Key {
    fn new(seed: u8) -> Self {
        let secret = blst::min_pk::SecretKey::key_gen(&[seed; 32], &[]).expect("32-byte ikm");
        let public = PublicKey::from_validated_bytes(&secret.sk_to_pk().to_bytes())
            .expect("a generated key passes KeyValidate");
        Self { secret, public }
    }

    fn pubkey(&self) -> CompressedPubkey {
        self.public.to_bytes()
    }

    /// The execution address of the builder: the first 20 bytes of its key.
    fn address(&self) -> Address {
        Address::from_slice(&self.pubkey()[..20])
    }

    fn sign(&self, root: Root) -> BLSSignature {
        self.secret
            .sign(root.as_slice(), crypto_bls::DST, &[])
            .to_bytes()
    }
}

/// `bls.Verify` over compressed bytes: `false` for a key or a signature that does not decode.
fn bls_verify(pubkey: &CompressedPubkey, root: Root, signature: &BLSSignature) -> bool {
    match (
        PublicKey::from_validated_bytes(pubkey),
        Signature::from_validated_bytes(signature),
    ) {
        (Ok(key), Ok(sig)) => crypto_bls::verify(&key, root.as_slice(), &sig),
        _ => false,
    }
}

/// The deposit backend of the state transition with real BLS: each set of a builder deposit
/// has one inline signer (`builder_deposit_signature_set`).
struct DepositBackend;

impl SignatureBackend for DepositBackend {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        Ok(sets.iter().all(|set| match set.signers() {
            [SignerRef::Inline(pubkey)] => bls_verify(pubkey, set.signing_root(), set.signature()),
            _ => false,
        }))
    }
}

// --- Chain ------------------------------------------------------------------------------------

/// A minimal state at slot 1 of epoch 0 with [`VALIDATORS`] validators. Validator `i` has the
/// key [`validator_key`]`(i)`, and the parent block is FULL.
fn chain() -> BeaconState<E> {
    let mut state = registry_state::<E>(&[32 * ETH; VALIDATORS], Bytes32::ZERO);
    for i in 0..VALIDATORS {
        state.validators.get_mut(i).unwrap().pubkey = validator_key(i as u64).pubkey();
    }
    state.slot = 1;
    state
}

fn validator_key(index: u64) -> Key {
    Key::new(100 + index as u8)
}

/// A builder deposit request of `amount` by `key`, with a valid proof of possession.
fn deposit(state: &mut BeaconState<E>, key: &Key, amount: Gwei) {
    let mut withdrawal_credentials = Bytes32::ZERO;
    withdrawal_credentials[0] = BUILDER_WITHDRAWAL_PREFIX;
    withdrawal_credentials[12..].copy_from_slice(key.address().as_slice());
    let mut request = BuilderDepositRequest {
        pubkey: key.pubkey(),
        withdrawal_credentials,
        amount,
        signature: [0; 96],
    };
    let set = builder_deposit_signature_set(&request, GENESIS_FORK_VERSION);
    request.signature = key.sign(set.signing_root());
    process_builder_deposit_request(state, &request, GENESIS_FORK_VERSION, &DepositBackend)
        .unwrap();
}

/// A builder exit request of `key`, from its execution address.
fn exit(state: &mut BeaconState<E>, key: &Key) {
    let request = BuilderExitRequest {
        source_address: key.address(),
        pubkey: key.pubkey(),
    };
    process_builder_exit_request(state, &request).unwrap();
}

/// Moves `state` to the first slot of `epoch` (no epoch processing), with `finalized` as the
/// epoch of its finalized checkpoint.
fn advance(state: &mut BeaconState<E>, epoch: Epoch, finalized: Epoch) {
    state.slot = E::start_slot_at_epoch(epoch) + 1;
    state.finalized_checkpoint.epoch = finalized;
}

/// The index of the builder with `key` in `state`.
fn index_of(state: &BeaconState<E>, key: &Key) -> Option<BuilderIndex> {
    state
        .builders
        .iter()
        .position(|b| b.pubkey == key.pubkey())
        .map(|i| i as BuilderIndex)
}

fn pubkey_at(state: &BeaconState<E>, index: BuilderIndex) -> CompressedPubkey {
    state.builders.get(index as usize).unwrap().pubkey
}

/// The builders `a` (index 0) and `b` (index 1), deposited in epoch 0. Then the state is at
/// epoch 3, finalized at epoch 2, and `a` exits. At its withdrawable epoch the builders sweep
/// pays its balance out, so that its index is free for a new key.
fn swept_registry(a: &Key, b: &Key) -> BeaconState<E> {
    let mut state = chain();
    deposit(&mut state, a, 5 * ETH);
    deposit(&mut state, b, 5 * ETH);
    advance(&mut state, 3, 2);
    exit(&mut state, a);
    let withdrawable = state.builders.get(0).unwrap().withdrawable_epoch;
    assert_eq!(withdrawable, 3 + E::MIN_BUILDER_WITHDRAWABILITY_DELAY);
    advance(&mut state, withdrawable, 2);
    process_withdrawals(&mut state).unwrap();
    let swept = state.builders.get(0).unwrap();
    assert_eq!((swept.pubkey, swept.balance), (a.pubkey(), 0));
    state
}

/// A bid of builder `index` for `state`, signed by `signer`.
fn bid(state: &BeaconState<E>, index: BuilderIndex, signer: &Key) -> SignedExecutionPayloadBid<E> {
    let mut bid = bid_for_state(state, index, ETH);
    let set = execution_payload_bid_signature_set(state, &bid).unwrap();
    bid.signature = signer.sign(set.signing_root());
    bid
}

/// The signature set of `bid` that a block or gossip verifies, after the bid checks of the
/// state transition (an active builder with `PAYLOAD_BUILDER_VERSION`).
fn checked_bid_set(state: &BeaconState<E>, bid: &SignedExecutionPayloadBid<E>) -> SignatureSet {
    block_bid_signature_set(state, bid, MINIMAL_MAX_BLOBS_PER_BLOCK)
        .unwrap()
        .expect("a builder bid has a signature set")
}

/// The signature set of `bid` only (`verify_execution_payload_bid_signature`), also for a
/// builder that is not active yet.
fn bid_set(state: &BeaconState<E>, bid: &SignedExecutionPayloadBid<E>) -> SignatureSet {
    execution_payload_bid_signature_set(state, bid).unwrap()
}

/// An execution payload envelope of `builder_index` for the latest block of `state`.
fn envelope(state: &BeaconState<E>, builder_index: BuilderIndex) -> ExecutionPayloadEnvelope<E> {
    ExecutionPayloadEnvelope {
        payload: ExecutionPayload {
            parent_hash: state.latest_block_hash,
            fee_recipient: Address::ZERO,
            state_root: Bytes32::ZERO,
            receipts_root: Bytes32::ZERO,
            logs_bloom: Default::default(),
            prev_randao: Bytes32::ZERO,
            block_number: 1,
            gas_limit: 0,
            gas_used: 0,
            timestamp: 0,
            extra_data: Default::default(),
            base_fee_per_gas: Default::default(),
            block_hash: Root::repeat_byte(0xbb),
            transactions: Default::default(),
            withdrawals: Default::default(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: state.slot,
        },
        execution_requests: empty_requests(),
        builder_index,
        beacon_block_root: Root::repeat_byte(0xcc),
        parent_beacon_block_root: state.latest_block_header.parent_root,
    }
}

/// The signature set of `verify_execution_payload_envelope_signature` (G L2104-2115) on
/// `state`: the signer of [`envelope_signer`] over the envelope in `DOMAIN_BEACON_BUILDER`.
fn envelope_set(
    state: &BeaconState<E>,
    envelope: &ExecutionPayloadEnvelope<E>,
    signature: BLSSignature,
) -> SignatureSet {
    let index = envelope.builder_index;
    // The key version of a self-build envelope is not used, and the self-build index is not
    // in the registry.
    let version = if index == BUILDER_INDEX_SELF_BUILD {
        0
    } else {
        builder_key_version(state, index).unwrap()
    };
    let signer = envelope_signer(index, state.latest_block_header.proposer_index, version);
    let root = compute_signing_root(envelope, get_domain(state, DOMAIN_BEACON_BUILDER, None));
    SignatureSet::single(signer, root, signature)
}

fn envelope_root(state: &BeaconState<E>, envelope: &ExecutionPayloadEnvelope<E>) -> Root {
    compute_signing_root(envelope, get_domain(state, DOMAIN_BEACON_BUILDER, None))
}

// --- Verifier ---------------------------------------------------------------------------------

/// The verdict on one signature set.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The signer resolved and the signature is valid: ACCEPT.
    Valid,
    /// The signer resolved and the signature is not valid: REJECT.
    Invalid,
    /// The signer did not resolve: IGNORE, never ACCEPT.
    Ignore,
}

/// cl-chain and cl-verify together: the validator cache and the builder key cache, both fed
/// from finalized states only, and a count of the lookups in the builder key cache.
struct Verifier {
    validators: PubkeyCache<PublicKey>,
    builders: BuilderKeyCache<PublicKey>,
    builder_lookups: Cell<usize>,
}

impl Verifier {
    fn new() -> Self {
        Self {
            validators: PubkeyCache::new(),
            builders: BuilderKeyCache::new(),
            builder_lookups: Cell::new(0),
        }
    }

    /// Feeds the validator and the builder registry of the finalized state `finalized`. As the
    /// builder feed of cl-chain, it sends `finalized.builders[from..]` from the first index whose
    /// cached entry is not the entry of the state.
    fn finalize(&mut self, finalized: &BeaconState<E>) {
        let validators = finalized.validators.len() as u64;
        let start = self.validators.high_water();
        let keys = (start..validators)
            .map(|i| {
                let pubkey = finalized.validators.get(i as usize).unwrap().pubkey;
                PublicKey::from_validated_bytes(&pubkey).unwrap()
            })
            .collect();
        self.validators.append_range(start, keys).unwrap();

        let entries: Vec<_> = (0..finalized.builders.len() as u64)
            .map(|i| {
                let pubkey = pubkey_at(finalized, i);
                let key = PublicKey::from_validated_bytes(&pubkey).unwrap();
                (
                    i,
                    BuilderEntry::new(builder_key_version(finalized, i).unwrap(), pubkey, key),
                )
            })
            .collect();
        let from = entries
            .iter()
            .find(|(i, e)| {
                !matches!(
                    self.builders.resolve(*i, e.version(), e.pubkey()),
                    Lookup::Known(_)
                )
            })
            .map_or(entries.len(), |(i, _)| *i as usize);
        let frame = entries.into_iter().skip(from).map(|(_, e)| e).collect();
        self.builders.append_range(from as u64, frame).unwrap();
    }

    /// The builder signer that cl-chain sends for `state.builders[index]`: the key version and
    /// the full key of `state`. On import the key goes inline when the cache does not hold that
    /// exact entry (`BuilderFeed::needs_inline`).
    fn builder_signer(
        &self,
        state: &BeaconState<E>,
        index: BuilderIndex,
        version: u64,
        origin: Origin,
    ) -> BuilderSigner<PublicKey> {
        let pubkey = pubkey_at(state, index);
        let cached = BuilderSigner::Cached {
            index,
            version,
            pubkey,
        };
        let held = matches!(
            self.builders.resolve(index, version, &pubkey),
            Lookup::Known(_)
        );
        match origin {
            Origin::Import if !held => BuilderSigner::Inline {
                index,
                key: PublicKey::from_validated_bytes(&pubkey).unwrap(),
            },
            _ => cached,
        }
    }

    /// Verifies the one-signer set `set` against `state` from `origin`.
    fn verify(&self, state: &BeaconState<E>, set: &SignatureSet, origin: Origin) -> Verdict {
        let [signer] = set.signers() else {
            panic!("the tests verify one-signer sets only");
        };
        let root = set.signing_root();
        let verdict = |key: &PublicKey| match Signature::from_validated_bytes(set.signature()) {
            Ok(sig) if crypto_bls::verify(key, root.as_slice(), &sig) => Verdict::Valid,
            _ => Verdict::Invalid,
        };
        match signer {
            SignerRef::Validator(index) => {
                let signer = Signer::Validator(*index);
                match self.validators.resolve_signer(&signer, origin) {
                    Resolution::Resolved(k) => verdict(k.key()),
                    _ => Verdict::Ignore,
                }
            }
            SignerRef::Builder { index, version } => {
                self.builder_lookups.set(self.builder_lookups.get() + 1);
                let signer = self.builder_signer(state, *index, *version, origin);
                match self.builders.resolve_signer(&signer, origin) {
                    Resolution::Resolved(k) => verdict(k.key()),
                    Resolution::Ignore(IgnoreReason::UnknownBuilder { .. }) => Verdict::Ignore,
                    other => panic!("unexpected builder resolution {other:?}"),
                }
            }
            SignerRef::Inline(pubkey) => match PublicKey::from_validated_bytes(pubkey) {
                Ok(key) => verdict(&key),
                Err(_) => Verdict::Invalid,
            },
        }
    }

    /// [`Self::verify`] from gossip and from import.
    fn verify_both(&self, state: &BeaconState<E>, set: &SignatureSet) -> (Verdict, Verdict) {
        (
            self.verify(state, set, Origin::Gossip),
            self.verify(state, set, Origin::Import),
        )
    }
}

// --- Exit 2b ----------------------------------------------------------------------------------

/// Exit 2b (G L2322-2331): a builder exits, the sweep pays it out, and a new key takes its
/// index. The old key is rejected and the new key is accepted, before and after the reuse is
/// finalized, and a stale view of the old registry resolves nothing.
#[test]
fn exit_then_index_reuse_rejects_the_old_key_and_accepts_the_new() {
    let (a, b, c) = (Key::new(1), Key::new(2), Key::new(3));
    let mut verifier = Verifier::new();

    // Before the exit: `a` at index 0 is finalized and active, and its bid is valid.
    let mut before = chain();
    deposit(&mut before, &a, 5 * ETH);
    deposit(&mut before, &b, 5 * ETH);
    advance(&mut before, 3, 2);
    verifier.finalize(&before);
    let set = checked_bid_set(&before, &bid(&before, 0, &a));
    assert_eq!(
        verifier.verify_both(&before, &set),
        (Verdict::Valid, Verdict::Valid)
    );

    // `a` exits and is swept; the deposit of `c` takes index 0 with a new version.
    let swept = swept_registry(&a, &b);
    let mut reused = swept.clone();
    deposit(&mut reused, &c, 3 * ETH);
    assert_eq!(index_of(&reused, &c), Some(0));
    assert_eq!(index_of(&reused, &a), None);
    let new = reused.builders.get(0).unwrap();
    assert_eq!(new.deposit_epoch, 3 + E::MIN_BUILDER_WITHDRAWABILITY_DELAY);
    assert_eq!(new.withdrawable_epoch, FAR_FUTURE_EPOCH);
    assert_ne!(
        builder_key_version(&reused, 0).unwrap(),
        builder_key_version(&swept, 0).unwrap(),
        "a reused index always gets a new version"
    );

    // The reuse is not finalized: the cache still holds `a` at index 0. The old key is never
    // accepted; the new key is ignored on gossip and accepted inline on import.
    let old = bid_set(&reused, &bid(&reused, 0, &a));
    let new = bid_set(&reused, &bid(&reused, 0, &c));
    assert_eq!(
        verifier.verify_both(&reused, &old),
        (Verdict::Ignore, Verdict::Invalid)
    );
    assert_eq!(
        verifier.verify_both(&reused, &new),
        (Verdict::Ignore, Verdict::Valid)
    );

    // The reuse is finalized and `c` is active: the cache now holds `c` at index 0.
    let mut finalized = reused.clone();
    advance(&mut finalized, 7, 6);
    verifier.finalize(&finalized);
    assert_eq!(verifier.builders.high_water(), 2);
    let old = checked_bid_set(&finalized, &bid(&finalized, 0, &a));
    let new = checked_bid_set(&finalized, &bid(&finalized, 0, &c));
    assert_eq!(
        verifier.verify_both(&finalized, &old),
        (Verdict::Invalid, Verdict::Invalid)
    );
    assert_eq!(
        verifier.verify_both(&finalized, &new),
        (Verdict::Valid, Verdict::Valid)
    );
    // Builder 1 did not change, and its key still resolves from the cache.
    let other = checked_bid_set(&finalized, &bid(&finalized, 1, &b));
    assert_eq!(
        verifier.verify(&finalized, &other, Origin::Gossip),
        Verdict::Valid
    );

    // A stale view of the old registry (a lagging peer, a state before the reuse) names `a`
    // at index 0. The cache does not resolve it: the old key cannot come back.
    let stale = bid_set(&before, &bid(&before, 0, &a));
    assert_eq!(
        verifier.verify(&before, &stale, Origin::Gossip),
        Verdict::Ignore
    );
    let version = builder_key_version(&before, 0).unwrap();
    assert_eq!(
        verifier.builders.resolve(0, version, &a.pubkey()),
        Lookup::Unknown
    );
}

/// The index reuse of `state_transition::testing::index_reuse_states` (the `Builder.version` of
/// the old and the new builder is the same): the exited key never resolves for the new
/// builder, and the new key resolves once its state is finalized.
#[test]
fn index_reuse_states_never_resolve_the_exited_key() {
    let (exited, reused) = index_reuse_states::<E>();
    let old = exited.builders.get(0).unwrap();
    let new = reused.builders.get(0).unwrap();
    assert_eq!(
        (old.pubkey, new.pubkey),
        ([EXITED_BUILDER_KEY; 48], [REUSING_BUILDER_KEY; 48])
    );
    assert_eq!(
        old.version, new.version,
        "Builder.version does not tell them apart"
    );

    // The cache of the tests holds the compressed key as the decoded key.
    let entry = |state: &BeaconState<E>, i: u64| {
        let pubkey = pubkey_at(state, i);
        BuilderEntry::new(builder_key_version(state, i).unwrap(), pubkey, pubkey)
    };
    let mut cache = BuilderKeyCache::new();
    cache
        .append_range(0, vec![entry(&exited, 0), entry(&exited, 1)])
        .unwrap();
    let new_version = builder_key_version(&reused, 0).unwrap();
    let old_version = builder_key_version(&exited, 0).unwrap();
    // The new builder against the old finalized entry: a miss, never the exited key.
    assert_eq!(cache.resolve(0, new_version, &new.pubkey), Lookup::Unknown);
    // The finalized reuse replaces the entry; the exited key misses from then on.
    cache.append_range(0, vec![entry(&reused, 0)]).unwrap();
    assert_eq!(
        cache.resolve(0, new_version, &new.pubkey),
        Lookup::Known(&new.pubkey)
    );
    assert_eq!(cache.resolve(0, old_version, &old.pubkey), Lookup::Unknown);
    // A version hint from the other builder with the right key also misses.
    assert_eq!(cache.resolve(0, old_version, &new.pubkey), Lookup::Unknown);
}

// --- Re-registration --------------------------------------------------------------------------

/// A key that was in the registry comes back under a new index (G L2322-2331: "a newly
/// registered builder's public key may have previously appeared in the builder set"). It
/// resolves at the new index only, with the same version as before (the version follows the
/// key), and its old index resolves to the builder that took it.
#[test]
fn re_registration_of_a_seen_pubkey_resolves_to_the_new_index() {
    let (a, b, c) = (Key::new(1), Key::new(2), Key::new(3));
    let mut verifier = Verifier::new();
    let swept = swept_registry(&a, &b);
    let old_version = builder_key_version(&swept, 0).unwrap();
    verifier.finalize(&swept);

    // A deposit of `a` before its index is reused tops up the exited builder: no new
    // registration, and an exited builder does not become active again.
    let mut topped_up = swept.clone();
    deposit(&mut topped_up, &a, ETH);
    assert_eq!(index_of(&topped_up, &a), Some(0));
    assert_ne!(
        topped_up.builders.get(0).unwrap().withdrawable_epoch,
        FAR_FUTURE_EPOCH
    );

    // `c` takes index 0, then `a` registers again: a new registration at the end.
    let mut state = swept.clone();
    deposit(&mut state, &c, 3 * ETH);
    deposit(&mut state, &a, 3 * ETH);
    assert_eq!(
        (
            index_of(&state, &c),
            index_of(&state, &b),
            index_of(&state, &a)
        ),
        (Some(0), Some(1), Some(2))
    );
    assert_eq!(builder_key_version(&state, 2).unwrap(), old_version);

    advance(&mut state, 7, 6);
    verifier.finalize(&state);
    assert_eq!(verifier.builders.high_water(), 3);
    let at_new_index = checked_bid_set(&state, &bid(&state, 2, &a));
    let at_old_index = checked_bid_set(&state, &bid(&state, 0, &a));
    let reuser = checked_bid_set(&state, &bid(&state, 0, &c));
    assert_eq!(
        verifier.verify_both(&state, &at_new_index),
        (Verdict::Valid, Verdict::Valid)
    );
    assert_eq!(
        verifier.verify_both(&state, &at_old_index),
        (Verdict::Invalid, Verdict::Invalid)
    );
    assert_eq!(
        verifier.verify_both(&state, &reuser),
        (Verdict::Valid, Verdict::Valid)
    );
    // The old placement (index 0, the version of `a`, the key of `a`) resolves nothing.
    assert_eq!(
        verifier.builders.resolve(0, old_version, &a.pubkey()),
        Lookup::Unknown
    );
    match verifier.builders.resolve(2, old_version, &a.pubkey()) {
        Lookup::Known(key) => assert_eq!(key.to_bytes(), a.pubkey()),
        Lookup::Unknown => panic!("the re-registered key must resolve at its new index"),
    }
}

// --- Reorg ------------------------------------------------------------------------------------

/// Two branches reuse the same index in the same epoch with different keys: `(index,
/// Builder.version, deposit_epoch)` is the same on both. After a reorg from one branch to the
/// other, a bid signed with the key of the wrong branch is rejected, and so is the key of the
/// finalized builder that left the index.
#[test]
fn reorg_across_a_builder_deposit_rejects_the_wrong_branch_key() {
    let (a, b, x, y) = (Key::new(1), Key::new(2), Key::new(24), Key::new(25));
    let mut verifier = Verifier::new();
    let finalized = swept_registry(&a, &b);
    verifier.finalize(&finalized);

    let mut branch_x = finalized.clone();
    deposit(&mut branch_x, &x, 3 * ETH);
    let mut branch_y = finalized.clone();
    deposit(&mut branch_y, &y, 3 * ETH);
    let (bx, by) = (
        branch_x.builders.get(0).unwrap(),
        branch_y.builders.get(0).unwrap(),
    );
    assert_eq!(
        (bx.version, bx.deposit_epoch),
        (by.version, by.deposit_epoch),
        "the same registration fields on both branches"
    );
    assert_ne!(bx.pubkey, by.pubkey);
    assert_ne!(
        builder_key_version(&branch_x, 0).unwrap(),
        builder_key_version(&branch_y, 0).unwrap()
    );

    // The head is on X: X's key is good there, Y's is not.
    let on_x = bid_set(&branch_x, &bid(&branch_x, 0, &x));
    let y_on_x = bid_set(&branch_x, &bid(&branch_x, 0, &y));
    assert_eq!(
        verifier.verify(&branch_x, &on_x, Origin::Import),
        Verdict::Valid
    );
    assert_eq!(
        verifier.verify(&branch_x, &y_on_x, Origin::Import),
        Verdict::Invalid
    );

    // Reorg to Y. The key of the wrong branch, and the key of the finalized builder that left
    // the index, are never accepted.
    for wrong in [&x, &a] {
        let set = bid_set(&branch_y, &bid(&branch_y, 0, wrong));
        assert_eq!(
            verifier.verify_both(&branch_y, &set),
            (Verdict::Ignore, Verdict::Invalid)
        );
    }
    let on_y = bid_set(&branch_y, &bid(&branch_y, 0, &y));
    assert_eq!(
        verifier.verify_both(&branch_y, &on_y),
        (Verdict::Ignore, Verdict::Valid)
    );

    // Y is finalized: its key resolves from the cache, and X's key stays rejected, also for a
    // stale view of branch X.
    advance(&mut branch_y, 7, 6);
    verifier.finalize(&branch_y);
    let on_y = checked_bid_set(&branch_y, &bid(&branch_y, 0, &y));
    let x_on_y = checked_bid_set(&branch_y, &bid(&branch_y, 0, &x));
    assert_eq!(
        verifier.verify_both(&branch_y, &on_y),
        (Verdict::Valid, Verdict::Valid)
    );
    assert_eq!(
        verifier.verify_both(&branch_y, &x_on_y),
        (Verdict::Invalid, Verdict::Invalid)
    );
    assert_eq!(
        verifier.verify(&branch_x, &on_x, Origin::Gossip),
        Verdict::Ignore
    );
}

// --- Self-build -------------------------------------------------------------------------------

/// A state at slot 1 whose latest block header is the block of the slot's proposer, with the
/// builders `a` and `b` in the registry, and a verifier fed with that state.
fn self_build_chain(a: &Key, b: &Key) -> (BeaconState<E>, Verifier) {
    let mut state = genesis_state::<E>(&[32 * ETH; VALIDATORS]);
    for i in 0..VALIDATORS {
        state.validators.get_mut(i).unwrap().pubkey = validator_key(i as u64).pubkey();
    }
    deposit(&mut state, a, 5 * ETH);
    deposit(&mut state, b, 5 * ETH);
    process_slots(&mut state, 1, &no_bls()).unwrap();
    let block = block_at_state_slot(&state);
    process_block_header(&mut state, &block.message).unwrap();
    let mut verifier = Verifier::new();
    verifier.finalize(&state);
    assert_eq!(verifier.builders.high_water(), 2);
    (state, verifier)
}

/// A self-build bid with the infinity signature passes the bid step with no signature set,
/// and a self-build envelope signed by the proposer's validator key passes (G L2104-2115,
/// L2170-2172). Neither makes a builder-key lookup.
#[test]
fn self_build_bid_and_envelope_pass() {
    let (a, b) = (Key::new(1), Key::new(2));
    let (state, verifier) = self_build_chain(&a, &b);

    let bid = bid_for_state(&state, BUILDER_INDEX_SELF_BUILD, 0);
    assert_eq!(bid.signature, crypto_bls::G2_POINT_AT_INFINITY);
    assert_eq!(
        block_bid_signature_set(&state, &bid, MINIMAL_MAX_BLOBS_PER_BLOCK),
        Ok(None),
        "a self-build bid has no signature set"
    );
    let mut after = state.clone();
    process_execution_payload_bid(&mut after, &bid, MINIMAL_MAX_BLOBS_PER_BLOCK).unwrap();
    assert_eq!(after.latest_execution_payload_bid, bid.message);

    let proposer = state.latest_block_header.proposer_index;
    let message = envelope(&state, BUILDER_INDEX_SELF_BUILD);
    let signature = validator_key(proposer).sign(envelope_root(&state, &message));
    let set = envelope_set(&state, &message, signature);
    assert_eq!(set.signers(), &[SignerRef::Validator(proposer)]);
    assert_eq!(
        verifier.verify_both(&state, &set),
        (Verdict::Valid, Verdict::Valid)
    );
    assert_eq!(verifier.builder_lookups.get(), 0);
}

/// A self-build envelope signed with a builder key is rejected: the signer is the proposer's
/// validator key, which fails for the builder's signature and passes for the proposer's.
/// Self-build bids and envelopes make zero builder-cache lookups; a builder envelope makes one.
#[test]
fn self_build_signer() {
    let (a, b) = (Key::new(1), Key::new(2));
    let (state, verifier) = self_build_chain(&a, &b);
    let proposer = state.latest_block_header.proposer_index;
    assert_eq!(
        envelope_signer(BUILDER_INDEX_SELF_BUILD, proposer, 0),
        SignerRef::Validator(proposer)
    );

    let message = envelope(&state, BUILDER_INDEX_SELF_BUILD);
    let root = envelope_root(&state, &message);
    let proposer_key = verifier.validators.get(proposer);
    let Lookup::Known(proposer_key) = proposer_key else {
        panic!("the proposer is in the finalized validator registry");
    };
    for builder in [&a, &b] {
        let by_builder = builder.sign(root);
        let sig = Signature::from_validated_bytes(&by_builder).unwrap();
        assert!(!crypto_bls::verify(proposer_key, root.as_slice(), &sig));
        let set = envelope_set(&state, &message, by_builder);
        assert_eq!(
            verifier.verify_both(&state, &set),
            (Verdict::Invalid, Verdict::Invalid)
        );
    }
    let by_proposer = validator_key(proposer).sign(root);
    let sig = Signature::from_validated_bytes(&by_proposer).unwrap();
    assert!(crypto_bls::verify(proposer_key, root.as_slice(), &sig));
    let set = envelope_set(&state, &message, by_proposer);
    assert_eq!(
        verifier.verify_both(&state, &set),
        (Verdict::Valid, Verdict::Valid)
    );

    // The self-build bid has no set at all.
    let bid = bid_for_state(&state, BUILDER_INDEX_SELF_BUILD, 0);
    assert_eq!(
        block_bid_signature_set(&state, &bid, MINIMAL_MAX_BLOBS_PER_BLOCK),
        Ok(None)
    );
    assert_eq!(
        verifier.builder_lookups.get(),
        0,
        "self-build: no builder lookup"
    );

    // An envelope of builder 0 is signed by the builder key, through the builder cache.
    let message = envelope(&state, 0);
    let root = envelope_root(&state, &message);
    let set = envelope_set(&state, &message, a.sign(root));
    assert_eq!(
        set.signers(),
        &[SignerRef::Builder {
            index: 0,
            version: builder_key_version(&state, 0).unwrap()
        }]
    );
    assert_eq!(
        verifier.verify(&state, &set, Origin::Gossip),
        Verdict::Valid
    );
    assert_eq!(verifier.builder_lookups.get(), 1);
    let by_proposer = envelope_set(&state, &message, validator_key(proposer).sign(root));
    assert_eq!(
        verifier.verify(&state, &by_proposer, Origin::Gossip),
        Verdict::Invalid
    );
}

/// Builder keys are in their own namespace, keyed by builder index and key version: they never
/// enter the validator cache, a builder index never resolves to a validator key, and a
/// validator index never resolves to a builder key.
#[test]
fn builder_keys_never_enter_the_validator_cache() {
    let (a, b) = (Key::new(1), Key::new(2));
    let (state, verifier) = self_build_chain(&a, &b);
    assert_eq!(verifier.validators.high_water(), VALIDATORS as u64);
    assert_eq!(verifier.builders.high_water(), 2);
    for (index, builder) in [(0u64, &a), (1, &b)] {
        match verifier.validators.get(index) {
            Lookup::Known(key) => {
                assert_eq!(key.to_bytes(), validator_key(index).pubkey());
                assert_ne!(key.to_bytes(), builder.pubkey());
            }
            Lookup::Unknown => panic!("validator {index} is finalized"),
        }
        // The validator key of the same index, under the builder's version, misses.
        let version = builder_key_version(&state, index).unwrap();
        let validator = validator_key(index).pubkey();
        assert_eq!(
            verifier.builders.resolve(index, version, &validator),
            Lookup::Unknown
        );
        // A builder bid signed by the validator of the same index is rejected.
        let set = bid_set(&state, &bid(&state, index, &validator_key(index)));
        assert_eq!(
            verifier.verify(&state, &set, Origin::Gossip),
            Verdict::Invalid
        );
    }
}
