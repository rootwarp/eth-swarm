//! Builder deposit and exit requests (G L2266-2383, New in Gloas): the builder registry
//! with index reuse, and builder exits.
//!
//! [`process_builder_deposit_request`] and [`process_builder_exit_request`] are the
//! functions that `apply_parent_execution_payload` (G L1784-1830) calls for each request.
//! The proof of possession of a new builder goes through a [`SignatureBackend`]. The caller
//! fetches its verdict before the transition (ADR-011): a missing verdict is
//! [`StfError::MissingVerdict`].
//!
//! The deposit domain takes `GENESIS_FORK_VERSION`, a value of the network config and not
//! of the preset: Sepolia and Hoodi run the mainnet preset with other versions. Thus the
//! deposit functions take it as an argument. The caller (cl-chain) reads it from
//! `network_config::ChainConfig::genesis_fork_version()`.
//!
//! # Builder indices are reusable
//!
//! A builder that exited, and that the builders sweep paid out, frees its index. The next
//! new builder takes that index with a new key ([`get_index_for_new_builder`], G
//! L2322-2331). A key that was in the registry can come back at another index.
//!
//! `Builder.version` and `deposit_epoch` do not tell the old and the new builder at a
//! reused index apart on every branch. [`add_builder_to_registry`] writes
//! `PAYLOAD_BUILDER_VERSION` as the `Builder.version` of each new builder. Before finality,
//! two branches can each reuse an index in the same epoch with different keys. Thus the
//! `version` of `SignerRef::Builder { index, version }` is
//! [`crate::accessors::builder_key_version`], a digest of the key, which changes when a new
//! key takes the index. A cache of builder keys uses `(index, version)` as its key, or
//! compares its key with `state.builders[index].pubkey` of the state that it verifies
//! against ([4.9], [4.10]).

use crate::accessors::{
    get_current_epoch, get_pending_balance_to_withdraw_for_builder, is_active_builder,
    is_builder_withdrawal_credential,
};
use crate::mutators::initiate_builder_exit;
use crate::preset::PAYLOAD_BUILDER_VERSION;
use crate::{Preset, SignatureBackend, SignatureSet, SignerRef, StfError};
use consensus_types::common::DepositMessage;
use consensus_types::gloas::{BeaconState, Builder, BuilderDepositRequest, BuilderExitRequest};
use consensus_types::primitives::{
    BLSPubkey, BuilderIndex, ExecutionAddress, Gwei, Root, Slot, Version, FAR_FUTURE_EPOCH,
};
use consensus_types::signing::{compute_domain, compute_signing_root, DOMAIN_BUILDER_DEPOSIT};

/// The signature set of `is_valid_builder_deposit_signature` (G L2276-2284) without the BLS
/// call: the inline key of the request over its `DepositMessage`, in the domain
/// `compute_domain(DOMAIN_BUILDER_DEPOSIT)`. That domain takes `genesis_fork_version` (the
/// `GENESIS_FORK_VERSION` of the network, from
/// `network_config::ChainConfig::genesis_fork_version()`) and a zero genesis validators
/// root. The caller uses the set to fetch the verdict before the transition.
///
/// A caller that prefetches verdicts must fetch one for each request with the
/// `BUILDER_WITHDRAWAL_PREFIX`, and must not use the pre-state to select the requests. An
/// earlier request of the same payload can change the registry. For example, a new key
/// takes the reused index of the key K, and then a later deposit for K is a new
/// registration that needs a verdict.
pub fn builder_deposit_signature_set(
    request: &BuilderDepositRequest,
    genesis_fork_version: Version,
) -> SignatureSet {
    let deposit_message = DepositMessage {
        pubkey: request.pubkey,
        withdrawal_credentials: request.withdrawal_credentials,
        amount: request.amount,
    };
    let domain = compute_domain(DOMAIN_BUILDER_DEPOSIT, genesis_fork_version, Root::ZERO);
    SignatureSet::single(
        SignerRef::Inline(request.pubkey),
        compute_signing_root(&deposit_message, domain),
        request.signature,
    )
}

/// `is_valid_builder_deposit_signature` (G L2276-2284, New in Gloas), through `backend`,
/// with the set of [`builder_deposit_signature_set`].
///
/// `Ok(false)` for an invalid signature. By the contract of [`SignatureBackend`], that
/// includes a key or a signature that does not decode or fails `KeyValidate`. A backend
/// without a verdict gives [`StfError::MissingVerdict`], never `Ok(false)`.
pub fn is_valid_builder_deposit_signature(
    request: &BuilderDepositRequest,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<bool, StfError> {
    let set = builder_deposit_signature_set(request, genesis_fork_version);
    backend
        .verify_signature_sets(std::slice::from_ref(&set))
        .map_err(StfError::MissingVerdict)
}

/// `get_index_for_new_builder` (G L2290-2294, New in Gloas): the first builder that is
/// withdrawable and has a zero balance, else the end of the registry.
///
/// The index can be the index of an earlier builder with another key (G L2322-2331). It
/// reads the registry. The registry is small and gets at most
/// `MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD` deposits for each payload.
pub fn get_index_for_new_builder<E: Preset>(state: &BeaconState<E>) -> BuilderIndex {
    let epoch = get_current_epoch(state);
    state
        .builders
        .iter()
        .position(|builder| builder.withdrawable_epoch <= epoch && builder.balance == 0)
        .unwrap_or(state.builders.len()) as BuilderIndex
}

/// `add_builder_to_registry` (G L2300-2319, New in Gloas), with `set_or_append_list`
/// (A L308-316): the new builder goes to [`get_index_for_new_builder`].
///
/// The registration fields `version` and `deposit_epoch` identify the builder at its index:
/// a reused index gets the epoch of the new deposit.
pub fn add_builder_to_registry<E: Preset>(
    state: &mut BeaconState<E>,
    pubkey: BLSPubkey,
    version: u8,
    execution_address: ExecutionAddress,
    amount: Gwei,
    slot: Slot,
) -> Result<(), StfError> {
    let index = get_index_for_new_builder(state);
    let builder = Builder {
        pubkey,
        version,
        execution_address,
        balance: amount,
        deposit_epoch: E::epoch_at_slot(slot),
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    };
    if index == state.builders.len() as BuilderIndex {
        // `Builders` is a `ProgressiveList` without a limit. milhouse fails only at a
        // length of `usize::MAX`: `StfError::Tree`, which is not a proof of an invalid input.
        state.builders.push(builder)?;
    } else {
        // `get_index_for_new_builder` gives an index in the registry.
        *state
            .builders
            .get_mut(index as usize)
            .ok_or(StfError::UnknownBuilder(index))? = builder;
    }
    Ok(())
}

/// The index of the builder with `pubkey`: `builder_pubkeys.index(pubkey)`, the first match.
/// It reads the registry.
fn builder_index_of<E: Preset>(state: &BeaconState<E>, pubkey: &BLSPubkey) -> Option<BuilderIndex> {
    state
        .builders
        .iter()
        .position(|builder| builder.pubkey == *pubkey)
        .map(|index| index as BuilderIndex)
}

/// `process_builder_deposit_request` (G L2334-2360, New in Gloas).
///
/// A request with another withdrawal prefix is ignored. A new key registers a builder only
/// with a valid proof of possession: an invalid one ignores the request, and a missing
/// verdict gives [`StfError::MissingVerdict`]. A known key tops up its builder, with no
/// signature check. A builder that exited and was paid out gets a new withdrawable epoch,
/// so that the sweep pays the deposit out. Exited builders do not become active again.
///
/// `genesis_fork_version` is the `GENESIS_FORK_VERSION` of the network, from
/// `network_config::ChainConfig::genesis_fork_version()` (see
/// [`builder_deposit_signature_set`]).
///
/// [`super::parent_payload::apply_parent_execution_payload`] calls it (G L1825). On `Err`,
/// `state` is partly updated: the caller drops it.
pub fn process_builder_deposit_request<E: Preset>(
    state: &mut BeaconState<E>,
    request: &BuilderDepositRequest,
    genesis_fork_version: Version,
    backend: &dyn SignatureBackend,
) -> Result<(), StfError> {
    // Ignore deposits with unexpected withdrawal credential prefixes
    if !is_builder_withdrawal_credential(&request.withdrawal_credentials) {
        return Ok(());
    }
    let Some(builder_index) = builder_index_of(state, &request.pubkey) else {
        if is_valid_builder_deposit_signature(request, genesis_fork_version, backend)? {
            add_builder_to_registry(
                state,
                request.pubkey,
                PAYLOAD_BUILDER_VERSION,
                ExecutionAddress::from_slice(&request.withdrawal_credentials[12..]),
                request.amount,
                state.slot,
            )?;
        }
        return Ok(());
    };
    let epoch = get_current_epoch(state);
    let builder = state
        .builders
        .get_mut(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?;
    // If exited and swept, reset the withdrawable epoch
    if builder.withdrawable_epoch != FAR_FUTURE_EPOCH && builder.balance == 0 {
        builder.withdrawable_epoch = epoch
            .checked_add(E::MIN_BUILDER_WITHDRAWABILITY_DELAY)
            .ok_or(StfError::ArithmeticOverflow)?;
    }
    // Increase balance by deposit amount
    builder.balance = builder
        .balance
        .checked_add(request.amount)
        .ok_or(StfError::ArithmeticOverflow)?;
    Ok(())
}

/// `process_builder_exit_request` (G L2368-2383, New in Gloas): an exit of an active
/// builder, requested from its execution address, when it has no pending withdrawal or
/// payment. Any other request is ignored.
///
/// [`super::parent_payload::apply_parent_execution_payload`] calls it (G L1826).
pub fn process_builder_exit_request<E: Preset>(
    state: &mut BeaconState<E>,
    request: &BuilderExitRequest,
) -> Result<(), StfError> {
    let Some(builder_index) = builder_index_of(state, &request.pubkey) else {
        return Ok(());
    };
    if !is_active_builder(state, builder_index)? {
        return Ok(());
    }
    let builder = state
        .builders
        .get(builder_index as usize)
        .ok_or(StfError::UnknownBuilder(builder_index))?;
    if builder.execution_address != request.source_address {
        return Ok(());
    }
    if get_pending_balance_to_withdraw_for_builder(state, builder_index)? != 0 {
        return Ok(());
    }
    initiate_builder_exit(state, builder_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessors::builder_key_version;
    use crate::preset::PAYLOAD_BUILDER_VERSION;
    use crate::testing::{
        builder, builder_deposit_request, builder_exit_request, index_reuse_states, registry_state,
        ContractBackend, ScriptedBackend, EXITED_BUILDER_KEY, GENESIS_FORK_VERSION,
        REUSING_BUILDER_KEY,
    };
    use crate::{state_root, BackendError, SignatureSet, SignerRef};
    use consensus_types::common::DepositMessage;
    use consensus_types::gloas::{BeaconState, Builder, BuilderPendingWithdrawal};
    use consensus_types::primitives::{Address, Bytes32, Gwei, Root, Version, FAR_FUTURE_EPOCH};
    use consensus_types::signing::{compute_domain, compute_signing_root, DOMAIN_BUILDER_DEPOSIT};
    use consensus_types::{Mainnet, Minimal};

    const ETH: Gwei = 1_000_000_000;

    /// A state in epoch 4, finalized at epoch 3, with the builders `[0xa1; 48]` and
    /// `[0xa2; 48]`, deposited in epoch 0 with 5 ETH each.
    fn state<E: Preset>() -> BeaconState<E> {
        let mut state = registry_state::<E>(&[32 * ETH; 8], Bytes32::ZERO);
        state.slot = E::start_slot_at_epoch(4) + 2;
        state.finalized_checkpoint.epoch = 3;
        for key in [0xa1, 0xa2] {
            state.builders.push(builder(key, 5 * ETH, 0)).unwrap();
        }
        state
    }

    fn builders<E: Preset>(state: &BeaconState<E>) -> Vec<Builder> {
        state.builders.iter().cloned().collect()
    }

    /// The builder that a new registration of `request` in `epoch` writes.
    fn registered(key: u8, amount: Gwei, epoch: u64) -> Builder {
        Builder {
            pubkey: [key; 48],
            version: PAYLOAD_BUILDER_VERSION,
            execution_address: Address::repeat_byte(key),
            balance: amount,
            deposit_epoch: epoch,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    }

    fn index_reuse_for<E: Preset>() {
        let (exited, reused) = index_reuse_states::<E>();
        let epoch = 3 + E::MIN_BUILDER_WITHDRAWABILITY_DELAY;
        let old = exited.builders.get(0).unwrap().clone();
        assert_eq!(old.pubkey, [EXITED_BUILDER_KEY; 48]);
        assert_eq!((old.withdrawable_epoch, old.balance), (epoch, 0));
        assert_eq!(get_index_for_new_builder(&exited), 0);
        // The new builder takes index 0 with its own key, and the registry does not grow.
        assert_eq!(
            builders(&reused),
            vec![
                registered(REUSING_BUILDER_KEY, 7, epoch),
                exited.builders.get(1).unwrap().clone(),
            ]
        );
        // `Builder.version` does not change with the reuse: both builders have
        // PAYLOAD_BUILDER_VERSION. Only the key and the deposit epoch differ, and the key
        // version of `SignerRef::Builder` follows the key.
        let new = reused.builders.get(0).unwrap();
        assert_eq!(new.version, old.version);
        assert_ne!(new.pubkey, old.pubkey);
        assert_ne!(new.deposit_epoch, old.deposit_epoch);
        assert_ne!(
            builder_key_version(&reused, 0),
            builder_key_version(&exited, 0)
        );

        // The old key is not in the registry now: a deposit for it is a new registration,
        // which needs a valid signature and goes to the end of the registry.
        let mut again = reused.clone();
        let backend = ScriptedBackend::new([Ok(true)]);
        let request = builder_deposit_request(EXITED_BUILDER_KEY, 9);
        assert_eq!(
            process_builder_deposit_request(&mut again, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(backend.seen().len(), 1);
        assert_eq!(
            again.builders.get(2),
            Some(&registered(EXITED_BUILDER_KEY, 9, epoch))
        );

        // One epoch before the withdrawable epoch, the index is not free.
        let mut early = exited.clone();
        early.slot = E::start_slot_at_epoch(epoch - 1);
        assert_eq!(get_index_for_new_builder(&early), 2);
        // A balance that the sweep did not pay out keeps the index.
        let mut unpaid = exited.clone();
        unpaid.builders.get_mut(0).unwrap().balance = 1;
        assert_eq!(get_index_for_new_builder(&unpaid), 2);
        // An index that is free from an earlier epoch is free too.
        let mut late = exited;
        late.slot = E::start_slot_at_epoch(epoch + 5);
        assert_eq!(get_index_for_new_builder(&late), 0);
    }

    #[test]
    fn index_reuse() {
        index_reuse_for::<Minimal>();
        index_reuse_for::<Mainnet>();
    }

    #[test]
    fn index_reuse_takes_the_first_free_index() {
        let mut state = state::<Minimal>();
        for key in [0xa3, 0xa4] {
            let mut free = builder(key, 0, 0);
            free.withdrawable_epoch = 4;
            state.builders.push(free).unwrap();
        }
        assert_eq!(get_index_for_new_builder(&state), 2);
        let backend = ScriptedBackend::new([Ok(true)]);
        let request = builder_deposit_request(0xc1, 3 * ETH);
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(state.builders.get(2), Some(&registered(0xc1, 3 * ETH, 4)));
        assert_eq!(get_index_for_new_builder(&state), 3);
    }

    #[test]
    fn builder_pop_verdicts() {
        let pre = state::<Minimal>();
        let request = builder_deposit_request(0xc1, 2 * ETH);
        // The set: the inline key of the request over its `DepositMessage`, in the domain
        // of `compute_domain(DOMAIN_BUILDER_DEPOSIT)` (GENESIS_FORK_VERSION, a zero root).
        let message = DepositMessage {
            pubkey: request.pubkey,
            withdrawal_credentials: request.withdrawal_credentials,
            amount: request.amount,
        };
        let domain = compute_domain(DOMAIN_BUILDER_DEPOSIT, [0, 0, 0, 1], Root::ZERO);
        let want = SignatureSet::single(
            SignerRef::Inline([0xc1; 48]),
            compute_signing_root(&message, domain),
            [0x22; 96],
        );
        assert_eq!(GENESIS_FORK_VERSION, [0, 0, 0, 1]);
        assert_eq!(
            builder_deposit_signature_set(&request, GENESIS_FORK_VERSION),
            want
        );

        // A valid proof of possession registers the builder.
        let mut state = pre.clone();
        let backend = ScriptedBackend::new([Ok(true)]);
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(backend.seen(), vec![want.clone()]);
        assert_eq!(state.builders.get(2), Some(&registered(0xc1, 2 * ETH, 4)));

        // An invalid proof of possession: the deposit is ignored, and the request is valid.
        let mut state = pre.clone();
        let backend = ScriptedBackend::new([Ok(false)]);
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(backend.seen(), vec![want.clone()]);
        assert_eq!(state_root(&mut state), state_root(&mut pre.clone()));

        // No verdict: the caller did not fetch it, so the transition cannot continue. This is
        // not a proof that the request is invalid.
        let mut state = pre.clone();
        let missing = BackendError("not prefetched".into());
        let backend = ScriptedBackend::new([Err(missing.clone())]);
        let err =
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend)
                .unwrap_err();
        assert_eq!(err, StfError::MissingVerdict(missing));
        assert!(!err.proves_invalid());
        assert_eq!(builders(&state), builders(&pre));

        // The predicate gives the same three answers.
        let verdicts = [Ok(true), Ok(false), Err(BackendError("x".into()))];
        let backend = ScriptedBackend::new(verdicts);
        let check = || is_valid_builder_deposit_signature(&request, GENESIS_FORK_VERSION, &backend);
        assert_eq!(check(), Ok(true));
        assert_eq!(check(), Ok(false));
        assert_eq!(
            check(),
            Err(StfError::MissingVerdict(BackendError("x".into())))
        );
    }

    #[test]
    fn builder_deposit_domain_takes_the_network_genesis_fork_version() {
        // Sepolia runs the mainnet preset with GENESIS_FORK_VERSION 0x90000069
        // (crates/network-config/networks/sepolia/config.yaml). The domain must use it, not
        // the 0x00000000 of the mainnet config.
        const SEPOLIA: Version = [0x90, 0x00, 0x00, 0x69];
        let request = builder_deposit_request(0xc1, 2 * ETH);
        let message = DepositMessage {
            pubkey: request.pubkey,
            withdrawal_credentials: request.withdrawal_credentials,
            amount: request.amount,
        };
        let sepolia = compute_domain(DOMAIN_BUILDER_DEPOSIT, SEPOLIA, Root::ZERO);
        let set = builder_deposit_signature_set(&request, SEPOLIA);
        assert_eq!(set.signing_root(), compute_signing_root(&message, sepolia));
        let mainnet = compute_domain(DOMAIN_BUILDER_DEPOSIT, [0; 4], Root::ZERO);
        assert_ne!(set.signing_root(), compute_signing_root(&message, mainnet));

        // The request on a Mainnet-preset state sends the set of that version.
        let mut state = state::<Mainnet>();
        let backend = ScriptedBackend::new([Ok(true)]);
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, SEPOLIA, &backend),
            Ok(())
        );
        assert_eq!(backend.seen(), vec![set]);
        assert_eq!(state.builders.get(2).unwrap().pubkey, [0xc1; 48]);
    }

    #[test]
    fn invalid_inline_key_ignores_the_deposit() {
        // The compressed identity point fails `KeyValidate`. A backend that follows the
        // contract of `SignatureBackend` gives `Ok(false)` for it, so the deposit is ignored
        // and the request is valid.
        let mut identity = [0u8; 48];
        identity[0] = 0xc0;
        let mut request = builder_deposit_request(0xc1, 2 * ETH);
        request.pubkey = identity;
        let pre = state::<Minimal>();
        let backend = ContractBackend::new([identity]);
        let mut state = pre.clone();
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(state_root(&mut state), state_root(&mut pre.clone()));
        assert_eq!(
            backend.seen(),
            vec![builder_deposit_signature_set(
                &request,
                GENESIS_FORK_VERSION
            )]
        );
        // The same backend accepts a key that decodes.
        let request = builder_deposit_request(0xc1, 2 * ETH);
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        assert_eq!(state.builders.get(2).unwrap().pubkey, [0xc1; 48]);
    }

    #[test]
    fn builder_top_up() {
        // A known key adds the amount and asks the backend nothing: the scripted backend
        // has no verdict, so a call panics.
        let mut state = state::<Minimal>();
        let backend = ScriptedBackend::new([]);
        let mut request = builder_deposit_request(0xa2, 3 * ETH);
        // The other fields of the request are ignored for a top-up.
        request.withdrawal_credentials[12..].fill(0xee);
        request.signature = [0; 96];
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        let mut want = builder(0xa2, 8 * ETH, 0);
        assert_eq!(state.builders.get(1), Some(&want));

        // Exited with a balance: the balance grows, and the withdrawable epoch stays.
        state.builders.get_mut(1).unwrap().withdrawable_epoch = 5;
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        want.balance = 11 * ETH;
        want.withdrawable_epoch = 5;
        assert_eq!(state.builders.get(1), Some(&want));

        // Exited and swept: the withdrawable epoch is reset to the current epoch plus
        // MIN_BUILDER_WITHDRAWABILITY_DELAY, so the sweep pays the deposit out.
        state.builders.get_mut(1).unwrap().balance = 0;
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Ok(())
        );
        want.balance = 3 * ETH;
        want.withdrawable_epoch = 4 + 2;
        assert_eq!(state.builders.get(1), Some(&want));
        assert_eq!(builders(&state)[0], builder(0xa1, 5 * ETH, 0));
        assert!(backend.seen().is_empty());

        // A balance past `u64::MAX` is a `Uint64` overflow.
        let request = builder_deposit_request(0xa1, u64::MAX);
        assert_eq!(
            process_builder_deposit_request(&mut state, &request, GENESIS_FORK_VERSION, &backend),
            Err(StfError::ArithmeticOverflow)
        );
    }

    #[test]
    fn builder_deposit_needs_the_builder_prefix() {
        let pre = state::<Minimal>();
        let backend = ScriptedBackend::new([]);
        for prefix in [0x00, 0x01, 0x02, 0xb1] {
            for key in [0xa1, 0xc1] {
                let mut request = builder_deposit_request(key, ETH);
                request.withdrawal_credentials[0] = prefix;
                let mut state = pre.clone();
                assert_eq!(
                    process_builder_deposit_request(
                        &mut state,
                        &request,
                        GENESIS_FORK_VERSION,
                        &backend
                    ),
                    Ok(())
                );
                assert_eq!(builders(&state), builders(&pre), "{prefix} {key}");
            }
        }
        assert!(backend.seen().is_empty());
    }

    #[test]
    fn builder_registry_appends_and_replaces() {
        let mut state = state::<Minimal>();
        let address = Address::repeat_byte(0xd1);
        assert_eq!(
            add_builder_to_registry(&mut state, [0xd1; 48], 3, address, 4, 17),
            Ok(())
        );
        // Slot 17 is in epoch 2 of the minimal preset.
        let mut want = registered(0xd1, 4, 2);
        want.version = 3;
        assert_eq!(builders(&state).len(), 3);
        assert_eq!(state.builders.get(2), Some(&want));
        // A free index is replaced.
        state.builders.get_mut(1).unwrap().balance = 0;
        state.builders.get_mut(1).unwrap().withdrawable_epoch = 4;
        assert_eq!(
            add_builder_to_registry(&mut state, [0xd2; 48], 0, address, 6, 40),
            Ok(())
        );
        let mut want = registered(0xd2, 6, 5);
        want.execution_address = address;
        assert_eq!(builders(&state).len(), 3);
        assert_eq!(state.builders.get(1), Some(&want));
    }

    #[test]
    fn builder_exit_request_paths() {
        let pre = state::<Minimal>();
        let unchanged = |request: BuilderExitRequest, before: &BeaconState<Minimal>| {
            let mut state = before.clone();
            assert_eq!(process_builder_exit_request(&mut state, &request), Ok(()));
            assert_eq!(builders(&state), builders(before), "{request:?}");
        };

        // Success: the builder can withdraw MIN_BUILDER_WITHDRAWABILITY_DELAY epochs later.
        let mut state = pre.clone();
        assert_eq!(
            process_builder_exit_request(&mut state, &builder_exit_request(0xa2)),
            Ok(())
        );
        let mut want = builder(0xa2, 5 * ETH, 0);
        want.withdrawable_epoch = 4 + 2;
        assert_eq!(builders(&state), vec![builder(0xa1, 5 * ETH, 0), want]);

        // An unknown key and a wrong source address are ignored.
        unchanged(builder_exit_request(0xc1), &pre);
        let mut request = builder_exit_request(0xa2);
        request.source_address = Address::repeat_byte(0xa1);
        unchanged(request, &pre);

        // An inactive builder is ignored: a deposit that is not finalized, or an exit.
        let mut recent = pre.clone();
        recent.builders.get_mut(1).unwrap().deposit_epoch = 3;
        unchanged(builder_exit_request(0xa2), &recent);
        // The second exit does not move the withdrawable epoch.
        let mut later = state.clone();
        later.slot += 8;
        let mut again = later.clone();
        assert_eq!(
            process_builder_exit_request(&mut again, &builder_exit_request(0xa2)),
            Ok(())
        );
        assert_eq!(builders(&again), builders(&later));

        // A pending withdrawal or a pending payment of the builder is ignored.
        let withdrawal = BuilderPendingWithdrawal {
            fee_recipient: Address::repeat_byte(0xfe),
            amount: 1,
            builder_index: 1,
        };
        let mut pending = pre.clone();
        pending
            .builder_pending_withdrawals
            .push(withdrawal.clone())
            .unwrap();
        unchanged(builder_exit_request(0xa2), &pending);
        let mut paying = pre.clone();
        paying
            .builder_pending_payments
            .get_mut(3)
            .unwrap()
            .withdrawal = withdrawal;
        unchanged(builder_exit_request(0xa2), &paying);
        // A pending amount of another builder does not stop the exit.
        let mut state = paying;
        assert_eq!(
            process_builder_exit_request(&mut state, &builder_exit_request(0xa1)),
            Ok(())
        );
        assert_eq!(state.builders.get(0).unwrap().withdrawable_epoch, 6);
    }
}
