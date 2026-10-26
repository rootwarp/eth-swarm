//! Model test of the builder key cache against the real Gloas state transition (minimal
//! preset).
//!
//! Random sequences of builder deposits (new keys, keys seen before, invalid proofs of
//! possession), exits, builders sweeps, epochs, forks, reorgs and finalizations run on a set of
//! branch states that descend from the last finalized state. The cache gets only finalized
//! registries, in the frames of cl-chain's builder feed, and it can lag behind finality.
//!
//! After each step:
//!
//! - Safety: for each live branch state and the finalized state, and each of its builders, a
//!   lookup with that state's key version and full key either misses or gives that builder's key
//!   at that index.
//! - No stale key: a lookup with any `(index, version, key)` that was ever in a registry (also of
//!   an abandoned branch) gives a key only if that key is the key at the index in the last fed
//!   finalized state.
//! - Liveness: each builder of the last fed finalized state resolves.

use super::{BuilderEntry, BuilderKeyCache, CompressedPubkey};
use crate::Lookup;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::BuilderIndex;
use consensus_types::{EthSpec, Minimal};
use proptest::prelude::*;
use state_transition::accessors::{builder_key_version, get_current_epoch};
use state_transition::per_block::builder::{
    process_builder_deposit_request, process_builder_exit_request,
};
use state_transition::per_block::process_withdrawals;
use state_transition::testing::{
    builder_deposit_request, builder_exit_request, registry_state, GENESIS_FORK_VERSION,
};
use state_transition::{BackendError, SignatureBackend, SignatureSet};
use std::collections::BTreeSet;

type E = Minimal;

/// The decoded key of the model: the index and the key that the feed sent for it, so that a
/// hit also shows which entry it came from.
type ModelKey = (BuilderIndex, CompressedPubkey);

/// The most branches that are live at one time.
const MAX_BRANCHES: usize = 3;
/// The builder keys of the model: `[KEY_BASE + k; 48]` for `k` in `0..KEYS`. A small pool, so
/// that keys come back at other indices.
const KEY_BASE: u8 = 0xa0;
const KEYS: u8 = 6;

/// A backend that gives one verdict for each proof of possession.
struct Verdict(bool);

impl SignatureBackend for Verdict {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Ok(self.0)
    }
}

#[derive(Clone, Debug)]
enum Op {
    /// A builder deposit request of `key` on a branch, with a valid or an invalid proof of
    /// possession (only a new registration checks it).
    Deposit { branch: usize, key: u8, valid: bool },
    /// A builder exit request of `key` on a branch.
    Exit { branch: usize, key: u8 },
    /// The builders sweep (`process_withdrawals`) on a branch.
    Sweep { branch: usize },
    /// A branch goes to the next epoch.
    NextEpoch { branch: usize },
    /// A new branch from a branch.
    Fork { branch: usize },
    /// A branch is abandoned (a reorg away from it).
    Abandon { branch: usize },
    /// A branch is finalized, and the other branches are abandoned. `feed` is false when the
    /// feed lags behind.
    Finalize { branch: usize, feed: bool },
    /// The feed catches up with the last finalized state.
    Feed,
}

fn op() -> impl Strategy<Value = Op> {
    let branch = 0..MAX_BRANCHES;
    prop_oneof![
        4 => (branch.clone(), 0..KEYS, proptest::bool::weighted(0.9))
            .prop_map(|(branch, key, valid)| Op::Deposit { branch, key, valid }),
        2 => (branch.clone(), 0..KEYS).prop_map(|(branch, key)| Op::Exit { branch, key }),
        2 => branch.clone().prop_map(|branch| Op::Sweep { branch }),
        3 => branch.clone().prop_map(|branch| Op::NextEpoch { branch }),
        1 => branch.clone().prop_map(|branch| Op::Fork { branch }),
        1 => branch.clone().prop_map(|branch| Op::Abandon { branch }),
        2 => (branch, any::<bool>()).prop_map(|(branch, feed)| Op::Finalize { branch, feed }),
        1 => Just(Op::Feed),
    ]
}

/// The feed entry of `state.builders[index]`: `(builder_key_version, pubkey)`.
fn entry_of(state: &BeaconState<E>, index: BuilderIndex) -> (u64, CompressedPubkey) {
    let pubkey = state.builders.get(index as usize).unwrap().pubkey;
    (builder_key_version(state, index).unwrap(), pubkey)
}

fn entries_of(state: &BeaconState<E>) -> Vec<(u64, CompressedPubkey)> {
    (0..state.builders.len() as u64)
        .map(|i| entry_of(state, i))
        .collect()
}

struct Model {
    /// The live branches. Each descends from `finalized`.
    branches: Vec<BeaconState<E>>,
    /// The last finalized state.
    finalized: BeaconState<E>,
    /// The registry of the last finalized state that the feed sent, as cl-chain records it.
    acked: Vec<(u64, CompressedPubkey)>,
    cache: BuilderKeyCache<ModelKey>,
    /// Each `(index, version, key)` that was ever in a registry.
    placements: BTreeSet<(BuilderIndex, u64, CompressedPubkey)>,
}

impl Model {
    fn new() -> Self {
        let state = registry_state::<E>(&[32_000_000_000; 4], Default::default());
        Self {
            branches: vec![state.clone()],
            finalized: state,
            acked: Vec::new(),
            cache: BuilderKeyCache::new(),
            placements: BTreeSet::new(),
        }
    }

    fn branch(&mut self, branch: usize) -> &mut BeaconState<E> {
        let len = self.branches.len();
        &mut self.branches[branch % len]
    }

    fn apply(&mut self, op: &Op) {
        match *op {
            Op::Deposit { branch, key, valid } => {
                let request = builder_deposit_request(KEY_BASE + key, 1_000_000_000);
                let state = self.branch(branch);
                process_builder_deposit_request(
                    state,
                    &request,
                    GENESIS_FORK_VERSION,
                    &Verdict(valid),
                )
                .unwrap();
            }
            Op::Exit { branch, key } => {
                let request = builder_exit_request(KEY_BASE + key);
                process_builder_exit_request(self.branch(branch), &request).unwrap();
            }
            Op::Sweep { branch } => process_withdrawals(self.branch(branch)).unwrap(),
            Op::NextEpoch { branch } => self.branch(branch).slot += E::slots_per_epoch(),
            Op::Fork { branch } => {
                if self.branches.len() < MAX_BRANCHES {
                    let fork = self.branch(branch).clone();
                    self.branches.push(fork);
                }
            }
            Op::Abandon { branch } => {
                if self.branches.len() > 1 {
                    let len = self.branches.len();
                    self.branches.remove(branch % len);
                }
            }
            Op::Finalize { branch, feed } => {
                let mut state = self.branch(branch).clone();
                // The checkpoint of the epoch before the head, so that the builders deposited
                // before it become active and can exit.
                let epoch = get_current_epoch(&state).saturating_sub(1);
                state.finalized_checkpoint.epoch = state.finalized_checkpoint.epoch.max(epoch);
                self.branches = vec![state.clone()];
                self.finalized = state;
                if feed {
                    self.feed();
                }
            }
            Op::Feed => self.feed(),
        }
        for state in &self.branches {
            for (i, (version, pubkey)) in entries_of(state).into_iter().enumerate() {
                self.placements.insert((i as BuilderIndex, version, pubkey));
            }
        }
    }

    /// cl-chain's builder feed (`BuilderFeed::frames`): `finalized.builders[from..]` from the
    /// first index whose acknowledged entry is not the entry of the state.
    fn feed(&mut self) {
        let entries = entries_of(&self.finalized);
        let from = entries
            .iter()
            .zip(&self.acked)
            .position(|(entry, acked)| entry != acked)
            .unwrap_or(self.acked.len().min(entries.len()));
        let frame = entries[from..]
            .iter()
            .enumerate()
            .map(|(i, (version, pubkey))| {
                BuilderEntry::new(*version, *pubkey, ((from + i) as BuilderIndex, *pubkey))
            })
            .collect();
        self.cache.append_range(from as u64, frame).unwrap();
        self.acked = entries;
    }

    fn check(&self) -> Result<(), TestCaseError> {
        // Safety: a lookup with the key of a state never gives another key.
        for state in self.branches.iter().chain([&self.finalized]) {
            for (i, (version, pubkey)) in entries_of(state).into_iter().enumerate() {
                let index = i as BuilderIndex;
                if let Lookup::Known(key) = self.cache.resolve(index, version, &pubkey) {
                    prop_assert_eq!(*key, (index, pubkey));
                }
            }
        }
        // No stale key: only the key of the last fed finalized state resolves at an index.
        for (index, version, pubkey) in &self.placements {
            if let Lookup::Known(key) = self.cache.resolve(*index, *version, pubkey) {
                prop_assert_eq!(*key, (*index, *pubkey));
                prop_assert_eq!(
                    self.acked.get(*index as usize),
                    Some(&(*version, *pubkey)),
                    "a key resolved that is not the fed finalized key at its index"
                );
            }
        }
        // Liveness: each builder of the last fed finalized state resolves.
        prop_assert_eq!(self.cache.high_water(), self.acked.len() as u64);
        for (i, (version, pubkey)) in self.acked.iter().enumerate() {
            let index = i as BuilderIndex;
            prop_assert_eq!(
                self.cache.resolve(index, *version, pubkey),
                Lookup::Known(&(index, *pubkey))
            );
        }
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Whatever the deposits, exits, sweeps, forks, reorgs and finalizations, no stale builder
    /// key resolves, and a hit is always the key of the state that is verified against.
    #[test]
    fn no_stale_builder_key_resolves(ops in proptest::collection::vec(op(), 1..48)) {
        let mut model = Model::new();
        for op in &ops {
            model.apply(op);
            model.check()?;
        }
    }
}
