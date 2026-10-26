//! The in-process BLS context of the state-transition runners, on `crypto-bls`. The
//! operations, epoch processing and sanity runners use the same one.
//!
//! - [`StateKeys`] is the one in-process [`SignatureBackend`]. It takes the validator and
//!   builder keys of one state, and resolves each [`SignerRef`] of a set to its key there.
//!   An inline key (a deposit) is in the set itself. The builder key `version` is not
//!   checked: all keys come from the same state. A key or a signature that does not decode
//!   makes the set invalid (`Ok(false)`), as the spec's `bls.Verify` and
//!   `bls.FastAggregateVerify` return `False` for it. Else, a set with a signer outside the
//!   state has no verdict (`BackendError`).
//! - [`BatchKeys`] checks all the sets of one call in one `crypto_bls::verify_batch`, and
//!   [`StateKeys::verify_each`] checks each set alone. Both give the same verdict, with the
//!   same precedence across the sets: a set that does not decode gives `Ok(false)`, else a
//!   signer outside the state gives `BackendError`.
//! - [`BlsOff`] finds every set valid, as the spec does with BLS off (`bls_setting: 2`).
//! - [`BlsAggregator`] is `eth_aggregate_pubkeys` for the next sync committee.
//! - [`bls_context`] puts a backend, the aggregator, and the `GENESIS_FORK_VERSION`, the
//!   `CAPELLA_FORK_VERSION` and the blob schedule of the preset config in one [`BlsContext`].
//! - [`bls_setting`] reads `bls_setting` from the `meta.yaml` of a case.

use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{BLSPubkey, Epoch, Root, Version};
use crypto_bls::{
    eth_aggregate_pubkeys, eth_fast_aggregate_verify, verify, verify_batch, PublicKey, Signature,
    SignatureSet as BatchSet,
};
use state_transition::{
    AggregationError, BackendError, BlobSchedule, BlsContext, Preset, PubkeyAggregator,
    SignatureBackend, SignatureSet, SignerRef,
};
use yaml_rust2::Yaml;

/// The keys of one state.
pub struct StateKeys {
    validators: Vec<BLSPubkey>,
    builders: Vec<BLSPubkey>,
}

impl StateKeys {
    /// The validator and builder keys of `state`.
    pub fn new<E: Preset>(state: &BeaconState<E>) -> Self {
        Self {
            validators: state.validators.iter().map(|v| v.pubkey).collect(),
            builders: state.builders.iter().map(|b| b.pubkey).collect(),
        }
    }

    fn key(&self, signer: &SignerRef) -> Result<BLSPubkey, BackendError> {
        let found = match signer {
            SignerRef::Validator(index) => usize::try_from(*index)
                .ok()
                .and_then(|i| self.validators.get(i)),
            SignerRef::Builder { index, .. } => usize::try_from(*index)
                .ok()
                .and_then(|i| self.builders.get(i)),
            SignerRef::Inline(pubkey) => Some(pubkey),
        };
        found
            .copied()
            .ok_or_else(|| BackendError(format!("unknown signer {signer:?}")))
    }

    /// The decoded keys and signature of `set`.
    ///
    /// A key or a signature that does not decode makes the set invalid, whatever its other
    /// signers are, as the spec's `bls.Verify` and `bls.FastAggregateVerify` return `False`
    /// for it. Thus the lookup error of a signer outside the state counts only when the
    /// available keys and the signature decode.
    fn decode(&self, set: &SignatureSet) -> Decode {
        let mut unknown = None;
        let mut keys = Vec::with_capacity(set.signers().len());
        for signer in set.signers() {
            match self.key(signer) {
                Ok(raw) => match PublicKey::from_validated_bytes(&raw) {
                    Ok(key) => keys.push(key),
                    Err(_) => return Decode::Invalid,
                },
                Err(e) => {
                    unknown.get_or_insert(e);
                }
            }
        }
        let Ok(signature) = Signature::from_validated_bytes(set.signature()) else {
            return Decode::Invalid;
        };
        match unknown {
            Some(e) => Decode::Unknown(e),
            None => Decode::Ok(Box::new(Decoded {
                keys,
                message: set.signing_root(),
                signature,
            })),
        }
    }

    /// The decoded sets of `sets`. `Ok(None)` if a set does not decode, and then the other
    /// sets do not matter. Else `Err` if a set has a signer outside the state.
    fn decode_all(&self, sets: &[SignatureSet]) -> Result<Option<Vec<Decoded>>, BackendError> {
        let mut decoded = Vec::with_capacity(sets.len());
        let mut unknown = None;
        for set in sets {
            match self.decode(set) {
                Decode::Ok(set) => decoded.push(*set),
                Decode::Invalid => return Ok(None),
                Decode::Unknown(e) => {
                    unknown.get_or_insert(e);
                }
            }
        }
        match unknown {
            Some(e) => Err(e),
            None => Ok(Some(decoded)),
        }
    }

    fn verify_set(&self, set: &SignatureSet) -> Result<bool, BackendError> {
        match self.decode(set) {
            Decode::Ok(set) => Ok(set.verify()),
            Decode::Invalid => Ok(false),
            Decode::Unknown(e) => Err(e),
        }
    }

    /// The verdict of each set alone: `Ok(false)` if a set does not decode, else `Err` if a
    /// set has a signer outside the state, else `Ok(true)` only if every set is valid. Each
    /// set gets its own check, so the order of the sets does not change the verdict.
    /// [`BatchKeys`] gives the same verdict in one batch.
    pub fn verify_each(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        let Some(decoded) = self.decode_all(sets)? else {
            return Ok(false);
        };
        let mut valid = true;
        for set in &decoded {
            valid &= set.verify();
        }
        Ok(valid)
    }
}

/// The result of the decode of one set.
enum Decode {
    /// The keys and the signature decode, and every signer is in the state.
    Ok(Box<Decoded>),
    /// A key or the signature does not decode: the set is invalid.
    Invalid,
    /// The keys and the signature that are available decode, but a signer is not in the
    /// state: the set has no verdict.
    Unknown(BackendError),
}

/// The keys, the message and the signature of one set, decoded.
struct Decoded {
    keys: Vec<PublicKey>,
    message: Root,
    signature: Signature,
}

impl Decoded {
    /// `bls.Verify` for one key, else `eth_fast_aggregate_verify`.
    fn verify(&self) -> bool {
        let message = self.message.as_slice();
        match self.keys.as_slice() {
            [key] => verify(key, message, &self.signature),
            many => {
                let refs: Vec<&PublicKey> = many.iter().collect();
                eth_fast_aggregate_verify(&refs, message, &self.signature)
            }
        }
    }
}

/// The keys of one state, checked in one `crypto_bls::verify_batch` call: a random linear
/// combination of all the sets with 64-bit non-zero randomizers, as cl-verify checks the
/// sets of a block. A key or a signature that does not decode makes the batch invalid
/// (`Ok(false)`). Else, a signer outside the state gives `BackendError`, as for
/// [`StateKeys::verify_each`]. No sets is valid, as for [`StateKeys`].
pub struct BatchKeys<'a>(pub &'a StateKeys);

impl SignatureBackend for BatchKeys<'_> {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        let Some(decoded) = self.0.decode_all(sets)? else {
            return Ok(false);
        };
        if decoded.is_empty() {
            return Ok(true);
        }
        let keys: Vec<Vec<&PublicKey>> = decoded.iter().map(|d| d.keys.iter().collect()).collect();
        let batch: Vec<BatchSet> = decoded
            .iter()
            .zip(&keys)
            .map(|(d, keys)| BatchSet {
                public_keys: keys,
                message: d.message.as_slice(),
                signature: &d.signature,
            })
            .collect();
        verify_batch(&batch).map_err(|e| BackendError(format!("verify_batch: {e}")))
    }
}

impl SignatureBackend for StateKeys {
    fn verify_signature_sets(&self, sets: &[SignatureSet]) -> Result<bool, BackendError> {
        for set in sets {
            if !self.verify_set(set)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A [`SignatureBackend`] with BLS off: every set is valid, as `bls.Verify` is with
/// `bls_active` false. It is for the vectors with `bls_setting: 2` only.
pub struct BlsOff;

impl SignatureBackend for BlsOff {
    fn verify_signature_sets(&self, _: &[SignatureSet]) -> Result<bool, BackendError> {
        Ok(true)
    }
}

/// A [`PubkeyAggregator`] on `crypto_bls::eth_aggregate_pubkeys`.
pub struct BlsAggregator;

impl PubkeyAggregator for BlsAggregator {
    fn aggregate_pubkeys(&self, pubkeys: &[BLSPubkey]) -> Result<BLSPubkey, AggregationError> {
        let keys = pubkeys
            .iter()
            .map(PublicKey::from_validated_bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AggregationError(e.to_string()))?;
        let refs: Vec<&PublicKey> = keys.iter().collect();
        eth_aggregate_pubkeys(&refs)
            .map(|sum| sum.to_bytes())
            .map_err(|e| AggregationError(e.to_string()))
    }
}

/// `GENESIS_FORK_VERSION` of the spec config of `preset`: `configs/minimal.yaml` L27 and
/// `configs/mainnet.yaml` L30 at v1.7.0-beta.4, the configs of the vectors.
pub fn genesis_fork_version(preset: &str) -> Result<Version, String> {
    match preset {
        "minimal" => Ok([0x00, 0x00, 0x00, 0x01]),
        "mainnet" => Ok([0x00, 0x00, 0x00, 0x00]),
        other => Err(format!("no GENESIS_FORK_VERSION for preset {other}")),
    }
}

/// `CAPELLA_FORK_VERSION` of the spec config of `preset`: `configs/minimal.yaml` L43 and
/// `configs/mainnet.yaml` L47 at v1.7.0-beta.4. It is the domain of the voluntary exits
/// (EIP-7044).
pub fn capella_fork_version(preset: &str) -> Result<Version, String> {
    match preset {
        "minimal" => Ok([0x03, 0x00, 0x00, 0x01]),
        "mainnet" => Ok([0x03, 0x00, 0x00, 0x00]),
        other => Err(format!("no CAPELLA_FORK_VERSION for preset {other}")),
    }
}

/// `MAX_BLOBS_PER_BLOCK_ELECTRA` of `configs/minimal.yaml` (L201) and
/// `configs/mainnet.yaml` (L204) at v1.7.0-beta.4: the limit before the first
/// `BLOB_SCHEDULE` entry.
const MAX_BLOBS_PER_BLOCK_ELECTRA: u64 = 9;

/// `get_blob_parameters(epoch).max_blobs_per_block` (`fulu/beacon-chain.md` L293-300) of
/// `configs/minimal.yaml`: its `BLOB_SCHEDULE` is empty (L239).
fn minimal_max_blobs_per_block(_: Epoch) -> u64 {
    MAX_BLOBS_PER_BLOCK_ELECTRA
}

/// `get_blob_parameters(epoch).max_blobs_per_block` of `configs/mainnet.yaml`: the
/// `BLOB_SCHEDULE` (L242-246) has 15 blobs from epoch 412672 and 21 from epoch 419072.
fn mainnet_max_blobs_per_block(epoch: Epoch) -> u64 {
    match epoch {
        419_072.. => 21,
        412_672.. => 15,
        _ => MAX_BLOBS_PER_BLOCK_ELECTRA,
    }
}

/// The blob schedule of the spec config of `preset`, the config of the vectors.
pub fn blob_schedule(preset: &str) -> Result<&'static dyn BlobSchedule, String> {
    match preset {
        "minimal" => Ok(&minimal_max_blobs_per_block),
        "mainnet" => Ok(&mainnet_max_blobs_per_block),
        other => Err(format!("no BLOB_SCHEDULE for preset {other}")),
    }
}

/// The context of the vectors of `preset`: `backend`, [`BlsAggregator`], and the
/// [`genesis_fork_version`], the [`capella_fork_version`] and the [`blob_schedule`] of the
/// preset.
pub fn bls_context<'a>(
    preset: &str,
    backend: &'a dyn SignatureBackend,
) -> Result<BlsContext<'a>, String> {
    Ok(BlsContext {
        backend,
        aggregator: &BlsAggregator,
        genesis_fork_version: genesis_fork_version(preset)?,
        capella_fork_version: capella_fork_version(preset)?,
        blob_schedule: blob_schedule(preset)?,
    })
}

/// What `meta.yaml` says about the signatures (`bls_setting`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bls {
    /// 0 (or no `meta.yaml`): optional, and checked here. 1: required.
    Check,
    /// 2: the vector has no valid signatures. The BLS checks do not run, as in the spec with
    /// BLS off. The checks that need no BLS still run, and one of them is stricter than the
    /// spec: an empty sync aggregate must have the infinity signature. With BLS off,
    /// `eth_fast_aggregate_verify` (`altair/bls.md` L58-66) calls `bls.FastAggregateVerify`,
    /// which returns True, so the spec accepts an empty aggregate with any signature. This
    /// runner rejects it. No vector at v1.7.0-beta.4 has this case.
    Ignore,
}

/// The `bls_setting` of the `meta.yaml` of `case`. An unknown value fails the case.
pub fn bls_setting(reads: &Reads, case: &Case) -> Result<Bls, String> {
    let Some(path) = case.file("meta.yaml") else {
        return Ok(Bls::Check);
    };
    let meta = fixture::load(reads, path)?;
    match &meta["bls_setting"] {
        Yaml::BadValue | Yaml::Integer(0 | 1) => Ok(Bls::Check),
        Yaml::Integer(2) => Ok(Bls::Ignore),
        other => Err(format!("meta.yaml: unknown bls_setting {other:?}")),
    }
}

/// The backend of `bls`: `keys` for [`Bls::Check`], [`BlsOff`] for [`Bls::Ignore`].
pub fn backend_for(bls: Bls, keys: &StateKeys) -> &dyn SignatureBackend {
    match bls {
        Bls::Check => keys,
        Bls::Ignore => &BlsOff,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crypto_bls::{aggregate_signatures, sign, G2_POINT_AT_INFINITY};

    /// The compressed G1 generator: the public key of the secret key 1.
    pub(crate) const PUBKEY_1: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    /// A big-endian 32-byte secret key `n`.
    pub(crate) fn secret(n: u8) -> [u8; 32] {
        let mut sk = [0u8; 32];
        sk[31] = n;
        sk
    }

    /// One validator and one builder, both with the key of the secret key 1.
    fn keys() -> StateKeys {
        let pubkey: BLSPubkey = hex::decode(PUBKEY_1).unwrap().try_into().unwrap();
        StateKeys {
            validators: vec![pubkey],
            builders: vec![pubkey],
        }
    }

    #[test]
    fn verifies_single_and_aggregate_sets() {
        let keys = keys();
        let root = Root::repeat_byte(5);
        let sig = |i: u8| sign(&secret(i), root.as_slice()).unwrap();
        let single = SignatureSet::single(SignerRef::Validator(0), root, sig(1).to_bytes());
        let builder = SignatureSet::single(
            SignerRef::Builder {
                index: 0,
                version: 0,
            },
            root,
            sig(1).to_bytes(),
        );
        let inline = SignatureSet::single(
            SignerRef::Inline(keys.validators[0]),
            root,
            sig(1).to_bytes(),
        );
        // A duplicate signer counts twice, as a sync committee member in two positions.
        let twice = aggregate_signatures(&[&sig(1), &sig(1)]).unwrap();
        let both = SignatureSet::aggregate(
            vec![SignerRef::Validator(0), SignerRef::Validator(0)],
            root,
            twice.to_bytes(),
        )
        .unwrap();
        assert_eq!(
            keys.verify_signature_sets(&[single, builder, inline, both]),
            Ok(true)
        );

        // A wrong signer, an undecodable signature or key, and an unknown signer.
        let wrong = SignatureSet::single(SignerRef::Validator(0), root, sig(2).to_bytes());
        assert_eq!(keys.verify_signature_sets(&[wrong]), Ok(false));
        let once = SignatureSet::aggregate(
            vec![SignerRef::Validator(0), SignerRef::Validator(0)],
            root,
            sig(1).to_bytes(),
        )
        .unwrap();
        assert_eq!(keys.verify_signature_sets(&[once]), Ok(false));
        let garbage = SignatureSet::single(SignerRef::Validator(0), root, [0x01; 96]);
        assert_eq!(keys.verify_signature_sets(&[garbage]), Ok(false));
        let bad_key = SignatureSet::single(SignerRef::Inline([0x01; 48]), root, sig(1).to_bytes());
        assert_eq!(keys.verify_signature_sets(&[bad_key]), Ok(false));
        let infinity = SignatureSet::single(SignerRef::Validator(0), root, G2_POINT_AT_INFINITY);
        assert_eq!(keys.verify_signature_sets(&[infinity]), Ok(false));
        for signer in [
            SignerRef::Validator(1),
            SignerRef::Builder {
                index: 1,
                version: 0,
            },
        ] {
            let unknown = SignatureSet::single(signer, root, sig(1).to_bytes());
            assert!(keys.verify_signature_sets(&[unknown]).is_err());
        }
    }

    #[test]
    fn a_batch_gives_the_verdict_of_each_set_alone() {
        let keys = keys();
        let root = Root::repeat_byte(6);
        let sig = |i: u8| sign(&secret(i), root.as_slice()).unwrap();
        let twice = aggregate_signatures(&[&sig(1), &sig(1)]).unwrap();
        let valid = [
            SignatureSet::single(SignerRef::Validator(0), root, sig(1).to_bytes()),
            SignatureSet::single(
                SignerRef::Builder {
                    index: 0,
                    version: 0,
                },
                root,
                sig(1).to_bytes(),
            ),
            SignatureSet::aggregate(
                vec![SignerRef::Validator(0), SignerRef::Validator(0)],
                root,
                twice.to_bytes(),
            )
            .unwrap(),
        ];
        let invalid = [
            // A wrong signer, an undecodable signature, the infinity signature and an
            // undecodable key.
            SignatureSet::single(SignerRef::Validator(0), root, sig(2).to_bytes()),
            SignatureSet::single(SignerRef::Validator(0), root, [0x01; 96]),
            SignatureSet::single(SignerRef::Validator(0), root, G2_POINT_AT_INFINITY),
            SignatureSet::single(SignerRef::Inline([0x01; 48]), root, sig(1).to_bytes()),
        ];
        let unknown = SignatureSet::single(SignerRef::Validator(1), root, sig(1).to_bytes());
        let batch = BatchKeys(&keys);
        assert_eq!(batch.verify_signature_sets(&[]), Ok(true));
        assert_eq!(keys.verify_each(&[]), Ok(true));
        assert_eq!(batch.verify_signature_sets(&valid), Ok(true));
        // The sets that do not decode: an undecodable signature and an undecodable key. The
        // wrong signer and the infinity signature decode.
        let undecodable = [&invalid[1], &invalid[3]];
        for bad in &invalid {
            // The invalid set at each position of the batch.
            for at in 0..=valid.len() {
                let mut sets = valid.to_vec();
                sets.insert(at, bad.clone());
                assert_eq!(batch.verify_signature_sets(&sets), Ok(false), "{bad:?}");
                assert_eq!(keys.verify_each(&sets), Ok(false), "{bad:?}");
            }
            // With an unknown signer in another set, a set that does not decode is invalid
            // whatever the unknown key is. A set that decodes gives no verdict.
            for sets in [
                [bad.clone(), unknown.clone()],
                [unknown.clone(), bad.clone()],
            ] {
                if undecodable.contains(&bad) {
                    assert_eq!(batch.verify_signature_sets(&sets), Ok(false), "{bad:?}");
                    assert_eq!(keys.verify_each(&sets), Ok(false), "{bad:?}");
                } else {
                    assert!(batch.verify_signature_sets(&sets).is_err());
                    assert!(keys.verify_each(&sets).is_err());
                }
            }
        }
        // A key that does not decode and an unknown signer in one set, in both orders: the
        // set is invalid, not without a verdict.
        for signers in [
            vec![SignerRef::Inline([0x01; 48]), SignerRef::Validator(1)],
            vec![SignerRef::Validator(1), SignerRef::Inline([0x01; 48])],
        ] {
            let set = SignatureSet::aggregate(signers, root, sig(1).to_bytes()).unwrap();
            let sets = std::slice::from_ref(&set);
            assert_eq!(batch.verify_signature_sets(sets), Ok(false), "{set:?}");
            assert_eq!(keys.verify_each(sets), Ok(false), "{set:?}");
            assert_eq!(keys.verify_signature_sets(sets), Ok(false), "{set:?}");
        }
        // A signature that does not decode and an unknown signer: also invalid.
        let set = SignatureSet::single(SignerRef::Validator(1), root, [0x01; 96]);
        let sets = std::slice::from_ref(&set);
        assert_eq!(batch.verify_signature_sets(sets), Ok(false));
        assert_eq!(keys.verify_each(sets), Ok(false));
        // An unknown signer with a key and a signature that decode gives no verdict.
        let set = SignatureSet::aggregate(
            vec![SignerRef::Validator(0), SignerRef::Validator(1)],
            root,
            sig(1).to_bytes(),
        )
        .unwrap();
        let sets = std::slice::from_ref(&set);
        assert!(batch.verify_signature_sets(sets).is_err());
        assert!(keys.verify_each(sets).is_err());
        assert_eq!(keys.verify_each(&valid), Ok(true));
    }

    #[test]
    fn aggregation_and_the_genesis_fork_versions() {
        let key: BLSPubkey = hex::decode(PUBKEY_1).unwrap().try_into().unwrap();
        // One key is its own sum.
        assert_eq!(BlsAggregator.aggregate_pubkeys(&[key]), Ok(key));
        assert_ne!(BlsAggregator.aggregate_pubkeys(&[key, key]), Ok(key));
        assert!(BlsAggregator.aggregate_pubkeys(&[]).is_err());
        assert!(BlsAggregator.aggregate_pubkeys(&[key, [0x01; 48]]).is_err());
        // GENESIS_FORK_VERSION of configs/minimal.yaml (L27) and configs/mainnet.yaml (L30).
        assert_eq!(genesis_fork_version("minimal"), Ok([0, 0, 0, 1]));
        assert_eq!(genesis_fork_version("mainnet"), Ok([0, 0, 0, 0]));
        assert!(genesis_fork_version("general").is_err());
        // CAPELLA_FORK_VERSION of configs/minimal.yaml (L43) and configs/mainnet.yaml (L47).
        assert_eq!(capella_fork_version("minimal"), Ok([3, 0, 0, 1]));
        assert_eq!(capella_fork_version("mainnet"), Ok([3, 0, 0, 0]));
        assert!(capella_fork_version("general").is_err());
        let keys = keys();
        let bls = bls_context("minimal", &keys).unwrap();
        assert_eq!(bls.genesis_fork_version, [0, 0, 0, 1]);
        assert_eq!(bls.capella_fork_version, [3, 0, 0, 1]);
        let bls = bls_context("mainnet", &keys).unwrap();
        assert_eq!(
            (bls.genesis_fork_version, bls.capella_fork_version),
            ([0, 0, 0, 0], [3, 0, 0, 0])
        );
        assert!(bls_context("general", &keys).is_err());
        // The blob schedules of configs/minimal.yaml and configs/mainnet.yaml.
        let minimal = blob_schedule("minimal").unwrap();
        assert_eq!(minimal.max_blobs_per_block(0), 9);
        assert_eq!(minimal.max_blobs_per_block(u64::MAX), 9);
        let mainnet = blob_schedule("mainnet").unwrap();
        for (epoch, max) in [
            (0, 9),
            (412_671, 9),
            (412_672, 15),
            (419_071, 15),
            (419_072, 21),
        ] {
            assert_eq!(mainnet.max_blobs_per_block(epoch), max, "{epoch}");
        }
        assert!(blob_schedule("general").is_err());
        // BLS off finds an invalid set valid, and `backend_for` selects it for setting 2.
        let garbage = SignatureSet::single(SignerRef::Inline([0x01; 48]), Root::ZERO, [0x01; 96]);
        let sets = std::slice::from_ref(&garbage);
        assert_eq!(BlsOff.verify_signature_sets(sets), Ok(true));
        assert_eq!(
            backend_for(Bls::Ignore, &keys).verify_signature_sets(sets),
            Ok(true)
        );
        assert_eq!(
            backend_for(Bls::Check, &keys).verify_signature_sets(sets),
            Ok(false)
        );
    }
}
