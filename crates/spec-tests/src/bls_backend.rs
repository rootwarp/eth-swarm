//! The in-process BLS context of the state-transition runners, on `crypto-bls`. The
//! operations, epoch processing and sanity runners use the same one.
//!
//! - [`StateKeys`] is the one in-process [`SignatureBackend`]. It takes the validator and
//!   builder keys of one state, and resolves each [`SignerRef`] of a set to its key there.
//!   An inline key (a deposit) is in the set itself. The builder key `version` is not
//!   checked: all keys come from the same state. A set with a signer outside the state has
//!   no verdict (`BackendError`). A key or a signature that does not decode makes the set
//!   invalid (`Ok(false)`), as the spec's `bls.Verify` and `bls.FastAggregateVerify` return
//!   `False` for it.
//! - [`BlsOff`] finds every set valid, as the spec does with BLS off (`bls_setting: 2`).
//! - [`BlsAggregator`] is `eth_aggregate_pubkeys` for the next sync committee.
//! - [`bls_context`] puts a backend, the aggregator and the `GENESIS_FORK_VERSION` of the
//!   preset config in one [`BlsContext`].
//! - [`bls_setting`] reads `bls_setting` from the `meta.yaml` of a case.

use crate::coverage::Reads;
use crate::fixture;
use crate::plan::Case;
use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{BLSPubkey, Version};
use crypto_bls::{eth_aggregate_pubkeys, eth_fast_aggregate_verify, verify, PublicKey, Signature};
use state_transition::{
    AggregationError, BackendError, BlsContext, Preset, PubkeyAggregator, SignatureBackend,
    SignatureSet, SignerRef,
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

    fn verify_set(&self, set: &SignatureSet) -> Result<bool, BackendError> {
        let mut keys = Vec::with_capacity(set.signers().len());
        for signer in set.signers() {
            match PublicKey::from_validated_bytes(&self.key(signer)?) {
                Ok(key) => keys.push(key),
                Err(_) => return Ok(false),
            }
        }
        let Ok(signature) = Signature::from_validated_bytes(set.signature()) else {
            return Ok(false);
        };
        let message = set.signing_root();
        Ok(match keys.as_slice() {
            [key] => verify(key, message.as_slice(), &signature),
            many => {
                let refs: Vec<&PublicKey> = many.iter().collect();
                eth_fast_aggregate_verify(&refs, message.as_slice(), &signature)
            }
        })
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

/// The context of the vectors of `preset`: `backend`, [`BlsAggregator`] and the
/// [`genesis_fork_version`] of the preset.
pub fn bls_context<'a>(
    preset: &str,
    backend: &'a dyn SignatureBackend,
) -> Result<BlsContext<'a>, String> {
    Ok(BlsContext {
        backend,
        aggregator: &BlsAggregator,
        genesis_fork_version: genesis_fork_version(preset)?,
    })
}

/// What `meta.yaml` says about the signatures (`bls_setting`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bls {
    /// 0 (or no `meta.yaml`): optional, and checked here. 1: required.
    Check,
    /// 2: the vector has no valid signatures. The BLS checks do not run (every signature is
    /// valid, as in the spec with BLS off), but the checks that need no BLS (the infinity
    /// signature of an empty sync aggregate) still run.
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
mod tests {
    use super::*;
    use consensus_types::primitives::Root;
    use crypto_bls::{aggregate_signatures, sign, G2_POINT_AT_INFINITY};

    /// The compressed G1 generator: the public key of the secret key 1.
    const PUBKEY_1: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    /// A big-endian 32-byte secret key `n`.
    fn secret(n: u8) -> [u8; 32] {
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
        let keys = keys();
        let bls = bls_context("minimal", &keys).unwrap();
        assert_eq!(bls.genesis_fork_version, [0, 0, 0, 1]);
        assert!(bls_context("general", &keys).is_err());
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
