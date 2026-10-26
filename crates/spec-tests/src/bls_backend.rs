//! An in-process [`SignatureBackend`] on `crypto-bls`, for the state-transition runners.
//!
//! [`StateKeys`] takes the validator and builder keys of one state, and resolves each
//! [`SignerRef`] of a set to its key there. The builder key `version` is not checked: all
//! keys come from the same state. A set with a signer outside the state has no verdict
//! (`BackendError`). A key or a signature that does not decode makes the set invalid, as the
//! spec's `bls.Verify` and `bls.FastAggregateVerify` return `False` for it.

use consensus_types::gloas::BeaconState;
use consensus_types::primitives::BLSPubkey;
use crypto_bls::{eth_fast_aggregate_verify, verify, PublicKey, Signature};
use state_transition::{BackendError, Preset, SignatureBackend, SignatureSet, SignerRef};

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
}
