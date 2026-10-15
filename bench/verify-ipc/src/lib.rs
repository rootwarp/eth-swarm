//! Benchmark harness: BLS signature-set batches sent to a `cl-verify`-like
//! process over UDS (tonic gRPC and raw length-prefixed frames).

#[allow(clippy::result_large_err)] // tonic-generated: tonic::Status is large
pub mod pb {
    tonic::include_proto!("ethswarm.benchverify.v1");
}

use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use pb::sig_set::Key;
use pb::SigSet;
use rand::{Rng, RngCore};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// How a signature set names its public key on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Validator index; the server holds its own decompressed pubkey cache.
    Index,
    /// 48 B compressed pubkey inline; the server decompresses and validates.
    Inline,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    UnknownIndex(u64),
    BadPubkey,
    BadSignature,
    MissingKey,
    BadRoot,
}

/// A decoded set ready for blst.
pub struct Resolved {
    pub pk: PublicKey,
    pub sig: Signature,
    pub root: [u8; 32],
}

/// Keys and pre-signed sets for a small validator registry.
pub struct Fixture {
    pub pks: Vec<PublicKey>,
    sks: Vec<SecretKey>,
}

impl Fixture {
    pub fn new(validators: usize) -> Self {
        // Deterministic so the client and server processes agree on the registry.
        let sks: Vec<SecretKey> = (0..validators)
            .map(|i| {
                let mut ikm = [7u8; 32];
                ikm[..8].copy_from_slice(&(i as u64).to_le_bytes());
                SecretKey::key_gen(&ikm, &[]).expect("32 B ikm is always valid")
            })
            .collect();
        let pks = sks.iter().map(SecretKey::sk_to_pk).collect();
        Self { pks, sks }
    }

    /// `n` sets signed by distinct-ish validators over random roots.
    pub fn sets(&self, n: usize, mode: Mode) -> Vec<SigSet> {
        let mut rng = rand::thread_rng();
        (0..n)
            .map(|_| {
                let i = rng.gen_range(0..self.sks.len());
                let mut root = [0u8; 32];
                rng.fill_bytes(&mut root);
                let sig = self.sks[i].sign(&root, DST, &[]);
                let key = match mode {
                    Mode::Index => Key::ValidatorIndex(i as u64),
                    Mode::Inline => Key::Pubkey(self.pks[i].compress().to_vec()),
                };
                SigSet {
                    key: Some(key),
                    signing_root: root.to_vec(),
                    signature: sig.compress().to_vec(),
                }
            })
            .collect()
    }
}

/// Turns wire sets into blst objects (cache lookup or decompress + key_validate).
pub fn resolve(sets: &[SigSet], cache: &[PublicKey]) -> Result<Vec<Resolved>, ResolveError> {
    sets.iter()
        .map(|s| {
            let pk = match s.key.as_ref().ok_or(ResolveError::MissingKey)? {
                Key::ValidatorIndex(i) => cache
                    .get(*i as usize)
                    .copied()
                    .ok_or(ResolveError::UnknownIndex(*i))?,
                Key::Pubkey(b) => {
                    PublicKey::key_validate(b).map_err(|_| ResolveError::BadPubkey)?
                }
            };
            let sig = Signature::sig_validate(&s.signature, true)
                .map_err(|_| ResolveError::BadSignature)?;
            let root: [u8; 32] = s
                .signing_root
                .as_slice()
                .try_into()
                .map_err(|_| ResolveError::BadRoot)?;
            Ok(Resolved { pk, sig, root })
        })
        .collect()
}

/// blst random-linear-combination batch verify (what Lighthouse uses).
pub fn verify(sets: &[Resolved]) -> bool {
    if sets.is_empty() {
        return false;
    }
    let mut rng = rand::thread_rng();
    let rands: Vec<blst::blst_scalar> = sets
        .iter()
        .map(|_| {
            let mut s = blst::blst_scalar::default();
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b[..8]);
            b[0] |= 1; // non-zero
            unsafe { blst::blst_scalar_from_lendian(&mut s, b.as_ptr()) };
            s
        })
        .collect();
    let msgs: Vec<&[u8]> = sets.iter().map(|s| s.root.as_slice()).collect();
    let pks: Vec<&PublicKey> = sets.iter().map(|s| &s.pk).collect();
    let sigs: Vec<&Signature> = sets.iter().map(|s| &s.sig).collect();
    Signature::verify_multiple_aggregate_signatures(
        &msgs, DST, &pks, false, &sigs, false, &rands, 64,
    ) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_batches_verify_in_both_modes() {
        let f = Fixture::new(16);
        for mode in [Mode::Index, Mode::Inline] {
            let r = resolve(&f.sets(8, mode), &f.pks).expect("valid sets resolve");
            assert!(verify(&r), "{mode:?}");
        }
    }

    #[test]
    fn tampered_root_fails_batch() {
        let f = Fixture::new(16);
        let mut sets = f.sets(8, Mode::Index);
        sets[3].signing_root[0] ^= 1;
        assert!(!verify(&resolve(&sets, &f.pks).unwrap()));
    }

    #[test]
    fn resolve_errors() {
        let f = Fixture::new(4);
        let mut s = f.sets(1, Mode::Index);
        s[0].key = Some(Key::ValidatorIndex(99));
        assert_eq!(
            resolve(&s, &f.pks).err(),
            Some(ResolveError::UnknownIndex(99))
        );
        s[0].key = Some(Key::Pubkey(vec![0u8; 48]));
        assert_eq!(resolve(&s, &f.pks).err(), Some(ResolveError::BadPubkey));
        s[0].key = None;
        assert_eq!(resolve(&s, &f.pks).err(), Some(ResolveError::MissingKey));
    }
}
