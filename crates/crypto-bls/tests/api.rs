//! Public API of `crypto-bls`: validated-bytes constructors and the `eth_*` edge rules.
//!
//! Key material comes from blst directly, so every non-empty result can be checked against the
//! library the wrapper delegates to.

use crypto_bls::{Error, PublicKey, Signature, G2_POINT_AT_INFINITY};
use std::path::PathBuf;

/// One `deserialization_G1`/`deserialization_G2` case: the encoded point and the `output` flag.
struct DeserializationCase {
    bytes: Vec<u8>,
    decodes: bool,
}

/// Reads a vendored bls12-381-tests case. The files are one-line YAML maps
/// (`input: {pubkey: <hex>}` / `output: <bool>`), so a full YAML parser is not needed.
fn fixture(case: &str) -> DeserializationCase {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bls12-381-tests-v0.1.2")
        .join(format!("{case}.yaml"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    let field = |prefix: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("{path:?}: no `{prefix}` line"))
    };
    let input = field("input: {").trim_end_matches('}');
    let (_, value) = input.split_once(": ").expect("input is `key: value`");
    let bytes = hex::decode(value.trim_matches('\'')).expect("hex input");
    let decodes = match field("output: ") {
        "true" => true,
        "false" => false,
        other => panic!("{path:?}: output {other:?}"),
    };
    DeserializationCase { bytes, decodes }
}

fn g1(case: &str) -> ([u8; 48], bool) {
    let c = fixture(&format!("deserialization_G1/{case}"));
    (c.bytes.try_into().expect("48-byte pubkey"), c.decodes)
}

fn g2(case: &str) -> ([u8; 96], bool) {
    let c = fixture(&format!("deserialization_G2/{case}"));
    (c.bytes.try_into().expect("96-byte signature"), c.decodes)
}

fn secret_key(seed: u8) -> blst::min_pk::SecretKey {
    blst::min_pk::SecretKey::key_gen(&[seed; 32], &[]).expect("32-byte ikm")
}

fn public_key(seed: u8) -> PublicKey {
    let bytes = secret_key(seed).sk_to_pk().to_bytes();
    PublicKey::from_validated_bytes(&bytes).expect("generated key validates")
}

#[cfg(any(feature = "verify", feature = "test-vectors"))]
fn sign(seeds: &[u8], message: &[u8]) -> Signature {
    let sigs: Vec<_> = seeds
        .iter()
        .map(|&s| secret_key(s).sign(message, crypto_bls::DST, &[]))
        .collect();
    let refs: Vec<_> = sigs.iter().collect();
    let aggregate = blst::min_pk::AggregateSignature::aggregate(&refs, false).expect("non-empty");
    Signature::from_validated_bytes(&aggregate.to_signature().to_bytes())
        .expect("generated signature validates")
}

#[test]
fn rejects_infinity_and_non_subgroup() {
    // The identity decodes as a point but fails KeyValidate.
    let (infinity, decodes) = g1("deserialization_succeeds_infinity_with_true_b_flag");
    assert!(decodes, "fixture: the identity is a decodable G1 point");
    assert_eq!(
        PublicKey::from_validated_bytes(&infinity),
        Err(Error::PublicKeyIsInfinity)
    );

    // On the curve, outside the prime-order subgroup: plain decoding accepts it, we must not.
    let (off_subgroup, decodes) = g1("deserialization_fails_not_in_G1");
    assert!(!decodes);
    assert!(blst::min_pk::PublicKey::from_bytes(&off_subgroup).is_ok());
    assert_eq!(
        PublicKey::from_validated_bytes(&off_subgroup),
        Err(Error::PointNotInGroup)
    );

    let (off_subgroup, decodes) = g2("deserialization_fails_not_in_G2");
    assert!(!decodes);
    assert!(blst::min_pk::Signature::from_bytes(&off_subgroup).is_ok());
    assert_eq!(
        Signature::from_validated_bytes(&off_subgroup),
        Err(Error::PointNotInGroup)
    );
}

#[test]
fn accepts_subgroup_points_and_round_trips() {
    let (bytes, decodes) = g1("deserialization_succeeds_correct_point");
    assert!(decodes);
    let pk = PublicKey::from_validated_bytes(&bytes).expect("valid pubkey");
    assert_eq!(pk.to_bytes(), bytes);

    let (bytes, decodes) = g2("deserialization_succeeds_correct_point");
    assert!(decodes);
    let sig = Signature::from_validated_bytes(&bytes).expect("valid signature");
    assert_eq!(sig.to_bytes(), bytes);

    // The G2 identity is a valid signature encoding (G2_POINT_AT_INFINITY).
    let (bytes, decodes) = g2("deserialization_succeeds_infinity_with_true_b_flag");
    assert!(decodes);
    assert_eq!(bytes, G2_POINT_AT_INFINITY);
    let sig = Signature::from_validated_bytes(&bytes).expect("identity signature");
    assert_eq!(sig.to_bytes(), G2_POINT_AT_INFINITY);
}

#[test]
fn rejects_bad_encodings() {
    // Compression flag cleared: not a valid 48/96-byte encoding.
    let (mut pk, _) = g1("deserialization_succeeds_correct_point");
    pk[0] &= 0x7f;
    assert_eq!(
        PublicKey::from_validated_bytes(&pk),
        Err(Error::BadEncoding)
    );
    let (mut sig, _) = g2("deserialization_succeeds_correct_point");
    sig[0] &= 0x7f;
    assert_eq!(
        Signature::from_validated_bytes(&sig),
        Err(Error::BadEncoding)
    );
}

#[test]
fn debug_prints_the_encoding() {
    let pk = public_key(1);
    assert_eq!(
        format!("{pk:?}"),
        format!("PublicKey(0x{})", hex::encode(pk.to_bytes()))
    );
    let sig = Signature::from_validated_bytes(&G2_POINT_AT_INFINITY).unwrap();
    assert_eq!(
        format!("{sig:?}"),
        format!("Signature(0x{})", hex::encode(G2_POINT_AT_INFINITY))
    );
}

#[cfg(feature = "verify")]
mod verify {
    use super::*;
    use crypto_bls::{eth_fast_aggregate_verify, verify, verify_batch, SignatureSet, DST};

    const MESSAGE: &[u8; 32] = &[0xab; 32];

    fn blst_fast_aggregate_verify(pks: &[&PublicKey], message: &[u8], sig: &Signature) -> bool {
        let pks: Vec<_> = pks
            .iter()
            .map(|pk| blst::min_pk::PublicKey::from_bytes(&pk.to_bytes()).unwrap())
            .collect();
        let refs: Vec<_> = pks.iter().collect();
        let sig = blst::min_pk::Signature::from_bytes(&sig.to_bytes()).unwrap();
        sig.fast_aggregate_verify(true, message, DST, &refs) == blst::BLST_ERROR::BLST_SUCCESS
    }

    #[test]
    fn verify_single() {
        let pk = public_key(1);
        let sig = sign(&[1], MESSAGE);
        assert!(verify(&pk, MESSAGE, &sig));
        assert!(!verify(&pk, &[0xcd; 32], &sig));
        assert!(!verify(&public_key(2), MESSAGE, &sig));
        let infinity = Signature::from_validated_bytes(&G2_POINT_AT_INFINITY).unwrap();
        assert!(!verify(&pk, MESSAGE, &infinity));
    }

    #[test]
    fn eth_fast_aggregate_verify_empty() {
        let infinity = Signature::from_validated_bytes(&G2_POINT_AT_INFINITY).unwrap();
        assert!(eth_fast_aggregate_verify(&[], MESSAGE, &infinity));
        assert!(!eth_fast_aggregate_verify(
            &[],
            MESSAGE,
            &sign(&[1], MESSAGE)
        ));
        let (bytes, _) = g2("deserialization_succeeds_correct_point");
        let other = Signature::from_validated_bytes(&bytes).unwrap();
        assert!(!eth_fast_aggregate_verify(&[], MESSAGE, &other));

        // Non-empty sets: same answer as blst's FastAggregateVerify.
        let (a, b, c) = (public_key(1), public_key(2), public_key(3));
        let sig_ab = sign(&[1, 2], MESSAGE);
        let cases: [(&[&PublicKey], &[u8], &Signature, bool); 6] = [
            (&[&a, &b], MESSAGE, &sig_ab, true),
            (&[&b, &a], MESSAGE, &sig_ab, true),
            (&[&a], MESSAGE, &sig_ab, false),
            (&[&a, &b, &c], MESSAGE, &sig_ab, false),
            (&[&a, &b], &[0xcd; 32], &sig_ab, false),
            (&[&a, &b], MESSAGE, &infinity, false),
        ];
        for (i, (pks, message, sig, expected)) in cases.into_iter().enumerate() {
            let ours = eth_fast_aggregate_verify(pks, message, sig);
            assert_eq!(ours, expected, "case {i}");
            assert_eq!(
                ours,
                blst_fast_aggregate_verify(pks, message, sig),
                "case {i}"
            );
        }
    }

    /// `S + D` for a signature `S` and a G2 point `D` (blst addition, then revalidated).
    fn add(sig: &Signature, d: &[u8; 96]) -> Signature {
        let a = blst::min_pk::Signature::from_bytes(&sig.to_bytes()).unwrap();
        let b = blst::min_pk::Signature::from_bytes(d).unwrap();
        let sum = blst::min_pk::AggregateSignature::aggregate(&[&a, &b], true).unwrap();
        Signature::from_validated_bytes(&sum.to_signature().to_bytes()).unwrap()
    }

    /// The compressed encoding of `-X`: negation flips the y-sign flag.
    fn negated<const N: usize>(mut bytes: [u8; N]) -> [u8; N] {
        bytes[0] ^= 0x20;
        bytes
    }

    #[test]
    fn verify_batch_edges() {
        assert_eq!(verify_batch(&[]), Err(Error::EmptyInput));

        let pks: Vec<_> = (0..64u8).map(public_key).collect();
        let messages: Vec<[u8; 32]> = (0..64u8).map(|i| [i; 32]).collect();
        let mut sigs: Vec<_> = (0..64u8)
            .map(|i| sign(&[i], &messages[i as usize]))
            .collect();
        let keys: Vec<[&PublicKey; 1]> = pks.iter().map(|pk| [pk]).collect();
        fn zip<'a>(
            keys: &'a [[&'a PublicKey; 1]],
            messages: &'a [[u8; 32]],
            sigs: &'a [Signature],
        ) -> Vec<SignatureSet<'a>> {
            (0..sigs.len())
                .map(|i| SignatureSet {
                    public_keys: &keys[i],
                    message: &messages[i],
                    signature: &sigs[i],
                })
                .collect()
        }

        // A set with no signers is malformed, not merely invalid.
        let mut no_signers = zip(&keys, &messages, &sigs);
        no_signers[5].public_keys = &[];
        assert_eq!(verify_batch(&no_signers), Err(Error::EmptyInput));

        assert_eq!(verify_batch(&zip(&keys, &messages, &sigs)), Ok(true));
        assert_eq!(verify_batch(&zip(&keys, &messages, &sigs)[..1]), Ok(true));

        // A valid key with the infinity signature: blst skips the identity signature, so only
        // the key's pairing decides, and it must fail.
        let infinity = Signature::from_validated_bytes(&G2_POINT_AT_INFINITY).unwrap();
        let mut with_infinity = zip(&keys, &messages, &sigs);
        with_infinity[9].signature = &infinity;
        assert_eq!(verify_batch(&with_infinity), Ok(false));

        // One set signed over the wrong message sinks the whole batch.
        sigs[41] = sign(&[41], &messages[40]);
        assert_eq!(verify_batch(&zip(&keys, &messages, &sigs)), Ok(false));
    }

    #[test]
    fn verify_batch_multi_signer_sets() {
        let (a, b, c) = (public_key(1), public_key(2), public_key(3));
        let (ab, only_a, only_c) = ([&a, &b], [&a], [&c]);
        let sig_ab = sign(&[1, 2], MESSAGE);
        let sig_c = sign(&[3], b"other");
        let set = |public_keys, message, signature| SignatureSet {
            public_keys,
            message,
            signature,
        };
        let other = set(&only_c, b"other", &sig_c);
        assert_eq!(verify_batch(&[set(&ab, MESSAGE, &sig_ab), other]), Ok(true));
        assert_eq!(
            verify_batch(&[set(&only_a, MESSAGE, &sig_ab), other]),
            Ok(false)
        );
    }

    #[test]
    fn verify_batch_rejects_cancelling_forgeries() {
        // S1 + D and S2 - D are both invalid, but with equal randomizers the D terms cancel.
        // The crate draws secret randomizers itself, so the pair is caught.
        let (p1, p2) = (public_key(1), public_key(2));
        let d = sign(&[9], b"d").to_bytes();
        let s1 = add(&sign(&[1], b"one"), &d);
        let s2 = add(&sign(&[2], b"two"), &negated(d));
        let sets = [
            SignatureSet {
                public_keys: &[&p1],
                message: b"one",
                signature: &s1,
            },
            SignatureSet {
                public_keys: &[&p2],
                message: b"two",
                signature: &s2,
            },
        ];
        for _ in 0..8 {
            assert_eq!(verify_batch(&sets), Ok(false));
        }
    }

    #[test]
    fn opposite_keys_cannot_vouch_for_nothing() {
        // P + (-P) is the identity; with the identity signature the pairing equation holds
        // trivially, so blst's identity-key rejection is what keeps this false.
        let p = public_key(1);
        let neg_p = PublicKey::from_validated_bytes(&negated(p.to_bytes())).unwrap();
        let infinity = Signature::from_validated_bytes(&G2_POINT_AT_INFINITY).unwrap();
        assert!(!eth_fast_aggregate_verify(
            &[&p, &neg_p],
            MESSAGE,
            &infinity
        ));
        let set = SignatureSet {
            public_keys: &[&p, &neg_p],
            message: MESSAGE,
            signature: &infinity,
        };
        assert_eq!(verify_batch(&[set]), Ok(false));
    }
}

#[cfg(feature = "aggregate")]
mod aggregate {
    use super::*;
    use crypto_bls::eth_aggregate_pubkeys;

    #[test]
    fn eth_aggregate_pubkeys_matches_blst() {
        assert_eq!(eth_aggregate_pubkeys(&[]), Err(Error::EmptyInput));

        let a = public_key(1);
        assert_eq!(
            eth_aggregate_pubkeys(&[&a]).unwrap().to_bytes(),
            a.to_bytes()
        );

        let keys: Vec<_> = (1..=3).map(|s| secret_key(s).sk_to_pk()).collect();
        let refs: Vec<_> = keys.iter().collect();
        let expected = blst::min_pk::AggregatePublicKey::aggregate(&refs, true)
            .unwrap()
            .to_public_key()
            .to_bytes();
        let ours: Vec<_> = (1..=3).map(public_key).collect();
        let ours: Vec<_> = ours.iter().collect();
        assert_eq!(eth_aggregate_pubkeys(&ours).unwrap().to_bytes(), expected);
    }

    #[test]
    fn identity_aggregate_cannot_reenter_as_a_key() {
        // P + (-P) is the G1 identity. The spec returns it, but it must never come back in as
        // a PublicKey: the type has no conversion, and its bytes fail KeyValidate.
        let p = public_key(1);
        let mut neg = p.to_bytes();
        neg[0] ^= 0x20;
        let neg_p = PublicKey::from_validated_bytes(&neg).unwrap();
        let z = eth_aggregate_pubkeys(&[&p, &neg_p]).unwrap();
        let mut g1_identity = [0u8; 48];
        g1_identity[0] = 0xc0;
        assert_eq!(z.to_bytes(), g1_identity);
        assert_eq!(
            PublicKey::from_validated_bytes(&z.to_bytes()),
            Err(Error::PublicKeyIsInfinity)
        );
        assert_eq!(
            format!("{z:?}"),
            format!("AggregatePublicKey(0x{})", hex::encode(g1_identity))
        );
    }
}

#[cfg(feature = "test-vectors")]
mod test_vectors {
    use super::*;
    use crypto_bls::{aggregate_signatures, aggregate_verify, sign as bls_sign};

    #[test]
    fn sign_matches_blst() {
        let sk = secret_key(7);
        let sig = bls_sign(&sk.to_bytes(), b"msg").expect("valid secret key");
        assert_eq!(sig, sign(&[7], b"msg"));
        assert_eq!(bls_sign(&[0; 32], b"msg"), Err(Error::BadEncoding));
    }

    #[test]
    fn aggregate_signatures_and_aggregate_verify() {
        assert_eq!(aggregate_signatures(&[]), Err(Error::EmptyInput));

        let (one, two) = (sign(&[1], b"one"), sign(&[2], b"two"));
        let agg = aggregate_signatures(&[&one, &two]).unwrap();
        let (a, b) = (public_key(1), public_key(2));
        assert!(aggregate_verify(&[&a, &b], &[b"one", b"two"], &agg));
        assert!(!aggregate_verify(&[&a, &b], &[b"two", b"one"], &agg));
        assert!(!aggregate_verify(&[&a, &b], &[b"one"], &agg));

        let infinity = Signature::from_validated_bytes(&G2_POINT_AT_INFINITY).unwrap();
        assert!(!aggregate_verify(&[], &[], &infinity));
    }
}
