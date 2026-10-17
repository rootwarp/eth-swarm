//! BLS vectors, run through `crypto-bls` in process:
//! - bls12-381-tests v0.1.2: `<handler>/<case>.yaml`;
//! - cryptography-specs v0.1.0: `tests/bls/<handler>/<case>/data.yaml`;
//! - consensus-spec-tests `general/<fork>/bls/<handler>/<suite>/<case>/data.yaml`.
//!
//! One function per handler directory ([`RUNNABLE`]). `sign`, `aggregate` and
//! `aggregate_verify` use the `crypto-bls/test-vectors` feature, which only this crate enables.
//! [`NOT_RUN`] handlers need a `skip.toml` entry; any other directory fails the run
//! ([`handler_runs`]).
//!
//! Inputs that do not decode (bad hex, wrong length, a point `from_validated_bytes` refuses)
//! make a verification `false` and an aggregation or signing `null`, as the spec functions
//! do on invalid input.
//!
//! **`deserialization_G1` and KeyValidate.** That suite tests point *decoding*: it expects the
//! compressed identity (`c0 00..`) to decode. `PublicKey::from_validated_bytes` also runs
//! `KeyValidate`, which rejects the identity with [`Error::PublicKeyIsInfinity`]. blst
//! reports that only after the bytes decoded to a curve point, so the runner counts it as a
//! successful decode. Every other error is a failed decode. The API keeps rejecting the
//! identity as a key; only the decode-only expectation is mapped.

use crate::coverage::Reads;
use crate::fixture::{self, compare, field, nullable};
use crypto_bls::{
    aggregate_signatures, aggregate_verify, eth_aggregate_pubkeys, eth_fast_aggregate_verify, sign,
    verify, verify_batch, Error, PublicKey, Signature, SignatureSet, PUBLIC_KEY_BYTES_LEN,
    SIGNATURE_BYTES_LEN,
};
use std::path::Path;
use yaml_rust2::Yaml;

/// Handlers this runner executes.
pub const RUNNABLE: [&str; 10] = [
    "aggregate",
    "aggregate_verify",
    "batch_verify",
    "deserialization_G1",
    "deserialization_G2",
    "eth_aggregate_pubkeys",
    "eth_fast_aggregate_verify",
    "fast_aggregate_verify",
    "sign",
    "verify",
];

/// Handlers known to exist but not run; each needs a `skip.toml` entry. `crypto-bls` does
/// not expose hash-to-curve on its own (it is internal to `sign`/`verify`).
pub const NOT_RUN: [&str; 1] = ["hash_to_G2"];

/// `Ok(true)` for a handler that runs, `Ok(false)` for a known one that needs a skip entry,
/// `Err` for a handler directory this runner does not know.
pub fn handler_runs(handler: &str) -> Result<bool, String> {
    if RUNNABLE.contains(&handler) {
        Ok(true)
    } else if NOT_RUN.contains(&handler) {
        Ok(false)
    } else {
        Err(format!(
            "unknown bls handler directory `{handler}`: classify it in crates/spec-tests/src/bls.rs"
        ))
    }
}

/// Runs one case of `handler` from its YAML file. `Err` describes a failure.
pub fn run(reads: &Reads, handler: &str, data: &Path) -> Result<(), String> {
    let doc = fixture::load(reads, data)?;
    let input = field(&doc, "input")?;
    let output = field(&doc, "output")?;
    let as_bool = |o: &Yaml| fixture::boolean(o).map(Some);
    let as_signature = |o: &Yaml| fixture::hex_array::<SIGNATURE_BYTES_LEN>(o);
    match handler {
        "verify" => compare(Some(verify_case(input)?), nullable(output, as_bool)?),
        "fast_aggregate_verify" => compare(
            Some(fast_aggregate_verify_case(input, false)?),
            nullable(output, as_bool)?,
        ),
        "eth_fast_aggregate_verify" => compare(
            Some(fast_aggregate_verify_case(input, true)?),
            nullable(output, as_bool)?,
        ),
        "aggregate_verify" => compare(
            Some(aggregate_verify_case(input)?),
            nullable(output, as_bool)?,
        ),
        "batch_verify" => compare(Some(batch_verify_case(input)?), nullable(output, as_bool)?),
        "deserialization_G1" => compare(
            Some(decodes_g1(field(input, "pubkey")?)?),
            nullable(output, as_bool)?,
        ),
        "deserialization_G2" => compare(
            Some(decodes_g2(field(input, "signature")?)?),
            nullable(output, as_bool)?,
        ),
        "eth_aggregate_pubkeys" => compare(
            public_keys(input)?
                .and_then(|pks| eth_aggregate_pubkeys(&refs(&pks)).ok())
                .map(|agg| agg.to_bytes()),
            nullable(output, fixture::hex_array::<PUBLIC_KEY_BYTES_LEN>)?,
        ),
        "sign" => compare(sign_case(input)?, nullable(output, as_signature)?),
        "aggregate" => compare(
            signatures(input)?
                .and_then(|sigs| aggregate_signatures(&refs(&sigs)).ok())
                .map(|s| s.to_bytes()),
            nullable(output, as_signature)?,
        ),
        other => Err(match handler_runs(other) {
            Ok(_) => format!("bls handler `{other}` is not run; it needs a skip.toml entry"),
            Err(e) => e,
        }),
    }
}

fn refs<T>(items: &[T]) -> Vec<&T> {
    items.iter().collect()
}

fn public_key(y: &Yaml) -> Result<Option<PublicKey>, String> {
    Ok(fixture::hex_array::<PUBLIC_KEY_BYTES_LEN>(y)?
        .and_then(|b| PublicKey::from_validated_bytes(&b).ok()))
}

fn signature(y: &Yaml) -> Result<Option<Signature>, String> {
    Ok(fixture::hex_array::<SIGNATURE_BYTES_LEN>(y)?
        .and_then(|b| Signature::from_validated_bytes(&b).ok()))
}

/// Every element of the list, or `None` if any does not decode.
fn all<T>(y: &Yaml, one: fn(&Yaml) -> Result<Option<T>, String>) -> Result<Option<Vec<T>>, String> {
    let mut out = Vec::new();
    for item in fixture::list(y)? {
        match one(item)? {
            Some(v) => out.push(v),
            None => return Ok(None),
        }
    }
    Ok(Some(out))
}

fn public_keys(y: &Yaml) -> Result<Option<Vec<PublicKey>>, String> {
    all(y, public_key)
}

fn signatures(y: &Yaml) -> Result<Option<Vec<Signature>>, String> {
    all(y, signature)
}

fn message(input: &Yaml) -> Result<Option<Vec<u8>>, String> {
    fixture::hex(field(input, "message")?)
}

fn verify_case(input: &Yaml) -> Result<bool, String> {
    let pk = public_key(field(input, "pubkey")?)?;
    let sig = signature(field(input, "signature")?)?;
    Ok(match (pk, message(input)?, sig) {
        (Some(pk), Some(msg), Some(sig)) => verify(&pk, &msg, &sig),
        _ => false,
    })
}

/// `FastAggregateVerify` (IETF: no keys is `false`) or, with `eth`, `eth_fast_aggregate_verify`
/// (no keys and the infinity signature is `true`). They agree for any non-empty key set.
fn fast_aggregate_verify_case(input: &Yaml, eth: bool) -> Result<bool, String> {
    let pks = public_keys(field(input, "pubkeys")?)?;
    let sig = signature(field(input, "signature")?)?;
    Ok(match (pks, message(input)?, sig) {
        (Some(pks), _, _) if pks.is_empty() && !eth => false,
        (Some(pks), Some(msg), Some(sig)) => eth_fast_aggregate_verify(&refs(&pks), &msg, &sig),
        _ => false,
    })
}

fn aggregate_verify_case(input: &Yaml) -> Result<bool, String> {
    let pks = public_keys(field(input, "pubkeys")?)?;
    let msgs = fixture::hex_list(field(input, "messages")?)?;
    let sig = signature(field(input, "signature")?)?;
    Ok(match (pks, msgs, sig) {
        (Some(pks), Some(msgs), Some(sig)) => {
            let msgs: Vec<&[u8]> = msgs.iter().map(Vec::as_slice).collect();
            aggregate_verify(&refs(&pks), &msgs, &sig)
        }
        _ => false,
    })
}

/// One single-signer set per `(pubkey, message, signature)`.
fn batch_verify_case(input: &Yaml) -> Result<bool, String> {
    let pks = public_keys(field(input, "pubkeys")?)?;
    let msgs = fixture::hex_list(field(input, "messages")?)?;
    let sigs = signatures(field(input, "signatures")?)?;
    let (Some(pks), Some(msgs), Some(sigs)) = (pks, msgs, sigs) else {
        return Ok(false);
    };
    if pks.len() != msgs.len() || pks.len() != sigs.len() {
        return Ok(false);
    }
    let keys: Vec<[&PublicKey; 1]> = pks.iter().map(|pk| [pk]).collect();
    let sets: Vec<SignatureSet<'_>> = keys
        .iter()
        .zip(&msgs)
        .zip(&sigs)
        .map(|((k, m), s)| SignatureSet {
            public_keys: k,
            message: m,
            signature: s,
        })
        .collect();
    match verify_batch(&sets) {
        Ok(valid) => Ok(valid),
        Err(Error::EmptyInput) => Ok(false),
        Err(e) => Err(format!("verify_batch: {e}")),
    }
}

/// Whether the bytes decode as a G1 point in the subgroup. See the module docs for why
/// [`Error::PublicKeyIsInfinity`] counts as decoded.
fn decodes_g1(y: &Yaml) -> Result<bool, String> {
    Ok(match fixture::hex_array::<PUBLIC_KEY_BYTES_LEN>(y)? {
        None => false,
        Some(b) => matches!(
            PublicKey::from_validated_bytes(&b),
            Ok(_) | Err(Error::PublicKeyIsInfinity)
        ),
    })
}

fn decodes_g2(y: &Yaml) -> Result<bool, String> {
    Ok(signature(y)?.is_some())
}

fn sign_case(input: &Yaml) -> Result<Option<[u8; SIGNATURE_BYTES_LEN]>, String> {
    let sk = fixture::hex_array::<32>(field(input, "privkey")?)?;
    Ok(match (sk, message(input)?) {
        (Some(sk), Some(msg)) => sign(&sk, &msg).ok().map(|s| s.to_bytes()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SK1: [u8; 32] = [1; 32];
    const SK2: [u8; 32] = [2; 32];
    const MSG: &str = "0x5656565656565656565656565656565656565656565656565656565656565656";

    fn hx(b: &[u8]) -> String {
        format!("'0x{}'", hex::encode(b))
    }

    fn sig(sk: &[u8; 32], msg: &str) -> String {
        hx(&sign(sk, &hex::decode(&msg[2..]).unwrap())
            .unwrap()
            .to_bytes())
    }

    fn vendored(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../crypto-bls/tests/fixtures/bls12-381-tests-v0.1.2")
            .join(name)
    }

    fn run_text(handler: &str, text: &str) -> Result<(), String> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("case.yaml");
        std::fs::write(&p, text).unwrap();
        run(&Reads::default(), handler, &p)
    }

    #[test]
    fn handler_classification() {
        assert_eq!(handler_runs("verify"), Ok(true));
        assert_eq!(handler_runs("hash_to_G2"), Ok(false));
        assert!(handler_runs("hash_to_G1")
            .unwrap_err()
            .contains("unknown bls handler directory `hash_to_G1`"));
    }

    #[test]
    fn deserialization_vectors_including_infinity() {
        let reads = Reads::default();
        for (handler, case) in [
            (
                "deserialization_G1",
                "deserialization_succeeds_correct_point",
            ),
            (
                "deserialization_G1",
                "deserialization_succeeds_infinity_with_true_b_flag",
            ),
            ("deserialization_G1", "deserialization_fails_not_in_G1"),
            (
                "deserialization_G2",
                "deserialization_succeeds_correct_point",
            ),
            (
                "deserialization_G2",
                "deserialization_succeeds_infinity_with_true_b_flag",
            ),
            ("deserialization_G2", "deserialization_fails_not_in_G2"),
        ] {
            let path = vendored(&format!("{handler}/{case}.yaml"));
            assert_eq!(run(&reads, handler, &path), Ok(()), "{handler}/{case}");
            assert!(reads.contains(&path));
        }
        // The identity still fails as a key.
        let infinity = format!("'c0{}'", "00".repeat(47));
        assert!(run_text(
            "deserialization_G1",
            &format!("input: {{pubkey: {infinity}}}\noutput: false\n")
        )
        .is_err());
        assert_eq!(
            run_text(
                "deserialization_G1",
                "input: {pubkey: 'c0'}\noutput: false\n"
            ),
            Ok(())
        );
    }

    #[test]
    fn sign_and_aggregate() {
        let s1 = sig(&SK1, MSG);
        let s2 = sig(&SK2, MSG);
        let text = format!(
            "input: {{privkey: {}, message: '{MSG}'}}\noutput: {s1}\n",
            hx(&SK1)
        );
        assert_eq!(run_text("sign", &text), Ok(()));
        let wrong = format!(
            "input: {{privkey: {}, message: '{MSG}'}}\noutput: {s2}\n",
            hx(&SK1)
        );
        assert!(run_text("sign", &wrong).unwrap_err().contains("differs"));
        let zero = format!(
            "input: {{privkey: {}, message: '{MSG}'}}\noutput: null\n",
            hx(&[0; 32])
        );
        assert_eq!(run_text("sign", &zero), Ok(()));

        let one = format!("input: [{s1}]\noutput: {s1}\n");
        assert_eq!(run_text("aggregate", &one), Ok(()));
        assert_eq!(run_text("aggregate", "input: []\noutput: null\n"), Ok(()));
        let bad = format!("input: [{s1}, '0x00']\noutput: null\n");
        assert_eq!(run_text("aggregate", &bad), Ok(()));
    }

    /// The key of the vendored `deserialization_succeeds_correct_point` vector; [`SK_A`] is its
    /// secret (the first bls12-381-tests signing key).
    fn correct_point() -> String {
        let doc = fixture::parse(
            &std::fs::read_to_string(vendored(
                "deserialization_G1/deserialization_succeeds_correct_point.yaml",
            ))
            .unwrap(),
        )
        .unwrap();
        let b = fixture::hex(&doc["input"]["pubkey"]).unwrap().unwrap();
        hx(&b)
    }

    const SK_A: [u8; 32] = [
        0x26, 0x3d, 0xbd, 0x79, 0x2f, 0x5b, 0x1b, 0xe4, 0x7e, 0xd8, 0x5f, 0x89, 0x38, 0xc0, 0xf2,
        0x95, 0x86, 0xaf, 0x0d, 0x3a, 0xc7, 0xb9, 0x77, 0xf2, 0x1c, 0x27, 0x8f, 0xe1, 0x46, 0x20,
        0x40, 0xe3,
    ];

    #[test]
    fn verification_handlers_accept_valid_signatures() {
        let pk = correct_point();
        let s = sig(&SK_A, MSG);
        for (handler, input) in [
            (
                "verify",
                format!("{{pubkey: {pk}, message: '{MSG}', signature: {s}}}"),
            ),
            (
                "fast_aggregate_verify",
                format!("{{pubkeys: [{pk}], message: '{MSG}', signature: {s}}}"),
            ),
            (
                "eth_fast_aggregate_verify",
                format!("{{pubkeys: [{pk}], message: '{MSG}', signature: {s}}}"),
            ),
            (
                "aggregate_verify",
                format!("{{pubkeys: [{pk}], messages: ['{MSG}'], signature: {s}}}"),
            ),
            (
                "batch_verify",
                format!("{{pubkeys: [{pk}], messages: ['{MSG}'], signatures: [{s}]}}"),
            ),
        ] {
            assert_eq!(
                run_text(handler, &format!("input: {input}\noutput: true\n")),
                Ok(()),
                "{handler}"
            );
        }
    }

    #[test]
    fn eth_aggregate_pubkeys_compares_output_bytes() {
        let pk = correct_point();
        assert_eq!(
            run_text(
                "eth_aggregate_pubkeys",
                &format!("input: [{pk}]\noutput: {pk}\n")
            ),
            Ok(())
        );
        assert_eq!(
            run_text("eth_aggregate_pubkeys", "input: []\noutput: null\n"),
            Ok(())
        );
        let infinity = format!("'0xc0{}'", "00".repeat(47));
        assert_eq!(
            run_text(
                "eth_aggregate_pubkeys",
                &format!("input: [{pk}, {infinity}]\noutput: null\n")
            ),
            Ok(())
        );
        assert!(run_text(
            "eth_aggregate_pubkeys",
            &format!("input: [{pk}, {pk}]\noutput: {pk}\n")
        )
        .is_err());
    }

    #[test]
    fn verification_handlers_reject_bad_inputs() {
        let pk = correct_point();
        let s1 = sig(&SK1, MSG);
        let infinity_sig = format!("'0xc0{}'", "00".repeat(95));
        // A signature by another key does not verify; undecodable input is false.
        for (handler, input) in [
            (
                "verify",
                format!("{{pubkey: {pk}, message: '{MSG}', signature: {s1}}}"),
            ),
            (
                "verify",
                format!("{{pubkey: '0x00', message: '{MSG}', signature: {s1}}}"),
            ),
            (
                "fast_aggregate_verify",
                format!("{{pubkeys: [{pk}], message: '{MSG}', signature: {s1}}}"),
            ),
            (
                "fast_aggregate_verify",
                format!("{{pubkeys: [], message: '{MSG}', signature: {infinity_sig}}}"),
            ),
            (
                "aggregate_verify",
                format!("{{pubkeys: [{pk}], messages: ['{MSG}'], signature: {s1}}}"),
            ),
            (
                "batch_verify",
                format!("{{pubkeys: [{pk}], messages: ['{MSG}'], signatures: [{s1}]}}"),
            ),
            (
                "batch_verify",
                format!("{{pubkeys: [{pk}], messages: [], signatures: [{s1}]}}"),
            ),
            (
                "batch_verify",
                "{pubkeys: [], messages: [], signatures: []}".to_owned(),
            ),
        ] {
            assert_eq!(
                run_text(handler, &format!("input: {input}\noutput: false\n")),
                Ok(()),
                "{handler} {input}"
            );
            assert!(
                run_text(handler, &format!("input: {input}\noutput: true\n")).is_err(),
                "{handler} {input}"
            );
        }
        // eth_ variant: no keys and the infinity signature verify.
        let eth = format!(
            "input: {{pubkeys: [], message: '{MSG}', signature: {infinity_sig}}}\noutput: true\n"
        );
        assert_eq!(run_text("eth_fast_aggregate_verify", &eth), Ok(()));
    }

    #[test]
    fn malformed_fixtures_and_unrun_handlers_fail() {
        assert!(run_text("verify", "input: {}\noutput: false\n")
            .unwrap_err()
            .contains("missing `pubkey`"));
        assert!(run_text("hash_to_G2", "input: {}\noutput: null\n")
            .unwrap_err()
            .contains("skip.toml"));
        assert!(run_text("nope", "input: {}\noutput: null\n")
            .unwrap_err()
            .contains("unknown bls handler"));
    }
}
