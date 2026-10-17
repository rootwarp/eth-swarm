// `verify` exists only with the `verify` feature; an `aggregate`-only build cannot call it.
use crypto_bls::{PublicKey, Signature};

fn check(public_key: &PublicKey, signature: &Signature) -> bool {
    crypto_bls::verify(public_key, b"message", signature)
}

fn main() {
    let _ = check;
}
