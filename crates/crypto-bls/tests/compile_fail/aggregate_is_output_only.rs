// `eth_aggregate_pubkeys` returns an `AggregatePublicKey`, which may be the identity. It can
// never be used where a `PublicKey` (one that passed KeyValidate) is expected.
use crypto_bls::{eth_aggregate_pubkeys, AggregatePublicKey, PublicKey};

fn reenter(p: &PublicKey, q: &PublicKey) {
    let z: AggregatePublicKey = eth_aggregate_pubkeys(&[p, q]).unwrap();
    let _ = eth_aggregate_pubkeys(&[&z, q]);
    let _: PublicKey = z.into();
    let _ = PublicKey::from(z);
}

fn main() {
    let _ = reenter;
}
