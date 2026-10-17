// A signature can only come from `Signature::from_validated_bytes` (G2 subgroup check).
use crypto_bls::Signature;

fn main() {
    let bytes = [0u8; 96];
    let _ = Signature::from_bytes(&bytes);
    let _ = Signature::deserialize(&bytes);
    let _ = Signature::default();
    let _: Signature = bytes.into();
    let _ = Signature::try_from(&bytes[..]);

    // Nor from a blst point that skipped the subgroup check.
    let raw = blst::min_pk::Signature::from_bytes(&bytes).unwrap();
    let _: Signature = raw.into();
    let _ = Signature(raw);
}
