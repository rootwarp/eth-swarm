// A public key can only come from `PublicKey::from_validated_bytes` (KeyValidate).
use crypto_bls::PublicKey;

fn main() {
    let bytes = [0u8; 48];
    let _ = PublicKey::from_bytes(&bytes);
    let _ = PublicKey::deserialize(&bytes);
    let _ = PublicKey::default();
    let _: PublicKey = bytes.into();
    let _ = PublicKey::try_from(&bytes[..]);

    // Nor from a blst point that skipped the subgroup check.
    let raw = blst::min_pk::PublicKey::from_bytes(&bytes).unwrap();
    let _: PublicKey = raw.into();
    let _ = PublicKey(raw);
}
