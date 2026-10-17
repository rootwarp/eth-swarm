// Every way to obtain a `TrustedSetup` other than `TrustedSetup::load_pinned` must fail to compile.
use crypto_kzg::TrustedSetup;

fn main() {
    let _ = TrustedSetup {};
    let _ = TrustedSetup::new();
    let _: TrustedSetup = Default::default();
    let _ = TrustedSetup::from(std::path::PathBuf::new());
    let _ = TrustedSetup::from([0u8; 32]);
}
