# cl-verify test fixtures

Vendored unchanged; only the cases the tests use are copied.

- The KZG trusted setup is not vendored here. Tests load crypto-kzg's copy
  (`crates/crypto-kzg/data/trusted_setup_4096.json`, consensus-specs `v1.7.0-beta.4`, sha256
  `f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f`) through
  `crypto_kzg::TrustedSetup::load_pinned`.
- `bls12-381-tests/<handler>/<case>.yaml`: ethereum/bls12-381-tests release `v0.1.2`, asset
  `bls_tests_yaml.tar.gz` (sha256 `a4ef909b6248395094949a3bcdeb4e1b5b999733d4436f2c5006edba99d29279`),
  archive paths `<handler>/<case>.yaml` for `verify`, `fast_aggregate_verify` and `batch_verify`.
- `cryptography-specs/verify_cell_kzg_proof_batch/<case>/data.yaml`: ethereum/cryptography-specs
  release `v0.1.0`, asset `tests.zip`
  (sha256 `eeb4893eb544f770810d9499007ebb0b9319431ea412bd54736e1c274da3d037`), archive path
  `tests/kzg/verify_cell_kzg_proof_batch/<case>/data.yaml`.
