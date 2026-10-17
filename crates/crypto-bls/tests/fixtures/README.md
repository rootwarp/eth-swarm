# Vendored BLS fixtures

Byte-identical copies of a few cases from
[ethereum/bls12-381-tests](https://github.com/ethereum/bls12-381-tests) release `v0.1.2`,
asset `bls_tests_yaml.tar.gz`
(sha256 `a4ef909b6248395094949a3bcdeb4e1b5b999733d4436f2c5006edba99d29279`).
Only `tests/api.rs` reads them; the full suite runs through the spec-vector runner.

| File under `bls12-381-tests-v0.1.2/` | Source path in the tarball | sha256 |
| --- | --- | --- |
| `deserialization_G1/deserialization_succeeds_correct_point.yaml` | `./deserialization_G1/deserialization_succeeds_correct_point.yaml` | `ac79afb3b83e0fc24e232bc58e574632e367a84b097d8b53606941c4f51c815d` |
| `deserialization_G1/deserialization_succeeds_infinity_with_true_b_flag.yaml` | `./deserialization_G1/deserialization_succeeds_infinity_with_true_b_flag.yaml` | `8ac9ff0487cccd32aa22f78618553190990ab02330475b5633af8d3b2d8e0f28` |
| `deserialization_G1/deserialization_fails_not_in_G1.yaml` | `./deserialization_G1/deserialization_fails_not_in_G1.yaml` | `355a994ba695f593f74329a760a16bba3191fa3ff017c71f1311c5dab52aa920` |
| `deserialization_G2/deserialization_succeeds_correct_point.yaml` | `./deserialization_G2/deserialization_succeeds_correct_point.yaml` | `a9aa66d8f426cdd200fcce51ae68f4b5b65231f2a6ddc3cc79453cfc52b88564` |
| `deserialization_G2/deserialization_succeeds_infinity_with_true_b_flag.yaml` | `./deserialization_G2/deserialization_succeeds_infinity_with_true_b_flag.yaml` | `50cd0b8c8a75e78bd5c5cf5460c8f191daae228084f71a79b3189afb28ed1670` |
| `deserialization_G2/deserialization_fails_not_in_G2.yaml` | `./deserialization_G2/deserialization_fails_not_in_G2.yaml` | `2409025b10628574aaf54453de4b3836ccd6c77cedd9a770626cf0bd3fc53b14` |

`deserialization_G1/deserialization_succeeds_infinity_with_true_b_flag` says `output: true`
because that suite tests plain point decoding. `PublicKey::from_validated_bytes` also runs
`KeyValidate`, which rejects the identity, so the API test expects it to fail.
