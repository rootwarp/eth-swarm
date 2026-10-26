//! consensus-spec-tests `tests/<preset>/phase0/shuffling/core/shuffle/<case>/`, run through
//! `state_transition::caches`.
//!
//! Each case is one `mapping.yaml` (`seed`, `count` and `mapping`, which is
//! `[compute_shuffled_index(i, count, seed) for i in range(count)]`) plus its `manifest.yaml`.
//! The vectors sit under phase0 only, and Gloas shuffles the same way. The whole-list shuffle
//! must equal `mapping`, and so must the per-index `compute_shuffled_index` for every `i`.

use crate::coverage::Reads;
use crate::fixture::{self, field};
use state_transition::caches::{compute_shuffled_index, compute_shuffled_permutation};
use state_transition::Preset;
use std::path::Path;
use yaml_rust2::Yaml;

/// Whether this runner takes `handler` of `fork` and `preset`.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    fork == "phase0" && handler == "core" && rounds(preset).is_some()
}

/// `SHUFFLE_ROUND_COUNT` of a preset.
fn rounds(preset: &str) -> Option<u8> {
    match preset {
        "minimal" => Some(consensus_types::Minimal::SHUFFLE_ROUND_COUNT),
        "mainnet" => Some(consensus_types::Mainnet::SHUFFLE_ROUND_COUNT),
        _ => None,
    }
}

/// Runs one case of `preset` from its `mapping.yaml`. `Err` describes a failure.
pub fn run(reads: &Reads, preset: &str, mapping: &Path) -> Result<(), String> {
    let rounds = rounds(preset).ok_or_else(|| format!("no shuffle round count for {preset}"))?;
    let doc = fixture::load(reads, mapping)?;
    let seed =
        fixture::hex_array::<32>(field(&doc, "seed")?)?.ok_or("`seed` is not 32 bytes of hex")?;
    let count = uint(field(&doc, "count")?)?;
    let want = fixture::u64_list(field(&doc, "mapping")?)?;
    if want.len() as u64 != count {
        return Err(format!(
            "`mapping` has {} entries, `count` is {count}",
            want.len()
        ));
    }
    if compute_shuffled_permutation(count, &seed, rounds) != want {
        return Err("the whole-list shuffle differs from `mapping`".into());
    }
    for (i, want) in want.iter().enumerate() {
        let got = compute_shuffled_index(i as u64, count, &seed, rounds)
            .map_err(|e| format!("compute_shuffled_index({i}): {e}"))?;
        if got != *want {
            return Err(format!(
                "compute_shuffled_index({i}) is {got}, `mapping` has {want}"
            ));
        }
    }
    Ok(())
}

/// A `uint64` scalar.
fn uint(y: &Yaml) -> Result<u64, String> {
    y.as_i64()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| format!("expected an unsigned integer, got {y:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const SEED: &str = "0x23bcd11624a07465b1c2fc1a0fe52996daae4bf87b0fb6bed45926096c644843";

    fn write(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join("mapping.yaml");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn handler_selection() {
        assert!(supported("phase0", "minimal", "core"));
        assert!(supported("phase0", "mainnet", "core"));
        assert!(!supported("phase0", "general", "core"));
        assert!(!supported("gloas", "minimal", "core"));
        assert!(!supported("phase0", "minimal", "other"));
    }

    /// `minimal/phase0/shuffling/core/shuffle/shuffle_0x23bc…_10`, as the vector writes it.
    #[test]
    fn a_vector_case_passes_and_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(
            dir.path(),
            &format!("seed: '{SEED}'\ncount: 10\nmapping: [6, 9, 2, 7, 8, 3, 0, 1, 4, 5]\n"),
        );
        let reads = Reads::default();
        assert_eq!(run(&reads, "minimal", &p), Ok(()));
        assert!(reads.contains(&p));
        let p = write(
            dir.path(),
            &format!("seed: '{SEED}'\ncount: 0\nmapping: []\n"),
        );
        assert_eq!(run(&Reads::default(), "minimal", &p), Ok(()));
    }

    #[test]
    fn wrong_mappings_and_malformed_fixtures_fail() {
        let dir = tempfile::tempdir().unwrap();
        for (preset, text, needle) in [
            (
                "minimal",
                format!("seed: '{SEED}'\ncount: 10\nmapping: [9, 6, 2, 7, 8, 3, 0, 1, 4, 5]\n"),
                "whole-list shuffle differs",
            ),
            // 90 mainnet rounds give another permutation than the 10 of the vector.
            (
                "mainnet",
                format!("seed: '{SEED}'\ncount: 10\nmapping: [6, 9, 2, 7, 8, 3, 0, 1, 4, 5]\n"),
                "differs",
            ),
            (
                "minimal",
                format!("seed: '{SEED}'\ncount: 2\nmapping: [0]\n"),
                "has 1 entries",
            ),
            (
                "minimal",
                "seed: '0x01'\ncount: 0\nmapping: []\n".into(),
                "32 bytes",
            ),
            (
                "minimal",
                format!("seed: '{SEED}'\ncount: -1\nmapping: []\n"),
                "unsigned integer",
            ),
            (
                "minimal",
                format!("seed: '{SEED}'\nmapping: []\n"),
                "missing",
            ),
            (
                "general",
                format!("seed: '{SEED}'\ncount: 0\nmapping: []\n"),
                "round count",
            ),
        ] {
            let err = run(&Reads::default(), preset, &write(dir.path(), &text)).unwrap_err();
            assert!(err.contains(needle), "{text}: {err}");
        }
    }
}
