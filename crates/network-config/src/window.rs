//! The block serve window: the epochs a node MUST serve `BeaconBlocksByRange` from
//! (`phase0/p2p-interface.md` L1527–1530), `[max(GENESIS_EPOCH, current_epoch -
//! compute_min_epochs_for_block_requests()), current_epoch]`.
//!
//! `compute_min_epochs_for_block_requests` is `MIN_VALIDATOR_WITHDRAWABILITY_DELAY +
//! CHURN_LIMIT_QUOTIENT // 2` (`phase0` L427–431; 33,024 epochs on mainnet values, 272 on
//! minimal) and, from Gloas (EIP-8061, `gloas/p2p-interface.md` L246–262), the arithmetic of
//! `compute_weak_subjectivity_period` (14,299 on mainnet values, 262 on minimal). Its inputs are
//! config values, read from the network's config ([`ChainConfig::get`]).

use crate::{ChainConfig, ConfigError, Epoch, ForkName};

/// The uint64 config value of `key`.
fn uint(config: &ChainConfig, key: &'static str) -> Result<u64, ConfigError> {
    let text = config.get(key).ok_or(ConfigError::Missing(key))?;
    text.parse().map_err(|_| ConfigError::Invalid {
        key,
        value: text.to_owned(),
        reason: "expected a uint64".into(),
    })
}

/// `compute_min_epochs_for_block_requests()` of the fork of `epoch`: the phase0 formula before
/// `GLOAS_FORK_EPOCH`, the Gloas one from it.
///
/// # Errors
///
/// A key it reads is missing or not a uint64, or the Gloas denominator is 0.
pub fn min_epochs_for_block_requests(
    config: &ChainConfig,
    epoch: Epoch,
) -> Result<Epoch, ConfigError> {
    let delay = uint(config, "MIN_VALIDATOR_WITHDRAWABILITY_DELAY")?;
    let gloas = config.fork_schedule().fork_epoch(ForkName::Gloas);
    if gloas.is_none_or(|gloas| epoch < gloas) {
        return Ok(delay.saturating_add(uint(config, "CHURN_LIMIT_QUOTIENT")? / 2));
    }
    // [Modified in Gloas:EIP8061]
    let exit = u128::from(uint(config, "CHURN_LIMIT_QUOTIENT_GLOAS")?);
    let consolidation = u128::from(uint(config, "CONSOLIDATION_CHURN_LIMIT_QUOTIENT")?);
    let numerator = (3 * exit).saturating_mul(consolidation);
    let denominator = 2 * consolidation + 3 * exit;
    if denominator == 0 {
        return Err(ConfigError::Invalid {
            key: "CONSOLIDATION_CHURN_LIMIT_QUOTIENT",
            value: "0".into(),
            reason: "with CHURN_LIMIT_QUOTIENT_GLOAS 0 the window divides by zero".into(),
        });
    }
    let churn = u64::try_from(numerator / denominator / 2).unwrap_or(u64::MAX);
    Ok(delay.saturating_add(churn))
}

/// The first epoch of the window at `current_epoch` (the wall clock's): `current_epoch` less
/// [`min_epochs_for_block_requests`], at genesis at the earliest.
///
/// # Errors
///
/// As [`min_epochs_for_block_requests`].
pub fn block_serve_window(
    config: &ChainConfig,
    current_epoch: Epoch,
) -> Result<Epoch, ConfigError> {
    Ok(current_epoch.saturating_sub(min_epochs_for_block_requests(config, current_epoch)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;

    /// Sepolia's config (mainnet values) with `edits` applied to its text, as a devnet config.
    fn edited(edits: &[(&str, &str)]) -> ChainConfig {
        let mut yaml = String::from_utf8(Network::Sepolia.embedded_config().to_vec()).unwrap();
        for (from, to) in edits {
            assert!(yaml.contains(from), "{from}");
            yaml = yaml.replace(from, to);
        }
        ChainConfig::from_devnet_yaml(yaml.as_bytes()).unwrap()
    }

    /// The minimal preset's churn values (`configs/minimal.yaml` at v1.7.0-beta.4).
    fn minimal() -> ChainConfig {
        edited(&[
            (
                "\nCHURN_LIMIT_QUOTIENT: 65536",
                "\nCHURN_LIMIT_QUOTIENT: 32",
            ),
            (
                "CHURN_LIMIT_QUOTIENT_GLOAS: 32768",
                "CHURN_LIMIT_QUOTIENT_GLOAS: 16",
            ),
            (
                "CONSOLIDATION_CHURN_LIMIT_QUOTIENT: 65536",
                "CONSOLIDATION_CHURN_LIMIT_QUOTIENT: 32",
            ),
        ])
    }

    /// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + CHURN_LIMIT_QUOTIENT // 2` before Gloas
    /// (mainnet 33,024, minimal 272) and the EIP-8061 formula from `GLOAS_FORK_EPOCH` on
    /// (mainnet 14,299, minimal 262); a missing key is an error; the window floors at genesis.
    #[test]
    fn min_epochs_fulu_and_gloas() {
        let mainnet = ChainConfig::load(Network::Sepolia).unwrap();
        let gloas = mainnet
            .fork_schedule()
            .fork_epoch(crate::ForkName::Gloas)
            .unwrap();
        for (config, before, from) in [(mainnet, 33_024, 14_299), (minimal(), 272, 262)] {
            assert_eq!(min_epochs_for_block_requests(&config, 0).unwrap(), before);
            assert_eq!(
                min_epochs_for_block_requests(&config, gloas - 1).unwrap(),
                before
            );
            assert_eq!(min_epochs_for_block_requests(&config, gloas).unwrap(), from);
            assert_eq!(
                min_epochs_for_block_requests(&config, gloas + 9).unwrap(),
                from
            );
            // The window: `max(GENESIS_EPOCH, current_epoch - min_epochs)`.
            assert_eq!(block_serve_window(&config, 0).unwrap(), 0);
            assert_eq!(block_serve_window(&config, before - 1).unwrap(), 0);
            assert_eq!(block_serve_window(&config, before + 5).unwrap(), 5);
            assert_eq!(
                block_serve_window(&config, gloas + 20_000).unwrap(),
                gloas + 20_000 - from
            );
        }
        let missing = edited(&[("CHURN_LIMIT_QUOTIENT_GLOAS: 32768\n", "")]);
        assert_eq!(
            min_epochs_for_block_requests(&missing, gloas),
            Err(ConfigError::Missing("CHURN_LIMIT_QUOTIENT_GLOAS"))
        );
        assert_eq!(min_epochs_for_block_requests(&missing, 0).unwrap(), 33_024);
        let zero = edited(&[
            (
                "CHURN_LIMIT_QUOTIENT_GLOAS: 32768",
                "CHURN_LIMIT_QUOTIENT_GLOAS: 0",
            ),
            (
                "CONSOLIDATION_CHURN_LIMIT_QUOTIENT: 65536",
                "CONSOLIDATION_CHURN_LIMIT_QUOTIENT: 0",
            ),
        ]);
        assert!(matches!(
            min_epochs_for_block_requests(&zero, gloas),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
