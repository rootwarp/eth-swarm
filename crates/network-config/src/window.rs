//! The block serve window: `compute_min_epochs_for_block_requests` (`phase0/p2p-interface.md`
//! L427–431; modified in Gloas, `gloas/p2p-interface.md` L246–262) from a network's config.

use crate::{ChainConfig, ConfigError, Epoch};

/// `compute_min_epochs_for_block_requests()` for a block at `epoch`.
///
/// # Errors
///
/// A key it reads is missing or not a uint64.
pub fn min_epochs_for_block_requests(
    _config: &ChainConfig,
    _epoch: Epoch,
) -> Result<Epoch, ConfigError> {
    todo!("#146 step 1")
}

/// The first epoch of the range a node MUST serve blocks of at `current_epoch`.
///
/// # Errors
///
/// As [`min_epochs_for_block_requests`].
pub fn block_serve_window(
    _config: &ChainConfig,
    _current_epoch: Epoch,
) -> Result<Epoch, ConfigError> {
    todo!("#146 step 1")
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
