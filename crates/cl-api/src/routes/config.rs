//! `/eth/v1/config/{spec,fork_schedule,deposit_contract}` (beacon-APIs `01e99a6`
//! `apis/config/`), all built once from the network's [`ChainConfig`] ([`ConfigData::new`]).
//!
//! - `spec` holds every `config.yaml` value as written: integers as decimal strings, `0x` values
//!   as hex strings, and the lists (`BLOB_SCHEDULE`, ...) as arrays of objects of strings.
//!   Presets and constants are not in it yet.
//! - `fork_schedule` lists every scheduled fork, oldest first. That is phase0 at epoch 0 with
//!   `GENESIS_FORK_VERSION`, each of Altair to Electra that the config schedules, then Fulu and
//!   Gloas from the [`ForkSchedule`](network_config::ForkSchedule). A fork at
//!   `FAR_FUTURE_EPOCH` is not listed.
//! - `deposit_contract` holds `DEPOSIT_CHAIN_ID` and `DEPOSIT_CONTRACT_ADDRESS`. A config
//!   without them, or with values that do not parse, stops cl-api at startup.

use axum::body::Bytes;
use axum::Router;
use network_config::ChainConfig;

use crate::server::ApiState;

/// The encoded config responses.
#[derive(Clone, Debug)]
pub struct ConfigData {
    spec: Bytes,
    fork_schedule: Bytes,
    deposit_contract: Bytes,
}

/// Why the network config cannot be served.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigDataError {
    #[error("the network config has no {0}")]
    Missing(&'static str),
    #[error("{key} = {value:?} in the network config is not {expected}")]
    Invalid {
        key: String,
        value: String,
        expected: &'static str,
    },
}

impl ConfigData {
    /// The responses of `chain`.
    ///
    /// # Errors
    ///
    /// The deposit contract keys are missing or malformed, or a fork key does not parse.
    pub fn new(chain: &ChainConfig) -> Result<Self, ConfigDataError> {
        let _ = chain;
        todo!()
    }
}

/// The config routes.
pub fn routes() -> Router<ApiState> {
    todo!()
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use network_config::{ChainConfig, ForkName, Network};
    use serde_json::{json, Value};

    use super::*;
    use crate::node_state::NodeState;
    use crate::server::router;
    use crate::testing::{self, get, json};

    async fn data(chain: &ChainConfig, uri: &str) -> Value {
        let state = ApiState {
            node: NodeState::new(testing::clock()),
            config: std::sync::Arc::new(ConfigData::new(chain).unwrap()),
        };
        let (status, headers, body) = get(&router(state), uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert_eq!(headers[http::header::CONTENT_TYPE], "application/json");
        let body = json(&body);
        assert_eq!(body.as_object().unwrap().len(), 1, "only data: {body}");
        body["data"].clone()
    }

    fn is_hex(s: &str) -> bool {
        s.strip_prefix("0x")
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_hexdigit()))
    }

    fn is_decimal(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }

    /// A devnet config with the deposit keys, `extra` lines and `from` replaced by `to`.
    fn devnet(from: &str, to: &str, extra: &str) -> ChainConfig {
        let text = format!(
            "{}DEPOSIT_CHAIN_ID: 3151908\n\
             DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa\n{extra}",
            ipc::testkit::devnet::DEVNET_CONFIG.replace(from, to)
        );
        ChainConfig::from_devnet_yaml(text.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn spec_string_integers() {
        for network in Network::ALL {
            let chain = ChainConfig::load(network).unwrap();
            let data = data(&chain, "/eth/v1/config/spec").await;
            let data = data.as_object().unwrap();
            // Every scalar, as written; every list, as an array.
            let scalars: Vec<(&str, &str)> = chain.scalars().collect();
            let lists: Vec<_> = chain.lists().collect();
            assert!(scalars.len() > 50, "{network}");
            assert_eq!(data.len(), scalars.len() + lists.len(), "{network}");
            for (key, value) in &scalars {
                assert_eq!(data[*key], Value::String((*value).into()), "{key}");
            }
            // Only strings: integers in decimal, the rest in hex, two names.
            for (key, value) in data {
                match value {
                    Value::String(s) => assert!(
                        is_decimal(s)
                            || is_hex(s)
                            || ["PRESET_BASE", "CONFIG_NAME"].contains(&key.as_str()),
                        "{network} {key} = {s:?}"
                    ),
                    Value::Array(records) => {
                        assert!(!records.is_empty(), "{key}");
                        for record in records {
                            for (field, v) in record.as_object().unwrap() {
                                assert!(v.as_str().is_some_and(is_decimal), "{key}.{field} = {v}");
                            }
                        }
                    }
                    other => panic!("{network} {key} = {other}: not a string"),
                }
            }
            // The blob schedule, from the typed reader.
            let blobs: Vec<Value> = chain
                .blob_schedule()
                .iter()
                .map(|b| {
                    json!({
                        "EPOCH": b.epoch.to_string(),
                        "MAX_BLOBS_PER_BLOCK": b.max_blobs_per_block.to_string(),
                    })
                })
                .collect();
            assert_eq!(data["BLOB_SCHEDULE"], Value::Array(blobs), "{network}");
        }
        // Sepolia, spelled out.
        let data = data(
            &ChainConfig::load(Network::Sepolia).unwrap(),
            "/eth/v1/config/spec",
        )
        .await;
        assert_eq!(data["SECONDS_PER_SLOT"], "12");
        assert_eq!(data["SLOT_DURATION_MS"], "12000");
        assert_eq!(data["DEPOSIT_CHAIN_ID"], "11155111");
        assert_eq!(data["GLOAS_FORK_EPOCH"], "353024");
        assert_eq!(data["TERMINAL_TOTAL_DIFFICULTY"], "17000000000000000");
        assert_eq!(data["FULU_FORK_VERSION"], "0x90000075");
        assert_eq!(data["PRESET_BASE"], "mainnet");
        assert_eq!(data["CONFIG_NAME"], "sepolia");
        assert_eq!(
            data["BLOB_SCHEDULE"],
            json!([
                {"EPOCH": "274176", "MAX_BLOBS_PER_BLOCK": "15"},
                {"EPOCH": "275712", "MAX_BLOBS_PER_BLOCK": "21"},
            ])
        );
        assert_eq!(
            data["GAS_LIMIT_SCHEDULE"],
            json!([{"EPOCH": "353024", "GAS_LIMIT": "200000000"}])
        );
    }

    fn fork(previous: &str, current: &str, epoch: u64) -> Value {
        json!({"previous_version": previous, "current_version": current, "epoch": epoch.to_string()})
    }

    #[tokio::test]
    async fn fork_schedule() {
        let chain = ChainConfig::load(Network::Sepolia).unwrap();
        let data = data(&chain, "/eth/v1/config/fork_schedule").await;
        assert_eq!(
            data,
            json!([
                fork("0x90000069", "0x90000069", 0),
                fork("0x90000069", "0x90000070", 50),
                fork("0x90000070", "0x90000071", 100),
                fork("0x90000071", "0x90000072", 56832),
                fork("0x90000072", "0x90000073", 132608),
                fork("0x90000073", "0x90000074", 222464),
                fork("0x90000074", "0x90000075", 272640),
                fork("0x90000075", "0x90000076", 353024),
            ])
        );
        // Fulu and Gloas are the ForkSchedule's.
        let schedule = chain.fork_schedule();
        let forks = data.as_array().unwrap();
        for (entry, name) in forks[forks.len() - 2..].iter().zip(ForkName::ALL) {
            let version = schedule.fork_version(name);
            let hex = format!(
                "0x{}",
                version
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            assert_eq!(entry["current_version"], hex, "{name}");
            assert_eq!(
                entry["epoch"],
                schedule.fork_epoch(name).unwrap().to_string()
            );
        }
        // A devnet: Electra has an epoch but no version, so it is not listed; an unscheduled
        // Gloas is not listed either.
        let far = devnet(
            "GLOAS_FORK_EPOCH: 2",
            "GLOAS_FORK_EPOCH: 18446744073709551615",
            "",
        );
        assert_eq!(
            data_of(&far).await,
            json!([
                fork("0x00000001", "0x00000001", 0),
                fork("0x00000001", "0x60000001", 0),
            ])
        );
        let both = devnet("", "", "");
        assert_eq!(
            data_of(&both).await,
            json!([
                fork("0x00000001", "0x00000001", 0),
                fork("0x00000001", "0x60000001", 0),
                fork("0x60000001", "0x70000001", 2),
            ])
        );
        // A fork version that does not parse, or a fork before the one it follows, is refused.
        let bad = devnet(
            "",
            "",
            "ALTAIR_FORK_VERSION: 0x0102\nALTAIR_FORK_EPOCH: 0\n",
        );
        assert!(matches!(
            ConfigData::new(&bad),
            Err(ConfigDataError::Invalid { key, .. }) if key == "ALTAIR_FORK_VERSION"
        ));
        // Altair at 5 and Fulu at 0: Fulu is the fork out of order.
        let late = devnet(
            "",
            "",
            "ALTAIR_FORK_VERSION: 0x01000001\nALTAIR_FORK_EPOCH: 5\n",
        );
        assert!(matches!(
            ConfigData::new(&late),
            Err(ConfigDataError::Invalid { key, .. }) if key == "FULU_FORK_EPOCH"
        ));
    }

    async fn data_of(chain: &ChainConfig) -> Value {
        data(chain, "/eth/v1/config/fork_schedule").await
    }

    #[tokio::test]
    async fn deposit_contract() {
        let sepolia = ChainConfig::load(Network::Sepolia).unwrap();
        assert_eq!(
            data(&sepolia, "/eth/v1/config/deposit_contract").await,
            json!({"chain_id": "11155111", "address": "0x7f02C3E3c98b133055B8B348B2Ac625669Ed295D"})
        );
        let hoodi = ChainConfig::load(Network::Hoodi).unwrap();
        let data_hoodi = data(&hoodi, "/eth/v1/config/deposit_contract").await;
        assert_eq!(data_hoodi["chain_id"], "560048");
        assert_eq!(
            data_hoodi["address"].as_str(),
            hoodi.get("DEPOSIT_CONTRACT_ADDRESS")
        );
        // Without the keys, or with values that do not parse, there is nothing to serve.
        let none =
            ChainConfig::from_devnet_yaml(ipc::testkit::devnet::DEVNET_CONFIG.as_bytes()).unwrap();
        assert_eq!(
            ConfigData::new(&none).unwrap_err(),
            ConfigDataError::Missing("DEPOSIT_CHAIN_ID")
        );
        for (from, to, key) in [
            (
                "DEPOSIT_CHAIN_ID: 3151908",
                "DEPOSIT_CHAIN_ID: 0x30",
                "DEPOSIT_CHAIN_ID",
            ),
            (
                "0x00000000219ab540356cBB839Cbe05303d7705Fa",
                "0x00000000219ab540356cBB839Cbe05303d7705",
                "DEPOSIT_CONTRACT_ADDRESS",
            ),
            (
                "0x00000000219ab540356cBB839Cbe05303d7705Fa",
                "0x00000000219ab540356cBB839Cbe05303d7705Fg",
                "DEPOSIT_CONTRACT_ADDRESS",
            ),
        ] {
            let text = format!(
                "{}DEPOSIT_CHAIN_ID: 3151908\n\
                 DEPOSIT_CONTRACT_ADDRESS: 0x00000000219ab540356cBB839Cbe05303d7705Fa\n",
                ipc::testkit::devnet::DEVNET_CONFIG
            )
            .replace(from, to);
            let chain = ChainConfig::from_devnet_yaml(text.as_bytes()).unwrap();
            assert!(
                matches!(ConfigData::new(&chain), Err(ConfigDataError::Invalid { key: k, .. }) if k == key),
                "{to}"
            );
        }
    }
}
