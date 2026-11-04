//! cl-store's `[store]` table.

use std::path::PathBuf;

use serde::Deserialize;
use svc_runtime::Config;

/// cl-chain's socket unless `chain_socket` says otherwise.
pub const DEFAULT_CHAIN_SOCKET: &str = "/run/ethswarm/cl-chain/cl-chain.sock";

/// The `[store]` table.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSettings {
    pub chain_socket: PathBuf,
    pub chain_uid: u32,
}

/// Why the `[store]` table was refused.
#[derive(Debug, thiserror::Error)]
#[error("config: {0}")]
pub struct SettingsError(String);

impl StoreSettings {
    /// The `[store]` table of `config`.
    ///
    /// # Errors
    ///
    /// The table is refused.
    pub fn load(config: &Config) -> Result<Self, SettingsError> {
        let _ = config;
        Err(SettingsError("not yet".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn config(store: &str) -> Config {
        let text = format!(
            "network = \"sepolia\"\nmetrics_port = 9106\n\
             [socket]\ngroup = 994\n\
             [callers]\ncl-api = 990\n\
             [methods]\n\"/ethswarm.store.v1.StoreService/GetBlock\" = [\"cl-api\"]\n{store}"
        );
        Config::from_toml("cl-store", &text, Path::new("cl-store.toml")).unwrap()
    }

    /// `[store]`: cl-chain's events socket (`chain_socket`, cl-chain's default socket unless
    /// set) and the UID its server must run as (`chain_uid`, required). Refused: no table, no
    /// `chain_uid`, an unknown key, a relative socket.
    #[test]
    fn store_table() {
        let settings = StoreSettings::load(&config("[store]\nchain_uid = 990\n")).unwrap();
        assert_eq!(
            settings,
            StoreSettings {
                chain_socket: DEFAULT_CHAIN_SOCKET.into(),
                chain_uid: 990,
            }
        );
        let full = "[store]\nchain_socket = \"/run/x/chain.sock\"\nchain_uid = 7\n";
        let settings = StoreSettings::load(&config(full)).unwrap();
        assert_eq!(
            (settings.chain_socket.as_path(), settings.chain_uid),
            (Path::new("/run/x/chain.sock"), 7)
        );
        for bad in [
            "",
            "[store]\n",
            "[store]\nchain_uid = 1\nchain_sockett = \"/run/x.sock\"\n",
            "[store]\nchain_uid = 1\nchain_socket = \"run/chain.sock\"\n",
        ] {
            assert!(StoreSettings::load(&config(bad)).is_err(), "{bad:?}");
        }
    }
}
