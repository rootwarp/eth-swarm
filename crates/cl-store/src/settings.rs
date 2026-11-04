//! cl-store's `[store]` table in `/etc/ethswarm/cl-store.toml` (svc-runtime's
//! [`Config::section`]):
//!
//! ```toml
//! [store]
//! chain_socket = "/run/ethswarm/cl-chain/cl-chain.sock"  # optional, this default
//! chain_uid = 990                                        # the UID cl-chain runs as
//! ```
//!
//! The follower ([`crate::follow`]) reaches cl-chain's `EventsService` on `chain_socket` only if
//! its server runs as `chain_uid` (`ipc::uds::PeerCheckedConnector`), and cl-chain's method ACL
//! must give cl-store [`CHAIN_METHODS`](crate::follow::CHAIN_METHODS):
//!
//! ```toml
//! # cl-chain.toml
//! [callers]
//! cl-store = 995                                         # the UID cl-store runs as
//! [methods]
//! "/ethswarm.chain.v1.EventsService/Subscribe" = ["cl-api", "cl-store"]
//! ```

use std::path::PathBuf;

use serde::Deserialize;
use svc_runtime::Config;

/// cl-chain's socket unless `chain_socket` says otherwise.
pub const DEFAULT_CHAIN_SOCKET: &str = "/run/ethswarm/cl-chain/cl-chain.sock";

/// The `[store]` table.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSettings {
    /// cl-chain's socket, absolute.
    #[serde(default = "default_chain_socket")]
    pub chain_socket: PathBuf,
    /// The UID cl-chain's server must run as.
    pub chain_uid: u32,
}

fn default_chain_socket() -> PathBuf {
    PathBuf::from(DEFAULT_CHAIN_SOCKET)
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
    /// The table does not parse, has no `chain_uid`, or has a relative `chain_socket`.
    pub fn load(config: &Config) -> Result<Self, SettingsError> {
        let settings: Self = config.section().map_err(|e| SettingsError(e.to_string()))?;
        if !settings.chain_socket.is_absolute() {
            let socket = settings.chain_socket.display();
            return Err(SettingsError(format!(
                "[store] chain_socket {socket} is not an absolute path"
            )));
        }
        Ok(settings)
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
    /// `chain_uid`, an unknown key, a relative socket, and the table in another service's file.
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
        // Another service's config with a `[store]` table is refused.
        let api = "network = \"sepolia\"\nmetrics_port = 9105\n[socket]\ngroup = 994\n\
                   [store]\nchain_uid = 990\n";
        let err = Config::from_toml("cl-api", api, Path::new("cl-api.toml")).unwrap_err();
        assert!(
            matches!(&err, svc_runtime::config::ConfigError::ForeignTable { table, service }
                if table == "store" && service == "cl-api"),
            "{err}"
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
