//! Anchor directories for tests (feature `test-support`).
//!
//! [`pinned_export`] opens the in-repo export that `testing/replay.manifest.toml` pins, through
//! [`open_export_pinned`] with the pinned `export_sha256`. [`AnchorFiles::genesis`] takes the
//! genesis state and the genesis block of an export, and [`AnchorFiles::write`] writes them into
//! a directory in the `anchor-fetch` layout. Nothing here writes into `testing/`.

use super::{AnchorRecord, FileRecord, ProviderRecord, ANCHOR_FILE, BLOCK_FILE, STATE_FILE};
use crate::export_blocks::{open_export_pinned, Export};
use consensus_types::primitives::{Root, Slot};
use network_config::ChainConfig;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The pin of the in-repo export, from the workspace root.
pub const PIN_FILE: &str = "testing/replay.manifest.toml";

/// The pinned export and the config it was made with.
pub struct Pinned {
    /// The export, opened through [`open_export_pinned`].
    pub export: Export,
    /// The devnet config of the pin, checked against its own sha256.
    pub config: ChainConfig,
}

#[derive(serde::Deserialize)]
struct PinFile {
    export: String,
    export_sha256: String,
    config: String,
}

/// Opens the export that [`PIN_FILE`] pins, with its `export_sha256`, and parses its config.
pub fn pinned_export() -> Result<Pinned, String> {
    let pin_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PIN_FILE);
    let text = fs::read_to_string(&pin_path).map_err(|e| format!("{PIN_FILE}: {e}"))?;
    let pin: PinFile = toml::from_str(&text).map_err(|e| format!("{PIN_FILE}: {e}"))?;
    let base = pin_path.parent().unwrap_or_else(|| Path::new("."));
    let sha: [u8; 32] = hex::decode(&pin.export_sha256)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{PIN_FILE}: export_sha256 is not 32 hex bytes"))?;
    let export = open_export_pinned(&base.join(&pin.export), sha).map_err(|e| e.to_string())?;
    let yaml = fs::read(base.join(&pin.config)).map_err(|e| format!("{}: {e}", pin.config))?;
    let digest: [u8; 32] = Sha256::digest(&yaml).into();
    let config = ChainConfig::from_yaml(&yaml, &digest).map_err(|e| e.to_string())?;
    Ok(Pinned { export, config })
}

/// The contents of an anchor directory. The test sets each field, so it can write a directory
/// whose files and record disagree.
#[derive(Clone, Debug)]
pub struct AnchorFiles {
    /// `block.ssz`.
    pub block_ssz: Vec<u8>,
    /// `state.ssz`.
    pub state_ssz: Vec<u8>,
    /// `block_root` of `anchor.json`.
    pub block_root: Root,
    /// `state_root` of `anchor.json`.
    pub state_root: Root,
    /// `slot` of `anchor.json`.
    pub slot: Slot,
}

impl AnchorFiles {
    /// The genesis state and the genesis block of `export`, with the roots its manifest gives.
    pub fn genesis(export: &Export) -> Result<Self, String> {
        let manifest = export.manifest();
        let genesis = manifest
            .blocks
            .iter()
            .find(|block| block.slot == 0)
            .ok_or("the export has no block at slot 0")?;
        Ok(Self {
            block_ssz: export.block_ssz(genesis).map_err(|e| e.to_string())?,
            state_ssz: export.genesis_state_ssz().map_err(|e| e.to_string())?,
            block_root: manifest.genesis_block_root,
            state_root: manifest.genesis_state_root,
            slot: 0,
        })
    }

    /// Writes `block.ssz`, `state.ssz` and then `anchor.json` into `dir`. The file records
    /// carry the length and the sha256 of the bytes written. `epoch` and `finalized_epoch` are
    /// 0: [`super::load_anchor`] does not read them.
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        let file = |name: &str, bytes: &[u8]| FileRecord {
            file: name.into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            bytes: bytes.len() as u64,
            provider: "fixture".into(),
        };
        let record = AnchorRecord {
            block_root: format!("{:#x}", self.block_root),
            slot: self.slot,
            epoch: 0,
            finalized_epoch: 0,
            state_root: format!("{:#x}", self.state_root),
            fork: "gloas".into(),
            block: file(BLOCK_FILE, &self.block_ssz),
            state: file(STATE_FILE, &self.state_ssz),
            providers: vec![ProviderRecord {
                role: "a".into(),
                name: "fixture".into(),
                operator: "fixture".into(),
                url: "http://127.0.0.1".into(),
            }],
            fetched_at: "1970-01-01T00:00:00Z".into(),
        };
        fs::write(dir.join(BLOCK_FILE), &self.block_ssz)?;
        fs::write(dir.join(STATE_FILE), &self.state_ssz)?;
        let json = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;
        fs::write(dir.join(ANCHOR_FILE), json)
    }
}
