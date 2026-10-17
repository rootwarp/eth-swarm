//! Reads the Gloas mainnet `SignedBeaconBlock` `ssz_static` cases the seeds frame.

use consensus_types::{forked, ForkName, Mainnet};
use ethswarm_fuzz::seeds::VectorBlock;
use std::fs;
use std::path::{Path, PathBuf};

/// The cases framed into seeds: the three smallest of the beta.4 set (5-10 KiB compressed).
pub const CASES: [&str; 3] = ["case_0", "case_1", "case_2"];

const SUITE: &str =
    "consensus-specs/v1.7.0-beta.4/mainnet/tests/mainnet/gloas/ssz_static/SignedBeaconBlock/ssz_random";

/// `SPEC_VECTORS_DIR`, else the repo's `target/spec-vectors`.
pub fn default_dir() -> PathBuf {
    std::env::var_os("SPEC_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/spec-vectors"))
}

/// The `ssz_random` directory of the Gloas mainnet `SignedBeaconBlock` cases under `root`.
pub fn suite_dir(root: &Path) -> PathBuf {
    root.join(SUITE)
}

/// The blocks if `root` holds the Gloas mainnet suite, `None` if it does not; a suite that is
/// there but does not load is an error, never "no vectors".
#[allow(dead_code)] // used by tests/corpus.rs, not by gen-seeds
pub fn load(root: &Path) -> Result<Option<Vec<VectorBlock>>, String> {
    if !suite_dir(root).exists() {
        return Ok(None);
    }
    gloas_blocks(root).map(Some)
}

/// Each case's block SSZ, checked to decode as a Gloas mainnet block.
pub fn gloas_blocks(root: &Path) -> Result<Vec<VectorBlock>, String> {
    CASES
        .iter()
        .map(|case| {
            let path = suite_dir(root).join(case).join("serialized.ssz_snappy");
            let raw = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let ssz = snap::raw::Decoder::new()
                .decompress_vec(&raw)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            forked::SignedBeaconBlock::<Mainnet>::from_ssz_bytes_for_fork(&ssz, ForkName::Gloas)
                .map_err(|e| format!("{}: not a Gloas mainnet block: {e:?}", path.display()))?;
            Ok(VectorBlock {
                case: case.to_string(),
                ssz,
            })
        })
        .collect()
}
