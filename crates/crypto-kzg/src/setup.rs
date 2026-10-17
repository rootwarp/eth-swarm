//! Loading the spec's JSON trusted setup, pinned by sha256.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use c_kzg::KzgSettings;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Fixed-base MSM precomputation passed to c-kzg. `0` keeps the settings at their minimum size;
/// `8` would add ~96 MiB per process, against cl-verify's 512 MiB `MemoryMax`.
pub const PRECOMPUTE: u64 = 0;
/// G1 points in each of `g1_monomial` and `g1_lagrange` (`FIELD_ELEMENTS_PER_BLOB`).
pub const NUM_G1_POINTS: usize = c_kzg::FIELD_ELEMENTS_PER_BLOB;
/// G2 points in `g2_monomial`.
pub const NUM_G2_POINTS: usize = 65;
/// Upper bound on the setup file size. The mainnet file is 881,553 bytes; anything far larger is
/// refused before it is read in full.
pub const MAX_SETUP_BYTES: u64 = 4 << 20;

/// sha256 of consensus-specs `v1.7.0-beta.4` `presets/mainnet/trusted_setups/trusted_setup_4096.json`
/// (`f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f`), taken over the raw file
/// bytes. The only digest cl-verify starts with.
pub const BETA4_MAINNET_SHA256: [u8; 32] = [
    0xf8, 0xe4, 0x4a, 0x31, 0xeb, 0xf0, 0xa6, 0xd0, 0x73, 0x4d, 0xcb, 0x30, 0x1b, 0x07, 0x16, 0xe2,
    0xc7, 0x7f, 0x3a, 0xe1, 0x8e, 0xd0, 0xca, 0xb0, 0x87, 0x0f, 0xbc, 0xc2, 0xca, 0x55, 0x61, 0x6f,
];

const G1_BYTES: usize = 48;
const G2_BYTES: usize = 96;

/// Why [`TrustedSetup::load_pinned`] refused a file. Every malformed input is an error, never a
/// panic.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("cannot read trusted setup {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("trusted setup {} is larger than {max} bytes", path.display())]
    TooLarge { path: PathBuf, max: u64 },
    /// The file is not the pinned one. Nothing in it was parsed.
    #[error(
        "trusted setup sha256 mismatch: expected {}, got {}",
        hex::encode(expected),
        hex::encode(actual)
    )]
    DigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Not JSON, a missing or unknown key, or a non-string entry.
    #[error("trusted setup JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{field}: expected {expected} points, got {got}")]
    PointCount {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("{field}[{index}]: missing 0x prefix")]
    MissingPrefix { field: &'static str, index: usize },
    /// Odd length, a non-hex character, or the wrong width for the point type.
    #[error("{field}[{index}]: {source}")]
    Hex {
        field: &'static str,
        index: usize,
        #[source]
        source: hex::FromHexError,
    },
    /// c-kzg refused the decoded points (e.g. not on the curve).
    #[error("c-kzg: {0}")]
    Backend(c_kzg::Error),
}

/// `presets/<preset>/trusted_setups/trusted_setup_4096.json`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupJson {
    g1_monomial: Vec<String>,
    g1_lagrange: Vec<String>,
    g2_monomial: Vec<String>,
}

/// The decoded setup: concatenated compressed points, in the order c-kzg takes them.
struct SetupPoints {
    g1_monomial: Vec<u8>,
    g1_lagrange: Vec<u8>,
    g2_monomial: Vec<u8>,
}

impl SetupPoints {
    fn parse(bytes: &[u8]) -> Result<Self, SetupError> {
        let json: SetupJson = serde_json::from_slice(bytes)?;
        Ok(Self {
            g1_monomial: decode_points("g1_monomial", &json.g1_monomial, NUM_G1_POINTS, G1_BYTES)?,
            g1_lagrange: decode_points("g1_lagrange", &json.g1_lagrange, NUM_G1_POINTS, G1_BYTES)?,
            g2_monomial: decode_points("g2_monomial", &json.g2_monomial, NUM_G2_POINTS, G2_BYTES)?,
        })
    }
}

fn decode_points(
    field: &'static str,
    entries: &[String],
    count: usize,
    width: usize,
) -> Result<Vec<u8>, SetupError> {
    if entries.len() != count {
        return Err(SetupError::PointCount {
            field,
            expected: count,
            got: entries.len(),
        });
    }
    let mut out = vec![0u8; count * width];
    for (index, (entry, dst)) in entries.iter().zip(out.chunks_exact_mut(width)).enumerate() {
        let digits = entry
            .strip_prefix("0x")
            .ok_or(SetupError::MissingPrefix { field, index })?;
        hex::decode_to_slice(digits, dst).map_err(|source| SetupError::Hex {
            field,
            index,
            source,
        })?;
    }
    Ok(out)
}

/// The sole FFI call that builds settings.
fn build_settings(points: &SetupPoints) -> Result<KzgSettings, SetupError> {
    KzgSettings::load_trusted_setup(
        &points.g1_monomial,
        &points.g1_lagrange,
        &points.g2_monomial,
        PRECOMPUTE,
    )
    .map_err(SetupError::Backend)
}

fn read_capped(path: &Path) -> Result<Vec<u8>, SetupError> {
    let io_err = |source| SetupError::Io {
        path: path.to_owned(),
        source,
    };
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io_err)?
        .take(MAX_SETUP_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_err)?;
    if bytes.len() as u64 > MAX_SETUP_BYTES {
        return Err(SetupError::TooLarge {
            path: path.to_owned(),
            max: MAX_SETUP_BYTES,
        });
    }
    Ok(bytes)
}

/// KZG settings loaded from a digest-pinned trusted setup.
///
/// The only constructor is [`TrustedSetup::load_pinned`]; the fields are private and there is no
/// `new`, `Default` or `From`.
pub struct TrustedSetup {
    settings: KzgSettings,
}

impl TrustedSetup {
    /// Loads the spec's JSON trusted setup from `path`, refusing it unless its sha256 equals
    /// `expected_sha256`.
    ///
    /// Order: read (at most [`MAX_SETUP_BYTES`]), compare the digest, parse the JSON, hex-decode
    /// exactly 4096 + 4096 G1 and 65 G2 points, then build c-kzg settings with
    /// [`PRECOMPUTE`]` = 0`. On a digest mismatch nothing is parsed and c-kzg is not called.
    pub fn load_pinned(
        path: impl AsRef<Path>,
        expected_sha256: [u8; 32],
    ) -> Result<Self, SetupError> {
        Self::load_with(path.as_ref(), expected_sha256, build_settings)
    }

    /// [`Self::load_pinned`] with the c-kzg call injected, so tests can observe whether it runs.
    fn load_with(
        path: &Path,
        expected_sha256: [u8; 32],
        build: impl FnOnce(&SetupPoints) -> Result<KzgSettings, SetupError>,
    ) -> Result<Self, SetupError> {
        let bytes = read_capped(path)?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual != expected_sha256 {
            return Err(SetupError::DigestMismatch {
                expected: expected_sha256,
                actual,
            });
        }
        let points = SetupPoints::parse(&bytes)?;
        Ok(Self {
            settings: build(&points)?,
        })
    }

    pub(crate) fn settings(&self) -> &KzgSettings {
        &self.settings
    }
}

impl fmt::Debug for TrustedSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedSetup").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const SETUP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data/trusted_setup_4096.json");

    fn pinned() -> [u8; 32] {
        Sha256::digest(std::fs::read(SETUP).unwrap()).into()
    }

    /// Runs `load_with` with a builder that records whether it was invoked, then defers to the
    /// real c-kzg call.
    fn load_counting(digest: [u8; 32]) -> (Result<TrustedSetup, SetupError>, usize) {
        let calls = Cell::new(0);
        let result = TrustedSetup::load_with(Path::new(SETUP), digest, |points| {
            calls.set(calls.get() + 1);
            build_settings(points)
        });
        (result, calls.get())
    }

    #[test]
    fn digest_mismatch_never_reaches_ckzg() {
        let mut wrong = pinned();
        wrong[0] ^= 0x80;
        let (result, calls) = load_counting(wrong);
        assert!(matches!(result, Err(SetupError::DigestMismatch { .. })));
        assert_eq!(calls, 0);
    }

    #[test]
    fn matching_digest_reaches_ckzg_once() {
        let (result, calls) = load_counting(pinned());
        assert!(result.is_ok());
        assert_eq!(calls, 1);
    }

    #[test]
    fn beta4_mainnet_pin_is_the_vendored_file() {
        assert_eq!(
            hex::encode(BETA4_MAINNET_SHA256),
            "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f"
        );
        assert_eq!(pinned(), BETA4_MAINNET_SHA256);
    }

    /// Loads `bytes` from a temp file under the production pin, counting c-kzg builds.
    fn load_tampered(bytes: &[u8]) -> (Result<TrustedSetup, SetupError>, usize) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trusted_setup_4096.json");
        std::fs::write(&path, bytes).unwrap();
        let calls = Cell::new(0);
        let result = TrustedSetup::load_with(&path, BETA4_MAINNET_SHA256, |points| {
            calls.set(calls.get() + 1);
            build_settings(points)
        });
        (result, calls.get())
    }

    #[test]
    fn one_changed_byte_fails_the_pin_before_ckzg() {
        let mut bytes = std::fs::read(SETUP).unwrap();
        // A hex digit inside the first G1 point: still valid JSON of the right shape.
        let at = bytes.windows(2).position(|w| w == b"0x").unwrap() + 2;
        bytes[at] = if bytes[at] == b'a' { b'b' } else { b'a' };
        let (result, calls) = load_tampered(&bytes);
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        assert!(
            matches!(result, Err(SetupError::DigestMismatch { expected, actual: got })
                if expected == BETA4_MAINNET_SHA256 && got == actual),
            "{result:?}"
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn whitespace_edit_fails_the_pin() {
        // The digest is over the raw bytes, so JSON-equivalent edits are refused too.
        let mut bytes = std::fs::read(SETUP).unwrap();
        bytes.push(b'\n');
        let (result, calls) = load_tampered(&bytes);
        assert!(
            matches!(result, Err(SetupError::DigestMismatch { .. })),
            "{result:?}"
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn load_pinned_builds_through_build_settings() {
        // `load_pinned` is `load_with(.., build_settings)`; this pins that wiring for the
        // counting tests above.
        assert!(TrustedSetup::load_pinned(SETUP, pinned()).is_ok());
    }
}
