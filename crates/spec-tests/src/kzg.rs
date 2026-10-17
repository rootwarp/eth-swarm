//! cryptography-specs `tests/kzg/<handler>/<case>/data.yaml`, run through `crypto-kzg`.
//!
//! Only the PeerDAS cell API that `crypto-kzg` exposes runs ([`RUNNABLE`]). The blob-level
//! (EIP-4844) handlers and the ones `crypto-kzg` does not expose yet are [`NOT_RUN`] and need a
//! `skip.toml` entry. Any other handler directory fails the run ([`handler_runs`]): a new
//! upstream handler must be classified here, not silently ignored.
//!
//! `output: null` means the spec function raises: an undecodable input (bad hex, wrong
//! length) or an error from `crypto-kzg`.

use crate::coverage::Reads;
use crate::fixture::{self, compare, field, nullable};
use crypto_kzg::{
    Blob, Bytes48, Cell, TrustedSetup, BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_PROOF,
};
use std::path::Path;
use std::sync::OnceLock;
use yaml_rust2::Yaml;

/// Handlers this runner executes.
pub const RUNNABLE: [&str; 3] = [
    "compute_cells",
    "compute_cells_and_kzg_proofs",
    "verify_cell_kzg_proof_batch",
];

/// Handlers known to exist but not run: blob-level KZG, which cl-verify does not use since
/// Fulu, and cell functions `crypto-kzg` does not expose. Each needs a `skip.toml` entry.
pub const NOT_RUN: [&str; 9] = [
    "blob_to_kzg_commitment",
    "compute_blob_kzg_proof",
    "compute_challenge",
    "compute_kzg_proof",
    "compute_verify_cell_kzg_proof_batch_challenge",
    "recover_cells_and_kzg_proofs",
    "verify_blob_kzg_proof",
    "verify_blob_kzg_proof_batch",
    "verify_kzg_proof",
];

/// The trusted setup `crypto-kzg` vendors (consensus-specs `v1.7.0-beta.4`
/// `presets/mainnet/trusted_setups/trusted_setup_4096.json`); cryptography-specs v0.1.0 uses
/// the same ceremony output.
const SETUP_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../crypto-kzg/data/trusted_setup_4096.json"
);
/// sha256 of [`SETUP_PATH`], as pinned by `crypto-kzg`'s own tests.
const SETUP_SHA256: &str = "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f";

/// `Ok(true)` for a handler that runs, `Ok(false)` for a known one that needs a skip entry,
/// `Err` for a handler directory this runner does not know.
pub fn handler_runs(handler: &str) -> Result<bool, String> {
    if RUNNABLE.contains(&handler) {
        Ok(true)
    } else if NOT_RUN.contains(&handler) {
        Ok(false)
    } else {
        Err(format!(
            "unknown kzg handler directory `{handler}`: classify it in crates/spec-tests/src/kzg.rs"
        ))
    }
}

/// The setup, loaded once through `TrustedSetup::load_pinned`.
fn setup() -> Result<&'static TrustedSetup, String> {
    static SETUP: OnceLock<Result<TrustedSetup, String>> = OnceLock::new();
    SETUP
        .get_or_init(|| {
            let digest: [u8; 32] = hex::decode(SETUP_SHA256)
                .ok()
                .and_then(|d| d.try_into().ok())
                .ok_or("bad pinned digest")?;
            TrustedSetup::load_pinned(SETUP_PATH, digest).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Runs one case of `handler` from its `data.yaml`. `Err` describes a failure.
pub fn run(reads: &Reads, handler: &str, data: &Path) -> Result<(), String> {
    let doc = fixture::load(reads, data)?;
    let input = field(&doc, "input")?;
    let output = field(&doc, "output")?;
    let setup = setup()?;
    match handler {
        "compute_cells" => {
            let got = blob(field(input, "blob")?)?
                .and_then(|b| setup.compute_cells(&b).ok())
                .map(|cells| cells.iter().map(Cell::to_bytes).collect::<Vec<_>>());
            let want = nullable(output, fixture::hex_arrays::<BYTES_PER_CELL>)?;
            compare(got, want)
        }
        "compute_cells_and_kzg_proofs" => {
            let got = blob(field(input, "blob")?)?
                .and_then(|b| setup.compute_cells_and_kzg_proofs(&b).ok())
                .map(|(cells, proofs)| {
                    (
                        cells.iter().map(Cell::to_bytes).collect::<Vec<_>>(),
                        proofs.iter().map(|p| *p.to_bytes()).collect::<Vec<_>>(),
                    )
                });
            let want = nullable(output, |o| {
                let [cells, proofs] = fixture::list(o)? else {
                    return Err("expected [cells, proofs]".into());
                };
                Ok(fixture::hex_arrays::<BYTES_PER_CELL>(cells)?
                    .zip(fixture::hex_arrays::<BYTES_PER_PROOF>(proofs)?))
            })?;
            compare(got, want)
        }
        "verify_cell_kzg_proof_batch" => {
            let got = verify_batch(setup, input)?;
            let want = nullable(output, |o| fixture::boolean(o).map(Some))?;
            compare(got, want)
        }
        other => Err(match handler_runs(other) {
            Ok(_) => format!("kzg handler `{other}` is not run; it needs a skip.toml entry"),
            Err(e) => e,
        }),
    }
}

/// The blob, or `None` if it is not `BYTES_PER_BLOB` bytes of hex. Boxed: a blob is 128 KiB,
/// too large to pass around on a test thread's stack.
fn blob(y: &Yaml) -> Result<Option<Box<Blob>>, String> {
    Ok(fixture::hex(y)?
        .filter(|b| b.len() == BYTES_PER_BLOB)
        .and_then(|b| Blob::from_bytes(&b).ok())
        .map(Box::new))
}

/// `verify_cell_kzg_proof_batch` on the case input; `None` where the spec raises.
fn verify_batch(setup: &TrustedSetup, input: &Yaml) -> Result<Option<bool>, String> {
    let commitments = fixture::hex_arrays::<48>(field(input, "commitments")?)?;
    let indices = fixture::u64_list(field(input, "cell_indices")?)?;
    let cells = fixture::hex_arrays::<BYTES_PER_CELL>(field(input, "cells")?)?;
    let proofs = fixture::hex_arrays::<48>(field(input, "proofs")?)?;
    let (Some(commitments), Some(cells), Some(proofs)) = (commitments, cells, proofs) else {
        return Ok(None);
    };
    let commitments: Vec<Bytes48> = commitments.into_iter().map(Bytes48::new).collect();
    let cells: Vec<Cell> = cells.into_iter().map(Cell::new).collect();
    let proofs: Vec<Bytes48> = proofs.into_iter().map(Bytes48::new).collect();
    Ok(setup
        .verify_cell_kzg_proof_batch(&commitments, &indices, &cells, &proofs)
        .ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// cryptography-specs v0.1.0 `compute_cells_and_kzg_proofs_case_valid_2/data.yaml`, as
    /// vendored (and digest-checked) by `crypto-kzg`.
    fn vendored_case() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../crypto-kzg/tests/data/compute_cells_and_kzg_proofs_case_valid_2/data.yaml")
    }

    fn write(dir: &Path, text: &str) -> PathBuf {
        let p = dir.join("data.yaml");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn handler_classification() {
        assert_eq!(handler_runs("compute_cells"), Ok(true));
        assert_eq!(handler_runs("verify_kzg_proof"), Ok(false));
        let err = handler_runs("compute_cells_v2").unwrap_err();
        assert!(err.contains("compute_cells_v2"), "{err}");
    }

    #[test]
    fn valid_cells_and_proofs_case_passes_and_is_recorded() {
        let reads = Reads::default();
        let path = vendored_case();
        assert_eq!(run(&reads, "compute_cells_and_kzg_proofs", &path), Ok(()));
        assert!(reads.contains(&path));
    }

    #[test]
    fn tampered_output_fails() {
        let text = std::fs::read_to_string(vendored_case()).unwrap();
        // Flip the first proof (the last scalar block) by rewriting one hex digit of it.
        let at = text.rfind("'0x").unwrap() + 3;
        let mut tampered = text.clone();
        let digit = if &text[at..at + 1] == "a" { "b" } else { "a" };
        tampered.replace_range(at..at + 1, digit);
        let dir = tempfile::tempdir().unwrap();
        let err = run(
            &Reads::default(),
            "compute_cells_and_kzg_proofs",
            &write(dir.path(), &tampered),
        )
        .unwrap_err();
        assert!(err.contains("differs"), "{err}");
    }

    #[test]
    fn invalid_blob_expects_null() {
        let dir = tempfile::tempdir().unwrap();
        let short = write(dir.path(), "input:\n  blob: '0x00'\noutput: null\n");
        assert_eq!(run(&Reads::default(), "compute_cells", &short), Ok(()));
        let cell = format!("0x{}", "00".repeat(BYTES_PER_CELL));
        let wrong = write(
            dir.path(),
            &format!("input:\n  blob: '0x00'\noutput: ['{cell}']\n"),
        );
        let err = run(&Reads::default(), "compute_cells", &wrong).unwrap_err();
        assert!(err.contains("expects to succeed"), "{err}");
        let blob = format!("0x{}", "ff".repeat(BYTES_PER_BLOB));
        let non_canonical = write(
            dir.path(),
            &format!("input:\n  blob: '{blob}'\noutput: null\n"),
        );
        assert_eq!(
            run(
                &Reads::default(),
                "compute_cells_and_kzg_proofs",
                &non_canonical
            ),
            Ok(())
        );
    }

    #[test]
    fn verify_batch_edges() {
        let dir = tempfile::tempdir().unwrap();
        let empty = "input:\n  commitments: []\n  cell_indices: []\n  cells: []\n  proofs: []\n";
        let p = write(dir.path(), &format!("{empty}output: true\n"));
        assert_eq!(
            run(&Reads::default(), "verify_cell_kzg_proof_batch", &p),
            Ok(())
        );
        let p = write(dir.path(), &format!("{empty}output: false\n"));
        assert!(run(&Reads::default(), "verify_cell_kzg_proof_batch", &p).is_err());
        let mismatch = "input:\n  commitments: []\n  cell_indices: [0]\n  cells: []\n  \
                        proofs: []\noutput: null\n";
        let p = write(dir.path(), mismatch);
        assert_eq!(
            run(&Reads::default(), "verify_cell_kzg_proof_batch", &p),
            Ok(())
        );
        let p = write(
            dir.path(),
            "input:\n  commitments: ['0x00']\n  cell_indices: [0]\n  cells: []\n  proofs: []\n\
             output: null\n",
        );
        assert_eq!(
            run(&Reads::default(), "verify_cell_kzg_proof_batch", &p),
            Ok(())
        );
    }

    #[test]
    fn malformed_fixtures_and_unrun_handlers_fail() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "input: {}\noutput: null\n");
        assert!(run(&Reads::default(), "compute_cells", &p)
            .unwrap_err()
            .contains("missing `blob`"));
        let p = write(dir.path(), "input:\n  blob: '0x00'\noutput: [1]\n");
        assert!(run(&Reads::default(), "compute_cells_and_kzg_proofs", &p).is_err());
        let p = write(dir.path(), "input: {}\noutput: null\n");
        assert!(run(&Reads::default(), "verify_kzg_proof", &p)
            .unwrap_err()
            .contains("skip.toml"));
        assert!(run(&Reads::default(), "nope", &p)
            .unwrap_err()
            .contains("unknown kzg handler"));
    }
}
