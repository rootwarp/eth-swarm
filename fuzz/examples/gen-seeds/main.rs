//! Writes the seed corpus: `fuzz/gen-seeds.sh [VECTORS_DIR]`.
//!
//! Replaces every file under `fuzz/corpus/<target>/` (the fuzzing corpus) and
//! `fuzz/corpus-slow/<target>/` (seeds too slow to fuzz from) with what `ethswarm_fuzz::seeds` builds,
//! framing the Gloas blocks of `VECTORS_DIR` (default `SPEC_VECTORS_DIR`, else the repo's
//! `target/spec-vectors`; fetch with `INCLUDE_OPTIONAL=1 testing/fetch-vectors.sh` or
//! `PRESETS=mainnet`).

mod vectors;

use ethswarm_fuzz::{seeds, TARGETS};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(vectors::default_dir);
    let blocks = match vectors::gloas_blocks(&root) {
        Ok(blocks) => blocks,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return ExitCode::FAILURE;
        }
    };
    let out = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Err(e) = write(out, &seeds::all(&blocks)) {
        eprintln!("ERROR: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn write(out: &Path, seeds: &[seeds::Seed]) -> std::io::Result<()> {
    for corpus in [seeds::FUZZ_DIR, seeds::SLOW_DIR] {
        let dir = out.join(corpus);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
    }
    let mut total = 0;
    for seed in seeds {
        let corpus = if seed.slow {
            seeds::SLOW_DIR
        } else {
            seeds::FUZZ_DIR
        };
        let dir = out.join(corpus).join(seed.target);
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(&seed.name), &seed.bytes)?;
        total += seed.bytes.len();
    }
    for target in TARGETS {
        fs::create_dir_all(out.join(seeds::FUZZ_DIR).join(target))?;
    }
    println!("{} seeds, {total} bytes, in {}", seeds.len(), out.display());
    Ok(())
}
