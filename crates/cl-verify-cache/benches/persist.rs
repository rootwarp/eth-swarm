//! Reload time of the on-disk pubkey cache at Hoodi scale (1,664,885 validators by default).
//!
//! `cargo bench -p cl-verify-cache --bench persist`. Env: `PERSIST_BENCH_KEYS` (entries),
//! `PERSIST_BENCH_RUNS` (timed runs per step). Uses the synthetic blst-free test codec, so the
//! numbers cover file I/O, both SHA-256 passes and the reload loop, not blst's decode of the
//! 96-byte points (measured in cl-verify). The file is read from a warm page cache, and the
//! rebuild step feeds already-decoded keys from memory (no decompression or KeyValidate).

#[path = "../tests/common/mod.rs"]
mod common;

use std::hint::black_box;
use std::time::{Duration, Instant};

use cl_verify_cache::persist::{load_with, save_with, startup_with, Registry, Startup};
use common::{cache_of, keys, TestCodec, VecFeed};

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn summary(label: &str, mut runs: Vec<Duration>) {
    runs.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!(
        "{label:<28} min {:>9.1} ms   median {:>9.1} ms   max {:>9.1} ms   ({} runs)",
        ms(runs[0]),
        ms(runs[runs.len() / 2]),
        ms(runs[runs.len() - 1]),
        runs.len()
    );
}

fn time(runs: u64, mut f: impl FnMut()) -> Vec<Duration> {
    (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect()
}

fn main() {
    let n = env_or("PERSIST_BENCH_KEYS", 1_664_885);
    let runs = env_or("PERSIST_BENCH_RUNS", 5).max(1);
    let registry_keys = keys(1, n);
    let cache = cache_of(&registry_keys);
    let registry = Registry::of(&TestCodec, &registry_keys);
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("pubkeys.bin");

    println!("persist bench: {n} keys, {runs} runs");
    summary(
        "save_with (write+fsync)",
        time(runs, || save_with(&TestCodec, &cache, &path).expect("save")),
    );
    let size = std::fs::metadata(&path).expect("snapshot").len();
    println!("snapshot size {:.1} MiB", size as f64 / (1 << 20) as f64);
    summary(
        "load_with (reload)",
        time(runs, || match load_with(&TestCodec, &path, &registry) {
            Startup::Use(c) => assert_eq!(black_box(c).high_water(), n),
            Startup::Rebuild(r) => panic!("reload rebuilt: {r}"),
        }),
    );
    let mut feed = VecFeed::honest(registry_keys.clone());
    summary(
        "startup_with (file matches)",
        time(runs, || {
            let restored = startup_with(&TestCodec, &path, &mut feed).expect("startup");
            assert!(restored.rebuilt.is_none());
            black_box(restored.cache);
        }),
    );
    let missing = dir.path().join("missing.bin");
    summary(
        "startup_with (rebuild, feed)",
        time(runs, || {
            let restored = startup_with(&TestCodec, &missing, &mut feed).expect("startup");
            assert!(restored.rebuilt.is_some());
            black_box(restored.cache);
        }),
    );
}
