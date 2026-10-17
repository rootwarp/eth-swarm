//! Synthetic keys, a blst-free codec and an in-memory feed for the persist tests and bench.
#![allow(dead_code)]

use cl_verify_cache::persist::{KeyCodec, Registry, RegistryFeed};
use cl_verify_cache::{Lookup, PubkeyCache};

/// Stand-in for a decompressed G1 pubkey: the 48 "compressed" bytes are the key itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TestKey(pub [u8; 48]);

/// Uncompressed form: the compressed bytes followed by the same bytes XOR `0xa5`, so a decode
/// can tell a consistent point from a damaged one (as blst's on-curve check would).
pub struct TestCodec;

impl KeyCodec for TestCodec {
    type Key = TestKey;

    fn compressed(&self, key: &TestKey) -> [u8; 48] {
        key.0
    }

    fn uncompressed(&self, key: &TestKey) -> [u8; 96] {
        let mut out = [0u8; 96];
        out[..48].copy_from_slice(&key.0);
        for (o, b) in out[48..].iter_mut().zip(key.0) {
            *o = b ^ 0xa5;
        }
        out
    }

    fn decode_uncompressed_unchecked(&self, bytes: &[u8; 96]) -> Option<TestKey> {
        let (x, y) = bytes.split_at(48);
        x.iter()
            .zip(y)
            .all(|(a, b)| a ^ 0xa5 == *b)
            .then(|| TestKey(x.try_into().expect("48 bytes")))
    }
}

/// Deterministic, distinct key for validator `i` (with `seed` to build a competing registry).
pub fn key(seed: u64, i: u64) -> TestKey {
    let mut b = [0x42u8; 48];
    b[..8].copy_from_slice(&i.to_le_bytes());
    b[8..16].copy_from_slice(&seed.to_le_bytes());
    b[16..24].copy_from_slice(&i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    TestKey(b)
}

pub fn keys(seed: u64, n: u64) -> Vec<TestKey> {
    (0..n).map(|i| key(seed, i)).collect()
}

pub fn cache_of(keys: &[TestKey]) -> PubkeyCache<TestKey> {
    let mut c = PubkeyCache::new();
    c.append_range(0, keys.to_vec()).unwrap();
    c
}

/// Every cached entry, in index order.
pub fn contents(cache: &PubkeyCache<TestKey>) -> Vec<TestKey> {
    (0..cache.high_water())
        .map(|i| match cache.get(i) {
            Lookup::Known(k) => *k,
            Lookup::Unknown => unreachable!("index below high_water"),
        })
        .collect()
}

/// cl-chain's side of the feed: announces `registry`, then serves `keys` on request.
pub struct VecFeed {
    pub registry: Option<Registry>,
    pub keys: Vec<TestKey>,
    /// Every `(start, max)` the startup asked for.
    pub requests: Vec<(u64, usize)>,
}

impl VecFeed {
    /// A feed whose announced registry is exactly `keys`.
    pub fn honest(keys: Vec<TestKey>) -> Self {
        Self {
            registry: Some(Registry::of(&TestCodec, &keys)),
            keys,
            requests: Vec::new(),
        }
    }
}

impl RegistryFeed for VecFeed {
    type Key = TestKey;
    type Error = String;

    fn registry(&mut self) -> Result<Option<Registry>, String> {
        Ok(self.registry)
    }

    fn range(&mut self, start: u64, max: usize) -> Result<Vec<TestKey>, String> {
        self.requests.push((start, max));
        let start = usize::try_from(start).map_err(|e| e.to_string())?;
        let end = start.saturating_add(max).min(self.keys.len());
        Ok(self.keys.get(start..end).unwrap_or_default().to_vec())
    }
}
