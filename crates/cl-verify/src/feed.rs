//! PubkeyFeed: cl-chain appends the finalized validator registry, in order, to the shared cache.
//!
//! A frame carries entries `start_index .. start_index + count`. `count` must equal the number of
//! keys, `start_index` must equal the current high-water mark, and every key must decompress and
//! pass `KeyValidate` from exactly 48 compressed bytes; anything else is `ERROR_CODE_CONTRACT_VIOLATION`, and the frame is not
//! applied at all. Every reply carries the high-water mark so the sender can resend from there.

use std::sync::{Arc, PoisonError, RwLock};

use blst::min_pk::PublicKey;
use cl_verify_cache::PubkeyCache;

use crate::bls::decode_pubkey;
use crate::proto::common::{Error, ErrorCode};
use crate::proto::verify::{PubkeyFeedRequestBody, PubkeyFeedResponseBody};
use crate::wire::wire_error;

/// The finalized pubkey cache shared by the feed (writer) and BLS verification (readers).
pub type SharedCache = Arc<RwLock<PubkeyCache<PublicKey>>>;

/// The current high-water mark, as sent right after the hello.
pub fn status(cache: &RwLock<PubkeyCache<PublicKey>>) -> PubkeyFeedResponseBody {
    PubkeyFeedResponseBody {
        high_water: high_water(cache),
        err: None,
    }
}

/// Applies one feed frame and returns the reply. Keys are decoded and validated before the write
/// lock is taken, so readers are blocked only for the append itself.
pub fn apply(
    cache: &RwLock<PubkeyCache<PublicKey>>,
    body: &PubkeyFeedRequestBody,
) -> PubkeyFeedResponseBody {
    let result = check_and_decode(cache, body).and_then(|keys| {
        let mut guard = cache.write().map_err(|_| poisoned())?;
        guard
            .append_range(body.start_index, keys)
            .map_err(|e| violation(&e.to_string()))
    });
    PubkeyFeedResponseBody {
        high_water: high_water(cache),
        err: result.err(),
    }
}

fn check_and_decode(
    cache: &RwLock<PubkeyCache<PublicKey>>,
    body: &PubkeyFeedRequestBody,
) -> Result<Vec<PublicKey>, Error> {
    if usize::try_from(body.count).ok() != Some(body.pubkeys.len()) {
        return Err(violation(&format!(
            "count {} != {} pubkeys",
            body.count,
            body.pubkeys.len()
        )));
    }
    // Cheap early check; append_range re-checks under the write lock.
    let expected = high_water(cache);
    if body.start_index != expected {
        return Err(violation(&format!(
            "start_index {} != high_water {expected}",
            body.start_index
        )));
    }
    body.pubkeys
        .iter()
        .enumerate()
        .map(|(i, k)| {
            decode_pubkey(k).ok_or_else(|| {
                violation(&format!(
                    "pubkey {} is not a valid 48-byte compressed key",
                    body.start_index + i as u64
                ))
            })
        })
        .collect()
}

fn high_water(cache: &RwLock<PubkeyCache<PublicKey>>) -> u64 {
    cache
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .high_water()
}

fn violation(detail: &str) -> Error {
    wire_error(ErrorCode::ContractViolation, detail)
}

fn poisoned() -> Error {
    wire_error(ErrorCode::ResourceUnavailable, "pubkey cache unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;

    fn key(i: u64) -> Vec<u8> {
        let mut ikm = [3u8; 32];
        ikm[..8].copy_from_slice(&i.to_le_bytes());
        SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .sk_to_pk()
            .compress()
            .to_vec()
    }

    fn body(start: u64, keys: impl IntoIterator<Item = u64>) -> PubkeyFeedRequestBody {
        let pubkeys: Vec<Vec<u8>> = keys.into_iter().map(key).collect();
        PubkeyFeedRequestBody {
            start_index: start,
            count: pubkeys.len() as u64,
            pubkeys,
        }
    }

    fn code(r: &PubkeyFeedResponseBody) -> Option<ErrorCode> {
        r.err.as_ref().map(Error::code)
    }

    #[test]
    fn appends_in_order_and_reports_the_high_water_mark() {
        let cache = SharedCache::default();
        assert_eq!(status(&cache).high_water, 0);
        let r = apply(&cache, &body(0, 0..3));
        assert_eq!((r.high_water, code(&r)), (3, None));
        let r = apply(&cache, &body(3, 3..5));
        assert_eq!((r.high_water, code(&r)), (5, None));
        assert_eq!(
            status(&cache),
            PubkeyFeedResponseBody {
                high_water: 5,
                err: None
            }
        );
    }

    #[test]
    fn count_must_equal_the_number_of_keys() {
        let cache = SharedCache::default();
        for count in [2, 4, 0] {
            let mut b = body(0, 0..3);
            b.count = count;
            let r = apply(&cache, &b);
            assert_eq!(
                (r.high_water, code(&r)),
                (0, Some(ErrorCode::ContractViolation))
            );
        }
    }

    #[test]
    fn gap_and_overlap_are_contract_violations() {
        let cache = SharedCache::default();
        apply(&cache, &body(0, 0..3));
        for start in [2, 4] {
            let r = apply(&cache, &body(start, 10..12));
            assert_eq!(
                (r.high_water, code(&r)),
                (3, Some(ErrorCode::ContractViolation))
            );
        }
    }

    #[test]
    fn one_invalid_key_rejects_the_whole_frame() {
        let cache = SharedCache::default();
        let mut b = body(0, 0..3);
        b.pubkeys[1] = vec![0xaa; 48];
        let r = apply(&cache, &b);
        assert_eq!(
            (r.high_water, code(&r)),
            (0, Some(ErrorCode::ContractViolation))
        );
        let mut infinity = body(0, 0..1);
        infinity.pubkeys[0] = [&[0xc0u8][..], &[0u8; 47][..]].concat();
        assert_eq!(
            code(&apply(&cache, &infinity)),
            Some(ErrorCode::ContractViolation)
        );
    }

    #[test]
    fn uncompressed_key_is_refused() {
        let cache = SharedCache::default();
        let mut b = body(0, 0..2);
        let mut ikm = [3u8; 32];
        ikm[..8].copy_from_slice(&1u64.to_le_bytes());
        b.pubkeys[1] = SecretKey::key_gen(&ikm, &[])
            .unwrap()
            .sk_to_pk()
            .serialize()
            .to_vec();
        assert_eq!(b.pubkeys[1].len(), 96);
        let r = apply(&cache, &b);
        assert_eq!(
            (r.high_water, code(&r)),
            (0, Some(ErrorCode::ContractViolation))
        );
    }

    #[test]
    fn poisoned_cache_refuses_the_frame() {
        let cache = SharedCache::default();
        let c2 = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _g = c2.write().unwrap();
            panic!("poison");
        })
        .join();
        let r = apply(&cache, &body(0, 0..1));
        assert_eq!(code(&r), Some(ErrorCode::ResourceUnavailable));
    }

    #[test]
    fn empty_frame_at_the_mark_is_a_no_op() {
        let cache = SharedCache::default();
        let r = apply(&cache, &body(0, []));
        assert_eq!((r.high_water, code(&r)), (0, None));
    }
}
