//! BuilderKeyFeed: cl-chain feeds the builder registry of its finalized state to the builder key
//! cache ([`cl_verify_cache::builders`]).
//!
//! A frame carries the entries `start_index .. start_index + count`. The namespace must be
//! `KEY_NAMESPACE_BUILDER`, `count` must equal the number of entries and be at most
//! [`MAX_ENTRIES_PER_FRAME`], `start_index` must be at most the high-water mark, and every key
//! must decompress and pass `KeyValidate` from exactly 48 compressed bytes. Anything else is
//! `ERROR_CODE_CONTRACT_VIOLATION` (an unknown non-zero namespace is
//! `ERROR_CODE_VERSION_MISMATCH`), and nothing of the frame is applied. An entry below the mark
//! replaces the cached entry of its index: the builder registry is not append-only.
//!
//! The cache is in memory only: no snapshot holds it, and a started server has an empty one
//! until cl-chain feeds it. Every reply carries the high-water mark.

use std::sync::{Arc, PoisonError, RwLock};

use blst::min_pk::PublicKey;
use cl_verify_cache::{BuilderEntry, BuilderKeyCache, CompressedPubkey};

use crate::bls::decode_pubkey;
use crate::feed::FrameEpochs;
use crate::proto::common::{Error, ErrorCode};
use crate::proto::verify::{
    BuilderKeyEntry, BuilderKeyFeedRequestBody, BuilderKeyFeedResponseBody, KeyNamespace,
};
use crate::wire::wire_error;

/// The builder key cache shared by the builder feed (writer) and BLS verification (readers).
pub type SharedBuilderCache = Arc<RwLock<BuilderKeyCache<PublicKey>>>;

/// Most entries one builder feed frame may carry (about 220 KiB of protobuf).
pub const MAX_ENTRIES_PER_FRAME: usize = 4_096;

/// The current high-water mark, as sent right after the hello.
pub fn status(cache: &RwLock<BuilderKeyCache<PublicKey>>) -> BuilderKeyFeedResponseBody {
    reply(cache, None)
}

/// The namespace rule of a frame: `KEY_NAMESPACE_BUILDER` only. `UNSPECIFIED` and
/// `KEY_NAMESPACE_VALIDATOR` are contract violations; an unknown non-zero value is a version
/// mismatch, and the frame is not looked at further.
pub fn check_namespace(body: &BuilderKeyFeedRequestBody) -> Result<(), Error> {
    match KeyNamespace::try_from(body.namespace) {
        Ok(KeyNamespace::Builder) => Ok(()),
        Ok(KeyNamespace::Unspecified) => Err(violation("KEY_NAMESPACE_UNSPECIFIED")),
        Ok(KeyNamespace::Validator) => {
            Err(violation("KEY_NAMESPACE_VALIDATOR on the builder key feed"))
        }
        Err(_) => Err(wire_error(
            ErrorCode::VersionMismatch,
            format!("unknown KeyNamespace {}", body.namespace),
        )),
    }
}

/// The finalized epochs a frame carries.
#[must_use]
pub fn epochs(body: &BuilderKeyFeedRequestBody) -> FrameEpochs {
    FrameEpochs {
        feed_finalized_epoch: body.feed_finalized_epoch,
        chain_finalized_epoch: body.chain_finalized_epoch,
    }
}

/// Applies one frame and returns the reply. Keys are decoded and validated before the write lock
/// is taken, so readers are blocked only for the write itself.
pub fn apply(
    cache: &RwLock<BuilderKeyCache<PublicKey>>,
    body: &BuilderKeyFeedRequestBody,
) -> BuilderKeyFeedResponseBody {
    let result = check_namespace(body)
        .and_then(|()| check_shape(cache, body))
        .and_then(|()| decode_entries(body))
        .and_then(|entries| {
            cache
                .write()
                .map_err(|_| poisoned())?
                .append_range(body.start_index, entries)
                .map_err(|e| violation(&e.to_string()))
        });
    reply(cache, result.err())
}

fn check_shape(
    cache: &RwLock<BuilderKeyCache<PublicKey>>,
    body: &BuilderKeyFeedRequestBody,
) -> Result<(), Error> {
    if usize::try_from(body.count).ok() != Some(body.entries.len()) {
        return Err(violation(&format!(
            "count {} != {} entries",
            body.count,
            body.entries.len()
        )));
    }
    if body.entries.len() > MAX_ENTRIES_PER_FRAME {
        return Err(violation(&format!(
            "{} entries exceed the cap of {MAX_ENTRIES_PER_FRAME} per frame",
            body.entries.len()
        )));
    }
    // Cheap early check; append_range checks again under the write lock.
    let high_water = high_water(cache);
    if body.start_index > high_water {
        return Err(violation(&format!(
            "start_index {} is past high_water {high_water}",
            body.start_index
        )));
    }
    Ok(())
}

fn decode_entries(body: &BuilderKeyFeedRequestBody) -> Result<Vec<BuilderEntry<PublicKey>>, Error> {
    body.entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            decode_entry(e).ok_or_else(|| {
                violation(&format!(
                    "builder {} pubkey is not a valid 48-byte compressed key",
                    body.start_index.saturating_add(i as u64)
                ))
            })
        })
        .collect()
}

fn decode_entry(entry: &BuilderKeyEntry) -> Option<BuilderEntry<PublicKey>> {
    let pubkey: CompressedPubkey = entry.pubkey.as_slice().try_into().ok()?;
    let key = decode_pubkey(&pubkey)?;
    Some(BuilderEntry::new(entry.key_version, pubkey, key))
}

fn reply(
    cache: &RwLock<BuilderKeyCache<PublicKey>>,
    err: Option<Error>,
) -> BuilderKeyFeedResponseBody {
    BuilderKeyFeedResponseBody {
        namespace: KeyNamespace::Builder as i32,
        high_water: high_water(cache),
        err,
    }
}

fn high_water(cache: &RwLock<BuilderKeyCache<PublicKey>>) -> u64 {
    cache
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .high_water()
}

fn violation(detail: &str) -> Error {
    wire_error(ErrorCode::ContractViolation, detail)
}

fn poisoned() -> Error {
    wire_error(
        ErrorCode::ResourceUnavailable,
        "builder key cache unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use blst::min_pk::SecretKey;
    use cl_verify_cache::Lookup;

    fn pk(i: u64) -> PublicKey {
        let mut ikm = [0x6bu8; 32];
        ikm[..8].copy_from_slice(&i.to_le_bytes());
        SecretKey::key_gen(&ikm, &[]).unwrap().sk_to_pk()
    }

    fn entries(tags: impl IntoIterator<Item = u64>) -> Vec<BuilderKeyEntry> {
        tags.into_iter()
            .map(|t| BuilderKeyEntry {
                key_version: t,
                pubkey: pk(t).compress().to_vec(),
            })
            .collect()
    }

    fn frame(start: u64, tags: impl IntoIterator<Item = u64>) -> BuilderKeyFeedRequestBody {
        let entries = entries(tags);
        BuilderKeyFeedRequestBody {
            namespace: KeyNamespace::Builder as i32,
            start_index: start,
            count: entries.len() as u64,
            entries,
            feed_finalized_epoch: 0,
            chain_finalized_epoch: 0,
        }
    }

    fn outcome(r: &BuilderKeyFeedResponseBody) -> (u64, Option<ErrorCode>) {
        assert_eq!(r.namespace, KeyNamespace::Builder as i32);
        (r.high_water, r.err.as_ref().map(Error::code))
    }

    fn hit(cache: &SharedBuilderCache, index: u64, tag: u64) -> bool {
        matches!(
            cache
                .read()
                .unwrap()
                .resolve(index, tag, &pk(tag).compress()),
            Lookup::Known(_)
        )
    }

    #[test]
    fn frames_extend_and_overwrite_and_every_reply_reports_the_mark() {
        let cache = SharedBuilderCache::default();
        assert_eq!(outcome(&status(&cache)), (0, None));
        assert_eq!(outcome(&apply(&cache, &frame(0, 10..13))), (3, None));
        // A finalized index reuse at 1, and a new builder at 3.
        assert_eq!(outcome(&apply(&cache, &frame(1, [21, 12, 13]))), (4, None));
        assert!(!hit(&cache, 1, 11) && hit(&cache, 1, 21) && hit(&cache, 3, 13));
        // A finality update with no change.
        assert_eq!(outcome(&apply(&cache, &frame(4, []))), (4, None));
    }

    #[test]
    fn a_gap_a_miscount_and_an_oversized_frame_are_refused_whole() {
        let cache = SharedBuilderCache::default();
        apply(&cache, &frame(0, 0..2));
        let mut miscounted = frame(2, 2..4);
        miscounted.count = 3;
        let mut oversized = frame(2, []);
        oversized.entries = entries(std::iter::repeat_n(2, MAX_ENTRIES_PER_FRAME + 1));
        oversized.count = oversized.entries.len() as u64;
        for bad in [frame(3, 3..4), miscounted, oversized] {
            assert_eq!(
                outcome(&apply(&cache, &bad)),
                (2, Some(ErrorCode::ContractViolation))
            );
        }
        assert!(!hit(&cache, 2, 2));
    }

    #[test]
    fn one_invalid_key_refuses_the_whole_frame() {
        let cache = SharedBuilderCache::default();
        for bad_key in [vec![0xaa; 48], pk(1).serialize().to_vec(), vec![1; 47]] {
            let mut f = frame(0, 0..3);
            f.entries[1].pubkey = bad_key;
            assert_eq!(
                outcome(&apply(&cache, &f)),
                (0, Some(ErrorCode::ContractViolation))
            );
        }
        assert!(!hit(&cache, 0, 0), "nothing of the frame is applied");
    }

    #[test]
    fn only_the_builder_namespace_is_applied() {
        let cache = SharedBuilderCache::default();
        for (namespace, code) in [
            (
                KeyNamespace::Unspecified as i32,
                ErrorCode::ContractViolation,
            ),
            (KeyNamespace::Validator as i32, ErrorCode::ContractViolation),
            (99, ErrorCode::VersionMismatch),
        ] {
            let mut f = frame(0, 0..2);
            f.namespace = namespace;
            assert_eq!(outcome(&apply(&cache, &f)), (0, Some(code)));
            assert_eq!(check_namespace(&f).unwrap_err().code(), code);
        }
        assert_eq!(check_namespace(&frame(0, [])), Ok(()));
    }

    #[test]
    fn a_poisoned_cache_refuses_the_frame() {
        let cache = SharedBuilderCache::default();
        let c2 = Arc::clone(&cache);
        let _ = std::thread::spawn(move || {
            let _g = c2.write().unwrap();
            panic!("poison");
        })
        .join();
        let r = apply(&cache, &frame(0, 0..1));
        assert_eq!(
            r.err.map(|e| e.code()),
            Some(ErrorCode::ResourceUnavailable)
        );
    }

    #[test]
    fn a_frame_reports_its_epochs() {
        let mut f = frame(0, []);
        f.feed_finalized_epoch = 7;
        f.chain_finalized_epoch = 9;
        assert_eq!(
            epochs(&f),
            FrameEpochs {
                feed_finalized_epoch: 7,
                chain_finalized_epoch: 9
            }
        );
    }
}
