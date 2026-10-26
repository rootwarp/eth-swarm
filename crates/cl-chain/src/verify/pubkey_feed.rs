//! cl-chain's side of `verify.v1` `BuilderKeyFeed`, and the builder signers of `VerifyBls`.
//!
//! cl-verify keeps Gloas builder keys in a cache separate from the validator one. cl-chain feeds
//! it only the builder registry of a *finalized* state ([`BuilderFeed::frames`], in frames of
//! [`BUILDER_CHUNK_ENTRIES`]), so nothing above finality is cached and a reorg rolls nothing back.
//!
//! # Builder indices are reusable
//!
//! A builder that exited and that the builders sweep paid out frees its index, and a new key can
//! take it (`gloas/beacon-chain.md` L2322-2331), also on a branch that is not finalized. A cached
//! entry is therefore never a safe key on its own, and the key version (`builder_key_version`, a
//! 64-bit digest of the key) is a lookup hint only. Each builder signer carries the full key of
//! `state.builders[index]` of the state that the signature is verified against
//! ([`builder_signer`]), and cl-verify uses its cached key only if the version AND the 48 bytes
//! are equal. On import the signer carries its key inline unless cl-verify acknowledged exactly
//! that entry ([`BuilderFeed::needs_inline`]). On gossip it never does: an active builder has a
//! finalized placement (`is_active_builder`), and a lagging cache only costs an IGNORE.
//!
//! # Stream
//!
//! After the hello, cl-verify sends its builder high-water mark. [`BuilderFeed::start`] needs
//! that first response: a stream without it is a contract violation. On every new stream
//! cl-chain sends the whole finalized registry again from index 0 (a frame may overwrite
//! entries), and on every finality update the entries from the lowest index that changed (one
//! empty frame if nothing changed, which reports the lag). Each reply must acknowledge its frame
//! ([`BuilderFeed::on_reply`]): cl-verify keeps its cache across a reconnect, so a replayed frame
//! below its high-water mark leaves that mark. cl-verify lets only the newest stream write: a new
//! stream fences the older one, which fails with `RESOURCE_UNAVAILABLE`.

use consensus_types::gloas::BeaconState;
use consensus_types::primitives::{BLSPubkey, BuilderIndex};
use ethswarm_proto::verify::{
    BuilderKeyEntry, BuilderKeyFeedRequestBody, BuilderKeyFeedResponseBody, BuilderSigner,
    KeyNamespace, Signer, VerifyOrigin,
};
use state_transition::accessors::builder_key_version;
use state_transition::{Preset, StfError};

/// Most entries in one builder feed frame (verify.v1: at most 4,096 per frame, about 220 KiB).
pub const BUILDER_CHUNK_ENTRIES: usize = 4_096;

/// The finalized epochs a builder feed frame reports (verify.v1 Lag).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedEpochs {
    /// The finalized checkpoint epoch whose whole builder registry cl-verify holds once the frame
    /// is applied.
    pub feed_finalized_epoch: u64,
    /// cl-chain's finalized checkpoint epoch when it sends the frame.
    pub chain_finalized_epoch: u64,
}

/// Why the builder feed cannot go on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuilderFeedError {
    /// cl-verify broke the contract, or refused a frame (`ERROR_CODE_CONTRACT_VIOLATION`). The
    /// caller drops the stream and opens a new one.
    #[error("builder key feed contract violation: {0}")]
    ContractViolation(String),
    /// [`BuilderFeed::frames`] before the stream's first response.
    #[error("no first response on the builder key feed yet")]
    NotStarted,
    /// The state has no builder at an index that was asked for.
    #[error("builder registry: {0}")]
    State(#[from] StfError),
}

/// The frames that carry `state.builders[start..]`, in chunks of [`BUILDER_CHUNK_ENTRIES`], with
/// the key version of each entry from `state`. At the end of the registry, one empty frame at
/// `start`. All frames carry `epochs`. A `start` past the registry is
/// [`StfError::UnknownBuilder`].
pub fn builder_chunks<E: Preset>(
    state: &BeaconState<E>,
    start: u64,
    epochs: FeedEpochs,
) -> Result<Vec<BuilderKeyFeedRequestBody>, StfError> {
    let len = state.builders.len() as u64;
    if start > len {
        return Err(StfError::UnknownBuilder(start));
    }
    let entries = (start..len)
        .map(|i| {
            Ok(BuilderKeyEntry {
                key_version: builder_key_version(state, i)?,
                pubkey: builder_pubkey(state, i)?.to_vec(),
            })
        })
        .collect::<Result<Vec<_>, StfError>>()?;
    if entries.is_empty() {
        return Ok(vec![frame(start, Vec::new(), epochs)]);
    }
    Ok(entries
        .chunks(BUILDER_CHUNK_ENTRIES)
        .zip((start..).step_by(BUILDER_CHUNK_ENTRIES))
        .map(|(chunk, at)| frame(at, chunk.to_vec(), epochs))
        .collect())
}

fn frame(
    start: u64,
    entries: Vec<BuilderKeyEntry>,
    epochs: FeedEpochs,
) -> BuilderKeyFeedRequestBody {
    BuilderKeyFeedRequestBody {
        namespace: KeyNamespace::Builder as i32,
        start_index: start,
        count: entries.len() as u64,
        entries,
        feed_finalized_epoch: epochs.feed_finalized_epoch,
        chain_finalized_epoch: epochs.chain_finalized_epoch,
    }
}

fn builder_pubkey<E: Preset>(
    state: &BeaconState<E>,
    index: BuilderIndex,
) -> Result<BLSPubkey, StfError> {
    usize::try_from(index)
        .ok()
        .and_then(|i| state.builders.get(i))
        .map(|b| b.pubkey)
        .ok_or(StfError::UnknownBuilder(index))
}

/// One builder entry as cl-verify acknowledged it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Acked {
    version: u64,
    pubkey: BLSPubkey,
}

/// cl-chain's view of cl-verify's builder cache on one BuilderKeyFeed stream: the entries that
/// cl-verify acknowledged, and the frames that bring it to a newer finalized registry.
#[derive(Debug, Default)]
pub struct BuilderFeed {
    started: bool,
    acked: Vec<Acked>,
    /// cl-verify's builder high-water mark: from the first response, then from each reply. It
    /// can be above `acked.len()`: cl-verify keeps its cache across a reconnect, and cl-chain
    /// acknowledges only what it sent on this stream.
    remote_high_water: u64,
    /// The finalized epoch whose whole builder registry cl-verify acknowledged on this stream.
    fed_epoch: Option<u64>,
}

impl BuilderFeed {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the stream's first response (cl-verify's builder high-water mark, sent right after
    /// the hello) and returns that mark. A missing first response, one of another namespace or
    /// one with an error is a contract violation. Nothing that an earlier stream acknowledged is
    /// kept: the next [`frames`](Self::frames) resend the whole registry from 0.
    pub fn start(
        &mut self,
        first: Option<&BuilderKeyFeedResponseBody>,
    ) -> Result<u64, BuilderFeedError> {
        let first = first.ok_or_else(|| {
            violation("the builder key feed sent no first response after its hello")
        })?;
        check_reply(first)?;
        self.acked.clear();
        self.fed_epoch = None;
        self.remote_high_water = first.high_water;
        self.started = true;
        Ok(first.high_water)
    }

    /// The frames that bring cl-verify to the builder registry of `finalized`, a finalized
    /// checkpoint state: from the lowest index whose entry is not the acknowledged one, to the
    /// end. If nothing changed, one empty frame that reports `epochs`. Every frame carries
    /// `epochs.chain_finalized_epoch`; only the last one carries `epochs.feed_finalized_epoch`,
    /// and the earlier ones the epoch that cl-verify last acknowledged on this stream (0 if none).
    pub fn frames<E: Preset>(
        &self,
        finalized: &BeaconState<E>,
        epochs: FeedEpochs,
    ) -> Result<Vec<BuilderKeyFeedRequestBody>, BuilderFeedError> {
        if !self.started {
            return Err(BuilderFeedError::NotStarted);
        }
        let mut from = self.acked.len() as u64;
        for (i, acked) in (0u64..).zip(&self.acked) {
            if i >= finalized.builders.len() as u64 || *acked != entry_of(finalized, i)? {
                from = i;
                break;
            }
        }
        let mut frames = builder_chunks(finalized, from, epochs)?;
        // Until the last frame lands, cl-verify holds only the registry it had before.
        let before = self.fed_epoch.unwrap_or(0).min(epochs.feed_finalized_epoch);
        if let Some((_, earlier)) = frames.split_last_mut() {
            for frame in earlier {
                frame.feed_finalized_epoch = before;
            }
        }
        Ok(frames)
    }

    /// Takes cl-verify's reply to `sent`. The reply must be of the builder namespace, carry no
    /// error and report the high-water mark that `sent` gives: the end of `sent`, or cl-verify's
    /// earlier mark if that is higher (a frame below the mark overwrites entries and leaves the
    /// mark). Anything else (or no reply) is a contract violation and acknowledges nothing.
    pub fn on_reply(
        &mut self,
        sent: &BuilderKeyFeedRequestBody,
        reply: Option<&BuilderKeyFeedResponseBody>,
    ) -> Result<(), BuilderFeedError> {
        let reply =
            reply.ok_or_else(|| violation("the builder key feed closed before its reply"))?;
        check_reply(reply)?;
        let end = sent.start_index.saturating_add(sent.count);
        let expected = end.max(self.remote_high_water);
        if reply.high_water != expected {
            return Err(violation(&format!(
                "builder key feed reply high_water {} != {expected}",
                reply.high_water
            )));
        }
        let entries = sent
            .entries
            .iter()
            .map(|e| {
                BLSPubkey::try_from(e.pubkey.as_slice())
                    .map(|pubkey| Acked {
                        version: e.key_version,
                        pubkey,
                    })
                    .map_err(|_| violation("a sent builder pubkey is not 48 bytes"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (i, acked) in (sent.start_index..).zip(entries) {
            match usize::try_from(i).ok().and_then(|i| self.acked.get_mut(i)) {
                Some(slot) => *slot = acked,
                None => self.acked.push(acked),
            }
        }
        self.fed_epoch = Some(sent.feed_finalized_epoch);
        self.remote_high_water = reply.high_water;
        Ok(())
    }

    /// Whether builder `index` with key `pubkey` (key version `version`) of the branch state must
    /// travel inline on import: cl-verify has not acknowledged exactly that entry.
    #[must_use]
    pub fn needs_inline(&self, index: BuilderIndex, version: u64, pubkey: &BLSPubkey) -> bool {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.acked.get(i))
            .is_none_or(|a| a.version != version || a.pubkey != *pubkey)
    }
}

fn entry_of<E: Preset>(state: &BeaconState<E>, index: BuilderIndex) -> Result<Acked, StfError> {
    Ok(Acked {
        version: builder_key_version(state, index)?,
        pubkey: builder_pubkey(state, index)?,
    })
}

/// The `verify.v1` signer for `state.builders[index]` of `state`, the state that the signature is
/// verified against: the builder namespace, the key version and the full key. It is inline on
/// import if `feed` has not acknowledged that entry, and never inline on gossip.
pub fn builder_signer<E: Preset>(
    state: &BeaconState<E>,
    index: BuilderIndex,
    origin: VerifyOrigin,
    feed: &BuilderFeed,
) -> Result<Signer, BuilderFeedError> {
    let Acked { version, pubkey } = entry_of(state, index)?;
    let inline = origin == VerifyOrigin::Import && feed.needs_inline(index, version, &pubkey);
    Ok(Signer {
        validator_index: 0,
        inline_pubkey: Vec::new(),
        namespace: KeyNamespace::Builder as i32,
        builder: Some(BuilderSigner {
            builder_index: index,
            key_version: version,
            pubkey: pubkey.to_vec(),
            inline,
        }),
    })
}

fn check_reply(reply: &BuilderKeyFeedResponseBody) -> Result<(), BuilderFeedError> {
    if reply.namespace != KeyNamespace::Builder as i32 {
        return Err(violation(&format!(
            "builder key feed reply of namespace {}",
            reply.namespace
        )));
    }
    if let Some(err) = &reply.err {
        return Err(violation(&format!(
            "builder key feed frame refused ({:?}): {}",
            err.code(),
            err.detail
        )));
    }
    Ok(())
}

fn violation(detail: &str) -> BuilderFeedError {
    BuilderFeedError::ContractViolation(detail.to_owned())
}

#[cfg(test)]
pub(crate) mod test_state;

#[cfg(test)]
mod tests {
    use super::test_state::state_with_builders;
    use super::*;
    use consensus_types::Minimal;
    use state_transition::accessors::builder_key_version;

    fn epochs(feed: u64, chain: u64) -> FeedEpochs {
        FeedEpochs {
            feed_finalized_epoch: feed,
            chain_finalized_epoch: chain,
        }
    }

    fn reply(high_water: u64) -> BuilderKeyFeedResponseBody {
        BuilderKeyFeedResponseBody {
            namespace: KeyNamespace::Builder as i32,
            high_water,
            err: None,
        }
    }

    /// A started feed that sent and had acknowledged every frame for `state`.
    fn fed(state: &BeaconState<Minimal>, epoch: u64) -> BuilderFeed {
        let mut feed = BuilderFeed::new();
        feed.start(Some(&reply(0))).unwrap();
        for frame in feed.frames(state, epochs(epoch, epoch)).unwrap() {
            let acked = frame.start_index + frame.count;
            feed.on_reply(&frame, Some(&reply(acked))).unwrap();
        }
        feed
    }

    #[test]
    fn version_from_state() {
        // An index reused with a new key, and a key that came back at another index.
        let mut state = state_with_builders::<Minimal>(&[0xa1, 0xa2, 0xa3]);
        state.builders.get_mut(0).unwrap().pubkey = [0xb1; 48];
        state
            .builders
            .push(state.builders.get(1).unwrap().clone())
            .unwrap();
        let frames = builder_chunks(&state, 0, epochs(3, 4)).unwrap();
        let entries: Vec<_> = frames.iter().flat_map(|f| &f.entries).collect();
        assert_eq!(entries.len(), state.builders.len());
        for (i, entry) in entries.iter().enumerate() {
            let i = i as u64;
            assert_eq!(entry.key_version, builder_key_version(&state, i).unwrap());
            assert_eq!(entry.pubkey, state.builders.get(i as usize).unwrap().pubkey);
        }
        assert_ne!(entries[0].key_version, entries[1].key_version);
        assert_eq!(entries[1].key_version, entries[3].key_version, "same key");
        assert!(frames
            .iter()
            .all(|f| f.namespace == KeyNamespace::Builder as i32));
    }

    #[test]
    fn chunks_start_where_asked_and_carry_the_epochs() {
        let state = state_with_builders::<Minimal>(&[1, 2, 3]);
        let frames = builder_chunks(&state, 1, epochs(3, 4)).unwrap();
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!((f.start_index, f.count, f.entries.len()), (1, 2, 2));
        assert_eq!((f.feed_finalized_epoch, f.chain_finalized_epoch), (3, 4));
        // At the end of the registry: one empty frame, the no-op that reports the lag.
        let at_end = builder_chunks(&state, 3, epochs(3, 4)).unwrap();
        assert_eq!(
            at_end
                .iter()
                .map(|f| (f.start_index, f.count))
                .collect::<Vec<_>>(),
            [(3, 0)]
        );
        assert!(builder_chunks(&state, 4, epochs(3, 4)).is_err());
    }

    #[test]
    fn a_feed_needs_a_first_response_of_the_builder_namespace() {
        let state = state_with_builders::<Minimal>(&[1]);
        let mut feed = BuilderFeed::new();
        assert!(matches!(
            feed.frames(&state, epochs(1, 1)),
            Err(BuilderFeedError::NotStarted)
        ));
        let mut validator = reply(0);
        validator.namespace = KeyNamespace::Validator as i32;
        let mut refused = reply(0);
        refused.err = Some(ethswarm_proto::common::Error::default());
        for bad in [None, Some(&validator), Some(&refused)] {
            assert!(matches!(
                feed.start(bad),
                Err(BuilderFeedError::ContractViolation(_))
            ));
        }
        assert_eq!(feed.start(Some(&reply(7))), Ok(7));
    }

    #[test]
    fn a_new_stream_resends_the_whole_registry_from_zero() {
        let state = state_with_builders::<Minimal>(&[1, 2]);
        let mut feed = fed(&state, 3);
        assert_eq!(feed.frames(&state, epochs(3, 3)).unwrap()[0].count, 0);
        // cl-verify restarted (high-water 0), or not (2): either way cl-chain resends from 0.
        for high_water in [0, 2] {
            feed.start(Some(&reply(high_water))).unwrap();
            let frames = feed.frames(&state, epochs(3, 3)).unwrap();
            assert_eq!((frames[0].start_index, frames[0].count), (0, 2));
        }
    }

    #[test]
    fn an_update_resends_from_the_lowest_changed_index() {
        let finalized = state_with_builders::<Minimal>(&[1, 2, 3, 4]);
        let mut feed = fed(&finalized, 3);
        // The next finalized state reused index 2 and added index 4.
        let mut next = finalized.clone();
        next.builders.get_mut(2).unwrap().pubkey = [9; 48];
        next.builders
            .push(next.builders.get(0).unwrap().clone())
            .unwrap();
        let frames = feed.frames(&next, epochs(4, 5)).unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|f| (f.start_index, f.count))
                .collect::<Vec<_>>(),
            [(2, 3)]
        );
        assert_eq!(
            (
                frames[0].feed_finalized_epoch,
                frames[0].chain_finalized_epoch
            ),
            (4, 5)
        );
        feed.on_reply(&frames[0], Some(&reply(5))).unwrap();
        assert_eq!(feed.frames(&next, epochs(4, 5)).unwrap()[0].start_index, 5);
    }

    #[test]
    fn a_multi_frame_update_reports_the_new_epoch_on_its_last_frame_only() {
        let keys: Vec<u8> = (0..BUILDER_CHUNK_ENTRIES + 1).map(|i| i as u8).collect();
        let finalized = state_with_builders::<Minimal>(&keys);
        let feed = fed(&finalized, 3);
        let mut next = finalized.clone();
        next.builders.get_mut(0).unwrap().pubkey = [0xee; 48];
        let frames = feed.frames(&next, epochs(4, 5)).unwrap();
        assert_eq!(
            frames
                .iter()
                .map(|f| (
                    f.start_index,
                    f.feed_finalized_epoch,
                    f.chain_finalized_epoch
                ))
                .collect::<Vec<_>>(),
            [(0, 3, 5), (BUILDER_CHUNK_ENTRIES as u64, 4, 5)]
        );
    }

    #[test]
    fn a_reconnect_to_a_cl_verify_that_kept_its_cache_replays_every_chunk() {
        let keys: Vec<u8> = (0..=BUILDER_CHUNK_ENTRIES).map(|i| i as u8).collect();
        let finalized = state_with_builders::<Minimal>(&keys);
        let held = finalized.builders.len() as u64;
        let mut feed = BuilderFeed::new();
        // cl-verify kept all 4,097 entries across the reconnect.
        assert_eq!(feed.start(Some(&reply(held))), Ok(held));
        let frames = feed.frames(&finalized, epochs(3, 3)).unwrap();
        assert_eq!(frames.len(), 2);
        for frame in &frames {
            // An overwrite below the mark leaves cl-verify's mark at 4,097.
            assert_eq!(feed.on_reply(frame, Some(&reply(held))), Ok(()));
        }
        // A reply below the mark it reported is still refused.
        let mut again = BuilderFeed::new();
        again.start(Some(&reply(held))).unwrap();
        assert!(matches!(
            again.on_reply(&frames[0], Some(&reply(BUILDER_CHUNK_ENTRIES as u64))),
            Err(BuilderFeedError::ContractViolation(_))
        ));
        let key = finalized.builders.get(0).unwrap().pubkey;
        let version = builder_key_version(&finalized, 0).unwrap();
        assert!(
            !feed.needs_inline(0, version, &key),
            "acknowledged after the replay"
        );
    }

    #[test]
    fn a_reply_must_acknowledge_the_frame() {
        let state = state_with_builders::<Minimal>(&[1, 2]);
        let mut feed = BuilderFeed::new();
        feed.start(Some(&reply(0))).unwrap();
        let frame = feed.frames(&state, epochs(1, 1)).unwrap().remove(0);
        let mut refused = reply(0);
        refused.err = Some(ethswarm_proto::common::Error::default());
        let mut validator = reply(2);
        validator.namespace = KeyNamespace::Validator as i32;
        for bad in [None, Some(&reply(1)), Some(&refused), Some(&validator)] {
            assert!(matches!(
                feed.on_reply(&frame, bad),
                Err(BuilderFeedError::ContractViolation(_))
            ));
        }
        let mut short = frame.clone();
        short.entries[1].pubkey.pop();
        assert!(matches!(
            feed.on_reply(&short, Some(&reply(2))),
            Err(BuilderFeedError::ContractViolation(_))
        ));
        // Nothing was acknowledged: the builders still go inline.
        let key = state.builders.get(0).unwrap().pubkey;
        let version = builder_key_version(&state, 0).unwrap();
        assert!(feed.needs_inline(0, version, &key));
        feed.on_reply(&frame, Some(&reply(2))).unwrap();
        assert!(!feed.needs_inline(0, version, &key));
    }

    #[test]
    fn a_builder_goes_inline_on_import_unless_cl_verify_acknowledged_its_key() {
        let finalized = state_with_builders::<Minimal>(&[1, 2]);
        let feed = fed(&finalized, 3);
        // The branch reuses finalized index 1 and adds index 2 above finality.
        let mut branch = finalized.clone();
        branch.builders.get_mut(1).unwrap().pubkey = [7; 48];
        branch
            .builders
            .push(branch.builders.get(0).unwrap().clone())
            .unwrap();
        let inline = |index, origin| {
            let s = builder_signer(&branch, index, origin, &feed).unwrap();
            assert_eq!(s.namespace, KeyNamespace::Builder as i32);
            assert_eq!((s.validator_index, s.inline_pubkey.len()), (0, 0));
            let b = s.builder.unwrap();
            assert_eq!(b.builder_index, index);
            assert_eq!(b.key_version, builder_key_version(&branch, index).unwrap());
            assert_eq!(
                b.pubkey,
                branch.builders.get(index as usize).unwrap().pubkey
            );
            b.inline
        };
        assert!(!inline(0, VerifyOrigin::Import), "finalized and unchanged");
        assert!(inline(1, VerifyOrigin::Import), "reused on the branch");
        assert!(inline(2, VerifyOrigin::Import), "above finality");
        for index in 0..3 {
            assert!(
                !inline(index, VerifyOrigin::Gossip),
                "never inline on gossip"
            );
        }
        assert!(matches!(
            builder_signer(&branch, 3, VerifyOrigin::Import, &feed),
            Err(BuilderFeedError::State(_))
        ));
    }

    #[test]
    fn errors_name_their_cause() {
        assert!(BuilderFeedError::ContractViolation("x".into())
            .to_string()
            .contains('x'));
        assert!(BuilderFeedError::NotStarted
            .to_string()
            .contains("first response"));
    }
}
