//! `chain.v1` `EventsService`: cl-chain's sequenced events (skeleton).

use crate::persist::durable::PayloadStatus;
use consensus_types::gloas;
use consensus_types::primitives::{BuilderIndex, Epoch, Hash32, Root, Slot};
use consensus_types::EthSpec;
use ethswarm_proto::chain as pb;
use ipc::stub::StubStream;
use ipc::Link;
use pb::events_service_server::EventsService;
use tonic::{Request, Response, Status};

/// The fork-choice head: the node `get_head` returned and what its state says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub slot: Slot,
    pub block: Root,
    pub state: Root,
    pub payload_status: PayloadStatus,
    pub previous_duty_dependent_root: Root,
    pub current_duty_dependent_root: Root,
    pub execution_optimistic: bool,
}

/// A block fork choice's `on_block` imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedBlock {
    pub slot: Slot,
    pub block: Root,
    pub execution_optimistic: bool,
    pub bid: Option<Bid>,
}

/// What a Gloas block's event names of its `signed_execution_payload_bid.message`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bid {
    pub builder_index: BuilderIndex,
    pub block_hash: Hash32,
}

impl<E: EthSpec> From<&gloas::ExecutionPayloadBid<E>> for Bid {
    fn from(_bid: &gloas::ExecutionPayloadBid<E>) -> Self {
        todo!()
    }
}

/// A new finalized checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub epoch: Epoch,
    pub block: Root,
    pub state: Root,
    pub execution_optimistic: bool,
}

/// The block tree fork choice holds.
pub trait BlockTree {
    /// The root and slot of the parent of `root`.
    fn parent(&self, root: &Root) -> Option<(Root, Slot)>;
}

/// The publisher of cl-chain's events.
#[derive(Clone, Debug)]
pub struct ChainEvents;

impl ChainEvents {
    #[must_use]
    pub fn new(_slots_per_epoch: u64) -> Self {
        todo!()
    }

    pub fn head(&self, _head: Head, _tree: &dyn BlockTree) {
        todo!()
    }

    pub fn block(&self, _block: &ImportedBlock) {
        todo!()
    }

    pub fn finalized(&self, _checkpoint: &Finalized) {
        todo!()
    }
}

/// `EventsService` over a [`ChainEvents`] bus.
#[derive(Clone, Debug)]
pub struct EventsServer;

impl EventsServer {
    #[must_use]
    pub fn new(_link: Link, _events: ChainEvents) -> Self {
        todo!()
    }
}

#[tonic::async_trait]
impl EventsService for EventsServer {
    type SubscribeStream = StubStream<pb::SubscribeResponse>;

    async fn subscribe(
        &self,
        _request: Request<pb::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_types::primitives::{Address, B256};
    use consensus_types::Minimal;
    use ethswarm_proto::common::{ErrorCode, Hello};
    use ipc::envelope::DigestTable;
    use ipc::hello::Generation;
    use ipc::ContractError;
    use network_config::{ForkName, ForkSchedule, ScheduledFork};
    use pb::subscribe_response::Frame;
    use pb::EventKind;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio_stream::StreamExt;

    /// `SLOTS_PER_EPOCH` of the minimal preset.
    const SLOTS: u64 = 8;

    const ALL: [EventKind; 4] = [
        EventKind::Head,
        EventKind::Block,
        EventKind::FinalizedCheckpoint,
        EventKind::ChainReorg,
    ];

    type Frames = StubStream<pb::SubscribeResponse>;

    fn link() -> Link {
        let at = |epoch| ScheduledFork {
            version: [7, 0, 0, 0],
            epoch,
        };
        let hello = Hello {
            api_version: 1,
            min_api_version: 1,
            max_api_version: 1,
            ..Default::default()
        };
        let digests = DigestTable::new(vec![(0, ForkName::Gloas, [1, 2, 3, 4])]).unwrap();
        Link::new::<Minimal>(hello, 1, ForkSchedule::new(at(0), at(0)).unwrap(), digests)
    }

    fn root(n: u8) -> Root {
        B256::repeat_byte(n)
    }

    /// The state root of block `n` in these tests.
    fn state(n: u8) -> Root {
        root(n | 0x80)
    }

    /// `root(n)` as the beacon API writes it.
    fn hex_of(root: Root) -> String {
        format!("0x{}", hex::encode(root))
    }

    /// The head on block `n` at `slot`.
    fn head(n: u8, slot: Slot, payload_status: PayloadStatus) -> Head {
        Head {
            slot,
            block: root(n),
            state: state(n),
            payload_status,
            previous_duty_dependent_root: root(0x71),
            current_duty_dependent_root: root(0x72),
            execution_optimistic: false,
        }
    }

    /// A block tree of `(block, slot, parent)`.
    struct Tree(HashMap<Root, (Slot, Root)>);

    fn tree(blocks: &[(u8, Slot, u8)]) -> Tree {
        Tree(
            blocks
                .iter()
                .map(|&(n, slot, parent)| (root(n), (slot, root(parent))))
                .collect(),
        )
    }

    impl BlockTree for Tree {
        fn parent(&self, root: &Root) -> Option<(Root, Slot)> {
            let (_, parent) = self.0.get(root)?;
            let (slot, _) = self.0.get(parent)?;
            Some((*parent, *slot))
        }
    }

    fn finalized(epoch: Epoch, n: u8) -> Finalized {
        Finalized {
            epoch,
            block: root(n),
            state: state(n),
            execution_optimistic: false,
        }
    }

    fn fulu_block(n: u8, slot: Slot) -> ImportedBlock {
        ImportedBlock {
            slot,
            block: root(n),
            execution_optimistic: false,
            bid: None,
        }
    }

    fn raw(kinds: &[EventKind]) -> Vec<i32> {
        kinds.iter().map(|k| *k as i32).collect()
    }

    fn request(kinds: Vec<i32>) -> pb::SubscribeRequest {
        pb::SubscribeRequest {
            kinds,
            resume_from_seq: 0,
            hello: Some(link().local()),
        }
    }

    async fn call(server: &EventsServer, request: pb::SubscribeRequest) -> Result<Frames, Status> {
        server
            .subscribe(Request::new(request))
            .await
            .map(Response::into_inner)
    }

    /// The next frame, within a few seconds.
    async fn next(frames: &mut Frames) -> Option<Result<pb::SubscribeResponse, Status>> {
        tokio::time::timeout(Duration::from_secs(5), frames.next())
            .await
            .expect("a frame in time")
    }

    /// A subscription to `kinds`, its hello (with a server generation) read.
    async fn open(server: &EventsServer, kinds: &[EventKind]) -> Frames {
        let mut frames = call(server, request(raw(kinds))).await.expect("subscribed");
        match next(&mut frames)
            .await
            .expect("a first frame")
            .unwrap()
            .frame
        {
            Some(Frame::Hello(hello)) => assert!(Generation::from_hello(&hello).is_ok()),
            other => panic!("first frame {other:?}"),
        }
        frames
    }

    async fn body(frames: &mut Frames) -> pb::SubscribeResponseBody {
        match next(frames).await.expect("a frame").unwrap().frame {
            Some(Frame::Body(body)) => body,
            other => panic!("not a body: {other:?}"),
        }
    }

    async fn bodies(frames: &mut Frames, n: usize) -> Vec<pb::SubscribeResponseBody> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(body(frames).await);
        }
        out
    }

    fn data(body: &pb::SubscribeResponseBody) -> Value {
        serde_json::from_slice(&body.data_json).expect("data_json is JSON")
    }

    fn kinds_of(bodies: &[pb::SubscribeResponseBody]) -> Vec<i32> {
        bodies.iter().map(|b| b.kind).collect()
    }

    fn bus() -> (ChainEvents, EventsServer) {
        let events = ChainEvents::new(SLOTS);
        let server = EventsServer::new(link(), events.clone());
        (events, server)
    }

    /// A head change is one HEAD frame: the head block's slot and root, and in `data_json` the
    /// beacon-API `head` fields with the fork-choice node's `payload_status`. Gloas: the same
    /// block turning full is a second HEAD (`head_v2`), and no re-org; the same node again is no
    /// event.
    #[tokio::test]
    async fn head_frame_carries_payload_status() {
        let (events, server) = bus();
        let mut frames = open(&server, &ALL).await;
        let tree = tree(&[(1, 9, 0), (2, 16, 1)]);

        events.head(head(1, 9, PayloadStatus::Empty), &tree);
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.root.as_slice(), b.optimistic),
            (EventKind::Head as i32, 9, root(1).as_slice(), false)
        );
        assert_eq!(
            data(&b),
            json!({
                "slot": "9",
                "block": hex_of(root(1)),
                "state": hex_of(state(1)),
                "epoch_transition": false,
                "previous_duty_dependent_root": hex_of(root(0x71)),
                "current_duty_dependent_root": hex_of(root(0x72)),
                "execution_optimistic": false,
                "payload_status": "empty",
            })
        );

        events.head(head(1, 9, PayloadStatus::Full), &tree);
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.root.as_slice()),
            (EventKind::Head as i32, root(1).as_slice())
        );
        assert_eq!(data(&b)["payload_status"], "full");

        // The same node again: nothing. The next head, in the next epoch, optimistic.
        events.head(head(1, 9, PayloadStatus::Full), &tree);
        let next_head = Head {
            execution_optimistic: true,
            ..head(2, 16, PayloadStatus::Empty)
        };
        events.head(next_head, &tree);
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.optimistic),
            (EventKind::Head as i32, 16, true)
        );
        let d = data(&b);
        assert_eq!(d["epoch_transition"], json!(true));
        assert_eq!(d["execution_optimistic"], json!(true));
        assert_eq!(d["payload_status"], "empty");
    }

    /// An imported Gloas block is a BLOCK frame whose `data_json` names its bid's
    /// `builder_index` and `block_hash` (quoted decimal, 0x hex); a Fulu block has neither.
    #[tokio::test]
    async fn block_frame_gloas_fields() {
        let (events, server) = bus();
        let mut frames = open(&server, &[EventKind::Block]).await;
        let bid = gloas::ExecutionPayloadBid::<Minimal> {
            parent_block_hash: B256::ZERO,
            parent_block_root: B256::ZERO,
            block_hash: B256::repeat_byte(0x12),
            prev_randao: B256::ZERO,
            fee_recipient: Address::ZERO,
            gas_limit: 0,
            builder_index: 42,
            slot: 10,
            value: 0,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: B256::ZERO,
        };
        events.block(&ImportedBlock {
            slot: 10,
            block: root(3),
            execution_optimistic: true,
            bid: Some(Bid::from(&bid)),
        });
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.root.as_slice(), b.optimistic),
            (EventKind::Block as i32, 10, root(3).as_slice(), true)
        );
        assert_eq!(
            data(&b),
            json!({
                "slot": "10",
                "block": hex_of(root(3)),
                "execution_optimistic": true,
                "builder_index": "42",
                "block_hash": format!("0x{}", "12".repeat(32)),
            })
        );

        // A self-built block: BUILDER_INDEX_SELF_BUILD, quoted in full.
        let self_built = gloas::ExecutionPayloadBid {
            builder_index: consensus_types::signing::BUILDER_INDEX_SELF_BUILD,
            ..bid
        };
        events.block(&ImportedBlock {
            slot: 11,
            block: root(4),
            execution_optimistic: false,
            bid: Some(Bid::from(&self_built)),
        });
        assert_eq!(
            data(&body(&mut frames).await)["builder_index"],
            "18446744073709551615"
        );

        events.block(&fulu_block(5, 12));
        assert_eq!(
            data(&body(&mut frames).await),
            json!({"slot": "12", "block": hex_of(root(5)), "execution_optimistic": false})
        );
    }

    /// A new finalized checkpoint is a FINALIZED_CHECKPOINT frame at its epoch's start slot.
    #[tokio::test]
    async fn finalized_checkpoint_frame() {
        let (events, server) = bus();
        let mut frames = open(&server, &[EventKind::FinalizedCheckpoint]).await;
        events.finalized(&Finalized {
            execution_optimistic: true,
            ..finalized(3, 5)
        });
        let b = body(&mut frames).await;
        assert_eq!(
            (b.kind, b.slot, b.root.as_slice(), b.optimistic),
            (
                EventKind::FinalizedCheckpoint as i32,
                3 * SLOTS,
                root(5).as_slice(),
                true
            )
        );
        assert_eq!(
            data(&b),
            json!({
                "block": hex_of(root(5)),
                "state": hex_of(state(5)),
                "epoch": "3",
                "execution_optimistic": true,
            })
        );
    }

    /// The new head is on another branch: CHAIN_REORG, then HEAD. `depth` is the old head's
    /// slot less the common ancestor's, both ways.
    #[tokio::test]
    async fn reorg_when_old_head_not_ancestor() {
        let (events, server) = bus();
        let mut frames = open(&server, &ALL).await;
        // 0 ← 1 ← 2 ← 3, and 1 ← 4 ← 5.
        let tree = tree(&[(1, 1, 0), (2, 2, 1), (3, 3, 2), (4, 4, 1), (5, 9, 4)]);

        events.head(head(3, 3, PayloadStatus::Full), &tree);
        assert_eq!(body(&mut frames).await.kind, EventKind::Head as i32);

        let new_head = Head {
            execution_optimistic: true,
            ..head(5, 9, PayloadStatus::Empty)
        };
        events.head(new_head, &tree);
        let [reorg, head_frame] = <[_; 2]>::try_from(bodies(&mut frames, 2).await).unwrap();
        assert_eq!(
            (
                reorg.kind,
                reorg.slot,
                reorg.root.as_slice(),
                reorg.optimistic
            ),
            (EventKind::ChainReorg as i32, 9, root(5).as_slice(), true)
        );
        assert_eq!(
            data(&reorg),
            json!({
                "slot": "9",
                "depth": "2",
                "old_head_block": hex_of(root(3)),
                "new_head_block": hex_of(root(5)),
                "old_head_state": hex_of(state(3)),
                "new_head_state": hex_of(state(5)),
                "epoch": "1",
                "execution_optimistic": true,
            })
        );
        assert_eq!(
            (head_frame.kind, head_frame.root.as_slice()),
            (EventKind::Head as i32, root(5).as_slice())
        );

        // Back to the shorter branch: the old head (slot 9) is 8 slots past block 1.
        events.head(head(3, 3, PayloadStatus::Full), &tree);
        let [reorg, head_frame] = <[_; 2]>::try_from(bodies(&mut frames, 2).await).unwrap();
        assert_eq!(reorg.kind, EventKind::ChainReorg as i32);
        let d = data(&reorg);
        assert_eq!(
            (&d["slot"], &d["depth"], &d["epoch"]),
            (&json!("3"), &json!("8"), &json!("0"))
        );
        assert_eq!(
            (&d["old_head_block"], &d["new_head_block"]),
            (&json!(hex_of(root(5))), &json!(hex_of(root(3))))
        );
        assert_eq!(d["execution_optimistic"], json!(false));
        assert_eq!(head_frame.kind, EventKind::Head as i32);
    }

    /// A head that extends the old one, even past a block, is HEAD only.
    #[tokio::test]
    async fn no_reorg_on_extension() {
        let (events, server) = bus();
        let mut frames = open(&server, &ALL).await;
        let tree = tree(&[(1, 1, 0), (2, 2, 1), (3, 3, 2)]);
        events.head(head(1, 1, PayloadStatus::Full), &tree);
        events.head(head(3, 3, PayloadStatus::Full), &tree);
        events.finalized(&finalized(0, 1));
        let got = bodies(&mut frames, 3).await;
        assert_eq!(
            kinds_of(&got),
            raw(&[
                EventKind::Head,
                EventKind::Head,
                EventKind::FinalizedCheckpoint
            ])
        );
        assert_eq!(got[1].root.as_slice(), root(3).as_slice());
    }

    /// A subscriber gets only the kinds it asked for (a kind named twice once, an unknown
    /// non-zero kind ignored); a request that names no v1 kind is refused.
    #[tokio::test]
    async fn kinds_filter() {
        let (events, server) = bus();
        let mut blocks = call(
            &server,
            request(vec![EventKind::Block as i32, EventKind::Block as i32, 99]),
        )
        .await
        .expect("subscribed");
        assert!(matches!(
            next(&mut blocks).await.unwrap().unwrap().frame,
            Some(Frame::Hello(_))
        ));
        let mut heads = open(&server, &[EventKind::Head, EventKind::FinalizedCheckpoint]).await;

        let tree = tree(&[]);
        events.head(head(1, 1, PayloadStatus::Full), &tree);
        events.block(&fulu_block(2, 2));
        events.finalized(&finalized(1, 1));
        events.block(&fulu_block(3, 3));
        events.finalized(&finalized(2, 3));

        let got = bodies(&mut blocks, 2).await;
        assert_eq!(kinds_of(&got), raw(&[EventKind::Block, EventKind::Block]));
        assert_eq!(
            (got[0].slot, got[1].slot),
            (2, 3),
            "each block once, in order"
        );
        let got = bodies(&mut heads, 3).await;
        assert_eq!(
            kinds_of(&got),
            raw(&[
                EventKind::Head,
                EventKind::FinalizedCheckpoint,
                EventKind::FinalizedCheckpoint
            ])
        );

        for kinds in [vec![], vec![99]] {
            let refused = call(&server, request(kinds.clone())).await.err();
            assert_eq!(
                refused.map(|s| s.code()),
                Some(tonic::Code::InvalidArgument),
                "{kinds:?}"
            );
        }
    }

    /// `seq` is cl-chain's, not the stream's: from 1, gap-free across every kind, so a
    /// filtered stream sees a strictly increasing subsequence and a later stream goes on from
    /// where the bus is.
    #[tokio::test]
    async fn seq_monotonic() {
        let (events, server) = bus();
        let mut all = open(&server, &ALL).await;
        let mut finality = open(&server, &[EventKind::FinalizedCheckpoint]).await;
        let tree = tree(&[(0, 0, 0xff), (1, 1, 0), (2, 2, 0)]);

        events.head(head(1, 1, PayloadStatus::Full), &tree);
        events.block(&fulu_block(2, 2));
        events.finalized(&finalized(0, 0));
        // A re-org: CHAIN_REORG and HEAD, two seqs.
        events.head(head(2, 2, PayloadStatus::Full), &tree);
        events.finalized(&finalized(1, 2));

        let seqs: Vec<u64> = bodies(&mut all, 6).await.iter().map(|b| b.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5, 6]);
        let seqs: Vec<u64> = bodies(&mut finality, 2)
            .await
            .iter()
            .map(|b| b.seq)
            .collect();
        assert_eq!(seqs, [3, 6]);

        let mut later = open(&server, &[EventKind::Block]).await;
        events.block(&fulu_block(3, 3));
        assert_eq!(body(&mut later).await.seq, 7);
        assert_eq!(body(&mut all).await.seq, 7);
    }

    /// Kinds outside v1 (5–8) are refused with INVALID_ARGUMENT, alone or beside a v1 kind;
    /// `EVENT_KIND_UNSPECIFIED` too, as the contract violation it is.
    #[tokio::test]
    async fn out_of_v1_kind_rejected() {
        let link = link();
        let server = EventsServer::new(link.clone(), ChainEvents::new(SLOTS));
        for kind in [
            EventKind::ExecutionPayload,
            EventKind::PayloadAttestation,
            EventKind::DataColumnSidecar,
            EventKind::ForkSchedule,
        ] {
            for kinds in [vec![kind as i32], vec![EventKind::Head as i32, kind as i32]] {
                let refused = call(&server, request(kinds)).await.err();
                assert_eq!(
                    refused.map(|s| s.code()),
                    Some(tonic::Code::InvalidArgument),
                    "{kind:?}"
                );
            }
        }
        assert_eq!(link.metrics().counts().contract_violations, 0);

        let refused = call(&server, request(vec![EventKind::Head as i32, 0]))
            .await
            .err()
            .expect("UNSPECIFIED refused");
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            ContractError::from_status(&refused).code(),
            ErrorCode::ContractViolation
        );
        assert_eq!(link.metrics().counts().contract_violations, 1);
    }
}
