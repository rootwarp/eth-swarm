# ethswarm protobuf contracts

These are the service-to-service contracts for the ETH Swarm beacon node. They are used with tonic and prost, and the spec pin is consensus-specs **v1.7.0-beta.4**.

## Layout
- `ethswarm/common/v1/` holds the shared types: `Envelope` (fork_digest, slot, root, ssz), `ForkSchedule`, `Verdict` (ACCEPT/REJECT/IGNORE), and the `Error`/`ErrorCode` model.
- Each package is owned by the service that **serves** it:
  - `ethswarm/chain/v1/` is served by cl-chain, the **single writer** for state transition, fork choice, DA status and ePBS. It contains `GossipService`, `ReqRespService`, `ImportService`, `QueryService` (fork choice, duties, produce, submit) and `EventsService` (sequenced events).
  - `ethswarm/store/v1/` is served by cl-store, the read side. It opens MDBX read-only and has **no write RPC**. It contains `StoreService`, which serves blocks, states, columns and envelopes by root or slot, plus head and finalized info, to cl-api and cl-sync. It follows chain's sequenced head and finalized events, so **head reads can be up to one write behind**. Every response carries the stamp `(as_of_seq, as_of_root, as_of_slot)` in `ReadMeta`: the chain head event the read was opened after.
  - `ethswarm/engine/v1/` is served by cl-engine and called only by cl-chain. It contains `EngineService`, an ordered, stateless Engine API adapter. The JWT secret lives only in cl-engine. Chain owns optimistic status and fcU ordering. Method versions: Fulu/Osaka uses newPayloadV4, fcUV3, getPayloadV5 and getBlobsV2/V3. Gloas/Amsterdam uses newPayloadV5, fcUV4, getPayloadV6 and getBlobsV4.
  - `ethswarm/p2p/v1/` is served by cl-p2p and contains `NetworkService`, for outbound peer requests and peer scoring.
  - `ethswarm/discv5/v1/` is served by cl-discv5 and contains `DiscoveryService`.
  - `ethswarm/sync/v1/` is served by cl-sync and contains `SyncService`.
  - `ethswarm/api/v1/` is served by cl-api and contains `ApiService` (health). The Beacon API itself is HTTP.

## Rules (normative)
1. **Decode SSZ by the fork of the object's slot**, never by the current fork. A message from the last slot before a fork boundary uses the pre-fork schema.
2. **A fork digest that doesn't match the slot's fork means drop and log a contract error** (`ERROR_CODE_FORK_DIGEST_MISMATCH`). The bytes are never decoded. From Fulu on, the digest also changes at BPO epochs (`specs/fulu/beacon-chain.md` `compute_fork_digest`), so look it up in the published `ForkSchedule`.
3. **`Envelope.payload_type` is a closed enum (`PayloadType`).**
   - `PAYLOAD_TYPE_UNSPECIFIED` (0) is a **contract error**. The receiver logs it, increments the contract-violation metric, and fails the call or stream with `ERROR_CODE_CONTRACT_VIOLATION`.
   - An unknown **non-zero** value from outside is IGNOREd: drop it, never decode it, never REJECT.
   - The SSZ schema is selected by (`payload_type`, fork of `slot`). New values are additive.
   - **The zero rule applies to every enum, with no exceptions** in these packages (`Verdict`, `ForkName`, `ErrorCode`, `Topic`, `DutyKind`, `ProduceKind`, `EventKind`, `SyncState`, `EngineMethodVersion`, `PayloadEncoding`, `PayloadStatusKind`, `EngineErrorKind`, `VerifyStatus`, `VerifyOrigin`). An `*_UNSPECIFIED` value on the wire means `ERROR_CODE_CONTRACT_VIOLATION`. The unknown non-zero rule (IGNORE) applies to every enum as well.
4. **Timeout or overload means IGNORE, never ACCEPT.** This applies to gossip verdicts, load shedding, and a core that isn't available. REJECT is only for a proven spec violation.
5. **Every `bytes` field documents its maximum size in a comment.** Use spec limits where they exist (`MAX_PAYLOAD_SIZE`, `MAX_REQUEST_*`, fixed-size roots and digests). Otherwise mark it `TODO(vera)`.
6. **Removed fields go into `reserved`** (both the number and the name).
7. **Field numbers are never reused.** Changes within `v1` are additive only, and a breaking change means a new `v2` package served alongside `v1`.
8. Every stream starts with `common.v1.Hello`, carrying the spec pin (consensus-specs and ssz-specs tags), the full fork schedule (version, epoch, digest per fork) and the BPO blob schedule (epoch, max_blobs). The receiver compares the **whole** handshake, not only `current_fork_digest`; any difference fails the stream with `ERROR_CODE_VERSION_MISMATCH`.

## Compatibility (hard rule): N and N-1
- **Additive only.** Never change a field's number, type, name or oneof membership, and never remove an RPC. A removed field goes into `reserved` (number and name). Field numbers are never reused.
- **Version range in `Hello`.** Each side advertises `min_api_version` and `max_api_version`, and the link uses the **highest common version**, min(max_a, max_b). The link fails with `ERROR_CODE_VERSION_MISMATCH` if there is no common version. There is **no fallback**: neither side retries with a lower version, an older package or an unversioned mode.
- **Floor.** Each service also enforces a **configured floor**, and a link below it fails. Every build accepts N and N-1. When we drop N-1, the floor rises to N, which prevents downgrades.
- **CI gate.** `scripts/buf-breaking.sh refs/remotes/origin/develop` (FILE rules) must pass on every PR. Without an argument the script checks against `refs/heads/develop` (else `refs/remotes/origin/develop`), and `--baseline` checks against the frozen `proto/.baseline/v1.binpb`. Short names are refused; pass `refs/...`.
- **Pre-v1 contract.** The contract is not frozen until v1 is tagged. Re-baselines are allowed before then, and each one gets its own commit that touches only the baseline and one README line.
- **After v1,** any re-baseline needs Ezra's sign-off.
- **How to re-baseline.** Run `buf build -o .baseline/v1.binpb` from `proto/`. Commit the result on its own, with one line in the re-baseline log below.

## Stream handshake: `oneof frame { hello; body }`
- **Streamed messages.** Every streamed message type is `oneof frame { ethswarm.common.v1.Hello hello = 1; <Msg>Body body = 2; }`. This covers every server-streamed response and every client-streamed request, including `ImportBatch` and `Subscribe`. `<Msg>Body` holds the payload, usually `Envelope`s plus metadata. `GossipService.Validate` uses the same `oneof frame { hello; batch/verdicts }`.
- **Exactly one hello, first.** Each stream direction must start with exactly one `hello` frame, and every later frame must be `body`. Any of the following is `ERROR_CODE_CONTRACT_VIOLATION`, and the stream is closed:
  - a first frame that isn't `hello`
  - a `hello` mid-stream
  - a frame with neither field set
- **Server-streaming requests.** The client sends exactly one request, so that request carries `Hello hello` in-line as a required field, and leaving it out is a contract violation. The server's response stream still opens with its own `hello` frame.
- **Unary calls** carry no Hello. They rely on the handshake already exchanged on the peers' streams.
- **`Envelope.seq`** increases strictly from 1 per stream direction. A non-monotonic seq (gap, repeat or decrease) is `ERROR_CODE_CONTRACT_VIOLATION`, and receivers never reorder silently.
- **`Envelope.trace_id`** is a 16-byte W3C trace id, with a documented max of 32 bytes.
- **Debugging and ordering only.** `trace_id` and `seq` are never used for auth or dedup.

## Tooling
`buf.yaml` sets lint to `STANDARD` and breaking checks to `FILE`. Run `buf lint && buf build` from this directory.
`scripts/check-proto-baseline.sh` fails if the committed `.baseline/v1.binpb` differs from a fresh `buf build -o` of the current sources (comments included), so the committed baseline stays in sync with the sources. It requires the buf version the baseline was built with (pinned in the script) and runs offline; its tests are `bash scripts/tests/check-proto-baseline-test.sh`. It does not decide what `buf breaking` compares against: `scripts/buf-breaking.sh` compares against the given `refs/...` ref (default `refs/heads/develop`, else `refs/remotes/origin/develop`), and against `.baseline/v1.binpb` only with `--baseline`.

## SSZ specification citation (pinned)
- consensus-specs v1.7.0-beta.4 does not contain the SSZ spec. `ssz/` was removed in ethereum/consensus-specs#5523 (commit `498449f`, 2026-08-12), and the spec moved to **ethereum/ssz-specs**. The tag's `README.md` and `specs/phase0/beacon-chain.md` link to that repo without a version.
- **Pinned citation:** `ethereum/ssz-specs` tag **`v0.1.0`** (commit `7bce07ff7d51b1a3c66ff4e2bd3233ac248ede70`). This is the exact version that beta.4 depends on: `pyproject.toml` has `eth-ssz-specs==0.1.0`.
  - Serialization and types (replaces `simple-serialize.md`): `README.md` §Types plus `src/ssz/*.py`, which is the executable reference.
  - Merkleization, generalized indices and proofs (replaces `merkle-proofs.md`): `src/ssz/roots.py`, `src/ssz/trees.py`, `src/ssz/gindex.py`, `src/ssz/paths.py`, `src/ssz/proofs.py`, `src/ssz/verification.py`.
  - Historical prose for reading only: `ethereum/consensus-specs@0ddf13b3dcdae1cc855c9aa8aa28af5e8c6f3c82` `ssz/simple-serialize.md` and `ssz/merkle-proofs.md`. This is the last commit before removal, and it is not normative for beta.4.
- **Test vectors:**
  - Generic SSZ vectors come from the ssz-specs release asset `ssz-test-vectors-v0.1.0.tar.gz`, which ships with a `.sha256` file. Its layout is `fixtures/<format>/<kind>/<valid|invalid>/<id>.json` with `manifest.json` (`specVersion`), and the formats are `ssz`, `ssz_type_rejection`, `ssz_gindex`, `proof`, `multiproof` and `ssz_json`.
  - `tests/formats/` at beta.4 has no `ssz_generic`.
  - `ssz_static`, which covers the consensus containers per fork, is still in consensus-spec-tests and is versioned with the consensus-specs release tag `v1.7.0-beta.4`.

- Per-item results (for example `SubmitResponse.results`) use `oneof result { ok; err }`. Leaving both unset is a contract error.
- **Re-baseline log.** On 2026-10-15, `.baseline/v1.binpb` was regenerated with `buf build -o .baseline/v1.binpb` after the pre-v1 `oneof frame { hello; body }` stream-handshake fix. It replaced the first-frame `hello` field workaround.
- **Re-baseline log.** On 2026-10-17, `.baseline/v1.binpb` was regenerated with `buf build -o .baseline/v1.binpb` to add the pre-v1 `ethswarm/verify/v1/verify.proto` contract, which the previous baseline did not contain, and the v1 contract-rule comment fixes. Additive only: no field, RPC or package was changed or removed.
- **Re-baseline log.** On 2026-10-17, `.baseline/v1.binpb` was regenerated with `buf build -o .baseline/v1.binpb` after the pre-v1 `ethswarm/verify/v1/verify.proto` update that specifies the inline-signer rules, the 1,024 inline packing cap, the inline bound and the PubkeyFeed hold-back rule, and adds the `VerifyOrigin` enum with the `VerifyBlsRequestBody.origin` field (4). Additive only: no field, RPC or package was changed or removed.
- **Re-baseline log.** On 2026-10-17, `.baseline/v1.binpb` was regenerated with `buf build -o .baseline/v1.binpb` after comment-only pre-v1 clarifications to `ethswarm/verify/v1/verify.proto`: the PubkeyFeed hold-back ends only when the matching VerifyBls response arrives, a pending range takes priority over new inline requests, the stream-gone wait and stalled-stream close add `MAX_CLOCK_SKEW_MS`, the deadline checks are ordered, and a zero-signer BLS set or a zero-cell VerifyKzg request is a contract violation. No field, RPC or package was added, changed or removed.
