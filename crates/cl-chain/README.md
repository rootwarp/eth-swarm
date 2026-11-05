# cl-chain

The `ethswarm.chain.v1` service: the single writer of the store env. The crate docs
(`src/lib.rs`) describe what it serves today; this file records values that need a review
outside the code.

## Non-finality disk budget (proposed values)

How much unfinalized data cl-chain keeps while finality stalls, and the free space it never
eats into (`cl_chain::persist::budget`, with its core in `store_schema::budget`). **Every value
below is proposed, pending Vera's review.** They are the compiled-in defaults
(`DiskBudget::default()`), and `tests/fixtures/budget.toml` holds them as a config table.
Operators override any of them in the `[chain.disk_budget]` table of
`/etc/ethswarm/cl-chain.toml` (sizes in MiB). An unknown key, or a per-type cap above the
aggregate, fails the start.

| Value | Proposed | Config key | Status |
|---|---|---|---|
| Aggregate unfinalized bytes, all kinds | 48 GiB | `aggregate_mib = 49152` | proposed |
| Columns | 32 GiB | `columns_mib = 32768` | proposed |
| States (compressed snapshots) | 8 GiB | `states_mib = 8192` | proposed |
| Fork-choice snapshots | 512 MiB | `fc_snapshots_mib = 512` | proposed |
| Execution payload envelopes | 4 GiB | `envelopes_mib = 4096` | proposed |
| Pending queues | 1 GiB | `pending_mib = 1024` | proposed |
| Pending items | 4,096 | `pending_items = 4096` | proposed |
| Fork-choice snapshots kept | last 2 | `fc_snapshots_kept = 2` | proposed |
| States kept | last 2 per epoch per branch head, plus the finalized state | `states_kept_per_epoch = 2` | proposed |
| Canonical headroom | 10% over the aggregate | `canonical_headroom_percent = 10` | proposed |
| Reserved free floor | max(10 GiB, 5% of the volume) | `floor_min_mib = 10240`, `floor_percent = 5` | proposed |
| Floor hysteresis | import resumes 1 GiB above the floor | `floor_hysteresis_mib = 1024` | proposed |
| Synchronous `statvfs` | before writes over 16 MiB, else once per slot | `sync_check_over_mib = 16` | proposed |

Estimates behind them:

- **Columns, 32 GiB.** About 5.6 MB of custody columns per slot, so roughly 180 epochs (about
  19 hours) of non-finality before the cap binds.
- **States, 8 GiB.** Compressed snapshots; a raw Hoodi state is about 234 MB.
- **Blocks** have no cap of their own: the aggregate bounds them.

What the values bound:

- **Only unfinalized bytes count**: the stored value lengths, not MDBX page usage. Finalized
  data, the trusted checkpoint, the anchor's file set and the finalized state are never charged,
  refused or deleted by the budget.
- **At the budget** a write on a side branch is ignored. A canonical write is still admitted
  past its kind's cap and the aggregate, up to the aggregate plus the canonical headroom; past
  that it is ignored too. The item caps bind both. Each refusal is counted in
  `chain_disk_budget_refusals_total{kind,branch}`. `chain_disk_budget_reached` rises with the
  first refusal and falls once a write is admitted within the caps, each change logged once.
- **Below the floor** import stops (the import gate closes) and finalized serving goes on;
  `chain_disk_floor_reached` is 1 and `chain_disk_free_bytes` shows the free space.
- **Envelopes**: every unfinalized one is kept; a finalized one is kept inside
  `[max(GLOAS_FORK_EPOCH, current - compute_min_epochs_for_block_requests()), current]`, and
  older ones are prunable, except the anchor's.
- **The budget never deletes.** Pruning stays with each table's finality prune.

Only the column store enforces the budget today. Blocks, states, pending queues and fork-choice
snapshots get the same admit and charge API when their writers land. The load test that
validates these numbers waits for the review.
