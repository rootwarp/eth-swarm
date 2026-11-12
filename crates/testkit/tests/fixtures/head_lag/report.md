# Head-lag report

Window: 24h; slots 0..=7199 (7200 expected).
Slot duration: 12 s; epoch: 32 slots.
Samples: 7200 compared, 0 gaps (0 s).

Overall: FAIL

## Exit-one thresholds
- p99 <= 2 slots: PASS (observed: 1).
- worst <= 32 slots: FAIL (observed: 33).
- recovery <= 1 epoch: PASS.
- complete evidence: PASS.

## Recoveries
| Start slot | End slot | Elapsed slots | Seconds | Over epoch | Gaps |
| --- | --- | --- | --- | --- | --- |
| 7198 | 7199 | 1 | 12 | no | no |

Threshold PASS requires complete coverage; open recoveries are incomplete.
