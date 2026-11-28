# Count checkpoint rows rather than distinct heights in offline retention

The reconstructed count-based retention planner sorted heights and then removed equal values before applying the keep count. That assigned too many retention slots when different input rows had the same height. It now counts each input row and preserves the planner's ascending presentation of the selected heights.

The selected native maintenance path passes 100 at `0x4d98d51`. The provider called at `0x38c5217` appends 32-byte rows with each unsigned height at `+0x18`. In the selected append path at `0x44690ef` the row count advances with that store. The count-maintenance caller sets up the row range and passes it with the keep count to the tail collector at `0x38c529f`. Its skip helper at `0x37c1369` derives the row count from the pointer range divided by 32. Equal numeric heights therefore still occupy two entries in the selection input. The [maintenance packet](../RE-015-evm-prune-policy-115/README.md) covers the original count route and sort boundaries. The [exact-height discovery fixture](../RE-009-node115-checkpoint-discovery/README.md) documents how ordinary alias spellings can yield equal-height rows.

The regression checks 102 rows with only 100 distinct heights, repeated heights inside the selected tail, and the exact keep limit. It covers the count and multiplicity projection. The adapter performs no checkpoint removal and does not model native removal order, retries or filesystem effects.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from repository root.

```sh
python3 -B research/work-items/RE-009-node115-retention-row-count/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
```

The [offline log](offline-log.txt) retains the baseline failure, static verification and passing Rust tests.
