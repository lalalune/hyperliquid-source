# RE-009 · Compare all six named Exchange BucketGuard subtrees against a #115 raw root

This offline checker projects the six standalone BucketGuard maps in a pinned named MessagePack checkpoint. Each maps to an ordered two-leaf raw ABCI subtree. The checker matches the checkpoint Context height and reference height and recomputes the complete reference digest before comparing the twelve leaf hashes.

| Checkpoint field | Compact Exchange offset | Raw exchange slot |
| --- | --- | --- |
| `funding_distribute_guard` | `+0x4158` | 4 |
| `funding_update_guard` | `+0x4168` | 5 |
| `cancel_aggressive_orders_at_open_interest_cap_guard` | `+0x4178` | 14 |
| `book_empty_user_states_pruning_guard` | `+0x4188` | 20 |
| `begin_block_logic_guard` | `+0x4198` | 33 |
| `hip3_stale_mark_px_guard` | `+0x41d8` | 43 |

In each raw subtree child 0 is BLAKE3 over the little-endian `last_bucket` qword and child 1 is BLAKE3 over the little-endian `bucket_millis` qword. The named checkpoint map can present either field first. The raw subtree order remains significant. This checks restored values at H. Deriving H+1 requires applying the corresponding replay transitions.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The named writer reaches `0x5617020` directly for `funding_distribute_guard` through `0x5480e7a`. The other five members send their field pointer and key to `0x56781f0`, which tail-calls the same writer at `0x5678226`. The verifier checks each name, data offset and call.
- The common writer loads named `last_bucket` from the guard at `+8` at `0x561708f` and `bucket_millis` from `+0` at `0x56170ed`. Both values are passed to unsigned integer writer `0x57d00b0`.
- Every slot uses descriptor `0x64a8200` and raw visitor `0x46f4560`. The visitor requires two entries and sends source `+8` into child 0 via `0x64df530` to `0x14199b0`. It sends source `+0` into child 1 via `0x64df5d0` to `0x141b3c0`. Both branches append complete qwords.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) supplies the Exchange name-to-slot map. [#7517](https://github.com/lalalune/hyperliquid-source/pull/7517) checks guards nested inside the three auction subtrees. This packet verifies the independent standalone guard slots.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler, and the pinned local ELF. Stage the exact `project.py` from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the exact `isolate.py` and `hash_tree.rs` from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item subdirectories under one helper directory. The verifier checks their source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-exchange-bucket-guards/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` executable, call `compare_guards.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [measured offline run](offline-log.txt) covers synthetic agreement across all six slots, a slot-33 millis difference, reversed slot-43 order with equal indexed digests, and bad input height, type, key and digest. Actual parity requires a genuine checkpoint and matching same-height raw export.
