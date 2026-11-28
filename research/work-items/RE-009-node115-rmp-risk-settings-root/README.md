# RE-009 · Verify two #115 risk settings subtrees from a named checkpoint

The offline checker projects `partial_liquidation_cooldown` and `default_hip3_limits` from a named MessagePack checkpoint into raw exchange ABCI slots 37 and 42. It checks the two file SHA-256 values and both decoded heights, recomputes the complete reference digest and reports each setting comparison.

Cooldown is optional. Nil leaves child 1 alone with the hash of little-endian qword 0. A finite MessagePack binary64 value adds child 0 with the same eight IEEE-754 bits in little-endian order and places the qword-1 hash in child 1. This preserves a present signed zero. The six HIP-3 values are unsigned words in the following raw order.

| Raw child | Checkpoint field | Compact offset within the settings object |
| --- | --- | --- |
| 0 | `total_oi_cap2` | `+0x08` |
| 1 | `oi_sz_cap_per_perp` | `+0x10` |
| 2 | `max_transfer_ntl2` | `+0x18` |
| 3 | `max_under_initial_margin_transfer_ntl2` | `+0x20` |
| 4 | `daily_px_range` | `+0x00` |
| 5 | `max_n_users_with_positions` | `+0x28` |

Each limit is a complete eight-byte little-endian leaf preimage. Named map order does not determine raw child order.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The cooldown writer at `0x5678670` receives the tag and double from compact Exchange `+0x37e0` and `+0x37e8`. It calls binary64 writer `0x4e380c0` on the selected tag-1 arm and writes nil on the other arm. Raw visitor `0x4d3f5c0` emits the present double through `0x64e1530` and `0x1603ec0` to `0x1419900`. Its second child receives the uniform qword tags through `0x14199b0`.
- The HIP-3 checkpoint writer passes Exchange `+0x41a8` from `0x5481404` through `0x5679b90` to `0x549c350`. It writes the table's six named values with unsigned integer writer `0x57d00b0`, including the final forwarding call through `0x56736b0`.
- Raw visitor `0x44e7560` passes the matching six offsets and descriptors to the six-child driver `0x41ade90`. The first four descriptors share appender `0x14199b0`. Child 4 uses `0x141b3c0`, which also copies a full qword. Child 5 uses `0x14199b0`.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps the two #115 field names to raw slots, while [#1369](https://github.com/lalalune/hyperliquid-source/pull/1369) describes earlier #94 JSON dispatch. This comparison authenticates the #115 writer-to-root bits for all children of both slots.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the exact named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and raw export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under a common helper directory. The scripts verify their source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-risk-settings-root/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

Use the built #7404 `hash_tree` executable with `compare_settings.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline output](offline-log.txt) covers synthetic present signed zero and nil options, reordered raw children, maximum u64, a one-field mismatch, a missing member and a stale reference digest. A genuine same-height checkpoint and raw export are required to verify an actual root.
