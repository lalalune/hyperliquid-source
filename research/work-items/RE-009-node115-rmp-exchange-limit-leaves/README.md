# RE-009 · Compare #115 Exchange numeric limits and scheduling heights with a raw root

This offline checker compares two named binary64 limits and two scheduling heights from a checkpoint with four complete raw ABCI slots. It pins both files, checks the decoded Context height and raw export height, and recomputes the reference tree's declared digest before comparing the selected fields.

| Named field | Layout A offset | Raw slot | Raw shape |
| --- | --- | --- | --- |
| `max_order_distance_from_anchor` | `+0x4220` | 12 | Eight little-endian IEEE-754 bytes |
| `scheduled_freeze_height` | `+0x10e8` | 13 | Optional u64 branch |
| `post_only_until_height` | `+0x4228` | 17 | Eight little-endian u64 bytes |
| `max_hlp_withdraw_fraction_per_day` | `+0x4238` | 25 | Eight little-endian IEEE-754 bytes |

The two finite binary64 limits use the MessagePack `cb` marker and big-endian bit order in the checkpoint. Their raw leaf preimages contain the same bits in little-endian order without the marker. The sign of zero is preserved. For `scheduled_freeze_height`, nil leaves only child 1 with a qword 0 preimage. A present u64 adds child 0 with its full little-endian value and sets child 1 to qword 1. Present zero and nil are different branch shapes. `post_only_until_height` has one leaf even at numeric zero.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The two float keys enter `0x5678170` through `0x5480f98` and `0x548119c`. It sends the double register to `0x4e380c0`, whose direct path writes byte `cb` at `0x4e380e9` and byte-swaps the full qword at `0x4e38187`. Raw method `0x1419900` stores the supplied qword directly with `movsd` at `0x141992e`.
- The freeze writer at `0x5675090` receives the two words from `+0x10e8` and `+0x10f0`. Under tag 1 it supplies the second word to unsigned MessagePack writer `0x57d00b0`; the alternate arm writes nil at `0x567511c`. In raw slot 13, `0x4d3ebe0` either writes that qword to child 0 and qword 1 to child 1 or skips child 0 and writes qword 0 to child 1. Both raw writer relocations target `0x14199b0`.
- Named `post_only_until_height` enters `0x56771f0` through `0x5481071` with a single source qword. `0x5677238` goes to `0x57d00b0`; raw slot 17 calls qword appender `0x14199b0` directly.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) establishes the Exchange name-to-slot map. [#7263](https://github.com/lalalune/hyperliquid-source/pull/7263) traces the local JSON freeze ingress. This packet verifies the named MessagePack writer-to-raw leaf boundary for the four selected fields.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler, and the pinned local ELF. Stage the exact named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the ordered export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under the same helper directory. File paths and exact SHA-256 values are in `compare_limits.py` and `verify.py`.

```sh
python3 -B research/work-items/RE-009-node115-rmp-exchange-limit-leaves/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` driver, run `compare_limits.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline run](offline-log.txt) exercises numeric signed zero, both freeze shapes, a nonzero post-only height with differing bytes, binary32 and infinity rejection, and a stale reference digest. The tests use synthetic data. Genuine parity at H needs an independently sourced checkpoint and same-height raw export.
