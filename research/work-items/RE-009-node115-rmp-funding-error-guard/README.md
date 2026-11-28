# RE-009 · Verify the #115 funding error duration guard subtree

The offline checker projects the complete named `exchange.funding_err_dur_guard` subtree at raw ABCI slot 11. It matches the decoded checkpoint Context height and the raw export height, checks both file SHA-256 values and rehashes the complete export before comparing the selected branch.

| Child | Named field | Raw structure |
| --- | --- | --- |
| 0 | `err_duration` | Finite binary64 bits, little-endian |
| 1 | `first_err_time` | Independently optional Time branch |
| 2 | `last_err_time` | Independently optional Time branch |

For each optional time a nil value gives child 1 alone with little-endian qword 0. A present clock gives child 0 with the 12-byte preimage and child 1 with little-endian qword 1. The clock preimage contains signed Unix seconds and unsigned nanoseconds, eight and four bytes in little-endian order. The supported named representation follows the ordinary clock reader's four-digit calendar years and canonical fraction widths. Nil and a present epoch clock differ even though the epoch clock's twelve source bytes are all zero. Field names identify values in the checkpoint map. Child order is required in the raw branch.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The main writer loads Exchange `+0x4200` at `0x5480f5e` and calls `0x5673740`, which writes the field name then jumps to nested writer `0x4d9ca80`. The nested writer sends the base double to `0x4e380c0`. Its first and last time branches test the first packed dword of the fields at offsets `+8` and `+0x14` respectively. Nonzero selects the ordinary canonical clock renderer at `0x5307510`; zero selects MessagePack nil.
- Raw slot 11 uses `0x15b4950`. The visitor supplies base, `+8` and `+0x14` to the three-child driver `0x14bbf10`. The first descriptor reaches the double appender `0x1419900`. Both time fields use descriptor `0x6400138`, which reaches `0x15d1540`.
- The raw option visitor uses the same zero-dword predicate. The present child 0 dispatches through `0x64e12d8` and `0x156f3a0` to time appender `0x141b1e0`. The tag child receives qword 1 or 0 via raw appender `0x14199b0`.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps the slot to its name. [#7533](https://github.com/lalalune/hyperliquid-source/pull/7533) covers two-word BucketGuards, and [#7549](https://github.com/lalalune/hyperliquid-source/pull/7549) covers direct standalone Time fields. This packet checks the funding duration guard's mixed, nested representation.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), the clock normalizer from [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368), the clock preimage encoder from [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) and the ordered export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under the same helper folder. The verifier checks exact helper source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-funding-error-guard/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` driver, run `compare_guard.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [measured offline run](offline-log.txt) checks pre-epoch Time, a present epoch Time, independent optional branches, reordered raw children, wrong float width, omitted clock and a stale reference digest. The inputs are synthetic. Actual chain parity requires genuine same-height checkpoint and export files.
