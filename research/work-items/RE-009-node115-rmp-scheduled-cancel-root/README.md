# RE-009 · Verify the #115 scheduled-cancel collection's raw ABCI subtree

The offline verifier projects `exchange.user_to_scheduled_cancel` from a pinned named MessagePack checkpoint into raw exchange slot 21. It checks the file hashes and both decoded heights and rehashes the complete reference before comparing the slot.

Each stored row is an Address followed by a map whose `t` is an optional canonical Time and whose `n` is an unsigned count. The writer omits `t` for an absent Time and omits a zero `n`. The raw visitor aggregates the rows into these ordered leaf streams.

| Path within slot 21 | BLAKE3 preimage |
| --- | --- |
| `[0]` | The 20-byte address keys concatenated in stored order |
| `[1,0,0]` | Only present `t` values, each signed Unix seconds qword followed by an unsigned nanosecond dword in little-endian order |
| `[1,0,1]` | One little-endian qword per row, 1 for present `t` and 0 for absent `t` |
| `[1,1]` | One little-endian `n` qword per row, including zero for an omitted count |
| `[2]` | Collection row count as a little-endian qword |

In an empty collection only `[2]` appears. In a nonempty collection with every `t` absent, only `[1,0,0]` is omitted. Each collection stream preserves the checkpoint writer's order. The selected ordinary Time grammar follows the existing four-digit calendar and canonical fractional width checks.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- Compact field `+0x3fa8` enters `0x5673cd0` from `0x54810f9`. Its collection writer `0x52d03a0` emits a two-element pair per stored row. The named value path at `0x4d935f0` reads the optional Time at `+8` and the count at `+0`, then delegates to the canonical clock and unsigned integer writers.
- Raw slot 21 calls `0x4d9df80`. It shares iterator `0x5133d90` with the snapshot writer, and its compact path advances by 0x30 bytes per row with the value record at row `+0x18`. The common visitor `0x4e1bea0` processes key and value arrays into their respective child slots, and writes the count from the original map.
- The value visitor at `0x3d38b00` applies the same pair of child visits for every value. Its first child goes to `0x4513370`; that visitor includes a Time item only in the present option arm, and contributes one tag qword to the same second leaf every time. The Time descriptor reaches `0x141b1e0`, and both the tag and value count descriptors reach u64 appender `0x14199b0`. Initializers leave unvisited children at the raw skip sentinel.
- [#2194](https://github.com/lalalune/hyperliquid-source/pull/2194) establishes field loading, materialization and snapshot omission, and leaves the generic raw visitor and completed digest open. This packet joins the ordered streams through those visitors to an executable raw subtree check. [#7610](https://github.com/lalalune/hyperliquid-source/pull/7610) covers the different display-name collection.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), time normalizer from [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368), clock preimage encoder from [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) and export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under the same helper folder. The verifier checks exact dependency source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-scheduled-cancel-root/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` driver, call `compare_scheduled.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline output](offline-log.txt) checks synthetic empty, nonempty all-absent and mixed rows, including two distinct clocks in one stream, a middle absent tag, count zero defaults, row order and a stale reference digest. Real equality at H requires a sourced checkpoint and raw export at that height.
