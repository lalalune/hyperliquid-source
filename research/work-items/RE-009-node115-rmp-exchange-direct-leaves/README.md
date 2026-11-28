# RE-009 · Verify six direct Exchange checkpoint leaves against a #115 raw root

The offline comparator checks the four named Exchange feature flags and two unsigned fields against independently supplied raw ABCI leaves at the checkpoint height. It takes exact SHA-256 pins for the checkpoint and raw export, verifies the decoded checkpoint and export heights, and rehashes the entire exported tree before comparing the six leaf digests. It reports the slot and match result for each field.

| Named checkpoint field | Compact Exchange offset | Raw slot | Leaf BLAKE3 input |
| --- | --- | --- | --- |
| `spot_disabled` | `+0x42ac` | 23 | Boolean byte |
| `prune_agent_idx` | `+0x4230` | 24 | Little-endian u64 |
| `evm_enabled` | `+0x42ad` | 38 | Boolean byte |
| `hip3_no_cross` | `+0x42ae` | 46 | Boolean byte |
| `dex_abstraction_enabled` | `+0x42af` | 50 | Boolean byte |
| `pmn` | `+0x4270` | 55 | Little-endian u64 |

The comparator requires explicitly typed MessagePack booleans for the four flags. Their raw preimages are one byte, `00` for false or `01` for true. A missing key, nil or integer MessagePack zero is outside that checkpoint writer representation. The unsigned pair covers the complete u64 domain. The packet applies to restored H and needs genuine same-height inputs to establish state parity.

## Native evidence

Target `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- Loads at `0x548112a`, `0x548136e`, `0x548148b` and `0x548152c` zero-extend the four source bytes into the flag writer at `0x56783a0`. The writer forms MessagePack `c2|flag` at `0x56783ea`. In the raw tree, the shared `0x64a8458` descriptor uses visitor `0x1419d40`, which appends the original single byte at `0x1419d6b`.
- Loads at `0x5481156` and `0x54815d4` pass the full qwords to `0x56736b0`, which dispatches to the unsigned MessagePack integer writer `0x57d00b0`. The shared raw descriptor `0x64a8480` uses visitor `0x14199b0`, which stores a qword at `0x14199dc` and advances by eight.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps Exchange names to raw slots. This packet authenticates the writer types and exact raw widths and makes the full set of six direct comparisons executable on pinned files.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the exact `project.py` from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the exact `isolate.py` and `hash_tree.rs` from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item subdirectories under the same helper folder. The verifier checks the source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-exchange-direct-leaves/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

Use the built #7404 `hash_tree` executable with `compare_leaves.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [measured offline run](offline-log.txt) covers both flag values, maximum u64, a bad one-byte width, swapped qword byte order, wrong height, wrong named type, an omitted field and a stale root. The fixture data is synthetic.
