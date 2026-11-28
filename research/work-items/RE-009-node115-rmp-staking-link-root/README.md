# RE-009 · Verify the #115 staking-link collection's raw ABCI subtree

The offline verifier projects `exchange.staking_link_tracker.user_to_staking_link2` from a pinned named MessagePack checkpoint and compares complete raw slot 40. It checks both file hashes and both decoded heights and recomputes the complete reference digest.

The stored field uses ordered pairs of Address and named link variant. A variant has a single nested Address.

| Variant | Named address key | Raw payload child | Raw tag |
| --- | --- | --- | --- |
| `Requested` | `staking_user` | 0 | 0 |
| `TradingUser` | `staking_user` | 1 | 1 |
| `StakingUser` | `trading_user` | 2 | 2 |

Slot 40 has a single child, the collection branch. Collection child 0 hashes the original 20-byte keys in row order. Collection child 1 holds separate leaves for the payload addresses of each present variant, concatenated in that variant's row order. Its child 3 hashes every variant tag in original row order as little-endian u64 words. Collection child 2 hashes the little-endian u64 row count. A variant with no rows has no payload child. An empty map still has the count leaf under collection child 2.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- Compact Exchange `+0x40a0` enters `0x5675030` via `0x54813c6`. The tracker writer `0x5363e30` writes its single named map field, then delegates the pair array to `0x5298fb0`. The pair writer calls the Address serializer and the named variant serializer `0x53645b0`.
- Slot 40's `0x472ea70` requires a one-child destination and hands it to collection visitor `0x3c56090`. Its three-member driver receives an Address stream, a variant stream and the original count. Both compact sequence paths advance 0x29 bytes per row with the value at `+0x14`. The writer iterator `0x5139600` and raw iterator `0x37ca6c0` are byte-identical through their normal traversal bodies. The final diagnostic relocation sequences differ.
- Variant visitor `0x4715460` selects index 0, 1 or 2 from the stored variant byte. It gives the address at `+1` to the selected index and the staged little-endian variant qword to fixed index 3. `0x41aed60` initializes and visits the selected children, preserving previous appends. The fresh variant destination starts with four skipped sentinels. The shared address and qword writers append respectively 20 and eight bytes.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) supplies the top-level slot name. This packet joins the nested named schema, ordering and variant partitioning into a complete raw subtree comparison.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the exact named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the raw export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under one helper directory. The scripts check each source SHA-256.

```sh
python3 -B research/work-items/RE-009-node115-rmp-staking-link-root/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

Use the built #7404 `hash_tree` executable with `compare_links.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline log](offline-log.txt) covers synthetic empty, sparse and mixed variant sets, two interleaved rows of the same variant, a reordered tag stream, a reordered payload stream and a stale reference digest. A genuine same-height checkpoint and raw export are required for actual state parity.
