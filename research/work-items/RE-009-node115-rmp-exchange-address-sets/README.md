# RE-009 · Verify two named #115 Address sets against their raw ABCI subtrees

The offline checker compares the two persisted Exchange Address sets at raw slots 7 and 44. It verifies both file SHA-256 values and both heights and recomputes the reference's full raw digest before checking each complete subtree.

| Named checkpoint field | Compact field offset | Raw slot |
| --- | --- | --- |
| `allowed_liquidators` | `+0x41e8` | 7 |
| `disabled_precompiles` | `+0x4250` | 44 |

Each named array stores lowercase `0x` Address strings. Raw child 0 hashes the concatenated 20-byte addresses in the order recorded by the native writer. Child 1 hashes the member count as a little-endian u64. An empty set contributes only the count child. The checker preserves recorded array order and rejects duplicate members.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- Compact Exchange sends the two fields through named writers `0x5677400` and `0x56773a0`. Their array writers `0x52ca1d0` and `0x52ee360` open MessagePack array framing and call the same set iterator `0x5138730`. The former passes a 20-byte input and a 42-byte output capacity to the prefixed hex formatter. The latter uses `0x4e2e020` with the same prefix, digit alphabet and 42-byte string size.
- The iterator and both raw visitors advance the index in tree order. The static verifier checks their node length loads, next-index increments and the same `8 + 20 * index` member addressing. The two raw collectors use descriptors `0x64a47d8` and `0x64a47b0`, both reaching 20-byte appender `0x141b9b0`.
- Each raw destination has two children initialized by `0x5330220` with the skipped sentinel. Visitors `0x5330f90` and `0x5330b20` visit child 0 once per member and append the original count from the set's `+0x10` through the qword visitor at child 1. An empty iteration never initializes the member slot.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps the two field names to slot indexes. This packet joins their independently located native writers with the shared Address/count hash representation.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the exact named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the ordered export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under the same helper folder. The scripts check each helper source's SHA-256.

```sh
python3 -B research/work-items/RE-009-node115-rmp-exchange-address-sets/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

Use the built #7404 `hash_tree` driver with `compare_sets.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline output](offline-log.txt) checks synthetic empty and populated sets, independent order and count differences, duplicate keys, wrong height and a stale reference digest. Genuine parity at H still requires same-height source data.
