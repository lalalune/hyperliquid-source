# RE-009 · Verify the #115 display-name collection against its raw ABCI subtree

The offline checker projects the entire `exchange.user_to_display_name` collection from a pinned native named MessagePack checkpoint. It compares raw exchange slot 19 at the same height after checking both file SHA-256 values, the embedded Context height and the reference's full declared ABCI digest.

The named field contains an array of two-element rows. Each row holds a 20-byte Address in lowercase `0x` text and a UTF-8 display name. The raw visitor uses three ordered leaves instead of hashing the MessagePack pairs.

| Child | BLAKE3 input |
| --- | --- |
| 0 | The original 20-byte addresses concatenated in stored row order |
| 1 | For each name, its byte length as a little-endian u64 followed by its UTF-8 bytes |
| 2 | Entry count as a little-endian u64 |

For an empty collection, only child 2 appears with the zero-count digest because the native address and name visitor loops never initialize their destination slots. An empty string in a populated row still contributes its eight-byte zero length. The count is independent of row order. The tool preserves stored pair order and uses UTF-8 byte lengths without changing the text.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- `0x54810af` passes compact Exchange `+0x3f88` to named field writer `0x56761a0`. It calls `0x52d81d0`, which opens an array through `0x57ceba0` and visits iterator `0x5133d90` or advances a 0x30-byte row in its two-span path. Each entry writer emits the `92` pair prefix, formats 20 address bytes as 42 text bytes and writes the following string's buffer and length.
- Raw slot 19 uses visitor `0x4d9e710`. Its two-span path advances by the same 0x30 bytes and separates the address at row base from the string record at `+0x18`; its other path also uses `0x5133d90`. It collects both streams in iteration order and supplies the original container count from `+0x18` to the third raw slot.
- `0x4e1bea0` directs the first two descriptor loops into separate destinations. Address descriptor `0x649a790` resolves to the 20-byte writer `0x141b9b0`. String descriptor `0x649c830` resolves to `0x141b610`, which appends the eight-byte length and exactly that many source bytes via `0x141a8c0`. Count descriptor `0x649a6f0` resolves to qword writer `0x14199b0`.
- The raw allocator `0x4d9db00` initializes all three children with the skipped sentinel. Only visiting a member initializes its destination. The single count visitor initializes child 2 for an empty collection.
- [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps the name to slot 19. This change joins the collection's stored pair format and traversal to the three raw leaf preimages.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the ordered export reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under one helper directory. The verifier checks each dependency's source SHA-256.

```sh
python3 -B research/work-items/RE-009-node115-rmp-display-name-root/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

Use the built #7404 `hash_tree` executable with `compare_display_names.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline log](offline-log.txt) checks synthetic empty and populated collections, an empty name in a populated row, a multibyte name, reversed row order, duplicate addresses and a stale reference digest. Real parity remains dependent on a sourced checkpoint and same-height raw export.
