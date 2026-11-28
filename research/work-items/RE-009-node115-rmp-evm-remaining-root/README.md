# RE-009 · Verify the #115 EVM-to-L1 remaining amount collection's raw ABCI subtree

The offline checker compares `exchange.user_to_evm_to_l1_wei_remaining` from a named checkpoint with the complete raw subtree at slot 49. It checks both file SHA-256 values and both decoded heights and recomputes the complete reference export digest.

The checkpoint writer emits ordered two-element rows with a lowercase `0x` Address string and an unsigned 64-bit amount. The raw slot separates the collection into parallel streams.

| Path relative to slot 49 | Hash preimage |
| --- | --- |
| `[0]` | 20 address bytes per row, concatenated in checkpoint order |
| `[1,0]` | Eight little-endian amount bytes per row, in the same order |
| `[1,1]` | Zero input bytes for the common quantity marker |
| `[2]` | Eight little-endian bytes for the overall row count |

For a nonempty collection each row visits the same nested quantity branch. Its amount leaf accumulates all words, and its second child remains one empty-input hash. For an empty collection only the row-count child appears. A present zero value still contributes eight bytes. The comparison rounds no amount and keeps the native stored row order.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- `0x548151a` directs compact Exchange field `+0x4138` to its named writer at `0x5678ea0`, which calls `0x52d3e50`. The collection writer opens an array and uses the shared iterator `0x5133940`. Pair writer `0x5310810` writes a two-element marker, emits Address text via `0x5320910` and appends the unsigned qword through `0x5320130`.
- Raw slot 49 calls `0x4da2e60`, whose iterator path also calls `0x5133940`. Its compact path advances by 32 bytes and takes the amount from row `+0x18`. The raw visitor obtains the original count at map `+0x18` and passes the two ordered source collections and count to `0x4e1bea0`.
- Address descriptor `0x649a790` leads to the 20-byte appender `0x141b9b0`. The value descriptor `0x649cba0` leads to quantity visitor `0x43c6a50`. It sends one qword to appender `0x14199b0` and the second child to no-write visitor `0x430b920`. The latter's initialized buffer count remains zero. The sibling map-count descriptor `0x649a6f0` uses the same qword appender.
- [#1883](https://github.com/lalalune/hyperliquid-source/pull/1883) establishes the corresponding named and JSON shape for #94. [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) maps #115 field names to slots. This packet establishes #115's complete ordered hash subtree and checks it against a source-pinned export.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the raw reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their exact published work-item directories under one helper directory. The scripts check each source SHA-256.

```sh
python3 -B research/work-items/RE-009-node115-rmp-evm-remaining-root/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` executable, run `compare_remaining.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline output](offline-log.txt) covers an empty collection, two ordered rows with zero and maximum u64 amounts, an empty-input marker mismatch, reversed order and a stale reference digest. The fixtures are synthetic. Actual parity requires independently sourced checkpoint and raw export data at the same height.
