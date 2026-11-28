# RE-009 · Reconstruct all three #115 checkpoint gas-auction root subtrees

The verifier projects complete ordered gas-auction subtrees from a named MessagePack checkpoint and compares them with raw exchange ABCI slots 28–30 at the same height. It pins the checkpoint and reference bytes and validates the reference's full raw digest. It reports the first meaningful differing path in each slot and recalculates the raw digest after substituting the three projected subtrees into the reference. That digest retains all independently captured non-auction branches.

[#7505](https://github.com/lalalune/hyperliquid-source/pull/7505) compares six numeric fields and the outer option tag for each auction. This follow-up establishes the remaining native `end_gas_wei` option and empty phantom leaves, then checks the whole ordered shapes. For a present auction, the six ordered payload entries are the bucket guard, start quantity, optional end quantity, token, initial-to-last ratio and minimum quantity.

| Relative branch or leaf | Preimage or shape |
| --- | --- |
| `[0,2]` with named `end_gas_wei: nil` | Child 1 contains qword 0 |
| `[0,2]` with named unsigned `end_gas_wei` | Child 0 holds the quantity branch and child 1 contains qword 1 |
| `[0,1]`, `[0,2,0]` when present, and `[0,5]` | Child 0 holds the little-endian quantity qword. Child 1 holds BLAKE3 of zero input bytes |

An absent end quantity and a present numeric zero yield different ordered subtrees. An omitted named field has no authenticated option representation and is rejected. The comparison applies at the checkpoint height H. No actual chain parity follows without a genuine same-height fixture and raw export.

## Static evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The field key comes from `0x5a016b7`. Source dword 1 at `0x5a016d5` selects qword `+8` for the unsigned writer `0x57d00b0`; the other ordinary option arm writes MessagePack nil at `0x5a0174d`.
- `0x3d1ebf4` binds the base of the payload to raw entry 2. Descriptor `0x64787a0` relocates to `0x45147f0`. Its present arm sets child-0 count 1 with source `+8` and quantity descriptor `0x648ed00`; its absent arm sets the count to 0. Both arms set child-1 count 1. The relocated descriptors point at qword 1 or 0 and visitor `0x14199b0`. With no item, the slot sentinel stays uninitialized. The raw branch writer skips this sentinel. [Native root slot evidence](../RE-008-abci-hash-slots-115/README.md)
- The quantity visitor at `0x43c6a50` uses a numeric first child and the zero-sized descriptor `0x6487b30` for its second child. The common `0x41ae280` driver initializes and visits the latter. Its constructor `0x41ad060` resolves to the leaf allocator at `0x141a020`, which starts the input count at zero at `0x141a14a`. Visitor `0x430b920` only checks the leaf marker and returns 4; it appends zero bytes. The leaf finalizer reads that count at `0x141a2a4` and skips the update at zero.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler, and the pinned local ELF. Stage the exact `compare_auctions.py` from [#7505](https://github.com/lalalune/hyperliquid-source/pull/7505), `project.py` from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), and `isolate.py` and `hash_tree.rs` from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item subdirectories under the same helper folder. The verifier checks all source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-auction-full-subtrees/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

For supplied input, use the built #7404 `hash_tree` executable with `compare_subtrees.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [measured offline run](offline-log.txt) checks native bytes and covers synthetic nil, zero and nonzero end quantities, a wrong phantom hash, whole-subtree substitution, an omitted option and a stale reference digest.
