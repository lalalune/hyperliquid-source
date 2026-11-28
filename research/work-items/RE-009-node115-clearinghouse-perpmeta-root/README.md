# Compare named PerpMeta scalar and string streams with raw ABCI

This offline comparator reads named `exchange.locus.cls[].meta` fields from pinned MessagePack bytes. It compares the ordered PDI, collateral token, and collateral token name streams against a separately pinned raw export at the same height. The three slots are `[0,1,0,0,1]`, `[0,1,0,0,3]`, and `[0,1,0,0,4]`. It separately checks the collection size at `[0,1,1]`.

The PerpMeta visitor `0x3d1c950` stages PDI at `+0x50`, token at `+0x58` and name at `+0x18`. Descriptors `0x6473fd0` and `0x6474020` reach U64 writer `0x14199b0`. The name descriptor `0x6477de0` enters `0x4303b90`, which loads pointer and byte length and calls `0x141a8c0`. That writer appends the little-endian U64 byte length at `0x141a8e8`, then copies exactly that many bytes at `0x141a90d`. Consequently an empty name still contributes eight bytes, and a non-ASCII name is measured in encoded bytes. The streams preserve row order.

Prior #6219 names the offsets. #7817 binds them to ordered raw paths and proves that all rows share one subtree. This packet adds the actual raw preimage bytes for the three fields and a scoped comparator; universe and margin table preimages remain open.

From repository root with the pinned helper packets, Python plus msgpack, and rustc:

```sh
python -B research/work-items/RE-009-node115-clearinghouse-perpmeta-root/verify.py --helpers /path/to/helpers --rustc /path/to/rustc
```

The verifier authenticates the captured artifact bytes and compiles only a local BLAKE3 fixture driver. It verifies synthetic empty and populated named checkpoints against separately assembled raw reference preimages and checks independently changed numeric order and character-count versus byte-length encoding. No real checkpoint or replay root was supplied.

[Measured offline output](offline-log.txt)
