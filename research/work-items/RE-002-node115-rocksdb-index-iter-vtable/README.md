# RE-002 · Node #115 RocksDB PartitionedIndexIterator virtual dispatch

Component: storage and snapshots. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Table and object-side anchor

The `.rodata` string at `0x97b9a0` is `N7rocksdb24PartitionedIndexIteratorE`. The typeinfo object at `0x64d5be0` has a RELATIVE relocation to that string at offset 8 and an absolute relocation to `_ZTVN10__cxxabiv120__si_class_type_infoE + 16` at offset 0. A RELATIVE relocation at `0x64d5c00` points to that object. The preceding signed word at `0x64d5bf8` is zero. This matches the [Itanium C++ ABI table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components) with the address point at `0x64d5c08`.

The single-inheritance typeinfo field at `0x64d5bf0` has a RELATIVE relocation to base typeinfo `0x64d3f70`. Its linked name is `N7rocksdb20InternalIteratorBaseINS_10IndexValueEEE` at `0x97a100`. This identifies the immediate RTTI base. It does not describe the full object layout.


The independently attributed body at `0x6151a50` computes this table's header or address point at `0x6151a5d`. [stores.tsv](stores.tsv) records that `lea`, any immediate adjustment, and the 64-bit memory store of the resulting address point. The complete selected trace is `0x6151a5d: 488d0594413800 lea rax, [rip + 0x384194]`, then `0x6151a6b: 4883c010 add rax, 0x10 | 0x6151a6f: 488907 mov qword ptr [rdi], rax`. The source identity of the body is recorded in the TSV.

## Linked slots

[slots.tsv](slots.tsv) records the contiguous relocation-backed prefix of **24 function entries**. All 24 land at starts in the authenticated artifact's `.eh_frame_hdr` search table. 10 have labels from exact starts in the existing [body registry](../../byte-windows.json). The first excluded word at `0x64d5cc8` has a relocation of type 1 with addend `0x10` outside the qualifying slot form.

| Slot index | Offset from address point | Target VA | Existing attribution |
| --- | --- | --- | --- |
| 4 | `0x20` | `0x6153330` | `_ZN7rocksdb24PartitionedIndexIterator10SeekToLastEv` |
| 7 | `0x38` | `0x6152a90` | `one of 2 identical copies of 2 build functions, e.g. _ZN7rocksdb24PartitionedIndexIterator4NextEv` |
| 9 | `0x48` | `0x6153200` | `one of 2 identical copies of 2 build functions, e.g. _ZN7rocksdb24PartitionedIndexIterator4NextEv` |
| 11 | `0x58` | `0x61516f0` | `_ZNK7rocksdb24PartitionedIndexIterator8user_keyEv` |

The table counts slots, including repeated target addresses. It does not assign names to unmatched code or infer a complete C++ class layout. A registered body label is an existing attribution. All aliases are preserved in the full table.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$node"
readelf --debug-dump=frames-interp "$node"
objdump -s --start-address=0x64d5bf8 --stop-address=0x64d5cd0 "$node"
objdump -d -M intel --start-address=0x6151a50 --stop-address=0x6151a72 "$node"
```

Re-derive the typeinfo and name relocations and the signed offset-to-top from [header.json](header.json). Starting at the address point, step by eight bytes while each relocation points into code with a matching unwind start. Decode the registered body's RIP-relative `lea` and follow its register through the recorded adjustment to the store. Moving the expected address point by eight bytes rejects the same instruction trace. The local extraction used Python 3.12.14, pyelftools 0.33 and Capstone 5.0.9. It read the binary without executing it. No byte coverage or acceptance gate changes.
