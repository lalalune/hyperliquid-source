# RE-002 · Node #115 RocksDB HistoryTrimmingIterator virtual dispatch

Component: storage and snapshots. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Table and object-side anchor

The `.rodata` string at `0x96e720` is `N7rocksdb23HistoryTrimmingIteratorE`. The typeinfo object at `0x64ca6a0` has a RELATIVE relocation to that string at offset 8 and an absolute relocation to `_ZTVN10__cxxabiv120__si_class_type_infoE + 16` at offset 0. A RELATIVE relocation at `0x64caa78` points to that object. The preceding signed word at `0x64caa70` is zero. This matches the [Itanium C++ ABI table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components) with the address point at `0x64caa80`.

The independently attributed body at `0x5df9a30` computes this table's header or address point at `0x5df9a34`. [stores.tsv](stores.tsv) records that `lea`, any immediate adjustment, and the 64-bit memory store of the resulting address point. The complete selected trace is `0x5df9a34: 488d0535106d00 lea rax, [rip + 0x6d1035]`, then `0x5df9a3f: 4883c010 add rax, 0x10 | 0x5df9a43: 488907 mov qword ptr [rdi], rax`. The source identity of the body is recorded in the TSV.

## Linked slots

[slots.tsv](slots.tsv) records the contiguous relocation-backed prefix of **24 function entries**. All 24 land at starts in the authenticated artifact's `.eh_frame_hdr` search table. 11 have labels from exact starts in the existing [body registry](../../byte-windows.json). The first excluded word at `0x64cab40` has no dynamic relocation at that word.

| Slot index | Offset from address point | Target VA | Existing attribution |
| --- | --- | --- | --- |
| 3 | `0x18` | `0x5df87d0` | `_ZN7rocksdb23HistoryTrimmingIterator11SeekToFirstEv` |
| 4 | `0x20` | `0x5df88c0` | `_ZN7rocksdb23HistoryTrimmingIterator10SeekToLastEv` |
| 5 | `0x28` | `0x5df89b0` | `_ZN7rocksdb23HistoryTrimmingIterator4SeekERKNS_5SliceE` |
| 6 | `0x30` | `0x5df83e0` | `_ZN7rocksdb23HistoryTrimmingIterator11SeekForPrevERKNS_5SliceE` |

The table counts slots, including repeated target addresses. It does not assign names to unmatched code or infer a complete C++ class layout. A registered body label is an existing attribution. All aliases are preserved in the full table.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$node"
readelf --debug-dump=frames-interp "$node"
objdump -s --start-address=0x64caa70 --stop-address=0x64cab48 "$node"
objdump -d -M intel --start-address=0x5df9a30 --stop-address=0x5df9a46 "$node"
```

Re-derive the typeinfo and name relocations and the signed offset-to-top from [header.json](header.json). Starting at the address point, step by eight bytes while each relocation points into code with a matching unwind start. Decode the registered body's RIP-relative `lea` and follow its register through the recorded adjustment to the store. Moving the expected address point by eight bytes rejects the same instruction trace. The local extraction used Python 3.12.14, pyelftools 0.33 and Capstone 5.0.9. It read the binary without executing it. No byte coverage or acceptance gate changes.
