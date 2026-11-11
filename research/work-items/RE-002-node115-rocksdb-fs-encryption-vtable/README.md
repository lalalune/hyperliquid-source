# RE-002 · Node #115 RocksDB CTREncryptionProvider virtual dispatch

Component: storage and snapshots. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Table and object-side anchor

The `.rodata` string at `0x9734e0` is `N7rocksdb21CTREncryptionProviderE`. The typeinfo object at `0x64cf740` has a RELATIVE relocation to that string at offset 8 and an absolute relocation to `_ZTVN10__cxxabiv120__si_class_type_infoE + 16` at offset 0. A RELATIVE relocation at `0x64cffa8` points to that object. The preceding signed word at `0x64cffa0` is zero. This matches the [Itanium C++ ABI table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components) with the address point at `0x64cffb0`.

The independently attributed body at `0x5ff30b0` computes this table's header or address point at `0x5ff30b4`. [stores.tsv](stores.tsv) records that `lea`, any immediate adjustment, and the 64-bit memory store of the resulting address point. The complete selected trace is `0x5ff30b4: 488d05e5ce4d00 lea rax, [rip + 0x4dcee5]`, then `0x5ff30c1: 4883c010 add rax, 0x10 | 0x5ff30c6: 488907 mov qword ptr [rdi], rax`. The source identity of the body is recorded in the TSV.

## Linked slots

[slots.tsv](slots.tsv) records the contiguous relocation-backed prefix of **26 function entries**. All 26 land at starts in the authenticated artifact's `.eh_frame_hdr` search table. 15 have labels from exact starts in the existing [body registry](../../byte-windows.json). The first excluded word at `0x64d0080` has no dynamic relocation at that word.

| Slot index | Offset from address point | Target VA | Existing attribution |
| --- | --- | --- | --- |
| 16 | `0x80` | `0x5ff1030` | `_ZNK7rocksdb21CTREncryptionProvider12IsInstanceOfERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE` |
| 21 | `0xa8` | `0x5ffabd0` | `_ZN7rocksdb21CTREncryptionProvider9AddCipherERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPKcmb` |
| 25 | `0xc8` | `0x5ff49b0` | `_ZN7rocksdb21CTREncryptionProvider28CreateCipherStreamFromPrefixERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEERKNS_10EnvOptionsEmRKNS_5SliceESE_PSt10unique_ptrINS_23BlockAccessCipherStreamESt14default_deleteISG_EE` |

The table counts slots, including repeated target addresses. It does not assign names to unmatched code or infer a complete C++ class layout. A registered body label is an existing attribution. All aliases are preserved in the full table.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$node"
readelf --debug-dump=frames-interp "$node"
objdump -s --start-address=0x64cffa0 --stop-address=0x64d0088 "$node"
objdump -d -M intel --start-address=0x5ff30b0 --stop-address=0x5ff30c9 "$node"
```

Re-derive the typeinfo and name relocations and the signed offset-to-top from [header.json](header.json). Starting at the address point, step by eight bytes while each relocation points into code with a matching unwind start. Decode the registered body's RIP-relative `lea` and follow its register through the recorded adjustment to the store. Moving the expected address point by eight bytes rejects the same instruction trace. The local extraction used Python 3.12.14, pyelftools 0.33 and Capstone 5.0.9. It read the binary without executing it. No byte coverage or acceptance gate changes.
