# RE-002 · Node #115 RocksDB DBImplSecondary virtual dispatch

Component: storage and snapshots. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Table and object-side anchor

The `.rodata` string at `0x970120` is `N7rocksdb15DBImplSecondaryE`. The typeinfo object at `0x64cbaa8` has a RELATIVE relocation to that string at offset 8 and an absolute relocation to `_ZTVN10__cxxabiv120__si_class_type_infoE + 16` at offset 0. A RELATIVE relocation at `0x64cbbb8` points to that object. The preceding signed word at `0x64cbbb0` is zero. This matches the [Itanium C++ ABI table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components) with the address point at `0x64cbbc0`.

The single-inheritance typeinfo field at `0x64cbab8` has a RELATIVE relocation to base typeinfo `0x64c9188`. Its linked name is `N7rocksdb6DBImplE` at `0x96ce90`. This identifies the immediate RTTI base. It does not describe the full object layout.
The mapped primary table for the base has address point `0x64c9368`. Within the 151 slot indexes covered by both prefixes, 124 have the same relocation and 27 differ. The TSV records the base addend and comparison at each covered index.


The independently attributed body at `0x5e7bd20` computes this table's header or address point at `0x5e7bd2d`. [stores.tsv](stores.tsv) records that `lea`, any immediate adjustment, and the 64-bit memory store of the resulting address point. The complete selected trace is `0x5e7bd2d: 488d057cfe6400 lea rax, [rip + 0x64fe7c]`, then `0x5e7bd34: 4883c010 add rax, 0x10 | 0x5e7bd38: 488907 mov qword ptr [rdi], rax`. The source identity of the body is recorded in the TSV.

## Linked slots

[slots.tsv](slots.tsv) records the contiguous relocation-backed prefix of **151 function entries**. All 151 land at starts in the authenticated artifact's `.eh_frame_hdr` search table. The scan follows each search record to the actual FDE in `.eh_frame` and verifies that its start equals the slot addend. The TSV records the descriptor VA and exclusive function end. 131 have labels from exact starts in the existing [body registry](../../byte-windows.json). The first excluded word at `0x64cc078` has a relocation of type 1 with addend `0x10` outside the qualifying slot form.

| Slot index | Offset from address point | Target VA | Existing attribution |
| --- | --- | --- | --- |
| 30 | `0xf0` | `0x5e7d920` | `_ZN7rocksdb15DBImplSecondary3GetERKNS_11ReadOptionsEPNS_18ColumnFamilyHandleERKNS_5SliceEPNS_13PinnableSliceE` |
| 33 | `0x108` | `0x5e7d970` | `_ZN7rocksdb15DBImplSecondary3GetERKNS_11ReadOptionsEPNS_18ColumnFamilyHandleERKNS_5SliceEPNS_13PinnableSliceEPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE` |
| 51 | `0x198` | `0x5e7dac0` | `_ZN7rocksdb15DBImplSecondary11NewIteratorERKNS_11ReadOptionsEPNS_18ColumnFamilyHandleE` |
| 53 | `0x1a8` | `0x5e807e0` | `_ZN7rocksdb15DBImplSecondary12NewIteratorsERKNS_11ReadOptionsERKSt6vectorIPNS_18ColumnFamilyHandleESaIS6_EEPS4_IPNS_8IteratorESaISC_EE` |

The table counts slots, including repeated target addresses. It does not assign names to unmatched code or infer a complete C++ class layout. A registered body label is an existing attribution. All aliases are preserved in the full table.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$node"
readelf --debug-dump=frames-interp "$node"
objdump -s --start-address=0x64cbbb0 --stop-address=0x64cc080 "$node"
objdump -d -M intel --start-address=0x5e7bd20 --stop-address=0x5e7bd3b "$node"
```

Re-derive the typeinfo and name relocations and the signed offset-to-top from [header.json](header.json). Starting at the address point, step by eight bytes while each relocation points into code with a matching unwind start. Decode the registered body's RIP-relative `lea` and follow its register through the recorded adjustment to the store. Moving the expected address point by eight bytes rejects the same instruction trace. The local extraction used Python 3.12.14, pyelftools 0.33 and Capstone 5.0.9. It read the binary without executing it. No byte coverage or acceptance gate changes.
