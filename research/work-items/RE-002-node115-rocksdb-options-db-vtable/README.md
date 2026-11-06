# RE-002 · Node #115 RocksDB DBOptionsConfigurable virtual dispatch

Component: storage and snapshots. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Table and object-side anchor

The `.rodata` string at `0x9773a0` is `N7rocksdb21DBOptionsConfigurableE`. The typeinfo object at `0x64d34d0` has a RELATIVE relocation to that string at offset 8 and an absolute relocation to `_ZTVN10__cxxabiv120__si_class_type_infoE + 16` at offset 0. A RELATIVE relocation at `0x64d36b0` points to that object. The preceding signed word at `0x64d36a8` is zero. This matches the [Itanium C++ ABI table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components) with the address point at `0x64d36b8`.

The single-inheritance typeinfo field at `0x64d34e0` has a RELATIVE relocation to base typeinfo `0x64d34b8`. Its linked name is `N7rocksdb21MutableDBConfigurableE` at `0x977360`. This identifies the immediate RTTI base. It does not describe the full object layout.
The mapped primary table for the base has address point `0x64d3638`. Within the 14 slot indexes covered by both prefixes, 10 have the same relocation and 4 differ. The TSV records the base addend and comparison at each covered index.


The independently attributed body at `0x60a47f0` computes this table's header or address point at `0x60a494d`. [stores.tsv](stores.tsv) records that `lea`, any immediate adjustment, and the 64-bit memory store of the resulting address point. The complete selected trace is `0x60a494d: 488d0554ed4200 lea rax, [rip + 0x42ed54]`, then `0x60a4954: 4883c010 add rax, 0x10 | 0x60a4958: 488903 mov qword ptr [rbx], rax`. The source identity of the body is recorded in the TSV.

## Linked slots

[slots.tsv](slots.tsv) records the contiguous relocation-backed prefix of **14 function entries**. All 14 land at starts in the authenticated artifact's `.eh_frame_hdr` search table. The scan follows each search record to the actual FDE in `.eh_frame` and verifies that its start equals the slot addend. The TSV records the descriptor VA and exclusive function end. 12 have labels from exact starts in the existing [body registry](../../byte-windows.json). The first excluded word at `0x64d3728` has a relocation of type 1 with addend `0x10` outside the qualifying slot form.

| Slot index | Offset from address point | Target VA | Existing attribution |
| --- | --- | --- | --- |
| 7 | `0x38` | `0x60a0240` | `_ZNK7rocksdb21DBOptionsConfigurable13GetOptionsPtrERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE` |
| 9 | `0x48` | `0x60a2470` | `_ZN7rocksdb21DBOptionsConfigurable16ConfigureOptionsERKNS_13ConfigOptionsERKSt13unordered_mapINSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEESA_St4hashISA_ESt8equal_toISA_ESaISt4pairIKSA_SA_EEEPSJ_` |

The table counts slots, including repeated target addresses. It does not assign names to unmatched code or infer a complete C++ class layout. A registered body label is an existing attribution. All aliases are preserved in the full table.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$node"
readelf --debug-dump=frames-interp "$node"
objdump -s --start-address=0x64d36a8 --stop-address=0x64d3730 "$node"
objdump -d -M intel --start-address=0x60a47f0 --stop-address=0x60a495b "$node"
```

Re-derive the typeinfo and name relocations and the signed offset-to-top from [header.json](header.json). Starting at the address point, step by eight bytes while each relocation points into code with a matching unwind start. Decode the registered body's RIP-relative `lea` and follow its register through the recorded adjustment to the store. Moving the expected address point by eight bytes rejects the same instruction trace. The local extraction used Python 3.12.14, pyelftools 0.33 and Capstone 5.0.9. It read the binary without executing it. No byte coverage or acceptance gate changes.
