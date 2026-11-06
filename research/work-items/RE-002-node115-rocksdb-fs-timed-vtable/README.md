# RE-002 · Node #115 RocksDB TimedFileSystem virtual dispatch

Component: storage and snapshots. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Table and object-side anchor

The `.rodata` string at `0x97f3d0` is `N7rocksdb15TimedFileSystemE`. The typeinfo object at `0x64d83d0` has a RELATIVE relocation to that string at offset 8 and an absolute relocation to `_ZTVN10__cxxabiv120__si_class_type_infoE + 16` at offset 0. A RELATIVE relocation at `0x64d83f0` points to that object. The preceding signed word at `0x64d83e8` is zero. This matches the [Itanium C++ ABI table layout](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#vtable-components) with the address point at `0x64d83f8`.

The single-inheritance typeinfo field at `0x64d83e0` has a RELATIVE relocation to base typeinfo `0x64ced40`. Its linked name is `N7rocksdb17FileSystemWrapperE` at `0x972d90`. This identifies the immediate RTTI base. It does not describe the full object layout.


The unwind-backed body at `0x61f0390` computes this table's header or address point at `0x61f039d`. [stores.tsv](stores.tsv) records that `lea`, any immediate adjustment, and the 64-bit memory store of the resulting address point. The complete selected trace is `0x61f039d: 488d0544802e00 lea rax, [rip + 0x2e8044]`, then `0x61f03a4: 4883c010 add rax, 0x10 | 0x61f03a8: 488903 mov qword ptr [rbx], rax`. The scan checks each candidate at an instruction boundary decoded from its actual FDE start. 1 of 1 store sites have no exact registry attribution. The TSV records each store body's FDE and byte-range digest.

## Linked slots

[slots.tsv](slots.tsv) records the contiguous relocation-backed prefix of **61 function entries**. All 61 land at starts in the authenticated artifact's `.eh_frame_hdr` search table. The scan follows each search record to the actual FDE in `.eh_frame` and verifies that its start equals the slot addend. The TSV records the descriptor VA and exclusive function end. The table also records the SHA-256 of each exact FDE byte range and the first eight bytes or the full range if shorter. These fingerprints include targets with no registered symbol label. 30 have labels from exact starts in the existing [body registry](../../byte-windows.json). The first excluded word at `0x64d85e0` has a relocation of type 1 with addend `0x10` outside the qualifying slot form.

| Slot index | Offset from address point | Target VA | Existing attribution |
| --- | --- | --- | --- |
| 2 | `0x10` | `0x609d760` | `_ZNK7rocksdb12Customizable9GetOptionERKNS_13ConfigOptionsERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPS9_` |
| 3 | `0x18` | `0x609dc40` | `_ZNK7rocksdb12Customizable13AreEquivalentERKNS_13ConfigOptionsEPKNS_12ConfigurableEPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE` |
| 5 | `0x28` | `0x5fe7d00` | `_ZN7rocksdb17FileSystemWrapper14PrepareOptionsERKNS_13ConfigOptionsE` |
| 6 | `0x30` | `0x6096790` | `_ZNK7rocksdb12Configurable15ValidateOptionsERKNS_9DBOptionsERKNS_19ColumnFamilyOptionsE` |

The table counts slots, including repeated target addresses. It does not assign names to unmatched code or infer a complete C++ class layout. A registered body label is an existing attribution. All aliases are preserved in the full table.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$node"
readelf --debug-dump=frames-interp "$node"
objdump -s --start-address=0x64d83e8 --stop-address=0x64d85e8 "$node"
objdump -d -M intel --start-address=0x61f0390 --stop-address=0x61f03ab "$node"
```

Re-derive the typeinfo and name relocations and the signed offset-to-top from [header.json](header.json). Starting at the address point, step by eight bytes while each relocation points into code with a matching unwind start. For the code fingerprint, map the slot addend to a file offset within `.text` and hash the bytes through the FDE's exclusive end. Decode the recorded body's RIP-relative `lea` and follow its register through the recorded adjustment to the store. Moving the expected address point by eight bytes rejects the same instruction trace. The local extraction used Python 3.12.14, pyelftools 0.33 and Capstone 5.0.9. It read the binary without executing it. No byte coverage or acceptance gate changes.
