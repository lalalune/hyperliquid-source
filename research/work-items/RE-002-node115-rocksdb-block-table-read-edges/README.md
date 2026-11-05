# RE-002 · Node #115 RocksDB block-based table block retrieval

Component: storage and snapshots, native dependency call linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observed transfers

Which external-to-body direct calls and jumps does the authenticated node encode in its block-based table block retrieval functions? The [root table](roots.tsv) names the 4 complete function windows from the existing [RocksDB body registry](../../byte-windows.json). The [edge table](edges.tsv) derives the concrete linked destinations from the target bytes.

| Root | Instruction VA | Transfer | Destination |
| --- | --- | --- | --- |
| `rocksdb::BlockBasedTable::RetrieveBlock` | `0x6112518` | `call` | `rocksdb::_GLOBAL__N_1::ReadAndParseBlockFromFile` at `0x6101200` |
| `rocksdb::BlockBasedTable::RetrieveBlock` | `0x6112684` | `call` | `rocksdb::BlockBasedTable::MaybeReadBlockAndLoadToCache` at `0x6111830` |
| `rocksdb::BlockBasedTable::RetrieveBlock` | `0x6112609` | `call` | `rocksdb::ParsedFullFilterBlock` at `0x6148520` |
| `rocksdb::BlockBasedTable::RetrieveBlock` | `0x6114267` | `call` | `_ZNSt10unique_ptrIN7rocksdb17UncompressionDictESt14default_deleteIS1_EED1Ev` at `0x60e8a40` |

The full table records **80 instruction sites**. 33 land at a registered body start, 32 at a PLT entry whose GOT slot has an `R_X86_64_JUMP_SLOT` symbol, and 15 lack either exact destination attribution. The class counts are by instruction site, including multiple transfers to the same address. Names come from the baseline registry or the ELF dynamic symbol table. Where the registry lists aliases, the table retains that ambiguity.

## Reproduce

From the repository root with the pinned node artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x61123b0 --stop-address=0x611281d "$target"
objdump -d -M intel --start-address=0x6113ec0 --stop-address=0x61142bd "$target"
objdump -d -M intel --start-address=0x6115a50 --stop-address=0x6115ed5 "$target"
objdump -d -M intel --start-address=0x6117670 --stop-address=0x6117af5 "$target"
objdump -d -j .plt "$target"
readelf -rW "$target"
```

Start each decode at the registered function VA and stop at its exclusive end. Retain direct `call` and unconditional `jmp` instructions with destinations outside that window. Derive each destination as the next instruction VA plus the signed displacement. Look up exact destination starts in the pinned registry. For a PLT destination, decode its first RIP-relative jump and look up the corresponding GOT slot in `.rela.plt`.

The packet was generated with Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. Each root hash matches the registry. Capstone decoded through every root's exclusive end, and independent displacement arithmetic agreed at each recorded site. As a negative control, changing `e8e3ecfeff` to `e8e2ecfeff` at `0x6112518` computes `0x61011ff` rather than the recorded `0x6101200`. The input artifact was read only.

Indirect calls, conditional exits, and runtime reachability are outside this map. This analysis adds target linkage evidence without changing registered byte coverage or acceptance gates.
