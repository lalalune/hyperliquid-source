# RE-002 · Node #115 RocksDB WAL record emission

Component: storage and snapshots, native dependency call linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observed transfers

Which external-to-body direct calls and jumps does the authenticated node encode in its WAL record emission functions? The [root table](roots.tsv) names the 3 complete function windows from the existing [RocksDB body registry](../../byte-windows.json). The [edge table](edges.tsv) derives the concrete linked destinations from the target bytes.

| Root | Instruction VA | Transfer | Destination |
| --- | --- | --- | --- |
| `rocksdb::DBImpl::WriteToWAL` | `0x5e86ed1` | `call` | `rocksdb::WriteBatch::VerifyChecksum` at `0x5fbc1a0` |
| `rocksdb::DBImpl::WriteToWAL` | `0x5e86f14` | `call` | `rocksdb::log::Writer::AddRecord` at `0x5f03d60` |
| `rocksdb::DBImpl::WriteToWAL` | `0x5e89d3d` | `call` | `rocksdb::DBImpl::MergeBatch` at `0x5e86c80` |
| `rocksdb::DBImpl::WriteToWAL` | `0x5e8a1d2` | `call` | `rocksdb::WritableFileWriter::Sync` at `0x6052800` |

The full table records **50 instruction sites**. 23 land at a registered body start, 17 at a PLT entry whose GOT slot has an `R_X86_64_JUMP_SLOT` symbol, and 10 lack either exact destination attribution. The class counts are by instruction site, including multiple transfers to the same address. Names come from the baseline registry or the ELF dynamic symbol table. Where the registry lists aliases, the table retains that ambiguity.

## Reproduce

From the repository root with the pinned node artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x5e86e80 --stop-address=0x5e87019 "$target"
objdump -d -M intel --start-address=0x5e89c90 --stop-address=0x5e8a4a9 "$target"
objdump -d -M intel --start-address=0x5e90500 --stop-address=0x5e908bd "$target"
objdump -d -j .plt "$target"
readelf -rW "$target"
```

Start each decode at the registered function VA and stop at its exclusive end. Retain direct `call` and unconditional `jmp` instructions with destinations outside that window. Derive each destination as the next instruction VA plus the signed displacement. Look up exact destination starts in the pinned registry. For a PLT destination, decode its first RIP-relative jump and look up the corresponding GOT slot in `.rela.plt`.

The packet was generated with Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. Each root hash matches the registry. Capstone decoded through every root's exclusive end, and independent displacement arithmetic agreed at each recorded site. As a negative control, changing `e8ca521300` to `e8cb521300` at `0x5e86ed1` computes `0x5fbc1a1` rather than the recorded `0x5fbc1a0`. The input artifact was read only.

Indirect calls, conditional exits, and runtime reachability are outside this map. This analysis adds target linkage evidence without changing registered byte coverage or acceptance gates.
