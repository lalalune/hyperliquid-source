# RE-002 · Node #115 RocksDB transaction log iteration

Component: storage and snapshots, native dependency call linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observed transfers

Which external-to-body direct calls and jumps does the authenticated node encode in its transaction log iteration functions? The [root table](roots.tsv) names the 3 complete function windows from the existing [RocksDB body registry](../../byte-windows.json). The [edge table](edges.tsv) derives the concrete linked destinations from the target bytes.

| Root | Instruction VA | Transfer | Destination |
| --- | --- | --- | --- |
| `rocksdb::DBImpl::GetUpdatesSince` | `0x5d48eff` | `call` | `rocksdb::WalManager::GetUpdatesSince` at `0x5faee60` |
| `rocksdb::WalManager::GetUpdatesSince` | `0x5faef0c` | `call` | `rocksdb::WalManager::GetSortedWalFiles` at `0x5fae7e0` |
| `rocksdb::TransactionLogIteratorImpl::NextImpl` | `0x5fb4085` | `call` | `rocksdb::TransactionLogIteratorImpl::OpenLogReader` at `0x5fb3a30` |
| `rocksdb::TransactionLogIteratorImpl::NextImpl` | `0x5fb40b6` | `call` | `rocksdb::TransactionLogIteratorImpl::UpdateCurrentWriteBatch` at `0x5fb4c70` |

The full table records **41 instruction sites**. 18 land at a registered body start, 19 at a PLT entry whose GOT slot has an `R_X86_64_JUMP_SLOT` symbol, and 4 lack either exact destination attribution. The class counts are by instruction site, including multiple transfers to the same address. Names come from the baseline registry or the ELF dynamic symbol table. Where the registry lists aliases, the table retains that ambiguity.

## Reproduce

From the repository root with the pinned node artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x5d48dd0 --stop-address=0x5d48f0e "$target"
objdump -d -M intel --start-address=0x5fb3ef0 --stop-address=0x5fb427a "$target"
objdump -d -M intel --start-address=0x5faee60 --stop-address=0x5faf14c "$target"
objdump -d -j .plt "$target"
readelf -rW "$target"
```

Start each decode at the registered function VA and stop at its exclusive end. Retain direct `call` and unconditional `jmp` instructions with destinations outside that window. Derive each destination as the next instruction VA plus the signed displacement. Look up exact destination starts in the pinned registry. For a PLT destination, decode its first RIP-relative jump and look up the corresponding GOT slot in `.rela.plt`.

The packet was generated with Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. Each root hash matches the registry. Capstone decoded through every root's exclusive end, and independent displacement arithmetic agreed at each recorded site. As a negative control, changing `e85c5f2600` to `e85d5f2600` at `0x5d48eff` computes `0x5faee61` rather than the recorded `0x5faee60`. The input artifact was read only.

Indirect calls, conditional exits, and runtime reachability are outside this map. This analysis adds target linkage evidence without changing registered byte coverage or acceptance gates.
