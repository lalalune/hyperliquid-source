# RE-002 · Node #115 RocksDB cache option initialization

Component: storage and snapshots, native dependency initialization. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

The [initializer census](../RE-001-node115-init-array-census/README.md) records slot 3. The existing byte-window registry identifies `[0x5d411e0, 0x5d41f9a)` as a RocksDB static initialization body. This packet binds the initializer slot to that body and separates the two option-table construction and registration paths within it.

## Observations and source attribution

- Slot 3 at `0x63f36e0` has a relative relocation to `0x5d41fa0`. The wrapper tail-jumps to `0x5d411e0`.
- Before the call at `0x5d4187a`, the body loads and passes five strings to the same helper at `0x5d3f5f0`: capacity, shard count, strict capacity, and the high- and low-priority pool ratios. Before the later tail jump at `0x5d41e5a`, it passes a second set of five strings to that helper. The [transcript](evidence.txt) records their exact spellings, string VAs, and helper call sites.
- Both registration sites transfer to PLT VA `0x63f0f80`. The associated relocation names `__cxa_atexit`. Both use callback VA `0x5d3f820` and DSO argument address `0x64efa20`. The first passes object VA `0x6500120`. The second moves `r13` to `rsi`, with the observed `r13` address formation at `0x5d41ce6` resolving to `0x65000e0`.

The ordered key groups match the LRU and compressed-secondary cache option maps in the pinned [RocksDB v8.1.1 source](https://github.com/meta/rocksdb/blob/6a436150417120a3f9732d65a2a5c2b8d19b60fc/cache/cache.cc). The object labels follow that correspondence. This packet does not map all members of `OptionTypeInfo`, prove the callback body, or infer which options a live node selects. The pre-existing matched-body accounting remains unchanged.

## Reproduction

From the repository root with the pinned artifact materialized, use Python 3.11+, Capstone 5.0.9 and pyelftools 0.33:

```sh
python3 -B research/work-items/RE-002-node115-rocksdb-cache-init/inspect_cache.py
python3 -B research/work-items/RE-002-node115-rocksdb-cache-init/inspect_cache.py research/work-items/RE-002-node115-rocksdb-cache-init/evidence.txt
```

The first command decodes the target's exact wrapper and recorded body range, derives the two sets of string references, and resolves the registration relocation. The second rejects a wrong input at the digest check. Addresses are ELF VAs and the captured node is never executed.
