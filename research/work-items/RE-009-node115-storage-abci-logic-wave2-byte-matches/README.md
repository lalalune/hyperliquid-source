# RE-009: Node #115 First-Party `storage` & `abci` Business-Logic Wave 2 Compiled-Byte FDE Matches

## Target
- Binary: `artifacts/node/115/hl-node` (Linux x86-64 ELF, `105,896,032` bytes)
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Toolchain: `rustc +1.95.0`, Rust 2021 edition, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `tikv-jemallocator = "=0.6.0"`, `#![forbid(unsafe_code)]`

## Summary
- **7 strictly disjoint pure first-party `.text` FDEs = `3,990 B`** (`3,380 / 3,990 = 84.71%` raw-equal, `100.00%` relocation-qualified via `tools/byte_progress.py::compare` with `0` non-relocation byte diffs, `0` relaxations, `0` `core::`/`alloc::`/`std::`/vendored attribution).
- Component breakdown (verified against CGU `.rela.dyn` -> `.data.rel.ro` `core::panic::Location` records and `research/components.json`):
  - **`storage`**: `2` FDEs = `1,105 B` (`db/src/db_hub.rs`, `db/src/rocks_db.rs`)
  - **`abci`**: `5` FDEs = `2,885 B` (`l1/src/abci/state.rs`, `l1/src/abci/hash_signature_tracker.rs`)

## Matched FDEs
| Component | Label | Source Anchor | VA Range | Size | Raw-Equal |
|---|---|---|---|---:|---:|
| `storage` | `db_hub_checkpoint_shard_1692ca0` | `db/src/db_hub.rs:62,66,68` `DbHub::checkpoint_shard` | `0x1692ca0..0x1692fe9` | 841 B | 692 / 841 |
| `storage` | `rocksdb_create_checkpoint_1698c00` | `db/src/rocks_db.rs` `RocksDb::create_checkpoint` | `0x1698c00..0x1698d08` | 264 B | 220 / 264 |
| `abci` | `abci_state_load_and_init_3c13520` | `l1/src/abci/state.rs:123:37` load & init | `0x3c13520..0x3c13609` | 233 B | 195 / 233 |
| `abci` | `abci_state_serialize_closure_4e4a960` | `l1/src/abci/state.rs:151:17,35` serialize closure (copy 1) | `0x4e4a960..0x4e4ac6f` | 783 B | 653 / 783 |
| `abci` | `abci_state_serialize_closure_4e4ac70` | `l1/src/abci/state.rs:151:17,35` serialize closure (copy 2) | `0x4e4ac70..0x4e4af7f` | 783 B | 652 / 783 |
| `abci` | `abci_hash_sig_tracker_prune_slow_5afa3b0` | `l1/src/abci/hash_signature_tracker.rs:174:42,184:22` (copy 1) | `0x5afa3b0..0x5afa5cf` | 543 B | 484 / 543 |
| `abci` | `abci_hash_sig_tracker_prune_slow_5afa5d0` | `l1/src/abci/hash_signature_tracker.rs:174:42,184:22` (copy 2) | `0x5afa5d0..0x5afa7ef` | 543 B | 484 / 543 |

## Verification
```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-logic-wave2-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-logic-wave2-byte-matches/verify.py --rebuild --self-test
(cd research/work-items/RE-009-node115-storage-abci-logic-wave2-byte-matches && sha256sum -c MANIFEST.sha256)
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_storage_abci_logic_wave2_115 -v
```
