# RE-009: Node #115 Storage (`db` CGU & `db_home`) Business-Logic Compiled-Byte FDE Matches

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `storage` (`db/src/{db_hub,block_reader,db_home}.rs`).
- **Build profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, edition 2021, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv_jemallocator::Jemalloc` (`tikv-jemallocator = "=0.6.0"`), `#![forbid(unsafe_code)]`.

## Verified Disjoint First-Party `storage` Business-Logic Compiled-Byte FDE Matches (4 windows / 2,218 B)

All **4** windows are strictly first-party `db/src/*.rs` business-logic functions (zero `core::`/`alloc::`/`std::` monomorphizations, zero vendored `rocksdb` attribution, zero visitor/macro-boilerplate attribution), **100.00% relocation-qualified** (`0` non-relocation byte diffs), **1,862 / 2,218 = 83.95% raw-equal**, and strictly disjoint from `research/byte-windows.json` (Wave-5/Wave-6 consolidation-safe) and from every sibling `*byte-matches*`, `*gate-closure*`, `*thinlto*`, `*100pct*`, and `*census*` packet:

1. `0x1692ff0..0x1693220` (`560 B`, `482/560 = 86.07%` raw-equal) — `db/src/db_hub.rs` `DbHub::checkpoint_evm` (computes checkpoint dir & `EvmState` marker path, skips if marker exists, otherwise reads RocksDB properties `"rocksdb.cur-size-all-mem-tables"`, `"rocksdb.block-cache-usage"`, `"rocksdb.size-all-mem-tables"` across `BTreeMap` shards, logs stats, copies checkpoint, and returns `(dir, !exists)`).
2. `0x16940b0..0x16941d9` (`297 B`, `243/297 = 81.82%` raw-equal) — `db/src/block_reader.rs` `<BlockReaderError as Display>::fmt` (5-variant error formatter with `.rodata` messages `"invalid block height: "`, `"could not deserialize db value"`, `"Tokio spawn_blocking join: "`, `"rocks db error: "`, `"More than "` archived blocks).
3. `0x44699c0..0x4469bd8` (`536 B`, `437/536 = 81.53%` raw-equal) — `db/src/db_home.rs` `check_db_home_evm` (formats `OwnedDbDir`, checks `RocksDbShard::EvmState` against `"db_bundle"`, panics `"db_home contains db_bundle {shard:?}"`).
4. `0x5a007c0..0x5a00af9` (`825 B`, `700/825 = 84.85%` raw-equal) — `db/src/db_home.rs` `check_db_home_core` (formats `DbHome` [`Default` -> `"{}/hyperliquid_data/db_hub"` vs `Custom(String)`], checks `[RocksDbShard::Exchange, RocksDbShard::Rpc]` against `"db_bundle"`, panics `"db_home contains db_bundle {shard:?}"`).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-db-cgu-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-db-cgu-logic-byte-matches/verify.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_db_cgu_logic_byte_matches_115 -v
(cd research/work-items/RE-009-node115-db-cgu-logic-byte-matches && sha256sum -c MANIFEST.sha256)
```
