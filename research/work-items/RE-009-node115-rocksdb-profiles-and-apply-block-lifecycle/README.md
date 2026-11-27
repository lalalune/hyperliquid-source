# RE-009: Node #115 RocksDB 3-Shard Profiles, TCP Stream Ceiling, Hardfork Compatibility, and `AbciEngine::apply_block` Lifecycle

- **Target release**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: `storage` (`db/src/{rocks_db,db_home,db_hub}.rs`), `abci` (`l1/src/abci/{state,engine}.rs`).
- **Static verification only**: Captured binary is never executed.

## Binary-Backed Findings

### 1. Contrast Between Core L1 Shards (`Exchange`, `Rpc`) and `EvmState` RocksDB Open Profiles
- **Core L1 open (`0x57c6530..0x57c70b4`, path builder `0x5a007c0..0x5a00af9`)**:
  - Subdirectories: `"Exchange"` (`.rodata 0x4595c0`, shard 0) and `"Rpc"` (`.rodata 0x47b428`, shard 1).
  - Default LRU block cache: `0x4000` MiB = **16 GiB** (`0x57c661b`: `mov edi, 0x4000`; shifted `<< 20`), with non-zero override `(gb << 10) << 20`.
  - Block size: `0x8000` = **32 KiB** (`0x57c66c6`: `mov esi, 0x8000` -> `0x5d34c40`).
  - `create_if_missing = true` (`0x5d34c50`), `write_buffer_size = 0x8000000` (**128 MiB**, `0x57c671b` -> `0x5d34c60`), directory creation mode `0o777` (`0x1ff` at `0x57c6957`).
  - Opens a single default column family (`rocksdb_open` `0x5d35a10`).
- **`EvmState` open (`0x4524660..0x4524adb`, path builder `0x44699c0..0x4469bd8`, CF open `0x3d5ed10..0x3d6032d`)**:
  - Subdirectory: `"EvmState"` (`.rodata 0x459a58`, shard 2).
  - Default LRU block cache: `0x800` MiB = **2 GiB** (`0x4524747`: `mov edi, 0x800`; shifted `<< 20`), with non-zero override `(gb << 10) << 20`.
  - Block size: `0x4000` = **16 KiB** (`0x45247f2`: `mov esi, 0x4000` -> `0x5d34c40`).
  - `create_if_missing = true` (`0x5d34c50`), `write_buffer_size = 0x8000000` (**128 MiB**, `0x452482e` -> `0x5d34c60`).
  - Opens multi-CF RocksDB via `0x4524882 -> 0x3d5ed10 -> 0x5d39590` (`rocksdb_open_column_families`), ensuring `"default"` (len `7` at `0x3d5f168`), `"EvmStateAccounts"` (`0x456bf0`), `"EvmStateContracts"` (`0x7bd710`), and `"EvmStateStorage"` (`0x7bd721`), failing with `"Received null column family handle from DB."` (`0x7bd7da`) on null handles.

### 2. RocksDB Read/Write/Batch/Checkpoint/Property C-API Wiring & Size / Marker Guards
- `0x3d5e960..0x3d5eb99`: `rocksdb_readoptions_create` -> `rocksdb_get` -> `rocksdb_readoptions_destroy` (`"Unable to create RocksDB read options..."` `0x7bd742`).
- `0x3d5eba0..0x3d5ed0d`: `rocksdb_writeoptions_create` -> `rocksdb_put` -> `rocksdb_writeoptions_destroy` (`"Could not create RocksDB write options"` `0x94440f`).
- `0x3d4c310..0x3d4c43d` & `0x3d4c6a0..0x3d4c7ba`: `rocksdb_writebatch_create` -> `0x3d9e820` -> `rocksdb_writebatch_destroy`.
- `0x1697060..0x16971ab`: `rocksdb_checkpoint_object_create` (`"Could not create checkpoint object."` `0x47b42b`).
- `0x16971b0..0x16973a6`: `rocksdb_property_value` (`"Failed to convert property name to CString: "` / `"Failed to convert property value to string: "`).
- `0x3d525a0..0x3d526e6`: 2-variant marker/data write error `Debug::fmt` (`cmp dword ptr [rcx], 1` at `0x3d525b6`: tag `0` = `"InvalidMarkerWrite"` `0x7bd730`, tag `1` = `"InvalidDataWrite"` `0x451bf0`), paired with `DbHub` `"dhs/"` sub-path prefix (`0x431b96`).
- **TCP-streamed RocksDB ceiling (`0x5a64aa0..0x5a69c05`, check at `0x5a69415..0x5a6941f`)**:
  - `shr rax, 0xb; cmp rax, 0x2e90edc; ja 0x5a698f7` rejects sizes `>= 100_000_000_000` bytes (`(0x2e90edc + 1) << 11 = 100 GB` decimal) with `"rocksdb from tcp stream too large, exiting"` (`0x93b19c`) / `"RocksDb too large"` (`0x93b1c6`).

### 3. Snapshot Hardfork Newer-Than-Binary Guard & `AbciEngine::apply_block` Full 7-Stage Pipeline
- **Snapshot load hardfork guard (`0x15a20a0..0x15a37fe` at `0x15a2219..0x15a221d` and `0x15a2ae9..0x15a2aed`)**:
  - `cmp [r15+0x10], rax; ja 0x15a3499/0x15a34ef` rejects `state_hardfork_version > binary_hardfork_version` with `"state hardfork version {state} is newer than binary hardfork version {binary}"` (`0x446bcb`), while allowing `<=` (upgrade path).
- **Ordered 7-stage `AbciEngine::apply_block` (`0x5a04e40..0x5a065f8`) pipeline**:
  1. 6 pre-execution guards (`0x5a04ec3..0x5a04f59`, proved in `RE-009-node115-abci-apply-block-guards-and-history-prune`).
  2. `Exchange::begin_block` (`0x5a04fe9 -> 0x5483850..0x5483f43`, `"begin_block"` `0x929dad`).
  3. Action/bundle execution loop (`0x5a05050..0x5a055b0`).
  4. `Exchange::end_block` (`0x5a055b0 -> 0x54897e0..0x548c8e0`, `"build_small_evm_block_and_apply_l1_effects"` `0x92a5cf`, `"build_big_evm_block_and_apply_l1_effects"` `0x92a5f9`).
  5. ABCI digest quorum tracking (`0x5a0584e -> 0x4de4a60..0x4de509a`, `"new abci digests reached quorum"` `0x93a6b9`).
  6. State-root capture & comparison (`0x5a05c5e -> 0x4e3a020`).
  7. History cutoff prune (`0x5a05ea1..0x5a05fbd -> 0x4de5ad0`, `BTreeMap::split_off(&(watermark.saturating_add(1)))`).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-rocksdb-profiles-and-apply-block-lifecycle/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rocksdb_profiles_and_apply_block_lifecycle_115 -v
```
