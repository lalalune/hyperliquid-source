# RE-009: Node #115 `storage` (`db/src/*.rs`) Complete 21-FDE / 28-Location Full-Scope Closure

- **Component ID**: `storage` (`db` crate: all 5 observed source files `block_reader.rs`, `db_home.rs`, `db_hub.rs`, `owned_db_home.rs`, `rocks_db.rs`).
- **Target release**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`, `105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Static verification only**: Captured binary is never executed.

## Complete `db/src/*.rs` Inventory (5/5 Files, 28/28 Locations, 21/21 FDEs = 32,810 B)

1. **`db/src/block_reader.rs` (3 Locations, 3 FDEs = 4,287 B)**:
   - `0x2a191e0..0x2a195a7` (`block_reader.rs:27:70`, 967 B): `BlockReader::block` point lookup.
   - `0x2b2be60..0x2b2c4f1` (`block_reader.rs:29:26`, 1,681 B): Tokio single-run `spawn_blocking` wrapper (`[internal exception] blocking task ran twice`, `2698f40`).
   - `0x2a0acc0..0x2a0b327` (`block_reader.rs:45:114`, 1,639 B): `BlockReader::range_query_inclusive`.
2. **`db/src/db_home.rs` (13 Locations, 6 FDEs = 13,689 B)**:
   - `0x25d3f20..0x25d4cab` (3,467 B), `0x4468e30..0x44699c0` (2,960 B), `0x59ffa30..0x5a007bb` (3,467 B) (`db_home.rs:21:24`): checkpoint discovery & latest-checkpoint loader with exact 3-variant error ladder:
     1. `"checkpoint outer dir does not exist "` (`.rodata 0x433a08`) when `<db_home>/checkpoint` (`.rodata 0x43473b`) is missing;
     2. strict unsigned ASCII digit parsing (`cmp esi, 0x2b` / `0x2d` rejecting `+`/`-` at `0x4469183`/`0x4469188`, digit range `<= 9` at `0x44691d7`), verifying `"/CHECKPOINT_COMPLETE"` (`.rodata 0x44bb46`) + required shard subdir;
     3. `"no checkpoints to load: "` (`.rodata 0x435938`) if 0 candidates exist, or `"unable to load any current checkpoint from "` (`.rodata 0x436988`) if candidates exist but none are valid/loadable.
   - `0x44681e0..0x4468b62` (`db_home.rs:286,291,302,309,310,317`, 2,434 B): `checkpoint/<height>` and `lt_hashes.json` copy/sync (`RE-009-node115-exchange-root-capture-and-db-paths`).
   - `0x44699c0..0x4469bd8` (536 B) & `0x5a007c0..0x5a00af9` (825 B) (`db_home.rs:85:13`): `"EvmState"`, `"Exchange"`, `"Rpc"` subdirs + `"$db_home contains db_bundle in path: "` guard.
3. **`db/src/db_hub.rs` (7 Locations, 9 FDEs = 9,338 B)**:
   - `0x38b3ad0..0x38b3f8c` (1,212 B) & `0x4e33ef0..0x4e342a5` (949 B) (`db_hub.rs:25:38`): `DbHub::new` resolving `"{home_dir}/hyperliquid_data/db_hub"` (`.rodata 0x443e3b`, reading `STATIC_CONFIG` `0x64f06c0`).
   - `0x3d4c7c0/cbe0/d000` & `0x57c58d0/cf0/6110` (6 × 1,056 B = 6,336 B, `db_hub.rs:51:18`): 29-kind 2-byte prefix table (`0x6479df0 -> 0x7bd4ed`), 3-shard bitmask routing (`0x031f_feff` / `0x00e0_0100` / shard 2), and `"dhs/"` sub-path prefix (`RE-009-node115-db-hub-routing-and-abci-schema`).
   - `0x1692ca0..0x1692fe9` (`db_hub.rs:62:41, 66:14, 68:14`, 841 B): `DbHub` checkpoint directory creation (`0o777` `0x1ff` at `0x1692ce3`), shard copy (`0x1698c00`), and completion marker write via `base/src/fu.rs` (`write_bytes_to_file`).
4. **`db/src/owned_db_home.rs` (3 Locations, 3 FDEs = 5,496 B; 2 shared with `rocks_db.rs`)**:
   - `0x16961b0..0x1696729` (`owned_db_home.rs:21:9`, 1,401 B): `"checkpoint"` path guard.
   - `0x4524660..0x4524adb` (1,147 B) & `0x57c6530..0x57c70b4` (2,948 B) (`owned_db_home.rs:72:37`, `rocks_db.rs:58:49`): live `EvmState` (2 GiB / 16 KiB / 128 MiB / multi-CF `0x3d5ed10`) vs core L1 `Exchange`/`Rpc` (16 GiB / 32 KiB / 128 MiB / single CF) RocksDB open profiles (`RE-009-node115-rocksdb-profiles-and-apply-block-lifecycle`).
5. **`db/src/rocks_db.rs` (2 Locations, shared FDEs above + companion `0x3d5ed10`, `0x3d5e960`, `0x3d5eba0`, `0x1697060`, `0x16971b0`, `0x3d525a0`)**.

## Compiled-Byte Identity Accounting (`storage`)
- `RE-009-node115-storage-abci-byte-matches`: 14 windows / 886 B.
- `RE-009-node115-storage-abci-debug-byte-matches`: 3 non-visitor `DbWriteError::fmt` windows / 978 B.
- Total authenticated `storage` compiled-byte FDEs: **17 windows / 1,864 B** (100% relocation-qualified; `identity` gate remains `false` honestly until full-crate FDE identity is met).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-db-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_storage_db_closure_115 -v
```
