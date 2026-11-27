# RE-009: node #115 complete `db` crate diagnostic map and integrated library

- Component ID: `storage` (`db/*` — 5/5 observed diagnostic source paths)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Method: static ELF/Location/FDE/instruction verification over the pinned #115 binary. No target execution.

## All 5 `db/src/*.rs` files mapped in node #115

| Source file | #115 `Location` count | Key enclosing FDEs | Binary-backed semantics integrated into `src/node115-db` |
| --- | --- | --- | --- |
| `db/src/block_reader.rs` | 3 (`L27:70`, `L29:26`, `L45:114`) | `0x2a191e0`, `0x2b2be60`, `0x2a0acc0` | SSTable `BlockHandle` varint codec (`node115-block-handle-codec`) and `IndexedArtifactVariant` classifier (`node115-indexed-artifact-variant`). |
| `db/src/db_home.rs` | 13 (`L21`, `L85`, `L286..317`) | `0x25d3f20`, `0x4468e30`, `0x59ffa30`, `0x44699c0`, `0x5a007c0`, `0x44681e0` | Rejects `"db_bundle"` in `db_home` path (`0x4469b5d`), checks `"EvmState"` (`0x4469a72`), checkpoint discovery (`node115-checkpoint-discovery`), lifecycle plan (`node115-checkpoint-plan`), restore `cp -al <dir>/EvmState <live_home>` (`node115-restore-copy`), replica end-height (`node115-replica-end-height`). |
| `db/src/db_hub.rs` | 7 (`L25`, `L51`, `L62`, `L66`, `L68`) | `0x38b3ad0`, `0x4e33ef0`, `0x3d4c7c0..0x3d4d420`, `0x57c58d0..0x57c6530`, `0x1692ca0` | Byte-key B-tree lookup (`node115-db-hub-byte-key`), 32-byte MsgPack storage-value decoding (`node115-storage-value-decode`), snapshot selector admission & routing. |
| `db/src/owned_db_home.rs` | 3 (`L21:9`, `L72:37`) | `0x16961b0`, `0x4524660`, `0x57c6530` | Rejects any path containing the 10-byte substring `"checkpoint"` (`0x696f706b63656863` + `0x746e` at `0x16961dc..0x169622f`, `OwnedDbDirError`); live (`2 GiB`) vs slow (`16 GiB`) cache budget (`node115-owned-db-open`). |
| `db/src/rocks_db.rs` | 2 (`L58:49`) | `0x4524660`, `0x57c6530` | RocksDB open option immediates (`BLOCK_SIZE = 0x4000`, `OPTIONS_FLAG = 1`, `COMPANION_BYTES = 0x0800_0000`) and error niche `0x8000_0000_0000_0000`. |

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-db-crate-map/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_db_crate_map_115
(cd research/work-items/RE-009-node115-db-crate-map && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/storage-abci \
  cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
```

## Limits

- Live RocksDB C++ FFI/column-family calls, filesystem-level concurrency, and full component identity equivalence remain open; no component gate in `research/progress.json` is advanced here.
