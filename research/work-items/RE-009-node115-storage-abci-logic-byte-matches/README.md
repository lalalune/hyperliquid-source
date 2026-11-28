# RE-009: Node #115 Storage (`db` CGU) & ABCI Business-Logic Compiled-Byte FDE Matches

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: `storage` (`db/src/{db_hub,db_home,owned_db_home,rocks_db}.rs`) & `abci` (`l1/src/abci/hash_signature_tracker.rs`).
- **Build profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, edition 2021, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv_jemallocator::Jemalloc` (`tikv-jemallocator = "=0.6.0"`), `anyhow = "=1.0.105"`, `#![forbid(unsafe_code)]`.

## Verified Disjoint First-Party Business-Logic Compiled-Byte FDE Matches (7 windows / 1,404 B)

All **7** windows are strictly first-party `db` and `l1/src/abci` functions (zero `core::`/`alloc::`/`std::` monomorphizations, zero visitor/macro-boilerplate attribution), **100.00% relocation-qualified** (`0` non-relocation byte diffs), **1,169 / 1,404 = 83.26% raw-equal**, and strictly disjoint from `research/byte-windows.json` (Wave-4/Wave-5 consolidation-safe) and from every sibling `*byte-matches*`, `*gate-closure*`, `*thinlto*`, `*100pct*`, and `*census*` packet:

### `storage` (`db` CGU `0x16928b0..0x1696b90` — 5 business-logic windows / 898 B, 747/898 = 83.18% raw-equal)
1. `0x16928b0..0x16929ae` (`254 B`, `211/254` raw-equal) — `db/src/db_hub.rs` `evm_db_hub_fast_dir` (`OwnedDbDir(format!("{}/evm_db_hub_fast", format!("{}/hyperliquid_data", GLOBAL_HOME.home)))`; `.rodata 0x44d724` `"/hyperliquid_data"`, `0x4401d0` `"/evm_db_hub_fast"`).
2. `0x16929b0..0x1692aae` (`254 B`, `211/254` raw-equal) — `db/src/db_hub.rs` `evm_db_hub_slow_dir` (`OwnedDbDir(format!("{}/evm_db_hub_slow", format!("{}/hyperliquid_data", GLOBAL_HOME.home)))`; `.rodata 0x43ddeb` `"/evm_db_hub_slow"`).
3. `0x1692ab0..0x1692b79` (`201 B`, `167/201` raw-equal) — `db/src/db_home.rs` `checkpoint_dir_for_height` (`format!("{}/{height}", dir.checkpoint_base())`; `.rodata 0x43473b` `"/checkpoint"`).
4. `0x1692bf0..0x1692c2d` (`61 B`, `51/61` raw-equal) — `db/src/owned_db_home.rs` `<&OwnedDbDir as Display>::fmt` (invoked via `0x1692ad0` inside `0x1692ab0`).
5. `0x1696b10..0x1696b90` (`128 B`, `107/128` raw-equal) — `db/src/rocks_db.rs` `write_checkpoint_complete_marker` (calls `0x1696b90` per-shard marker formatter, invokes touch helper, drops any `anyhow::Error` and frees path `String` via jemalloc `sdallocx`).

### `abci` (`l1/src/abci/hash_signature_tracker.rs` — 2 business-logic windows / 506 B, 422/506 = 83.40% raw-equal)
6. `0x27604d0..0x27605cd` (`253 B`, `211/253` raw-equal) — `l1/src/abci/hash_signature_tracker.rs` `tracker_watermark_seal_prune` (live #1; updates `max_height = max_height.max(h)` at `+0x80`, checks `LazyLock<String>`, seals `+0x90 = 1` when `h == ctx.seal_height`, prunes at `h.saturating_sub(50_000)` [`0xc350`], frees `Vec<u64>` via jemalloc `sdallocx`).
7. `0x27605d0..0x27606cd` (`253 B`, `211/253` raw-equal) — `l1/src/abci/hash_signature_tracker.rs` `tracker_watermark_seal_prune` (live #2; identical live monomorphization with distinct call-site locations).

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-logic-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-logic-byte-matches/verify.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_storage_abci_logic_byte_matches_115 -v
(cd research/work-items/RE-009-node115-storage-abci-logic-byte-matches && sha256sum -c MANIFEST.sha256)
```
