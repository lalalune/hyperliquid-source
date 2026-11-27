# RE-009: Node #115 ABCI ThinLTO + `tikv-jemallocator` Byte Matches & `node115-db` Checkpoint Marker

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Components**: `abci` (`l1/src/abci/*.rs` first-party compiled-byte windows) & `storage` (`src/node115-db` behavioral anchors).
- **Build profile**: `rustc 1.95.0 (59807616e 2026-04-14)`, edition 2021, `opt-level = 3`, `overflow-checks = true`, `lto = "thin"`, `#[global_allocator] tikv_jemallocator::Jemalloc` (`tikv-jemallocator = "=0.6.0"`), `#![forbid(unsafe_code)]`.

## Verified Disjoint Non-Visitor First-Party Compiled-Byte FDE Matches (3 windows / 836 B)

All **3** windows are strictly first-party (`storage_abci_extra` defining crate — zero `core::`/`alloc::`/`std::` monomorphizations), **100.00% relocation-qualified** (`0` non-relocation byte diffs), **714 / 836 = 85.41% raw-equal**, and strictly disjoint from `research/byte-windows.json` (Wave-4 consolidation-safe) and from every sibling `*byte-matches*`, `*gate-closure*`, `*thinlto*`, `*100pct*`, and `*census*` packet:

### `abci` (`l1/src/abci/*.rs` — 3 non-visitor `Debug` windows / 836 B, 714/836 = 85.41% raw-equal)
1. `0x2772c80..0x2772d7d` (`253 B`, `213/253` raw-equal) — `l1/src/abci/hash_signature_tracker.rs` `<&HashHardQuorum as Debug>::fmt` (live copy; `.rodata 0x5f6fcd` `"HashHardQuorum"`, proving `0x20`-byte `FxMap` layout at `+0x00`/`+0x20` and `hash: [u8; 32]` at `+0x40`).
2. `0x5b08940..0x5b08a3d` (`253 B`, `217/253` raw-equal) — `l1/src/abci/hash_signature_tracker.rs` `<&HashHardQuorum as Debug>::fmt` (slow-path copy).
3. `0x57d1030..0x57d117a` (`330 B`, `284/330` raw-equal) — `l1/src/abci/` `<&L1Hash as Debug>::fmt` (lowercase-hex `DebugTuple` with alternate pretty-print indent; `.rodata 0x9362b4` `"L1Hash"`).

## Additional `storage` Behavioral Anchors Ported to `src/node115-db`

- `0x1696b90..0x1696d23` (`403 B`, `.rodata 0x442eae` `"/CHECKPOINT_COMPLETE_"`): per-shard lowercase checkpoint marker path (`CHECKPOINT_COMPLETE_exchange`, `CHECKPOINT_COMPLETE_rpc`, `CHECKPOINT_COMPLETE_evmstate`).
- `0x16961b0..0x1696729` (`1,401 B`, `.rodata 0x447e29` `"OwnedDbDir invalid dir "`): rejects any owned DB directory path containing `"checkpoint"`.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-jemalloc-thinlto-byte-matches/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-009-node115-storage-abci-jemalloc-thinlto-byte-matches/verify.py --rebuild --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_storage_abci_jemalloc_thinlto_115 -v
(cd research/work-items/RE-009-node115-storage-abci-jemalloc-thinlto-byte-matches && sha256sum -c MANIFEST.sha256)
```
