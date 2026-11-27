# RE-006: node #115 orderbook `Book` 8-field layout, `cloid_tracker`/`CancelByCloid`, `Trigger`/`TriggerOrder`/`tpsl`, `TwapState`/`TwapHeapKey`, and `ScheduleCancel` integration

- Component ID: `orderbook` (`RE-006`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation for all `.rodata` struct/variant strings, virtual addresses, and byte digests; inference for the composed Rust APIs (`TriggerBook`, `TwapEngine`, `ScheduleCancelEngine`, `Book::cancel_by_cloid`, `BookKind`). No full-component acceptance gate is claimed by this packet alone.
- Implementation path: `src/node115-orderbook` (`src/{matching,books,trigger,twap,schedule_cancel_book,lib}.rs`).

## Evidence (node #115 `.rodata` & `.text` observations)

| `.rodata` / `.text` VA | Observed #115 schema / behavior |
| --- | --- |
| `.rodata` `0x44bae3`, `0x5c9bf8`, `0x5ed264` | `struct Book` has 8 fields: `halfs`, `oid_to_key`, `cloid_tracker`, `book_orders` (`bod`), `asset`, `user_states`, `last_trade_px`, `total_sz` |
| `.rodata` `0x5e6493`, `0x5e6767` | `struct CancelByCloid` (2 elements: `asset`, `cloid`) and `struct CancelByCloidAction` |
| `.rodata` `0x5ca088`, `0x5ca3a8`, `0x5ed239`, `0x453b8c` | `struct Trigger` (3 elements), `struct TriggerOrder` (2 elements), `tpsl` (`0 <= i < 2`), `is_position_tpsl` |
| `.rodata` `0x5eaf9d` | Order description variants: `Limit`, `Market`, `TakeProfitLimit`, `TakeProfitMarket`, `StopLimit`, `StopMarket` |
| `.rodata` `0x458360`, `0x5c9d18` | `struct TwapState` (7 elements), `struct TwapHeapKey` (3 elements: `next_slice_time`, `twap_id`, `user`), `struct PriorityTracker` (5 elements) |
| `.text` `0x58e74c0` (`book/mod.rs:1153`, 5,296B) | Book invariant / BBO / user-state iteration helper reading `book+0xa8` (`halfs`), `book+0x08/+0x10` (`oid_to_key`), and `book+0xe8/+0xf0/+0xf8/+0x100` (`user_states` BTree/ring niche `0x8000000000000000`) |

## Reproduce

```sh
python3 tools/artifacts.py verify
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_orderbook_twap_trigger_cloid_115
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/assets-fees-book \
  cargo test --offline --locked --manifest-path src/node115-orderbook/Cargo.toml
(cd research/work-items/RE-006-node115-twap-trigger-cloid && sha256sum -c MANIFEST.sha256)
```
