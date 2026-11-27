# RE-006: Node #115 Complete `orderbook` (`l1/src/book/*`, `l1/src/slab/*`, `l1/src/books.rs`) Full-Scope Closure

## Scope & Target

- **Target binary**: `artifacts/node/115/hl-node` (`105,896,032` bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
- **Component**: `orderbook` (`l1/book/*`, `l1/slab/*`, `l1/books.rs`, `l1/order_wire.rs` — Stream E1 / `RE-006`).
- **Objective**: Provide an exhaustive, machine-verified full-scope closure of **every** observed `orderbook` source file (**6/6**: `l1/src/book/book/impl_insert_order.rs`, `l1/src/book/book/mod.rs`, `l1/src/book/book_orders.rs`, `l1/src/book/level.rs`, `l1/src/books.rs`, `l1/src/slab/slab.rs`), **every** `.data.rel.ro` `Location` struct (**35/35**, `0` unreferenced), **every** `.text` FDE referencing those `Location` structs (**36/36** core `book/*`+`slab/*` FDEs = `191,801 B` plus **140/140** `books.rs`-only caller FDEs = `549,681 B`; **176/176** Location FDEs = `741,482 B`), and **4/4** audited extra business-logic FDEs (`8,775 B`: impact walk `0x46a6370` + 3 price-shaper CGUs `0x5a21510`, `0x5a21ed0`, `0x2d3a160`) — **180 unique FDEs (`750,257 B`)** combined.

## Complete Source-File & Panic-Location Closure

1. **`l1/src/book/book/impl_insert_order.rs` (10 Locations / 5 sites × 2 CGUs)**:
   - `:197:17` (`"assertion failed: reduce_only"` at `.rodata 0x937ff2`), `:537:45` (priority ring append `0x5911890`/`0x5911b30`), `:593:43` & `:597:54` (resting level/slot insertion unwrap), `:744:91` (self-trade prevention `0x23f5460`/`0x5911dd0`/`0x5912740`).
   - Mapped to `src/node115-orderbook/src/{matching.rs,priority_level.rs}`.
2. **`l1/src/book/book/mod.rs` (8 Locations / 4 sites × 2 CGUs)**:
   - `:1148:79`, `:1149:54`, `:1149:64` (L2 snapshot / top-orders unwraps in `0x22eea60`/`0x22eef90`/`0x50bcc80`/`0x50bd240`), `:1153:17` (`"book is crossed book=..."` at `.rodata 0x43f061` in `0x23d4790`/`0x23d76c0`/`0x58e74c0`/`0x58e8970`, enforced by `Book::is_crossed` & `Book::assert_not_crossed`).
   - Mapped to `src/node115-orderbook/src/{matching.rs,impact_walk.rs,price_shape.rs}`.
3. **`l1/src/book/book_orders.rs` (8 Locations / 4 sites × 2 CGUs)**:
   - `:81:40` & `:89:40` (doubly-linked slab insert/link `0x23cd2d0`/`0x23cd700`/`0x58df360`/`0x58df790`), `:137:44` & `:145:44` (cancel/modify unlink from level `0x23ce3e0`/`0x23d0600`/`0x58dfbc0`/`0x58dff20`).
   - Mapped to `src/node115-orderbook/src/{slab.rs,relations.rs}`.
4. **`l1/src/book/level.rs` (2 Locations / 1 site × 2 CGUs)**:
   - `:32:54` (`"called \`Result::unwrap()\` on an \`Err\` value"` at `.rodata 0x91f9eb`) in level priority-deque / summary maintenance (`0x25da200`/`0x25da3e0`/`0x518f240`/`0x5192060`/`0x5192240` + unlink/insert callers).
   - Mapped to `src/node115-orderbook/src/{slab.rs,priority_level.rs}`.
5. **`l1/src/slab/slab.rs` (2 Locations / 1 site × 2 CGUs)**:
   - `:78:21` (slab slot allocation/recycling invariant in `0x23cd2d0`/`0x23cd700`/`0x58df360`/`0x58df790`).
   - Mapped to `src/node115-orderbook/src/slab.rs`.
6. **`l1/src/books.rs` (5 Locations / 2 sites across CGUs)**:
   - `:14:16` (`Books::get` bounds check `panic_bounds_check`) and `:19:47` (`Books::get_mut` unwrap), referenced by 140 caller FDEs (`549,681 B`).
   - Mapped to `src/node115-orderbook/src/books.rs`.

## Complete `orderbook` Acceptance Inventory

- **Mapped**: 6/6 `orderbook` source files, 35/35 `Location` structs (`0` unreferenced), 176/176 Location-referencing FDEs (`741,482 B`) + 4/4 extra business FDEs (`8,775 B`) = **180 unique FDEs (`750,257 B`)** verified against `work/index/node-115-fde.tsv` and raw ELF bytes.
- **Built & Behavior**: Integrated `src/node115-orderbook` (`#![forbid(unsafe_code)]`, 0 external deps, wired into `src/hl-node` and `src/exchange`) combines `node115-assets`, `node115-fees`, and all 19 verified Cargo-packaged `orderbook` micro-crates with full implementations of slab allocation/recycling, doubly-linked per-level FIFO queues, priority ring splicing, peer/parent-child relations, TIF (`Alo`/`Ioc`/`Gtc`/`FrontendMarket`/`LiquidationMarket`), self-trade prevention (including HLP vault set), resting reduce-only & margin clamping, cancel/modify, `Book::assert_not_crossed`, impact walk & L2 bucketing, 12-step order price shaping, TWAP, triggers, schedule-cancel, and multi-asset `Books`.
- **Compiled-Byte Identity (honest status)**: `identity` remains `false`; compiled-byte proof currently covers **66** non-visitor `orderbook` ThinLTO `Debug::fmt` FDEs (`27,425 B`) in `RE-006-node115-stream-e1-thinlto-byte-matches` plus leaf `orderbook` helpers in `RE-004-node115-stream-e1-byte-matches`.

## Verification

```bash
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-006-node115-orderbook-closure/verify.py --self-test
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_orderbook_closure_115 -v
(cd research/work-items/RE-006-node115-orderbook-closure && sha256sum -c MANIFEST.sha256)
```
