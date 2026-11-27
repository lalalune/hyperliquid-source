# RE-006: Rust Port of Node #115 Orderbook Impact Walk (`0x46a6370`), Order Price Shaping (`0x5a21510`), and L2 Aggregation

- **Target binary**: Linux x86-64 node #115 (`artifacts/node/115/hl-node`)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Component**: `orderbook` (`src/node115-orderbook/src/{impact_walk,price_shape,matching,lib}.rs`)

## Scope and Method

Closes the previously "not yet implemented in Rust" specifications in `RE-014-book-impact-walk-115` (`0x46a6370` + `0x37c5dd0`) and `RE-006-order-price-shape-115` (`0x5a21510` / `0x5a21ed0` / `0x2d3a160`), binds all 6 `.text` FDE SHA-256 digests (`9,544 B` total, including `LevelSummary` serializer `0x241e9b0`), 6 `.rodata` IEEE-754 constants, and both `.rodata` system-user exemption keys (`[0xff; 20]` / `[0xee; 20]`) directly against node #115, and wires `Book::impact_px`, `Book::impact_pxs`, `Book::l2_snapshot_aggregated`, and `shape_order_price` into `src/node115-orderbook`.

## Directly Observed Binary Evidence

1. **Orderbook impact walk (`0x46a6370..0x46a685c`, 1,260 B) & B-tree step (`0x37c5dd0..0x37c5ff4`, 548 B)**:
   - Walks best-to-worst book levels summing resting order sizes with `sat_add`, rejects zero-size or `px * sz > 0x7fff_ffff_ffff_fffe`, and returns `Some(Px(total / count))` at the target-reaching level (with `q = (target - running) / px`, returning `None` if `count == 0 || count - 1 >= total` or if exhausted).
2. **Order price shaping (`0x5a21510..0x5a21ed0`, 2,496 B; `0x5a21ed0..0x5a22890`, 2,496 B; `0x2d3a160..0x2d3ab3b`, 2,523 B)**:
   - Reference/stop selection, amount vs fraction (`±100_000.0` at `0x459510`/`0x458f20`) move, `1.1` (`0x459400`) / `0.9` (`0x459788`) limit factor, tick-grid snap (`q + 1` for Ask, `q` for Bid), max notional `0x1999_9999_9999_9999` (`0x6d`), available notional (`0x6c`, `/ 1_000_000.0` at `0x4599a0`), `$10.00` min-notional (`> 9_999_999`, `0xc8`) with system users `[0xff; 20]` (`0x93e30b`) & `[0xee; 20]` (`0x93eb11`), rate-limit alert (`0x78`, `+5000 ms`), and price-band ratio test (`0x63`, `* 100.0` at `0x459498`).
3. **`LevelSummary` serializer (`0x241e9b0..0x241ea8d`, 221 B)**: anchored for L2 level summary representation (`px`, `sz`, `n`).

## Scope Boundary

- `aggregate_l2_levels` / `bucket_l2_px` implement conservative `n_sig_figs`/`mantissa` L2 bucketing on top of `Book::l2_levels`; exact RPC JSON wire formatting of `L2Book` remains in `info-api`.
- This packet advances `orderbook` behavioral coverage and does not claim the full `identity` gate.
