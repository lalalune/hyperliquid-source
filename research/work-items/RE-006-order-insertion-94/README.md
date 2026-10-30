# RE-006: Order Book Transition and Resting Order Insertion (node #94)

- Component ID: RE-006 (Book transitions / Order insertion; `l1/book/*`, `l1/slab/*`, `l1/books.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/book/book/impl_insert_order.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for byte-level disassembly of FDE `0x26ebdc0..0x26eff10` (16,720 bytes),
    limit price validation bounds (`MAX_LIMIT_PX = 10^15`), notional bounds (`MAX_NOTIONAL = 0x7ffffffffffffffe`, `MIN_NOTIONAL_FLOOR = 0x0098967f`),
    high-bit error status codes (`0x8000000000000000..0x8000000000000018`), and static source location records in `.data.rel.ro`.
  - Inference for high-level orderbook struct fields, resting order slab memory strides, and matching engine event streams.
  - Unresolved items are listed under Results and Limitations.
- Scope included and excluded:
  - Included:
    - FDE extent: `0x26ebdc0..0x26eff10` (16,720 bytes; file offset `0x26eadc0..0x26eef10`).
    - Numeric bounds:
      - `MAX_LIMIT_PX`: `1_000_000_000_000_000` (10^15).
      - `MAX_NOTIONAL`: `0x7fff_ffff_ffff_fffe`.
      - `MIN_NOTIONAL_FLOOR`: `0x0098_967f` (10,000,000 - 1 raw notional threshold).
    - Status code representations:
      - `0x8000000000000000`: `STATUS_PRICE_OR_TICK`
      - `0x8000000000000001`: `STATUS_NOTIONAL`
      - `0x8000000000000003`: `STATUS_QUEUE_MASK`
      - `0x8000000000000005`: `STATUS_NO_USER_PRICE_QTY`
      - `0x8000000000000006`: `STATUS_POST_ONLY_CROSSES`
      - `0x8000000000000008`: `STATUS_TIF_NOT_MARKETABLE`
      - `0x8000000000000012`: `STATUS_AVAILABLE_SIZE`
      - `0x8000000000000013`: `STATUS_NO_VALID_CROSS`
      - `0x8000000000000014`: `STATUS_INDEX_ROUTE`
      - `0x8000000000000015`: `STATUS_SLOT_EMPTY_FOR_REPLACE`
      - `0x8000000000000016`: `STATUS_SLOT_MISSING`
      - `0x8000000000000017`: `STATUS_DUPLICATE_ORDER`
      - `0x8000000000000018`: `STATUS_OK`
    - Nine static source location records in `.data.rel.ro`:
      - `0x56bd858`: line 514, column 43 -> `/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs` (VA `0x1eaba7`).
      - `0x56bd870`: line 517, column 59 -> `/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs` (VA `0x1eaba7`).
      - `0x56bd888`: line 445, column 56 -> `/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs` (VA `0x1eaba7`).
      - `0x56bd8b8`: line 167, column 17 -> `/home/ubuntu/hl/code_Mainnet/l1/src/book/book/impl_insert_order.rs` (VA `0x1eaba7`).
      - `0x56e9ae0`: line 11, column 29 -> `/home/ubuntu/hl/code_Mainnet/l1/src/dex_registry/clearinghouses.rs` (VA `0x202282`).
      - `0x56e9af8`: line 17, column 33 -> `/home/ubuntu/hl/code_Mainnet/l1/src/dex_registry/clearinghouses.rs` (VA `0x202282`).
      - `0x56bd1a8`: line 197, column 18 -> `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/oracle/oracle.rs` (VA `0x1f685d`).
      - `0x56bd7e0`: line 827, column 1 -> `/home/ubuntu/hl/code_Mainnet/l1/src/qtys/mod.rs` (VA `0x1e65a2`).
      - `0x56bd810`: line 9, column 1 -> `/home/ubuntu/hl/code_Mainnet/l1/src/qtys/impl_sz.rs` (VA `0x1e02f6`).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline structural verification only).
    - No live trading network or execution harness.
    - No full cancel/replace state machine closure.
    - Node #115 and visor targets excluded.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
# Verify authentic node #94 input digest
python3 -c "import hashlib; assert hashlib.sha256(open('artifacts/node/94/hl-node','rb').read()).hexdigest() == '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'"

# Verify packet integrity against sha256 manifest
(cd research/work-items/RE-006-order-insertion-94 && sha256sum -c MANIFEST.sha256)

# Optional human cross-check: disassemble the FDE extent
objdump -d -M intel --start-address=0x26ebdc0 --stop-address=0x26eff10 artifacts/node/94/hl-node
```

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` VA = file offset + 0x2000.

### 1. Observed Binary Facts (Ground Truth)

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `Book::insert_order` / `rest_residual_order` | `0x26ebdc0..0x26eff10` | `0x26eadc0..0x26eef10` | 16,720 B | `3e433627e7c5029341c07d37a9bf8e8d7f7a03a8dd29c5f795283f22b476cdf9` |

#### A. Initial Preconditions & Bounds Checks
- Limit price bound: Compares `limit_px` against constant `10^15` (`0x00038d7ea4c68000`). If out of range, sets high-bit status code `0x8000000000000000`.
- Notional ceiling & floor:
  - Validates `notional = sz * px` against `0x7fff_ffff_ffff_fffe`.
  - Checks minimum notional threshold `0x0098_967f` (exempt for sentinel user accounts).
  - Violation returns `0x8000000000000001` (`STATUS_NOTIONAL`).
- Time-In-Force (TIF) and Post-Only validation:
  - If `tif == AddLiquidityOnly` (Post-Only) and the order crosses the opposing book top, execution halts with `0x8000000000000006` (`STATUS_POST_ONLY_CROSSES`).
  - If `tif == ImmediateOrCancel` and the order cannot immediately fill, it rejects or cancels residual with `0x8000000000000008` (`STATUS_TIF_NOT_MARKETABLE`).

#### B. Resting Residual Insertion & Slab Management
- When an order has unexecuted size (`remaining_sz > 0`):
  - Traverses orderbook price levels (B-tree / queue level structures).
  - Allocates a resting order slot in the orders slab table.
  - Updates level queue: sets `first_key`, `last_key`, and appends slot index into price-level queue.
  - Generates resting order record and updates best bid/ask indicators.
- Source panic records:
  - `0x56bd858` and `0x56bd870`: line 514:43 and line 517:59 in `impl_insert_order.rs`, guarding notional calculation overflow.
  - `0x56bd888`: line 445:56 in `impl_insert_order.rs`, guarding level removal logic.
  - `0x56bd8b8`: line 167:17 in `impl_insert_order.rs`, guarding slot status transitions.

---

### 2. Inferred Role Models (Separated from Binary Proof)

The following role assignments are inferred based on search leads from `references/can1357-hl/l1/book/book/impl_insert_order.rs`:
- Function role: `Book::insert_order(args, asset, ctx) -> InsertOutcome` and `Book::rest_residual_order(args, remaining_sz, asset, ctx) -> Result<SlotId, InsertStatus>`.
- Inferred types:
  - `Side`: `Buy` vs `Sell` (signed price key convention: `-(px as i64)` for bids, `px as i64` for asks).
  - `InsertTif`: `AddLiquidityOnly` (Post-Only), `ImmediateOrCancel` (IOC), `Normal` (GTC).
  - `InsertOutcome`: Struct containing `status: InsertStatus`, `remaining_sz: Sz`, `resting_slot: Option<usize>`, and fill event vectors.

## Implementation and comparison

Not yet implemented in clean-room Rust.
An independent clean-room Rust implementation must:
1. Mirror the 10^15 limit price ceiling and notional boundary constraints.
2. Return exact high-bit `InsertStatus` error codes matching observed values.
3. Enforce post-only crossing rejection and IOC marketability rules.
4. Correctly manage price-level FIFO queues and residual resting order slot allocation.
5. Be independently authored under MIT license without copying from unlicensed reference repositories.
6. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE extent validated: 1/1 (16,720 B).
  - Status error codes cataloged: 13/13 (100%).
  - Panic source records mapped: 9/9 (including 4 in `impl_insert_order.rs`).
- Limitations & Inferences:
  - Order cancellation paths and trade execution settle events outside this FDE are excluded.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How does `Book::cancel_order` locate and unlink resting order slots from the price-level FIFO queue?
