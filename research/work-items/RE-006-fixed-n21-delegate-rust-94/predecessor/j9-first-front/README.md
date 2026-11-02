# Node #94 order-book lifecycle

`node94-orderbook` is an independently authored, dependency-free Rust library
for the bounded RE-006 book-state transitions established against the
authenticated node #94 binary:

`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`

It is a standalone component, not a root workspace or a speculative exchange.
The safe Rust representation is not claimed to match the target ABI. Verified
target offsets and the `0xf8` slot stride are retained separately in
`layout.rs`.

## Implemented scope

- slab-style order slots with append allocation and LIFO free-list reuse;
- node #94's bid `-price` and ask `+price` ascending keys;
- FIFO-shaped price-level head/tail and previous/next links;
- insert, unlink, cancel, empty-level deletion, and saturating global quantity;
- user-wide collect/sort/deduplicate/cancel over a fixed order list;
- parent/child and reciprocal peer relations plus depth-first cascade cancel;
- one resting-slot match transition, partial/full fills, verified result words,
  fill-mask bit ordering, and the inclusive notional ceiling;
- a consistency checker and deterministic offline snapshots.

The matching API consumes `MatchLimits`, the already-computed results of the
external cap and fill-mask helpers observed in the target. It does not compute
margin, leverage, positions, oracle state, or other clearinghouse behavior.
`match_best_once` consumes at most one FIFO head. The surrounding price-crossing
walk and full insertion loop are outside this crate.

## Explicitly unsupported

- target duplicate-order behavior (duplicates return
  `UnsupportedDuplicateOrder` without mutating the book);
- target repeated-cancellation semantics (the safe API returns `VacantSlot`
  after the first successful removal);
- reduce-only matching without external signed-position state;
- the unresolved special self-cross predicate beyond equal 20-byte users;
- full perp/spot insertion, trigger orders, rollback, concurrency, settlement,
  fees, event emission, persistence, networking, and live trading;
- source, ABI, machine-code, whole-component, or full-reconstruction identity.

No captured executable is run by this crate or its tests.

## Example

```rust
use node94_orderbook::{
    Book, InsertOrder, MatchLimits, OrderId, Side, TakerOrder, UserId,
};

let mut book = Book::new();
book.insert(InsertOrder {
    order_id: OrderId(1),
    user: UserId::repeated(1),
    side: Side::Ask,
    price: 100,
    quantity: 10,
    reduce_only: false,
})?;

let result = book.match_best_once(
    TakerOrder {
        order_id: OrderId(2),
        user: UserId::repeated(2),
        side: Side::Bid,
        price: 100,
        asset: 10_001,
        budget: 4,
    },
    MatchLimits::PERMISSIVE,
)?;

book.check_consistency()?;
let stable_text = book.snapshot()?.render();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Evidence map

| Implemented behavior | Retained upstream packet |
| --- | --- |
| slot/free-list, signed prices, FIFO links, aggregate boundaries | `RE-006-price-level-lifecycle-94` |
| one match body, status words, caps, mask, notional boundary | `RE-006-match-resting-order-94` |
| sorted fixed-list user cancellation | `RE-006-user-book-cancel-94` |
| parent/peer/children and depth-first cascade | `RE-006-order-relation-transitions-94` |
| partial-fill caller subtraction | `RE-006-node94-orderbook-94/partial-fill-caller.tsv` |

`RE-006-order-request-view-94` and `RE-006-open-order-view-94` were reviewed
but are not implementation inputs for this bounded mutation engine. In
particular, `OrderView` is a safe projection of the live Rust slot, not the
target's `0xa8` client-facing record, and it makes no claim about target float
scaling, timestamps, trigger text, or child view construction.

The implementation packet records exact target coordinates, source/base pins,
commands, limitations, and the distinction between observations and safe
component policies.

## One local short-run insertion

`first_left_insertion::insert_loaded` represents only the native j=8 step at
node94 `0x4918eef..0x4918f4d`, reached on the qualified n=21..32 short-run
path. Its chosen safe API accepts a nine-qword scratch window and the already
loaded value. It moves only the contiguous suffix of unsigned-greater words
right, preserving earlier prefix words even when that prefix is unsorted.
Equality stops the scan. The returned insertion index is chosen observation
metadata, not a recovered target return value.

The module does not recover seed behavior, subsequent insertions, the right
half, merge, a full sorting API or the original pointer/alias contract. Book
callers are unchanged. Evidence, frozen states and compiled comparison scope
belong to `RE-006-first-left-insertion-rust-94`.
## Separate short-run point relations

`j9_first_front` exposes two separate safe projections: exactly the entered
native j=9 insertion over a ten-word scratch window, and the conditional
n21 first merge-front write from two current front values. The latter is not
composed with the former into a sorter. Seed/right-half transformations,
global minimum, subsequent merge, original ABI and book-caller integration
remain unresolved. Returned index/side are chosen observation metadata.
See `RE-006-j9-first-front-rust-94` for native premises and frozen comparisons.

## Build and test

```sh
cargo test --manifest-path src/node94-orderbook/Cargo.toml
cargo clippy --manifest-path src/node94-orderbook/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-orderbook/Cargo.toml -- --check
```

The crate has no third-party dependencies and commits its generated lockfile.
Repository-wide validation remains `make verify test catalogue-check`. No
reconstruction progress gate is changed by this component.

