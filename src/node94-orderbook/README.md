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

## Qualified raw-key normalization

The isolated `monotone_keys` module offers `classify(&[u64])` and
`normalize(&mut [u64])` for lengths 21..4096. Nondecreasing unsigned words,
including ties, take a source path without input mutation. Strictly decreasing
words are reversed in place, preserving the odd center and every qword's bits.
These are the two complete native paths qualified by
`RE-006-large-sort-monotone-path-94`.

Its returned enums and refusal of unsupported lengths/orderings are chosen
safe-API policies; the target's unresolved fallback may sort those inputs.
The API does not provide general sorting or the target ABI. Book callers have
not been migrated to this conditional helper. Source, frozen comparison inputs
and compiled receipts are in `RE-006-monotone-keys-rust-94`.
With official Rust 1.94.1, four local builds at optimization levels 0 and 3
match all 76 frozen native-derived cases and five separate API-policy cases.
The component's 30 tests pass at both levels. A native audit of the compiled
optimization-level-3 helper also confirms no input stores on its ascending
path. These are comparisons to static target evidence; the captured node was
not run, and target machine-code equality is not claimed.

## Build and test

```sh
cargo test --manifest-path src/node94-orderbook/Cargo.toml
cargo clippy --manifest-path src/node94-orderbook/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path src/node94-orderbook/Cargo.toml -- --check
```

The crate has no third-party dependencies and commits its generated lockfile.
Repository-wide validation remains `make verify test catalogue-check`. No
reconstruction progress gate is changed by this component.

