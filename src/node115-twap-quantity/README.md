# Node 115 perpetual TWAP quantity

Independent Rust source for the selected duration, scheduled target, jitter,
notional minimum, average cap and quantity rounding calculation. Inputs include
an already computed positive limit price; book selection, price/tick math,
calendar decoding, advance/finish callbacks and submission are separate.

The [evidence packet](../../research/work-items/RE-006-node115-twap-quantity-source/README.md)
records the pinned native contract, selected FMA dispatch scope, fixtures and
limits. This std crate has no external dependencies and runs no captured code.

Run `cargo test --offline --locked --manifest-path src/node115-twap-quantity/Cargo.toml`.
