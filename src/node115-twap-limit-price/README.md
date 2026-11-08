# Node #115 TWAP limit-price model

Models the price construction for the order-producing path from
`research/work-items/RE-006-twap-slice-115`. The target is node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

This crate covers the part explicitly left outside the open TWAP quantity PR
#4375: deriving a limit price from the supplied perp top-of-book or spot mid,
the side multiplier, half-away rounding, and side-dependent tick adjustment.
Lookup, market errors, quantity sizing, scheduling side effects, record layout,
and the four full slice entrypoints are not included.

The 3,510 committed price vectors were generated from the packet's pure Python
specification for cases whose outcome is an order. That specification is
reported in the packet as matching the original #115 bytes across 11,488 cases;
the Rust tests do not execute or emulate captured instructions. Run with
`cargo test --manifest-path src/node115-twap-limit-price/Cargo.toml`. Regenerate
the vectors with `python3 src/node115-twap-limit-price/generate_vectors.py`.
