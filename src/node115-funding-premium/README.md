# Node 115 funding premium

Independently authored `no_std` Rust with `alloc` collection inputs and no
external dependencies. `impact` walks typed order-pool links in supplied native
level order. `premium` selects the per-asset target and computes both impacts,
the selected binary64 formula, the optional /100 step, and finite clamping.

This is a logical selected contract, not a native ABI or complete funding engine.
The [evidence packet](../../research/work-items/RE-006-node115-funding-premium-source/README.md)
records exact target identity, observed branches, input premises, fixtures and
limits. No captured code is executed or emulated by the crate or its tests.

Run `cargo test --offline --locked --manifest-path src/node115-funding-premium/Cargo.toml`.
