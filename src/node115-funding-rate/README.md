# Node 115 funding rate

Independent `no_std` Rust with `alloc` maps and sample vectors. `rate` performs
real logical key lookups, preserves stored sample order and the negative-zero
fold seed, applies selected config defaults/overrides and finite-only clamps,
and returns the observed scaled rate or absence.

The [evidence packet](../../research/work-items/RE-006-node115-funding-rate-source/README.md)
records target identity, selected native operations, floating-point premises,
reference cases and limits. Native collection ABI and settlement are excluded.

Run `cargo test --offline --locked --manifest-path src/node115-funding-rate/Cargo.toml`.
