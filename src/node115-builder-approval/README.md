# Node 115 builder approval state

Independent `no_std` Rust over real nested 20-byte keyed maps. `approve` performs
the complete logical approval-map behavior of `0x3c1a510`: user entry creation,
zero-fee removal, the pre-lookup count gate, and raw fee insertion/replacement.

The [evidence packet](../../research/work-items/RE-010-node115-builder-approval-source/README.md)
records exact ordering, target identity, sequence reference tests and limits.
The map is a projection of approval state, not the full native user object.

Run `cargo test --offline --locked --manifest-path src/node115-builder-approval/Cargo.toml`.
