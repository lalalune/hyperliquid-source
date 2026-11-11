# Node 115 referral-code registration and modification

Independent `no_std` Rust implementing the selected logical state contract of
`0x3c193d0`, using actual volume-row, referrer and code maps. `apply` preserves
registration gate ordering, code collisions, ownership checks and record/index
mutations. `register` projects the normal wrapper's status and result tag.

The [evidence packet](../../research/work-items/RE-010-node115-referral-code-source/README.md)
records the original target, native dataflow, independent reference sequences
and explicit limits. `Mode::Modify` selects recovered behavior; it does not
authenticate or authorize a caller. User referral assignment and quota
consumption are separate operations.

Run `cargo test --offline --locked --manifest-path src/node115-referral-code/Cargo.toml`.
