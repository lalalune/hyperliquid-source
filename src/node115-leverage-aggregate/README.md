# Node 115 leverage aggregate update

Independent `no_std` Rust with owned 20-byte user and unsigned asset maps.
`update` implements `0x44831a0`'s selected normal-return behavior: real keyed
lookup, directional integer value selection, leverage replacement, and the
separately saturating debit/credit of the user's aggregate.

The [evidence packet](../../research/work-items/RE-007-node115-leverage-aggregate-source/README.md)
records exact native branches, integer bounds, reference cases and limits.
Physical map ABI, diagnostic effects and caller position mutation are excluded.

Run `cargo test --offline --locked --manifest-path src/node115-leverage-aggregate/Cargo.toml`.
