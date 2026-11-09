# Node 115 per-user funding settlement

Independent Rust over owned keyed positions, rates, oracle prices and balances.
`settle` implements the complete selected normal-return behavior of
`0x4205370`: signed notional checks, payment conversion, real cross/isolated
balance and accumulator mutations, records, sequential total and largest
notional selection. A missing timestamp still validates applicable notionals.

The [evidence packet](../../research/work-items/RE-006-node115-funding-user-source/README.md)
binds original instructions and constants, documents the logical-state premises,
and provides reproducible offline reference tests. This is the per-user helper;
outer parallel collection and cross-user redistribution remain outside scope.

Run `cargo test --offline --locked --manifest-path src/node115-funding-settlement-user/Cargo.toml`.
