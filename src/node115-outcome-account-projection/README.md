# Node #115 outcome account projection

This dependency-free `no_std` Rust crate independently models the logical row
projection established by the static evidence packet for Linux x86-64 node
#115, ELF SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Given the caller's first/second/destination token identifiers, pre-resolved
total/held balances, account address and coarse weight `c`, `project` applies
the two reserved-address exclusions, ordered available-balance checks,
`u64`-checked products, saturating payout sum, and ordered nonzero output rows.
It preserves the native error codes 19 and 14 as raw values and the special
nonfatal underflow/sum diagnostics. The safe Rust types and `Projection` enum
are descriptive logical types, not the original native layouts or error ABI.

The target-bound instruction walk and limitations are in
[`research/work-items/RE-001-node115-outcome-account-settlement-projection/README.md`](../../research/work-items/RE-001-node115-outcome-account-settlement-projection/README.md).
The caller's coarse input is constrained to 0 through 1000; the previous
conversion packet establishes its production. This crate accepts explicit map
lookup results and does not recover map internals, lookup execution, native
allocation, parallel collection, diagnostic callbacks that fail to return,
token units or later payout application.

Tests cover reserved-address early returns, exact error/lookup precedence,
underflow diagnostics, checked product overflow, sum saturation, duplicate
identifiers, zero-weight rows, and 1,152 boundary combinations plus 4,096
deterministic generated cases against an independent `u128` oracle. They do
not execute or emulate the captured binary and do not establish full
settlement equivalence.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-outcome-account-projection/Cargo.toml
cargo +1.95.0 clippy --offline --locked --all-targets --manifest-path src/node115-outcome-account-projection/Cargo.toml -- -D warnings
cargo +1.95.0 build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-outcome-account-projection/Cargo.toml
```

The implementation is independently authored under the repository MIT
license. No imported code or live data is used.
