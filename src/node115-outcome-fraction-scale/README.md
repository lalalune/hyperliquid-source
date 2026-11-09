# Node #115 outcome fraction scales

This dependency-free `no_std` Rust crate independently implements the two
numeric conversions established by the static evidence packet for Linux
x86-64 node #115, ELF SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The target multiplies the original binary64 input by 1,000 and by 100,000,000
independently. Each product maps nonfinite values to zero, clamps finite values
to the u64 conversion domain, and truncates toward zero with saturation. The
coarse path rejects a result above 1,000 and returns its complement; the fine
path saturates its complement at zero. Fine is never derived from coarse.

The exact operation, constraints and retained binary64 examples are documented
in [`research/work-items/RE-001-node115-outcome-dual-fraction-scales/README.md`](../../research/work-items/RE-001-node115-outcome-dual-fraction-scales/README.md).
The code does not model the earlier lookup/equality and token-tag prerequisites,
the enclosing error ABI, payout accounting, token denominations or outer
action admission. An input slightly greater than 1 can pass the internal
coarse integer check; this is not an external-action acceptance claim.

Tests use exact binary64 fixture bits from the evidence packet, cover both
independent scales, coarse rejection, nonfinite inputs, negative inputs and
u64 saturation. They validate the derived numerical relation; they do not run
or emulate the captured binary and do not establish settlement equivalence.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-outcome-fraction-scale/Cargo.toml
cargo +1.95.0 build --offline --locked --manifest-path src/node115-outcome-fraction-scale/Cargo.toml
cargo +1.95.0 build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-outcome-fraction-scale/Cargo.toml
```

The implementation is independently authored under the repository MIT
license; no imported implementation or live data is used.
