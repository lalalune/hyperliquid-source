# Node #115 outcome record MessagePack

This crate independently encodes the five-field record writer described by the
target-bound packet [`risk-outcome-record-set-115`](../../research/work-items/risk-outcome-record-set-115/README.md).
The packet binds the observations to node #115's SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` and
reports 17,400 original-byte interpreter cases with zero mismatches against a
separately written rule list.

The value encoder preserves the observed field order, named/compact marker,
three copy-family key conditions, smallest unsigned MessagePack encoding, and
two-string array fields. It excludes the outer set header/iterator, allocator
and reserve behavior, and writer failure paths. Strings at or above 65,536
bytes are rejected by this host API because that range was not covered by the
packet's generated cases; this is not a claim about native rejection behavior.

The crate's unit tests check representative output bytes and width boundaries.
They are value-model tests and do not themselves compare Rust output with the
captured instructions. The packet's target-grounded evidence remains the source
for the behavioral claim. No progress gate is changed.

Build and test with Rust 1.95.0:

```sh
cargo test --offline --locked --manifest-path src/node115-outcome-record-msgpack/Cargo.toml
```
