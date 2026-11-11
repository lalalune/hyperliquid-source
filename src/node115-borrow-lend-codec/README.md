# Node #115 `borrowLend` wire-name codec

This crate independently models the four observed operation names and tags,
the three exact struct field identifiers, tagged visitor success words, and
the MessagePack fixstr bytes written for each operation. Its evidence is the
static packet `research/work-items/RE-007-borrow-lend-codec-115/`, bound to
Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Observed operations are `borrow`, `supply`, `repay`, and `withdraw` at tags
0 through 3. The corresponding field names are `operation`, `token`, and
`amount` at tags 0 through 2. Operation strings use MessagePack fixstr
markers `0xa6`, `0xa6`, `0xa5`, and `0xa8` followed by the exact ASCII name.

The crate rejects unknown names and out-of-range host tags with `None`; the
native serializer's unchecked dispatch is only defined for valid enum tags.
It does not reproduce unknown-name error objects or lossy UTF-8 allocation,
serializer reserve/growth calls, or the `borrowLend` state transition. The
packet identifies unknown field names as errors (deny-unknown-fields shape),
but this crate does not model serde's error payload.

Run from the repository root:

```sh
cargo test --offline --manifest-path src/node115-borrow-lend-codec/Cargo.toml
cargo fmt --manifest-path src/node115-borrow-lend-codec/Cargo.toml -- --check
cargo clippy --offline --manifest-path src/node115-borrow-lend-codec/Cargo.toml -- -D warnings
```
