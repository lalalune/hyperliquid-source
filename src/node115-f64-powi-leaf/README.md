# Node #115 binary64 integer-power leaf

This dependency-free `no_std` Rust crate independently implements the
operation established by the static evidence packet for Linux x86-64 node
#115, ELF SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`powi_leaf(base, exponent)` uses the target's binary-exponentiation order: the
low exponent bit selects `base` or `1.0`; later bits multiply in successive
squares; a negative exponent takes the reciprocal at the end. It accepts the
full `i32` range, including `i32::MIN`. The function name and Rust API are
descriptive choices, not recovered source identity or ABI.

The target body is the complete 70-byte leaf at `0x63f0080..0x63f00c6`, with
zero calls and a pinned `1.0` seed at `0x4592b0`. The exact instruction walk,
84-point independent comparison and mutation controls are retained in
[`research/work-items/RE-001-node115-f64-powi-leaf/README.md`](../../research/work-items/RE-001-node115-f64-powi-leaf/README.md).
The likely compiler-builtin identity remains unconfirmed. No caller ownership,
first-party module, whole-node equivalence or component gate is claimed.

Tests compare 84 packet-grid cases bit-for-bit with a separately ordered
binary-exponentiation reference, then cover signed zero, reciprocal behavior,
NaN at exponent zero and the full `i32::MIN` magnitude. The tests validate the
derived numeric relation; they do not execute or emulate the captured binary.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-f64-powi-leaf/Cargo.toml
cargo +1.95.0 build --offline --locked --manifest-path src/node115-f64-powi-leaf/Cargo.toml
cargo +1.95.0 build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-f64-powi-leaf/Cargo.toml
```

The implementation is independently authored under the repository MIT
license. No imported implementation or live data is used.
