# Node 115 field1-5 varint reader

This allocation-free `no_std` Rust model implements one scalar reader family
documented by the digest-bound
[`RE-005-node115-field1-5-varint-reader`](../../research/work-items/RE-005-node115-field1-5-varint-reader/README.md)
packet. Its copies at `0x2cd7bb0..0x2cd7c95` and
`0x5821340..0x5821425` share a slow helper at `0x5822710..0x582284c` on the
Linux x86-64 node #115 target, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The model covers the mode-1 eight-byte charge, the fast threshold of more than
eight remaining bytes, the 251/252/253 little-endian payload widths, the
slow-path marker consumption and shortfall results, and raw invalid fields
`field1=5`, `field2=4/12`. Nonminimal encodings remain accepted. This family is
separate from the existing #115 u64 reader model: the same invalid markers
produce different raw field1 values, and fast and slow routes consume input
differently. The model does not combine callers, infer Rust enum names, or
claim original ABI, wire-format completeness, binary equivalence, or component
completion.

The input slice is the unread cursor window, so its length represents the
native remaining-byte count for this bounded projection. Both observed copies
pass the slow helper's little-endian mode; the helper's unused big-endian path
is outside this model.

```sh
cargo test --offline --locked
cargo test --offline --locked --release
cargo fmt --all --check
cargo clippy --offline --locked --all-targets -- -D warnings
cargo build --offline --locked --release --lib --target x86_64-unknown-linux-gnu
```

No captured executable is run or emulated. Tests exercise the independently
authored model against the packet's bounded route and marker contracts.
