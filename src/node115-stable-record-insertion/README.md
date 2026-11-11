# Node #115 stable record insertion

This dependency-free Rust crate models the local value behavior of target
function `0x26cf370` from node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The source type name is unknown. The target packet
[`RE-001-node115-record-insertion`](../../research/work-items/RE-001-node115-record-insertion/README.md)
records 40-byte records with an unsigned u64 key at offset 0 and a 32-byte
payload.

`sort_suffix` applies stable insertion from a caller-supplied sorted prefix.
Equal keys keep their original order, payload bytes move with each record, and
the supported index range is `1..=len`. The original leaf traps with UD2
outside that range; `InvalidPrefix` is a safe host API and does not model the
trap. Its sorted-prefix condition is a precondition for the entire slice to be
sorted, not something the function validates.

Unit tests use the packet's nine successful target-grounded key/order vectors,
including unsigned high-bit values, equal keys, a nontrivial prefix, and
skip-all, plus the documented guard boundaries. They check the value model;
they do not compile and compare Rust machine code with the captured leaf. No
native type name, caller semantics, compiler flags, whole-node equivalence, or
progress gate is claimed.

Build and test with Rust 1.95.0:

```sh
cargo test --offline --locked --manifest-path src/node115-stable-record-insertion/Cargo.toml
```
