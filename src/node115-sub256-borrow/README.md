# Node #115 256-bit subtraction with final borrow

This dependency-free `no_std` crate implements the bounded arithmetic and
memory result observed at node #115 function `0x2ccdd80`. The target is Linux
x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`subtract` treats the 32-byte inputs as four little-endian unsigned limbs,
computes `(left - right) mod 2^256`, writes the difference back to `left` and
to `out[0..32]`, and writes `1` to `out[32]` exactly when `left < right`.
The implementation uses two checked 64-bit subtractions per limb to preserve
the SUB/SBB borrow chain, including the `u64::MAX` subtrahend plus incoming
borrow case.

The target-grounded packet at
`research/work-items/RE-001-node115-sub256-borrow/README.md` binds the complete
49-byte, 14-instruction body, its output borrow byte, 289 boundary vectors and
a first-party quantity-associated caller. The native leaf's source name,
owner, units, caller reachability and quantity-level meaning remain
unresolved. This crate does not implement the caller or claim financial
semantics, source ownership, native ABI, compiled-byte equivalence or a
component gate. It does not execute or emulate captured code.

## Reproduction

```sh
python3 research/work-items/RE-001-node115-sub256-borrow/verify.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-sub256-borrow/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-sub256-borrow/Cargo.toml --all-targets -- -D warnings
```

Three focused tests cover equality, wraparound and long borrow propagation.
An additional integration test checks all 289 packet vectors. The packet
verifier remains the evidence for the pinned target bytes; Rust tests validate
only this independently authored logical projection.
