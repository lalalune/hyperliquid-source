# Node #115 unsigned128 to binary64

This dependency-free Rust library computes the nearest-even IEEE754 binary64
bits for every `u128`, including zero and the maximum value.

The complete 132-byte target leaf at `0x63f00d0..0x63f0154` in node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
is byte-identical to the previously qualified leaf. Its unique exact FDE and
register-only instruction body let the existing numerical proof and frozen
fixtures apply to this target without transferring addresses or an ABI claim.

The Rust implementation is independently authored MIT code. Its source was
migrated with only the target comment and client crate name changed. It is a
numerical projection, not a byte-identical rebuild of the target machine code.

```sh
cargo +1.95.0 test --offline --locked --manifest-path src/node115-u128-binary64/Cargo.toml
python3 tools/node115_u128_binary64.py --check --build-dir work/u128-binary64-check
```

The verifier authenticates the node and complete FDE, checks the retained
published-artifact body, and compares a compiled input-only Rust client against
the frozen pre-existing corpus. It never executes the captured node.
See [evidence and limits](../../research/work-items/RE-004-node115-u128-binary64/README.md).
