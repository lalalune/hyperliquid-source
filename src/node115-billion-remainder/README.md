# Node #115 unsigned remainder by one billion

This dependency-free `no_std` crate implements the complete arithmetic leaf
at `0x63bfbc0` for Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`remainder(value)` preserves the target's observed reciprocal-multiply
quotient: shift by nine, multiply by `0x44b82fa09b5a53`, take product bits
75 and above, and subtract that quotient times `1_000_000_000`. The static
packet proves that this is exact over the full `u64` domain. The code exposes
the mathematical relation only; it does not assign a source name, type,
ownership, units, caller behavior, or pointer ABI.

The authenticated evidence packet is
`research/work-items/RE-001-node115-billion-remainder/README.md`. It binds the
complete 45-byte body and 11 instructions, proves the reciprocal certificate,
and confirms two instruction-aligned direct-call candidates. It does not
establish caller reachability or the remainder's business meaning. No captured
binary is executed or emulated.

## Reproduction

```sh
python3 research/work-items/RE-001-node115-billion-remainder/verify.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-billion-remainder/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-billion-remainder/Cargo.toml --all-targets -- -D warnings
```

Tests cover divisor and `u64` boundaries, quotient transitions, and 20,000
deterministic full-width samples against the independent integer remainder
operator. They check this projection; they are not a runtime comparison with
the captured node.
