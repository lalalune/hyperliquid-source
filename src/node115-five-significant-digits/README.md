# Node #115 five-significant-digit truncation

This dependency-free `no_std` crate implements the complete arithmetic leaf
at `0x269d520` for Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`truncate(value)` rounds an unsigned 64-bit value down to five significant
decimal digits: `scale(value)` is `10^max(0, digits - 5)`, selected by the
same ladder of bounds the target compares against (up to `10^15` for 20-digit
values), and the result is `(value / scale) * scale`. The target's
overflow fallback to `u64::MAX` is kept as a saturating multiply although it
cannot be reached. The
code does not assign a source name, type, ownership or units.

The authenticated evidence packet is
`research/work-items/RE-001-node115-five-significant-digits/README.md`. It
binds the complete 381-byte body and 79 instructions and proves the closed
form for every `u64` input with a monotone-threshold partition of 37 cells. It
also confirms the two direct call sites in the TWAP slice family `0x2dd34f0` /
`0x2dd4530`. No captured binary is executed or emulated.

## Reproduction

```sh
python3 research/work-items/RE-001-node115-five-significant-digits/verify.py
cargo +1.95.0 test --offline --locked --manifest-path src/node115-five-significant-digits/Cargo.toml
cargo +1.95.0 clippy --offline --locked --manifest-path src/node115-five-significant-digits/Cargo.toml --all-targets -- -D warnings
```

Tests cover values below the first bound, every power-of-ten boundary, the
`u64` upper boundary and 20,000 deterministic samples of varied width against
an independent digit-string definition. They check this projection; they are
not a runtime comparison with the captured node.
