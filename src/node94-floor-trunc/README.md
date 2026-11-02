# node94 floor and truncation values

Independent, safe `no_std` Rust for the low binary64 output bits of node #94
ELF ranges `0x565f490..0x565f4e5` and `0x565f6f0..0x565f784`.
The source uses integer operations only, preserving NaN payloads and signed zeros.

`trunc_bits(u64) -> u64` truncates toward zero. `floor_bits(u64, bool) -> u64`
takes an explicit target DAZ setting. With DAZ set, the captured floor leaf
returns a negative subnormal's original bits. It does not flush its returned
value to negative zero. With DAZ clear it returns -1 on normal completion;
the target denormal exception must be masked for that completion.

These are value APIs, not the original ABI or floating-environment side effects.
No external dependencies, generated code, build scripts or root Cargo workspace
are required. The actual qualified build uses Rust 1.94.1, edition 2024, native
`aarch64-apple-darwin`, opt0 and opt3, overflow checks enabled. Build the library:

```sh
rustc +1.94.1 --edition=2024 --crate-name node94_floor_trunc --crate-type rlib \
  -D warnings -C codegen-units=1 -C panic=abort -C overflow-checks=yes \
  -C opt-level=3 src/node94-floor-trunc/lib.rs -o /tmp/libnode94_floor_trunc.rlib
```

The evidence packet at `research/work-items/RE-004-floor-trunc-rust-94/`
contains the complete target binding, proof, commands, input-only client recipe,
frozen rational expectations and compiled negative controls. A Cargo manifest
and lockfile are inapplicable to this direct, dependency-free rustc build.
