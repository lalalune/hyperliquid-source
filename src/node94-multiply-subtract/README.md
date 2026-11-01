# node94 scalar-product subtraction

Dependency-free `no_std`, safe value reconstructions of two node #94 leaves:

- `subtract_wide([u64;3], [u64;2], u64)` projects ELF VA
  `0x565ee40..0x565ee9b`. It subtracts the full scalar product, adds the operand
  back to the low 128 bits on borrow, and stores/returns the adjusted scalar.
- `subtract_narrow(u64, u64, u64)` projects `0x565eea0..0x565eeba`.
  It subtracts the low 64-bit product and stores/returns the original scalar.

Words are least significant first. `WideOutput` and `NarrowOutput` expose the
destination words and RAX separately; these are descriptive value types, not
recovered native structs or return signatures.

Arguments represent stable entry snapshots. All native memory reads precede
the first store, so consistent snapshots also describe the arithmetic for
overlapping input/output ranges. The value API does not implement their
shared-memory write effects, pointer ABI, faults, MMIO or concurrent mutation.
The native little-endian byte-to-word interpretation is the caller's snapshot
responsibility; Rust values themselves have no byte alignment requirement.

With Rust 1.94.1 and the authenticated repository inputs:

```sh
cargo +1.94.1 build --offline --locked --manifest-path src/node94-multiply-subtract/Cargo.toml
python3 research/work-items/RE-001-multiply-subtract-rust-94/verify.py --out work/subtract-review
```

The verifier defaults to the installed macOS paths; `--rustc` accepts a rustup
rustc shim, and `GNU_OBJDUMP`/`LLVM_OBJDUMP` select installed decoders. The
output directory must be fresh and below the repository. The separate CLI
uses `std` and accepts only inputs on stdin. No captured executable runs.

The [evidence packet](../../research/work-items/RE-001-multiply-subtract-rust-94/README.md)
contains the arithmetic proof, shared-caller grouping, FDE correction,
independent oracle and native checks. No source/library identity is claimed.
