# Node #94 four-word conditional-correction family

`apply(image, destination, left, right, correction, variant)` reconstructs four
complete node #94 leaves:

| Variant | ELF VA interval |
|---|---|
| `Add` | `[0x565da40,0x565daba)` |
| `Subtract` | `[0x565dd00,0x565dd72)` |
| `AddNonzero` | `[0x565dde0,0x565de6e)` |
| `SubtractNonzero` | `[0x565de80,0x565df06)` |

Each offset starts a 32-byte little-endian four-qword window. Every operand bit
pattern is admitted. Add conditionally subtracts the correction from the full
257-bit sum, retaining a 256-bit result. Subtract adds the correction only on
borrow, again retaining 256 bits. No modulus or reduced-input assumption is
made. The Nonzero variants retain the same stored result and report exact
zero/nonzero RAX; their extra OR operations also change R8/R10. All seven
written, unrestored general-purpose register values are returned explicitly.

All reads precede output stores, so input windows and output may overlap each
other, including partial unaligned overlap. `None` means the new safe API
refuses an overflowing or out-of-image range, leaving the image unchanged.
It is not an original target return. Original memory correspondence assumes
stable successful reads/writes, valid address formation, and no data-window
overlap with the target's stack scratch or return control. This API does not
recreate faults, flags, changing memory, or the original machine ABI.

The component is dependency-free no_std Rust with no unsafe code, root Cargo
workspace or dependency lockfile. Direct build with the pinned installed compiler:

```sh
/opt/homebrew/opt/rustup/bin/rustc +1.94.1 \
  --edition=2021 --crate-name node94_conditional_correction --crate-type rlib \
  -Dwarnings -C opt-level=3 -C overflow-checks=yes -C panic=abort \
  src/node94-conditional-correction/lib.rs -o /tmp/libnode94_conditional_correction.rlib
```

The input-only client accepts six tab-separated fields: variant 0..3 in the
order above; destination, left, right and correction offsets in decimal; then
hexadecimal image bytes. It prints an admission bit, RAX/RDX/RSI/R8/R9/R10/R11,
and the complete resulting image. Refusals use zero register placeholders;
those placeholders are only client serialization, not target observations.
The process is never supplied expected outputs.

See the [complete evidence and universal proof](../../research/work-items/RE-004-node94-conditional-correction-rust/README.md)
for the target identity, pre-Rust oracle, exact compiler/build commands,
repeated native results, alias cases and effective negative controls.
