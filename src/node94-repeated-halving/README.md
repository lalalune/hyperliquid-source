# Node #94 repeated conditional-add halving

`apply(image, destination, input, correction, raw_count)` reconstructs the
complete 159-byte loop `[0x565dbc0,0x565dc5f)` over every operand bit and
raw u64 count. All offsets start 32-byte little-endian four-qword windows.
Each original pass adds the correction when the current value is odd, then
right-shifts the full 257-bit sum. Only the low32 count participates; zero
means 2^32 passes through the do-while loop.

The implementation performs at most 256 direct passes before using a proved
modular-exponentiation relation for larger counts. This admits unreduced inputs,
even corrections, zero correction, and all high-bit count encodings. It does
not assume an original modulus meaning. Exact output bytes and the seven
written, unrestored registers RAX/RDX/RSI/R8/R9/R10/R11 are returned.

All original correction reads are assumed successful and stable across every
pass. No output stores occur until the loop completes, so input/output windows
may partially or fully overlap. Original stack scratch, saved registers and
return-control storage must remain separate. The safe image API does not
recreate faults, flags, racing memory or the machine calling convention.
`None` refuses an overflowing or out-of-image range without mutation; that is
new API behavior, not an original return.

The dependency-free library is no_std and forbids unsafe code. It creates no
Cargo workspace or dependency lockfile. Build with the pinned installed compiler:

```sh
/opt/homebrew/opt/rustup/bin/rustc +1.94.1 \
  --edition=2021 --crate-name node94_repeated_halving --crate-type rlib \
  -Dwarnings -C opt-level=3 -C overflow-checks=yes -C panic=abort \
  src/node94-repeated-halving/lib.rs -o /tmp/libnode94_repeated_halving.rlib
```

The input-only client accepts five tab-separated fields: destination/input/
correction offsets in decimal, the raw count in hexadecimal, and image bytes
in hexadecimal. It prints an admission bit, the seven named registers, and
the entire resulting image. Refusal rows use zero register placeholders solely
for client serialization. The client never receives expected results.

The [evidence and universal proof](../../research/work-items/RE-004-node94-repeated-halving-rust/README.md)
include independent pre-Rust closed-form expectations, exact target and compiler
identities, all-count bounds, repeated native builds and negative controls.
