# Node #94 normalization and packed-coefficient loop

This dependency-free no_std component reconstructs two complete entries:
`[0x565ec20,0x565ecb2)` normalizes two four-qword snapshots and unconditionally
tails into `[0x565ecc0,0x565ed4d)`, a variable-count pair/coefficient loop.
All operand bits and raw u64 counts are admitted. The low 32 count is used;
zero means 2^32 passes, not zero passes.

`normalize_iterate(a,b,count)` preserves the original low 31 bits, selects and
shifts a shared highest nonzero limb pair, then executes the loop relation.
The zero BSR intermediate is overwritten before any observable use, so even
zero high limbs have a defined result. `iterate(x,y,count,r9,r11)` exposes the
loop entry directly and preserves its supplied untouched R9/R11 values.
Both APIs return the same thirteen named raw register observations.

A bit-length descent proof bounds nonzero-X processing by 128 passes for all
u64 pairs. Remaining zero-X passes have an exact affine closed form modulo
2^64, including final saved temporaries. Coefficients wrap as entire 64-bit
words; the final bias subtraction and 32-bit extraction are kept in their
observed order. No mathematical meaning, oddness or reduced-input condition
is imposed on the original pair.

Original normalizer reads must be successful and stable. There are no stores,
so the value API takes snapshots without modeling pointers, faults, flags,
racing memory or the custom register ABI. RDI/RSI and return control are not
synthesized. No unsafe code, dependencies, Cargo workspace or lockfile is used.
Build directly with the pinned installed compiler:

```sh
/opt/homebrew/opt/rustup/bin/rustc +1.94.1 \
  --edition=2021 --crate-name node94_packed_coefficient --crate-type rlib \
  -Dwarnings -C opt-level=3 -C overflow-checks=yes -C panic=abort \
  src/node94-packed-coefficient/lib.rs -o /tmp/libnode94_packed_coefficient.rlib
```

The input-only client accepts ten tab-separated fields: entry selector 0/1,
four hexadecimal a words, four b words, then raw count. Selector 0 uses a0/b0
as X/Y and a1/b1 as preserved R9/R11; remaining array words are unused client
padding. Selector 1 calls the full normalizer. It prints RAX,RBX,RCX,RDX,RBP,
R8,R9,R10,R11,R12,R13,R14,R15. It never receives expected outputs.

See the [proof and evidence](../../research/work-items/RE-004-node94-packed-coefficient-rust/README.md)
for the pre-Rust oracle, explicitly post-Rust coverage supplement, retained
initial ineffective-control result, final qualification and exact replay.
