# Node #94 four-round multiply/carry fold

`fold(input, operand, coefficient)` reconstructs the numeric relation of the
complete 388-byte leaf `[0x565d8a0,0x565da24)`. Each array is four qwords in
little-endian limb order. Every u64 input is admitted. The result names the
nine general-purpose registers written by the leaf.

Each round multiplies the current low word by the coefficient modulo 2^64,
then combines that multiplier with four operand words. The first product folds
its low remainder into its high carry modulo 2^64; overflow from that fold is
discarded. This behavior is preserved even when no cancellation or inverse
condition holds. Mathematical operand meanings and caller constraints remain
unknown.

This is a safe value API. Relating it to the target assumes successful stable
reads from the original RSI/RBX windows; overlapping input windows are allowed
because the leaf has no stores. It does not recreate pointer faults, changing
memory, flags, return control, or the target's custom register ABI.

The component has no dependencies and uses `#![no_std]` with no unsafe code.
There is no Cargo workspace or dependency lockfile. Build it directly with the
pinned installed compiler:

```sh
/opt/homebrew/opt/rustup/bin/rustc +1.94.1 \
  --edition=2021 --crate-name node94_four_round_fold --crate-type rlib \
  -Dwarnings -C opt-level=3 -C overflow-checks=yes -C panic=abort \
  src/node94-four-round-fold/lib.rs -o /tmp/libnode94_four_round_fold.rlib
```

The input-only client accepts nine hexadecimal words per tab-separated row:
four input words, four operand words, then the coefficient. It prints RAX,
RDX, R9, R10, R11, R12, R13, R14, R15 as nine comma-separated words. The client
never receives expected results. Full proof, frozen pre-Rust expectations,
compiler identity, exact builds, repeat checks and native negative controls
are in
[`RE-004-node94-four-round-fold-rust`](../../research/work-items/RE-004-node94-four-round-fold-rust/README.md).
