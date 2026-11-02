# node94 BSR normalization value projection

`normalize(word: Option<u32>, value: u32, flag: u32, refinement: u32)`
returns `Result<u32, Refusal>` for the numeric relation in node #94 ELF VA
`[0x55c9800, 0x55c9830)`. Argument meanings remain unknown.

`word` is a supplied snapshot of the original 32-bit load's value. This
API neither takes a pointer nor reproduces memory access or fault behavior.
`flag == 1` returns 0 or 256 according to whether `refinement` is zero;
this path accepts `None` and `Some(u32::MAX)` without requiring the word.
Every other flag takes the main path, which needs `Some(word)` and excludes
`u32::MAX` because incrementing it produces the zero BSR operand.

`MissingWord` and `UndefinedBitScan` are new safe-API refusal reasons, not
original target error returns. The main path preserves u32 increment,
left-shift truncation before logical right shift, and wrapping subtraction.
Its three non-word inputs represent the original registers' low 32 bits.

The independently authored MIT library uses `no_std`, forbids unsafe code,
and has no external dependencies. Pinned rustc 1.94.1 builds it directly as
an rlib; no Cargo workspace, dependency resolution or crate identity is
claimed. The separate host-standard-library client reads only synthetic
inputs and prints results.

```sh
python3 -O research/work-items/RE-004-node94-bsr-normalize-rust/validate.py
```

The [evidence packet](../../research/work-items/RE-004-node94-bsr-normalize-rust/README.md)
contains exact byte/FDE/caller checks, the pre-Rust mathematical oracle,
native builds, negative controls and limitations. Captured code is never run.
