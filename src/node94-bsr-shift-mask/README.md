# node94 BSR shift-mask raw value

`raw_value(n: u64) -> u32` reconstructs the numeric result of node #94
ELF VA `[0x54b4390, 0x54b43d2)`. The input and extracted field have no
established application meaning.

Every u64 input is admitted. The wrapping operand `2*n−1` is always odd,
so BSR never receives zero. The shifts stay in `4..=60`; the final result
is in `1..=232`. Zero and `2^63` both return 232, while `2^63+1` returns 1.
The implementation preserves the separate floors of 7 for shift selection
and 6 for the final arithmetic term, along with the original u32 return width.

The independently authored MIT library is `no_std`, forbids unsafe code
and has no external dependencies. It is built directly with pinned rustc
1.94.1; no Cargo workspace, recovered crate identity or original ABI is
claimed. The separate standard-library client receives only synthetic
inputs and prints results.

```sh
python3 -O research/work-items/RE-004-node94-bsr-shift-mask-rust/validate.py
```

See the [evidence packet](../../research/work-items/RE-004-node94-bsr-shift-mask-rust/README.md)
for byte/FDE/caller checks, the frozen interval oracle and compiled controls.
Only newly built Rust runs; no captured code or instruction emulator runs.
