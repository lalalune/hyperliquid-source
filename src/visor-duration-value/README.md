# Visor supplied binary64 duration values

This real dependency-free Cargo component implements the conditional value
relation proved in `research/work-items/RE-013-visor-duration-value-rust` for
Visor SHA256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
It accepts any raw u64 binary64 encoding through `convert_bits` and returns
`DurationValue`, with private fields and `seconds()`/`nanoseconds()` accessors.
Nanoseconds is always below one billion. New safe API names/layout are not
recovered native types or ABI.

For positive inputs below 2^64, the result rounds exact nanoseconds to nearest,
ties to even. Negative/nonfinite inputs and both zeros yield zero. Positive
finite inputs at least 2^64 instead yield `(18446744073709,551615000)` until
their million-fold binary64 product would overflow; those inputs yield zero.
The large-input discontinuity is intentional, not conventional saturation.

The library uses bounded integer arithmetic, with no host floating operations,
unsafe code, allocator, clock, sleep, filesystem, process or network access.
The raw-bit overflow boundary follows the independently frozen exact inequality.
Native correspondence still depends on the packet's explicit ISA/memory/call
premises; compiled host values do not establish original source/compiler/ABI,
machine-byte or whole-Visor equivalence. No captured binary is executed.

Source/test/client and build admission are a separate frozen phase. Actual
debug/release outcomes belong to later packet receipts; this source draft alone
does not claim a successful build. The root repository has no Cargo workspace.
