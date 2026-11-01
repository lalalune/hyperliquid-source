# Visor readiness values

A standalone dependency-free Rust component for the conditional numeric sample,
canonical calendar and fixed60 deadline relation proved in
[`RE-013-visor-readiness-value-rust`](../../research/work-items/RE-013-visor-readiness-value-rust).
It is not a root workspace, clock service or complete readiness implementation.

`Timestamp` has private fields. `from_parts` admits years -262143..262142,
one-based valid Gregorian ordinals, seconds below86400 and nanos below1e9.
`from_clock_sample` admits supplied seconds0..8210266876799 and ordinary nanos;
sample zero maps to1970 ordinal1. `None` is newly chosen safe policy, not a
recovered native error ABI. No clock, environment or external state is read.

`raw_words` returns the exact logical signed date/unsigned second/nano triple,
without an ABI/layout claim. `deadline_60` adds60 seconds and saturates at
`(2147473118,86399,999999999)`. The free function
`is_strictly_past_deadline(current,source)` uses strict comparison; equality is
false. There is no arbitrary raw-word constructor or extended-nano operation.

The native theorem requires the packet's successful imported-return, numeric
domain, storage/nonaliasing and preservation premises. The source timestamp's
lifecycle producer, opaque failures, elapsed-time guarantees, generic date/time
APIs and full Visor policy remain outside scope. This independent MIT source
contains no imported inferred implementation or captured machine code.

Actual build/test/comparison receipts belong to the packet's separate
`rust-validation` phase. Source creation alone is not a build success claim.
