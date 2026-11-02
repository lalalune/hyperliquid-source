# node94-connect-delay

The baseline has static evidence for per-candidate connect delays, but no independent Rust scalar implementation. This adds supplied map-value/list-index/list-length precedence and the measured delay arithmetic. A supplied map value, including zero, wins; otherwise use the list index or length. An absent snapshot returns +0.0. A present snapshot computes min(0.07, float(k) * (float(X) * 0.001)), preserving both conversions and multiply order. Snapshot wait/hold durations are not used by this selected arithmetic.

Build directly with rustc 1.94.1, edition 2021; safe `no_std`, no external
dependencies or invented Cargo workspace. Evidence, commands and exact build
flags: `research/work-items/RE-012-connect-delay-rust-94/`.

The API receives normal lookup outcomes and raw u64 X/k words. It does not implement map/list traversal, key equality, snapshot/lock effects, Instant or wall-clock addition, seconds-to-nanoseconds conversion, scheduling, sockets, original ABI, FP exception flags/alternate rounding modes or unwind. Arithmetic is compared in the normal binary64 round-to-nearest domain; no reassociation or integer product is substituted.
