# Node94 Pending-poll metric projection

Independently authored safe `no_std` Rust for the first/idle/scheduled and
fast/slow metric increments at the normal Pending exit of the instrumented
node94 accept-loop twins. It preserves exact observed offset attribution,
strict threshold comparisons, no-wake zero, saturating elapsed differences,
the new last-end value and modulo-2^64 counter addition.

Build directly with rustc 1.94.1, edition 2021. No external crate, fake Tokio
runtime or Cargo workspace is introduced. Times and thresholds are supplied
as representable u64 nanoseconds since creation, conditional on normal original
clock/duration helper returns. This finite scalar domain does not reconstruct
Instant layout, wide-duration truncation, overflow panic paths, wakers, atomic
ordering/concurrency, sockets or an integrated accept future.

Evidence and reproduction: `research/work-items/RE-012-poll-metrics-rust-94/`.
