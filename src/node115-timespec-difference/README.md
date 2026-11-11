# Node #115 complete normalized timespec difference

Independently authored dependency-free MIT no_std Rust. Reuses the licensed
`core::time::Duration` type and recovers the logical full two-input subtraction
at `0x5c84210..0x5c842d6`, Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`Timestamp::new(i64_seconds, u32_nanoseconds)` enforces normalized nanos<1e9.
`a.difference(b)` returns `Ok(magnitude)` for a>=b and `Err(magnitude)` for a<b;
equality is Ok zero. Signed seconds ordering, nanosecond borrowing and the
entire i64-to-i64 span are preserved, including u64MAX duration seconds.
It never calls the OS, subtracts signed seconds unsafely, or invents a clock.
Raw-invalid timestamps, original Result layout and native panic ABI are outside
this logical API. This is a shared standard-library primitive, not recovered
private-node bytes or new byte-equivalence credit.

Evidence, independent pre-Rust big-integer expectations, actual compiled
mutants, default/caller FDEs and remaining boundaries are in
`research/work-items/RE-012-timespec-difference-115`.

```sh
cargo +1.95.0 build --offline --locked --manifest-path src/node115-timespec-difference/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-timespec-difference/Cargo.toml
```
