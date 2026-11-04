# Node #115 CE packed date and time producer

Dependency-free independently authored MIT `no_std` Rust for the observed
CE-day constructor and time producer, target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`from_ce_day(i32)` recovers the signed year, ordinal, flags and packed date word
for the supported Gregorian range -262143..262142. It handles year zero and
negative years using Euclidean calendar arithmetic. CE1 is 0001-01-01.
`from_clock_read(i64,u64)` accepts an explicit successful Linux clock-read
boundary, rejects invalid nanoseconds and pre-origin seconds, and returns the
packed date, seconds within the day and nanoseconds. It never calls the OS.
Logical errors are not original panic payloads, enum tags or a native ABI.

The Rust uses a direct year search and arithmetic flags, rather than copying
the target's reciprocal code or its tables. Actual captured 400-year tables,
full FDEs, independent Python calendar/datetime expectations and compiled mutant
controls are in `research/work-items/RE-012-time-producer-115`. No clock mock,
calendar stub, external Cargo dependency or whole-node claim is supplied.

```sh
cargo +1.95.0 build --offline --locked --manifest-path src/node115-time-producer/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-time-producer/Cargo.toml
```
