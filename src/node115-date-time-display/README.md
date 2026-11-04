# Node #115 date/time display text

Dependency-free independently authored MIT `no_std` Rust for the complete
successful date display, time display and space-separated adapter text observed
in Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
No allocator, clock, callback, captured execution or fake writer is used.

`Date::new(year, ordinal)` accepts Gregorian years -262143..262142 and a valid
ordinal. `Time::new(seconds, nanos)` selects an explicit safe 24-hour domain,
including conventional leap-second encoding (nanos1e9..2e9 at second59).
Those constructors' domain rejection is wrapper behavior, not a recovered
native constructor or invalid-representation ABI.

`render_date`, `render_time` and `render` return ASCII in a fixed 32-byte
`Output`. Years0..9999 use four digits; other years use a sign and at least
four magnitude digits. Fractions use exactly3/6/9 digits, so100,000,000ns is
`.100`, not `.1`. The adapter emits an ASCII space, with no timezone suffix.
A conventional encoded leap second displays second60 and removes the1e9 flag
from its fractional part. `.as_str()` and `.as_bytes()` expose the result.

This API covers successful text, not native fmt-writer failure granularity,
partially emitted prefixes, allocation failure or panic ABI. Evidence and
qualification live in `research/work-items/RE-012-date-time-display-115`.
It does not depend on an unmerged producer crate or duplicate its production
source; callers may map established logical year/ordinal/time fields directly.

```sh
cargo +1.95.0 build --offline --locked --manifest-path src/node115-date-time-display/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-date-time-display/Cargo.toml
```
