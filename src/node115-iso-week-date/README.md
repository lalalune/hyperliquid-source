# Node #115 ISO week date constructor

Dependency-free MIT no_std Rust reconstructing the complete helper at
`0x1628dd0..0x1628f50`, Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

`from_iso_week(i32_year, u32_week, Weekday)` returns a packed date with logical
year/ordinal/flags, `None` for invalid week or final supported-date range, and
`YearOverflow` for the captured checked year-adjustment failure boundary.
The safe weekday enum represents Monday0..Sunday6; arbitrary native u8 values
are outside this API. ISO year is checked only after week validation and any
cross-year adjustment, so an adjacent ISO year may yield a supported date.
No clock, allocator, native panic ABI or original Rust nominal type is claimed.

Independent Python fromisocalendar expectations, both-sign complete cycles,
real static tables/FDE/RELA, mathematical controls and compiled mutants live in
`research/work-items/RE-012-iso-week-date-115`. No prior unmerged producer source
or fake Cargo dependency is imported; the Gregorian field facts are reused as
observations, with an independently authored ISO-week algorithm.

```sh
cargo +1.95.0 build --offline --locked --manifest-path src/node115-iso-week-date/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-iso-week-date/Cargo.toml
```
