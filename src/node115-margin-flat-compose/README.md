# Node 115 flat margin selection and arithmetic

An owned, offline composition of the existing `node115-margin-range` and
`node115-margin-row` research code. It selects the last live flat row whose
unsigned key is at most the supplied amount, then feeds that row's +24 offset
and +32 divisor to one of the existing selected-row arithmetic functions.
Wrapped rings and duplicate keys retain the range library's logical ordering.

Empty selections, invalid host views and zero divisors are explicit safe API
refusals, not recovered native error returns. Arithmetic diagnostic boundaries
are preserved; this API does not invent a diagnostic helper result. The
correspondence is limited to valid stable flat storage and selected normal
paths. Native tree representation, allocator/unwind, constructor invariants,
economic units, position authorization and complete risk policy remain open.

`row-adapter/Cargo.toml` points at the unchanged existing MIT margin-row source;
it does not claim an original Cargo workspace. Source identities and the two
native caller FDEs are checked by the accompanying evidence packet.

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-margin-flat-compose/Cargo.toml
```
