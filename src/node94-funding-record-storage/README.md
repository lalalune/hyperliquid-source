# node94-funding-record-storage

A dependency-free standalone Rust value reconstruction of the node 94 host's
returned-record storage loop. `apply_returned_records` updates explicit sample
and fallback maps from one supplied record slice. Full tag 2 stops before any
update; other even tags append raw u64 payloads; odd tags insert or replace a
fallback value only for dex byte 3. Initial unrelated state is preserved.

The source is independently authored MIT code from the qualified binary proof
and pre-source frozen expectations in
`research/work-items/RE-007-funding-sample-storage-94`. The selected host result
ends at `0x222b480` in node 94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Native valid-tree/vector, allocator/copy/frame and ordinary-return premises
remain explicit. This library represents active values; it does not reproduce
native data layout, capacity growth, scheduling, outer dex pairing, allocation
failure, panic/rollback behavior or economic meaning. Rust allocations must
succeed for the stated value result.

The crate uses Rust 1.94.1 or later and only `std`. There is no root workspace,
build script, dependency, network operation or captured-binary execution.

```sh
cargo test --manifest-path src/node94-funding-record-storage/Cargo.toml --offline --locked
cargo test --manifest-path src/node94-funding-record-storage/Cargo.toml --offline --locked --release
```

The packet-local input-only driver and externally compared frozen corpus provide
the value validation. A source build or passing value comparison is not native
ABI/byte identity or a component acceptance gate.
