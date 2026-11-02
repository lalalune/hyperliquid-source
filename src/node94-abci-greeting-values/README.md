# Node94 ABCI greeting values

This real standalone MIT library reconstructs the complete bounded value and
Reader-state operation at node94 `0x4674820..0x4674b45`. It uses only the merged
`hl-bincode-varint` path provider. There is no root workspace, external package,
build script, pending PR1365 dependency, captured code or network operation.

The independently derived pre-code contract, complete native proof and18,290
input/expected frames are frozen in
[`RE-012-abci-stream-greeting-values-94`](../../research/work-items/RE-012-abci-stream-greeting-values-94/README.md).
The target SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source qualification is separate; the frozen pre-code packet is not edited to
claim an implementation or build retroactively.

`Reader::new(input, cursor, limit, charged)` constructs a safe Reader. `None`
is canonical native limit tag0; `Some(limit)` is tag1. `decode()` returns one
complete owned `Greeting` or an active `NativeError`, retaining cursor/remaining
and charged state on error. It accepts trailing input and nonminimal scalars.
The fast/slow u64 invalid categories and marker consumption remain distinct.
`decode_with_limit(input, limit)` is the selected EDX=0 caller: fresh enabled
Reader, consumed count only with success, no internal Reader-state ABI claim.

Signatures contain eight u64 limbs and one unrestricted byte; no cryptographic
validity follows. Maps use unsigned20-byte keys, last duplicate wins, and charge
every wire row. Records carry two wire-order u64 values plus2048 raw bytes.
Container layout, native B-tree shape, allocation identity, callbacks and pointer
ABI are not part of this safe representation.

`InvalidState` and `HostAllocation` are safe policies distinct from native error
kinds. The vector explicitly attempts a checked reservation; ordinary standard
map and box allocation can still abort on exhaustion. The correspondence theorem
requires successful allocation and normal imported/frame behavior, and excludes
arbitrary native flags, foreign mutation, unwind and instrumentation-enabled
caller paths. No network handshake compatibility or component gate is claimed.

After the separate source/build gate, the genuine package can be built using
the repository-pinned Rust1.94.1 toolchain:

```sh
cargo test --offline --locked --manifest-path src/node94-abci-greeting-values/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node94-abci-greeting-values/Cargo.toml
```

Those commands are reproduction instructions, not an assertion that they have
already run. Actual source qualification receipts belong in the packet's additive
`rust-validation` directory after execution. No captured target is needed by
this library or its unit/integration tests.
