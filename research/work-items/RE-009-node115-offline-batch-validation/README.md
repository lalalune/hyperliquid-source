# Validate local storage batch names before changing the reconstructed shard

The offline shard store applied puts and deletes to its live in-memory maps while validating column-family names one at a time. If a later operation named an unknown family, the call returned an error but left earlier operations in memory. A subsequent successful batch could persist them. The fixture now checks every requested family first, so a batch rejected for an unsupported family has no effects.

The selected #115 storage wrappers create a separate batch through `0x64e7390` at `0x3d4c31f` and `0x3d4c6af`, stage its contents through `0x64e96b0`, and submit through a later helper at `0x3d4c3da` and `0x3d4c757`. The [storage integration packet](../RE-009-node115-rocksdb-profiles-and-apply-block-lifecycle/README.md) binds those caller families and the supported column-family names. The reconstructed store's lookup takes Rust strings. The native calls establish the separate preparation and write stages, rather than an original error contract for an unknown string.

The local test batches a put and delete ahead of a misspelled family, then checks both immediate reads and reads after a later successful flush and reopen. This validates rejection before mutation. The fixture still uses per-file replacements and does not claim cross-family crash atomicity for an I/O error after validation.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-offline-batch-validation/verify.py
cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-db/Cargo.toml --test write_batch_validation
```

The [offline log](offline-log.txt) records the failing baseline and passing tests. The verifier only reads the pinned ELF as data.
