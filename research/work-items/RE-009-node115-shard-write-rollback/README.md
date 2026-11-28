# Roll back a failed single write in the offline shard fixture

The reconstructed shard store modified its in-memory map before replacing the column-family file. If the file write failed, the returned error left the attempted update in memory. A subsequent successful flush could persist it. A failed single put or delete now restores the previous value without rewriting the existing on-disk file.

The selected #115 storage wrapper calls through `0x64e6f78` at `0x3d5ebe0` and distinguishes the returned error pointer from its successful case at `0x3d5ebee`. The [storage lifecycle packet](../RE-009-node115-rocksdb-profiles-and-apply-block-lifecycle/README.md) covers the surrounding storage API. This change keeps the reconstructed single-write result consistent with its own atomic file replacement. It does not infer native RocksDB cache rollback or change batch error handling.

The regression blocks the local temporary output path with a directory. It verifies that a failed replacement, new insertion and deletion leave the original values in memory and after a later successful flush and reopen. All writes occur in temporary fixture storage.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from repository root.

```sh
python3 -B research/work-items/RE-009-node115-shard-write-rollback/verify.py
cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
```

The [offline log](offline-log.txt) records the baseline failure and passing checks. The verifier reads the captured executable as data.
