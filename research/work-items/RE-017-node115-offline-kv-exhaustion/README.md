# Require complete consumption of local shard snapshot records

The reconstructed shard store could open a `.kv` file containing two concatenated snapshots. Its reader interpreted the first header and declared entries, then ignored the remaining bytes. The binary fixture format represents one complete column family per file. The reader now returns an invalid-data error when the declared entries leave a tail.

The native [EVM checkpoint hash study](../RE-011-evm-db-checkpoint-hashes-115/README.md) records the separate end-of-document check for its JSON format. At `0x3ef17e3` the reader compares the consumed offset with the input length. Remaining bytes that fail the whitespace check branch to the error at `0x3ef185e`. The local shard file is a reconstructed binary format, so its writer has no trailing whitespace convention. This fix applies complete-consumption behavior to that local reader without claiming native RocksDB file compatibility.

The regression writes two normal snapshots through the existing local shard implementation. It reopens the first alone, then confirms their concatenation fails instead of silently restoring the first record. Only temporary local files are used.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from repository root.

```sh
python3 -B research/work-items/RE-017-node115-offline-kv-exhaustion/verify.py
cargo test --offline --locked --manifest-path src/node115-db/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-db/Cargo.toml --test kv_snapshot_exhaustion
```

The [offline log](offline-log.txt) records the failing baseline, static check and passing Rust tests. The pinned target is read as data.
