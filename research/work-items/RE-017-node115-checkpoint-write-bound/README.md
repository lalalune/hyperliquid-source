# Keep written local checkpoints within the restore byte limit

The reconstructed `hl-node` writer could persist a completed checkpoint whose decompressed payload exceeded the maximum supported by its own reader. Reopening would select that checkpoint and return an LZ4 limit error. The writer now checks the encoded size against the same reader constant before compression or checkpoint-directory writes.

The [size-prefixed LZ4 study](../RE-012-lz4-decode-115/README.md) binds the native adapter at `0x477f8c0`. It reads the declared decoded size at `0x477f8ee`, compares it to the caller's bound and branches to the limit path at `0x477f8fc` before allocating output. The 16 MiB checkpoint limit and local bincode record belong to the reconstructed runtime. This fix does not assign that value to the native checkpoint decoder.

The regression persists and later reopens a valid local checkpoint. Between those operations it attempts to save a local synthetic successor with an inert payload whose encoded record exceeds the existing limit. The baseline publishes the oversized checkpoint and its restart reports `Decode(Limit)`. The fixed path rejects the write before creating the new checkpoint directory, so restart preserves the preceding checkpoint's height and root. No network or captured execution is used.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from repository root.

```sh
python3 -B research/work-items/RE-017-node115-checkpoint-write-bound/verify.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test checkpoint_write_bound
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test e2e_node_runtime e2e_checkpoint_replay_blake3_root_and_restart_persistence
```

The [offline log](offline-log.txt) records the baseline failure and passing offline tests.
