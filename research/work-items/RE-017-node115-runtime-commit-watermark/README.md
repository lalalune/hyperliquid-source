# Preserve the committed round of a local runtime checkpoint

The reconstructed runtime writes the applied round and the committed round separately in its local checkpoint metadata. Restore previously initialized the commit watermark from the applied round even when the metadata contained the actual saved watermark. The local restore path now uses the saved value, including zero. Older metadata without the field retains the existing inference from the applied round.

In node #115 the ABCI state writes its block round at state `+0x30` in `0x54838f1` and the loader reloads that word at `0x3c128e7`. Separately, the established [two-chain commit boundary](../RE-008-node115-hotstuff-commit-and-quorum/README.md) reads its own committed round from consensus state `+0x380` at `0x2e15e49` before testing the candidate. These native anchors establish the separate roles. The JSON file is the reconstructed runtime's local format. The change does not claim an original node checkpoint metadata schema, rebuild a commit graph or exercise consensus network behavior.

The offline fixture advances one empty local block to round 7 while the committed round remains zero. It persists and reloads the checkpoint and compares both round values and the exact same local root. A second restart uses legacy metadata without the committed-round field.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-runtime-commit-watermark/verify.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test checkpoint_commit_watermark
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test e2e_node_runtime e2e_checkpoint_replay_blake3_root_and_restart_persistence
```

The [offline log](offline-log.txt) records the failing baseline, passing restart controls and static checks. The captured binary is read as data.
