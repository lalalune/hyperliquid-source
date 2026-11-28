# Match the runtime checkpoint directory height to the saved record

The reconstructed runtime selects a numerical checkpoint directory before decoding its local checkpoint record. It previously checked the record's chain, root and sidecar but could restore a matching record and sidecar from a directory labelled with a different height. Runtime restore now checks that the selected height matches the decoded record before constructing the engine state.

The #115 loader saves the selected height from the row at `0x3c12822`. After decoding, `0x3c128ca` reads the persisted state height at `+0x28`. Comparison at `0x3c128d4` sends unequal values to `0x3c12a16`, before the ordinary write path begins at `0x3c128dd`. The [loader handoff study](../RE-017-abci-loader-handoff-115/README.md) establishes the source offsets and branch. The lower-level Rust replay fixture already checks the same relationship. This patch connects it to the actual reconstructed runtime entry point and keeps that runtime's local checkpoint encoding.

The regression writes one real local checkpoint with the reconstructed runtime on a temporary directory. An unchanged copy of its data is first placed under a different numerical directory name. Reopening the correctly labelled directory keeps the original restore result. The test uses only local files and opens no node connection.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-runtime-checkpoint-height/verify.py
cargo test --offline --locked --manifest-path src/hl-node/Cargo.toml --test e2e_node_runtime checkpoint_directory_height_must_match_persisted_record
```

The [offline log](offline-log.txt) records the baseline mismatch and the passing Rust and static checks. The captured binary is read as ELF data.
