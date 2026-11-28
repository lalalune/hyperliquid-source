# Preserve native slot numbering while assembling the top-level root tree

The Rust encoder accepts already indexed reduction rows. A caller assembling them from ordinary checkpoint capture results previously had to reimplement the sparse mapping. The new top-level adapter accepts exactly 59 outcomes, retains the original positions for values and preserves any already reduced nested vector. An unpopulated slot and a child with the omit status each leave no row.

The selected [compact capture](../RE-017-abci-compact-root-115/README.md) allocates `0x588` bytes at `0x4e35155`, records 59 slots and reaches the reducer through `0x4e35359`. The reducer visits 24-byte children. It increments the original slot index at `0x141a3b0`, including after the sentinel and returned tag-2 branches at `0x141a3d2` and `0x141a407`. The original index is staged at `0x141a3f7`. An exhausted result with no retained rows returns a tag-1 vector with zero length at `0x141a741–0x141a750`. That vector's wire shape is the one documented in the [reduction-tree packet](../RE-017-abci-root-tree-115/README.md).

This adapter consumes selected ordinary capture outcomes. It does not read native pointer cells, reconstruct missing leaves, or mix the original checkpoint-root provenance with local synthetic digests. Tests compare the complete tree preimage with independent bytes for sparse indices including the last slot, an empty nested group, a populated nested group and an entirely empty capture.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-top-level-root-capture/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test top_level_root_capture
```

The [offline log](offline-log.txt) records the verification. The pinned executable is read as data.
