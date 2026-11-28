# Record the reconstructed checkpoint root before first replay

The integrated Rust engine could record a synthetic successor digest after replay but had no entry to compute and retain its reconstructed root at the restored height. The new startup entry uses the existing reduction-tree encoder and the same selector/history path as the post-comparison stage. It accepts already reconstructed rows and uses the existing cadence gate at H. The call must occur while the engine remains at its restored replay coordinate.

The selected native constructor calls `0x5a07ec0` from `0x5a0901f`. The post-comparison block finalizer calls the same selector at `0x5a05fc9`. Both use the state pointer and height loaded at `0x5a07ed7`. The eligible path calls the root helper at `0x5a07fce` and supplies that height and root buffer to the history insert at `0x5a07fe5`. [PR #7323](https://github.com/lalalune/hyperliquid-source/pull/7323) covered eligibility preflight. The [reduction-tree study](../RE-017-abci-root-tree-115/README.md) established the selected MessagePack preimage.

The fixture computes a one-row synthetic H root using the existing encoder and checks it against the hash of independently specified bytes. It then retains the separate H+1 digest under the successor key. A cadence-skip control leaves the initial history and selector untouched. This does not project a complete native checkpoint into the reduction rows, infer digest provenance from a file name, or supply an independent native reference root.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-restored-root/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test restored_root
```

See the [offline log](offline-log.txt) for the pinned static check and Rust results. No captured code ran.
