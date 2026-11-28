# Read packed clock pairs from an offline restored checkpoint

The Rust checkpoint clock helper rendered separately supplied words. It can now read the current and previous clocks from a caller-pinned materialized checkpoint, preserving all six words, including the low packed date flags. It checks the compact image size and expected checkpoint height before returning the pair.

The [MessagePack clock study](../RE-017-node115-messagepack-context-clocks/README.md) binds the selected writes at `0x30d31fe/0x30d3209` and `0x30d320d/0x30d3219`. They place the two independent 12-byte values at `+0x60` and `+0x6c`. The [materializer](../RE-016-state-materialize-3c2e860-115/README.md) copies the prefix through `0x3c2ebf3`. Ordinary replay Begin reads the current clock and updates the prior lane at `0x54838b7` and `0x54838bf`. [PR #7548](https://github.com/lalalune/hyperliquid-source/pull/7548) stages those words from text. This adapter reads them back after the materialized handoff.

The regression uses different dates, nanosecond fields and flags for the two words, including the selected leap-second display form. It checks both output strings with the existing renderer and rejects a wrong height and short image. It does not infer the historical checkpoint's provenance from its bytes or apply the replay clock transition.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-compact-clock-read/verify.py
cargo test --offline --locked --manifest-path src/node115-checkpoint-clock-text/Cargo.toml
```

The [offline log](offline-log.txt) preserves actual static and Rust results.
