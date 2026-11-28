# RE-017 #115 compact local-startup restore ingress

[The local replay fixture](https://github.com/lalalune/hyperliquid-source/pull/7338) receives independently decoded startup words. This patch adds a standalone Rust projection of those inputs from a caller-pinned materialized checkpoint. It covers the selected compact image immediately before the local startup rewrites, before the original hardfork pair is copied and possibly changed.

The [local hardfork materialization](../RE-017-node115-local-hardfork-materialization/README.md) places the original version/round pair at `+0x18/+0x20`. The persisted Context height and round occupy `+0x28/+0x30`. The [scheduled freeze projection](../RE-017-node115-local-scheduled-freeze-option/README.md) carries the optional low dword tag at `+0x10e8` and height payload at `+0x10f0`. The local startup read at `0x2cc1aa6` tests only the tag dword. The payload of tag zero is ignored, while tag one preserves even a value of zero.

`CompactLocalRestoreInput::from_checkpoint` checks the exact `0x42c8`-byte size and requested height, reads the two round values independently, and admits the ordinary tag-zero/tag-one shapes. The regression controls verify that neighboring tag bytes are irrelevant and that an inactive option stays absent despite arbitrary payload bytes. The software projection rejects other tags in its supported domain. Clamp and replay decisions remain in the existing restore fixture.

```sh
python3 -B research/work-items/RE-017-node115-local-hardfork-materialization/verify.py
python3 -B research/work-items/RE-017-node115-local-scheduled-freeze-option/verify.py
python3 -B research/work-items/RE-017-node115-local-replay-hardfork-rewrite/verify.py
cargo test --offline --locked --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

The offline log includes a separate composition with the actual compact assembler and #7338 on absent, future, equal and past freeze cases. Second-stage rewrite, real checkpoint provenance and state-root alignment are outside this ingress proof. No captured instructions are executed.
