# RE-017 #115 local startup hardfork inputs in the replay fixture

The checkpoint/replay fixture initializes its comparison pair from the always-rewriting `0x3c12800` loader. The separately traced local startup path at `0x2cc1120` preserves the on-disk hardfork pair unless a scheduled freeze reaches the current height. Fixtures for that path previously had no matching restore entry point. `restore_local_checkpoint` uses the existing discovery check and accepts decoded state fields, then passes the locally selected pair into the existing replay engine. The original restore entry point retains the always-rewriting behavior.

The target is Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [static rewrite packet](../RE-017-node115-local-replay-hardfork-rewrite/README.md) verifies the original copy at future `+0x68/+0x70`, the two bypass edges, the equality-only state stores and the failure edge for a past target. Its selected spawn path reloads materialized state `+0x18/+0x20`. The separately verified [MessagePack restore projection](../RE-017-node115-local-hardfork-materialization/README.md) binds those offsets to on-disk `hardfork.version` and `hardfork.round`.

The new fixture records the original pair and projects the pair used by the next replay block. A missing freeze or future target retains both words. An exact match saturating-increments the hardfork version and copies the distinct persisted Context round into the second word. A past target gives a typed error. The test feeds the pre-rewrite hardfork round into the existing replay gate, sees a mismatch, and applies the first block with the materialized pair. The independent replay height/round initializer still uses the persisted Context height/round.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-local-replay-hardfork-rewrite/verify.py
cargo test --locked --offline --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

[Offline log](offline-log.txt) includes the base diagnostic and complete crate check. The Rust model uses synthetic decoded inputs and ordinary temporary checkpoint directories. It models this projection after discovery. It does not open a native MessagePack checkpoint, execute captured code, or establish H/H+1 root equality.
