# RE-017 #115 offline startup height admission

The [replica ending-height reader](../RE-012-node115-replica-end-height-source/README.md) obtains a local end height from ordinary replica directories. The selected startup caller then decides whether the requested starting height can proceed. The Rust reader now exposes that decision for offline restore fixtures.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

- On the [selected startup path](../RE-012-node115-startup-end-height/README.md), `0x2b41d32` invokes the ending-height producer only when the mode byte equals 1. The new API accepts that mode and the local `data/replica_cmds` directory.
- The selector error tag at `0x2b41d42` proceeds to the common continuation after selected cleanup. The adapter retains the underlying local error as a distinct bypass outcome.
- On a selector success, `0x2b41eb8` compares the requested height with the observed end height. The unsigned below branch at `0x2b41ebb` reaches the starting-height diagnostic. Equality and greater values pass that comparison.

The first-party test suite uses temporary replica trees to exercise a known ending height, equality, one lower height, disabled mode, an empty tree, an unavailable directory, and a result above the signed range. The adapter calls the existing file-selection reader and implements the selected admission check. It does not open a checkpoint, replay records or validate their chain provenance.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-starting-height-fixture/verify.py
cargo test --offline --locked --manifest-path src/node115-replica-end-height/Cargo.toml
```

See the [offline log](offline-log.txt) for the base diagnostic, anchored checks and full crate result.
