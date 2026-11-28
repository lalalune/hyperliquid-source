# RE-017 · Locate a first #115 Block in mixed offline replay input

The selected replay decoder produces either a Block with optional attachments or an opaque Tx owner with a null first word. The worker has a separate null-first callback and retrieval continuation. That item can occupy a replay position without supplying the Block inputs needed for checkpoint replay. The [wire pair](../RE-017-node115-replay-payload-pair/README.md), [null-first worker trace](../RE-017-node115-replay-null-published-worker/README.md), and [Block startup comparison](../RE-017-node115-replay-block-identity-gate/README.md) give these native boundaries. The test fixture supplies the ordered completed payloads explicitly.

`first_block::select_first_block` consumes an already ordered offline fixture from its first entry. Before selecting the first Block, it skips successfully decoded opaque Tx entries, preserving their positions in the input numbering. It returns the selected Block and the original attachment option, its zero-based fixture position, the observed decoder span and consumed prefix, and the selected successor. The explicit startup pair is checked in native order.

The offline evidence selection reports an undecodable entry or mismatching first Block rather than substituting a subsequent match. This is a fixture input rule and supplies no native retry claim. The integration case finds a compressed Block at position two after two plain Tx records and preserves its decoder prefix length despite trailing bytes. A second fixture distinguishes an all-Tx input from a Block. A third records the first pair mismatch with a later matching Block present. The selector omits callback effects, transport time, and the later converter decision.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-first-decoded-block-fixture/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The [raw offline log](offline-log.txt) contains the pinned verifier and Rust fixture results.
