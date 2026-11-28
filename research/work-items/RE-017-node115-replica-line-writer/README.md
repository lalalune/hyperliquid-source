# RE-017 · Assemble one native-shaped #115 replica JSON line

The [replica JSON schema](../RE-017-node115-replica-json-schema/README.md) identifies the line's outer fields, Block members and newline terminator. The [bundle trace](../RE-017-node115-replica-bundle-json/README.md) identifies each ordered two-element bundle and its metadata. This change composes those boundaries with the existing [response emitter](../RE-017-node115-replica-response-source/README.md) into the Rust `record::write_record` adapter.

The selected outer order is `abci_block`, `resps`, `height`. The block contains `time`, `signed_action_bundles`, `round`, `parent_round`, `hardfork`, and `proposer`, in that order. Each bundle is a pair of a fixed 32-byte lowercase hex reference and a metadata object containing `signed_actions`, `broadcaster`, and `broadcaster_nonce`. A single LF terminates the successful line. The fixture retains the sequential height independently from all round words.

The caller supplies the clock text already formatted, and gives a callback for the contents of each action value and another for each response entry. An error preserves the prefix from this Rust writer and stops at the failed entry. A successful offline fixture tests exact line bytes, leading zeroes, an empty bundle, unsigned decimal width, and a populated Full response. Its action entries are synthetic callback stand-ins that demonstrate surrounding punctuation and order. Further fixtures check explicit null and an early callback error. The adapter assembles surrounding archive output and stops at the original action encoding boundary.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-line-writer/verify.py
cargo test --locked --offline --manifest-path src/node115-replica-response-json/Cargo.toml
```

The [raw offline log](offline-log.txt) records native field and edge checks and the Rust fixture results.
