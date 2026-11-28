# RE-017 · Supply the restored checkpoint chain to #115 replay preflight

The selected native replay preflight compares a chain discriminator from restored state. The current Rust input calls the byte `feature_version`. Its source is the checkpoint's Locus `chn` value. A caller preparing a first-block fixture can now pass the decoded `ChainName` through the existing pipeline without constructing an unrelated block-header value.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

| Native stage | Pinned relation |
| --- | --- |
| Named MessagePack Locus | Slot 5 of the field dispatch table selects `0x332d17f`. The duplicate arm references the exact `chn` bytes. The successful field call at `0x332d195` reads the visitor's returned byte and saves it at stack `+0xf`. |
| Chain name projection | The selected MessagePack reader reaches the two existing chain-name visitors at `0x4682470` and `0x4682610`. Their canonical names are `Local`, `Sandbox`, `Testnet` and `Mainnet`, with success values 0 through 3. |
| Compact Locus result | On the selected completion path `0x3330c3e` stores the saved byte at stack `+0x280a`. The output copy at `0x332e02a` transfers `0xba0` bytes from stack `+0x1c70` to the output. The byte's output displacement is `0xb9a`. |
| Apply preflight | The compact reader compares state `+0xb9a` with 3. The expanded reader checks `+0x170a` with the same literal and diagnostic descriptor. The earlier round, hardfork pair and bundle-count guards are separate. |

The [Locus field-table packet](../RE-008-locus-msgpack-fields-115/README.md) established the `chn` field arm, the [chain codec](../RE-015-chain-codec-115/README.md) established the exact names and tags, and the [apply guard packet](../RE-009-node115-abci-apply-block-guards-and-history-prune/README.md) established guard order. The new result is the selected named checkpoint value-to-state-to-preflight join and its integration with the existing Rust input. The proof covers the selected named MessagePack path and the compared offsets. The caller still supplies the decoded restored state and any startup transformations required by its chosen path.

`ApplyBlockPipelineInput::with_restored_chain` uses the shared `ChainName` type. The legacy raw field and error variant remain available for existing callers. The focused integration test supplies a valid Testnet name and observes the same chain mismatch before any begin/action callbacks. Supplying Mainnet reaches the existing successful stages. These tests exercise independently authored Rust with synthetic state.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-restored-chain/verify.py
cargo test --locked --offline --manifest-path src/node115-abci/Cargo.toml
cargo check --locked --offline --manifest-path src/hl-node/Cargo.toml
```

The [offline run](offline-log.txt) has the target digest, native checks and actual Rust command results. The target ELF is read as data.
