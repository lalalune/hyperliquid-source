# Initialize the offline ABCI engine from a post-restore image

The integrated Rust fixture previously required separate height, round and replay-pair inputs. It can now take the exact completed checkpoint directory and one caller-pinned compact image after local startup. This uses the pair already stored in the image without running the startup rewrite or incrementing the first word again. It also reads the Context round and materialized root settings from the same image.

| Field | Native observation |
| --- | --- |
| Replay comparison pair at `+0x18/+0x20` | The selected empty-vector continuation reads the whole pair at `0x2cc24b2`. |
| Starting height and Context round at `+0x28/+0x30` | The startup continuation loads both at `0x2cb7976` and copies them to its replay initializer at `0x2cb80c6`. The accepted loader stage separately verifies the requested height at `0x3c128d4`. |
| Freeze option at `+0x10e8/+0x10f0` | The root selector compares the low tag dword at `0x5a07f48` and reads the payload on the active path. |
| Cadence at `+0x39c8` | The selector reads the persisted interval at `0x5a07f85`. |

[PR #7561](https://github.com/lalalune/hyperliquid-source/pull/7561) parses the pre-rewrite image for startup, [PR #7594](https://github.com/lalalune/hyperliquid-source/pull/7594) applies the startup mutation, and [PR #7617](https://github.com/lalalune/hyperliquid-source/pull/7617) validates supplied pair values. This adapter connects the later materialized image to the existing Rust engine. It assumes the image is already pinned and excludes native checkpoint decoding and raw-root proof.

The offline regression reads a temporary compact image at H, retains a pair round distinct from the Context round, checks the completion marker and height, and runs one existing synthetic replay block at H+1. The input's cadence triggers the candidate root exactly at the successor height. Size, coordinate and malformed option checks are exercised separately.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-post-restore-replay/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test post_restore_image
```

The [offline log](offline-log.txt) records the pinned spans and actual tests. The captured executable is read as data.
