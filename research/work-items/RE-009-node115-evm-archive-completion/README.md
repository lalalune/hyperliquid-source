# Classify the result of EVM archive creation

The existing ABCI fixture can prepare a tar command. The new read-only completion helper classifies the two archive paths after the tar command has succeeded and the native destination-preparation step has been reached. A regular final file takes precedence. The temporary file is then eligible for cleanup only if it is also regular. With a missing or nonregular final path, a regular temporary file is eligible for publication. With neither regular, there is no archive to publish.

| Decision | #115 evidence |
| --- | --- |
| Reach completion after successful command | The null error return branches at `0x38c4a3e` to `0x38c4cac`. |
| Keep an existing regular final | The final path saved at stack `+0xe8/+0xf0` is checked at `0x38c4cdf`. The true branch passes the temporary path from `+0x98/+0xf8` into cleanup via `0x38c4cfc`. The cleanup helper tests regular-file type before its `unlink` import. |
| Publish a regular temporary archive | When the final check is false, `0x38c4d24` tests the temporary path. Success passes temporary and final to `0x1502da0` through `0x38c4d55`. That helper builds an invocation of `mvtmp`. |
| No eligible archive | When both regular-file tests fail, the branch at `0x38c4d2c` bypasses the move helper. |

The [preparation intersection](../RE-001-node115-evm-archive-checkpoint-intersection/README.md) and [PR #7094](https://github.com/lalalune/hyperliquid-source/pull/7094) establish member and path planning before tar. This fixture accepts those paths as inputs to the later decision. It performs metadata reads only. It does not call the filesystem-mutation helpers, launch a command or infer that a move would succeed.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-evm-archive-completion/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test integration daily_evm_archive_completion_prefers_final_regular_file
```

The [offline log](offline-log.txt) records the pinned static check and tests with absent paths, real regular files and directory lookalikes.
