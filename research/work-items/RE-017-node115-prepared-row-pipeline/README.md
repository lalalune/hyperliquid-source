# Pass actual prepared rows to the offline replay guard

The integrated ABCI fixture previously took two numerical counts and dispatched only integer indices. A fixture could supply two equal counts even when its actual converted action data had a different length. The new row-based entry point derives the converted payload length from the provided slice and hands each row to the existing ordered action stage after the guard succeeds. Existing index-only fixtures keep their entry point.

The original descriptor count is loaded from `[rax+0x10]` at `0x5a04f29`. The engine loads the independent converted payload descriptor from `[rsp+0x118]` and reads its length at `0x5a04f3d`. The mismatch branch at `0x5a04f4c` precedes Begin at `0x5a04fe9`. The ordinary execution path then reads the converted vector again at `0x5a050d0`. [PR #7296](https://github.com/lalalune/hyperliquid-source/pull/7296) traced original and converted descriptor ownership, [PR #7359](https://github.com/lalalune/hyperliquid-source/pull/7359) checked per-bundle length, and [PR #7598](https://github.com/lalalune/hyperliquid-source/pull/7598) exercised the empty block.

The regression starts at a synthetic completed checkpoint and supplies two inert string rows against a claimed count of three. The mismatch leaves height and round at their restored values and runs no callbacks. The same slice then passes with a header count of two, and the callbacks see Begin, both exact rows in order, and End at the successor height. Neither the fixture nor the verifier performs order submission, signing, networking or captured code execution.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-prepared-row-pipeline/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test integration first_replay_block_dispatches_the_actual_prepared_rows_after_the_count_guard
```

The [offline log](offline-log.txt) contains the static check and Rust results. The static verifier reads the pinned ELF as data.
