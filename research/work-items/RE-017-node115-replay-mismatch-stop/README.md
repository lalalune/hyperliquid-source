# Stop offline successor publication when the reference comparison mismatches

The reconstructed replay retained a mismatch observation but then proceeded to prune history and generate a successor root. The selected native comparison ends on its mismatch arm. Both offline fixture entry points now preserve the completed sink writes and comparison prefix, then suppress the later history and selector effects.

The sink call at `0x5a05c5e` precedes the digest comparisons. The selected 32-byte equality test uses two 16-byte comparisons and jumps at `0x5a05d28` to the mismatch path at `0x5a060ec`. That path calls the diagnostic through `0x5a06212`; its next instruction jumps to `ud2` at `0x5a0639a`. The ordinary history split at `0x5a05ee3` and successor selector at `0x5a05fc9` are outside this failure continuation. The existing [reference-handoff packet](../RE-017-node115-digest-reference-handoff/README.md) established the ordered sink and comparison prefix.

The fixtures return the comparison report for inspection. They do not emulate the diagnostic or terminate the test process. The synthetic regression supplies pre-staged reference rows and checks that the mismatch leaves both sink rows visible, produces only one comparison, and performs neither history pruning nor successor capture. This is a local reconstruction check with no network, signer or captured binary execution.

## Reproduce

Node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-replay-mismatch-stop/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

The [offline log](offline-log.txt) retains the failing baseline, static check and both passing test suites.
