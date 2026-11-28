# RE-017 #115 restored hardfork guard before begin-block

The reconstructed ABCI pipeline accepted its legacy precondition tuple, called Begin, Action and End, and only then checked the separate replay pair in `EngineBlock`. For an ordinary mismatching restored hardfork pair, the original node makes that comparison before the selected Begin call. The fix reuses the Rust engine's existing pair guard in both entry points and checks it in the pipeline before invoking any callbacks. The pipeline still reports the same admission error and preserves the behavior of matching calls.

In the pinned #115 FDE at `0x5a04e40`, the incoming block words at `+0x28/+0x30` load into RSI/RDX before the engine loads its state pointer from context `+0x450`. At `0x5a04f05..0x5a04f23` it reads restored `+0x18/+0x20` and compares both separately. Each unequal branch enters `0x5a0626d`. The selected matching continuation reaches Begin at `0x5a04fe9 → 0x5483850`. The [local-startup rewrite evidence](../RE-017-node115-local-replay-hardfork-rewrite/README.md) identifies the restored words supplied by that path. The previous [precondition packet](../RE-009-node115-abci-apply-block-guards-and-history-prune/README.md) catalogs the comparison. This patch changes its placement in the model.

```sh
python3 -B research/work-items/RE-017-node115-pipeline-hardfork-guard/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
```

The two Rust regressions place a mismatch in a different word each time. Both show three premature callbacks on the starting source and zero after the fix. The same test suite retains the success path, callback ordering and previous feature guard. This change does not model new root production or execute any captured instructions.
