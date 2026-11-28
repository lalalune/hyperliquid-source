# RE-009 #115 fixture local root-history pruning

The replay fixture can now model the local-history prune that runs between comparison and end-root insertion. The [apply-block guards packet](../RE-009-node115-abci-apply-block-guards-and-history-prune/README.md) established the branch in the captured image. The fixture previously compared and then ran the end selector without the optional split.

The captured branch tests the byte at context `+0x10`, loads the base at `+0x18`, and passes its saturating increment to the split helper at `0x5a05ee3` on context history `+0x400`. The end selector call at `0x5a05fc9` follows that operation. The fixture exposes the prune base as an explicit optional input. It keeps keys at or above the cutoff, then runs the end selector. The original entry point still selects the flag-clear path.

The regression case checks all three stages in one block. Comparison sees a matching local entry that the subsequent prune removes. A key at `u64::MAX` survives the saturated cutoff. The end selector then writes the new root, which would disappear if pruning ran last. The control in the offline log disables only the split. The same regression test fails when the old entry remains in history. All six tests pass with the split enabled.

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-fixture-history-pruning/verify.py
cargo test --locked --offline --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

This adds the documented ordering to a synthetic fixture. The prune base and new digest are caller-supplied, and this does not establish the corresponding values for a real checkpoint.

[Raw test output](offline-log.txt) | [Instruction windows](windows.txt)
