# RE-017 #115 local startup pair selection at the offline replay gate

The offline completed-reader API now takes the decoded local state fields and selects the pair used at the first Block comparison on the bounded local startup path. This connects the [startup rewrite](../RE-017-node115-local-replay-hardfork-rewrite/README.md) to the [completed read and replay Block gate](../RE-017-node115-completed-replay-block-gate/README.md). A fixture no longer needs to duplicate the rule or supply the already rewritten pair.

| Scheduled freeze height | Expected pair on normal continuation |
| --- | --- |
| Absent or greater than the restored height | Original hardfork version and round |
| Equal to the restored height | Saturating increment of the hardfork version and the restored Context round |
| Less than the restored height | Stale-height result before the Block gate |

The test uses a plain Block containing the original parent pair and an LZ4 Block containing the rewritten pair. It also exercises the mismatch, stale-height failure and saturating version boundary. The caller still provides typed local restore fields. No captured binary is executed. This models the two compared words and excludes the remaining rewrite state changes, native helper behavior, queue selection, and root equality.

## Offline verification

```sh
python3 -B research/work-items/RE-017-node115-replay-local-startup-selection/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

See [actual offline output](offline-log.txt) from both commands.
