# RE-017 #115 prune before publishing the successor root

The integrated Rust `apply_block_pipeline` previously wrote the successor root and then pruned the map. At an eligible successor height included in the pruning cutoff, its report said a new root was written even though the same pipeline call removed it. The lower-level replay fixture already uses the native order. This change aligns the integrated engine and counts only rows removed from the history that existed before the successor write.

In the [native apply-block analysis](../RE-009-node115-abci-apply-block-guards-and-history-prune/README.md), root comparison at `0x5a05c5e` precedes the selected history split at `0x5a05ee3`. That call receives context `+0x400` and a saturating cutoff increment. The disabled-prune branch joins the same continuation before the selector call at `0x5a05fc9`. The eligible selector at `0x5a07fce..0x5a07fe5` builds the root and inserts it into the same history. The focused verifier authenticates these edges and the cutoff instructions within the pinned #115 ELF.

The Rust pipeline reuses its existing history split after quorum comparison and before eligible local root insertion. The direct `apply_block` entry continues without implicit pruning. The new regression observes a missing successor root on the starting code and the expected retained successor after the change. The offline log also records the independent lower-level comparison/prune/insert test.

```sh
python3 -B research/work-items/RE-017-node115-prune-before-successor-root/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

The tests use synthetic roots and ordinary offline calls. Real root computation and archive provenance remain separate. No captured instructions are executed.
