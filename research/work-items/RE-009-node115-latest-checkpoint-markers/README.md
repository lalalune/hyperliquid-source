# RE-009: recover latest checkpoint marker admission

In the reconstructed `DbHome::load_latest_checkpoint`, a directory at `CHECKPOINT_COMPLETE` previously satisfied the marker predicate, and an EVM-only checkpoint did not. The two selected node #115 loader bodies at `0x4468e30` and `0x59ffa30` establish the same regular-file contract.

Each prepares the global marker using format record `0x44bb44` and calls through `0x64e0950`. That slot resolves to `0x1500d20`, whose metadata success branch masks the mode with `0xf000` and compares against `0x8000`. If the global predicate fails, each loader passes selector 2 to `0x1696b90` and tests the returned path with the same regular-file predicate. Either success enters the same continuation. Both failures take the rejection route. [The marker-casing packet](https://github.com/lalalune/hyperliquid-source/pull/7216) derives selector 2's final uppercase filename from the formatter.

The Rust change applies these two marker checks at the existing latest-checkpoint selection boundary. The before-and-after fixture verifies that two marker-shaped directories cannot qualify, an uppercase EVM marker can qualify on its own, and the next lower checkpoint with a regular global marker qualifies if the EVM marker is removed. The packet covers marker admission. It does not establish checkpoint integrity, restart equivalence or publication durability.

Run `python3 -B research/work-items/RE-009-node115-latest-checkpoint-markers/verify.py` from the root for the static checks. See [offline-log.txt](offline-log.txt) for the red and green regression commands and [windows.txt](windows.txt) for the original instruction windows.
