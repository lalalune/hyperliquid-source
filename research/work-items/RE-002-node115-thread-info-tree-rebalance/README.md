# RE-002: thread-info tree rebalancing in node #115

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Licensed Rust 1.95.0 release source commit 59807616e1fa2540724bfbac14d7976d7e4a3860 and rust-src SHA-256 67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363.

The pinned B-tree code reproduces both bulk redistribution directions for the thread-info map at their complete 839- and 923-byte FDE extents. The verifier checks each source relocation and its linked destination. The scope is the two collection operations.

Provision the offline cache using RE-002-node115-umodti3-source-build. Rebuild
std and panic_unwind with frame pointers and one codegen unit. Run with Python 3.12 and GNU
binutils 2.42 from the repository root.

```sh
python3 -B research/work-items/RE-002-node115-thread-info-tree-rebalance/verify.py /path/to/cache /path/to/binutils
```
