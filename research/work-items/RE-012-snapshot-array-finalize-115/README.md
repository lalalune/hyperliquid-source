# RE-012: map node #115 snapshot array finalizer

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The book-pair and composite order-record writers use finalizer 0x2331920. A first descriptor byte of 1 takes a diagnostic path. A zero second byte bypasses the depth transition. Otherwise the worker requires a nonzero depth, decrements it, and tests the writer state at +0x20 before the indentation path. It appends the closing bracket at 0x23319f4 and has a capacity-equality branch before that write. This records the closing protocol shared by the two callers.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-array-finalize-115/collect.py --out work/node115-snapshot-array-finalize-fresh
python3 -B research/work-items/RE-012-snapshot-array-finalize-115/verify.py --out work/node115-snapshot-array-finalize-check-fresh.json
```
