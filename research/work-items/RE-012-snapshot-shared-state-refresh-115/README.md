# RE-012: recover node #115 guarded shared-state refresh dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

This routine acquires the byte at 0x64fee00 by setting bit zero with compare-exchange. If the shared pointer at 0x64fee08 is nonnull, it reads the pointer's +0x138 qword, clears its low bit, and compares it with 0x64fee10. Equality skips refresh; a difference updates the cached value, acquires the second byte at 0x64fede0, and calls 0x5cee900.

The null-pointer arm also acquires the second byte but instead checks 0x64fedf8 before invoking 0x5cde710 with selector 17. The packet records the guarded dispatch and cache key without assigning a meaning to the selector or the low bit.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-shared-state-refresh-115/collect.py --out work/node115-snapshot-shared-state-refresh-fresh
python3 -B research/work-items/RE-012-snapshot-shared-state-refresh-115/verify.py --out work/node115-snapshot-shared-state-refresh-check-fresh.json
```
