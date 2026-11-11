# RE-012: map node #115 snapshot direct children array

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The direct children key wrapper tail-jumps to 0x22521f0. The callee checks writer byte +0x1c, then tests the direct count prefix result against raw tag 2. Two selected record calls both target 0x25ddf30, with independent result checks. The loop advances the record pointer by 168 bytes. The observed handoff calls 0x227e1b0, and the unwind branch releases a buffer before resuming. This establishes the children value path below the key wrapper without assigning source types to the records.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-direct-children-array-115/collect.py --out work/node115-snapshot-direct-children-array-fresh
python3 -B research/work-items/RE-012-snapshot-direct-children-array-115/verify.py --out work/node115-snapshot-direct-children-array-check-fresh.json
```
