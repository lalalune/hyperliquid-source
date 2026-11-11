# RE-012: map node #115 snapshot span writer iterator

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The formatting adapter uses 0x22f2f70. The entry tests the supplied length for zero. The observed loop compares its cursor against the saved boundary at +0x18 and tests a byte at descriptor +0x10 against 0x23 before the path reaching 0x2308f50. This binds the cursor, marker and helper boundary without identifying the original source type.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-span-writer-iterator-115/collect.py --out work/node115-snapshot-span-writer-iterator-fresh
python3 -B research/work-items/RE-012-snapshot-span-writer-iterator-115/verify.py --out work/node115-snapshot-span-writer-iterator-check-fresh.json
```
