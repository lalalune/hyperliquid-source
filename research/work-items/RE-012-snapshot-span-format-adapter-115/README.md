# RE-012: map node #115 snapshot span formatting adapter

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The pair state writer calls 0x25bf160 for both value spans. The callee calls 0x22f2f70 at two separate sites and tests the returned word immediately after each call. It separately checks the two saved span bounds and a byte flag before the latter call. The packet pins those branch boundaries and retains the full unwind extent.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-span-format-adapter-115/collect.py --out work/node115-snapshot-span-format-adapter-fresh
python3 -B research/work-items/RE-012-snapshot-span-format-adapter-115/verify.py --out work/node115-snapshot-span-format-adapter-check-fresh.json
```
