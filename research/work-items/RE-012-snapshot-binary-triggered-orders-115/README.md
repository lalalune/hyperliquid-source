# RE-012: map node #115 snapshot binary triggered-order dispatch

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The binary paired writer calls 0x22269f0 for its second value. This worker tests writer byte +0xc for zero and checks the count-prefix return against tag 2. It reaches 0x22b8860 at multiple distinct sites and passes one result route to 0x227e2e0. A separate branch calls 0x22b8590 and tests the returned record. The packet maps those branch boundaries without assigning runtime schema semantics to the raw result.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-binary-triggered-orders-115/collect.py --out work/node115-snapshot-binary-triggered-orders-fresh
python3 -B research/work-items/RE-012-snapshot-binary-triggered-orders-115/verify.py --out work/node115-snapshot-binary-triggered-orders-check-fresh.json
```
