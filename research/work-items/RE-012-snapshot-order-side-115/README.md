# RE-012: map node #115 snapshot order side encoding

Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 05bc2de303c05525b71e7e257426e741bc66a390. Original ELF virtual addresses.

The dbOrder object writer calls 0x26a6c80 for side. The selector tests the source byte for exact equality to 1. That arm takes its source from 0x5f3ed7 and the other takes it from 0x5f3ed3. The bytes are A and B respectively. Each arm opens a quote and passes exactly one byte to 0x25bf330. The common continuation closes the quote. The three capacity branches converge back to their respective quote writes. This packet preserves raw selector behavior and literal payloads.

GNU, LLVM and Capstone agree on the retained instruction partition. GNU readelf confirms the full FDE. The qualification record retains the altered-window and target identity rejection results. Static analysis only. Collector scaffolding is adapted from the MIT Build ID packet via the snapshot mode-1 packet.

```sh
python3 -B research/work-items/RE-012-snapshot-order-side-115/collect.py --out work/node115-snapshot-order-side-fresh
python3 -B research/work-items/RE-012-snapshot-order-side-115/verify.py --out work/node115-snapshot-order-side-check-fresh.json
```
