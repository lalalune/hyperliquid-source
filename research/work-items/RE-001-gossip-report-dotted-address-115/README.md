# RE-001: map node115 gossip report dotted four-byte value formatting

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The key-object serializer delegates this value formatter after the colon. It reads four consecutive unsigned input bytes into a stack formatter, whose temporary buffer is prefilled with dots. The first byte uses one, two or three decimal digits, with the retained decimal pair table on the multi-digit routes. It calls the bound direct digit helper for each remaining byte and leaves a single prefilled dot before each.

The combined span is passed through the byte escape helper between two quote writes. The wrapper therefore returns a quoted dotted four-byte value. This is a format observation, independent of how caller addresses are selected or interpreted.

The retained 1 full FDEs cover 382 bytes and 106 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-dotted-address-115/collect.py --out work/gossip-report-dotted-address-fresh
python3 -B research/work-items/RE-001-gossip-report-dotted-address-115/verify.py --out work/gossip-report-dotted-address-check-fresh.json
```
