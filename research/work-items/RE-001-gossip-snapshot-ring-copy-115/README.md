# RE-001: map node115 gossip snapshot ring copy sizing and span dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The ordinary gossip snapshot arm delegates to this copy routine. The routine computes allocation bytes at 24 bytes per element, applies an explicit upper bound before allocating, and selects sentinel pointer eight for zero allocation. It projects the nonempty source cursor into a first span and a wrapped remainder using the source capacity, with address steps of 24 bytes.

The resulting span length is compared with destination capacity. The growth path can relocate owned bytes using memmove or memcpy on separate branches. The subsequent dispatch compares contiguous destination space with required elements before selecting the copy path. This packet records allocation and span dispatch, leaving the per-element helper semantics and full unwind equivalence open.

The retained 1 full FDEs cover 920 bytes and 219 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-snapshot-ring-copy-115/collect.py --out work/gossip-snapshot-ring-copy-fresh
python3 -B research/work-items/RE-001-gossip-snapshot-ring-copy-115/verify.py --out work/gossip-snapshot-ring-copy-check-fresh.json
```
