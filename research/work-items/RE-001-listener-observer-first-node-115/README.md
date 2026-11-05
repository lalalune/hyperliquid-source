# RE-001: map node115 listener observation first record allocation

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener observer record adapter delegates here when constructing a slot. This wrapper selects an existing-node helper when the input word at +0x20 is nonzero. Otherwise it allocates 0x1b38 bytes, initializes the parent and occupancy words, and installs the new pointer through the output owner. The first-node arm checks occupancy against eleven before writing a 24-byte side record and a 608-byte observation record.

The shared normal return updates the owner count and returns four descriptor words. The packet maps the first-node construction path and its existing-node boundary without inferring record field meanings.

The retained 1 full FDEs cover 510 bytes and 119 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-listener-observer-first-node-115/collect.py --out work/listener-observer-first-node-fresh
python3 -B research/work-items/RE-001-listener-observer-first-node-115/verify.py --out work/listener-observer-first-node-check-fresh.json
```
