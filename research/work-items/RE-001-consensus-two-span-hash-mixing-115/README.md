# RE-001: map node115 consensus two-span hash input and final fold

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The candidate table probe uses this helper for its initial hash. It reads two pointer and length pairs from offsets zero/eight and +0x20/+0x28. For each selected span, the short routes use distinct load widths: first/middle/last bytes through length three, first and last dwords through length seven, and first and last qwords below seventeen. Longer spans fold 64-bit products with XOR of the high and low halves.

The final fold includes both lengths and additional descriptor words, combines fixed multiply constants, and rotates the result left by twenty. The packet binds the arithmetic and load bounds without inferring a named algorithm or treating it as a cryptographic identity check.

The retained 1 full FDEs cover 679 bytes and 185 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-two-span-hash-mixing-115/collect.py --out work/consensus-two-span-hash-mixing-fresh
python3 -B research/work-items/RE-001-consensus-two-span-hash-mixing-115/verify.py --out work/consensus-two-span-hash-mixing-check-fresh.json
```
