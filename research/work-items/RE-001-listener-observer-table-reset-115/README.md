# RE-001: map node115 listener period table reset and temporary ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener period observer calls this function between its two clock samples. The function conditionally builds an occupied-control cursor from each of two table descriptors and calls the same collector. The second collection additionally checks the owner flag. It releases each returned temporary allocation using a 24-byte stride when the returned capacity is nonzero.

Subsequent reset arms fill control storage with 0xff, clear the occupied count and store a recomputed growth word, with a separate small-mask branch. The packet distinguishes conditional collection from the subsequent descriptor reset and leaves collector eligibility and live behavior outside scope.

The retained 1 full FDEs cover 653 bytes and 152 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-listener-observer-table-reset-115/collect.py --out work/listener-observer-table-reset-fresh
python3 -B research/work-items/RE-001-listener-observer-table-reset-115/verify.py --out work/listener-observer-table-reset-check-fresh.json
```
