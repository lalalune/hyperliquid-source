# RE-001: map node115 listener observer occupied control cursor

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The period reset path passes its occupied-control descriptor to this collector. A nonzero remaining count permits the scan. If the current lane mask is exhausted, the collector loads the next sixteen control bytes and inverts the sign-bit mask to recover occupied lanes. It advances the control cursor by sixteen bytes and the record base in the opposite direction by 512 bytes.

For a selected lane it clears the lowest bit, converts its index to a 32-byte record displacement and decrements the remaining count. It then can pass the record key to the previously mapped fixed-width hash. This packet limits its claim to the occupied cursor and handoff, leaving the rest of the collection transformation open.

The retained 1 full FDEs cover 1249 bytes and 290 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-listener-observer-occupied-scan-115/collect.py --out work/listener-observer-occupied-scan-fresh
python3 -B research/work-items/RE-001-listener-observer-occupied-scan-115/verify.py --out work/listener-observer-occupied-scan-check-fresh.json
```
