# RE-001: map node115 child descriptor read sizing and partial progress

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The child collector hands each ready descriptor and its accumulated output vector to this reader. The entry compares spare capacity with 32 and may use a separate small probe. The main loop initially limits reads to 8192 bytes, further bounded by spare capacity and signed ssize_t maximum. The read -1 path retries errno four, otherwise packages errno in the high 32 bits with low tag two and retains the current vector length.

A successful read adds the actual byte count to the vector length. Zero ends the loop and returns the delta from entry length. When capacity is exhausted, the selected allocation path requests the larger of double capacity and capacity plus 32. Allocation failure is a separate tagged result. The evidence ties partial-progress semantics to the child collector without claiming how real pipes schedule reads.

The retained 1 full FDEs cover 603 bytes and 168 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-child-reader-growth-115/collect.py --out work/startup-child-reader-growth-fresh
python3 -B research/work-items/RE-001-startup-child-reader-growth-115/verify.py --out work/startup-child-reader-growth-check-fresh.json
```
