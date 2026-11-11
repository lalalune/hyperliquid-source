# RE-012: map node115 readiness-gated writev retry and result

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The write path first calls the readiness helper. A readiness
tag 3 returns result tag 2, and tag 2 forwards its payload
as result tag 1. The other route loads the live fd, guards
the -1 sentinel and calls writev with at most 1024 vectors.

A write return other than -1 yields tag zero with the actual byte count.
On -1 the wrapper packs errno and classifies it through
0x5cf1700. Class 0xd alone enters the readiness retry route.
It compares the sampled byte with bits 16..23 of the shared
word. When the generation matches, the CAS clears only bits
selected by the projected mask; otherwise it rejoins the
readiness helper without writing that word. Other classes
return tag one with the packed error. No write was performed
on a live socket.

The retained 1 full FDEs cover 367 bytes and 96 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-readiness-writev-115/collect.py --out work/readiness-writev-fresh
python3 -B research/work-items/RE-012-readiness-writev-115/verify.py --out work/readiness-writev-check-fresh.json
```
