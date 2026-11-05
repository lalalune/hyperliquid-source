# RE-012: map node115 child stdio remap and interrupted retry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The child-side routine reads three consecutive eight-byte descriptor
records. A zero first dword skips its remap. A nonzero first dword
selects the second dword as the source for dup2, with destination
0, 1 or 2 at call sites 0x5c870f5, 0x5c87175 and 0x5c871f8.

Each retry path checks specifically for -1 and reads errno through
the bound import. It forms (zero-extended errno << 32) | 2.
Errno 4 runs the local helper at 0x5c74b90 and retries with the
same source and destination. Other errors branch to shared cleanup.
Cleanup tests each record tag against unsigned threshold two and
closes the source for tags at or above two. The packed error survives
these close calls in a callee-saved register and is returned in RAX.
Scope is direct child remapping. The remaining child setup and the
separate posix_spawn path are outside the reconstructed behavior.

The retained 1 full FDEs cover 1037 bytes and 274 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 7 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-child-stdio-remap-115/collect.py --out work/child-stdio-remap-fresh
python3 -B research/work-items/RE-012-child-stdio-remap-115/verify.py --out work/child-stdio-remap-check-fresh.json
```
