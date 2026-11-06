# RE-012: map node115 cached debug-directory metadata predicate

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

A nonzero cache byte returns true only for value one.
The uncached route constructs the null-terminated path
/usr/lib/debug on the stack and queries metadata with
dirfd -100 and flags zero.

Tag three falls back to stat64. Tag two drops the saved
metadata error, and failed stat64 packs and drops errno.
Both failure routes cache two. A successful metadata
result masks mode with 0xf000 and caches one only for
0x4000, otherwise two. The result concerns this exact
cached predicate and leaves debug-file search outside
scope.

The retained 1 full FDEs cover 286 bytes and 65 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-debug-directory-presence-115/collect.py --out work/debug-directory-presence-fresh
python3 -B research/work-items/RE-012-debug-directory-presence-115/verify.py --out work/debug-directory-presence-check-fresh.json
```
