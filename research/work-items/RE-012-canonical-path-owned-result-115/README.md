# RE-012: map node115 canonical path result ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper calls realpath with a null output buffer. A null
result stores the high-bit sentinel at output +0 and packed
errno at +8. Otherwise it computes strlen and allocates exactly
that many bytes when nonempty, then copies without the terminator.

Empty output uses pointer one and size zero. Both successful
branches free the libc buffer before publishing capacity, pointer,
and length at +0/+8/+16. A failed allocation enters the bound
allocation-error helper with alignment one and the required size.
The scope is the ownership boundary, independent of path resolution
inside libc and the distinct getcwd and readlink paths.

The retained 1 full FDEs cover 168 bytes and 51 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 2 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-canonical-path-owned-result-115/collect.py --out work/canonical-path-owned-result-fresh
python3 -B research/work-items/RE-012-canonical-path-owned-result-115/verify.py --out work/canonical-path-owned-result-check-fresh.json
```
