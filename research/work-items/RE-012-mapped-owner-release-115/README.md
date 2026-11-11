# RE-012: map node115 mapped owner ordinary and unwind release order

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The owner release first decrements the reference count reached
through +0x1d0 and calls its release helper on zero. It then
runs the visible field cleanup at +0x1d8 and for the pair at
+0x1f8/+0x200.

When the count at +8 is nonzero, it releases the allocation
at +0x10 with byte size count times 24. It calls munmap with
the independent pair at +0x208/+0x210 and tail-dispatches the
remaining field at +0x218. The unwind continuations preserve
the remaining field cleanup sequence, including the unmap,
before resuming. The packet assigns no application type to
the enclosing object.

The retained 1 full FDEs cover 257 bytes and 59 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-mapped-owner-release-115/collect.py --out work/mapped-owner-release-fresh
python3 -B research/work-items/RE-012-mapped-owner-release-115/verify.py --out work/mapped-owner-release-check-fresh.json
```
