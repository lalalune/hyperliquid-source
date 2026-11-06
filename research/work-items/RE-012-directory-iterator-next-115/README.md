# RE-012: map node115 directory iterator admission and owned entry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

An exhausted iterator returns tag zero immediately. Otherwise
it clears errno before readdir64. A null return sets the exhausted
byte and tests errno. Zero is end of iteration. Nonzero produces
the error payload at +0x10 and a zero entry owner at +8.

A nonnull record reads the name at +0x13. Only the exact one- and
two-byte names . and .. cause another readdir64. For other names
the copied byte count includes the terminator. The entry retains
the shared directory by atomically incrementing its reference
count, and publishes the copied pointer and count, inode qword and
type byte at +0x10/+0x18/+0x20/+0x28. The normal item and error
routes both use outer tag one. Directory creation and recursive
removal are outside this iterator scope.

The retained 1 full FDEs cover 369 bytes and 106 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-directory-iterator-next-115/collect.py --out work/directory-iterator-next-fresh
python3 -B research/work-items/RE-012-directory-iterator-next-115/verify.py --out work/directory-iterator-next-check-fresh.json
```
