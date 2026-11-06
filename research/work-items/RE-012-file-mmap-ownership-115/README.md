# RE-012: map node115 file-backed mmap result and descriptor release

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected file path queries metadata on an already opened
descriptor. Tag three falls back to fstat64, while tag two
disposes of the error and writes result tag zero. The successful
metadata route loads the length and calls mmap64 with address
zero, protection one, flags two, the open fd and offset zero.

Return -1 writes tag zero. Success stores pointer and length
at +8/+16 with tag one. Both ordinary outcomes close the
original fd. The retained unwind path also closes it before
resuming. This scope follows the metadata-to-mapping handoff
and does not claim file content semantics.

The retained 1 full FDEs cover 881 bytes and 185 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-file-mmap-ownership-115/collect.py --out work/file-mmap-ownership-fresh
python3 -B research/work-items/RE-012-file-mmap-ownership-115/verify.py --out work/file-mmap-ownership-check-fresh.json
```
