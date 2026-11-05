# RE-012: map node115 recursive mkdir existing-directory acceptance

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This selected recursive-create branch packs mkdir errno
on -1, then classifies the encoded error. Only class 12
takes a follow-up metadata query on the candidate path.

A non-error metadata result checks (mode & 0xf000) against
0x4000. The directory arm drops the saved mkdir error and
rejoins the success continuation. Another file type leaves
the saved error in the failure path. A metadata tag-two
route has separate temporary error cleanup. This scope
isolates existing-directory acceptance, complementing the
existing caller evidence for invoking recursive mkdir.

The retained 1 full FDEs cover 3615 bytes and 770 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-mkdir-existing-directory-115/collect.py --out work/mkdir-existing-directory-fresh
python3 -B research/work-items/RE-012-mkdir-existing-directory-115/verify.py --out work/mkdir-existing-directory-check-fresh.json
```
