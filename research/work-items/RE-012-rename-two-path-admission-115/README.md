# RE-012: map node115 two-path rename admission and errno result

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The wrapper handles source and destination in order, using
distinct stack buffers for spans up to 383 bytes. Each path
is copied, terminated with a zero and scanned. The accepted
index must equal that path's original length. An interior
zero in either path selects the shared static error payload.

Long source and long destination have different callbacks
(0x5c81470 and 0x5c80650) through 0x5c78ed0. When both
paths fit and pass admission, the wrapper invokes rename
with the two stack pointers. -1 reads errno and returns
(errno << 32) | 2. Other returns produce zero. The scope
excludes helper internals and any live rename.

The retained 1 full FDEs cover 749 bytes and 181 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-rename-two-path-admission-115/collect.py --out work/rename-two-path-admission-fresh
python3 -B research/work-items/RE-012-rename-two-path-admission-115/verify.py --out work/rename-two-path-admission-check-fresh.json
```
