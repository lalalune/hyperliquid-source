# RE-012: map node115 file copy mode gate and interrupted chmod retry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The copy path calls fstat64 on the opened destination and branches
on -1. For the successful result it masks the returned mode by
0xf000. Only the 0x8000 arm reaches fchmod on that descriptor
with the saved mode word. Other types go to the continuation
at 0x5c9c299 without this chmod.

The chmod branch checks specifically for -1, reads errno and
builds (errno << 32) | 2. Errno 4 drops the temporary error
and retries with the same fd and mode. Other errors enter the
common cleanup, which closes the destination and source descriptors.
The packet isolates the mode gate and retry boundary. Copy
engines and other metadata fields remain context.

The retained 1 full FDEs cover 2052 bytes and 469 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-file-copy-mode-gate-115/collect.py --out work/file-copy-mode-gate-fresh
python3 -B research/work-items/RE-012-file-copy-mode-gate-115/verify.py --out work/file-copy-mode-gate-check-fresh.json
```
