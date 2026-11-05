# RE-012: map node115 no-follow file timestamp admission and fallback

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This selected file timestamp branch invokes the metadata
helper with dirfd -100 and flags 0x100. Tag three falls
back to lstat64 with the same path, and tag two uses the
existing error continuation.

Both successful metadata formats load seconds and a
nanoseconds word. An unsigned nanoseconds value below
1000000000 publishes those fields. Otherwise the code calls
the clock helper with clock id zero and publishes its pair
after the diagnostic helper returns. The lstat64 failure
path captures errno and joins the metadata error path.
The packet follows timestamp admission and leaves the
upstream scheduling decisions outside scope.

The retained 1 full FDEs cover 922 bytes and 222 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-file-lstat-projection-115/collect.py --out work/file-lstat-projection-fresh
python3 -B research/work-items/RE-012-file-lstat-projection-115/verify.py --out work/file-lstat-projection-check-fresh.json
```
