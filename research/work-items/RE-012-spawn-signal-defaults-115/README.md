# RE-012: map node115 posix_spawn signal-default option dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected spawn attribute path checks global byte 0x64ffffc.
The zero route creates an empty signal set and adds signal
13. A return of -1 from either libc set helper takes the
errno path. The subsequent setsigdefault call instead
consumes its direct status, branching on nonzero.

Success ORs mask 0x4 into the accumulated flags before the
setflags call. The nonzero global-byte route skips the
signal-set construction. The retained local branches show
how direct status and errno converge on the already mapped
object cleanup. The scope is signal defaults and flag
selection, following the file-action initialization.

The retained 1 full FDEs cover 9849 bytes and 2000 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-spawn-signal-defaults-115/collect.py --out work/spawn-signal-defaults-fresh
python3 -B research/work-items/RE-012-spawn-signal-defaults-115/verify.py --out work/spawn-signal-defaults-check-fresh.json
```
