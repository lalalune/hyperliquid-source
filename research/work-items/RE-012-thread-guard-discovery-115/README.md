# RE-012: map node115 thread stack guard discovery

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected discovery route requires the global enable byte
and a zero low argument byte. It queries attributes of
pthread_self. A nonzero getattr status bypasses discovery
and proceeds to the alternate-stack query.

A successful getattr reads guard size and, on the nonzero
guard route, reads the stack address and destroys the
attributes before calling 0x5ca2950 with stack address minus
and plus guard size. The code checks the direct return
statuses and keeps separate diagnostic routes for them.
This packet ends before sigaltstack; it covers normal-thread
guard discovery, separate from alternate-stack allocation.

The retained 1 full FDEs cover 682 bytes and 159 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-thread-guard-discovery-115/collect.py --out work/thread-guard-discovery-fresh
python3 -B research/work-items/RE-012-thread-guard-discovery-115/verify.py --out work/thread-guard-discovery-check-fresh.json
```
