# RE-012: map node115 execvp environment swap and failure restore

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

After child setup and callbacks, this route tests whether
an environment record was supplied. If present, it saves the
current environ pointer and installs the record's +8 pointer
before execvp. The filename and argv come from command
offsets +0x80 and +8.

If execvp returns, the code captures errno before restoring
the saved environment pointer. It then closes standard
descriptor sources selected by unsigned record tags at or
above two and returns the packed errno. A null environment
record skips both the swap and restore. The result concerns
the final exec handoff, following the previously mapped
pre-exec option and descriptor paths.

The retained 1 full FDEs cover 1037 bytes and 274 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 4 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-child-exec-environment-restore-115/collect.py --out work/child-exec-environment-restore-fresh
python3 -B research/work-items/RE-012-child-exec-environment-restore-115/verify.py --out work/child-exec-environment-restore-check-fresh.json
```
