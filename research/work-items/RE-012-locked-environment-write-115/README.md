# RE-012: map node115 setenv writer lock and result handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The fast path acquires the environment writer state with
CAS from zero to 0x3fffffff. A failed CAS calls the writer
slow path while preserving both arguments. Under the lock,
setenv receives the dereferenced name pointer, value and
overwrite one. Only return -1 reads and packs errno;
other returns publish zero.

Release atomically adds 0xc0000001 to the state and tests
the post-update word against unsigned 0x40000000. The
selected wake path preserves the result across the helper.
The retained auxiliary status checks are outside this
projection. This packet follows the mutation boundary,
separate from the getenv owned-copy path.

The retained 1 full FDEs cover 298 bytes and 79 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 2 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-locked-environment-write-115/collect.py --out work/locked-environment-write-fresh
python3 -B research/work-items/RE-012-locked-environment-write-115/verify.py --out work/locked-environment-write-check-fresh.json
```
