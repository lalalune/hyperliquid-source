# RE-012: map node115 pidfd spawn selection and capability downgrade

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected branch checks the request byte, capability
byte one and optional pidfd_spawnp relocation. It initializes
the output fd to -1 before calling the optional function.
Its direct status is packed on nonzero. Status 0x26 updates
the capability byte to two and selects the fallback
continuation after dropping the error record.

The ordinary spawn branch uses posix_spawnp with the
prepared action and attribute records. Both paths retain
their direct status handling and the common reader-lock
release path. This packet follows selection and downgrade,
separate from action initialization, ancillary transfer and
child wait.

The retained 1 full FDEs cover 9849 bytes and 2000 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-pidfd-spawn-dispatch-115/collect.py --out work/pidfd-spawn-dispatch-fresh
python3 -B research/work-items/RE-012-pidfd-spawn-dispatch-115/verify.py --out work/pidfd-spawn-dispatch-check-fresh.json
```
