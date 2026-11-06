# RE-012: map node115 runtime stdio validation and repair

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The runtime entry constructs pollfd records for fds 0, 1 and 2
with zero events. It calls poll with count three and timeout zero.
On a result other than -1, it scans the three records and tests
revents bit 0x20. The first needed repair opens /dev/null with
flags 2 and mode 0. Later repairs try dup on the retained source,
opening /dev/null again if duplication returns -1.

A poll result of -1 retries on errno 4. For other errors the
fallback is selected only by the bounded mask 0x401800, whose
set positions are errno 11, 12 and 22. That fallback checks each
descriptor with fcntl command 1 and selects repair on return -1
and errno 9. It uses the same retained-source dup then open policy.
An open failure and an unselected poll error reach the common
terminal helper.

The packet covers process startup's own standard descriptors.
The earlier child setup packet follows requested remaps to an
already selected source, a separate call path. No capture was
executed with altered descriptors.

The retained 1 full FDEs cover 1749 bytes and 394 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 8 instruction/data windows, 0 RELATIVE addends, 5 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-runtime-stdio-repair-115/collect.py --out work/runtime-stdio-repair-fresh
python3 -B research/work-items/RE-012-runtime-stdio-repair-115/verify.py --out work/runtime-stdio-repair-check-fresh.json
```
