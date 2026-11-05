# RE-001: map node115 gossip report first-value callback and separator gating

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The first-field wrapper installs this specific formatting callback. It follows three loads from the supplied capture record to obtain the value pointer and calls the first bound formatter. If that returns zero in AL, it emits character T through the writer vtable at +0x20. A nonzero result from either stage returns one without entering the second formatter.

On success the adapter tail-dispatches through the second bound slot using the original value pointer plus four and the same writer. This records the field split, character and failure ordering without inferring calendar, timezone or clock semantics.

The retained 1 full FDEs cover 81 bytes and 29 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-first-value-callback-115/collect.py --out work/gossip-report-first-value-callback-fresh
python3 -B research/work-items/RE-001-gossip-report-first-value-callback-115/verify.py --out work/gossip-report-first-value-callback-check-fresh.json
```
