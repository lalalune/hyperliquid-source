# RE-001: map node115 listener event frame and output handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener report route uses an encoder separate from the gossip snapshot sequence writer. The encoder allocates a temporary buffer and frames an outer array and a nested array. Two first-value formatting calls populate separate positions. A nonzero result branches to temporary-buffer and error cleanup before the later field is emitted.

The remaining field passes through a bound conversion and the quote/escape path. The successful route appends two closing brackets and a line feed before handing off the resulting bytes. The packet records shape and error boundaries without claiming delivery or original event schema names.

The retained 1 full FDEs cover 1026 bytes and 246 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-listener-event-frame-115/collect.py --out work/consensus-listener-event-frame-fresh
python3 -B research/work-items/RE-001-consensus-listener-event-frame-115/verify.py --out work/consensus-listener-event-frame-check-fresh.json
```
