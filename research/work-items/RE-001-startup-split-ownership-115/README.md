# RE-001: map node115 startup split tail and owned token collection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The previously mapped separator search returns offsets rather than owned tokens. The collector converts each match into a span from the prior end to the new match start and moves its saved end past the separator. On exhaustion it marks the iterator finished and emits the final span if nonempty or if the tail flag requests it. An already finished iterator returns an empty vector with sentinel pointer eight.

The first retained token creates a four-entry vector. A nonempty span gets an exact-length copy; an empty span has zero length and sentinel pointer one. Later tokens append three words at stride 24 and grow the vector on capacity equality. The emitted count is published only after storing the record. This extends the build-selection packet from its observed one-byte separator to the selected tail and owned-result behavior.

The retained 1 full FDEs cover 869 bytes and 207 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-split-ownership-115/collect.py --out work/startup-split-ownership-fresh
python3 -B research/work-items/RE-001-startup-split-ownership-115/verify.py --out work/startup-split-ownership-check-fresh.json
```
