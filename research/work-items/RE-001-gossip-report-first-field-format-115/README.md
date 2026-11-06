# RE-001: map node115 gossip report first-field formatting and error ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report frame encoder delegates the first array value to this wrapper. The wrapper appends an opening quote, constructs the writer context and a callback descriptor, then calls the bound formatter. Zero status appends the closing quote and drops a pending temporary if present before returning zero. A nonzero formatter status instead inspects the temporary error slot. A populated slot is passed to a bound error handoff and its return value is propagated; an empty slot takes a separate diagnostic path.

Both quote writes have capacity-equality branches. The unwind path conditionally drops the temporary before resuming. This resolves the first-field writer contract independently of the report label escape helper and does not assign a business meaning to the formatted value.

The retained 1 full FDEs cover 316 bytes and 78 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-first-field-format-115/collect.py --out work/gossip-report-first-field-format-fresh
python3 -B research/work-items/RE-001-gossip-report-first-field-format-115/verify.py --out work/gossip-report-first-field-format-check-fresh.json
```
