# RE-001: map node115 report time fraction precision and overflow-second route

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report callback tail-dispatches here after T. The helper reads two adjacent dwords. At a second-word threshold of one billion, it increments the seconds component and subtracts one billion from the fraction. The visible components emit digit pairs and colon bytes via the writer callback, with nonzero callback returns short-circuiting later output.

A zero fraction skips fractional formatting. For a nonzero fraction the multiply/rotate tests select a three-digit fraction when divisible by one million, six when divisible by one thousand, and nine otherwise. The selected retained templates supply the leading dot and width. The result applies to valid internal time fields and does not infer timezone behavior.

The retained 1 full FDEs cover 566 bytes and 158 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-time-fraction-115/collect.py --out work/gossip-report-time-fraction-fresh
python3 -B research/work-items/RE-001-gossip-report-time-fraction-115/verify.py --out work/gossip-report-time-fraction-check-fresh.json
```
