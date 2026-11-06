# RE-001: map node115 report packed date extraction and writer failures

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report first-value callback dispatches to this formatter before its T separator. The formatter obtains a signed year-like value by arithmetic right shift by thirteen, and a separate ten-bit table index by shifting right three. It rejects an index at or above 733 before reading the table. The year-like value uses an unsigned comparison with 10000 to select the four-digit direct path or the alternate formatter.

After successful year output the remaining field projection uses the table byte and index, with two literal dashes. Each writer callback can return failure before later output. The packet records the packed input and write ordering, without treating arbitrary packed words as valid calendar dates.

The retained 1 full FDEs cover 527 bytes and 158 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-packed-date-115/collect.py --out work/gossip-report-packed-date-fresh
python3 -B research/work-items/RE-001-gossip-report-packed-date-115/verify.py --out work/gossip-report-packed-date-check-fresh.json
```
