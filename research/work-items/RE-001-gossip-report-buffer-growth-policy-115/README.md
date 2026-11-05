# RE-001: map node115 report buffer reserve capacity and error publication

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report writers invoke this capacity helper on space exhaustion. It checks for zero element width and detects carry in used plus additional before computing a new capacity. The selected capacity is the maximum of the required count, doubled old capacity and a width-dependent floor. The floor is eight at width one, four for widths two through 1024, and one for larger widths.

The helper passes old capacity and pointer plus the new capacity to the checked allocator. It publishes pointer and capacity only after the returned record clears the error tag. The error arm forwards the returned error words. This extends the earlier observed reserve call sites with the actual sizing and publication rules.

The retained 1 full FDEs cover 142 bytes and 41 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-buffer-growth-policy-115/collect.py --out work/gossip-report-buffer-growth-policy-fresh
python3 -B research/work-items/RE-001-gossip-report-buffer-growth-policy-115/verify.py --out work/gossip-report-buffer-growth-policy-check-fresh.json
```
