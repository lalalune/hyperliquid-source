# RE-001: resolve node115 gossip report string escape table and append paths

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report frame encoder wraps this helper in quotes. The helper indexes a 256-byte table by each original byte and batches consecutive table-zero bytes into a raw copy. A nonzero table entry selects a two-byte escape consisting of a backslash and the table byte, except for the literal u tag. That tag emits a six-byte escape with a backslash-u00 prefix and two lowercase hexadecimal digits selected by the source byte nibbles.

The destination length advances by the actual copy or escape size. Capacity checks distinguish the raw span, two-byte escape and six-byte escape paths before stores. The retained table and digit bytes establish encoding choices without interpreting caller UTF-8 or surrounding quotes.

The retained 1 full FDEs cover 552 bytes and 140 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 2 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-string-escape-115/collect.py --out work/gossip-report-string-escape-fresh
python3 -B research/work-items/RE-001-gossip-report-string-escape-115/verify.py --out work/gossip-report-string-escape-check-fresh.json
```
