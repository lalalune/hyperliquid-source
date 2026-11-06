# RE-001: map node115 gossip peer-sequence serialization and separator placement

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The report frame wrapper hands a normalized peer snapshot descriptor to this sequence writer. It opens a sequence, reads entries from either the span cursor or an iterator helper, and writes each selected entry as a nested pair. The key helper is called before the value helper, with a comma between the two. Nonzero helper results branch out before the ordinary closing bracket.

The span route advances by 24 bytes and can replace exhausted first-span bounds with the second-span bounds. Later entries receive a leading comma, whereas the first entry does not. Ordinary exhaustion closes the outer sequence. This captures structural framing and traversal dispatch while leaving key and value encoding as separate helper contracts.

The retained 1 full FDEs cover 1276 bytes and 309 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-peer-sequence-115/collect.py --out work/gossip-report-peer-sequence-fresh
python3 -B research/work-items/RE-001-gossip-report-peer-sequence-115/verify.py --out work/gossip-report-peer-sequence-check-fresh.json
```
