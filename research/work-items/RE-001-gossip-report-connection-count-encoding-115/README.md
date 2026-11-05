# RE-001: resolve node115 gossip connection-count writer and numeric handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The peer-value object writer calls this helper with the connection_count label and its value pointer. After key framing and the colon, it loads the full qword value, calls 0x50fc010 with the stack scratch address, and receives a pointer and length. The returned span is appended directly without quotes. The wrapper compares its size against remaining output capacity and skips memcpy for an empty span.

Normal return commits the exact formatter length to the writer. The capacity branch reserves for that length and rejoins the copy path. The packet distinguishes this numeric field from the sibling Boolean literal path and stops at the number formatter boundary.

The retained 1 full FDEs cover 492 bytes and 131 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-connection-count-encoding-115/collect.py --out work/gossip-report-connection-count-encoding-fresh
python3 -B research/work-items/RE-001-gossip-report-connection-count-encoding-115/verify.py --out work/gossip-report-connection-count-encoding-check-fresh.json
```
