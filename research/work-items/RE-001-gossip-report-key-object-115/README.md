# RE-001: map node115 gossip report key object and value handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The peer sequence writer calls this serializer for its entry key side. It emits an opening brace and quote, calls the byte escape helper for the field name, and appends a closing quote and colon. It then passes the value to 0x50a2ad0. A nonzero result returns through the error arm without emitting the closing brace. The ordinary route emits that brace.

The five single-byte writes have separate capacity-equality branches that reserve one byte and rejoin the stores. This packet distinguishes the key object from the sibling value object and records the value conversion boundary.

The retained 1 full FDEs cover 365 bytes and 93 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-key-object-115/collect.py --out work/gossip-report-key-object-fresh
python3 -B research/work-items/RE-001-gossip-report-key-object-115/verify.py --out work/gossip-report-key-object-check-fresh.json
```
