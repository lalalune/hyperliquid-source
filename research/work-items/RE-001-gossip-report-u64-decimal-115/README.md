# RE-001: map node115 gossip report unsigned decimal chunking

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The connection-count writer delegates to this unsigned formatter. It works backward in a 20-byte scratch region. Values at or above 10000 take the reciprocal-multiply path, subtract quotient times 10000 and write each four-digit remainder as two table pairs. The most significant group uses shorter paths selected at 100 and 10, so the returned suffix has no leading zeros. A zero value takes the one-digit route.

The ordinary return adds the final index to the input buffer pointer and returns length 20 minus that index. The result is a pointer and length consumed by the report writer. The packet preserves the reciprocal constant, table and boundary branch bytes without asserting caller value semantics.

The retained 1 full FDEs cover 322 bytes and 81 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-u64-decimal-115/collect.py --out work/gossip-report-u64-decimal-fresh
python3 -B research/work-items/RE-001-gossip-report-u64-decimal-115/verify.py --out work/gossip-report-u64-decimal-check-fresh.json
```
