# RE-001: map node115 gossip report peer value fields and writer status

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The peer sequence writer calls this separate value-object serializer. It starts with an opening brace and a two-byte local writer state, and passes the eight-byte literal verified with value pointer +8 to the first helper. A nonzero helper result exits. A zero result with writer byte equal to one dispatches to a separate bound error constructor. Otherwise it passes the sixteen-byte literal connection_count and the base value pointer to the second helper.

After that helper returns zero, the local writer state gates appending the closing brace. The opening and closing stores both have capacity branches. The literal identities are retained in the packet, while field types and meaning outside this writer are left open.

The retained 1 full FDEs cover 281 bytes and 74 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-peer-value-fields-115/collect.py --out work/gossip-report-peer-value-fields-fresh
python3 -B research/work-items/RE-001-gossip-report-peer-value-fields-115/verify.py --out work/gossip-report-peer-value-fields-check-fresh.json
```
