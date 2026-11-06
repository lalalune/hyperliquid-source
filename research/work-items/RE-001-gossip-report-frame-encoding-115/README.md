# RE-001: map node115 gossip report array framing and output handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The prior gossip report-state packet ends at the report update call. This callee allocates an initial 128-byte buffer and writes an opening bracket. It delegates the first value, adds a comma and opens a nested array, then places quotes around the text passed to a separate helper. After a further comma, it projects the peer snapshot descriptor and hands it to its serializer. A nonzero error from either serialization stage takes a cleanup path before any output handoff.

Successful serialization appends two closing brackets and a line feed before handing off the buffer with the caller key. Error cleanup releases the temporary buffer, dispatches on the returned error representation and releases the 40-byte error box. The packet binds framing and ownership without inferring the opaque serializers or claiming delivery.

The retained 1 full FDEs cover 1168 bytes and 284 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-frame-encoding-115/collect.py --out work/gossip-report-frame-encoding-fresh
python3 -B research/work-items/RE-001-gossip-report-frame-encoding-115/verify.py --out work/gossip-report-frame-encoding-check-fresh.json
```
