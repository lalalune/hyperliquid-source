# RE-001: map node115 gossip report state replacement and drain gate

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The child-peer status poll previously mapped only the report call boundary. This body obtains a temporary record through a bound helper, then tests the destination field at +0x48 for the signed-minimum sentinel. The sentinel route skips the state update and releases a temporary allocation when its size is neither zero nor signed minimum. For a non-sentinel destination and a non-sentinel temporary, the wrapper constructs a replacement and calls the old-record cleanup before publishing the replacement at +0x48. The unwind landing path also stores the replacement before resuming.

The update path calls 0x50e7c90 and stores the input key at +0x9c and +0xa4. Further draining is conditional on the destination byte at +0xaa, a bound global byte, and the updated record no longer being the sentinel. These are report-state ownership and dispatch conditions. The packet does not infer delivery, field types or the effect of the opaque helpers.

The retained 1 full FDEs cover 521 bytes and 121 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 4 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-peer-report-replacement-115/collect.py --out work/gossip-peer-report-replacement-fresh
python3 -B research/work-items/RE-001-gossip-peer-report-replacement-115/verify.py --out work/gossip-peer-report-replacement-check-fresh.json
```
