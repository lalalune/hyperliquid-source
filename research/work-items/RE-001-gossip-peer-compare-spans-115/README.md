# RE-001: resolve node115 gossip snapshot comparison span handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The gossip peer-status report packet establishes the comparison length guard and leaves the representation conversion open. Equal length permits each input to be projected independently. The signed-minimum first word takes a distinct representation arm. For the ordinary nonempty arm, the cursor is reduced by the capacity once when it is at or above capacity, and the available first span is capacity minus that reduced cursor. A length beyond that span leaves a remainder for the second span. Pointer arithmetic uses a 24-byte element stride. Zero length uses zero span indices.

The resulting descriptor for each operand is stored in a separate 72-byte stack area before the call to 0x4e56dc0. The adapter returns the callee result directly. This identifies the exact normalized inputs without claiming what makes peer entries equal.

The retained 1 full FDEs cover 407 bytes and 110 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-peer-compare-spans-115/collect.py --out work/gossip-peer-compare-spans-fresh
python3 -B research/work-items/RE-001-gossip-peer-compare-spans-115/verify.py --out work/gossip-peer-compare-spans-check-fresh.json
```
