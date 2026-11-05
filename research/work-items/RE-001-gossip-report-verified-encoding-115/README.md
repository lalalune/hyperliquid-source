# RE-001: resolve node115 gossip verified-field encoding

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The previously mapped peer-value wrapper calls this helper with the verified key. The helper rejects writer state byte zero-offset equal to one before appending anything. The second state byte determines whether to emit a comma, and is set to two before writing the quoted escaped key and colon.

The payload is selected by bit zero of the input byte. The set arm emits true and commits four bytes; the clear arm emits false and commits five. Both arms separately reserve capacity when the spare length is too small. This closes the output representation without attributing any upstream peer authentication meaning to the byte.

The retained 1 full FDEs cover 535 bytes and 137 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-gossip-report-verified-encoding-115/collect.py --out work/gossip-report-verified-encoding-fresh
python3 -B research/work-items/RE-001-gossip-report-verified-encoding-115/verify.py --out work/gossip-report-verified-encoding-check-fresh.json
```
