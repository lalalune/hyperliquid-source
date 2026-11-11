# RE-001: map node115 consensus candidate two-key control probe

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The candidate collector uses this transformation. Its selected initial probe takes the upper seven bits of the returned hash and broadcasts them to compare against sixteen control bytes. It extracts matching lanes with a bitmask and selects candidate indices under the table mask. The record address calculation uses a stride of 112 bytes.

The control match is followed by independent metadata, span-length and byte comparisons for two key spans. Failure clears the current candidate bit and examines the next. An all-ones control byte in the current group terminates the selected miss route after candidate exhaustion. This resolves the entry matching rather than interpreting the resulting object or caller admission.

The retained 1 full FDEs cover 2818 bytes and 559 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-candidate-control-probe-115/collect.py --out work/consensus-candidate-control-probe-fresh
python3 -B research/work-items/RE-001-consensus-candidate-control-probe-115/verify.py --out work/consensus-candidate-control-probe-check-fresh.json
```
