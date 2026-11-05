# RE-001: map node115 listener period observer timing and lock entry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener accounting caller passes a descriptor to this observer. Entry requires byte +0x20 to equal one for the timed route. The helper samples the clock, invokes 0x59db700, then samples again and passes the two records to the known difference helper in second-then-first order. A nonzero difference tag selects the zero-valued observation path; the other route converts the pair to a floating-point observation using the retained scaling constant.

The timed route later reaches a shared byte compare-exchange, with separate slow or initialization branches. This packet isolates timing and lock entry. It does not infer what the timed callback does, delivery, or how the remainder of the observer uses the observation.

The retained 1 full FDEs cover 1039 bytes and 237 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-listener-period-observation-115/collect.py --out work/consensus-listener-period-observation-fresh
python3 -B research/work-items/RE-001-consensus-listener-period-observation-115/verify.py --out work/consensus-listener-period-observation-check-fresh.json
```
