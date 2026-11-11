# RE-001: map node115 consensus lookup candidate collection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The listener lookup passes its thread-local entry span to this collector when the selected direct scan does not find a match. The collector advances through source records by 56 bytes and calls a bound transformation. A zero first output word skips the candidate. The first retained result triggers allocation of 896 bytes for four 224-byte records and copies the first record into that allocation.

Subsequent accepted outputs append at a 224-byte stride, grow at capacity equality and commit the count after the copy. The no-result path returns a zero-capacity, pointer-eight, zero-length record. This resolves candidate collection without inferring how the transformation decides eligibility.

The retained 1 full FDEs cover 525 bytes and 118 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-consensus-lookup-candidate-collection-115/collect.py --out work/consensus-lookup-candidate-collection-fresh
python3 -B research/work-items/RE-001-consensus-lookup-candidate-collection-115/verify.py --out work/consensus-lookup-candidate-collection-check-fresh.json
```
