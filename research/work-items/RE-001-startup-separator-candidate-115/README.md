# RE-001: map node115 startup separator search cursor and validation

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The startup build-selection packet identifies the single-space split caller. This packet resolves the search adapter, including why a hit on a candidate byte does not establish a short-pattern match. The entry checks the search endpoint lies between the current cursor and total length. The short-pattern arm searches using the final pattern byte, with scalar searches and an aligned two-word bulk candidate filter. After a hit it advances the saved cursor past the candidate, subtracts pattern length to obtain the proposed start, checks bounds, and calls bcmp on the complete short pattern. A mismatch continues searching from the updated cursor.

An accepted short match returns a tag and the half-open start/end offsets. Exhaustion moves the cursor to the search endpoint and returns the empty tag. The longer-pattern arm has a separate helper dispatch for search windows above 15 bytes. This packet records that boundary without inferring the downstream long-pattern verifier.

The retained 1 full FDEs cover 754 bytes and 202 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-separator-candidate-115/collect.py --out work/startup-separator-candidate-fresh
python3 -B research/work-items/RE-001-startup-separator-candidate-115/verify.py --out work/startup-separator-candidate-check-fresh.json
```
