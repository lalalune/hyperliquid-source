# RE-012: map node115 elapsed-time weighted sample update

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

A subsecond word equal to 1000000000 bypasses the first
elapsed accumulation. Otherwise the wrapper obtains a
clock sample and calls the difference helper. It combines
seconds and nanoseconds with a wide multiply, saturates
the wide result on a nonzero high word, and replaces it
with zero on a tagged difference. The sum into +0x10
takes a separate overflow diagnostic.

A nonzero first qword enables the floating update. The
second difference supplies the sample divided by that
qword. The wrapper computes w = pow(0.9, divisor) and
stores sample*(1-w) + old*w at +8. The constants and
arithmetic order are retained. No timing workload ran.

The retained 1 full FDEs cover 363 bytes and 86 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-elapsed-weighted-update-115/collect.py --out work/elapsed-weighted-update-fresh
python3 -B research/work-items/RE-012-elapsed-weighted-update-115/verify.py --out work/elapsed-weighted-update-check-fresh.json
```
