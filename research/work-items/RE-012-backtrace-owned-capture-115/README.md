# RE-012: map node115 backtrace capture buffer ownership and release

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The capture wrapper acquires the shared state before
preparing a temporary vector and callback argument record.
It passes the callback at 0x5ca53b0 to _Unwind_Backtrace.
The count at the temporary vector controls the result arm.

Zero count writes tag zero and releases any allocated
56-byte-stride storage. Nonzero count writes tag two,
copies capacity, pointer and count, and stores the selected
callback marker. The ordinary paths converge on the shared
state release. This packet covers capture ownership and
does not reconstruct stack traversal itself.

The retained 1 full FDEs cover 431 bytes and 104 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-backtrace-owned-capture-115/collect.py --out work/backtrace-owned-capture-fresh
python3 -B research/work-items/RE-012-backtrace-owned-capture-115/verify.py --out work/backtrace-owned-capture-check-fresh.json
```
