# RE-012: map node115 BIO retry error kind predicate

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The retry predicate dispatches first on the low two bits
of the error word. Two pointer forms read their own kind
byte. One immediate form extracts the high dword and
caps it. The errno form decrements the upper dword and
range-checks it before a signed-relative table lookup.

The shared return compares the selected kind with 7 and
13 and ORs the two equality results. This packet follows
the predicate used by the already mapped BIO retry flag
writers, without re-claiming those callers.

The retained 1 full FDEs cover 274 bytes and 105 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-bio-retry-kind-predicate-115/collect.py --out work/bio-retry-kind-predicate-fresh
python3 -B research/work-items/RE-012-bio-retry-kind-predicate-115/verify.py --out work/bio-retry-kind-predicate-check-fresh.json
```
