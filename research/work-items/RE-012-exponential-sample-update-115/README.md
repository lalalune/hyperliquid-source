# RE-012: map node115 exponential sample update and factor admission

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected update computes a floating quotient by the
scale at +0x10. It takes the quotient bits, derives their
absolute magnitude and exponent bucket, and toggles the
sign bit before exp. Subsequent branches select the factor
using the saved magnitude and sign and check it against one.

On the admitted path the wrapper stores the selected stamp
and applies the factor to the prior two values. The second
store adds the saved sample to the scaled second value.
The first store is the result from the bound helper using
the selected floating arguments. This scope follows the
exponential update, separate from upstream stamp selection.

The retained 1 full FDEs cover 846 bytes and 203 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-exponential-sample-update-115/collect.py --out work/exponential-sample-update-fresh
python3 -B research/work-items/RE-012-exponential-sample-update-115/verify.py --out work/exponential-sample-update-check-fresh.json
```
