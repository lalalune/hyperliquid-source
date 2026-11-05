# RE-012: map node115 SSL error class description dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The description formatter takes the class dword from +0x18,
subtracts one and uses a six-entry signed-relative table
when in range. Other values use the numeric formatting
adapter with the original class value.

The class branches distinguish static descriptions from
forms with a payload. Selected branches test the high-bit
sentinel or compare against high-bit-plus-two before
choosing a string, the list formatter, or the payload
adapter. Each returns the sink result. This is description
dispatch after classification, independent of SSL I/O.

The retained 1 full FDEs cover 381 bytes and 94 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-ssl-error-description-dispatch-115/collect.py --out work/ssl-error-description-dispatch-fresh
python3 -B research/work-items/RE-012-ssl-error-description-dispatch-115/verify.py --out work/ssl-error-description-dispatch-check-fresh.json
```
