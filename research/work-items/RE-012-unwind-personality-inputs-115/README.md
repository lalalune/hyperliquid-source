# RE-012: map node115 unwind personality input and IP normalization

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The personality entry returns code three for a version
other than one. For version one it obtains language-specific
data and calls _Unwind_GetIPInfo with a zero-initialized
flag. The instruction pair subtracts one from IP only
when the unsigned flag is below one.

It obtains the region start separately. A null language
data pointer takes the selected no-table path. Nonnull
data reads the first encoding byte and treats 0xff as a
separate branch before the encoding table. This packet
isolates argument preparation before the table parser.

The retained 1 full FDEs cover 1439 bytes and 410 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-unwind-personality-inputs-115/collect.py --out work/unwind-personality-inputs-fresh
python3 -B research/work-items/RE-012-unwind-personality-inputs-115/verify.py --out work/unwind-personality-inputs-check-fresh.json
```
