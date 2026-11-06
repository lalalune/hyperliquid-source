# RE-012: map node115 OpenSSL numeric display base selection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The 32-bit and 64-bit formatters test flags 0x2000000 and
0x4000000 before the default decimal arm. Decimal uses
paired digits and writes groups backwards into the stack
buffer. The final residual handling emits a single digit
when needed, including zero input.

The alternate arms shift by four and use separate digit
tables, then pass the computed span and prefix descriptor
to the shared formatter. This packet covers the integer
field formatter, separate from selection of error text.

The retained 2 full FDEs cover 824 bytes and 212 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 9 instruction/data windows, 1 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-openssl-numeric-format-115/collect.py --out work/openssl-numeric-format-fresh
python3 -B research/work-items/RE-012-openssl-numeric-format-115/verify.py --out work/openssl-numeric-format-check-fresh.json
```
