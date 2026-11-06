# RE-012: map node115 TLS shutdown return and classifier ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The shutdown wrapper accepts unsigned return values zero
and one directly, producing zero. Other values go through
the shared classifier. Its high-bit-plus-two result or class
six enters the local success normalization route.

That route skips cleanup for the two small sentinel forms,
drops the high-bit payload through the helper or releases
the owned error entries before returning zero. Other error
records either return the stored payload directly or enter
the boxed conversion. This is the OpenSSL shutdown adapter,
separate from the native socket shutdown wrapper.

The retained 1 full FDEs cover 335 bytes and 98 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-shutdown-result-115/collect.py --out work/tls-shutdown-result-fresh
python3 -B research/work-items/RE-012-tls-shutdown-result-115/verify.py --out work/tls-shutdown-result-check-fresh.json
```
