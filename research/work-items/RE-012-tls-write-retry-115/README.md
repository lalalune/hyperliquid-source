# RE-012: map node115 TLS write result and classified retry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This write wrapper zeroes the byte count before SSL_write_ex.
A positive result returns tag zero and that count. Nonpositive
results go through the classifier. Its high-bit-plus-two form
also returns tag zero with the supplied payload.

For the eligible class-two arm, high-bit-plus-one retries
with the same buffer and length. Other forms run the visible
error-record cleanup before retrying. Remaining errors return
tag one, using the existing payload for the high-bit form or
the boxed conversion for other forms. This packet covers write
retry and result ownership at the local adapter boundary.

The retained 1 full FDEs cover 477 bytes and 127 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-tls-write-retry-115/collect.py --out work/tls-write-retry-fresh
python3 -B research/work-items/RE-012-tls-write-retry-115/verify.py --out work/tls-write-retry-check-fresh.json
```
