# RE-012: map node115 OpenSSL error queue collection and vector ownership

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The collector initializes a vector with capacity zero, pointer
eight and length zero. It calls the bound error-entry helper
into a temporary record. The high-bit-plus-two marker ends
collection. Otherwise capacity equality calls the growth
helper and the entry is copied with a 72-byte stride.

The wrapper publishes capacity, pointer and length. The
unwind paths drop the temporary entry when locally owned
and release the accumulated vector before resuming.
This scope covers queue accumulation and cleanup, separate
from the error entry field projection.

The retained 1 full FDEs cover 261 bytes and 67 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-openssl-error-queue-collection-115/collect.py --out work/openssl-error-queue-collection-fresh
python3 -B research/work-items/RE-012-openssl-error-queue-collection-115/verify.py --out work/openssl-error-queue-collection-check-fresh.json
```
