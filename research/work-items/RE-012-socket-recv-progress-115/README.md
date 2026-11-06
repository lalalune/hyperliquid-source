# RE-012: map node115 recv readiness and short-read cursor update

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The recv helper computes remaining capacity as capacity minus
cursor and forms the write pointer as base plus cursor. The
ready route calls recv with that span and flags zero. Readiness
tag three exits as pending and tag two propagates its payload.

A recv return of -1 packs errno. Error class 0xd alone enters
the readiness retry, with a generation check before modifying
the shared state word. Positive short reads also attempt a
generation-checked state clear. Zero and full-span reads skip
that short-read update. On success it adds the actual count to
the cursor, rejects overflow, raises the initialized watermark
only if needed and writes the new cursor. Existing prefix decode
uses this helper as context. The packet scopes the recv body,
separate from its callers and the write-side retry.

The retained 1 full FDEs cover 576 bytes and 151 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-socket-recv-progress-115/collect.py --out work/socket-recv-progress-fresh
python3 -B research/work-items/RE-012-socket-recv-progress-115/verify.py --out work/socket-recv-progress-check-fresh.json
```
