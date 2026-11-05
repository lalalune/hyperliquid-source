# RE-012: map node115 SSL index once-state result handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The adapter initializes a local flag and a high-bit result
marker, then builds a callback record holding pointers to
the flag, the supplied state plus eight and the result.
It calls the bound once helper with the callback descriptor.

Ordinary return copies the three result words out of the
local record. The unwind landing path drops the temporary
result before resuming. This packet isolates the caller-side
once contract. Callback publication and SSL object ownership
are separate bodies.

The retained 1 full FDEs cover 138 bytes and 32 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-ssl-index-once-result-115/collect.py --out work/ssl-index-once-result-fresh
python3 -B research/work-items/RE-012-ssl-index-once-result-115/verify.py --out work/ssl-index-once-result-check-fresh.json
```
