# RE-012: map node115 backtrace symbol lookup address selection

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The callback skips the selected path if a control byte is
zero and the count exceeds 100. It otherwise chooses the
address directly from the frame or queries _Unwind_GetIP,
depending on the frame discriminator.

The primary lookup uses address minus one for nonzero
address and preserves zero. The secondary helper uses
the unadjusted IP and is entered only when the first
callback flag stays clear and the fallback enable byte
is set. This packet follows lookup selection, separate
from frame collection or text rendering.

The retained 1 full FDEs cover 332 bytes and 85 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-backtrace-symbol-ip-selection-115/collect.py --out work/backtrace-symbol-ip-selection-fresh
python3 -B research/work-items/RE-012-backtrace-symbol-ip-selection-115/verify.py --out work/backtrace-symbol-ip-selection-check-fresh.json
```
