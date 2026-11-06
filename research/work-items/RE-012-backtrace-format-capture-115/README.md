# RE-012: map node115 formatted backtrace callback and failure routing

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The formatter first obtains a helper result and emits a
fixed 17-byte prefix through the sink. A prefix write error
bypasses traversal. Otherwise the routine creates callback
state referencing the formatting sink, local flags and
temporary record, then calls _Unwind_Backtrace.

The callback result flag is checked after traversal and
selects the early error arm. The other path continues to
the final formatting branch. Locally owned helper storage
is released on the visible completion and unwind routes.
This is the formatted path, separate from the owned frame
vector capture.

The retained 1 full FDEs cover 447 bytes and 108 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-backtrace-format-capture-115/collect.py --out work/backtrace-format-capture-fresh
python3 -B research/work-items/RE-012-backtrace-format-capture-115/verify.py --out work/backtrace-format-capture-check-fresh.json
```
