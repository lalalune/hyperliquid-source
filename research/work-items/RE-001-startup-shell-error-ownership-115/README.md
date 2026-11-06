# RE-001: map node115 startup output error formatting and owned cleanup

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The shell-output adapter passes an initial process error to this formatter. The formatter binds the output error literal, original command record, original error word, and separate formatting callbacks. It retains the resulting formatted error while dropping the original temporary. An unwind landing path drops that same temporary before resuming.

The drop helper admits only low-two-bit tag one, reconstructs the box base by subtracting one, and loads the payload and descriptor from the box. It conditionally invokes the descriptor destructor, conditionally frees the payload using descriptor size and alignment, and then releases the 24-byte box. A throwing destructor reaches a distinct cleanup path that frees both remaining allocations before resuming. This packet closes the ownership handoff on the initial process error arm; it does not claim the source type or OS error category. The second-structure readers packet hash-pins the shared drop helper as an opaque boundary. This packet traces its tag and cleanup behavior in the startup output error path.

The retained 2 full FDEs cover 324 bytes and 93 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 2 RELATIVE addends, 0 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-shell-error-ownership-115/collect.py --out work/startup-shell-error-ownership-fresh
python3 -B research/work-items/RE-001-startup-shell-error-ownership-115/verify.py --out work/startup-shell-error-ownership-check-fresh.json
```
