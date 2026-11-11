# RE-012: map node115 diagnostic thread ID source and formatter handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The diagnostic path tests whether the gettid relocation
is populated. It calls that import when available, or
syscall 0xba otherwise, and sign-extends the returned
dword to the local thread-ID word.

It zeroes a 512-byte stack buffer and passes a formatter
record containing a pointer to that ID. The formatter
result selects the buffer path or an alternate callback
using the saved argument record. The selected callback
error is disposed of on the visible branch. This scope
covers diagnostic argument provenance without running a
thread or reading host process state.

The retained 1 full FDEs cover 684 bytes and 155 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-diagnostic-tid-fallback-115/collect.py --out work/diagnostic-tid-fallback-fresh
python3 -B research/work-items/RE-012-diagnostic-tid-fallback-115/verify.py --out work/diagnostic-tid-fallback-check-fresh.json
```
