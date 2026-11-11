# RE-012: map node115 artifact watcher relative sleep and remaining-time retry

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The artifact watcher packet already follows query, parse and
watermark publication up to the delay boundary. This follow-up
uses the same FDE and isolates the delay itself. At 0x4e4d2e0 the
watcher supplies the binary64 constant 5.0 to the bound duration
conversion helper. A zero seconds and zero subsecond result
skips the sleep call.

The selected loop chunks unsigned seconds at INT64_MAX and
subtracts the chosen chunk before the call. The two qwords at
stack +0x160/+0x168 form the request. clock_nanosleep receives
clock id 1, flags zero, and that same address for request and
remainder. Return zero checks the remaining chunk state.
Return 4 adds back the remainder seconds from the first qword
and reloads the second qword before re-evaluating the loop.
Other nonzero returns take the diagnostic path using the returned
code. The scope excludes duration converter internals and measured
wall-clock behavior.

The retained 1 full FDEs cover 2795 bytes and 567 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 1 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-artifact-watcher-sleep-115/collect.py --out work/artifact-watcher-sleep-fresh
python3 -B research/work-items/RE-012-artifact-watcher-sleep-115/verify.py --out work/artifact-watcher-sleep-check-fresh.json
```
