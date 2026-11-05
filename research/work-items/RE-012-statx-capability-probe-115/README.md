# RE-012: map node115 statx capability probe and result dispatch

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This adapter reads capability byte 0x6500088. Value two
returns tag three immediately. Otherwise it zeroes 256 bytes
and calls the statx import when present, or syscall 0x14c,
with the supplied dirfd, path and flags and mask 0xfff.
Success publishes tag one and the projected metadata. If
the initial byte was zero it first stores capability one.

Failure saves the original packed errno. If the capability
byte is already one, it returns that original error under
tag two. Otherwise it probes through the same import-or-syscall
split with null path and output, zero dirfd and flags and mask
0xfff. Probe failure with errno 14 stores capability one and
returns the original error. All other probe outcomes store
capability two and return tag three. The packet isolates probe
dispatch from metadata field interpretation and kernel behavior.

The retained 1 full FDEs cover 791 bytes and 173 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-statx-capability-probe-115/collect.py --out work/statx-capability-probe-fresh
python3 -B research/work-items/RE-012-statx-capability-probe-115/verify.py --out work/statx-capability-probe-check-fresh.json
```
