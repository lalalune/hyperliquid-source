# RE-012: map node115 clock timespec admission and diagnostics

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The clock wrapper forwards the caller clock ID and a stack
timespec pointer. Return -1 selects the errno diagnostic.
Otherwise it tests the nanoseconds qword as unsigned against
1000000000, so negative encodings also select the invalid
timespec diagnostic. The accepted arm returns seconds in
RAX and the nanoseconds word in RDX.

The two diagnostic routes use distinct descriptors. Only the
syscall-failure route packs the current errno with low tag two.
Both converge on ud2 if the diagnostic unexpectedly returns.
The complete FDE retains the separate unwind cleanup edges.
Existing timed-wait packets use this helper as context. This
scope isolates its output admission and exceptional behavior.

The retained 1 full FDEs cover 201 bytes and 48 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 4 instruction/data windows, 0 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-clock-timespec-admission-115/collect.py --out work/clock-timespec-admission-fresh
python3 -B research/work-items/RE-012-clock-timespec-admission-115/verify.py --out work/clock-timespec-admission-check-fresh.json
```
