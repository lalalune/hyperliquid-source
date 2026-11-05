# RE-012: map node115 hard link path admission and syscall result

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected adapter loads a path pointer and length and retains
the other path in a closure record. Up to length 383 it copies
bytes to stack storage, appends a zero, and scans for the first
zero. Short input uses byte scanning; longer input can skip
16-byte chunks using paired word masks and then checks bytes.

Only a zero at exactly the supplied length enters the stack
arm's linkat call. The call supplies -100 for each directory
descriptor and flags zero. A return other than -1 yields zero, while
-1 returns the packed errno with low tag 2. An embedded zero
returns the static payload address 0x64c2fb8. Above the stack
threshold the adapter delegates to the longer-path helper with
callback 0x5c80680. That helper is outside the projection.

The retained 1 full FDEs cover 417 bytes and 106 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 0 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-hardlink-path-admission-115/collect.py --out work/hardlink-path-admission-fresh
python3 -B research/work-items/RE-012-hardlink-path-admission-115/verify.py --out work/hardlink-path-admission-check-fresh.json
```
