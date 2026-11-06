# RE-001: resolve node115 startup shell output adapter

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The startup line-count path delegates through slot 0x64e0960 to this adapter. The adapter constructs a command with /bin/sh, adds -c, and adds the supplied command buffer as a separate pointer/length argument. The launch output uses a high-bit sentinel for the initial error. After successful handoff, a nonzero status word follows a formatted error path. The zero-status arm invokes the conversion helper, which has a separate tag-one error arm.

Successful output is copied to an independent allocation with capacity and length both equal to the extracted byte count. A zero-length result instead stores a pointer value of one and zero lengths. The three ordinary return classes release the selected temporary buffers according to their capacity words. This resolves the caller-facing ownership contract, while command escaping and all live subprocess effects remain opaque.

The retained 1 full FDEs cover 737 bytes and 165 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 6 instruction/data windows, 5 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-001-startup-shell-output-115/collect.py --out work/startup-shell-output-fresh
python3 -B research/work-items/RE-001-startup-shell-output-115/verify.py --out work/startup-shell-output-check-fresh.json
```
