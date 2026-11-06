# RE-012: map node115 environment name admission before writer handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

This adapter retains the value and environment-write context
while converting the name. Names up to 383 bytes are
copied into stack storage with an appended terminator.
The scalar and word-scan branches locate the first zero.

The stack arm calls the writer only when the zero index
equals the original length. An interior zero returns
the static error payload. Larger names use the long-path
adapter with the same writer as callback. This packet
covers name admission before the separately mapped setenv
lock and result path.

The retained 1 full FDEs cover 377 bytes and 93 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 3 instruction/data windows, 0 RELATIVE addends, 1 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-environment-name-stack-admission-115/collect.py --out work/environment-name-stack-admission-fresh
python3 -B research/work-items/RE-012-environment-name-stack-admission-115/verify.py --out work/environment-name-stack-admission-check-fresh.json
```
