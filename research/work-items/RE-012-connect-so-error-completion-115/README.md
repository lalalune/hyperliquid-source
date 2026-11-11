# RE-012: map node115 connect completion through SO_ERROR

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The selected completion path takes the readiness helper's tag
three directly to result three. Tag two takes the helper's error
payload to cleanup. The remaining path fetches the live fd at
owner +0x18 and calls getsockopt with level 1 and option 4.
Its value dword starts at zero and its length dword starts at four.

A syscall return of -1 sources the error from errno. Otherwise a
nonzero value dword supplies the error. Both pack the selected
value with low tag 2, then enter the cleanup that checks fd -1
before close and emits result tag 2. Value zero copies the saved
owner fields into the output. The completion route stores state
byte 1 at owner +0x2c. This packet covers the readiness-to-SO_ERROR
handoff and not the network handshake itself.

The retained 1 full FDEs cover 547 bytes and 140 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 5 instruction/data windows, 1 RELATIVE addends, 3 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-connect-so-error-completion-115/collect.py --out work/connect-so-error-completion-fresh
python3 -B research/work-items/RE-012-connect-so-error-completion-115/verify.py --out work/connect-so-error-completion-check-fresh.json
```
