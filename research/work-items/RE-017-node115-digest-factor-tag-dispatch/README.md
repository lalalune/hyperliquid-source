# Node #115: selected dispatcher tag leading to digest-factor inputs

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This binds a selected tag in dispatcher `0x538cd30` to the previously scoped factor parsing and write in #6751 and #6749, rather than claiming the complete dispatcher.

At entry the dispatcher saves input pointer `rsi` in `r15`, the owner pointer `rdx` in `r13`, and loads the first input qword as a dispatch value. For an input value of decimal 113, the `sub 0x14` and unsigned `cmovae` select table index 93. The signed relative dword at `0x9225e0` (table base `0x92246c` plus `4*93`) points to `0x538d228`. This is a static dispatch case; it does not identify the source or validity of the input tag.

At that case the code saves the owner, reads the first descriptor at input `+8..+0x1f`, reads the second at `+0x20..+0x37`, and saves the byte at `+0x38` for the later selector. The two descriptor-dependent paths and success guards lead, on the selected normal path, to the normalized inputs and call to `0x54cf1b0`; the saved owner is restored to `rdi` for that call. **If the saved selector is 3**, the separate #6749 path writes the first normalized input to the digest-producer factor.

This packet establishes neither an external action name nor that tag 113 or selector 3 is admitted or reachable from live traffic. Input origin, ownership, full dispatcher and canonical state effects remain open. No gate changes.

Run `python3 research/work-items/RE-017-node115-digest-factor-tag-dispatch/verify.py` for target digest, table entry, selected instruction anchors, direct-call and mutation controls without target execution. `windows.txt` contains selected disassembly.
