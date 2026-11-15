# RE-008 · EMA reader on the `+0x4e0` node table

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is a separate reader from the `+0x218` helper in PRs #6788 and #6789; no existing work item covered this FDE or its `+0x4e0` table accesses.

The actual FDE at `0xf1649c` covers `[0x4d30c80,0x4d31061)` (993 bytes), with full body SHA-256 `fbc21b2a3e4c1b659195550a0f0c84de35ef88c5b7e063aa727b812ab1f22167`. The reader preserves the caller's output pointer, follows a descriptor-selected table through node offset `+0x4e0`, and calls `0x4d256e0` with a stack descriptor. On the selected path it replaces a table entry pointer and copies a record region rooted at `+0x60` plus fields through `+0xc0` before joining the common return path.

The common path writes a larger output structure: a scalar at `+0x00`, vector blocks covering `+0x08..+0x67`, qwords at `+0x68` and `+0x70`, clears `+0x78`, and writes a final qword at `+0x80`. The empty path builds a three-qword stack descriptor and reaches the same layout. These are static field observations; tuple types, ownership, and the called helper's semantics remain unresolved.

Run `python3 research/work-items/RE-008-node115-ema-reader-4e0/verify.py`. It checks the target digest, full FDE body digest, 20 instruction witnesses, three direct edges and 20 byte-mutation controls. The captured binary is never executed.
