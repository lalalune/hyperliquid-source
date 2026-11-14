# RE-008 · `+0x4e0` reader update helper

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. PR #6790 maps the caller at `0x4d30c80`; this packet follows its helper `0x4d256e0` and records selected path reconstruction and output writes.

The actual FDE at `0xf16098` covers `[0x4d256e0,0x4d25fd8)` (2,296 bytes), with full body SHA-256 `f872fc8a63299d0e5d3f450cb54d40ceb07e876151aa155c10d6c6bc9ae0277e`. The helper reads the root object and 16-bit count at `+0x4da`, identifies a selected slot at `+0x08`, preserves record fields rooted at `+0x60` and `+0xc0`, and decrements the count before descending. It has separate empty, capacity, and descendant paths; a selected descendant path builds a stack descriptor and calls an internal recursive helper.

The common return path copies the assembled record into the caller's output through `+0x80`, including the scalar at `+0x00`, vector blocks, and qwords at `+0x68`, `+0x70`, `+0x78`, and `+0x80`. These are static field observations. The structure's source-level type, allocator semantics, and recursive helper behavior remain unresolved.

Run `python3 research/work-items/RE-008-node115-ema-reader-helper/verify.py`. It checks the target digest, full FDE body digest, 18 instruction witnesses, four direct edges and 18 byte-mutation controls. The captured binary is never executed.
