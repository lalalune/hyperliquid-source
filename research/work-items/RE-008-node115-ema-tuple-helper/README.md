# RE-008 · EMA tuple helper node-link maintenance

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. PR #6788 maps the caller's result fields and identifies `0x4d2ec40` as the called helper; this packet follows the helper's selected node-link maintenance.

The actual FDE at `0xf1646c` covers `[0x4d2ec40,0x4d2f8bb)` (3,195 bytes), with full body SHA-256 `cdf565ff24380bd6d5f1bcb456ba828dd2b8d0bdf2279f51b221c82ae1bad691`. At entry it reads the root node and a selected child slot, computes capacity-relative scratch ranges, and decrements the node count before selecting the next path. On selected child creation/update loops it writes each child's parent pointer at `+0x210` and child index at `+0x270`. On a selected removal path it moves the removed node's first child into the parent slot, decrements the remaining count, clears that child's parent pointer at `+0x210`, and resumes the surrounding update path.

These are observed field writes and control-flow relationships. The node type, allocator semantics, balancing invariant, and the indirect helper targets remain unresolved. The packet does not claim a complete tree algorithm.

Run `python3 research/work-items/RE-008-node115-ema-tuple-helper/verify.py`. It checks the target digest, full FDE body digest, 13 instruction witnesses, three direct edges and 13 byte-mutation controls. The captured binary is never executed.
