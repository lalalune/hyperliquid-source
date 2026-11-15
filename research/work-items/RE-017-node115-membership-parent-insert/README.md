# Node #115: promoted membership key into nonfull parent

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the selected promoted-key parent arm after the full leaf split in #6763.

When the selected parent has N < 11 keys, `0x4c3978d..0x4c397a5` obtains index i from the old child's `+0xe4` and enters `0x4c39bb5`. Assuming `0 <= i <= N`, if i < N it shifts `20*(N-i)` bytes of parent keys right with the pinned `memmove` import, writes the 20-byte promoted key at i, and shifts `8*(N-i)` bytes of child pointers right to open slot i+1. At i=N both moves are skipped. `0x4c39c54..0x4c39c60` stores the new right child in slot i+1 and sets the parent key count to N+1.

The following loop at `0x4c39ca0..0x4c39d28` writes each affected child's parent pointer and 16-bit child index, including the inserted child and shifted children through slot N+1. This is a selected same-owner path under valid tree/index state, successful leaf split and normal memory-operation returns. It does not establish full-parent splitting, root allocation, all parent propagation or complete B-tree invariants. The parent identity and key/child terminology are inferred from the linked instructions.

Run `python3 research/work-items/RE-017-node115-membership-parent-insert/verify.py` for target digest, selected instruction anchors and mutation controls without target execution. Static windows and `memmove` relocation are in `windows.txt`; no progress gate changes.
