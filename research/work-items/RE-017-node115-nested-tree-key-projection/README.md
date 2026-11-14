# Node #115 tracker: tree-variant 20-byte key projection

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static evidence; this extends the separately documented flat iterator used by `0x5b7b900`.

For a non-flat iterator variant, `0x5b7b95c..0x5b7b977` calls `0x513b200`; on non-null return it copies 16 bytes and a four-byte tail from the returned pointer. The iterator checks the remaining count at descriptor +0x40, decrements it on nonempty input, and for tag 1 with a null current node follows height h child-zero pointers at node +0x400 (`0x513b247..0x513b2dc`). With valid pointers, a consistent height and a nonempty resulting leaf, it selects slot zero.

At `0x513b3c1..0x513b3e4`, for selected node p and slot i, the returned pointer is `p+0x320+20*i`; a second returned pointer is `p+0x08+72*i`. The iterator stores its next state before returning. Therefore this caller's 20-byte projection on the tree variant comes from the first of those two arrays, not the 72-byte per-slot area. This conclusion assumes the selected normal path and does not claim full traversal, ownership, protocol meaning, runtime values or equivalence.

`0x513b200` was mentioned as an input boundary in open PR #6459; this packet supplies the selected initial descent and slot projection on the distinct tracker-builder call. Run `python3 research/work-items/RE-017-node115-nested-tree-key-projection/verify.py` to authenticate the target and validate instruction/call anchors and mutations without execution. Disassembly is in `windows.txt`.
