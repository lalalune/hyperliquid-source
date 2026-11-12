# Node #115 tracker tree split: multi-level count walk

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This extends the separate zero-height count result to valid multi-level trees; static evidence only.

`0x4de5642` passes original total N and old/new tree headers to `0x4ca3b70`. It compares their heights at `0x4ca3b73..0x4ca3b7e`: if old height is smaller it counts the old tree; on equal or greater old height it counts the new tree. In either branch it initializes the accumulator from the root's 16-bit entry count, descends child pointers at `node + 0x380 + 8*slot`, adds the child count at +0x37a, and traverses successive child slots using each child's parent pointer and +0x378 parent-slot index. The loops are `0x4ca3ba0..0x4ca3c09` for old and `0x4ca3c20..0x4ca3c85` for new.

Assuming a finite, well-formed tree whose child and parent/index links are consistent and whose stated height matches its leaves, this traversal counts every node's entries once. If the old side is counted as S the helper returns `(S, N-S)`; if the new side is counted as S it returns `(N-S, S)` (`0x4ca3c87..0x4ca3c94`). The caller stores the first value as the original count and preserves the second for the new descriptor. Underflow is unchecked; malformed pointers, overflow, concurrency and runtime reachability are outside scope.

Run `python3 research/work-items/RE-017-node115-tracker-tree-count-walk/verify.py` to authenticate the target and check instruction/call anchors and mutations without executing the target. Disassembly is in `windows.txt`.
