# Node #115 tracker: leaf-only tree split count partition

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This is a static bounded result following the separately traced tree leaf split.

For the sentinel representation with nonzero root and count, `0x4de561c..0x4de5642` calls the split helper and then `0x4ca3b70` with original total count N and pointers to old and new tree headers. `0x4ca3b70` compares their height fields. When both heights are zero and the new root is valid, the path `0x4ca3c0b..0x4ca3c18` reads the new root's 16-bit count S at +0x37a, and `0x4ca3c91` returns `(rax, rdx) = (N-S, S)` under the stated 0<=S<=N invariant.

The caller stores `rax` back to the original map count at `0x4de5654` and preserves `rdx` for its new descriptor. Combined with the separately documented selected leaf split where S=N-i, this partitions the counts as i and N-i. The subtraction is not itself checked here; malformed counts, nonzero-height traversal, subsequent representation transitions and runtime reachability remain open.

Run `python3 research/work-items/RE-017-node115-tracker-tree-split-count/verify.py` for target authentication and byte/direct-call anchors with mutation controls; `windows.txt` contains the disassembly. No target execution is performed.
