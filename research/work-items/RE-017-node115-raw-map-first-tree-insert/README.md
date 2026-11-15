# Node #115 raw-map first insertion into an empty tree

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This documents a selected static path only.

The absent-key descriptor assembled by `0x4dbe5c5..0x4dbe5f8` is passed to `0x51ef9a0`. When its node field at descriptor +0x10 is null, `0x51efa01..0x51efa31` requests a 0xe8-byte node; on successful allocation it clears the parent pointer and node count, stores the node in the tree header and clears header height. The separate non-null path calls `0x4c3f280` and is not analyzed here.

On the successful empty-node path, the initialized count is zero and the `< 11` check at `0x51efa38` passes. `0x51efa3e..0x51efa60` sets count to one, stores the descriptor's key at node +0x08 and the 12 input bytes at node +0x60. At `0x51efa67` the tree header's total count is incremented, and `0x51efa6c..0x51efa7a` returns the node, index zero, prior slot count, and header pointer. Null allocation and failed bounds take separate error paths. This does not establish live reachability, concurrency safety, or nonempty insertion behavior.

Reproduce: `python3 research/work-items/RE-017-node115-raw-map-first-tree-insert/verify.py` authenticates the binary, checks byte and call anchors, and rejects mutated anchors without executing the target. See `windows.txt` for the captured disassembly.
