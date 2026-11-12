# Node #115 raw-map split: root promotion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Conditional static evidence; the containing FDE is `0x4c3f280..0x4c3fde6`.

After the separately traced full-leaf split, `0x4c3f583` tests the old node's parent pointer. If it is null, `0x4c3f9af..0x4c3fa1f` obtains the tree header, requires a non-null old root, and requests a 0x148-byte node. On allocation success it initializes that node's parent and count to zero, puts the prior root in child slot zero at +0xe8, sets the prior root's parent pointer and parent index, stores the new root in the header, and increments the header height. A null root, failed allocation, or height overflow takes a separate failure branch.

Subject to the subsequent height consistency and node-capacity checks, `0x4c3fa40..0x4c3fa77` inserts the saved split key and 12-byte value into the new root, places the other split node in child slot one at +0xf0, and updates that child's parent pointer and index. This records the observed root-promotion path; it does not cover propagation through a non-root parent, indirect allocation behavior, or production execution.

Run `python3 research/work-items/RE-017-node115-raw-map-split-root/verify.py` to authenticate the target and validate instruction anchors with mutation controls without executing the target. The disassembly is saved in `windows.txt`.
