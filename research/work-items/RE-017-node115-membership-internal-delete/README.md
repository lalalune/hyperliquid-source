# Node #115: selected internal membership-key deletion

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the nonzero-height path of `0x4d317e0`, complementing the height-zero leaf path in #6760 and the selected membership removal in #6759.

Given a valid selected internal node and index, `0x4d317f6..0x4d318de` selects the child at node `+0xe8+8*index` and follows each descendant's rightmost child (index from `+0xe6`) until reaching a leaf. It forms the last leaf index `count-1` and calls `0x4d17720` to remove the 20-byte value there. Under valid ordered-tree invariants this is the selected left-subtree predecessor.

The returned location is followed through parent/index links as needed at `0x4d31919..0x4d31956`. The code then saves a 20-byte value at the recovered location and writes the removed predecessor value into that location (`0x4d31956..0x4d31979`). It prepares a continuation by descending the next child and returns the previously saved value (`0x4d319ee..0x4d31a6a`). The selected caller decrements the owning count once on normal return, per #6759.

The identification as an ordered-tree predecessor is conditional on valid child/index relationships and normal return from the leaf helper; full rebalancing, failure paths and runtime reachability remain open. This is not a full tree implementation or a quorum claim. Run `python3 research/work-items/RE-017-node115-membership-internal-delete/verify.py` for target digest, selected anchors, direct-call and mutation controls without target execution. Disassembly is in `windows.txt`.
