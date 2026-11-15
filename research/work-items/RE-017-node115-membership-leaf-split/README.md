# Node #115: selected full membership-leaf split

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the full-leaf branch left open by #6762.

For a valid full leaf of exactly 11 entries and insertion index i in `0..=11`, `0x4c395a3..0x4c395f9` selects the old pivot index, insertion side and local insertion index as follows:

| i | old pivot | insertion side | local i | resulting left / right entry counts |
| --- | --- | --- | --- | --- |
| 0..4 | 4 | left | i | 5 / 6 |
| 5 | 5 | left | 5 | 6 / 5 |
| 6 | 5 | right | 0 | 5 / 6 |
| 7..11 | 6 | right | i-7 | 6 / 5 |

`0x4c39602..0x4c39690` allocates a 0xe8-byte node, saves the selected 20-byte pivot, copies the suffix following it to the new node, and sets the old node count to the pivot index. `0x4c396ad..0x4c3971c` selects the old or new leaf, shifts that leaf's suffix with the pinned `memmove` slot, writes the incoming 20-byte key and increments that leaf's count. The pivot remains separate for later parent handling. The total is 11 entries across the two leaves plus one promoted entry, for 12 after insertion.

The table assumes valid ordered input, disjoint incoming-key storage and normal allocation/copy returns; source names and physical node ownership are inferred from these instructions. Parent propagation, malformed indices, error paths and whole-tree correctness remain open. Run `python3 research/work-items/RE-017-node115-membership-leaf-split/verify.py` for target digest, instruction anchors, direct call and mutation controls without target execution. Static windows and copy/allocator relocations are in `windows.txt`. No component gate changes.
