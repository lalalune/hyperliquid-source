# Node #115: selected full membership-parent split

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the full-parent branch after the leaf split in #6763; #6764 covers the nonfull parent instead.

For a valid full parent with 11 keys and incoming child position i in `0..=11`, `0x4c3978d..0x4c39800` selects the old pivot, insertion side and local insertion position:

| i | old pivot | insertion side | local i | final left / right key counts |
| --- | --- | --- | --- | --- |
| 0..4 | 4 | left | i | 5 / 6 |
| 5 | 5 | left | 5 | 6 / 5 |
| 6 | 5 | right | 0 | 5 / 6 |
| 7..11 | 6 | right | i-7 | 6 / 5 |

`0x4c39800..0x4c3989a` allocates a 0x148-byte node, saves the selected 20-byte pivot, copies the keys after it and updates the two key counts. `0x4c398af..0x4c39926` copies right-key-count plus one child pointers to the new node and rewrites each moved child's parent pointer and index. `0x4c3993e..0x4c39aca` selects a side, inserts the incoming key and child and updates affected links. After insertion the nodes contain 11 keys in total, with one additional pivot carried upward, and 13 child pointers in total.

The count table assumes valid parent and child state, disjoint incoming-key storage and normal allocation/copy returns. These are static observations of the selected path; names and ownership are inferred. Higher-level propagation, root creation, allocation failures and whole-tree correctness are outside this packet. Run `python3 research/work-items/RE-017-node115-membership-parent-split/verify.py` for target digest, instruction anchors and mutation controls without target execution. Static windows and copy/allocator relocations are in `windows.txt`. No component gate changes.
