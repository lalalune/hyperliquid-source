# RE-009 — Node #115 quantity-tree right-edge growth

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The ordered builder at `0x4caff20` enters this path when its current rightmost node cannot take the next distinct entry. The equal-key folding and nonfull insertion path are covered in #7570.

The growth path climbs +0xb0 parent pointers until it finds a parent whose count at +0x112 is below 11. If the climb reaches a null pointer, it allocates a 376-byte root, installs the old root as child zero at +0x118, updates its parent and edge index, and publishes the new root and incremented height. It then starts a new right branch with a 280-byte leaf and adds 376-byte single-child internal nodes as needed to match the height of the accepting parent.

The pending key and value are written at the parent's old count index. The new subtree is stored at child index old count + 1, and the child's parent pointer and edge index are set accordingly. This packet documents the successful growth path. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-tree-right-growth/verify.py`.
