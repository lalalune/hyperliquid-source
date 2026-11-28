# RE-009 — Node #115 quantity-tree final right-edge fill

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

When the ordered builder at `0x4caff20` exhausts its input, it releases the owned row buffer when its capacity is nonzero, using 24 bytes per row. A tree with height zero needs no right-edge walk. For a taller tree, the builder descends through the last child at each level. It reads the parent's count at +0x112, sets the separator index to count minus one, and extracts the children at indices count minus one and count from the pointer array based at +0x118.

If the right child holds fewer than five entries, the builder passes 5 minus its count and the parent/sibling descriptor to `0x4c958a0`, then continues downward. The existing ring-map packet describes that callee as a left-sibling transfer in the removal repair path. The evidence here covers the builder's normal completion path and its distinct call site.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-tree-final-fill/verify.py`.
