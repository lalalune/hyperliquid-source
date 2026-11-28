# RE-009 — Node #115 quantity two-tree match

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The tree traversal path at `0x3ce9010` repeatedly calls `0x3877d60` until its returned tag is zero. The helper advances the quantity-tree cursor, using the node count at +0x112 and parent pointer and parent index at +0xb0 and +0x110. For a current quantity key read at node +0xb8 + 8*index, it searches a second tree whose keys and edges are at +0x10 and +0x68 and whose node count is at +0x62. Comparison is unsigned and descent follows the returned insertion edge.

On an equal-key match the helper decrements the counter addressed by cursor +8, calls `0x35b6600` with the selected quantity-tree node, height and slot, and returns tag one together with the resulting payload and updated cursor. A null cursor returns tag zero. The packet binds the match and handoff; it does not claim the second tree's field names or the removal helper's internals. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-two-tree-match/verify.py`.
