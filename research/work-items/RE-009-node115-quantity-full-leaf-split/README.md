# RE-009 — Node #115 full quantity leaf split

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The quantity vacant-entry insertion helper at `0x4c5b580` selects this path at the full leaf count of 11.

The old row that becomes the separator depends on the requested insertion position. For positions 0–4 it is row 4 and the insertion remains on the left. For position 5 it is row 5 with insertion on the left at 5. For position 6 it is row 5 with insertion on the right at 0. For positions 7–11 it is row 6 with insertion on the right at position minus 7. The helper stages both words of the separator value and its key, allocates a 280-byte sibling, copies the rows strictly after the separator into it, and truncates the old leaf count to the separator index. Keys and values move at their respective eight- and sixteen-byte strides. The next insertion operates on the chosen half.

This packet covers separator selection, allocation and redistribution. Parent propagation is outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-full-leaf-split/verify.py`.
