# RE-009 — Node #115 quantity parent edge insertion

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. After splitting a leaf, the vacant-entry helper reads the original child's parent-edge index at +0x110 and takes the path at `0x4c5bd5a` when the parent has fewer than 11 entries.

The separator's key and value are inserted at that index. For a middle edge, the helper shifts the key and value suffixes and shifts child pointers starting one slot after the original child. It publishes the split sibling at the next edge, leaves the original child at its existing edge, and increments the parent count. It then rewrites the parent pointer (+0xb0) and edge index (+0x110) for the inserted and shifted children. For a split at the last edge, the parent writes the separator and new child without shifting a suffix.

The packet covers the parent with room. Full-parent propagation is outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-parent-edge-insertion/verify.py`.
