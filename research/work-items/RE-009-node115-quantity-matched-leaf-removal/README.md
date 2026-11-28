# RE-009 — Node #115 matched quantity leaf removal

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched quantity removal helper `0x35b6600` calls `0x35b00b0` directly for a leaf, or after predecessor selection as described in #7719.

For a leaf with count n and selected index i, the callee saves the key at +0xb8+8i and the 16-byte value at +16i. It moves the n-i-1 following keys and values down by one slot, using 8 and 16 bytes per entry, and writes n-1 at node +0x112. A resulting count above four skips the underfull-node path. Otherwise it reads the parent pointer and branches on its presence.

This packet establishes the leaf mutation and underfull gate for the matched traversal's callee. Sibling selection and repair remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-matched-leaf-removal/verify.py`.
