# RE-009 — Node #115 matched quantity successor traversal

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched quantity iterator at `0x3877d60` searches a second tree for each current key (#7712).

After a second-tree miss, the iterator advances its quantity cursor. At an internal node it takes the edge immediately after the current key, at node +0x120+8*index, then follows child zero at +0x118 for the remaining descent. The descent is grouped in blocks of eight. At a leaf it increments the current slot. The next slot index is stored at cursor +0x28 and the cursor node fields are reset before the next key check. A slot at or above the node count causes ascent through parent pointers.

This packet covers the successor step following a miss. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-successor/verify.py`.
