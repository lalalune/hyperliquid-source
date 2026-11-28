# RE-009 — Node #115 matched quantity predecessor replacement

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The matching traversal calls `0x35b6600` after finding a quantity key in the second tree (#7712). If the selected quantity node has nonzero height, the helper first follows the child at the selected slot and then repeatedly follows the last child, whose index is the node count at +0x112. It passes the rightmost leaf's last slot to `0x35b00b0`. With zero height it calls the same helper directly for the selected slot.

The internal-node path reads the returned key and 16-byte value, follows the returned cursor upwards when its slot is at or beyond the current node count, then exchanges those fields with the destination slot. This packet binds the predecessor traversal and replacement. The leaf-removal and rebalancing internals are outside its scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-match-predecessor/verify.py`.
