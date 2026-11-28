# RE-009 — Node #115 quantity tree iterator cursor handoff

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. #7511 identifies this iterator at `0x51da3a0` and its caller's row extraction. This packet follows an in-range cursor within the iterator.

The iterator reads remaining count at state +0x40 and decrements it before returning a row. For tag 1, the selected in-range path reads node pointer, height and slot from state +8, +0x10 and +0x18. It checks the slot against the node's 16-bit key count at +0x112.

An in-range leaf slot makes the next cursor the same leaf at slot +1. For an in-range internal slot, the next cursor comes from the child edge at node +0x120 + 8*slot, then the first child at +0x118 down the remaining levels. The remainder loop handles height modulo eight before the unrolled eight-edge groups. That path selects slot zero of the descended leaf. Both paths return the original node, height and slot in three words, separately writing the next node, zero height and next slot back to the cursor.

The scope here is an in-range cursor. Advancement after an exhausted node and the zero-remaining cleanup path have separate continuations. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-tree-iterator-cursor/verify.py` from the repository root.
