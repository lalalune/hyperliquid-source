# RE-009 — Node #115 matched quantity root collapse

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched quantity removal helper `0x35b00b0` can reach an ancestor without a parent after repair (#7741).

When that ancestor's count is zero, the helper takes its tree handle from the saved owner pointer, clears that pointer temporarily and reads the root and height. On the normal nonzero-height path it promotes child zero from root +0x118, decreases the handle height by one, clears the promoted child's parent pointer at +0xb0, and releases the old 376-byte internal root. It then restores the handle pointer and returns through the existing result path. A nonzero root count skips the collapse.

This packet binds the root transition for the matched traversal's own removal helper. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-root-collapse/verify.py`.
