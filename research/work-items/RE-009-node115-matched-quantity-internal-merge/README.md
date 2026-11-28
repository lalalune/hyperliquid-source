# RE-009 — Node #115 matched quantity internal merge

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched quantity deletion ancestor path chooses an internal-node merge when the sibling counts plus the separator are below 12 (#7750).

At `0x35b04d8` the left node's count is set to the combined count. The parent separator key and 16-byte value are saved, the parent's following key and value arrays move down one slot, and the saved separator is placed after the left node's old entries. The right node's key and value arrays follow it. The parent child-pointer suffix is also shifted. The loop at `0x35b0610` rewrites parent pointers and edge indices for shifted children.

This packet covers internal-node merge assembly and parent child-index repair. The leaf-level merge is separately traced in #7738. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-internal-merge/verify.py`.
