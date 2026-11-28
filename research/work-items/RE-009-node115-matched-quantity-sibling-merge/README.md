# RE-009 — Node #115 matched quantity sibling merge

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched quantity leaf repair selects `0x35336f0` when the sibling counts sum to less than 12 (#7728).

The helper checks that the combined key count, including the parent separator, remains below 12. It updates the left node's count to left count plus right count plus one. The selected parent key and its 16-byte value become the next left-node entry, followed by the right node's key and value arrays. The helper shifts the parent's remaining key and value suffixes. It also shifts the parent's child pointers and rewrites parent pointers and edge indices for affected children.

This packet covers the merge's key/value assembly and parent edge repair. Further root handling is outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-sibling-merge/verify.py`.
