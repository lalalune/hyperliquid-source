# RE-009 — Node #115 matched quantity sibling transfer

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched quantity leaf repair dispatch calls `0x3524610` for a left sibling and `0x352bf00` for a right sibling, each with transfer count one (#7728).

Both helpers guard the recipient count plus transfer count against 12 and subtract the transfer count from the donor's +0x112 count. In the left-sibling case the recipient's key and 16-byte value arrays are shifted right. The donor's boundary entry replaces the parent separator and the old separator enters the recipient. In the right-sibling case the donor boundary entry likewise replaces the parent separator and the old separator is appended to the recipient, after which donor arrays shift left.

The packet covers the normal key/value transfer and count updates. Child-edge movements for internal nodes are outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-sibling-transfer/verify.py`.
