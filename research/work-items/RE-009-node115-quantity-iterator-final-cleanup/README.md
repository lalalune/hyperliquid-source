# RE-009 — Node #115 quantity iterator final cleanup

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. In the quantity iterator `0x51da3a0`, the zero-remaining path begins at `0x51da449`. Earlier packets document in-range iteration (#7519) and exhausted-node ascent while entries remain (#7765).

The zero-remaining path takes the iterator's tag, node, height and slot, then clears its tag. For tag one with a non-null node, it follows +0xb0 parent pointers to the root, releasing each node. It uses 280 bytes for a height-zero node and 376 bytes for higher nodes, incrementing height on ascent. It releases the final root with the same size rule and returns a null result. Other tags bypass this node-chain cleanup.

Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-iterator-final-cleanup/verify.py` to check the target-bound instruction windows and branch targets.
