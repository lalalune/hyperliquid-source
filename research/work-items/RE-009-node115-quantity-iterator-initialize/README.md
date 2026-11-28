# RE-009 — Node #115 quantity iterator initialization

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The quantity tree iterator `0x51da3a0` decrements remaining count when it is nonzero. If its low dword state tag is not one, it initializes a cursor at `0x51da4df`.

The initializer reads a root pointer from state +0x10 and height from +0x18. It follows child zero at node +0x118 once per height level, with a remainder loop and an unrolled group of eight. It writes tag one, the selected node at +8, and zero height and index at +0x10 and +0x18. It then checks index zero against the selected node's count before entering normal iteration.

This initialization precedes the in-range cursor behavior documented in #7519. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-iterator-initialize/verify.py`.
