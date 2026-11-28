# RE-009 — Node #115 matched quantity ancestor sibling selection

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. After the matched deletion ancestor gate (#7741), the underfull internal-node path selects a sibling using the node's parent-edge index.

A nonzero edge selects the left sibling from parent +0x118+8*(edge-1). Edge zero selects the right sibling from parent +0x120. The code computes the two node counts plus one for the parent separator. A total below 12 continues into the internal merge path. Otherwise it requests 5 minus the underfull count from `0x3524610` for the left sibling or `0x352bf00` for the right.

This packet covers internal-node sibling selection and the count-dependent transfer handoff. The leaf-level sibling selection is separately documented in #7728. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-ancestor-sibling/verify.py`.
