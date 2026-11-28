# RE-009 — Node #115 matched quantity ancestor gate

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Following sibling repair, the matched quantity removal helper `0x35b00b0` resumes at `0x35b02ef`.

It reads the current node's parent at +0xb0. If present, it checks the parent's count at +0x112. A count above four leaves the ancestor repair path. A count of four or less enters it and follows parent links; the path reads a child's +0x110 parent-edge index before selecting a sibling. On the return path at `0x35b033b`, the helper writes the saved removed key, 16-byte value, node pointer, height and slot into its result.

This packet binds the post-sibling-repair gate and output. The leaf mutation and first sibling dispatch are documented in #7723 and #7728. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-matched-quantity-ancestor-gate/verify.py`.
