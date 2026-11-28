# RE-009 — Node #115 quantity leftmost descent

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The paired quantity caller invokes `0x3ce8df0` twice on a shared input field, as documented in #7684. On its tree arm, the helper reads the root pointer at descriptor +8 and the height at +0x10. A non-null root is followed through child zero at node offset +0x118 once per level. The first loop handles height modulo eight, and the unrolled loop performs eight child-zero loads per remaining group. The selected node is then passed in the local traversal descriptor along with the descriptor's count address.

A zero root produces a null traversal node. A zero height keeps the root as the selected node. The packet binds traversal setup, not the later per-entry iterator behavior. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-leftmost-descent/verify.py`.
