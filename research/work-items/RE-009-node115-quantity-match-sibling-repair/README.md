# RE-009 — Node #115 matched quantity sibling repair dispatch

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The matched traversal's leaf-removal path `0x35b00b0` enters the repair path when the remaining leaf count is below five (#7723).

If a parent exists, the code reads the child's parent-edge index at +0x110. A nonzero index selects the child immediately to its left and uses the preceding separator. Index zero selects the parent's child at +0x120, the immediate right sibling. It adds the two leaf counts and compares the sum with 12. When the sum is below 12, both directions call `0x35336f0`, passing a direction value of one for the left sibling and zero for the right. Otherwise the left and right cases call `0x3524610` and `0x352bf00` respectively with a count argument of one.

This packet covers sibling selection and helper dispatch. The helper internals and root-without-parent handling remain outside scope. Run `PYTHONPATH=tools python3 research/work-items/RE-009-node115-quantity-match-sibling-repair/verify.py`.
