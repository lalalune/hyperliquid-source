# RE-012: selected node 115 gossip range bound searches

This packet examines the two opaque ring-search helpers from [#5084](https://github.com/lalalune/hyperliquid-source/pull/5084). It concerns the valid, non-wrapped, unsigned-sorted row case, not all representations or arbitrary container contents. Target: Linux x86-64 node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Selected range and representation

The selected `0x4dce320` call receives unsigned endpoint words A and B and a zero flag. It rejects A > B, then in its ring-like representation calls `0x57f2fb0` on A and `0x57f2c40` on B. The view-construction arithmetic after those calls is covered in #5084.

Let C be the representation's capacity qword, H its head, N its count, and P its data pointer. Assume `C > 0`, `H < C`, `N <= C-H`, valid address arithmetic and a readable contiguous run of N 24-byte rows from `P+24*H`. The two helpers' selected non-wrapped branch uses the first qword of each row as an unsigned key. Assume those keys are nondecreasing; the code in these selected helpers does not itself prove that invariant.

## Endpoint relation

Under those premises, the loop in `0x57f2fb0` advances its candidate on a strict `row_key < A` comparison; its final `cmp`/`adc` increments the return exactly when the final row key is less than A. Its result I is the number of selected keys strictly less than A. The corresponding loop in `0x57f2c40` retains its earlier candidate when `row_key > B`; its final `cmp`/`sbb` increments exactly when B is at least the final row key. Its result J is the number of selected keys less than or equal to B. Empty runs return zero.

Therefore, for A <= B and these valid sorted non-wrapped premises, the view interval `[I,J)` selects exactly rows whose raw unsigned key is in the inclusive range `[A,B]`, including all duplicates equal to either endpoint. This is a conditional interpretation of the local comparisons; it does not establish row semantics, ordering at runtime, tree or wrapped paths, or the complete response payload. The stored key values need not be block heights or network identifiers.

## Reproduce

From the repository root run `PYTHONPATH=tools python research/work-items/RE-012-node115-gossip-range-bounds/verify.py`. It authenticates the target and three FDE bodies, selected instruction bytes and direct targets, and checks static sorted-sequence boundary examples. It reads and decodes bytes only and never executes or emulates the captured target.
