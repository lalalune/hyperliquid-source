# Evidence

The packet records input mode classification, paired 64-bit/32-bit equality and ordering comparisons, result-class jump-table dispatch, and terminal construction. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d3a440, 0x4d3ab20)`, length 1760, FDE VA `0xf17124`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3a440` include `0x4dce66d` (`0x4dce580` FDE, call).
