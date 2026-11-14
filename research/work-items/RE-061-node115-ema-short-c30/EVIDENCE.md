# Evidence

The packet records empty-count handling, initial remainder traversal, the eight repeated `+0x90` link loads, fast-path loop decrement, and terminal stores. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d3ab20, 0x4d3abea)`, length 202, FDE VA `0xf17170`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3ab20` include `0x513d23e` (`0x513d120` FDE, call).
