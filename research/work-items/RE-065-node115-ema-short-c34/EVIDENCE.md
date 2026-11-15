# Evidence

The packet records normalized length subtraction, jump-table dispatch, pointer-field comparisons, sentinel handling at `0x8000...`, and mode-specific branches. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d3ae00, 0x4d3b4cb)`, length 1739, FDE VA `0xf171c8`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d3ae00` include `0x4d3be1e` (`0x4d3bbe0` FDE, jmp).
