# Evidence

The packet records the indexed count scaling, bounded key comparison, result-code branches, child descent at `+0x170`, second-table scanning, jump-table redispatch, and terminal tuple stores. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch targets, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d38fd0, 0x4d391a8)`, length 472, FDE VA `0xf16fcc`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d38fd0` include `0x4dce7e3` (`0x4dce7b0` FDE, call).
