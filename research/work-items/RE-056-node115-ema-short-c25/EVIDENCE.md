# Evidence

The packet records the `+0x2ca` count load, 0x8-byte scaling, bounded comparison loops, child descent through `+0x2d0`, secondary-table scan, and terminal tuple path. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch targets, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d391b0, 0x4d39388)`, length 472, FDE VA `0xf17004`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d391b0` include `0x4dce4b3` (`0x4dce480` FDE, call).
