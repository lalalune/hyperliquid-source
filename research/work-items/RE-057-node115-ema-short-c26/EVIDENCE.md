# Evidence

The packet records the `+0x34e` count load, 0x14-byte cursor stride, comparator result rank, child descent through `+0x350`, secondary jump-table dispatch, and terminal tuple stores. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch targets, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d39390, 0x4d39617)`, length 647, FDE VA `0xf1703c`

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d39390` include `0x4dce24f` (`0x4dce210` FDE, call).
