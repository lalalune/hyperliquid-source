# Evidence

The packet records the entry frame, indexed count load, record-width scaling, comparator setup, loop condition, and backward transition edge. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch target, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d388b0, 0x4d38993)`, length 227, FDE VA `0xf16e98`

Witnessed entry bytes:

`0x4d388b0: 55 41 57 41 56 41 55 41 54 53 48 83 ec 18 49 89 cc 48 89 14 24 49 89 f6 48 89 7c 24 08 4c 8b 2d 7c 72 7a 01`

The loop compares the scaled bound at `0x4d388f0`, advances by `0x20` at `0x4d38914`, and takes the backward edge at `0x4d3891a` to `0x4d388f0` when the comparator result is equal.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d388b0` include `0x4e41a08` (`0x4e41510` FDE, call), `0x4e44983` (`0x4e41510` FDE, call).
