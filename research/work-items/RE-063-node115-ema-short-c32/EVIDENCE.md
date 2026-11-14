# Evidence

The packet records the distinct `+0x18` root adjustment, remainder traversal, repeated `+0x10` child loads, fast-path loop decrement, and terminal stores. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d3acc0, 0x4d3ad62)`, length 162, `.eh_frame` offset `0xf17198`
