# Evidence

The packet records the entry frame, indexed record load, comparator call setup, loop condition, and transition edge. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch target, and mutation controls.

The existing peer-address admission packet binds a caller to the exact-key lookup. This packet adds internal cursor and loop witnesses. [Related packet](../RE-008-node115-peer-address-admission/README.md) Reviewed static incoming edges to `0x4d38140` include `0x24b817d` (`0x24b7920` FDE, call), `0x2a4fd95` (`0x2a4fc50` FDE, call), `0x2a4fec6` (`0x2a4fc50` FDE, call), `0x2a592d3` (`0x2a59160` FDE, call).
