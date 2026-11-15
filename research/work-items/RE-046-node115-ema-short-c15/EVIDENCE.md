# Evidence

The packet records the entry frame, indexed record load, comparator call setup, loop condition, and transition edge. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch target, and mutation controls.

Task RE-001. This packet records the selected behavior of one bounded node #115 code interval. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. Reviewed static incoming edges to `0x4d37fa0` include `0x4e41bc0` (`0x4e41510` FDE, call), `0x4e4494e` (`0x4e41510` FDE, call).
