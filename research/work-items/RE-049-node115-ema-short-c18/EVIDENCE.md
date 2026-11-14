# Evidence

The packet records the entry frame, indexed count load, record-width scaling, comparator setup, loop condition, and transition edge. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch target, and mutation controls.

The existing hash-signature tracker packet pins the hit encoding. This packet adds internal record-scan and transition witnesses. [Related packet](../RE-008-hash-signature-tracker-cap-115/README.md) Reviewed static incoming edges to `0x4d38340` include `0x4e4106d` (`0x4e40990` FDE, call), `0x4e4120c` (`0x4e40990` FDE, call).
