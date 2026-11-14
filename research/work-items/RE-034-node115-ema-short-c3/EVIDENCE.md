# Evidence

The packet records the entry frame, input-field loads, non-empty admission test, and the root branch into the staged-state path. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, branch target, and mutation controls.

The existing LU resolver packet binds a call into this helper. This packet pins the entry and selected internal branch within the helper FDE. [Related packet](../RE-001-node115-lu-resolver/README.md) Reviewed static incoming edges to `0x4d35df0` include `0x4da8a2b` (`0x4da8a00` FDE, call).
