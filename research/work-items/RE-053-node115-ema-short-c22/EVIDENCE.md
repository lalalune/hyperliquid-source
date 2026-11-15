# Evidence

The packet records the tag classification, two bounded scan loops, table offsets `+0x1a2a/+0x1a2d/+0x1a38`, child descent, and terminal tuple path. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, control-flow edges, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d38c10, 0x4d38e67)`, length 599, FDE VA `0xf16f60`

The existing variant-cursor packet notes the inlined member and child-edge offset. This packet adds tag dispatch and count-load instruction witnesses. [Related packet](../RE-006-node115-variant-cursor/README.md) Reviewed static incoming edges to `0x4d38c10` include `0x4dccb1c` (`0x4dcca20` FDE, call).
