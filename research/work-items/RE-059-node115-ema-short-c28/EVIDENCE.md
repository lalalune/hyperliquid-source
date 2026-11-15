# Evidence

The packet records initial range validation, jump-table dispatch, the `+0x112` and `+0x2d0` child-table scans, bounded loop edges, and terminal result construction. `verify.py` checks the exact FDE, artifact identity, instruction witnesses, and mutation controls.

Pinned node #115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
FDE: `[0x4d39ef0, 0x4d3a43c)`, length 1356, FDE VA `0xf170d8`

The existing gossip range packet binds a caller and its height-zero behavior. This packet adds internal dual-layout scan and dispatch witnesses. [Related packet](../RE-012-node115-gossip-tree-leaf-range/README.md) Reviewed static incoming edges to `0x4d39ef0` include `0x4dce388` (`0x4dce320` FDE, call).
