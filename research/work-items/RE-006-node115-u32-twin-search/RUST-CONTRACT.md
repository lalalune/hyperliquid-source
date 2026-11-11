# Frozen Node115 u32 twin cursor-search contract

Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The selected body is `0x35bf500..0x35bf592`, 146 bytes, SHA-256
`90fda960e4f1a5fbffb665662ff5ae5384a64c5c54ac1443f37536c1d5400142`.
It selects the u32-key layout with at most 11 ascending keys and records
`{flag, final node, remaining height, equal/insertion position}`.

The safe model validates the logical node shape, scans to the first key greater
than or equal to the probe, returns flag zero on equality, and otherwise follows
the selected child while height remains. At height zero a miss returns flag one,
the current node, height zero and insertion position. Native offsets, pointers,
malformed trees, ownership and caller effects are excluded.
