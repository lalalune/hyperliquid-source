# RE-071: node115 EMA short c40

Static evidence packet for FDE `[0x4d3c990, 0x4d3ca91)` (257 bytes), FDE VA `0xf174cc`.

The helper is a compact tagged/null comparator: it handles tag-3 scalar ordering, tag-2 sentinel pairing, optional pointer fields, and a final `+0x20` comparison. Only static bytes and unwind ownership are recorded; no captured code is executed or emulated.
