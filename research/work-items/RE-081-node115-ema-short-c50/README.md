# RE-081: node 115 EMA short c50

This packet records the statically bounded FDE at `0x4d3dcd0–0x4d3ddd9` in the pinned node 115 binary. The routine builds two stack-resident three-word records, repeatedly calls the same helper, and compares returned scalar fields before returning a signed ordering result.

The packet is evidence-only: it does not execute or emulate the captured binary.
