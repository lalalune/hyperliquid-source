# RE-087: node 115 EMA short c58

This packet records the statically bounded FDE at `0x4d3e770–0x4d3e881` in the pinned node 115 binary. The routine validates tagged records, invokes bounded helper calls, writes returned 16-byte payloads into adjacent record slots, and follows separate sentinel layouts. It is static evidence only; no source reconstruction or behavioral equivalence is claimed.
