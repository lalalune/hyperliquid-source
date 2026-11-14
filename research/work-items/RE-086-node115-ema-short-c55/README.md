# RE-086: node 115 EMA short c55

This packet records the statically bounded FDE at `0x4d3e4f0–0x4d3e53d` in the pinned node 115 binary. The routine requests a fixed-size allocation, initializes sentinel words and a two-element record on success, and has a distinct fallback allocation call. It is static evidence only; no source reconstruction or behavioral equivalence is claimed.
