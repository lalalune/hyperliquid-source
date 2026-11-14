# RE-082: node 115 EMA short c51

This packet records the statically bounded FDE at `0x4d3dde0–0x4d3df07` in the pinned node 115 binary. The routine compares tagged byte fields, lengths and a bounded payload helper before continuing through additional tag comparisons; the packet preserves observations without claiming reconstructed source or behavioral equivalence.

The verifier is static-only and binds every claim to the target digest, FDE extent, GNU objdump byte partition, and representative control-flow/data witnesses.
