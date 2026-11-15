# RE-001: node115 return-tag sibling family c282-c285

This packet records four adjacent function extents in the digest-pinned
Hyperliquid node #115 ELF. Each record preserves the shared helper call and
the terminal instruction observed in a static disassembly excerpt. The packet
is descriptive only: it does not claim runtime reachability, semantics beyond
the captured bytes, or a reproduced defect.

Target digest: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`

Validation is fail-closed on target digest, function extent, call bytes,
terminal bytes, and return bytes. No captured code was executed or emulated.
