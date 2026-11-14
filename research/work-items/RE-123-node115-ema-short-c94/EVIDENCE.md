# RE-123: node115 EMA short c94

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43a40–0x4d43b2a` (234 bytes), `.eh_frame` FDE VA `0xf18110`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 11 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected fallback passes the twelve bytes ExpiresAfter from .rodata at 0x938088 in RDX and length 12 in ECX to 0x47a1da0. This differs from the Unvalidated and UsdcNtl sibling fallbacks. The marker path clears result +8, and the joined arm writes byte 9 to result +0.
