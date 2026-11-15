# RE-120: node115 EMA short c91

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d436b0–0x4d4379a` (234 bytes), `.eh_frame` FDE VA `0xf18084`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 11 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor/count updates, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected fallback passes the seven bytes UsdcNtl from .rodata at 0x91bfdb in RDX and length 7 in ECX to 0x47acc80. In the same-size sibling in RE-118, the corresponding inputs are the eleven bytes Unvalidated and the target is 0x47a70c0. The marker path here clears result +8, and the merged return arm writes byte 9 to result +0.
