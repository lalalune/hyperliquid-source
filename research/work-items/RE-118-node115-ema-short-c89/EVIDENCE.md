# RE-118: node115 EMA short c89

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43420–0x4d4350a` (234 bytes), `.eh_frame` FDE VA `0xf1802c`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, nine instruction witnesses, and two negative controls. The selected instructions show state-byte initialization, cursor/count updates, the zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The marker path clears the qword at result +8 at 0x4d434aa. The separate direct call at 0x4d434c9 targets 0x47a70c0 and is followed by a one-byte value 9 at 0x4d434e5.
