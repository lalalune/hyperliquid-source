# RE-124: node115 EMA short c95

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43b30–0x4d43c08` (216 bytes), `.eh_frame` FDE VA `0xf18144`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 18 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The 0xc0 branch zeros the qword at result +8 and jumps directly to the byte-9 store. The alternate call to 0x4ae1940 passes zero in EDX and checks the returned local byte against 9. On equality it copies sixteen bytes to result +8 and joins the tag write. The other branch copies two sixteen-byte blocks to result +0 and +0x10.
