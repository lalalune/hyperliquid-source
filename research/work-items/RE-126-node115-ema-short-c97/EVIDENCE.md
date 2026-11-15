# RE-126: node115 EMA short c97

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43d00–0x4d43de2` (226 bytes), `.eh_frame` FDE VA `0xf181ac`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 13 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected fallback passes the two bytes Px from .rodata at 0x93619f in RDX and length 2 in ECX to 0x47b9640. A local result tag of 9 selects a single qword at result +8 before the byte-9 store. The 0xc0 input path writes qword 0 at +8 and joins the same tag store.
