# RE-127: node115 EMA short c98

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43df0–0x4d43eda` (234 bytes), `.eh_frame` FDE VA `0xf181e0`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 14 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected fallback passes the twelve bytes BookOrderKey from .rodata at 0x937fde in RDX and length 12 in ECX to 0x479b790. A local result tag of 9 stages qword 1 at result +8 and the returned local +8 qword at result +0x10, then writes byte 9 at result +0.
