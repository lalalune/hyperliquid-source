# RE-125: node115 EMA short c96

- Target: `artifacts/node/115/hl-node`
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- FDE: `.text 0x4d43c10–0x4d43cf6` (230 bytes), `.eh_frame` FDE VA `0xf18178`.
- Static binary witness only; no source-equivalence or runtime claim.

The verifier independently checks the target hash, exact FDE row, 18 instruction witnesses, and two negative controls. Selected instructions show state-byte initialization, cursor update, zero-pointer marker, fallback call, and return sequence as direct disassembly observations.

Task RE-001. The EMA label identifies the submitted packet sequence. Source ownership and runtime reachability remain open. The selected fallback zero-extends two one-byte fields into EDX and ECX and calls through slot 0x64dfeb0. The slot has a R_X86_64_RELATIVE addend of 0x14b7aa0. A local result tag of 9 becomes result byte 9 with qword 1 at +8 and the local +8 qword at +0x10. The selected input-0xc0 path instead sets qword 0 at +8 before joining the byte-9 store.
